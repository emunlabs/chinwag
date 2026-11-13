// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Provisioning follows durable path-lease admission, with explicit quarantine.
#![forbid(unsafe_code)]
use crate::{
    FleetManifest, FleetPolicyError, FleetResult, ResolvedDispatchPlan, WriteMode, pattern_matches,
};
use chinwag_claim::path_lease::{
    PathLeaseError, PathLeaseRecord, PathLeaseRequest, PathLeaseStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum IsolationSpec {
    #[default]
    ReadOnly,
    GitWorktree {
        #[serde(default)]
        root: Option<PathBuf>,
    },
    JujutsuWorkspace {
        #[serde(default)]
        root: Option<PathBuf>,
    },
    CopyOnWriteDir {
        #[serde(default)]
        root: Option<PathBuf>,
    },
    ContainerOrMicroVmMount {
        root: PathBuf,
    },
    ArtifactSubdirOnly {
        root: PathBuf,
    },
}
impl IsolationSpec {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::GitWorktree { .. } => "git_worktree",
            Self::JujutsuWorkspace { .. } => "jujutsu_workspace",
            Self::CopyOnWriteDir { .. } => "copy_on_write_dir",
            Self::ContainerOrMicroVmMount { .. } => "container_or_micro_vm_mount",
            Self::ArtifactSubdirOnly { .. } => "artifact_subdir_only",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceLeaseReceipt {
    pub backend: String,
    pub isolated_cwd: PathBuf,
    pub claim_id: String,
    pub allowed_write_roots: Vec<String>,
    pub base_revision: Option<String>,
    pub seat_actor: String,
    lease: PathLeaseRecord,
}
impl WorkspaceLeaseReceipt {
    /// Repository identity retained by the durable claim gate.
    pub fn repository(&self) -> &Path {
        &self.lease.request.repository
    }
    /// Manifest digest retained by the durable claim gate.
    pub fn manifest_digest(&self) -> Option<&str> {
        self.lease
            .request
            .metadata
            .get("manifest_digest")
            .map(String::as_str)
    }
}

/// Backends are explicit capabilities supplied by a host, rather than fallback chains.
pub trait IsolationBackend {
    fn prepare(&self, workspace: &Path, destination: &Path) -> FleetResult<()>;
    fn release(&self, workspace: &Path, destination: &Path) -> FleetResult<()>;
}
pub struct GitWorktree;
impl IsolationBackend for GitWorktree {
    fn prepare(&self, workspace: &Path, destination: &Path) -> FleetResult<()> {
        run(
            "git",
            &["worktree", "add", "--detach"],
            workspace,
            Some(destination),
        )
    }
    fn release(&self, workspace: &Path, destination: &Path) -> FleetResult<()> {
        run("git", &["worktree", "remove"], workspace, Some(destination))
    }
}
pub struct JujutsuWorkspace;
impl IsolationBackend for JujutsuWorkspace {
    fn prepare(&self, workspace: &Path, destination: &Path) -> FleetResult<()> {
        run("jj", &["workspace", "add"], workspace, Some(destination))
    }
    fn release(&self, workspace: &Path, destination: &Path) -> FleetResult<()> {
        let name = destination
            .file_name()
            .ok_or_else(|| FleetPolicyError::IsolationFailed("workspace has no name".into()))?;
        run(
            "jj",
            &["workspace", "forget"],
            workspace,
            Some(Path::new(name)),
        )?;
        std::fs::remove_dir_all(destination)?;
        Ok(())
    }
}
/// Portable private-directory copy isolation. The fallback copies file contents;
/// hosts can register a cloning backend when filesystem CoW is available.
pub struct CopyOnWriteDir;
impl IsolationBackend for CopyOnWriteDir {
    fn prepare(&self, workspace: &Path, destination: &Path) -> FleetResult<()> {
        copy_directory(workspace, destination)
    }
    fn release(&self, _workspace: &Path, destination: &Path) -> FleetResult<()> {
        std::fs::remove_dir_all(destination)?;
        Ok(())
    }
}
pub struct ContainerOrMicroVmMount;
impl IsolationBackend for ContainerOrMicroVmMount {
    fn prepare(&self, _workspace: &Path, _destination: &Path) -> FleetResult<()> {
        Err(FleetPolicyError::IsolationFailed(
            "mount provisioning requires a registered runtime backend".into(),
        ))
    }
    fn release(&self, _workspace: &Path, _destination: &Path) -> FleetResult<()> {
        Err(FleetPolicyError::IsolationFailed(
            "mount release requires a registered runtime backend".into(),
        ))
    }
}
pub struct ArtifactSubdirOnly;
impl IsolationBackend for ArtifactSubdirOnly {
    fn prepare(&self, _workspace: &Path, destination: &Path) -> FleetResult<()> {
        std::fs::create_dir(destination)?;
        Ok(())
    }
    fn release(&self, _workspace: &Path, _destination: &Path) -> FleetResult<()> {
        Ok(())
    }
}
/// A zero-write-authority lease. This does not constitute an OS sandbox for an
/// untrusted executable; such executables require a registered runtime backend.
pub struct ReadOnly;
impl IsolationBackend for ReadOnly {
    fn prepare(&self, _workspace: &Path, _destination: &Path) -> FleetResult<()> {
        Ok(())
    }
    fn release(&self, _workspace: &Path, _destination: &Path) -> FleetResult<()> {
        Ok(())
    }
}

pub fn validate_write_pattern(pattern: &str) -> FleetResult<()> {
    chinwag_claim::path_lease::validate_root(pattern)
        .map_err(|e| FleetPolicyError::WriteScopeDenied(e.to_string()))
}
pub fn authorize_write_roots(requested: &[String], allowed: &[String]) -> FleetResult<()> {
    for requested in requested {
        validate_write_pattern(requested)?;
        let covered = allowed.iter().any(|allowed| {
            if allowed == requested {
                return true;
            }
            allowed.strip_suffix("/**").is_some_and(|base| {
                let request = requested.strip_suffix("/**").unwrap_or(requested);
                request
                    .strip_prefix(base)
                    .is_some_and(|tail| tail.starts_with('/'))
            })
        });
        if !covered {
            return Err(FleetPolicyError::WriteScopeDenied(requested.clone()));
        }
    }
    Ok(())
}
pub fn check_repo_holds(manifest: &FleetManifest, mode: WriteMode, cwd: &Path) -> FleetResult<()> {
    if mode == WriteMode::ReadOnly {
        return Ok(());
    }
    let canonical = cwd.canonicalize()?;
    for candidate in canonical.ancestors() {
        if candidate.join(".git").exists() || candidate.join(".jj").exists() {
            if candidate != canonical {
                return Err(FleetPolicyError::WriteScopeDenied(
                    "mutating execution cwd must be the repository root".into(),
                ));
            }
            break;
        }
    }
    for rule in &manifest.policy.repo_holds {
        if rule.active
            && canonical.ancestors().any(|candidate| {
                pattern_matches(&rule.repo_pattern, &candidate.to_string_lossy())
                    || candidate.file_name().is_some_and(|file| {
                        pattern_matches(&rule.repo_pattern, &file.to_string_lossy())
                    })
            })
        {
            return Err(FleetPolicyError::RepoHoldActive(rule.reason.clone()));
        }
    }
    Ok(())
}
pub fn prepare_execution_sandbox(
    manifest: &FleetManifest,
    plan: &ResolvedDispatchPlan,
    claim_root: &Path,
    seat_actor: &str,
) -> FleetResult<WorkspaceLeaseReceipt> {
    let implementation = backend(&plan.isolation);
    prepare_execution_sandbox_with_backend(
        manifest,
        plan,
        claim_root,
        seat_actor,
        implementation.as_ref(),
    )
}

/// Hosts register their mount/container backend explicitly through this boundary.
pub fn prepare_execution_sandbox_with_backend(
    manifest: &FleetManifest,
    plan: &ResolvedDispatchPlan,
    claim_root: &Path,
    seat_actor: &str,
    implementation: &dyn IsolationBackend,
) -> FleetResult<WorkspaceLeaseReceipt> {
    plan.verify_policy(true)?;
    manifest.validate()?;
    crate::validate_actor(&plan.seat, seat_actor)?;
    if plan.manifest_digest != manifest.digest()? {
        return Err(FleetPolicyError::InvalidManifest(
            "dispatch plan manifest mismatch".into(),
        ));
    }
    let seat = manifest
        .seat(plan.seat.as_str())
        .ok_or_else(|| FleetPolicyError::UnknownSeat(plan.seat.to_string()))?;
    if !seat.lifecycle.is_active() {
        return Err(FleetPolicyError::RetiredOrPausedSeat(plan.seat.to_string()));
    }
    if plan.isolation != seat.isolation || plan.write_mode != seat.write_mode {
        return Err(FleetPolicyError::WriteScopeDenied(
            "plan isolation disagrees with seat policy".into(),
        ));
    }
    authorize_write_roots(&plan.allowed_write_roots, &seat.allowed_write_roots)?;
    check_repo_holds(manifest, plan.write_mode, &plan.cwd)?;
    if plan.write_mode == WriteMode::Isolated && matches!(plan.isolation, IsolationSpec::ReadOnly) {
        return Err(FleetPolicyError::WriteScopeDenied(
            "mutating seat requires an isolation backend".into(),
        ));
    }
    let workspace = plan.cwd.canonicalize()?;
    for root in &plan.allowed_write_roots {
        let path = workspace.join(root.strip_suffix("/**").unwrap_or(root));
        reject_existing_symlinks(&path)?;
    }
    let store = PathLeaseStore::open(claim_root).map_err(lease_error)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| FleetPolicyError::IsolationFailed(e.to_string()))?
        .as_nanos();
    let claim_id = chinwag_claim::encode_hex(&chinwag_claim::sha256(
        format!(
            "{}\n{}\n{}\n{timestamp}",
            std::process::id(),
            seat_actor,
            workspace.display()
        )
        .as_bytes(),
    ));
    let default_root = claim_root.join("sandboxes");
    let root = match &plan.isolation {
        IsolationSpec::GitWorktree { root }
        | IsolationSpec::JujutsuWorkspace { root }
        | IsolationSpec::CopyOnWriteDir { root } => root
            .as_ref()
            .map(|p| manifest.resolve_path(p, &workspace))
            .unwrap_or(default_root),
        IsolationSpec::ContainerOrMicroVmMount { root }
        | IsolationSpec::ArtifactSubdirOnly { root } => manifest.resolve_path(root, &workspace),
        IsolationSpec::ReadOnly => workspace.clone(),
    };
    let isolated_cwd = if matches!(plan.isolation, IsolationSpec::ReadOnly) {
        workspace.clone()
    } else {
        root.join(&claim_id)
    };
    if matches!(plan.isolation, IsolationSpec::CopyOnWriteDir { .. })
        && isolated_cwd.starts_with(&workspace)
    {
        return Err(FleetPolicyError::IsolationFailed(
            "copy destination must be outside source repository".into(),
        ));
    }
    let base_revision = read_base_revision(&workspace);
    let metadata = BTreeMap::from([
        ("backend".into(), plan.isolation.name().into()),
        (
            "isolated_cwd".into(),
            isolated_cwd.to_string_lossy().into_owned(),
        ),
        ("manifest_digest".into(), plan.manifest_digest.clone()),
        (
            "base_revision".into(),
            base_revision.clone().unwrap_or_default(),
        ),
    ]);
    let lease = store
        .acquire(&PathLeaseRequest {
            claim_id: claim_id.clone(),
            actor: seat_actor.into(),
            repository: workspace.clone(),
            roots: plan.allowed_write_roots.clone(),
            metadata,
        })
        .map_err(lease_error)?;
    let preparation = (|| {
        if !matches!(plan.isolation, IsolationSpec::ReadOnly) {
            std::fs::create_dir_all(&root)?;
            reject_symlinks(&root)?;
        }
        implementation.prepare(&workspace, &isolated_cwd)
    })();
    if let Err(error) = preparation {
        store.release(&lease, true).map_err(lease_error)?;
        return Err(error);
    }
    let receipt = WorkspaceLeaseReceipt {
        backend: plan.isolation.name().into(),
        isolated_cwd,
        claim_id,
        allowed_write_roots: plan.allowed_write_roots.clone(),
        base_revision,
        seat_actor: seat_actor.into(),
        lease,
    };
    verify_execution_sandbox(claim_root, &receipt)?;
    Ok(receipt)
}
pub fn verify_execution_sandbox(
    claim_root: &Path,
    receipt: &WorkspaceLeaseReceipt,
) -> FleetResult<()> {
    let request = &receipt.lease.request;
    if receipt.claim_id != request.claim_id
        || receipt.seat_actor != request.actor
        || receipt.allowed_write_roots != request.roots
        || request.metadata.get("backend") != Some(&receipt.backend)
        || request.metadata.get("isolated_cwd")
            != Some(&receipt.isolated_cwd.to_string_lossy().into_owned())
        || request.metadata.get("base_revision")
            != Some(&receipt.base_revision.clone().unwrap_or_default())
    {
        return Err(FleetPolicyError::IsolationFailed(
            "lease receipt mismatch".into(),
        ));
    }
    reject_symlinks(&receipt.isolated_cwd)?;
    PathLeaseStore::open(claim_root)
        .map_err(lease_error)?
        .verify(&receipt.lease)
        .map_err(lease_error)
}
pub fn release_execution_sandbox(
    claim_root: &Path,
    receipt: &WorkspaceLeaseReceipt,
    quarantine: bool,
) -> FleetResult<()> {
    let implementation: Box<dyn IsolationBackend> = match receipt.backend.as_str() {
        "git_worktree" => Box::new(GitWorktree),
        "jujutsu_workspace" => Box::new(JujutsuWorkspace),
        "copy_on_write_dir" => Box::new(CopyOnWriteDir),
        "container_or_micro_vm_mount" => Box::new(ContainerOrMicroVmMount),
        "artifact_subdir_only" => Box::new(ArtifactSubdirOnly),
        "read_only" => Box::new(ReadOnly),
        _ => {
            return Err(FleetPolicyError::IsolationFailed(
                "unknown lease backend".into(),
            ));
        }
    };
    release_execution_sandbox_with_backend(claim_root, receipt, quarantine, implementation.as_ref())
}

pub fn release_execution_sandbox_with_backend(
    claim_root: &Path,
    receipt: &WorkspaceLeaseReceipt,
    quarantine: bool,
    implementation: &dyn IsolationBackend,
) -> FleetResult<()> {
    verify_execution_sandbox(claim_root, receipt)?;
    let store = PathLeaseStore::open(claim_root).map_err(lease_error)?;
    if !quarantine
        && let Err(error) =
            implementation.release(&receipt.lease.request.repository, &receipt.isolated_cwd)
    {
        store.release(&receipt.lease, true).map_err(lease_error)?;
        return Err(error);
    }
    store
        .release(&receipt.lease, quarantine)
        .map_err(lease_error)
}
fn backend(spec: &IsolationSpec) -> Box<dyn IsolationBackend> {
    match spec {
        IsolationSpec::ReadOnly => Box::new(ReadOnly),
        IsolationSpec::GitWorktree { .. } => Box::new(GitWorktree),
        IsolationSpec::JujutsuWorkspace { .. } => Box::new(JujutsuWorkspace),
        IsolationSpec::CopyOnWriteDir { .. } => Box::new(CopyOnWriteDir),
        IsolationSpec::ContainerOrMicroVmMount { .. } => Box::new(ContainerOrMicroVmMount),
        IsolationSpec::ArtifactSubdirOnly { .. } => Box::new(ArtifactSubdirOnly),
    }
}
fn lease_error(error: PathLeaseError) -> FleetPolicyError {
    match error {
        PathLeaseError::OverlappingClaim(id) => FleetPolicyError::OverlappingClaim(id),
        other => FleetPolicyError::IsolationFailed(other.to_string()),
    }
}
fn run(binary: &str, args: &[&str], cwd: &Path, destination: Option<&Path>) -> FleetResult<()> {
    let mut command = Command::new(crate::resolve_binary(binary)?);
    let private_home = tempfile::TempDir::new()?;
    let hooks = private_home.path().join("hooks");
    std::fs::create_dir(&hooks)?;
    configure_utility_environment(&mut command, private_home.path(), &hooks);
    command.args(args).current_dir(cwd);
    if let Some(destination) = destination {
        command.arg(destination);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(FleetPolicyError::IsolationFailed(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(())
}
fn configure_utility_environment(command: &mut Command, private_home: &Path, hooks: &Path) {
    let path = std::env::var_os("PATH");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    command
        .env("HOME", private_home)
        .env("XDG_CONFIG_HOME", private_home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "")
        .env("GIT_CONFIG_SYSTEM", "")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", hooks)
        .env("GIT_CONFIG_KEY_1", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_1", "false");
}
fn reject_symlinks(path: &Path) -> FleetResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if std::fs::symlink_metadata(&current)?
            .file_type()
            .is_symlink()
        {
            return Err(FleetPolicyError::IsolationFailed(
                "symlink sandbox path".into(),
            ));
        }
    }
    Ok(())
}
fn reject_existing_symlinks(path: &Path) -> FleetResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(FleetPolicyError::WriteScopeDenied(
                    "symlink write root".into(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn copy_directory(source: &Path, destination: &Path) -> FleetResult<()> {
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" || name == ".chinwag" {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(FleetPolicyError::IsolationFailed(
                "symlinks are not copied into execution sandboxes".into(),
            ));
        }
        if file_type.is_dir() {
            copy_directory(&entry.path(), &destination.join(name))?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), destination.join(name))?;
        }
    }
    Ok(())
}

fn read_base_revision(workspace: &Path) -> Option<String> {
    let git = workspace.join(".git");
    let git = if git.is_file() {
        let link = std::fs::read_to_string(&git).ok()?;
        let path = Path::new(link.trim().strip_prefix("gitdir: ")?);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            workspace.join(path)
        }
    } else {
        git
    };
    let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    let revision = if let Some(reference) = head.strip_prefix("ref: ") {
        if !reference.starts_with("refs/")
            || reference
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return None;
        }
        std::fs::read_to_string(git.join(reference)).ok()?
    } else {
        head.to_owned()
    };
    let revision = revision.trim();
    if [40, 64].contains(&revision.len()) && revision.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(revision.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(command: &mut Command, home: &Path, hooks: &Path) -> std::process::Output {
        configure_utility_environment(command, home, hooks);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    #[test]
    fn utility_environment_removes_foreign_repository_and_config_overrides() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let hooks = root.join("hooks");
        std::fs::create_dir(&hooks).unwrap();
        let binary = crate::resolve_binary("git").unwrap();
        let selected = root.join("selected");
        let foreign = root.join("foreign");
        for repository in [&selected, &foreign] {
            git(
                Command::new(&binary)
                    .args(["init", "--quiet", "--template="])
                    .arg(repository)
                    .current_dir(&root),
                &root,
                &hooks,
            );
        }
        let output = git(
            Command::new(&binary)
                .args(["rev-parse", "--show-toplevel"])
                .current_dir(&selected)
                .env("GIT_DIR", foreign.join(".git"))
                .env("GIT_WORK_TREE", &foreign)
                .env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "core.bare")
                .env("GIT_CONFIG_VALUE_0", "true")
                .env("HOME", &foreign),
            &root,
            &hooks,
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            selected.to_string_lossy()
        );
    }

    #[cfg(unix)]
    #[test]
    fn worktree_provisioning_disables_host_hooks_and_releases_cleanly() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repository = root.join("repository");
        let empty_hooks = root.join("empty-hooks");
        std::fs::create_dir(&empty_hooks).unwrap();
        let binary = crate::resolve_binary("git").unwrap();
        git(
            Command::new(&binary)
                .args(["init", "--quiet", "--template="])
                .arg(&repository)
                .current_dir(&root),
            &root,
            &empty_hooks,
        );
        git(
            Command::new(&binary)
                .args([
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@invalid",
                    "commit",
                    "--allow-empty",
                    "--quiet",
                    "-m",
                    "fixture",
                ])
                .current_dir(&repository),
            &root,
            &empty_hooks,
        );
        let host_hooks = repository.join(".git/hooks");
        std::fs::create_dir(&host_hooks).unwrap();
        let hook = host_hooks.join("post-checkout");
        std::fs::write(&hook, "#!/bin/sh\nexit 93\n").unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        let destination = root.join("sandbox");
        GitWorktree.prepare(&repository, &destination).unwrap();
        assert!(destination.join(".git").is_file());
        GitWorktree.release(&repository, &destination).unwrap();
        assert!(!destination.exists());
    }
}
