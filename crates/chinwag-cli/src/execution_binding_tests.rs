use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[derive(Clone)]
pub(crate) struct FixtureOptions {
    pub workspace_id: String,
    pub repo_id: String,
    pub worktree_id: String,
    pub source_root: Option<PathBuf>,
    pub source_id: String,
    pub source_generation: u64,
    pub canonical_task_path: String,
    pub integration_target: String,
    pub initial_files: Vec<(String, Vec<u8>)>,
}
impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            workspace_id: "scheduler-fixture".into(),
            repo_id: "repository-fixture".into(),
            worktree_id: "fixture-executor".into(),
            source_root: None,
            source_id: "00000000000000000000000000000001".into(),
            source_generation: 1,
            canonical_task_path: "source-1.md".into(),
            integration_target: "refs/heads/main".into(),
            initial_files: Vec::new(),
        }
    }
}
pub(crate) struct BindingFixture {
    _root: TempDir,
    _source: TempDir,
    root: PathBuf,
    source: PathBuf,
    store: PathBuf,
    enrollment: Enrollment,
    generation: Cell<u64>,
    source_generation: Cell<u64>,
    epoch: Cell<u64>,
}
fn fixture_git(root: &Path, args: &[&str]) {
    let mut c = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            c.env_remove(key);
        }
    }
    let output = c
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "controlled temporary Git fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
impl BindingFixture {
    pub(crate) fn new() -> Self {
        Self::with_options(FixtureOptions::default())
    }
    pub(crate) fn with_options(options: FixtureOptions) -> Self {
        let temporary = TempDir::new().unwrap();
        let source_temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let source = options
            .source_root
            .unwrap_or_else(|| fs::canonicalize(source_temp.path()).unwrap());
        fixture_git(&root, &["init", "--initial-branch=main"]);
        fixture_git(&root, &["config", "user.name", "Controlled Fixture"]);
        fixture_git(&root, &["config", "user.email", "fixture@example.invalid"]);
        fs::write(root.join("code.rs"), b"fixture code\n").unwrap();
        fixture_git(&root, &["add", "code.rs"]);
        fixture_git(&root, &["commit", "-m", "controlled baseline"]);
        fs::create_dir(root.join(".chinwag")).unwrap();
        fs::set_permissions(root.join(".chinwag"), fs::Permissions::from_mode(0o700)).unwrap();
        for (relative, bytes) in options.initial_files {
            let path = Path::new(&relative);
            assert!(
                !path.is_absolute() && path.components().all(|c| matches!(c, Component::Normal(_)))
            );
            assert!(!path.components().any(|c| c.as_os_str() == ".git"));
            assert!(!relative.starts_with(".chinwag/state.crdb"));
            let target = root.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(target, bytes).unwrap();
        }
        chinwag_snapshot_session_private::initial_create::fresh_empty_store_image_for_private_fixture().unwrap().begin_private_fixture(&root).unwrap().finish().unwrap();
        let store = root.join(".chinwag/state.crdb");
        let selected = select_repository(RepoSelectors {
            explicit_repo: Some(&root),
            environment_repo: None,
            cwd: &root,
        })
        .unwrap();
        let source_pin = HeldDir::open(&source).unwrap();
        let image = HeldFile::open(&store, MAX_IMAGE).unwrap();
        let receipt =
            chinwag_snapshot_session_private::validate_detached_private_image(&image.bytes)
                .unwrap();
        let (baseline, branch) = git_state(&selected.root, &selected.git).unwrap();
        let enrollment = Enrollment {
            workspace: options.workspace_id,
            repo: options.repo_id,
            worktree: options.worktree_id,
            root: root.clone(),
            root_id: selected.root.id,
            gitdir: selected.git.gitdir.id,
            common: selected.git.common.id,
            generation: 1,
            authority_epoch: 1,
            baseline,
            branch,
            integration_target: options.integration_target,
            overlay: overlay(&selected.root, &selected.git, &store).unwrap(),
            source: SourceEnrollment {
                root: source.clone(),
                identity: source_pin.id,
                root_generation: 1,
                source_id: options.source_id,
                source_generation: options.source_generation,
                path: options.canonical_task_path,
            },
            store: StoreEnrollment {
                id: "fixture-store".into(),
                path: store.clone(),
                identity: image.snapshot.id,
                parent: image.parent.id,
                image: image.digest,
                site: receipt.site_id(),
                application: receipt.application_id(),
                schema: receipt.schema_version(),
            },
        };
        Self {
            _root: temporary,
            _source: source_temp,
            root,
            source,
            store,
            enrollment,
            generation: Cell::new(1),
            source_generation: Cell::new(1),
            epoch: Cell::new(1),
        }
    }
    pub(crate) fn selection(&self) -> RepositorySelection {
        select_repository(RepoSelectors {
            explicit_repo: Some(&self.root),
            environment_repo: None,
            cwd: &self.root,
        })
        .unwrap()
    }
    pub(crate) fn authority(&self) -> ExecutionAuthority<'_> {
        ExecutionAuthority {
            profile: Some(TrustedFixtureAuthority {
                enrollment: &self.enrollment,
                generation: &self.generation,
                source_generation: &self.source_generation,
                epoch: &self.epoch,
            }),
        }
    }
    pub(crate) fn store_selector(&self) -> StoreSelector<'_> {
        StoreSelector {
            explicit_crdb: Some(&self.store),
        }
    }
    pub(crate) fn bind(&self) -> WorkspaceExecutionBinding {
        bind_execution(&self.selection(), self.store_selector(), &self.authority()).unwrap()
    }
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn source_root(&self) -> &Path {
        &self.source
    }
    pub(crate) fn store_path(&self) -> &Path {
        &self.store
    }
    pub(crate) fn baseline(&self) -> GitOid {
        self.enrollment.baseline
    }
    pub(crate) fn bump_generation(&self) {
        self.generation.set(self.generation.get() + 1)
    }
    pub(crate) fn bump_source_generation(&self) {
        self.source_generation.set(self.source_generation.get() + 1)
    }
    pub(crate) fn bump_epoch(&self) {
        self.epoch.set(self.epoch.get() + 1)
    }
}

#[test]
fn p009_binding_fixture_is_nondefault_and_source_root_is_separate() {
    let f = BindingFixture::new();
    let b = f.bind();
    assert_eq!(b.execution_root(), f.root());
    assert_eq!(b.store_path(), f.store_path());
    assert_ne!(b.source_root(), b.execution_root());
    assert_eq!(b.baseline(), f.baseline());
    assert!(validate_id(&b.commitment_id(), "binding id").is_ok());
    b.revalidate(&f.authority()).unwrap();
}
#[test]
fn p009_public_unsupported_refuses_before_store_read_or_native_import() {
    let f = BindingFixture::new();
    let missing = f.root().join("does-not-exist.crdb");
    assert!(matches!(
        bind_execution(
            &f.selection(),
            StoreSelector {
                explicit_crdb: Some(&missing)
            },
            &ExecutionAuthority::unsupported()
        ),
        Err(BindingError::Unsupported)
    ));
    assert!(!missing.exists());
}
#[test]
fn p009_selector_precedence_never_falls_through_invalid_explicit_or_environment() {
    let f = BindingFixture::new();
    let bad = Path::new("relative");
    assert!(matches!(
        select_repository(RepoSelectors {
            explicit_repo: Some(bad),
            environment_repo: Some(f.root().as_os_str()),
            cwd: f.root()
        }),
        Err(BindingError::InvalidSelector)
    ));
    assert!(matches!(
        select_repository(RepoSelectors {
            explicit_repo: None,
            environment_repo: Some(OsStr::new("")),
            cwd: f.root()
        }),
        Err(BindingError::InvalidSelector)
    ));
    assert_eq!(
        select_repository(RepoSelectors {
            explicit_repo: Some(f.root()),
            environment_repo: Some(OsStr::new("relative")),
            cwd: Path::new("/missing")
        })
        .unwrap()
        .root(),
        f.root()
    );
}
#[test]
fn p009_live_generation_source_generation_epoch_and_untracked_bytes_fence_effects() {
    for change in 0..4 {
        let f = BindingFixture::new();
        let b = f.bind();
        match change {
            0 => f.bump_generation(),
            1 => f.bump_source_generation(),
            2 => f.bump_epoch(),
            _ => fs::write(f.root().join(".chinwag/uncontrolled"), b"bytes").unwrap(),
        };
        assert!(b.revalidate(&f.authority()).is_err());
    }
}
#[test]
fn p009_root_store_parent_and_store_file_replacements_refuse() {
    for parent in [false, true] {
        let f = BindingFixture::new();
        let b = f.bind();
        if parent {
            fs::rename(f.root().join(".chinwag"), f.root().join("old-private")).unwrap();
            fs::create_dir(f.root().join(".chinwag")).unwrap();
            fs::copy(f.root().join("old-private/state.crdb"), f.store_path()).unwrap();
        } else {
            fs::copy(f.store_path(), f.root().join("replacement.crdb")).unwrap();
            fs::rename(f.root().join("replacement.crdb"), f.store_path()).unwrap();
        }
        assert!(b.revalidate(&f.authority()).is_err());
    }
}
#[test]
fn p009_branch_head_overlay_and_store_selectors_are_exact() {
    let f = BindingFixture::new();
    let b = f.bind();
    fixture_git(f.root(), &["checkout", "-b", "other"]);
    assert!(matches!(
        b.revalidate(&f.authority()),
        Err(BindingError::BranchChanged)
    ));
    let f = BindingFixture::new();
    let wrong = f.root().join("other.crdb");
    assert!(matches!(
        bind_execution(
            &f.selection(),
            StoreSelector {
                explicit_crdb: Some(&wrong)
            },
            &f.authority()
        ),
        Err(BindingError::StoreSelector)
    ));
    assert!(!wrong.exists());
    let f = BindingFixture::new();
    let b = f.bind();
    fs::write(f.root().join("code.rs"), b"changed tracked bytes").unwrap();
    assert!(matches!(
        b.revalidate(&f.authority()),
        Err(BindingError::OverlayChanged)
    ));
}

#[test]
fn p009_commitment_encodes_every_store_mapping_field_and_unambiguous_strings() {
    let f = BindingFixture::new();
    let original = enrollment_bytes(&f.enrollment).unwrap();
    for changed in 0..8 {
        let mut e = f.enrollment.clone();
        match changed {
            0 => e.store.path = f.root().join(".chinwag/other.crdb"),
            1 => e.store.identity.1 += 1,
            2 => e.store.parent.1 += 1,
            3 => e.store.site[0] ^= 1,
            4 => e.store.application += 1,
            5 => e.store.schema += 1,
            6 => e.store.id.push('2'),
            _ => e.source.root_generation += 1,
        }
        assert_ne!(enrollment_bytes(&e).unwrap(), original);
    }
    let mut a = f.enrollment.clone();
    let mut b = a.clone();
    a.workspace = "a|b".into();
    a.repo = "c".into();
    b.workspace = "a".into();
    b.repo = "b|c".into();
    assert_ne!(enrollment_bytes(&a).unwrap(), enrollment_bytes(&b).unwrap());
}
#[test]
fn p009_introduced_store_control_marker_refuses_before_next_effect() {
    for suffix in ["lock", "intent", "next"] {
        let f = BindingFixture::new();
        let b = f.bind();
        fs::write(
            f.root().join(format!(".chinwag/state.crdb.{suffix}")),
            b"foreign original operation",
        )
        .unwrap();
        let effects = Cell::new(0);
        let result = (|| -> BindingResult<()> {
            b.revalidate(&f.authority())?;
            effects.set(1);
            Ok(())
        })();
        assert!(matches!(result, Err(BindingError::StoreChanged)));
        assert_eq!(effects.get(), 0);
        assert!(
            f.root()
                .join(format!(".chinwag/state.crdb.{suffix}"))
                .exists()
        );
    }
}
#[test]
fn p009_same_native_image_under_different_enrolled_store_mapping_changes_commitment() {
    let mut f = BindingFixture::new();
    let original = f.bind();
    let new_path = f.root().join(".chinwag/other.crdb");
    fs::copy(f.store_path(), &new_path).unwrap();
    fs::set_permissions(&new_path, fs::Permissions::from_mode(0o600)).unwrap();
    let new = HeldFile::open(&new_path, MAX_IMAGE).unwrap();
    assert_eq!(new.digest, f.enrollment.store.image);
    f.enrollment.store.path = new_path;
    f.enrollment.store.identity = new.snapshot.id;
    f.enrollment.store.parent = new.parent.id;
    let selected = f.selection();
    f.enrollment.overlay =
        overlay(&selected.root, &selected.git, &f.enrollment.store.path).unwrap();
    let changed = bind_execution(
        &selected,
        StoreSelector {
            explicit_crdb: Some(&f.enrollment.store.path),
        },
        &f.authority(),
    )
    .unwrap();
    assert_ne!(original.commitment_id(), changed.commitment_id());
}

#[test]
fn p009_linked_worktree_has_distinct_root_gitdir_and_shared_common_directory() {
    let f = BindingFixture::new();
    let worktree = TempDir::new().unwrap();
    let linked = fs::canonicalize(worktree.path()).unwrap().join("linked");
    fixture_git(
        f.root(),
        &["worktree", "add", "--detach", linked.to_str().unwrap()],
    );
    let main = f.selection();
    let selected = select_repository(RepoSelectors {
        explicit_repo: Some(&linked),
        environment_repo: None,
        cwd: f.root(),
    })
    .unwrap();
    assert_ne!(selected.root.id, main.root.id);
    assert_ne!(selected.git.gitdir.id, main.git.gitdir.id);
    assert_eq!(selected.git.common.id, main.git.common.id);
    assert!(selected.git.gitfile.is_some());
    assert!(selected.git.commonfile.is_some());
    selected.revalidate().unwrap();
    fs::write(linked.join(".git"), b"gitdir: /missing-mapping\n").unwrap();
    assert!(selected.revalidate().is_err());
}
#[test]
fn p009_nearest_nested_unenrolled_repository_cannot_fall_back_to_outer_enrollment() {
    let f = BindingFixture::new();
    let nested = f.root().join("nested");
    fs::create_dir(&nested).unwrap();
    fixture_git(&nested, &["init", "--initial-branch=main"]);
    let cwd = nested.join("inside");
    fs::create_dir(&cwd).unwrap();
    let selected = select_repository(RepoSelectors {
        explicit_repo: None,
        environment_repo: None,
        cwd: &cwd,
    })
    .unwrap();
    assert_eq!(selected.root(), nested);
    assert!(matches!(
        bind_execution(&selected, f.store_selector(), &f.authority()),
        Err(BindingError::Unenrolled)
    ));
}
#[test]
fn p009_detached_head_requires_exact_private_profile_approval() {
    let mut f = BindingFixture::new();
    fixture_git(f.root(), &["checkout", "--detach"]);
    assert!(matches!(
        bind_execution(&f.selection(), f.store_selector(), &f.authority()),
        Err(BindingError::BranchChanged)
    ));
    f.enrollment.branch = BranchBinding::Detached;
    let binding = f.bind();
    assert_eq!(binding.branch_binding(), &BranchBinding::Detached);
    assert_eq!(
        binding.branch_metadata(),
        format!("detached:{}", binding.baseline())
    );
}
#[test]
#[ignore = "Owned child only: inherited Git environment isolation fixture"]
fn p009_git_environment_probe_child() {
    let root = PathBuf::from(std::env::var_os("P009_PRIVATE_REPO").unwrap());
    let selected = select_repository(RepoSelectors {
        explicit_repo: Some(&root),
        environment_repo: None,
        cwd: &root,
    })
    .unwrap();
    let (baseline, branch) = git_state(&selected.root, &selected.git).unwrap();
    assert_eq!(
        baseline.to_string(),
        std::env::var("P009_EXPECTED_BASELINE").unwrap()
    );
    assert_eq!(branch, BranchBinding::Branch("refs/heads/main".into()));
}
#[test]
fn p009_inherited_git_environment_and_fake_path_cannot_select_another_repository() {
    let f = BindingFixture::new();
    let fake = TempDir::new().unwrap();
    let fake_git = fake.path().join("git");
    fs::write(&fake_git, b"#!/bin/sh\nexit 98\n").unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "execution_binding::test_support::p009_git_environment_probe_child",
            "--ignored",
            "--nocapture",
        ])
        .env("P009_PRIVATE_REPO", f.root())
        .env("P009_EXPECTED_BASELINE", f.baseline().to_string())
        .env("PATH", fake.path())
        .env("GIT_DIR", "/definitely-wrong-git-dir")
        .env("GIT_WORK_TREE", "/definitely-wrong-worktree")
        .env("GIT_INDEX_FILE", "/definitely-wrong-index")
        .env("GIT_OBJECT_DIRECTORY", "/definitely-wrong-objects")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "/never-execute")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn p009_local_git_include_is_refused_before_any_execution_effect() {
    use std::io::Write;
    let f = BindingFixture::new();
    let b = f.bind();
    let mut config = fs::OpenOptions::new()
        .append(true)
        .open(f.root().join(".git/config"))
        .unwrap();
    config
        .write_all(b"\n[include]\n path = /never-read-unapproved-config\n")
        .unwrap();
    drop(config);
    assert!(matches!(
        b.revalidate(&f.authority()),
        Err(BindingError::UnsupportedGitConfig)
    ));
}
#[test]
fn p009_git_config_allows_harmless_include_substrings_and_rejects_includeif_directives() {
    use std::io::Write;
    let f = BindingFixture::new();
    let b = f.bind();
    let config_path = f.root().join(".git/config");
    let baseline_cfg = fs::read(&config_path).unwrap();

    let mut config = fs::OpenOptions::new()
        .append(true)
        .open(&config_path)
        .unwrap();
    config
        .write_all(
            b"\n# This clone includes generated files\n; include comment\n[remote \"origin\"]\n\turl = https://example.com/include-chinwag.git\n\tnote = \"[include]\"\n",
        )
        .unwrap();
    drop(config);
    b.revalidate(&f.authority()).unwrap();
    f.selection().verify_effective_toplevel().unwrap();

    for directive in [
        b"\n[includeIf \"gitdir:~/work/\"]\n\tpath = /never-read\n".as_slice(),
        b"\n[Include.sub]\n\tpath = /never-read\n".as_slice(),
    ] {
        let mut next = baseline_cfg.clone();
        next.extend_from_slice(directive);
        fs::write(&config_path, &next).unwrap();
        assert!(matches!(
            b.revalidate(&f.authority()),
            Err(BindingError::UnsupportedGitConfig)
        ));
        assert!(matches!(
            f.selection().verify_effective_toplevel(),
            Err(BindingError::UnsupportedGitConfig)
        ));
    }
}
#[test]
fn p009_wrong_native_application_schema_and_site_refuse_before_effects() {
    for variant in 0..3 {
        let mut f = BindingFixture::new();
        if variant < 2 {
            let mut bytes = fs::read(f.store_path()).unwrap();
            let offset = if variant == 0 { 68 } else { 60 };
            bytes[offset..offset + 4].copy_from_slice(&0_u32.to_be_bytes());
            fs::write(f.store_path(), &bytes).unwrap();
            f.enrollment.store.image = Sha256Digest::of(&bytes);
        } else {
            f.enrollment.store.site[0] ^= 1;
        }
        let effects = Cell::new(0);
        let result =
            with_execution_binding(&f.selection(), f.store_selector(), &f.authority(), |_| {
                effects.set(1);
                Ok(())
            });
        assert!(result.is_err());
        assert_eq!(effects.get(), 0);
        assert!(!f.root().join(".chinwag/state.crdb.lock").exists());
        assert!(!f.root().join(".chinwag/state.crdb.next").exists());
    }
}
#[test]
fn p009_execution_root_and_source_root_replacements_refuse_without_fallback() {
    let f = BindingFixture::new();
    let binding = f.bind();
    fs::rename(
        f.root(),
        f.source_root().join("retained-old-execution-root"),
    )
    .unwrap();
    fs::create_dir(f.root()).unwrap();
    assert!(binding.revalidate(&f.authority()).is_err());
    let f = BindingFixture::new();
    let binding = f.bind();
    fs::rename(f.source_root(), f.root().join("old-source-root")).unwrap();
    fs::create_dir(f.source_root()).unwrap();
    assert!(binding.revalidate(&f.authority()).is_err());
}

#[test]
fn p009_private_store_custody_mode_is_checked_before_native_import() {
    for parent in [false, true] {
        let f = BindingFixture::new();
        let path = if parent {
            f.root().join(".chinwag")
        } else {
            f.store_path().to_path_buf()
        };
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if parent { 0o755 } else { 0o644 }),
        )
        .unwrap();
        let effects = Cell::new(0);
        let result =
            with_execution_binding(&f.selection(), f.store_selector(), &f.authority(), |_| {
                effects.set(1);
                Ok(())
            });
        // Parent permissions also participate in the approved overlay. Either
        // that earlier refusal or the explicit store-custody refusal is valid.
        assert!(result.is_err());
        assert_eq!(effects.get(), 0);
        assert!(!f.root().join(".chinwag/state.crdb.lock").exists());
    }
}

#[test]
fn p009_commondir_absent_to_present_redirect_refuses_retained_contexts() {
    fn copy_owned_git_metadata(from: &Path, to: &Path) {
        fs::create_dir(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            let kind = entry.file_type().unwrap();
            assert!(
                !kind.is_symlink(),
                "fixture metadata must be ordinary owned data"
            );
            if kind.is_dir() {
                copy_owned_git_metadata(&entry.path(), &target)
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }
    let f = BindingFixture::new();
    let selected = f.selection();
    let binding = f.bind();
    assert!(selected.git.commonfile.is_none());
    let before = safe_git(f.root(), &["rev-parse", "--git-common-dir"]).unwrap();
    let foreign = f.source_root().join("owned-foreign-common");
    copy_owned_git_metadata(&f.root().join(".git"), &foreign);
    fs::write(
        f.root().join(".git/commondir"),
        format!("{}\n", foreign.display()),
    )
    .unwrap();
    let actual_common = safe_git(f.root(), &["rev-parse", "--git-common-dir"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&actual_common).unwrap().trim(),
        foreign.to_str().unwrap()
    );
    assert_ne!(actual_common, before);
    let head = safe_git(f.root(), &["rev-parse", "--verify", "HEAD^{commit}"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&head).unwrap().trim(),
        f.baseline().to_string()
    );
    println!(
        "owned common-dir redirect proved; old={}, new={}, unchanged HEAD={}",
        String::from_utf8_lossy(&before).trim(),
        String::from_utf8_lossy(&actual_common).trim(),
        String::from_utf8_lossy(&head).trim()
    );
    let selection_result = selected.revalidate();
    let effects = Cell::new(0);
    let binding_result = (|| -> BindingResult<()> {
        binding.revalidate(&f.authority())?;
        effects.set(1);
        Ok(())
    })();
    assert!(
        selection_result.is_err() && binding_result.is_err() && effects.get() == 0,
        "retained metadata must refuse redirection: selection={selection_result:?}, binding={binding_result:?}, effects={}",
        effects.get()
    );
}

#[test]
fn p009_local_core_worktree_redirect_refuses_before_execution_effect() {
    use std::io::Write;

    let f = BindingFixture::new();
    let binding = f.bind();
    let before = safe_git(f.root(), &["rev-parse", "--show-toplevel"]).unwrap();
    let foreign = f.source_root().join("foreign-executor-root");
    fs::create_dir(&foreign).unwrap();
    let mut config = fs::OpenOptions::new()
        .append(true)
        .open(f.root().join(".git/config"))
        .unwrap();
    writeln!(config, "\n[core]\n\tworktree = {}", foreign.display()).unwrap();
    config.sync_all().unwrap();

    let actual = safe_git(f.root(), &["rev-parse", "--show-toplevel"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&actual).unwrap().trim(),
        foreign.to_str().unwrap()
    );
    assert_ne!(actual, before);
    let head = safe_git(f.root(), &["rev-parse", "--verify", "HEAD^{commit}"]).unwrap();
    assert_eq!(
        std::str::from_utf8(&head).unwrap().trim(),
        f.baseline().to_string()
    );
    println!(
        "owned core.worktree redirect proved; old={}, new={}, unchanged HEAD={}",
        String::from_utf8_lossy(&before).trim(),
        String::from_utf8_lossy(&actual).trim(),
        String::from_utf8_lossy(&head).trim()
    );
    let effects = Cell::new(0);
    let result = (|| -> BindingResult<()> {
        binding.revalidate(&f.authority())?;
        effects.set(1);
        Ok(())
    })();
    assert!(
        result.is_err() && effects.get() == 0,
        "effective Git worktree must remain the bound root: result={result:?}, effects={}",
        effects.get()
    );
}
