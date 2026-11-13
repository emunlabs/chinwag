// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Deterministic policy resolution and an explicit local subprocess driver.
#![forbid(unsafe_code)]
use crate::{
    EgressPolicy, ExecutionTarget, FleetManifest, FleetPolicyError, FleetResult, IsolationSpec,
    ModelBinding, NodeTransport, RemoteProtocol, SeatId, SkillResolver, WriteMode, pattern_matches,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DriverSpec {
    CliSubprocess {
        executable: String,
        #[serde(default)]
        argv_template: Vec<String>,
        #[serde(default)]
        auth_isolation: CredentialIsolation,
        #[serde(default)]
        env_allowlist: Vec<String>,
        #[serde(default)]
        env_overrides: BTreeMap<String, String>,
        #[serde(default = "stdin_framing")]
        framing: String,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },
    OpenAiCompatibleHttp {
        base_url: String,
        api_key_env: String,
        wire_mode: String,
        stream_mode: String,
        timeout_secs: u64,
        #[serde(default)]
        auth_isolation: CredentialIsolation,
        #[serde(default)]
        tools: crate::http_driver::HttpToolConfig,
    },
    GoogleGenAiHttp {
        endpoint_mode: String,
        base_url_or_region: String,
        auth_env: String,
        stream_mode: String,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        #[serde(default)]
        auth_isolation: CredentialIsolation,
        #[serde(default)]
        tools: crate::http_driver::HttpToolConfig,
    },
    AnthropicMessagesHttp {
        base_url: String,
        auth_env: String,
        #[serde(default)]
        beta_headers: Vec<String>,
        stream_mode: String,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
        #[serde(default)]
        auth_isolation: CredentialIsolation,
        #[serde(default)]
        tools: crate::http_driver::HttpToolConfig,
    },
}
fn stdin_framing() -> String {
    "stdin".into()
}
fn default_timeout() -> u64 {
    300
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialIsolation {
    FirstPartyCliOauth {
        #[serde(default)]
        scrub_env: Vec<String>,
        #[serde(default)]
        preflight_cmd: Vec<String>,
    },
    SecretEnvFile {
        path: PathBuf,
        #[serde(default)]
        key_map: BTreeMap<String, String>,
    },
    #[default]
    NoneLocal,
}

#[derive(Clone, Debug)]
pub struct DispatchRequest {
    pub seat: String,
    pub room: Option<String>,
    pub task_profile: Option<String>,
    pub cwd: PathBuf,
    pub requested_skills: Vec<String>,
    pub requested_write_globs: Vec<String>,
    pub actor: Option<String>,
}
impl Default for DispatchRequest {
    fn default() -> Self {
        Self {
            seat: String::new(),
            room: None,
            task_profile: None,
            cwd: PathBuf::from("."),
            requested_skills: Vec::new(),
            requested_write_globs: Vec::new(),
            actor: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedDispatchPlan {
    pub seat: SeatId,
    pub driver: DriverSpec,
    pub target: ExecutionTarget,
    pub model: ModelBinding,
    pub allowed_skills: Vec<String>,
    pub allowed_write_roots: Vec<String>,
    pub write_mode: WriteMode,
    pub isolation: IsolationSpec,
    pub cwd: PathBuf,
    pub manifest_digest: String,
    pub resolved_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_dir: Option<PathBuf>,
    #[serde(skip)]
    pub resolved_skill_files: Vec<(String, PathBuf)>,
    #[serde(skip)]
    pub boot_files: Vec<String>,
    #[serde(skip)]
    resolved_cwd: PathBuf,
    #[serde(skip)]
    policy_digest: String,
    #[serde(skip)]
    execution_lease: Option<(PathBuf, crate::WorkspaceLeaseReceipt)>,
}
impl ResolvedDispatchPlan {
    fn policy_digest(&self) -> FleetResult<String> {
        let bytes = serde_jcs::to_vec(self)
            .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?;
        Ok(chinwag_claim::encode_hex(&chinwag_claim::sha256(&bytes)))
    }
    pub(crate) fn verify_policy(&self, preparing: bool) -> FleetResult<()> {
        if self.policy_digest != self.policy_digest()?
            || (preparing && self.cwd != self.resolved_cwd)
        {
            return Err(FleetPolicyError::InvalidManifest(
                "dispatch plan was modified after resolution".into(),
            ));
        }
        Ok(())
    }
    /// Relocate only to the exact workspace authorized by an active durable lease.
    pub fn with_sandbox(
        mut self,
        claim_root: &Path,
        receipt: &crate::WorkspaceLeaseReceipt,
    ) -> FleetResult<Self> {
        self.verify_policy(false)?;
        crate::verify_execution_sandbox(claim_root, receipt)?;
        crate::validate_actor(&self.seat, &receipt.seat_actor)?;
        if receipt.repository() != self.resolved_cwd
            || receipt.allowed_write_roots != self.allowed_write_roots
            || receipt.manifest_digest() != Some(self.manifest_digest.as_str())
            || receipt.backend != self.isolation.name()
        {
            return Err(FleetPolicyError::IsolationFailed(
                "sandbox lease does not bind this dispatch plan".into(),
            ));
        }
        self.cwd = receipt.isolated_cwd.clone();
        self.execution_lease = Some((claim_root.to_path_buf(), receipt.clone()));
        self.policy_digest = self.policy_digest()?;
        Ok(self)
    }
}

pub fn resolve_dispatch_plan(
    manifest: &FleetManifest,
    request: &DispatchRequest,
) -> FleetResult<ResolvedDispatchPlan> {
    manifest.validate()?;
    let mut effective = request.clone();
    if let Some(name) = &request.task_profile {
        let profile = manifest
            .task_profiles
            .get(name)
            .ok_or_else(|| FleetPolicyError::UnknownTaskProfile(name.clone()))?;
        effective
            .requested_skills
            .extend(profile.requested_skills.iter().cloned());
        effective
            .requested_write_globs
            .extend(profile.requested_write_globs.iter().cloned());
        effective.requested_skills.sort();
        effective.requested_skills.dedup();
        effective.requested_write_globs.sort();
        effective.requested_write_globs.dedup();
    }
    let request = &effective;
    let seat = manifest
        .seat(&request.seat)
        .ok_or_else(|| FleetPolicyError::UnknownSeat(request.seat.clone()))?;
    if !seat.lifecycle.is_active() {
        return Err(FleetPolicyError::RetiredOrPausedSeat(seat.id.to_string()));
    }
    if let Some(actor) = &request.actor {
        validate_actor(&seat.id, actor)?;
    }
    if manifest
        .policy
        .deny_providers
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&seat.model.provider))
    {
        return Err(FleetPolicyError::ProviderDenied(
            seat.model.provider.clone(),
        ));
    }
    if let Some(room) = &request.room {
        if seat
            .allowed_rooms
            .as_ref()
            .is_some_and(|rooms| !rooms.iter().any(|p| pattern_matches(p, room)))
        {
            return Err(FleetPolicyError::RoomAclDenied(room.clone()));
        }
        if !manifest.policy.room_acls.is_empty() {
            // Overlapping rules may narrow access, never accidentally grant it.
            let matches: Vec<_> = manifest
                .policy
                .room_acls
                .iter()
                .filter(|(pattern, _)| pattern_matches(pattern, room))
                .collect();
            if matches.is_empty() || matches.iter().any(|(_, seats)| !seats.contains(&seat.id)) {
                return Err(FleetPolicyError::RoomAclDenied(room.clone()));
            }
        }
    } else if seat.allowed_rooms.is_some() || !manifest.policy.room_acls.is_empty() {
        return Err(FleetPolicyError::RoomAclDenied(
            "room is required by policy".into(),
        ));
    }
    let resolved_skill_files =
        SkillResolver::resolve_files(manifest, seat, &request.requested_skills, &request.cwd)?;
    let allowed_skills = resolved_skill_files
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let profile_dir = seat
        .profile_dir
        .as_ref()
        .map(|dir| resolve_clean_directory(&manifest.resolve_path(dir, &request.cwd)))
        .transpose()?;
    crate::isolation::authorize_write_roots(
        &request.requested_write_globs,
        &seat.allowed_write_roots,
    )?;
    if seat.write_mode == WriteMode::ReadOnly && !request.requested_write_globs.is_empty() {
        return Err(FleetPolicyError::WriteScopeDenied("read-only seat".into()));
    }
    crate::isolation::check_repo_holds(manifest, seat.write_mode, &request.cwd)?;
    let mut resolved_node = None;
    match &seat.target_selector {
        ExecutionTarget::MeshPeerSelector {
            required_labels,
            preferred_labels,
        } => {
            let mut nodes: Vec<_> = manifest
                .nodes
                .iter()
                .filter(|n| {
                    n.capabilities.max_concurrency != Some(0)
                        && required_labels
                            .iter()
                            .all(|(k, v)| n.labels.get(k) == Some(v))
                })
                .collect();
            nodes.sort_by_key(|n| {
                (
                    std::cmp::Reverse(
                        preferred_labels
                            .iter()
                            .filter(|(k, v)| n.labels.get(*k) == Some(*v))
                            .count(),
                    ),
                    &n.node_id,
                )
            });
            let node = nodes
                .first()
                .ok_or_else(|| FleetPolicyError::TargetNodeUnavailable(seat.id.to_string()))?;
            if let NodeTransport::Endpoint { endpoint, .. } = &node.transport {
                check_egress(&manifest.policy.egress_policy, endpoint)?;
            }
            resolved_node = Some(node.node_id.clone());
        }
        ExecutionTarget::RemoteExec {
            endpoint_template, ..
        } => check_egress(&manifest.policy.egress_policy, endpoint_template)?,
        ExecutionTarget::CloudSandbox { provider, .. } => {
            check_egress(&manifest.policy.egress_policy, provider)?
        }
        _ => {}
    }
    let mut driver = seat.driver.clone();
    match &mut driver {
        DriverSpec::CliSubprocess {
            executable,
            auth_isolation,
            timeout_secs,
            ..
        } => {
            if *timeout_secs == 0 {
                return Err(FleetPolicyError::InvalidManifest(
                    "timeout_secs must be positive".into(),
                ));
            }
            if matches!(seat.target_selector, ExecutionTarget::LocalProcess) {
                let candidate = Path::new(executable);
                let name = if candidate.components().count() > 1 && candidate.is_relative() {
                    manifest
                        .resolve_path(candidate, &request.cwd)
                        .to_string_lossy()
                        .into_owned()
                } else {
                    executable.clone()
                };
                *executable = resolve_binary(&name)?.to_string_lossy().into_owned();
            }
            if let CredentialIsolation::SecretEnvFile { path, .. } = auth_isolation {
                *path = manifest.resolve_path(path, &request.cwd);
                crate::keys::validate_private_key_path(path)?;
            }
        }
        DriverSpec::OpenAiCompatibleHttp {
            base_url,
            timeout_secs,
            auth_isolation,
            tools,
            ..
        }
        | DriverSpec::AnthropicMessagesHttp {
            base_url,
            timeout_secs,
            auth_isolation,
            tools,
            ..
        } => {
            if *timeout_secs == 0 {
                return Err(FleetPolicyError::InvalidManifest(
                    "timeout_secs must be positive".into(),
                ));
            }
            check_egress(&manifest.policy.egress_policy, base_url)?;
            resolve_driver_credentials(manifest, &request.cwd, auth_isolation, tools)?;
        }
        DriverSpec::GoogleGenAiHttp {
            base_url_or_region,
            timeout_secs,
            auth_isolation,
            tools,
            ..
        } => {
            if *timeout_secs == 0 {
                return Err(FleetPolicyError::InvalidManifest(
                    "timeout_secs must be positive".into(),
                ));
            }
            check_egress(&manifest.policy.egress_policy, base_url_or_region)?;
            resolve_driver_credentials(manifest, &request.cwd, auth_isolation, tools)?;
        }
    }
    let cwd = request.cwd.canonicalize()?;
    let mut plan = ResolvedDispatchPlan {
        seat: seat.id.clone(),
        driver,
        target: seat.target_selector.clone(),
        model: seat.model.clone(),
        allowed_skills,
        allowed_write_roots: request.requested_write_globs.clone(),
        write_mode: seat.write_mode,
        isolation: seat.isolation.clone(),
        cwd: cwd.clone(),
        manifest_digest: manifest.digest()?,
        resolved_node,
        profile_dir,
        resolved_skill_files,
        boot_files: seat.boot_files.clone(),
        resolved_cwd: cwd,
        policy_digest: String::new(),
        execution_lease: None,
    };
    plan.policy_digest = plan.policy_digest()?;
    Ok(plan)
}

pub fn validate_actor(seat: &SeatId, actor: &str) -> FleetResult<()> {
    let Some((name, instance)) = actor.split_once('#') else {
        return Err(FleetPolicyError::BareSeatAddressRejected(actor.into()));
    };
    if name != seat.as_str()
        || instance.is_empty()
        || instance.len() > 128
        || !instance
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(FleetPolicyError::BareSeatAddressRejected(actor.into()));
    }
    Ok(())
}
fn check_egress(policy: &EgressPolicy, endpoint: &str) -> FleetResult<()> {
    let allowed = match policy {
        EgressPolicy::Unrestricted => true,
        EgressPolicy::DenyAll => false,
        EgressPolicy::AllowList { endpoints } => endpoints.iter().any(|e| {
            endpoint == e
                || endpoint
                    .strip_prefix(e)
                    .is_some_and(|tail| tail.starts_with('/'))
        }),
    };
    if allowed {
        Ok(())
    } else {
        Err(FleetPolicyError::EgressViolation(endpoint.into()))
    }
}
pub fn resolve_binary(executable: &str) -> FleetResult<PathBuf> {
    let supplied = Path::new(executable);
    let candidates = if supplied.components().count() > 1 || supplied.is_absolute() {
        vec![supplied.to_path_buf()]
    } else {
        std::env::var_os("PATH")
            .map(|p| {
                std::env::split_paths(&p)
                    .map(|d| d.join(executable))
                    .collect()
            })
            .unwrap_or_default()
    };
    for path in candidates {
        if let Ok(metadata) = path.metadata() {
            if !metadata.is_file() {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return Ok(path.canonicalize()?);
        }
    }
    Err(FleetPolicyError::DriverBinaryMissing(executable.into()))
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionContext {
    pub env: BTreeMap<String, String>,
    pub prompt: Option<String>,
    pub interactive: bool,
    /// Remove ambient/manifest credential namespaces before trusted context is installed.
    pub scrub_env_prefixes: Vec<String>,
    pub timeout_override_secs: Option<u64>,
    pub max_turns_override: Option<usize>,
    pub max_output_tokens_override: Option<u32>,
    pub tools_disabled: bool,
    pub seat_docs_disabled: bool,
}
/// Fail-closed token accounting across HTTP driver turns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpUsageSummary {
    pub usage_status: String,
    pub turns: u32,
    pub tool_calls: u32,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub cached_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub gross_tokens: Option<u64>,
    #[serde(default)]
    pub observed_partial_gross_tokens: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    pub exit_code: Option<i32>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub termination_signal: Option<i32>,
    pub output_limit_exceeded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<HttpUsageSummary>,
}
pub trait ExecutionDriver {
    fn execute(
        &self,
        plan: &ResolvedDispatchPlan,
        context: &ExecutionContext,
    ) -> FleetResult<ExecutionOutcome>;
}
pub struct ProcessExecutionDriver;
impl ExecutionDriver for ProcessExecutionDriver {
    fn execute(
        &self,
        plan: &ResolvedDispatchPlan,
        context: &ExecutionContext,
    ) -> FleetResult<ExecutionOutcome> {
        self.execute_with_started(plan, context, |_| {})
    }
}
impl ProcessExecutionDriver {
    pub fn execute_with_started(
        &self,
        plan: &ResolvedDispatchPlan,
        context: &ExecutionContext,
        on_started: impl FnOnce(u32),
    ) -> FleetResult<ExecutionOutcome> {
        plan.verify_policy(false)?;
        if let Some((root, receipt)) = &plan.execution_lease {
            crate::verify_execution_sandbox(root, receipt)?;
        } else if plan.write_mode != WriteMode::ReadOnly {
            return Err(FleetPolicyError::WriteScopeDenied(
                "mutating execution requires an active sandbox lease".into(),
            ));
        }
        if context.timeout_override_secs == Some(0) {
            return Err(FleetPolicyError::InvalidManifest(
                "timeout_secs must be positive".into(),
            ));
        }
        match &plan.driver {
            DriverSpec::OpenAiCompatibleHttp { .. }
            | DriverSpec::GoogleGenAiHttp { .. }
            | DriverSpec::AnthropicMessagesHttp { .. } => {
                if !matches!(plan.target, ExecutionTarget::LocalProcess) {
                    return Err(FleetPolicyError::UnsupportedDriver(
                        "HTTP drivers require a local execution point".into(),
                    ));
                }
                return crate::http_driver::execute_http_driver(plan, context, on_started);
            }
            DriverSpec::CliSubprocess { .. } => {}
        }
        let DriverSpec::CliSubprocess {
            executable,
            argv_template,
            auth_isolation,
            env_allowlist,
            env_overrides,
            framing,
            timeout_secs,
        } = &plan.driver
        else {
            unreachable!();
        };
        let effective_timeout = context.timeout_override_secs.unwrap_or(*timeout_secs);
        let needs_composed_prompt = argv_template
            .iter()
            .any(|arg| arg.contains("{composed_prompt}"))
            || framing == "composed_stdin";
        let composed_prompt = if needs_composed_prompt {
            Some(compose_prompt(plan, context)?)
        } else {
            None
        };
        let mut command = match &plan.target {
            ExecutionTarget::LocalProcess => {
                let executable = resolve_binary(executable)?;
                let mut cmd = Command::new(executable);
                for arg in argv_template {
                    cmd.arg(expand(arg, plan, context, composed_prompt.as_deref())?);
                }
                cmd.current_dir(&plan.cwd);
                configure_env(
                    &mut cmd,
                    plan,
                    context,
                    auth_isolation,
                    env_allowlist,
                    env_overrides,
                )?;
                if let CredentialIsolation::FirstPartyCliOauth { preflight_cmd, .. } =
                    auth_isolation
                    && let Some((binary, args)) = preflight_cmd.split_first()
                {
                    let mut preflight = Command::new(resolve_binary(binary)?);
                    preflight
                        .args(args)
                        .current_dir(&plan.cwd)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::CommandExt;
                        preflight.process_group(0);
                    }
                    configure_env(
                        &mut preflight,
                        plan,
                        context,
                        auth_isolation,
                        env_allowlist,
                        env_overrides,
                    )?;
                    let mut child = preflight.spawn()?;
                    let (status, _, _) = wait_timeout(&mut child, effective_timeout, None, true)?;
                    if !status.success() {
                        return Err(FleetPolicyError::DriverExecutionFailed(
                            "authentication preflight failed".into(),
                        ));
                    }
                }
                cmd
            }
            ExecutionTarget::RemoteExec {
                protocol: RemoteProtocol::Ssh,
                endpoint_template,
                workdir_template,
            } => build_ssh_command(
                plan,
                context,
                endpoint_template,
                workdir_template,
                executable,
                argv_template,
                auth_isolation,
                env_allowlist,
                env_overrides,
                composed_prompt.as_deref(),
            )?,
            _ => {
                return Err(FleetPolicyError::UnsupportedDriver(
                    "no execution backend registered for selected target".into(),
                ));
            }
        };
        let mut stdout = tempfile::tempfile()?;
        let mut stderr = tempfile::tempfile()?;
        if context.interactive {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        } else {
            // Anonymous files avoid pipe deadlocks when descendants retain FDs;
            // output is monitored during execution and bounded when read back.
            let mut input = tempfile::tempfile()?;
            if framing == "stdin" {
                input.write_all(context.prompt.as_deref().unwrap_or("").as_bytes())?;
            } else if framing == "composed_stdin" {
                input.write_all(composed_prompt.as_deref().unwrap_or("").as_bytes())?;
            }
            input.seek(SeekFrom::Start(0))?;
            command
                .stdin(Stdio::from(input))
                .stdout(Stdio::from(stdout.try_clone()?))
                .stderr(Stdio::from(stderr.try_clone()?));
        }
        #[cfg(unix)]
        if !context.interactive {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn()?;
        on_started(child.id());
        let (status, timed_out, output_limit_exceeded) = wait_timeout(
            &mut child,
            effective_timeout,
            Some((&stdout, &stderr)),
            !context.interactive,
        )?;
        let stdout = read_output(&mut stdout)?;
        let stderr = read_output(&mut stderr)?;
        #[cfg(unix)]
        let termination_signal = {
            use std::os::unix::process::ExitStatusExt;
            status.signal()
        };
        #[cfg(not(unix))]
        let termination_signal = None;
        Ok(ExecutionOutcome {
            exit_code: status.code(),
            success: status.success() && !timed_out && !output_limit_exceeded,
            stdout,
            stderr,
            timed_out,
            termination_signal,
            output_limit_exceeded,
            usage: None,
        })
    }
}
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;
fn read_output(file: &mut File) -> FleetResult<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_CAPTURE_BYTES).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
fn wait_timeout(
    child: &mut std::process::Child,
    seconds: u64,
    output: Option<(&File, &File)>,
    own_process_group: bool,
) -> FleetResult<(std::process::ExitStatus, bool, bool)> {
    let start = Instant::now();
    loop {
        let output_limit_exceeded = if let Some((stdout, stderr)) = output {
            stdout.metadata()?.len() > MAX_CAPTURE_BYTES
                || stderr.metadata()?.len() > MAX_CAPTURE_BYTES
        } else {
            false
        };
        if let Some(status) = child.try_wait()? {
            return Ok((status, false, output_limit_exceeded));
        }
        let timed_out = start.elapsed() >= Duration::from_secs(seconds);
        if timed_out || output_limit_exceeded {
            #[cfg(unix)]
            {
                if own_process_group
                    && let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32)
                {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
            }
            // A concurrent natural exit may race the timeout; wait still gives
            // the real terminal status rather than an invocation-unknown DTO.
            let _ = child.kill();
            let status = child.wait()?;
            return Ok((status, timed_out, output_limit_exceeded));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
/// Verify every path component is free of symlinks and resolves to a directory.
pub fn resolve_clean_directory(path: &Path) -> FleetResult<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(FleetPolicyError::InvalidManifest(format!(
                "symlink profile_dir: {}",
                path.display()
            )));
        }
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(FleetPolicyError::InvalidManifest(format!(
            "profile_dir must be a regular directory: {}",
            path.display()
        )));
    }
    Ok(path.canonicalize()?)
}

/// Load workspace-relative boot files while rejecting symlinks and traversal escapes.
pub fn load_seat_boot_files(
    base_dir: &Path,
    boot_files: &[String],
) -> FleetResult<Vec<(PathBuf, String)>> {
    let canonical_base = base_dir.canonicalize()?;
    let mut loaded = Vec::with_capacity(boot_files.len());
    for relative_path in boot_files {
        let mut path = canonical_base.clone();
        for component in Path::new(relative_path).components() {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err(FleetPolicyError::InvalidManifest(
                    "boot_file_invalid".into(),
                ));
            }
            path.push(component);
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                FleetPolicyError::InvalidManifest(format!("boot_file_unavailable: {error}"))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(FleetPolicyError::InvalidManifest(
                    "boot_file_invalid".into(),
                ));
            }
        }
        if !path.canonicalize()?.starts_with(&canonical_base) {
            return Err(FleetPolicyError::InvalidManifest(
                "boot_file_invalid".into(),
            ));
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            FleetPolicyError::InvalidManifest(format!("boot_file_unavailable: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(FleetPolicyError::InvalidManifest(
                "boot_file_invalid".into(),
            ));
        }
        let text = std::fs::read_to_string(&path).map_err(|error| {
            FleetPolicyError::InvalidManifest(format!("boot_file_unavailable: {error}"))
        })?;
        loaded.push((path, text));
    }
    Ok(loaded)
}

pub(crate) fn compose_prompt(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
) -> FleetResult<String> {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "Seat: {}", plan.seat.as_str());
    let _ = writeln!(
        out,
        "Model: {}/{}",
        plan.model.provider, plan.model.model_id
    );
    let _ = writeln!(out, "Working directory: {}", plan.cwd.display());
    if let Some(profile_dir) = &plan.profile_dir {
        let _ = writeln!(out, "Profile directory: {}", profile_dir.display());
    }
    if let Some(directive) = plan
        .model
        .params
        .get("system_directive")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        let _ = writeln!(out, "\nDirective: {}", directive.trim());
    }
    if !context.seat_docs_disabled {
        let boot_base = plan.profile_dir.as_deref().unwrap_or(&plan.cwd);
        for (path, text) in load_seat_boot_files(boot_base, &plan.boot_files)? {
            let _ = write!(out, "\n--- {} ---\n{}", path.display(), text);
            if !text.ends_with('\n') {
                out.push('\n');
            }
        }
        for (skill_name, skill_path) in &plan.resolved_skill_files {
            let text = std::fs::read_to_string(skill_path)?;
            let _ = write!(
                out,
                "\n--- skill: {skill_name} ({}) ---\n{}",
                skill_path.display(),
                text
            );
            if !text.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    if let Some(prompt) = context.prompt.as_deref().filter(|p| !p.is_empty()) {
        let _ = write!(out, "\n## Task\n\n{prompt}");
    }
    Ok(out)
}

pub(crate) fn resolve_driver_credentials(
    manifest: &FleetManifest,
    cwd: &Path,
    auth_isolation: &mut CredentialIsolation,
    tools: &mut crate::http_driver::HttpToolConfig,
) -> FleetResult<()> {
    if let CredentialIsolation::SecretEnvFile { path, .. } = auth_isolation {
        *path = manifest.resolve_path(path, cwd);
        crate::keys::validate_private_key_path(path)?;
    }
    for rule in &mut tools.auth_fetches {
        rule.secret_env_file = manifest.resolve_path(&rule.secret_env_file, cwd);
        crate::keys::validate_private_key_path(&rule.secret_env_file)?;
    }
    for rule in &mut tools.env_injections {
        if let Some(path) = &mut rule.secret_env_file {
            *path = manifest.resolve_path(path, cwd);
            crate::keys::validate_private_key_path(path)?;
        }
    }
    Ok(())
}

pub(crate) fn parse_ssh_endpoint(endpoint_template: &str) -> FleetResult<(String, Option<String>)> {
    let Some(rest) = endpoint_template.strip_prefix("ssh://") else {
        return Err(FleetPolicyError::InvalidManifest(
            "remote_exec endpoint_template must start with ssh://".into(),
        ));
    };
    let rest = rest.trim_end_matches('/');
    if rest.is_empty()
        || rest.starts_with('-')
        || rest
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#'))
    {
        return Err(FleetPolicyError::InvalidManifest(format!(
            "invalid ssh endpoint: {endpoint_template}"
        )));
    }
    if let Some((host_part, port)) = rest.rsplit_once(':') {
        if host_part.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return Err(FleetPolicyError::InvalidManifest(format!(
                "invalid ssh port in endpoint: {endpoint_template}"
            )));
        }
        Ok((host_part.to_owned(), Some(port.to_owned())))
    } else {
        Ok((rest.to_owned(), None))
    }
}

fn posix_shell_quote(value: &str) -> FleetResult<String> {
    if value.contains('\0') {
        return Err(FleetPolicyError::InvalidManifest(
            "NUL byte not permitted in remote shell argument".into(),
        ));
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    Ok(quoted)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_ssh_command(
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    endpoint_template: &str,
    workdir_template: &str,
    executable: &str,
    argv_template: &[String],
    auth_isolation: &CredentialIsolation,
    env_allowlist: &[String],
    env_overrides: &BTreeMap<String, String>,
    composed_prompt: Option<&str>,
) -> FleetResult<Command> {
    if matches!(auth_isolation, CredentialIsolation::SecretEnvFile { .. }) {
        return Err(FleetPolicyError::InvalidManifest(
            "SecretEnvFile credentials cannot be forwarded over SSH remote_exec".into(),
        ));
    }
    let (target, port) = parse_ssh_endpoint(endpoint_template)?;
    let expanded_workdir = expand(workdir_template, plan, context, composed_prompt)?;
    if expanded_workdir.contains(['\0', '\n', '\r']) {
        return Err(FleetPolicyError::InvalidManifest(
            "invalid remote workdir template".into(),
        ));
    }
    if executable.trim().is_empty() || executable.contains(['\0', '\n', '\r']) {
        return Err(FleetPolicyError::InvalidManifest(
            "invalid remote executable".into(),
        ));
    }

    let mut remote_env: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in env_overrides {
        remote_env.insert(k.clone(), v.clone());
    }
    for (k, v) in &context.env {
        remote_env.insert(k.clone(), v.clone());
    }
    for key in [
        "CHINWAG_ALLOWED_SKILLS",
        "CHINWAG_SELECTED_SKILLS",
        "CHINWAG_MODEL_PROVIDER",
        "CHINWAG_MODEL_ID",
        "CHINWAG_FLEET_DIGEST",
    ] {
        let val = match key {
            "CHINWAG_ALLOWED_SKILLS" | "CHINWAG_SELECTED_SKILLS" => plan.allowed_skills.join(","),
            "CHINWAG_MODEL_PROVIDER" => plan.model.provider.clone(),
            "CHINWAG_MODEL_ID" => plan.model.model_id.clone(),
            "CHINWAG_FLEET_DIGEST" => plan.manifest_digest.clone(),
            _ => unreachable!(),
        };
        remote_env.insert(key.to_owned(), val);
    }

    let mut remote_parts = Vec::new();
    if !expanded_workdir.is_empty() && expanded_workdir != "." {
        remote_parts.push(format!("cd -- {} &&", posix_shell_quote(&expanded_workdir)?));
    }
    if !remote_env.is_empty() {
        remote_parts.push("env".to_owned());
        for (k, v) in &remote_env {
            if k.is_empty()
                || !k
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(FleetPolicyError::InvalidManifest(format!(
                    "invalid remote env var name: {k}"
                )));
            }
            remote_parts.push(posix_shell_quote(&format!("{k}={v}"))?);
        }
    }
    remote_parts.push(posix_shell_quote(executable)?);
    for arg in argv_template {
        let expanded = expand(arg, plan, context, composed_prompt)?;
        remote_parts.push(posix_shell_quote(&expanded)?);
    }
    let remote_cmdline = remote_parts.join(" ");

    let ssh_bin = resolve_binary("ssh")?;
    let mut cmd = Command::new(ssh_bin);
    cmd.env_clear();
    for key in [
        "HOME",
        "PATH",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TERM",
        "SSH_AUTH_SOCK",
    ]
    .into_iter()
    .chain(env_allowlist.iter().map(String::as_str))
    {
        if let Some(val) = std::env::var_os(key) {
            cmd.env(key, val);
        }
    }
    cmd.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ]);
    if let Some(port) = port {
        cmd.args(["-p", &port]);
    }
    cmd.args(["--", &target, &remote_cmdline]);
    Ok(cmd)
}

fn expand(
    arg: &str,
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    composed_prompt: Option<&str>,
) -> FleetResult<String> {
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let token = &after_open[..close];
        let replacement: Option<String> = match token {
            "model" => Some(plan.model.model_id.clone()),
            "provider" => Some(plan.model.provider.clone()),
            "seat" => Some(plan.seat.as_str().to_owned()),
            "cwd" => Some(plan.cwd.to_string_lossy().into_owned()),
            "profile_dir" => {
                let dir = plan.profile_dir.as_ref().ok_or_else(|| {
                    FleetPolicyError::InvalidManifest("unbound profile_dir template".into())
                })?;
                Some(dir.to_string_lossy().into_owned())
            }
            "composed_prompt" => Some(
                composed_prompt
                    .unwrap_or_else(|| context.prompt.as_deref().unwrap_or(""))
                    .to_owned(),
            ),
            "prompt" => Some(context.prompt.as_deref().unwrap_or("").to_owned()),
            _ if token.starts_with("param:") => {
                let key = &token["param:".len()..];
                let value = plan.model.params.get(key).ok_or_else(|| {
                    FleetPolicyError::InvalidManifest("unbound model parameter template".into())
                })?;
                Some(
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                )
            }
            _ => None,
        };
        match replacement {
            Some(value) => out.push_str(&value),
            None => {
                out.push('{');
                out.push_str(token);
                out.push('}');
            }
        }
        rest = &after_open[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}
fn configure_env(
    command: &mut Command,
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    isolation: &CredentialIsolation,
    allowlist: &[String],
    overrides: &BTreeMap<String, String>,
) -> FleetResult<()> {
    let actor = context
        .env
        .get("CHINWAG_ACTOR")
        .map(String::as_str)
        .or_else(|| {
            plan.execution_lease
                .as_ref()
                .map(|(_, receipt)| receipt.seat_actor.as_str())
        });
    if let Some(actor) = actor {
        validate_actor(&plan.seat, actor)?;
        if plan
            .execution_lease
            .as_ref()
            .is_some_and(|(_, receipt)| receipt.seat_actor != actor)
        {
            return Err(FleetPolicyError::BareSeatAddressRejected(
                "context actor disagrees with sandbox owner".into(),
            ));
        }
    }
    command.env_clear();
    for key in allowlist {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.envs(overrides);
    if let CredentialIsolation::SecretEnvFile { path, key_map } = isolation {
        crate::keys::validate_private_key_path(path)?;
        for line in std::fs::read_to_string(path)?
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let (key, value) = line.split_once('=').ok_or_else(|| {
                FleetPolicyError::InvalidManifest("invalid credential env file".into())
            })?;
            if let Some(target) = key_map.get(key) {
                if target.starts_with("CHINWAG_") {
                    return Err(FleetPolicyError::InvalidManifest(
                        "credential env mappings cannot replace execution context".into(),
                    ));
                }
                command.env(target, value);
            }
        }
    }
    let scrubbed: Vec<_> = command
        .get_envs()
        .filter_map(|(key, _)| {
            key.to_str()
                .filter(|key| {
                    context
                        .scrub_env_prefixes
                        .iter()
                        .any(|prefix| key.starts_with(prefix))
                })
                .map(str::to_owned)
        })
        .collect();
    for key in scrubbed {
        command.env_remove(key);
    }
    command.envs(&context.env);
    if let Some(actor) = actor {
        command.env("CHINWAG_ACTOR", actor);
        if let Some((_, instance)) = actor.split_once('#') {
            command.env("CHINWAG_INSTANCE_ID", instance);
        }
    }
    if let CredentialIsolation::FirstPartyCliOauth { scrub_env, .. } = isolation {
        for key in [
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_API_KEY",
        ]
        .into_iter()
        .chain(scrub_env.iter().map(String::as_str))
        {
            command.env_remove(key);
        }
    }
    command
        .env("CHINWAG_ALLOWED_SKILLS", plan.allowed_skills.join(","))
        .env("CHINWAG_SELECTED_SKILLS", plan.allowed_skills.join(","))
        .env(
            "CHINWAG_TARGET",
            serde_json::to_string(&plan.target)
                .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?,
        )
        .env("CHINWAG_MODEL_PROVIDER", &plan.model.provider)
        .env("CHINWAG_MODEL_ID", &plan.model.model_id)
        .env(
            "CHINWAG_MODEL_PARAMS",
            serde_json::to_string(&plan.model.params)
                .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?,
        )
        .env("CHINWAG_FLEET_DIGEST", &plan.manifest_digest);
    if let Some(profile_dir) = &plan.profile_dir {
        command.env("CHINWAG_PROFILE_DIR", profile_dir);
    }
    if let Some(node) = &plan.resolved_node {
        command.env("CHINWAG_TARGET_NODE", node);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_remote_exec_rejects_leading_dash_host_and_quotes_remote_command() {
        let mut manifest = FleetManifest::starter_profile("solo").unwrap();
        manifest.seats[0].lifecycle = crate::SeatLifecycle::ActiveStanding;
        manifest.seats[0].target_selector = ExecutionTarget::RemoteExec {
            protocol: RemoteProtocol::Ssh,
            endpoint_template: "ssh://-oProxyCommand=evil".into(),
            workdir_template: "/tmp/work".into(),
        };
        let plan = resolve_dispatch_plan(
            &manifest,
            &DispatchRequest {
                seat: "default".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let err = build_ssh_command(
            &plan,
            &ExecutionContext::default(),
            "ssh://-oProxyCommand=evil",
            "/tmp/work",
            "/usr/bin/true",
            &[],
            &CredentialIsolation::NoneLocal,
            &[],
            &BTreeMap::new(),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("InvalidManifest"));

        let cmd = build_ssh_command(
            &plan,
            &ExecutionContext::default(),
            "ssh://operator@example.internal:2222",
            "/srv/work",
            "/usr/local/bin/worker",
            &["--prompt".into(), "hi 'there'".into()],
            &CredentialIsolation::NoneLocal,
            &[],
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"-p".to_owned()));
        assert!(args.contains(&"2222".to_owned()));
        assert!(args.contains(&"operator@example.internal".to_owned()));
        assert!(args.last().unwrap().contains("hi '\\''there'\\''"));
    }
}
