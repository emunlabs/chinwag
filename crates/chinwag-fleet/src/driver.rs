// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Deterministic policy resolution and an explicit local subprocess driver.
#![forbid(unsafe_code)]
use crate::{
    EgressPolicy, ExecutionTarget, FleetManifest, FleetPolicyError, FleetResult, IsolationSpec,
    ModelBinding, NodeTransport, SeatId, SkillResolver, WriteMode, pattern_matches,
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
    },
    GoogleGenAiHttp {
        endpoint_mode: String,
        base_url_or_region: String,
        auth_env: String,
        stream_mode: String,
    },
    AnthropicMessagesHttp {
        base_url: String,
        auth_env: String,
        #[serde(default)]
        beta_headers: Vec<String>,
        stream_mode: String,
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
    let allowed_skills =
        SkillResolver::resolve(manifest, seat, &request.requested_skills, &request.cwd)?;
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
        DriverSpec::OpenAiCompatibleHttp { base_url, .. }
        | DriverSpec::AnthropicMessagesHttp { base_url, .. } => {
            check_egress(&manifest.policy.egress_policy, base_url)?
        }
        DriverSpec::GoogleGenAiHttp {
            base_url_or_region, ..
        } => check_egress(&manifest.policy.egress_policy, base_url_or_region)?,
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
        if !matches!(plan.target, ExecutionTarget::LocalProcess) {
            return Err(FleetPolicyError::UnsupportedDriver(
                "no execution backend registered for selected target".into(),
            ));
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
            return Err(FleetPolicyError::UnsupportedDriver(
                "HTTP driver requires a registered implementation".into(),
            ));
        };
        let executable = resolve_binary(executable)?;
        let mut command = Command::new(executable);
        for arg in argv_template {
            command.arg(expand(arg, plan, context)?);
        }
        command.current_dir(&plan.cwd);
        configure_env(
            &mut command,
            plan,
            context,
            auth_isolation,
            env_allowlist,
            env_overrides,
        )?;
        if let CredentialIsolation::FirstPartyCliOauth { preflight_cmd, .. } = auth_isolation
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
            let (status, _, _) = wait_timeout(&mut child, *timeout_secs, None, true)?;
            if !status.success() {
                return Err(FleetPolicyError::DriverExecutionFailed(
                    "authentication preflight failed".into(),
                ));
            }
        }
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
            *timeout_secs,
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
fn expand(
    arg: &str,
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
) -> FleetResult<String> {
    let mut arg = arg
        .replace("{model}", &plan.model.model_id)
        .replace("{provider}", &plan.model.provider)
        .replace("{seat}", plan.seat.as_str())
        .replace("{cwd}", &plan.cwd.to_string_lossy())
        .replace("{prompt}", context.prompt.as_deref().unwrap_or(""));
    for (key, value) in &plan.model.params {
        arg = arg.replace(
            &format!("{{param:{key}}}"),
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string())
                .as_str(),
        );
    }
    if arg.contains("{param:") {
        return Err(FleetPolicyError::InvalidManifest(
            "unbound model parameter template".into(),
        ));
    }
    Ok(arg)
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
    if let Some(node) = &plan.resolved_node {
        command.env("CHINWAG_TARGET_NODE", node);
    }
    Ok(())
}
