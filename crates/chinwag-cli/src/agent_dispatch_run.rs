// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use crate::AgentDispatchRequest;
use crate::execution_binding::{
    ExecutionAuthority, RepoSelectors, StoreSelector, WorkspaceExecutionBinding, bind_execution,
    select_repository,
};
use crate::seat_signing;
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::replacement::{
    AgentDispatchRecord, WriteOwner, WriteSession,
};
use chinwag_snapshot_session_private::{SnapshotSession, Value};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CRDB_TEXT_BYTES: usize = 60_000;

fn user_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned())
}

const MAX_PROMPT_BYTES: usize = 262_144;

#[derive(Debug, Default, Deserialize)]
struct StdinDispatchPayload {
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default, rename = "itemKey")]
    item_key: Option<String>,
    #[serde(default)]
    item: Option<String>,
    #[serde(default)]
    crdb: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    history: Vec<HistoryEntry>,
    #[serde(default, rename = "customAgent")]
    custom_agent: Option<CustomAgentMeta>,
}

#[derive(Debug, Default, Deserialize)]
struct HistoryEntry {
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CustomAgentMeta {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    dept: Option<String>,
    #[serde(default)]
    system_prompt: Option<String>,
}

fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn load_persona(agent: &str, custom: Option<&CustomAgentMeta>) -> String {
    let mut persona = format!("You are {agent}. Follow your configured workspace instructions.");
    if let Some(meta) = custom {
        if let Some(role) = &meta.role {
            persona.push_str(&format!("\nRole: {role}"));
        }
        if let Some(dept) = &meta.dept {
            persona.push_str(&format!("\nGroup: {dept}"));
        }
        if let Some(prompt) = &meta.system_prompt {
            persona.push_str(&format!("\n{prompt}"));
        }
    }
    persona
}

fn check_binding(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
) -> Result<(), String> {
    binding
        .revalidate(authority)
        .map_err(|error| error.to_string())
}

fn native_store_root(binding: &WorkspaceExecutionBinding) -> Result<&Path, String> {
    if binding.store_path() != binding.execution_root().join(".chinwag/state.crdb") {
        return Err("execution_store_adapter_unsupported".into());
    }
    Ok(binding.execution_root())
}

fn recall_native_memory(binding: &WorkspaceExecutionBinding) -> Result<String, String> {
    let root = native_store_root(binding)?;
    let owner = ReadOwner::acquire_existing_private_fixture(root)
        .map_err(|error| format!("memory_read_owner: {}", error.reason))?;
    let session = SnapshotSession::from_owner(owner).map_err(|error| error.to_string())?;
    let read = (|| {
        let mut rows = session.tombstones().map_err(|error| error.to_string())?;
        rows.extend(
            session
                .verified_invariants()
                .map_err(|error| error.to_string())?,
        );
        Ok::<_, String>(
            rows.into_iter()
                .take(8)
                .map(|row| {
                    let text = row
                        .into_iter()
                        .filter_map(|value| match value {
                            Value::Text(text) => Some(text),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(" | ");
                    format!("- {}", truncate_utf8(&text, 360))
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )
    })();
    let closed = session.finish().map_err(|error| error.to_string());
    match (read, closed) {
        (Ok(memory), Ok(_)) => Ok(memory),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

/// Only the fixed signing keys constructed for this bound seat may re-enter
/// the child after all ambient/explicit Git controls have been removed.
#[derive(Default)]
struct BoundGitSigning {
    environment: Vec<(String, String)>,
}
impl BoundGitSigning {
    fn from_generated(
        agent: &str,
        binding: &WorkspaceExecutionBinding,
        signing: &seat_signing::SeatSigning,
    ) -> Result<Self, String> {
        let actual: Vec<_> = signing
            .env
            .iter()
            .filter(|(key, _)| key.starts_with("GIT_"))
            .cloned()
            .collect();
        if actual.is_empty() {
            return Ok(Self::default());
        }
        let slug = seat_signing::seat_slug(agent).ok_or("bound_signing_seat_invalid")?;
        let home = PathBuf::from(user_home());
        let entries = [
            (
                "user.name",
                format!("{} (agent)", agent.to_ascii_uppercase()),
            ),
            ("user.email", seat_signing::SIGNING_EMAIL.to_owned()),
            (
                "user.signingkey",
                home.join(".chinwag/signing")
                    .join(format!("{slug}_ed25519.pub"))
                    .display()
                    .to_string(),
            ),
            ("gpg.format", "ssh".into()),
            ("commit.gpgsign", "true".into()),
            (
                "gpg.ssh.allowedSignersFile",
                binding
                    .execution_root()
                    .join(".chinwag/allowed_signers")
                    .display()
                    .to_string(),
            ),
        ];
        let mut expected = Vec::new();
        for (index, (key, value)) in entries.into_iter().enumerate() {
            expected.push((format!("GIT_CONFIG_KEY_{index}"), key.to_owned()));
            expected.push((format!("GIT_CONFIG_VALUE_{index}"), value));
        }
        expected.push(("GIT_CONFIG_COUNT".into(), "6".into()));
        if actual != expected {
            return Err("bound_signing_configuration_held".into());
        }
        Ok(Self {
            environment: expected,
        })
    }
}

fn bound_execution_environment(
    binding: &WorkspaceExecutionBinding,
    identity: &crate::agent_instance::DispatchIdentity,
    signing: &BoundGitSigning,
) -> std::collections::BTreeMap<String, String> {
    let mut environment = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect::<std::collections::BTreeMap<_, _>>();
    environment.extend(signing.environment.iter().cloned());
    environment.extend(identity.environment());
    environment.extend([
        (
            "CHINWAG_REPO_ROOT".into(),
            binding.execution_root().display().to_string(),
        ),
        (
            "CHINWAG_STORE_PATH".into(),
            binding.store_path().display().to_string(),
        ),
        ("CHINWAG_STORE_ID".into(), binding.store_id().to_owned()),
        (
            "CHINWAG_EXECUTION_BINDING".into(),
            binding.commitment_id().to_owned(),
        ),
        ("CHINWAG_AGENT".into(), identity.child().seat().to_owned()),
    ]);
    environment
}

#[cfg(test)]
fn install_bound_launch_environment(
    command: &mut Command,
    binding: &WorkspaceExecutionBinding,
    identity: &crate::agent_instance::DispatchIdentity,
    signing: &BoundGitSigning,
) {
    let mut names: Vec<_> = std::env::vars_os()
        .map(|(name, _)| name)
        .chain(command.get_envs().map(|(name, _)| name.to_os_string()))
        .filter(|name| {
            let name = name.as_encoded_bytes();
            name.starts_with(b"GIT_") || name.starts_with(b"CHINWAG_")
        })
        .collect();
    names.sort();
    names.dedup();
    for name in names {
        command.env_remove(name);
    }
    command.envs(bound_execution_environment(binding, identity, signing));
}

#[cfg(test)]
fn run_bound_local_command(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
    identity: &crate::agent_instance::DispatchIdentity,
    command: &mut Command,
) -> Result<String, String> {
    run_bound_local_command_with_signing(
        binding,
        authority,
        identity,
        command,
        &BoundGitSigning::default(),
    )
}

#[cfg(test)]
fn run_bound_local_command_with_signing(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
    identity: &crate::agent_instance::DispatchIdentity,
    command: &mut Command,
    signing: &BoundGitSigning,
) -> Result<String, String> {
    check_binding(binding, authority)?;
    command
        .current_dir(binding.execution_root())
        .env("PWD", binding.execution_root());
    install_bound_launch_environment(command, binding, identity, signing);
    check_binding(binding, authority)?;
    let output = command
        .output()
        .map_err(|error| format!("engine_outcome_unknown: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "engine_failed_without_replacement: {:?}",
            output.status.code()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        return Err("engine_empty_reply_without_replacement".into());
    }
    Ok(text)
}

#[cfg(test)]
struct BoundHostedExecutor<'a> {
    binding: &'a WorkspaceExecutionBinding,
    authority: &'a ExecutionAuthority<'a>,
    inner: crate::hosted_agent::StandardToolExecutor,
}
#[cfg(test)]
impl crate::hosted_agent::ToolExecutor for BoundHostedExecutor<'_> {
    fn execute(
        &mut self,
        call: &crate::hosted_agent::ToolCall,
        policy: &crate::hosted_agent::ToolPolicy,
        transport: &mut dyn crate::hosted_agent::HostedTransport,
    ) -> serde_json::Value {
        if let Err(error) = check_binding(self.binding, self.authority) {
            return json!({"ok": false, "error": error, "authority": "HELD"});
        }
        if call.name == "run_command" {
            return json!({"ok": false, "error": "bound_hosted_command_adapter_unsupported", "authority": "HELD"});
        }
        crate::hosted_agent::ToolExecutor::execute(&mut self.inner, call, policy, transport)
    }
}

struct EngineRequest<'a> {
    agent: &'a str,
    prompt: &'a str,
    environment: &'a [(String, String)],
    git_signing: &'a BoundGitSigning,
    identity: &'a crate::agent_instance::DispatchIdentity,
}

fn dispatch_to_engine(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
    request: &EngineRequest<'_>,
) -> Result<(String, &'static str), String> {
    check_binding(binding, authority)?;
    let (_, manifest) = crate::fleet_cmd::load_manifest(None, binding.execution_root())?;
    let plan = chinwag_fleet::resolve_dispatch_plan(
        &manifest,
        &chinwag_fleet::DispatchRequest {
            seat: request.agent.to_owned(),
            requested_write_globs: manifest
                .seat(request.agent)
                .map(|seat| seat.allowed_write_roots.clone())
                .unwrap_or_default(),
            cwd: binding.execution_root().to_owned(),
            actor: Some(request.identity.child().to_string()),
            ..Default::default()
        },
    )
    .map_err(|error| error.to_string())?;
    let mut context = chinwag_fleet::ExecutionContext {
        env: request
            .environment
            .iter()
            .filter(|(name, _)| !name.starts_with("GIT_") && !name.starts_with("CHINWAG_"))
            .cloned()
            .collect(),
        scrub_env_prefixes: vec!["GIT_".into(), "CHINWAG_".into()],
        prompt: Some(request.prompt.to_owned()),
        ..Default::default()
    };
    context.env.extend(bound_execution_environment(
        binding,
        request.identity,
        request.git_signing,
    ));
    check_binding(binding, authority)?;
    let claim_root = binding
        .execution_control_root()
        .join("chinwag-fleet-claims");
    let outcome = crate::fleet_cmd::execute_plan_with_claim_root(
        &manifest,
        &plan,
        &context,
        &request.identity.child().to_string(),
        &claim_root,
        || check_binding(binding, authority),
    )?;
    check_binding(binding, authority)?;
    if !outcome.success {
        return Err(format!(
            "engine_failed_without_replacement: {:?}",
            outcome.exit_code
        ));
    }
    Ok((outcome.stdout, "fleet-manifest-driver"))
}

/// One inbound/outbound dispatch exchange to persist into the CRDB store.
struct DispatchExchange<'a> {
    identity: &'a crate::agent_instance::DispatchIdentity,
    item_key: &'a str,
    inbound_id: &'a str,
    inbound_body: &'a str,
    outbound_id: &'a str,
    outbound_body: &'a str,
    now_ms: i64,
}

/// Merge explicit CLI and stdin context before any persona, signing or engine I/O.
fn prepare_dispatch_identity(
    request: &AgentDispatchRequest,
    payload: &StdinDispatchPayload,
    ambient_actor: Option<&str>,
) -> Result<crate::agent_instance::DispatchIdentity, crate::agent_instance::InstanceError> {
    use crate::agent_instance::{ActorAddress, DispatchIdentity, InstanceError};
    let agent = request
        .agent
        .as_deref()
        .or(payload.agent.as_deref())
        .ok_or(InstanceError::InvalidAddress)?;
    let mut child = ActorAddress::parse(agent)?;
    if child.instance().is_none() {
        child = child.with_instance(&crate::agent_instance::new_instance_id()?)?;
    }
    let sender = request
        .sender
        .as_deref()
        .or(payload.sender.as_deref())
        .or(ambient_actor)
        .ok_or(InstanceError::MissingCaller)?;
    let parent =
        crate::agent_instance::resolve_from_environment(sender, request.instance.as_deref())?;
    DispatchIdentity::new(child, parent)
}

fn persist_to_crdb(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
    exchange: &DispatchExchange<'_>,
) -> Result<(), String> {
    check_binding(binding, authority)?;
    let repo_root = native_store_root(binding)?;
    let DispatchExchange {
        identity,
        item_key,
        inbound_id,
        inbound_body,
        outbound_id,
        outbound_body,
        now_ms,
    } = *exchange;
    let thread_id = identity.child().to_string();
    let mut owner = WriteOwner::acquire_existing_private_fixture(repo_root)
        .map_err(|e| format!("acquire_write_owner: {}", e.reason))?;
    binding
        .revalidate_for_store_owner(authority, &mut owner)
        .map_err(|error| error.to_string())?;
    let mut session =
        WriteSession::from_owner(owner).map_err(|e| format!("write_session: {}", e.reason))?;
    let record = AgentDispatchRecord::try_new(
        thread_id.clone(),
        binding.repo_id().to_owned(),
        binding.branch_metadata(),
        format!("Chinwag Agent Comms · {thread_id} · {item_key}"),
        inbound_id.to_owned(),
        identity.parent().record_author(),
        "user".to_owned(),
        truncate_utf8(inbound_body, MAX_CRDB_TEXT_BYTES),
        outbound_id.to_owned(),
        identity.child().record_author(),
        "assistant".to_owned(),
        truncate_utf8(outbound_body, MAX_CRDB_TEXT_BYTES),
        now_ms,
    )
    .map_err(|e| e.to_owned())?;
    binding
        .revalidate_for_store_owner(authority, &mut session)
        .map_err(|error| error.to_string())?;
    let mut prepared = session
        .prepare_agent_dispatch(record, || false)
        .map_err(|e| format!("prepare_agent_dispatch: {}", e.reason))?;
    binding
        .revalidate_for_store_owner(authority, &mut prepared)
        .map_err(|error| error.to_string())?;
    let completion = prepared
        .commit(false)
        .map_err(|e| format!("commit_agent_dispatch: {}", e.reason))?;
    if completion.is_error() {
        return Err(format!("crdb_refused: {}", completion.response()));
    }
    Ok(())
}

trait AgentRouteEffects {
    fn persona(&mut self, agent: &str, custom: Option<&CustomAgentMeta>) -> Result<String, String>;
    fn memory(&mut self, binding: &WorkspaceExecutionBinding) -> Result<String, String>;
    fn signing(
        &mut self,
        agent: &str,
        binding: &WorkspaceExecutionBinding,
    ) -> seat_signing::SeatSigning;
    fn engine(
        &mut self,
        binding: &WorkspaceExecutionBinding,
        authority: &ExecutionAuthority,
        request: &EngineRequest<'_>,
    ) -> Result<(String, &'static str), String>;
    fn persist(
        &mut self,
        binding: &WorkspaceExecutionBinding,
        authority: &ExecutionAuthority,
        exchange: &DispatchExchange<'_>,
    ) -> Result<(), String>;
}

struct NativeRouteEffects;
impl AgentRouteEffects for NativeRouteEffects {
    fn persona(&mut self, agent: &str, custom: Option<&CustomAgentMeta>) -> Result<String, String> {
        Ok(load_persona(agent, custom))
    }
    fn memory(&mut self, binding: &WorkspaceExecutionBinding) -> Result<String, String> {
        recall_native_memory(binding)
    }
    fn signing(
        &mut self,
        agent: &str,
        binding: &WorkspaceExecutionBinding,
    ) -> seat_signing::SeatSigning {
        seat_signing::build(
            agent,
            Path::new(&user_home()),
            binding.execution_root(),
            None,
        )
    }
    fn engine(
        &mut self,
        binding: &WorkspaceExecutionBinding,
        authority: &ExecutionAuthority,
        request: &EngineRequest<'_>,
    ) -> Result<(String, &'static str), String> {
        dispatch_to_engine(binding, authority, request)
    }
    fn persist(
        &mut self,
        binding: &WorkspaceExecutionBinding,
        authority: &ExecutionAuthority,
        exchange: &DispatchExchange<'_>,
    ) -> Result<(), String> {
        persist_to_crdb(binding, authority, exchange)
    }
}

struct BoundDispatchInput<'a> {
    identity: &'a crate::agent_instance::DispatchIdentity,
    item: &'a str,
    body: &'a str,
    history: &'a [HistoryEntry],
    custom: Option<&'a CustomAgentMeta>,
}

#[cfg(test)]
pub(crate) struct AgentRouteProbe {
    pub stdout: String,
    pub effects: Vec<&'static str>,
}

/// Controlled route-composition probe, not native-persistence evidence. A
/// separate regression exercises the original native replacement and reopen.
#[cfg(test)]
pub(crate) fn probe_bound_route(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
    command: &mut Command,
) -> Result<AgentRouteProbe, String> {
    struct Probe<'a> {
        command: &'a mut Command,
        effects: Vec<&'static str>,
    }
    impl AgentRouteEffects for Probe<'_> {
        fn persona(&mut self, _: &str, _: Option<&CustomAgentMeta>) -> Result<String, String> {
            self.effects.push("persona");
            Ok("Controlled route probe".into())
        }
        fn memory(&mut self, _: &WorkspaceExecutionBinding) -> Result<String, String> {
            self.effects.push("memory");
            Ok(String::new())
        }
        fn signing(&mut self, _: &str, _: &WorkspaceExecutionBinding) -> seat_signing::SeatSigning {
            self.effects.push("signing");
            seat_signing::SeatSigning::default()
        }
        fn engine(
            &mut self,
            binding: &WorkspaceExecutionBinding,
            authority: &ExecutionAuthority,
            request: &EngineRequest<'_>,
        ) -> Result<(String, &'static str), String> {
            self.effects.push("engine");
            run_bound_local_command(binding, authority, request.identity, self.command)
                .map(|text| (text, "controlled-route-probe"))
        }
        fn persist(
            &mut self,
            _: &WorkspaceExecutionBinding,
            _: &ExecutionAuthority,
            _: &DispatchExchange<'_>,
        ) -> Result<(), String> {
            self.effects.push("mock-persistence");
            Ok(())
        }
    }
    let identity = crate::agent_instance::DispatchIdentity::new(
        crate::agent_instance::ActorAddress::parse("RUST#p009-route-probe")
            .map_err(|error| error.to_string())?,
        crate::agent_instance::ActorAddress::parse("FIXTURE-A#p009-route-parent")
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let mut probe = Probe {
        command,
        effects: Vec::new(),
    };
    let response = run_bound_exchange(
        binding,
        authority,
        &BoundDispatchInput {
            identity: &identity,
            item: "controlled-route-probe",
            body: "controlled route probe",
            history: &[],
            custom: None,
        },
        &mut probe,
        &mut std::io::sink(),
    )?;
    Ok(AgentRouteProbe {
        stdout: response["reply"]
            .as_str()
            .ok_or("probe_reply_missing")?
            .to_owned(),
        effects: probe.effects,
    })
}

/// Both production and controlled route tests enter this exact ordered boundary.
/// A binding supplies context, never a scheduler grant or resource lease.
fn run_bound_exchange(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
    input: &BoundDispatchInput<'_>,
    effects: &mut impl AgentRouteEffects,
    err: &mut dyn Write,
) -> Result<serde_json::Value, String> {
    check_binding(binding, authority)?;
    let agent = input.identity.child().seat();
    let persona = effects.persona(agent, input.custom)?;
    check_binding(binding, authority)?;
    let memory = effects.memory(binding)?;
    check_binding(binding, authority)?;
    let signing = effects.signing(agent, binding);
    let git_signing = BoundGitSigning::from_generated(agent, binding, &signing)?;
    if let Some(warning) = &signing.warning {
        let _ = writeln!(err, "chinwag: warning: {warning}");
    }
    let signing_note =
        (!git_signing.environment.is_empty()).then(|| seat_signing::brief_note(agent));
    let child = input.identity.child().to_string();
    let sender = input.identity.parent().to_string();
    let prompt = assemble_dispatch_prompt(
        agent,
        &persona,
        &memory,
        input.item,
        &child,
        &sender,
        input.history,
        signing_note.as_deref(),
        input.body,
        MAX_PROMPT_BYTES,
    )?;
    let mut environment: Vec<_> = signing
        .env
        .into_iter()
        .filter(|(key, _)| !key.starts_with("GIT_"))
        .collect();
    environment.extend(input.identity.environment());
    check_binding(binding, authority)?;
    let (reply, engine) = effects.engine(
        binding,
        authority,
        &EngineRequest {
            agent,
            prompt: &prompt,
            environment: &environment,
            git_signing: &git_signing,
            identity: input.identity,
        },
    )?;
    if matches!(engine, "unavailable" | "hosted-agent-error") {
        return Err("engine_outcome_held_without_replacement".into());
    }
    let suffix = crate::agent_instance::new_instance_id().map_err(|error| error.to_string())?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "dispatch_clock_unavailable")?
        .as_millis();
    let now_ms = i64::try_from(now_ms).map_err(|_| "dispatch_clock_range")?;
    let inbound_id = format!("msg-in-{now_ms}-{suffix}");
    let outbound_id = format!("msg-out-{now_ms}-{suffix}");
    check_binding(binding, authority)?;
    effects
        .persist(
            binding,
            authority,
            &DispatchExchange {
                identity: input.identity,
                item_key: input.item,
                inbound_id: &inbound_id,
                inbound_body: input.body,
                outbound_id: &outbound_id,
                outbound_body: &reply,
                now_ms,
            },
        )
        .map_err(|error| format!("dispatch_persistence_unknown_no_retry: {error}"))?;
    // The original native replacement may have changed the store inode. Stop
    // here: no unrelated retention/relay or implicit adoption of that new file.
    Ok(json!({
        "ok": true, "agent": agent, "agent_instance": child, "sender_instance": sender,
        "engine": engine, "reply": reply, "item_key": input.item,
        "crdb_message_id": outbound_id, "crdb_inbound_id": inbound_id, "crdb_thread_id": child,
        "crdb_persisted": true, "crdb_status": "stored",
        "workspace_id": binding.workspace_id(), "repo_id": binding.repo_id(),
        "worktree_id": binding.worktree_id(), "execution_root": binding.execution_root(),
        "store_id": binding.store_id(), "store_path": binding.store_path(),
        "execution_binding": binding.commitment_id(),
    }))
}

pub fn run_agent_dispatch(
    request: AgentDispatchRequest,
    input: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    run_agent_dispatch_with_effects(
        request,
        input,
        out,
        err,
        &ExecutionAuthority::unsupported(),
        &mut NativeRouteEffects,
    )
}

fn run_agent_dispatch_with_effects(
    request: AgentDispatchRequest,
    input: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
    authority: &ExecutionAuthority,
    effects: &mut impl AgentRouteEffects,
) -> u8 {
    let mut payload = StdinDispatchPayload::default();
    if request.stdin_json {
        let mut raw = String::new();
        if input.read_to_string(&mut raw).is_err() {
            let _ = writeln!(err, "chinwag: failed to read stdin payload");
            return 2;
        }
        if !raw.trim().is_empty() {
            match serde_json::from_str(&raw) {
                Ok(parsed) => payload = parsed,
                Err(_) => {
                    let _ = writeln!(err, "chinwag: invalid_arguments");
                    return 2;
                }
            }
        }
    }
    let ambient_actor = std::env::var("CHINWAG_ACTOR").ok();
    let fleet_manifest_path = request.fleet_manifest.clone();
    let room = request.room.clone();
    let Some(body) = request
        .body
        .clone()
        .or(payload.body.clone())
        .or(payload.message.clone())
    else {
        let _ = writeln!(err, "chinwag: invalid_arguments");
        return 2;
    };
    if body.trim().is_empty() {
        let _ = writeln!(err, "chinwag: invalid_arguments");
        return 2;
    }
    let item = request
        .item
        .clone()
        .or(payload.item_key.clone())
        .or(payload.item.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "chinwag-v0.1.1-sprint".into());
    let repo = request
        .repo
        .clone()
        .or_else(|| payload.repo.as_ref().map(PathBuf::from));
    let store = request
        .crdb
        .clone()
        .or_else(|| payload.crdb.as_ref().map(PathBuf::from));
    let environment_repo = std::env::var_os("CHINWAG_REPO_ROOT");
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) => {
            let _ = writeln!(err, "chinwag: execution_cwd_unavailable");
            return 2;
        }
    };
    let fleet_cwd = repo.as_deref().unwrap_or(&cwd);
    let fleet_path = crate::fleet_cmd::manifest_path(fleet_manifest_path.as_deref(), fleet_cwd);
    // Selecting a native store retains its original execution authority gate.
    // A discovered fleet manifest cannot authorize this store or a legacy remote dispatcher.
    if store.is_none()
        && (fleet_manifest_path.is_some()
            || std::env::var_os("CHINWAG_FLEET_MANIFEST").is_some()
            || fleet_path.exists())
    {
        let result = run_manifest_exchange(
            &fleet_path,
            fleet_cwd,
            room,
            request
                .agent
                .as_deref()
                .or(payload.agent.as_deref())
                .unwrap_or_default(),
            request
                .sender
                .as_deref()
                .or(payload.sender.as_deref())
                .or(ambient_actor.as_deref()),
            request.instance.as_deref(),
            &body,
            &item,
            &payload.history,
            payload.custom_agent.as_ref(),
        );
        return match result {
            Ok(response) => {
                if serde_json::to_writer(&mut *out, &response).is_err()
                    || out.write_all(b"\n").is_err()
                {
                    1
                } else {
                    0
                }
            }
            Err(error) => {
                let _ = writeln!(
                    err,
                    "{}",
                    json!({"ok": false, "error": error, "status": "HELD"})
                );
                2
            }
        };
    }
    let identity = match prepare_dispatch_identity(&request, &payload, ambient_actor.as_deref()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = writeln!(err, "chinwag: {error}");
            return 2;
        }
    };
    let selected = select_repository(RepoSelectors {
        explicit_repo: repo.as_deref(),
        environment_repo: environment_repo.as_deref(),
        cwd: &cwd,
    })
    .and_then(|selection| {
        bind_execution(
            &selection,
            StoreSelector {
                explicit_crdb: store.as_deref(),
            },
            authority,
        )
    });
    let binding = match selected {
        Ok(binding) => binding,
        Err(error) => {
            let _ = writeln!(err, "chinwag: execution_binding_held: {error}");
            return 2;
        }
    };
    let result = run_bound_exchange(
        &binding,
        authority,
        &BoundDispatchInput {
            identity: &identity,
            item: &item,
            body: &body,
            history: &payload.history,
            custom: payload.custom_agent.as_ref(),
        },
        effects,
        err,
    );
    match result {
        Ok(response) => {
            let child_seat = identity.child().seat().to_string();
            let parent_seat = identity.parent().seat().to_string();
            let _ = crate::board::upsert_agent_thread_board_card(
                binding.execution_root(),
                &item,
                &child_seat,
                Some(&parent_seat),
                &body,
                false,
                None,
                "agent_dispatch",
            );
            if serde_json::to_writer(&mut *out, &response).is_err()
                || out.write_all(b"\n").is_err()
                || out.flush().is_err()
            {
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(err, "chinwag: dispatch_held: {error}");
            1
        }
    }
}

struct ManifestDispatchIdentity {
    seat: chinwag_fleet::SeatId,
    actor: String,
    instance: String,
    caller: String,
}

impl ManifestDispatchIdentity {
    fn new(
        raw_child: &str,
        raw_caller: Option<&str>,
        explicit_parent_instance: Option<&str>,
    ) -> Result<Self, String> {
        let raw_child = raw_child.trim().trim_start_matches('@');
        let (seat, child_instance) = raw_child
            .split_once('#')
            .map_or((raw_child, None), |(seat, instance)| (seat, Some(instance)));
        let seat = chinwag_fleet::SeatId::new(seat).map_err(|error| error.to_string())?;
        let instance = match child_instance {
            Some(instance) => instance.to_owned(),
            None => crate::agent_instance::new_instance_id().map_err(|error| error.to_string())?,
        };
        let actor = format!("{seat}#{instance}");
        chinwag_fleet::validate_actor(&seat, &actor).map_err(|error| error.to_string())?;
        let caller = raw_caller
            .ok_or("agent_caller_required")?
            .trim()
            .trim_start_matches('@');
        let (caller_seat, caller_instance) = caller
            .split_once('#')
            .map_or((caller, None), |(seat, instance)| (seat, Some(instance)));
        let caller_seat =
            chinwag_fleet::SeatId::new(caller_seat).map_err(|error| error.to_string())?;
        if let (Some(embedded), Some(explicit)) = (caller_instance, explicit_parent_instance)
            && embedded != explicit
        {
            return Err("conflicting_actor_instance".into());
        }
        let inherited = if caller_instance.is_none() && explicit_parent_instance.is_none() {
            crate::agent_instance::inherited_instance().map_err(|error| error.to_string())?
        } else {
            None
        };
        let caller_instance = explicit_parent_instance
            .or(caller_instance)
            .or(inherited.as_deref())
            .ok_or("agent_instance_required")?;
        let caller = format!("{caller_seat}#{caller_instance}");
        chinwag_fleet::validate_actor(&caller_seat, &caller).map_err(|error| error.to_string())?;
        Ok(Self {
            seat,
            actor,
            instance,
            caller,
        })
    }
    fn environment(&self) -> std::collections::BTreeMap<String, String> {
        [
            ("CHINWAG_ACTOR", self.actor.clone()),
            ("CHINWAG_INSTANCE_ID", self.instance.clone()),
            ("CHINWAG_CALLER", self.caller.clone()),
            ("CHINWAG_PARENT_INSTANCE", self.caller.clone()),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn run_manifest_exchange(
    manifest_path: &Path,
    cwd: &Path,
    room: Option<String>,
    recipient: &str,
    caller: Option<&str>,
    parent_instance: Option<&str>,
    body: &str,
    item: &str,
    history: &[HistoryEntry],
    custom: Option<&CustomAgentMeta>,
) -> Result<serde_json::Value, String> {
    let identity = ManifestDispatchIdentity::new(recipient, caller, parent_instance)?;
    let seat = identity.seat.as_str();
    let manifest =
        chinwag_fleet::FleetManifest::load(manifest_path).map_err(|error| error.to_string())?;
    let actor = identity.actor.clone();
    let plan = chinwag_fleet::resolve_dispatch_plan(
        &manifest,
        &chinwag_fleet::DispatchRequest {
            seat: seat.to_owned(),
            requested_write_globs: manifest
                .seat(seat)
                .map(|seat| seat.allowed_write_roots.clone())
                .unwrap_or_default(),
            room,
            cwd: cwd.to_path_buf(),
            actor: Some(actor.clone()),
            ..Default::default()
        },
    )
    .map_err(|error| error.to_string())?;
    let definition = manifest.seat(seat).ok_or("UnknownSeat")?;
    let mut persona = load_persona(seat, custom);
    let workspace = cwd.canonicalize().map_err(|error| error.to_string())?;
    for relative_path in &definition.boot_files {
        let mut path = workspace.clone();
        for component in Path::new(relative_path).components() {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err("boot_file_invalid".into());
            }
            path.push(component);
            if fs::symlink_metadata(&path)
                .map_err(|error| format!("boot_file_unavailable: {error}"))?
                .file_type()
                .is_symlink()
            {
                return Err("boot_file_invalid".into());
            }
        }
        if !path
            .canonicalize()
            .map_err(|error| error.to_string())?
            .starts_with(&workspace)
        {
            return Err("boot_file_invalid".into());
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("boot_file_unavailable: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("boot_file_invalid".into());
        }
        let text =
            fs::read_to_string(&path).map_err(|error| format!("boot_file_unavailable: {error}"))?;
        persona.push_str(&format!("\n--- {} ---\n{text}", path.display()));
    }
    let prompt = assemble_dispatch_prompt(
        seat,
        &persona,
        "",
        item,
        &actor,
        &identity.caller,
        history,
        None,
        body,
        MAX_PROMPT_BYTES,
    )?;
    let mut context = chinwag_fleet::ExecutionContext {
        env: identity.environment(),
        prompt: Some(prompt),
        ..Default::default()
    };
    context.env.insert("CHINWAG_ACTOR".into(), actor.clone());
    context.env.insert(
        "CHINWAG_FLEET_MANIFEST".into(),
        manifest_path.display().to_string(),
    );
    context
        .env
        .insert("CHINWAG_ITEM_KEY".into(), item.to_owned());
    let outcome = crate::fleet_cmd::execute_plan(&manifest, &plan, &context, &actor)?;
    if !outcome.success {
        return Err(format!(
            "driver_exit_failed: {:?}: {}",
            outcome.exit_code, outcome.stderr
        ));
    }
    Ok(json!({
        "ok": true, "agent": seat, "agent_instance": actor, "sender_instance": identity.caller,
        "engine": plan.model, "target": plan.target, "reply": outcome.stdout, "item_key": item,
        "exit_code": outcome.exit_code, "crdb_persisted": false, "crdb_status": "not_requested",
        "manifest_digest": plan.manifest_digest,
    }))
}

#[allow(clippy::too_many_arguments)]
fn assemble_dispatch_prompt(
    agent_upper: &str,
    persona: &str,
    memories: &str,
    item_key: &str,
    agent_instance: &str,
    sender: &str,
    history: &[HistoryEntry],
    signing_note: Option<&str>,
    body: &str,
    max_bytes: usize,
) -> Result<String, &'static str> {
    let mut head_parts = vec![persona.to_owned()];
    if !memories.is_empty() {
        head_parts.push(format!(
            "\n--- Recalled Chinwag 3-Tier Memories & Tombstones ({agent_upper}) ---\n{memories}"
        ));
    }
    head_parts.push(format!(
        "\n--- Active Work Item & Thread Instance Context ---\nLinked item: {item_key}\nYour unique thread instance ID: {agent_instance}\nCaller thread instance ID: {sender}\n(When posting to the Chinwag bus, always pass --from \"{agent_instance}\" --to \"@{sender}\")"
    ));

    let mut tail_parts = Vec::new();
    if let Some(note) = signing_note {
        tail_parts.push(note.to_owned());
    }
    tail_parts.push(format!(
        "\n--- New Message from {sender} ---\n{body}\n\nReply directly as {agent_instance}:"
    ));

    let head = head_parts.join("\n");
    let tail = tail_parts.join("\n");
    let required_only = format!("{head}\n{tail}");
    if required_only.len() > max_bytes {
        return Err("prompt_too_large");
    }

    if history.is_empty() {
        return Ok(required_only);
    }

    let len = history.len();
    let base_start = len.saturating_sub(10);
    for start in base_start..len {
        let mut transcript = Vec::new();
        for h in &history[start..] {
            let who = if h.role.as_deref() == Some("user") {
                h.sender.as_deref().unwrap_or("User")
            } else {
                agent_upper
            };
            transcript.push(format!("{who}: {}", h.body.as_deref().unwrap_or("")));
        }
        let history_block = format!("\n--- Recent Conversation ---\n{}", transcript.join("\n\n"));
        let candidate = format!("{head}\n{history_block}\n{tail}");
        if candidate.len() <= max_bytes {
            return Ok(candidate);
        }
    }

    Ok(required_only)
}

#[cfg(test)]
#[path = "agent_dispatch_route_tests.rs"]
mod execution_binding_route_tests;

#[cfg(test)]
mod instance_dispatch_tests {
    use super::*;
    use crate::agent_instance::InstanceError;

    fn request(args: &[&str]) -> AgentDispatchRequest {
        let mut args = args
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        args.push("--stdin".into());
        crate::parse_agent_dispatch(&args).unwrap()
    }

    #[test]
    fn stdin_sender_and_explicit_instance_are_merged_before_dispatch() {
        let payload: StdinDispatchPayload = serde_json::from_str(
            r#"{"agent":"RUST#child-long-id","sender":"FIXTURE-A","body":"fixture"}"#,
        )
        .unwrap();
        let req = request(&["--instance", "parent-long-id"]);
        let identity = prepare_dispatch_identity(&req, &payload, Some("OTHER#ambient")).unwrap();
        assert_eq!(identity.parent().to_string(), "FIXTURE-A#parent-long-id");
        assert_eq!(identity.child().to_string(), "RUST#child-long-id");
    }

    #[test]
    fn inherited_caller_is_used_without_human_default_and_each_spawn_is_fresh() {
        let payload: StdinDispatchPayload = serde_json::from_str(r#"{"agent":"RUST"}"#).unwrap();
        let req = request(&[]);
        assert_eq!(
            prepare_dispatch_identity(&req, &payload, None),
            Err(InstanceError::MissingCaller)
        );
        let a = prepare_dispatch_identity(&req, &payload, Some("FIXTURE-A#parent")).unwrap();
        let b = prepare_dispatch_identity(&req, &payload, Some("FIXTURE-A#parent")).unwrap();
        assert_eq!(a.parent().to_string(), "FIXTURE-A#parent");
        assert_ne!(a.child(), b.child());
        assert_eq!(a.child().instance().unwrap().len(), 32);
    }

    #[test]
    fn conflicting_stdin_identity_stops_before_files_or_engine_io() {
        let req = request(&["--instance", "one"]);
        let mut input = std::io::Cursor::new(
            br#"{"agent":"RUST#child","sender":"FIXTURE-A#two","body":"fixture"}"#,
        );
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(run_agent_dispatch(req, &mut input, &mut out, &mut err), 2);
        assert!(out.is_empty());
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "chinwag: conflicting_actor_instance\n"
        );
    }
}

#[cfg(test)]
mod persona_loader_tests {
    use super::*;

    #[test]
    fn assemble_dispatch_prompt_preserves_50kb_persona_and_trims_history_before_failing() {
        let large_persona = "P".repeat(55_000);
        let history = vec![
            HistoryEntry {
                sender: Some("User".to_owned()),
                role: Some("user".to_owned()),
                body: Some("OLD_HISTORY_TURN_".to_owned() + &"H".repeat(30_000)),
            },
            HistoryEntry {
                sender: Some("User".to_owned()),
                role: Some("user".to_owned()),
                body: Some("RECENT_HISTORY_TURN".to_owned()),
            },
        ];
        let assembled = assemble_dispatch_prompt(
            "FIXTURE-F",
            &large_persona,
            "MEMORIES_BLOCK",
            "CHWG-TEST-1",
            "FIXTURE-F#instance123",
            "FIXTURE-C#caller456",
            &history,
            Some("SIGNING_NOTE_SENTINEL"),
            "FINAL_USER_MESSAGE_SENTINEL",
            70_000,
        )
        .unwrap();

        assert!(assembled.contains("RECENT_HISTORY_TURN"));
        assert!(!assembled.contains("OLD_HISTORY_TURN_"));
        assert!(assembled.contains("SIGNING_NOTE_SENTINEL"));
        assert!(assembled.contains("FINAL_USER_MESSAGE_SENTINEL"));

        // Required context larger than ceiling must return prompt_too_large.
        let err = assemble_dispatch_prompt(
            "FIXTURE-F",
            &large_persona,
            "",
            "CHWG-TEST-1",
            "FIXTURE-F#instance123",
            "FIXTURE-C#caller456",
            &[],
            None,
            "FINAL_USER_MESSAGE_SENTINEL",
            10_000,
        );
        assert_eq!(err, Err("prompt_too_large"));
    }
}
