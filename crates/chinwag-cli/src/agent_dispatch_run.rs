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
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CRDB_TEXT_BYTES: usize = 60_000;

fn user_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned())
}

fn fleet_skills_agents_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("CHINWAG_FLEET_AGENTS_DIR")
        && !override_dir.trim().is_empty()
    {
        return PathBuf::from(override_dir);
    }
    PathBuf::from(user_home()).join("fleet-skills/agents")
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
    engine: Option<String>,
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

/// Ordered canonical persona document specification (`CHWG-PERSONA-LOADER-FIX-01`).
///
/// Reads ONLY from `<fleet_root>/<AGENT>/`:
/// 1. `SOUL.md`
/// 2. `AGENT.md`, otherwise `AGENTS.md` (only when `AGENT.md` is absent)
/// 3. `TOOL.md`, otherwise `TOOLS.md` (only when `TOOL.md` is absent)
/// 4. `SKILLS.md`
/// 5. `MEMORY.md`
/// 6. `DESIGN.md` for `TYPE` only (`INV-DESIGN-TYPE-ONLY-01`)
///
/// Preserves the complete UTF-8 content of each selected document without per-file truncation,
/// and never loads legacy `docuswiki`, `paperclip-wiki`, or `.paperclip-pilot` directories.
fn load_persona_from_root(
    agent_upper: &str,
    custom: Option<&CustomAgentMeta>,
    fleet_root: &Path,
) -> String {
    let mut parts = Vec::new();
    if agent_upper == "GEMINI-PM" {
        parts.push(
            "You are ■ GEMINI-PM (Antigravity Product Owner & Chief Orchestrator for Chinwag & Emun Labs on Gemini 4 Argon High), talking directly with Brian Spector on Mission Control (:5487).\nKeep your answers concise, sharp, and grounded in live repo & database state. You coordinate the 3-Node Multi-Host Fleet across Node 1 Mac Studio (127.0.0.1), Node 2 Brian's MacBook Pro (100.108.108.25: ■ WORKHORSE on GPT-6.1-SOL Max & ■ FLINT on Recursive Flint MLX 262k), and Node 3 Nicola's MacBook Pro (100.89.25.127: ■ H, ■ AUSDRA, ⚡ H-SWARM).".to_owned(),
        );
    } else if agent_upper == "FLINT" {
        parts.push(
            "You are ■ FLINT (Flint from Recursive · flint-int4 MLX · 262k context running on Node 2 MacBook Pro 100.108.108.25:11500), Local Adversarial Code Auditor & Rust/CRDT Verifier for Chinwag at Emun Labs.\nRespond with surgical Rust/CRDT/concurrency rigor.".to_owned(),
        );
    } else if agent_upper == "WORKHORSE" {
        parts.push(
            "You are ■ WORKHORSE (Codex - GPT-6.1-SOL Max running on Node 2 Brian's MacBook Pro 100.108.108.25), Principal Engineering Workhorse, PRD Reviewer & Ephemeral Dev/QA Pool Coordinator at Emun Labs.\nRespond with concrete systems rigor, exact file/schema/state-machine boundaries, and zero fluff.".to_owned(),
        );
    } else if agent_upper == "H" {
        parts.push(
            "You are ■ H (Codex - GPT-6.1-SOL Ultra on Node 3 Nicola's MacBook Pro 100.89.25.127 · nicolas-macbook-pro), Lead Creative & Technical Agent for Nicola Spector (Co-Founder & Chief Creative Officer) leading laglords.tv, chinwag.tv, and Captionizm™.".to_owned(),
        );
    } else if agent_upper == "AUSDRA" {
        parts.push(
            "You are ■ AUSDRA (Codex - GPT-6.1-SOL Ultra on Node 3 Nicola's MacBook Pro 100.89.25.127), Business, Legal & Governance Advisor to Nicola Spector.".to_owned(),
        );
    } else {
        parts.push(format!(
            "You are ■ {agent_upper}, a core specialist agent at Emun Labs working directly with Brian and Nicola Spector.\nRespond directly, helpfully, and in your authentic specialist persona."
        ));
    }

    let fleet_dir = fleet_root.join(agent_upper);
    let doc_slots: &[&[&str]] = &[
        &["SOUL.md"],
        &["AGENT.md", "AGENTS.md"],
        &["TOOL.md", "TOOLS.md"],
        &["SKILLS.md"],
        &["MEMORY.md"],
    ];
    for candidates in doc_slots {
        for fname in *candidates {
            let fpath = fleet_dir.join(fname);
            match fs::read_to_string(&fpath) {
                Ok(content) => {
                    parts.push(format!(
                        "\n--- {fname} (fleet-skills/{agent_upper}) ---\n{content}"
                    ));
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => break,
            }
        }
    }
    if agent_upper == "TYPE" {
        let design_path = fleet_dir.join("DESIGN.md");
        if let Ok(content) = fs::read_to_string(&design_path) {
            parts.push(format!(
                "\n--- DESIGN.md (TYPE Only · INV-DESIGN-TYPE-ONLY-01) ---\n{content}"
            ));
        }
    }

    if let Some(meta) = custom {
        let role = meta.role.as_deref().unwrap_or("");
        let dept = meta.dept.as_deref().unwrap_or("");
        let sys = meta.system_prompt.as_deref().unwrap_or("");
        if !role.is_empty() || !sys.is_empty() {
            parts.push(format!(
                "\n--- Custom Agent Configuration ({agent_upper}) ---\nRole: {role} ({dept})\n{sys}"
            ));
        }
    }

    parts.join("\n")
}

fn load_persona(agent_upper: &str, custom: Option<&CustomAgentMeta>) -> String {
    load_persona_from_root(agent_upper, custom, &fleet_skills_agents_dir())
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

fn strip_flint_banner(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    if let Some(first) = lines.first()
        && (first.contains("Opening Pi") || first.contains("11500/v1"))
    {
        return lines[1..].join("\n").trim().to_owned();
    }
    raw.trim().to_owned()
}

fn codex_effort_arg(agent_upper: &str) -> &'static str {
    match agent_upper {
        "WORKHORSE" => "model_reasoning_effort=\"max\"",
        "ARCHITECT" | "RUST" | "GAMEDEV" | "H" | "AUSDRA" => "model_reasoning_effort=\"ultra\"",
        _ => "model_reasoning_effort=\"high\"",
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
    // These fixed exceptions align child Git's config sources with binding
    // validation; no inherited or caller-selected config file is reintroduced.
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .envs(signing.environment.iter().cloned())
        .env("CHINWAG_REPO_ROOT", binding.execution_root())
        .env("CHINWAG_STORE_PATH", binding.store_path())
        .env("CHINWAG_STORE_ID", binding.store_id())
        .env("CHINWAG_EXECUTION_BINDING", binding.commitment_id())
        .envs(identity.environment())
        .env("CHINWAG_AGENT", identity.child().seat());
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

struct BoundHostedTransport<'a> {
    binding: &'a WorkspaceExecutionBinding,
    authority: &'a ExecutionAuthority<'a>,
    inner: crate::hosted_agent::CurlTransport,
}
impl crate::hosted_agent::HostedTransport for BoundHostedTransport<'_> {
    fn send(
        &mut self,
        request: &crate::hosted_agent::HttpRequest,
    ) -> Result<crate::hosted_agent::HttpResponse, crate::hosted_agent::HostedAgentError> {
        check_binding(self.binding, self.authority)
            .map_err(crate::hosted_agent::HostedAgentError::ConfigError)?;
        crate::hosted_agent::HostedTransport::send(&mut self.inner, request)
    }
}

struct BoundHostedExecutor<'a> {
    binding: &'a WorkspaceExecutionBinding,
    authority: &'a ExecutionAuthority<'a>,
    inner: crate::hosted_agent::StandardToolExecutor,
}
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
    custom: Option<&'a CustomAgentMeta>,
    environment: &'a [(String, String)],
    git_signing: &'a BoundGitSigning,
    identity: &'a crate::agent_instance::DispatchIdentity,
}

fn require_local_route(agent: &str, custom: Option<&CustomAgentMeta>) -> Result<(), String> {
    if crate::deepseek_pool::pool_for_agent(agent).is_some() {
        return Err("pool_execution_binding_unsupported".into());
    }
    let hint = custom
        .and_then(|meta| meta.engine.as_deref().or(meta.dept.as_deref()))
        .unwrap_or("")
        .to_ascii_lowercase();
    if agent == "WORKHORSE" || hint.contains("workhorse") {
        return Err("remote_execution_binding_unsupported".into());
    }
    Ok(())
}

fn dispatch_to_engine(
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority,
    request: &EngineRequest<'_>,
) -> Result<(String, &'static str), String> {
    check_binding(binding, authority)?;
    let EngineRequest {
        agent,
        prompt,
        custom,
        environment,
        git_signing,
        identity,
    } = request;
    require_local_route(agent, *custom)?;
    let engine_hint = custom
        .and_then(|meta| meta.engine.as_deref().or(meta.dept.as_deref()))
        .unwrap_or("")
        .to_ascii_lowercase();
    if let Ok(mock) = std::env::var("CHINWAG_AGENT_MOCK_REPLY")
        && !mock.trim().is_empty()
    {
        return Ok((mock, "mock-engine"));
    }

    let home = user_home();
    let local_bin = Path::new(&home).join(".local/bin");
    let path_env = format!(
        "{}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        local_bin.display()
    );
    let rich_prompt = truncate_utf8(prompt, MAX_PROMPT_BYTES);
    let explicit_cfg_path = std::env::var("CHINWAG_PROVIDERS_CONFIG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    let default_cfg_path = Path::new(&home).join(".chinwag/providers.json");
    let default_gemini =
        *agent == "FREQUENCY" && Path::new(&home).join(".chinwag/gemini.env").is_file();
    if explicit_cfg_path.is_some() || default_cfg_path.symlink_metadata().is_ok() || default_gemini
    {
        check_binding(binding, authority)?;
        let config = crate::hosted_agent::ProvidersConfig::load_or_default(
            explicit_cfg_path.as_deref(),
            Path::new(&home),
            binding.execution_root(),
        )
        .map_err(|error| error.to_string())?;
        if config.agents.contains_key(*agent) {
            let mut exec_env = vec![("PATH".to_owned(), path_env.clone())];
            exec_env.extend(environment.iter().cloned());
            let mut transport = BoundHostedTransport {
                binding,
                authority,
                inner: crate::hosted_agent::CurlTransport::system_default(Path::new(&home)),
            };
            let mut executor = BoundHostedExecutor {
                binding,
                authority,
                inner: crate::hosted_agent::StandardToolExecutor::new(
                    binding.execution_root().to_owned(),
                    exec_env,
                ),
            };
            check_binding(binding, authority)?;
            let system = format!(
                "You are {agent} ({}), executing in the approved Chinwag workspace.",
                identity.child()
            );
            let reply = crate::hosted_agent::run_hosted_seat(
                &config,
                agent,
                &system,
                &rich_prompt,
                &mut transport,
                &mut executor,
            )
            .map_err(|error| format!("hosted_outcome_without_replacement: {error}"))?;
            return Ok((reply.text, "hosted-agent-api"));
        }
    }

    let is_flint = *agent == "FLINT" || engine_hint.contains("flint");
    let is_deepseek = agent.starts_with("DEV-")
        || agent.starts_with("EPHEMERAL-DEV-")
        || agent.starts_with("QA-")
        || agent.starts_with("EPHEMERAL-QA-")
        || matches!(
            *agent,
            "SKILL"
                | "MANNY"
                | "SUMMARIZER"
                | "RECORD"
                | "SUPPORT"
                | "EPHEMERAL-ANALYST"
                | "EPHEMERAL-SDR"
                | "EPHEMERAL-SUPPORT"
        )
        || engine_hint.contains("deepseek");
    let is_codex = matches!(
        *agent,
        "ARCHITECT"
            | "RUST"
            | "GAMEDEV"
            | "WORKHORSE"
            | "H"
            | "AUSDRA"
            | "H-SWARM"
            | "TYPE"
            | "INDEX"
            | "DECLARATION"
            | "CLOUDFLARE"
    ) || engine_hint.contains("codex")
        || engine_hint.contains("gpt-6.1-sol");
    let is_grok = matches!(*agent, "GROWTH" | "SALES") || engine_hint.contains("grok");

    for (enabled, name, engine) in [
        (is_flint, "flint-agent", "flint-agent"),
        (is_deepseek, "deepseek-agent", "deepseek-workers-ai"),
    ] {
        let binary = local_bin.join(name);
        if enabled && binary.exists() {
            let mut command = Command::new(binary);
            command
                .args(["run", &rich_prompt, "--cwd"])
                .arg(binding.execution_root())
                .env("PATH", &path_env)
                .envs(environment.iter().cloned());
            let text = run_bound_local_command_with_signing(
                binding,
                authority,
                identity,
                &mut command,
                git_signing,
            )?;
            let text = if engine == "flint-agent" {
                strip_flint_banner(&text)
            } else {
                text
            };
            if text.is_empty() {
                return Err("engine_empty_reply_without_replacement".into());
            }
            return Ok((text, engine));
        }
    }
    let local_codex = local_bin.join("codex");
    let codex = if local_codex.exists() {
        local_codex
    } else {
        PathBuf::from("/opt/homebrew/bin/codex")
    };
    if is_codex && codex.exists() {
        let mut command = Command::new(&codex);
        command
            .args([
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "-m",
                "gpt-6.1-sol",
                "-c",
                codex_effort_arg(agent),
                "-c",
                "service_tier=\"priority\"",
                &rich_prompt,
            ])
            .env("PATH", &path_env)
            .envs(environment.iter().cloned());
        return run_bound_local_command_with_signing(
            binding,
            authority,
            identity,
            &mut command,
            git_signing,
        )
        .map(|text| (text, "codex-gpt-6.1-sol"));
    }
    let grok = local_bin.join("grok");
    if is_grok && grok.exists() {
        let mut command = Command::new(grok);
        command
            .args(["agent", "--always-approve", &rich_prompt])
            .env("PATH", &path_env)
            .envs(environment.iter().cloned());
        return run_bound_local_command_with_signing(
            binding,
            authority,
            identity,
            &mut command,
            git_signing,
        )
        .map(|text| (text, "grok-4.7-high"));
    }
    if Path::new("/opt/homebrew/bin/gemini").exists() {
        let mut command = Command::new("/opt/homebrew/bin/node");
        command
            .args(["/opt/homebrew/bin/gemini", "-p", &rich_prompt, "--yolo"])
            .env("PATH", &path_env)
            .envs(environment.iter().cloned());
        return run_bound_local_command_with_signing(
            binding,
            authority,
            identity,
            &mut command,
            git_signing,
        )
        .map(|text| (text, "gemini-4-argon-high"));
    }
    if codex.exists() {
        let mut command = Command::new(codex);
        command
            .args([
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "-m",
                "gpt-6.1-sol",
                "-c",
                "model_reasoning_effort=\"high\"",
                &rich_prompt,
            ])
            .env("PATH", &path_env)
            .envs(environment.iter().cloned());
        return run_bound_local_command_with_signing(
            binding,
            authority,
            identity,
            &mut command,
            git_signing,
        )
        .map(|text| (text, "codex-gpt-6.1-sol"));
    }
    Err("engine_unavailable_without_replacement".into())
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

#[cfg(test)]
fn workhorse_remote_command(identity: &crate::agent_instance::DispatchIdentity) -> String {
    format!(
        "PATH=/Users/brianspector/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin {} /Users/brianspector/.local/bin/codex exec --skip-git-repo-check --ephemeral -m gpt-6.1-sol -c 'model_reasoning_effort=\"max\"' -c 'service_tier=\"priority\"' -",
        identity.remote_environment()
    )
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
        crate::agent_instance::ActorAddress::parse("WORKHORSE#p009-route-parent")
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
    require_local_route(agent, input.custom)?;
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
            custom: input.custom,
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
    let identity = match prepare_dispatch_identity(&request, &payload, ambient_actor.as_deref()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = writeln!(err, "chinwag: {error}");
            return 2;
        }
    };
    let Some(body) = request.body.or(payload.body).or(payload.message) else {
        let _ = writeln!(err, "chinwag: invalid_arguments");
        return 2;
    };
    if body.trim().is_empty() {
        let _ = writeln!(err, "chinwag: invalid_arguments");
        return 2;
    }
    let item = request
        .item
        .or(payload.item_key)
        .or(payload.item)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "chinwag-v0.1.1-sprint".into());
    let repo = request.repo.or_else(|| payload.repo.map(PathBuf::from));
    let store = request.crdb.or_else(|| payload.crdb.map(PathBuf::from));
    let environment_repo = std::env::var_os("CHINWAG_REPO_ROOT");
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) => {
            let _ = writeln!(err, "chinwag: execution_cwd_unavailable");
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
mod codex_effort_tests {
    use super::codex_effort_arg;

    #[test]
    fn ultra_max_and_high_tiers_match_3node_roster() {
        for seat in ["ARCHITECT", "RUST", "GAMEDEV", "H", "AUSDRA"] {
            assert_eq!(codex_effort_arg(seat), "model_reasoning_effort=\"ultra\"");
        }
        assert_eq!(
            codex_effort_arg("WORKHORSE"),
            "model_reasoning_effort=\"max\""
        );
        for seat in ["TYPE", "INDEX", "DECLARATION", "CLOUDFLARE"] {
            assert_eq!(codex_effort_arg(seat), "model_reasoning_effort=\"high\"");
        }
    }
}

#[cfg(test)]
mod instance_dispatch_tests {
    use super::*;
    use crate::agent_instance::{ActorAddress, DispatchIdentity, InstanceError};

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
            r#"{"agent":"RUST#child-long-id","sender":"WORKHORSE","body":"fixture"}"#,
        )
        .unwrap();
        let req = request(&["--instance", "parent-long-id"]);
        let identity = prepare_dispatch_identity(&req, &payload, Some("OTHER#ambient")).unwrap();
        assert_eq!(identity.parent().to_string(), "WORKHORSE#parent-long-id");
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
        let a = prepare_dispatch_identity(&req, &payload, Some("WORKHORSE#parent")).unwrap();
        let b = prepare_dispatch_identity(&req, &payload, Some("WORKHORSE#parent")).unwrap();
        assert_eq!(a.parent().to_string(), "WORKHORSE#parent");
        assert_ne!(a.child(), b.child());
        assert_eq!(a.child().instance().unwrap().len(), 32);
    }

    #[test]
    fn conflicting_stdin_identity_stops_before_files_or_engine_io() {
        let req = request(&["--instance", "one"]);
        let mut input = std::io::Cursor::new(
            br#"{"agent":"RUST#child","sender":"WORKHORSE#two","body":"fixture"}"#,
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

    #[test]
    fn remote_workhorse_command_contains_full_validated_lineage() {
        let identity = DispatchIdentity::new(
            ActorAddress::parse("WORKHORSE#01a146d0-d769-7a02-a1a5-75c407ffaa3c").unwrap(),
            ActorAddress::parse("GEMINI-PM#parent-long-id").unwrap(),
        )
        .unwrap();
        let command = workhorse_remote_command(&identity);
        assert!(command.contains("CHINWAG_ACTOR='WORKHORSE#01a146d0-d769-7a02-a1a5-75c407ffaa3c'"));
        assert!(command.contains("CHINWAG_INSTANCE_ID='01a146d0-d769-7a02-a1a5-75c407ffaa3c'"));
        assert!(command.contains("CHINWAG_CALLER='GEMINI-PM#parent-long-id'"));
        assert!(command.contains("CHINWAG_PARENT_INSTANCE='GEMINI-PM#parent-long-id'"));
    }
}

#[cfg(test)]
mod persona_loader_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn canonical_fleet_skills_loader_deduplicates_aliases_and_never_truncates_at_3500_bytes() {
        let tmp = TempDir::new().unwrap();
        let freq_dir = tmp.path().join("FREQUENCY");
        fs::create_dir_all(&freq_dir).unwrap();

        let long_prefix = "A".repeat(5_000);
        let tail_sentinel = "SENTINEL_PAST_3500_BYTES_SURVIVES";
        fs::write(freq_dir.join("SOUL.md"), "SOUL_CANONICAL").unwrap();
        fs::write(freq_dir.join("AGENT.md"), "AGENT_SINGULAR_WINS").unwrap();
        fs::write(freq_dir.join("AGENTS.md"), "AGENTS_PLURAL_DUPLICATE").unwrap();
        fs::write(
            freq_dir.join("TOOL.md"),
            format!("{long_prefix}\n{tail_sentinel}"),
        )
        .unwrap();
        fs::write(freq_dir.join("TOOLS.md"), "TOOLS_PLURAL_DUPLICATE").unwrap();
        fs::write(freq_dir.join("SKILLS.md"), "SKILLS_CANONICAL").unwrap();
        fs::write(freq_dir.join("MEMORY.md"), "MEMORY_CANONICAL").unwrap();
        fs::write(
            freq_dir.join("DESIGN.md"),
            "DESIGN_MUST_NOT_LOAD_FOR_FREQUENCY",
        )
        .unwrap();

        let persona = load_persona_from_root("FREQUENCY", None, tmp.path());
        assert!(persona.contains("SOUL_CANONICAL"));
        assert!(persona.contains("AGENT_SINGULAR_WINS"));
        assert!(
            !persona.contains("AGENTS_PLURAL_DUPLICATE"),
            "AGENTS.md must not be double-loaded when AGENT.md exists"
        );
        assert!(
            persona.contains(tail_sentinel),
            "content beyond 3,500 bytes must survive intact without truncation"
        );
        assert!(
            !persona.contains("TOOLS_PLURAL_DUPLICATE"),
            "TOOLS.md must not be double-loaded when TOOL.md exists"
        );
        assert!(persona.contains("SKILLS_CANONICAL"));
        assert!(persona.contains("MEMORY_CANONICAL"));
        assert!(
            !persona.contains("DESIGN_MUST_NOT_LOAD_FOR_FREQUENCY"),
            "DESIGN.md is strictly reserved for TYPE"
        );
        assert!(!persona.contains("(Wiki)"));
        assert!(!persona.contains("(Instructions)"));
    }

    #[test]
    fn plural_aliases_load_when_singular_files_are_absent_and_design_loads_for_type() {
        let tmp = TempDir::new().unwrap();
        let type_dir = tmp.path().join("TYPE");
        fs::create_dir_all(&type_dir).unwrap();

        fs::write(type_dir.join("AGENTS.md"), "AGENTS_FALLBACK_CONTENT").unwrap();
        fs::write(type_dir.join("TOOLS.md"), "TOOLS_FALLBACK_CONTENT").unwrap();
        fs::write(type_dir.join("DESIGN.md"), "TYPE_DESIGN_SYSTEM_CONTENT").unwrap();

        let persona = load_persona_from_root("TYPE", None, tmp.path());
        assert!(persona.contains("--- AGENTS.md (fleet-skills/TYPE) ---"));
        assert!(persona.contains("AGENTS_FALLBACK_CONTENT"));
        assert!(persona.contains("--- TOOLS.md (fleet-skills/TYPE) ---"));
        assert!(persona.contains("TOOLS_FALLBACK_CONTENT"));
        assert!(persona.contains("TYPE_DESIGN_SYSTEM_CONTENT"));
    }

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
            "FREQUENCY",
            &large_persona,
            "MEMORIES_BLOCK",
            "CHWG-TEST-1",
            "FREQUENCY#instance123",
            "GEMINI-PM#caller456",
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
            "FREQUENCY",
            &large_persona,
            "",
            "CHWG-TEST-1",
            "FREQUENCY#instance123",
            "GEMINI-PM#caller456",
            &[],
            None,
            "FINAL_USER_MESSAGE_SENTINEL",
            10_000,
        );
        assert_eq!(err, Err("prompt_too_large"));
    }
}
