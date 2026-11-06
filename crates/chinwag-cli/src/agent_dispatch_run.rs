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
use crate::seat_signing;
use chinwag_snapshot_session_private::replacement::{
    AgentDispatchRecord, WriteOwner, WriteSession,
};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CRDB_TEXT_BYTES: usize = 60_000;

fn user_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned())
}

fn default_repo_root() -> PathBuf {
    PathBuf::from(user_home()).join("WORKSPACE/chinwag")
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

fn grokbot_dept(agent_upper: &str) -> &'static str {
    match agent_upper {
        "ALISTAIR" | "HOUSEKEEPING" | "INFRA BOT (GROK)" | "INFRAJR" | "QA" | "FLINT" | "DOCS"
        | "MGMT-INFRA" | "INFRA" | "EPHEMERAL-QA" => "infra",
        "ARCHITECT" | "RUST" | "INDEX" | "DEV-1" | "DEV-2" | "DEV-3" | "ENG" | "MGMT-ENG"
        | "EPHEMERAL-DEV" => "eng",
        "VENTURE" | "MO" | "EAGLE-EYE" | "BIZFIN" | "INVESTIGATIONS" | "RECORD" | "DEX"
        | "MGMT-BIZFIN" => "bizfin",
        "DECLARATION" | "GROWTH" | "SOCIAL" | "S-AND-M" | "SALES" | "MGMT-S-AND-M" => "s-and-m",
        _ => "product",
    }
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

fn recall_native_memory(agent_lower: &str, query: &str, repo_root: &Path) -> String {
    crate::memory_run::recall_for_agent_prompt(agent_lower, query, repo_root)
}

fn retain_native_memory(
    repo_root: &Path,
    agent_upper: &str,
    engine: &str,
    sender: &str,
    item_key: &str,
    message: &str,
    reply: &str,
) {
    crate::memory_run::retain_from_agent_dispatch(
        repo_root,
        agent_upper,
        engine,
        sender,
        item_key,
        message,
        reply,
    );
}

fn notify_grokbot_department_relay(
    agent_upper: &str,
    sender: &str,
    item_key: &str,
    message: &str,
    reply: &str,
) {
    let dept = grokbot_dept(agent_upper);
    let home = user_home();
    let env_path = Path::new(&home)
        .join(".paperclip-pilot/secrets/relay-webhooks")
        .join(format!("{dept}.env"));
    let Ok(raw) = fs::read_to_string(&env_path) else {
        return;
    };
    let mut url = String::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=')
            && k.trim() == "RELAY_SLACK_WEBHOOK_URL"
        {
            url = v.trim().trim_matches('"').trim_matches('\'').to_owned();
        }
    }
    if !url.starts_with("https://") {
        return;
    }
    let tag = dept.to_ascii_uppercase();
    let text = format!(
        "[CHINWAG MISSION CONTROL][{tag}] ■ {agent_upper} | {item_key} (from {sender})\nPrompt: {}\nReply Summary: {}\nMission Control: https://brians-mac-studio-468.tail23ad5.ts.net:5487/",
        truncate_utf8(message, 280),
        truncate_utf8(reply, 420)
    );
    let Ok(payload) = serde_json::to_string(&json!({ "text": text })) else {
        return;
    };
    let _ = Command::new("/usr/bin/curl")
        .args([
            "-sS",
            "--max-time",
            "5",
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            &url,
            "-d",
            &payload,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
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

fn dispatch_to_engine(
    agent_upper: &str,
    full_prompt: &str,
    custom: Option<&CustomAgentMeta>,
    signing_env: &[(String, String)],
    identity: &crate::agent_instance::DispatchIdentity,
) -> (String, &'static str) {
    if let Ok(mock) = std::env::var("CHINWAG_AGENT_MOCK_REPLY")
        && !mock.trim().is_empty()
    {
        return (mock, "mock-engine");
    }

    // 0. Ephemeral seats DEV-1..5 and QA-1..5 (plus legacy EPHEMERAL-DEV /
    //    EPHEMERAL-QA) use Cloudflare Workers AI DeepSeek v4.1 Flash once the
    //    credential file exists. Plain QA is NOT routed here. Off-switch:
    //    EPHEMERAL_DEEPSEEK_DISABLE=1. The kill switch, 10-slot concurrency cap
    //    and spend ledger live in deepseek_pool. Once active there is no
    //    fallback to another engine.
    if let Some(pool) = crate::deepseek_pool::pool_for_agent(agent_upper)
        && crate::deepseek_pool::enabled()
    {
        return crate::deepseek_pool::run(pool, agent_upper, full_prompt, identity);
    }

    let home = user_home();
    let local_bin = format!("{home}/.local/bin");
    let path_env = format!("{local_bin}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin");
    let repo_dir = default_repo_root();
    let default_cwd: PathBuf = if repo_dir.exists() {
        repo_dir.clone()
    } else {
        PathBuf::from(&home)
    };

    let engine_hint = custom
        .and_then(|c| c.engine.as_deref())
        .or_else(|| custom.and_then(|c| c.dept.as_deref()))
        .unwrap_or("")
        .to_ascii_lowercase();

    let is_flint = agent_upper == "FLINT" || engine_hint.contains("flint");
    let is_deepseek = agent_upper.starts_with("DEV-")
        || agent_upper.starts_with("EPHEMERAL-DEV-")
        || agent_upper.starts_with("QA-")
        || agent_upper.starts_with("EPHEMERAL-QA-")
        || matches!(
            agent_upper,
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
    let is_workhorse = agent_upper == "WORKHORSE" || engine_hint.contains("workhorse");
    let is_codex = matches!(
        agent_upper,
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
    let is_grok = matches!(agent_upper, "GROWTH" | "SALES") || engine_hint.contains("grok");

    // Pass full prompt context up to MAX_PROMPT_BYTES (256 KiB) so complete 5-doc personas
    // and the trailing message/identity/signing instructions are never clipped at 48 KB.
    let rich_prompt = truncate_utf8(full_prompt, MAX_PROMPT_BYTES);

    // 0b. Configurable Hosted-Model / AI-Service Agent Runner (`crates/chinwag-cli/src/hosted_agent.rs`).
    //     Routes seats bound in `~/.chinwag/providers.json` (or `CHINWAG_PROVIDERS_CONFIG`, plus the
    //     default `FREQUENCY` Gemini REST API binding when `~/.chinwag/gemini.env` is present) through
    //     the native multi-turn tool loop without requiring Antigravity or external CLI wrappers.
    let explicit_cfg_path = std::env::var("CHINWAG_PROVIDERS_CONFIG")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let default_cfg_path = Path::new(&home).join(".chinwag/providers.json");
    let has_explicit_providers_file =
        explicit_cfg_path.is_some() || default_cfg_path.symlink_metadata().is_ok();
    let default_gemini_env_ready =
        agent_upper == "FREQUENCY" && Path::new(&home).join(".chinwag/gemini.env").is_file();

    if has_explicit_providers_file || default_gemini_env_ready {
        let workspace_dir = Path::new(&home).join("WORKSPACE");
        match crate::hosted_agent::ProvidersConfig::load_or_default(
            explicit_cfg_path.as_deref(),
            Path::new(&home),
            &workspace_dir,
        ) {
            Ok(providers_cfg) if providers_cfg.agents.contains_key(agent_upper) => {
                let mut exec_env = vec![("PATH".to_owned(), path_env.clone())];
                exec_env.extend(signing_env.iter().cloned());
                let mut transport =
                    crate::hosted_agent::CurlTransport::system_default(Path::new(&home));
                let mut executor =
                    crate::hosted_agent::StandardToolExecutor::new(default_cwd.clone(), exec_env);
                let sys_instruction = format!(
                    "You are ■ {agent_upper} ({}), executing over Chinwag's native hosted-agent library. Follow the canonical SOUL.md, AGENT.md, TOOL.md, SKILLS.md, and MEMORY.md instructions embedded in the prompt strictly.",
                    identity.child()
                );
                match crate::hosted_agent::run_hosted_seat(
                    &providers_cfg,
                    agent_upper,
                    &sys_instruction,
                    &rich_prompt,
                    &mut transport,
                    &mut executor,
                ) {
                    Ok(hosted_reply) => {
                        return (hosted_reply.text, "hosted-agent-api");
                    }
                    Err(err) => {
                        return (
                            format!("[{agent_upper} error]: {err}"),
                            "hosted-agent-error",
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(err) => {
                return (
                    format!("[{agent_upper} error]: {err}"),
                    "hosted-agent-error",
                );
            }
        }
    }

    // 1. Recursive Flint (Local MLX 262k on Node 2 MacBook Pro 100.108.108.25:11500)
    let flint_bin = Path::new(&local_bin).join("flint-agent");
    if is_flint
        && flint_bin.exists()
        && let Ok(out) = Command::new(&flint_bin)
            .args(["run", &rich_prompt, "--cwd", &repo_dir.to_string_lossy()])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .envs(signing_env.iter().cloned())
            .output()
    {
        let text = strip_flint_banner(&String::from_utf8_lossy(&out.stdout));
        if out.status.success() && !text.is_empty() {
            return (text, "flint-agent");
        }
    }

    // 2. DeepSeek 4.1 on Cloudflare Workers AI (@cf/deepseek-ai/deepseek-v4.1-flash-1017)
    let deepseek_bin = Path::new(&local_bin).join("deepseek-agent");
    if is_deepseek
        && deepseek_bin.exists()
        && let Ok(out) = Command::new(&deepseek_bin)
            .args(["run", &rich_prompt, "--cwd", &repo_dir.to_string_lossy()])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .envs(signing_env.iter().cloned())
            .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if out.status.success() && !text.is_empty() {
            return (text, "deepseek-workers-ai");
        }
    }

    // 3. Node 2 MacBook Pro (100.108.108.25) Remote Dispatch for ■ WORKHORSE (Codex - GPT-6.1-SOL Max)
    let remote_command = workhorse_remote_command(identity);
    if is_workhorse
        && let Ok(mut child) = Command::new("/usr/bin/ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "brianspector@100.108.108.25",
                &remote_command,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    {
        if let Some(mut stdin_pipe) = child.stdin.take() {
            let _ = stdin_pipe.write_all(rich_prompt.as_bytes());
        }
        if let Ok(out) = child.wait_with_output() {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() && !text.is_empty() {
                return (text, "codex-gpt-6.1-sol-max-node2");
            }
        }
    }

    // 4. OpenAI Codex (GPT-6.1-SOL Ultra / Max / High) Engine
    let local_codex = Path::new(&local_bin).join("codex");
    let codex_bin: PathBuf = if local_codex.exists() {
        local_codex
    } else {
        PathBuf::from("/opt/homebrew/bin/codex")
    };
    if is_codex && codex_bin.exists() {
        let effort = codex_effort_arg(agent_upper);
        if let Ok(out) = Command::new(&codex_bin)
            .args([
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "-m",
                "gpt-6.1-sol",
                "-c",
                effort,
                "-c",
                "service_tier=\"priority\"",
                &rich_prompt,
            ])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .envs(signing_env.iter().cloned())
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() && !text.is_empty() {
                return (text, "codex-gpt-6.1-sol");
            }
        }
    }

    // 5. Grok 4.7 High CLI Engine (Strictly #s-and-m Outbound Execution: GROWTH, SALES)
    let grok_bin = Path::new(&local_bin).join("grok");
    if is_grok
        && grok_bin.exists()
        && let Ok(out) = Command::new(&grok_bin)
            .args(["agent", "--always-approve", &rich_prompt])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .envs(signing_env.iter().cloned())
            .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if out.status.success() && !text.is_empty() {
            return (text, "grok-4.7-high");
        }
    }

    // 6. Official Gemini 4 Argon High CLI Engine (Primary for GEMINI-PM, DELIVERY, QA, INFRAJR, HOUSEKEEPING, SPARK, PATENT, EAGLE-EYE, ALISTAIR, MO, VENTURE, SCRIBE, FREQUENCY, MOTION, DEX, DOCS, SOCIAL & Fleet Default — Zero Anthropic Seats)
    if Path::new("/opt/homebrew/bin/gemini").exists()
        && let Ok(out) = Command::new("/opt/homebrew/bin/node")
            .args(["/opt/homebrew/bin/gemini", "-p", &rich_prompt, "--yolo"])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .envs(signing_env.iter().cloned())
            .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if out.status.success() && !text.is_empty() {
            return (text, "gemini-4-argon-high");
        }
    }

    // 7. Secondary Fallback to Codex GPT-6.1-SOL if Gemini CLI is unavailable
    if codex_bin.exists()
        && let Ok(out) = Command::new(&codex_bin)
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
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .envs(signing_env.iter().cloned())
            .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !text.is_empty() {
            return (text, "codex-gpt-6.1-sol");
        }
    }

    (
        format!("[{agent_upper} note]: Unable to invoke local agent engine."),
        "unavailable",
    )
}

fn resolve_repo_root(crdb_path: Option<&Path>) -> PathBuf {
    let Some(path) = crdb_path else {
        return default_repo_root();
    };
    if path.file_name().is_some_and(|n| n == "state.crdb")
        && let Some(chinwag_dir) = path.parent()
        && chinwag_dir.file_name().is_some_and(|n| n == ".chinwag")
        && let Some(repo) = chinwag_dir.parent()
    {
        return repo.to_path_buf();
    }
    if path.file_name().is_some_and(|n| n == ".chinwag")
        && let Some(repo) = path.parent()
    {
        return repo.to_path_buf();
    }
    path.to_path_buf()
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

fn persist_to_crdb_once(repo_root: &Path, exchange: &DispatchExchange<'_>) -> Result<(), String> {
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
    crate::memory_run::clear_stale_crdb_operation_artifacts(repo_root);
    let owner = WriteOwner::acquire_existing_private_fixture(repo_root)
        .map_err(|e| format!("acquire_write_owner: {}", e.reason))?;
    let session =
        WriteSession::from_owner(owner).map_err(|e| format!("write_session: {}", e.reason))?;
    let record = AgentDispatchRecord::try_new(
        thread_id.clone(),
        "emunlabs/chinwag".to_owned(),
        "refs/heads/feat/v0.1.1-invariants-and-memory".to_owned(),
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
    let prepared = session
        .prepare_agent_dispatch(record, || false)
        .map_err(|e| format!("prepare_agent_dispatch: {}", e.reason))?;
    let completion = prepared
        .commit(false)
        .map_err(|e| format!("commit_agent_dispatch: {}", e.reason))?;
    if completion.is_error() {
        return Err(format!("crdb_refused: {}", completion.response()));
    }
    Ok(())
}

fn persist_to_crdb(repo_root: &Path, exchange: &DispatchExchange<'_>) -> Result<(), String> {
    let backoff_ms = [50_u64, 100, 150, 200, 250];
    let mut last_err = String::new();
    for (attempt, delay_ms) in backoff_ms.iter().enumerate() {
        match persist_to_crdb_once(repo_root, exchange) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = format!("attempt_{}:{e}", attempt + 1);
                if attempt + 1 < backoff_ms.len() {
                    std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
                }
            }
        }
    }
    Err(format!("crdb_persist_failed_after_5_attempts ({last_err})"))
}

pub fn run_agent_dispatch(
    request: AgentDispatchRequest,
    input: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let mut stdin_payload = StdinDispatchPayload::default();
    if request.stdin_json {
        let mut raw = String::new();
        if input.read_to_string(&mut raw).is_err() {
            let _ = writeln!(err, "chinwag: failed to read stdin payload");
            return 2;
        }
        if !raw.trim().is_empty() {
            match serde_json::from_str::<StdinDispatchPayload>(&raw) {
                Ok(parsed) => stdin_payload = parsed,
                Err(_) => {
                    let _ = writeln!(err, "chinwag: invalid_arguments");
                    return 2;
                }
            }
        }
    }

    let ambient_actor = std::env::var("CHINWAG_ACTOR").ok();
    let identity =
        match prepare_dispatch_identity(&request, &stdin_payload, ambient_actor.as_deref()) {
            Ok(value) => value,
            Err(error) => {
                let _ = writeln!(err, "chinwag: {error}");
                return 2;
            }
        };
    let agent_upper = identity.child().seat().to_owned();
    let Some(body) = request
        .body
        .or(stdin_payload.body)
        .or(stdin_payload.message)
    else {
        let _ = writeln!(err, "chinwag: invalid_arguments");
        return 2;
    };
    if agent_upper.is_empty() || body.trim().is_empty() {
        let _ = writeln!(err, "chinwag: invalid_arguments");
        return 2;
    }

    let sender = identity.parent().to_string();
    let item_key = request
        .item
        .or(stdin_payload.item_key)
        .or(stdin_payload.item)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "chinwag-v0.1.1-sprint".to_owned());
    let crdb_path = request.crdb.or_else(|| {
        stdin_payload
            .crdb
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
    });

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let hash_suffix = match crate::agent_instance::new_instance_id() {
        Ok(value) => value,
        Err(error) => {
            let _ = writeln!(err, "chinwag: {error}");
            return 2;
        }
    };
    let agent_instance = identity.child().to_string();

    let repo_root = resolve_repo_root(crdb_path.as_deref());
    let persona = load_persona(&agent_upper, stdin_payload.custom_agent.as_ref());
    let memories = recall_native_memory(&agent_upper.to_ascii_lowercase(), &body, &repo_root);

    // Per-seat commit signing for the engine process. Fails safe: with no key
    // pair for the seat nothing is injected and only a warning is logged.
    let signing =
        seat_signing::resolve(&agent_upper, Path::new(&user_home()), &default_repo_root());
    if let Some(warning) = &signing.warning {
        let _ = writeln!(err, "chinwag: warning: {warning}");
    }
    let signing_note = signing
        .is_active()
        .then(|| seat_signing::brief_note(&agent_upper));

    let full_prompt = match assemble_dispatch_prompt(
        &agent_upper,
        &persona,
        &memories,
        &item_key,
        &agent_instance,
        &sender,
        &stdin_payload.history,
        signing_note.as_deref(),
        &body,
        MAX_PROMPT_BYTES,
    ) {
        Ok(prompt) => prompt,
        Err(reason) => {
            let _ = writeln!(err, "chinwag: {reason}");
            return 2;
        }
    };

    let mut engine_env = signing.env.clone();
    engine_env.extend(identity.environment());

    let (reply, engine_used) = dispatch_to_engine(
        &agent_upper,
        &full_prompt,
        stdin_payload.custom_agent.as_ref(),
        &engine_env,
        &identity,
    );
    let dispatch_ok = !matches!(engine_used, "unavailable" | "hosted-agent-error");

    let inbound_id = format!("msg-in-{now_ms}-{hash_suffix}");
    let outbound_id = format!("msg-out-{now_ms}-{hash_suffix}");

    let (crdb_status, crdb_persisted) = match persist_to_crdb(
        &repo_root,
        &DispatchExchange {
            identity: &identity,
            item_key: &item_key,
            inbound_id: &inbound_id,
            inbound_body: &body,
            outbound_id: &outbound_id,
            outbound_body: &reply,
            now_ms,
        },
    ) {
        Ok(()) => ("stored".to_owned(), true),
        Err(reason) => {
            let _ = writeln!(err, "chinwag: crdb_error: {reason}");
            (format!("error:{reason}"), false)
        }
    };

    notify_grokbot_department_relay(&agent_upper, &sender, &item_key, &body, &reply);
    retain_native_memory(
        &repo_root,
        &agent_upper,
        engine_used,
        &sender,
        &item_key,
        &body,
        &reply,
    );

    let output = json!({
        "ok": dispatch_ok,
        "agent": agent_upper,
        "agent_instance": agent_instance,
        "sender_instance": sender,
        "engine": engine_used,
        "reply": reply,
        "crdb_message_id": outbound_id,
        "crdb_inbound_id": inbound_id,
        "crdb_thread_id": agent_instance,
        "item_key": item_key,
        "crdb_persisted": crdb_persisted,
        "crdb_status": crdb_status
    });
    if serde_json::to_writer(&mut *out, &output).is_err()
        || out.write_all(b"\n").is_err()
        || out.flush().is_err()
    {
        return 1;
    }
    if dispatch_ok { 0 } else { 1 }
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
