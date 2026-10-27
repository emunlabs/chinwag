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
use chinwag_snapshot_session_private::replacement::{AgentDispatchRecord, WriteOwner, WriteSession};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
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

fn wiki_agents_dir() -> PathBuf {
    PathBuf::from(user_home()).join("WORKSPACE/paperclip-wiki/wiki/agents")
}

fn pilot_company_agents_dir() -> PathBuf {
    PathBuf::from(user_home())
        .join(".paperclip-pilot/control/instances/pilot/companies/055c2eb5-1b6e-4255-9c29-5a562c0be9e9/agents")
}

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

fn agent_uuid(agent_upper: &str) -> Option<&'static str> {
    match agent_upper {
        "GEMINI-PM" => Some("382e7010-ea4d-48f7-a1bb-96dca02a0921"),
        "TYPE" => Some("712957a9-81c7-4421-860a-812c92935d2d"),
        "MOTION" => Some("b825e467-2cd1-419b-8d7e-60bfa279e6d3"),
        "FREQUENCY" => Some("81d5c117-b837-47d6-9a40-4d046cc5b43a"),
        "SCRIBE" => Some("b994f8bd-c7a4-49a9-847e-b7573b3ad20a"),
        "DELIVERY" => Some("27908fde-54f6-4e22-98e8-8b25c02fe405"),
        "PRODUCT" => Some("48c077d3-d7cb-4d0c-95a8-0a861769ae1d"),
        "VENTURE" => Some("d41eae97-03d6-4661-8041-595d35bdf8c1"),
        "EAGLE-EYE" => Some("d54f57ec-d69f-49de-b970-296e056f6dbc"),
        "MO" => Some("2be0efe4-8464-4631-a6a0-05ec43e171dd"),
        "INVESTIGATIONS" => Some("ac426346-0c88-48d6-bd5e-e60fbacc70c8"),
        "BIZFIN" => Some("a7a86d5b-f4b1-4c8f-b10f-a626bb8fa491"),
        "RECORD" => Some("a5e93796-026f-429e-8eb5-cc57406e6134"),
        "DECLARATION" => Some("0337b4c3-b7d5-4103-825f-3284d03eb99a"),
        "GROWTH" => Some("89c93164-a28d-49d5-9762-d553b38ab4a3"),
        "SPARK" => Some("b519d4d3-258b-406e-a888-897ccdca7119"),
        "DEX" => Some("7ce8b26d-b874-42dc-bc4b-b8151ca44b2d"),
        "SOCIAL" => Some("e804bfac-d3b9-41ad-901c-99e56ab6d6c4"),
        "S-AND-M" => Some("decc277b-4bb2-4895-b239-b2b240b78782"),
        "ENG" => Some("d11fb9f7-cd54-4871-96ea-a026ec27fd41"),
        "ARCHITECT" => Some("507a20e1-4712-40a8-94b6-445af620af87"),
        "RUST" => Some("1d8289f3-9215-4ad2-ab68-92b579d12f68"),
        "INDEX" => Some("f7f321de-5a63-4d89-ab89-eb275bf44ae8"),
        "DEV-1" => Some("20f1fef2-576e-4829-9107-2f2f6883e84a"),
        "DEV-2" => Some("7259c85e-d752-42e9-ad3f-66be7f4225cf"),
        "DEV-3" => Some("2d462326-c1cf-4863-ac4a-01d505e5be5f"),
        "INFRA BOT (GROK)" => Some("93e39019-ca70-4875-a8f5-bf2d5edf6d9d"),
        "INFRAJR" => Some("f4459182-97d5-4865-b6e9-6ad46a5c4e99"),
        "ALISTAIR" => Some("a3c04053-bc91-467c-9e63-29ed08ae652a"),
        "QA" => Some("2a4cbbfe-ca74-416c-8150-05d295350770"),
        "HOUSEKEEPING" => Some("ee288c4e-b0d0-4eee-b40d-327c760408d7"),
        "DOCS" => Some("9c3c7457-6605-4d0e-80f4-462ab4bf5df7"),
        "SUMMARIZER" => Some("3d094e2a-2bec-41be-858e-6ae490e04411"),
        _ => None,
    }
}

fn grokbot_dept(agent_upper: &str) -> &'static str {
    match agent_upper {
        "ALISTAIR" | "HOUSEKEEPING" | "INFRA BOT (GROK)" | "INFRAJR" | "QA" | "FLINT" | "DOCS" | "MGMT-INFRA" | "INFRA" => "infra",
        "ARCHITECT" | "RUST" | "INDEX" | "DEV-1" | "DEV-2" | "DEV-3" | "ENG" | "MGMT-ENG" => "eng",
        "VENTURE" | "MO" | "EAGLE-EYE" | "BIZFIN" | "INVESTIGATIONS" | "RECORD" | "DEX" | "MGMT-BIZFIN" => "bizfin",
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

fn short_hash(parts: &[&str], ts_ms: i64) -> String {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(ts_ms.to_be_bytes());
    let digest = hasher.finalize();
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn load_persona(agent_upper: &str, custom: Option<&CustomAgentMeta>) -> String {
    let agent_lower = agent_upper.to_ascii_lowercase();
    let mut parts = Vec::new();
    if agent_upper == "GEMINI-PM" {
        parts.push(
            "You are ■ GEMINI-PM (Antigravity Product Owner & Chief Orchestrator for Chinwag & Rogue Machine), talking directly with Brian Spector on Mission Control (:5487).\nKeep your answers concise, sharp, and grounded in live repo & database state. You coordinate all agent engines across Mac Studio and MacBook Pro: Claude Code, OpenAI Codex/ChatGPT, Grok CLI, Recursive Flint (Local MLX 262k on MacBook Pro), and Grok Bot Department Relays.".to_owned(),
        );
    } else if agent_upper == "FLINT" {
        parts.push(
            "You are ■ FLINT (Flint from Recursive · flint-int4 MLX · 262k context running on MacBook Pro 100.108.108.25:11500), Local Adversarial Code Auditor & Rust/CRDT Verifier for Chinwag at Emun Labs.\nRespond with surgical Rust/CRDT/concurrency rigor.".to_owned(),
        );
    } else {
        parts.push(format!(
            "You are {agent_upper}, a core specialist agent at Emun Labs / Rogue Machine working directly with Brian and Nic.\nRespond directly, helpfully, and in your authentic specialist persona."
        ));
    }

    let wiki_dir = wiki_agents_dir().join(&agent_lower);
    for fname in ["SOUL.md", "AGENT.md", "AGENTS.md", "SKILLS.md", "MEMORY.md", "TOOLS.md"] {
        let fpath = wiki_dir.join(fname);
        if let Ok(content) = fs::read_to_string(&fpath) {
            parts.push(format!(
                "\n--- {fname} (Wiki) ---\n{}",
                truncate_utf8(&content, 4000)
            ));
        }
    }

    if let Some(uid) = agent_uuid(agent_upper) {
        let inst_dir = pilot_company_agents_dir()
            .join(uid)
            .join("instructions");
        for fname in ["SOUL.md", "AGENT.md", "AGENTS.md", "MEMORY.md"] {
            let fpath = inst_dir.join(fname);
            if let Ok(content) = fs::read_to_string(&fpath) {
                parts.push(format!(
                    "\n--- {fname} (Instructions) ---\n{}",
                    truncate_utf8(&content, 3000)
                ));
            }
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

fn dispatch_to_engine(
    agent_upper: &str,
    full_prompt: &str,
    custom: Option<&CustomAgentMeta>,
) -> (String, &'static str) {
    if let Ok(mock) = std::env::var("CHINWAG_AGENT_MOCK_REPLY")
        && !mock.trim().is_empty()
    {
        return (mock, "mock-engine");
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
    let is_gemini = agent_upper == "GEMINI-PM"
        || engine_hint == "gemini-cli"
        || engine_hint == "gemini"
        || engine_hint.contains("gemini-cli");

    // 1. Recursive Flint (Local MLX 262k on MacBook Pro 100.108.108.25:11500)
    let flint_bin = Path::new(&local_bin).join("flint-agent");
    if is_flint && flint_bin.exists() {
        if let Ok(out) = Command::new(&flint_bin)
            .args([
                "run",
                full_prompt,
                "--cwd",
                &repo_dir.to_string_lossy(),
            ])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .output()
        {
            let text = strip_flint_banner(&String::from_utf8_lossy(&out.stdout));
            if out.status.success() && !text.is_empty() {
                return (text, "flint-agent");
            }
        }
    }

    // 2. Official Gemini CLI Engine for GEMINI-PM
    if is_gemini && Path::new("/opt/homebrew/bin/gemini").exists() {
        if let Ok(out) = Command::new("/opt/homebrew/bin/node")
            .args(["/opt/homebrew/bin/gemini", "-p", full_prompt, "--yolo"])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() && !text.is_empty() {
                return (text, "gemini-cli");
            }
        }
    }

    // 3. OpenAI Codex / ChatGPT Engine for ARCHITECT, RUST, DEV-1
    let codex_bin = Path::new(&local_bin).join("codex");
    if (matches!(agent_upper, "ARCHITECT" | "RUST" | "DEV-1") || engine_hint.contains("codex"))
        && codex_bin.exists()
    {
        if let Ok(out) = Command::new(&codex_bin)
            .args(["exec", "--skip-git-repo-check", full_prompt])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() && !text.is_empty() {
                return (text, "codex-chatgpt");
            }
        }
    }

    // 4. Grok CLI Engine for DELIVERY, SPARK, GROWTH, HOUSEKEEPING, INFRA BOT (GROK)
    let grok_bin = Path::new(&local_bin).join("grok");
    if (matches!(
        agent_upper,
        "DELIVERY" | "SPARK" | "GROWTH" | "HOUSEKEEPING" | "INFRA BOT (GROK)"
    ) || engine_hint.contains("grok"))
        && grok_bin.exists()
    {
        if let Ok(out) = Command::new(&grok_bin)
            .args(["agent", "--always-approve", full_prompt])
            .current_dir(&default_cwd)
            .env("PATH", &path_env)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() && !text.is_empty() {
                return (text, "grok-cli");
            }
        }
    }

    // 5. Claude Code Engine (Primary for MO, TYPE, VENTURE, EAGLE-EYE, DECLARATION, ALISTAIR, SCRIBE & Fallback)
    let local_claude = Path::new(&local_bin).join("claude");
    let claude_bin: PathBuf = if local_claude.exists() {
        local_claude
    } else {
        PathBuf::from("/opt/homebrew/bin/claude")
    };
    if let Ok(out) = Command::new(&claude_bin)
        .args(["--print", "--dangerously-skip-permissions", full_prompt])
        .current_dir(&default_cwd)
        .env("PATH", &path_env)
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !text.is_empty() {
            return (text, "claude-code");
        }
        let err_text = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return (
            format!(
                "[{agent_upper} note]: Engine exited with {:?}. {}",
                out.status.code(),
                truncate_utf8(&err_text, 400)
            ),
            "claude-code",
        );
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

fn persist_to_crdb(
    repo_root: &Path,
    thread_id: &str,
    inbound_id: &str,
    sender: &str,
    inbound_body: &str,
    outbound_id: &str,
    agent_upper: &str,
    outbound_body: &str,
    now_ms: i64,
) -> Result<(), String> {
    let owner = WriteOwner::acquire_existing_private_fixture(repo_root)
        .map_err(|e| format!("acquire_write_owner: {}", e.reason))?;
    let session =
        WriteSession::from_owner(owner).map_err(|e| format!("write_session: {}", e.reason))?;
    let record = AgentDispatchRecord::try_new(
        thread_id.to_owned(),
        "emunlabs/chinwag".to_owned(),
        "refs/heads/feat/v0.1.1-invariants-and-memory".to_owned(),
        format!("Chinwag Agent Comms · {thread_id}"),
        inbound_id.to_owned(),
        format!("{}@chinwag.sh", sender.to_ascii_lowercase().replace(' ', "-")),
        "user".to_owned(),
        truncate_utf8(inbound_body, MAX_CRDB_TEXT_BYTES),
        outbound_id.to_owned(),
        format!("{}@chinwag.sh", agent_upper.to_ascii_lowercase().replace(' ', "-")),
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

    let Some(agent_raw) = request.agent.or(stdin_payload.agent) else {
        let _ = writeln!(err, "chinwag: invalid_arguments");
        return 2;
    };
    let agent_upper = agent_raw.trim().to_ascii_uppercase();
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

    let sender = request
        .sender
        .or(stdin_payload.sender)
        .unwrap_or_else(|| "Brian".to_owned());
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

    let repo_root = resolve_repo_root(crdb_path.as_deref());
    let persona = load_persona(&agent_upper, stdin_payload.custom_agent.as_ref());
    let memories = recall_native_memory(&agent_upper.to_ascii_lowercase(), &body, &repo_root);

    let mut prompt_parts = vec![persona];
    if !memories.is_empty() {
        prompt_parts.push(format!(
            "\n--- Recalled Chinwag 3-Tier Memories & Tombstones ({agent_upper}) ---\n{memories}"
        ));
    }
    prompt_parts.push(format!(
        "\n--- Active Work Item Context ---\nLinked item: {item_key}"
    ));
    if !stdin_payload.history.is_empty() {
        let mut transcript = Vec::new();
        let len = stdin_payload.history.len();
        let start = len.saturating_sub(10);
        for h in &stdin_payload.history[start..] {
            let who = if h.role.as_deref() == Some("user") {
                h.sender.as_deref().unwrap_or("User")
            } else {
                &agent_upper
            };
            transcript.push(format!("{who}: {}", h.body.as_deref().unwrap_or("")));
        }
        prompt_parts.push(format!(
            "\n--- Recent Conversation ---\n{}",
            transcript.join("\n\n")
        ));
    }
    prompt_parts.push(format!(
        "\n--- New Message from {sender} ---\n{body}\n\nReply directly as {agent_upper}:"
    ));
    let full_prompt = prompt_parts.join("\n");

    let (reply, engine_used) =
        dispatch_to_engine(&agent_upper, &full_prompt, stdin_payload.custom_agent.as_ref());

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let hash_suffix = short_hash(&[&agent_upper, &sender, &item_key, &body], now_ms);
    let inbound_id = format!("msg-in-{now_ms}-{hash_suffix}");
    let outbound_id = format!("msg-out-{now_ms}-{hash_suffix}");

    let crdb_status = match persist_to_crdb(
        &repo_root,
        &item_key,
        &inbound_id,
        &sender,
        &body,
        &outbound_id,
        &agent_upper,
        &reply,
        now_ms,
    ) {
        Ok(()) => "stored".to_owned(),
        Err(reason) => {
            let _ = writeln!(err, "chinwag: crdb_notice: {reason}");
            format!("deferred:{reason}")
        }
    };

    notify_grokbot_department_relay(&agent_upper, &sender, &item_key, &body, &reply);
    retain_native_memory(&repo_root, &agent_upper, engine_used, &sender, &item_key, &body, &reply);

    let output = json!({
        "ok": true,
        "agent": agent_upper,
        "engine": engine_used,
        "reply": reply,
        "crdb_message_id": outbound_id,
        "crdb_inbound_id": inbound_id,
        "crdb_thread_id": item_key,
        "crdb_status": crdb_status
    });
    if serde_json::to_writer(&mut *out, &output).is_err()
        || out.write_all(b"\n").is_err()
        || out.flush().is_err()
    {
        return 1;
    }
    0
}
