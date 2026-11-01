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

//! DeepSeek v4.1 Flash engine (Cloudflare Workers AI, `@cf/deepseek-ai/deepseek-v4.1-flash-1017`)
//! for the ephemeral DEV-1..5 and QA-1..5 seats (and legacy EPHEMERAL-DEV / EPHEMERAL-QA pools).
//!
//! * Gate: the engine is only used when the token file exists (`enabled()`), so
//!   merging this before activation changes nothing.
//! * Concurrency: at most `POOL_CONCURRENCY` (10) in-flight tasks per pool,
//!   enforced across processes with advisory file locks (`slots/<pool>-N.lock`).
//! * Kill switch: if `<state>/PAUSE` exists (or `EPHEMERAL_POOLS_PAUSED=1`) no
//!   task starts and nothing is sent to Cloudflare. No fallback to other engines.
//! * Spend ledger: every call appends token usage and estimated cost to
//!   `<state>/usage/YYYY-MM.jsonl` (read by the spend-guard Dagu DAG).
//! * The token is read from a mode-0600 file and handed to curl on stdin, so it
//!   never appears in argv, logs, errors or the ledger.

use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MODEL_ID: &str = "@cf/deepseek-ai/deepseek-v4.1-flash-1017";
pub const DEFAULT_ACCOUNT_ID: &str = "a9dce15ce0193da7d7f1d5dd3a53022b";
pub const POOL_CONCURRENCY: usize = 10;
pub const ENGINE_LABEL: &str = "cloudflare-deepseek-v4.1-flash";

const USD_PER_M_INPUT: f64 = 0.30;
const USD_PER_M_OUTPUT: f64 = 1.20;
const USD_PER_M_CACHED_INPUT: f64 = 0.006;
const MAX_COMPLETION_TOKENS: u64 = 16_000;
/// Appended as a system message. Without it the model's default `high` reasoning can eat the whole
/// completion budget and return `content: ""` with `finish_reason: "length"`.
const OUTPUT_CONTRACT: &str = "Answer in the requested output format only; when JSON is requested, return only that JSON with no preamble or code fences. Keep your reasoning brief and always finish the answer; never use your whole output budget on reasoning.";
const CURL_MAX_TIME_SECS: u64 = 600;
const SLOT_WAIT: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    Dev,
    Qa,
}

impl Pool {
    pub fn tag(self) -> &'static str {
        match self {
            Pool::Dev => "dev",
            Pool::Qa => "qa",
        }
    }
}

/// Reasoning effort sent to Workers AI. Env `EPHEMERAL_DEEPSEEK_REASONING` (none|low|high|max)
/// overrides; otherwise DEV seats use `low` and QA seats `none`. (The model defaults to `high`,
/// which burned the entire output budget on hidden reasoning and left `content` empty.)
pub fn reasoning_effort_for(pool: Pool, env_override: Option<&str>) -> &'static str {
    match env_override.map(str::trim) {
        Some("none") => "none",
        Some("low") => "low",
        Some("high") => "high",
        Some("max") => "max",
        _ => match pool {
            Pool::Dev => "low",
            Pool::Qa => "none",
        },
    }
}

/// Seats routed to the DeepSeek engine:
///
/// * `DEV-1`..`DEV-5` -> [`Pool::Dev`], `QA-1`..`QA-5` -> [`Pool::Qa`]
/// * legacy `EPHEMERAL-DEV`, `EPHEMERAL-DEV-3`, `EPHEMERAL-QA`, `EPHEMERAL-QA-2`, ...
///
/// Plain `QA` (the Cleanroom Verifier seat) and anything outside 1..=5 are *not* matched.
pub fn pool_for_agent(agent_upper: &str) -> Option<Pool> {
    let is_legacy = |base: &str| {
        agent_upper == base
            || agent_upper
                .strip_prefix(base)
                .and_then(|r| r.strip_prefix('-'))
                .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    };
    let is_seat = |base: &str| {
        agent_upper
            .strip_prefix(base)
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5"))
    };
    if is_seat("DEV") || is_legacy("EPHEMERAL-DEV") {
        Some(Pool::Dev)
    } else if is_seat("QA") || is_legacy("EPHEMERAL-QA") {
        Some(Pool::Qa)
    } else {
        None
    }
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned()))
}

pub fn state_dir() -> PathBuf {
    match std::env::var("EPHEMERAL_POOLS_DIR") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => home().join(".config/ephemeral-pools"),
    }
}

pub fn token_path() -> PathBuf {
    match std::env::var("EPHEMERAL_DEEPSEEK_TOKEN_FILE") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => home().join(".config/cloudflare/workers-ai-ephemeral.token"),
    }
}

fn account_id() -> String {
    match std::env::var("CF_WORKERS_AI_ACCOUNT_ID") {
        Ok(v) if v.len() == 32 && v.chars().all(|c| c.is_ascii_hexdigit()) => v,
        _ => DEFAULT_ACCOUNT_ID.to_owned(),
    }
}

/// True when the pools should use DeepSeek: token file present and not disabled.
pub fn enabled() -> bool {
    std::env::var("EPHEMERAL_DEEPSEEK_DISABLE")
        .map(|v| v != "1")
        .unwrap_or(true)
        && token_path().is_file()
}

/// Kill switch. Returns Some(reason) when the pools are paused.
pub fn paused(dir: &Path) -> Option<String> {
    if std::env::var("EPHEMERAL_POOLS_PAUSED").is_ok_and(|v| v == "1") {
        return Some("EPHEMERAL_POOLS_PAUSED=1".to_owned());
    }
    let flag = dir.join("PAUSE");
    if flag.exists() {
        let why = fs::read_to_string(&flag).unwrap_or_default();
        let why: String = why.trim().chars().take(200).collect();
        return Some(if why.is_empty() {
            "PAUSE file present".to_owned()
        } else {
            why
        });
    }
    None
}

pub struct SlotGuard {
    _file: File,
}

/// Take one of `max` per-pool slots, waiting up to `wait`. Released on drop
/// (or process exit, so a crashed worker never leaks a slot).
pub fn acquire_slot(
    dir: &Path,
    pool: Pool,
    max: usize,
    wait: Duration,
) -> Result<SlotGuard, String> {
    let slots = dir.join("slots");
    fs::create_dir_all(&slots).map_err(|e| format!("slot dir: {e}"))?;
    let deadline = Instant::now() + wait;
    loop {
        for i in 0..max {
            let path = slots.join(format!("{}-{i}.lock", pool.tag()));
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| format!("slot open: {e}"))?;
            match file.try_lock() {
                Ok(()) => return Ok(SlotGuard { _file: file }),
                Err(TryLockError::WouldBlock) => continue,
                Err(TryLockError::Error(e)) => return Err(format!("slot lock: {e}")),
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("all {max} {} slots busy", pool.tag()));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn read_token(path: &Path) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|_| "token file unreadable".to_owned())?;
    if meta.mode() & 0o077 != 0 {
        return Err("token file must be mode 600".to_owned());
    }
    let raw = fs::read_to_string(path).map_err(|_| "token file unreadable".to_owned())?;
    let tok = raw.trim().to_owned();
    let ok = (20..=300).contains(&tok.len())
        && tok
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(tok)
    } else {
        Err("token file malformed".to_owned())
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub cached_tokens: u64,
    pub completion_tokens: u64,
}

impl Usage {
    pub fn cost_usd(&self) -> f64 {
        let fresh = self.prompt_tokens.saturating_sub(self.cached_tokens) as f64;
        (fresh * USD_PER_M_INPUT
            + self.cached_tokens as f64 * USD_PER_M_CACHED_INPUT
            + self.completion_tokens as f64 * USD_PER_M_OUTPUT)
            / 1_000_000.0
    }
}

/// A parsed Workers AI completion, before any emptiness/truncation judgement.
#[derive(Debug, PartialEq)]
pub struct Completion {
    pub text: String,
    pub usage: Usage,
    pub finish_reason: Option<String>,
}

impl Completion {
    /// `Some(reason)` when the answer must not be treated as a result: empty content, or cut off
    /// by the token limit. Names finish_reason and completion_tokens so the cause is visible.
    pub fn failure(&self) -> Option<String> {
        let fin = self.finish_reason.as_deref();
        let detail = format!(
            "finish_reason={}, completion_tokens={}",
            fin.unwrap_or("none"),
            self.usage.completion_tokens
        );
        if self.text.is_empty() {
            let hint = if fin == Some("length") {
                "; reasoning likely consumed the whole budget"
            } else {
                ""
            };
            Some(format!("empty completion ({detail}){hint}"))
        } else if fin == Some("length") {
            Some(format!("truncated completion ({detail})"))
        } else {
            None
        }
    }
}

/// Parses both the native `{"result":{...}}` envelope and a bare OpenAI-style body.
/// Does not judge emptiness/truncation; see [`Completion::failure`].
pub fn parse_completion(raw: &str) -> Result<Completion, String> {
    let v: Value = serde_json::from_str(raw.trim()).map_err(|_| "non-JSON response".to_owned())?;
    if v.get("success").and_then(Value::as_bool) == Some(false) {
        let msg = v
            .pointer("/errors/0/message")
            .and_then(Value::as_str)
            .unwrap_or("request failed");
        let code = v
            .pointer("/errors/0/code")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        return Err(format!(
            "cloudflare error {code}: {}",
            msg.chars().take(200).collect::<String>()
        ));
    }
    let root = v.get("result").unwrap_or(&v);
    let text = match root.pointer("/choices/0/message/content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(""),
        _ => root
            .get("response")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_default(),
    };
    let u = root.get("usage");
    let n = |p: &str| {
        u.and_then(|u| u.pointer(p))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    Ok(Completion {
        text: text.trim().to_owned(),
        usage: Usage {
            prompt_tokens: n("/prompt_tokens"),
            cached_tokens: n("/prompt_tokens_details/cached_tokens"),
            completion_tokens: n("/completion_tokens"),
        },
        finish_reason: root
            .pointer("/choices/0/finish_reason")
            .or_else(|| root.get("finish_reason"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Strict form: errors on empty content or `finish_reason: "length"`.
pub fn parse_response(raw: &str) -> Result<(String, Usage), String> {
    let c = parse_completion(raw)?;
    match c.failure() {
        Some(why) => Err(why),
        None => Ok((c.text, c.usage)),
    }
}

fn civil_from_days(z: i64) -> (i64, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32)
}

/// `YYYY-MM` (UTC) for a unix-seconds timestamp.
pub fn month_key(unix_secs: i64) -> String {
    let (y, m) = civil_from_days(unix_secs.div_euclid(86_400));
    format!("{y:04}-{m:02}")
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn ledger_append(dir: &Path, pool: Pool, agent: &str, ok: bool, usage: &Usage) {
    let secs = now_secs();
    let usage_dir = dir.join("usage");
    if fs::create_dir_all(&usage_dir).is_err() {
        return;
    }
    let line = json!({
        "ts": secs,
        "pool": pool.tag(),
        "agent": agent,
        "model": MODEL_ID,
        "ok": ok,
        "prompt_tokens": usage.prompt_tokens,
        "cached_tokens": usage.cached_tokens,
        "completion_tokens": usage.completion_tokens,
        // Tokens are billed even when the answer is empty/truncated; a transport failure passes
        // Usage::default() so its cost is still 0.
        "cost_usd": usage.cost_usd(),
    });
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(usage_dir.join(format!("{}.jsonl", month_key(secs))))
    {
        let _ = f.write_all(format!("{line}\n").as_bytes());
    }
}

fn call_workers_ai(dir: &Path, token: &str, prompt: &str, pool: Pool) -> Result<String, String> {
    let mut body = json!({
        "messages": [
            { "role": "system", "content": OUTPUT_CONTRACT },
            { "role": "user", "content": prompt },
        ],
        "max_completion_tokens": MAX_COMPLETION_TOKENS,
    });
    let env_effort = std::env::var("EPHEMERAL_DEEPSEEK_REASONING").ok();
    body["reasoning_effort"] = json!(reasoning_effort_for(pool, env_effort.as_deref()));
    let tmp = dir.join("tmp").join(format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&tmp).map_err(|e| format!("tmp dir: {e}"))?;
    let _ = fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let body_path = tmp.join("req.json");
    let result = (|| -> Result<String, String> {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&body_path)
            .map_err(|e| format!("body file: {e}"))?;
        f.write_all(body.to_string().as_bytes())
            .map_err(|e| format!("body write: {e}"))?;
        drop(f);
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/ai/run/{MODEL_ID}",
            account_id()
        );
        let mut child = Command::new("/usr/bin/curl")
            .args([
                "-sS",
                "--max-time",
                &CURL_MAX_TIME_SECS.to_string(),
                "-K",
                "-",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                &format!("@{}", body_path.display()),
                "-w",
                "\n%{http_code}",
                &url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "curl spawn failed".to_owned())?;
        if let Some(mut stdin) = child.stdin.take() {
            // curl config on stdin keeps the bearer token out of argv.
            let _ =
                stdin.write_all(format!("header = \"Authorization: Bearer {token}\"\n").as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|_| "curl wait failed".to_owned())?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (payload, code) = text.rsplit_once('\n').unwrap_or((text.as_str(), ""));
        let code = code.trim();
        if !out.status.success() {
            return Err(format!(
                "transport error (curl exit {:?})",
                out.status.code()
            ));
        }
        if code != "200" {
            let detail = parse_response(payload).err().unwrap_or_default();
            return Err(format!("HTTP {code} {detail}").trim().to_owned());
        }
        Ok(payload.to_owned())
    })();
    let _ = fs::remove_dir_all(&tmp);
    result
}

/// Entry point used by `dispatch_to_engine`. Never falls back to another engine.
pub fn run(pool: Pool, agent_upper: &str, prompt: &str) -> (String, &'static str) {
    let dir = state_dir();
    let note = |msg: String| (format!("[{agent_upper} note]: {msg}"), ENGINE_LABEL);

    if let Some(why) = paused(&dir) {
        return note(format!(
            "{} pool paused by kill switch ({why}); task not run.",
            pool.tag()
        ));
    }
    let token = match read_token(&token_path()) {
        Ok(t) => t,
        Err(e) => return note(format!("DeepSeek engine unavailable: {e}; task not run.")),
    };
    let _slot = match acquire_slot(&dir, pool, POOL_CONCURRENCY, SLOT_WAIT) {
        Ok(s) => s,
        Err(e) => return note(format!("{e}; task not run.")),
    };
    // Re-check after waiting for a slot: the guard may have tripped meanwhile.
    if let Some(why) = paused(&dir) {
        return note(format!(
            "{} pool paused by kill switch ({why}); task not run.",
            pool.tag()
        ));
    }
    match call_workers_ai(&dir, &token, prompt, pool).and_then(|raw| parse_completion(&raw)) {
        Ok(c) => {
            if let Some(why) = c.failure() {
                // Billed but unusable: record the real cost with ok=false and say why.
                ledger_append(&dir, pool, agent_upper, false, &c.usage);
                return note(format!("DeepSeek call failed: {why}"));
            }
            ledger_append(&dir, pool, agent_upper, true, &c.usage);
            (c.text, ENGINE_LABEL)
        }
        Err(e) => {
            ledger_append(&dir, pool, agent_upper, false, &Usage::default());
            note(format!("DeepSeek call failed: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("deepseek-pool-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn pool_matching() {
        assert_eq!(pool_for_agent("EPHEMERAL-DEV"), Some(Pool::Dev));
        assert_eq!(pool_for_agent("EPHEMERAL-DEV-3"), Some(Pool::Dev));
        assert_eq!(pool_for_agent("EPHEMERAL-QA-2"), Some(Pool::Qa));
        assert_eq!(pool_for_agent("EPHEMERAL-QA"), Some(Pool::Qa));
        for n in 1..=5 {
            assert_eq!(pool_for_agent(&format!("DEV-{n}")), Some(Pool::Dev));
            assert_eq!(pool_for_agent(&format!("QA-{n}")), Some(Pool::Qa));
        }
        assert_eq!(pool_for_agent("QA"), None);
        assert_eq!(pool_for_agent("DEV"), None);
        assert_eq!(pool_for_agent("DEV-0"), None);
        assert_eq!(pool_for_agent("DEV-6"), None);
        assert_eq!(pool_for_agent("QA-0"), None);
        assert_eq!(pool_for_agent("QA-6"), None);
        assert_eq!(pool_for_agent("DEV-10"), None);
        assert_eq!(pool_for_agent("QA-1X"), None);
        assert_eq!(pool_for_agent("FLINT"), None);
        assert_eq!(pool_for_agent("TYPE"), None);
        assert_eq!(pool_for_agent("EPHEMERAL-DEVX"), None);
        assert_eq!(pool_for_agent("EPHEMERAL-ANALYST"), None);
    }

    #[test]
    fn parses_native_and_openai_shapes() {
        let native = r#"{"result":{"choices":[{"message":{"content":" hi "}}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"prompt_tokens_details":{"cached_tokens":200}}},"success":true}"#;
        let (t, u) = parse_response(native).unwrap();
        assert_eq!(t, "hi");
        assert_eq!(
            u,
            Usage {
                prompt_tokens: 1000,
                cached_tokens: 200,
                completion_tokens: 500
            }
        );
        let bare = r#"{"choices":[{"message":{"content":"yo"}}]}"#;
        assert_eq!(parse_response(bare).unwrap().0, "yo");
        let legacy = r#"{"result":{"response":"old"},"success":true}"#;
        assert_eq!(parse_response(legacy).unwrap().0, "old");
        let err = r#"{"success":false,"errors":[{"code":7003,"message":"nope"}]}"#;
        assert!(parse_response(err).unwrap_err().contains("7003"));
        assert!(parse_response("<html>").is_err());
        assert!(parse_response(r#"{"result":{"choices":[{"message":{"content":""}}]}}"#).is_err());
    }

    #[test]
    fn empty_and_truncated_completions_name_finish_reason() {
        let empty_len = r#"{"result":{"choices":[{"message":{"content":"","reasoning":"thinking"},"finish_reason":"length"}],"usage":{"prompt_tokens":10,"completion_tokens":16000}}}"#;
        let c = parse_completion(empty_len).unwrap();
        assert_eq!(c.finish_reason.as_deref(), Some("length"));
        assert_eq!(c.usage.completion_tokens, 16000);
        let why = c.failure().unwrap();
        assert!(
            why.contains("empty completion") && why.contains("finish_reason=length"),
            "{why}"
        );
        assert!(
            why.contains("completion_tokens=16000") && why.contains("reasoning"),
            "{why}"
        );
        assert!(
            parse_response(empty_len)
                .unwrap_err()
                .contains("finish_reason=length")
        );

        let partial = r#"{"choices":[{"message":{"content":"half"},"finish_reason":"length"}]}"#;
        assert!(
            parse_completion(partial)
                .unwrap()
                .failure()
                .unwrap()
                .starts_with("truncated completion")
        );
        assert!(parse_response(partial).is_err());

        let empty_stop = r#"{"choices":[{"message":{"content":""},"finish_reason":"stop"}]}"#;
        assert!(
            parse_completion(empty_stop)
                .unwrap()
                .failure()
                .unwrap()
                .contains("finish_reason=stop")
        );

        let ok = r#"{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}"#;
        assert_eq!(parse_completion(ok).unwrap().failure(), None);
        assert_eq!(parse_response(ok).unwrap().0, "{}");
    }

    #[test]
    fn reasoning_effort_defaults_and_override() {
        assert_eq!(reasoning_effort_for(Pool::Dev, None), "low");
        assert_eq!(reasoning_effort_for(Pool::Qa, None), "none");
        assert_eq!(reasoning_effort_for(Pool::Qa, Some("high")), "high");
        assert_eq!(reasoning_effort_for(Pool::Dev, Some(" none ")), "none");
        assert_eq!(reasoning_effort_for(Pool::Dev, Some("turbo")), "low");
        assert_eq!(reasoning_effort_for(Pool::Qa, Some("")), "none");
    }

    #[test]
    fn ledger_records_cost_of_unusable_answers() {
        let dir = tmpdir("ledger");
        let u = Usage {
            prompt_tokens: 1_000_000,
            cached_tokens: 0,
            completion_tokens: 1_000_000,
        };
        ledger_append(&dir, Pool::Dev, "DEV-1", false, &u);
        ledger_append(&dir, Pool::Dev, "DEV-1", false, &Usage::default());
        let file = dir
            .join("usage")
            .join(format!("{}.jsonl", month_key(now_secs())));
        let rows: Vec<Value> = fs::read_to_string(file)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows[0]["ok"], json!(false));
        assert!((rows[0]["cost_usd"].as_f64().unwrap() - 1.50).abs() < 1e-9);
        assert_eq!(rows[1]["cost_usd"].as_f64().unwrap(), 0.0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cost_math() {
        let u = Usage {
            prompt_tokens: 1_000_000,
            cached_tokens: 0,
            completion_tokens: 1_000_000,
        };
        assert!((u.cost_usd() - 1.50).abs() < 1e-9);
        let c = Usage {
            prompt_tokens: 1_000_000,
            cached_tokens: 1_000_000,
            completion_tokens: 0,
        };
        assert!((c.cost_usd() - 0.006).abs() < 1e-9);
    }

    #[test]
    fn month_keys() {
        assert_eq!(month_key(0), "1970-01");
        assert_eq!(month_key(1_767_225_600), "2026-01");
        assert_eq!(month_key(1_767_225_599), "2025-12");
        assert_eq!(month_key(1_793_253_600), "2026-10");
    }

    #[test]
    fn slots_cap_at_ten_per_pool_and_release() {
        let dir = tmpdir("slots");
        let mut held = Vec::new();
        for _ in 0..POOL_CONCURRENCY {
            held.push(
                acquire_slot(&dir, Pool::Dev, POOL_CONCURRENCY, Duration::from_millis(50)).unwrap(),
            );
        }
        assert!(
            acquire_slot(
                &dir,
                Pool::Dev,
                POOL_CONCURRENCY,
                Duration::from_millis(600)
            )
            .is_err()
        );
        assert!(acquire_slot(&dir, Pool::Qa, POOL_CONCURRENCY, Duration::from_millis(50)).is_ok());
        held.pop();
        assert!(
            acquire_slot(
                &dir,
                Pool::Dev,
                POOL_CONCURRENCY,
                Duration::from_millis(600)
            )
            .is_ok()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn kill_switch_file() {
        let dir = tmpdir("kill");
        assert!(paused(&dir).is_none());
        fs::write(dir.join("PAUSE"), "spend 1600").unwrap();
        assert_eq!(paused(&dir).as_deref(), Some("spend 1600"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_must_be_private_and_wellformed() {
        let dir = tmpdir("tok");
        let p = dir.join("t");
        fs::write(&p, "abcdefghijklmnopqrstuvwxyz0123456789_-\n").unwrap();
        fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        assert!(read_token(&p).is_err());
        fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert!(read_token(&p).is_ok());
        fs::write(&p, "short").unwrap();
        assert!(read_token(&p).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
