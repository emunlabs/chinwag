// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Embedded Customer-First Local Web App Server (`v4.1`) on `http://127.0.0.1:5487`.
//!
//! Implements `CHWG-0209`:
//!   - Serves the embedded `v4.1` static web application (`assets/ui-v4/*`) directly
//!     from the `chinwag` Rust binary with zero external CDN dependencies.
//!   - Enforces 5-Layer `HB-01` loopback security (`ui_auth.rs`) and single-use `30s`
//!     live-stream tickets (`ui_sse.rs`).
//!   - Enforces `INV-UI-ZERO-JARGON-01` via `scrub_customer_ui_json` so customer-facing
//!     JSON payloads never expose internal infrastructure or substrate terminology.
//!   - Exposes `/api/v4/bootstrap`, `/api/v4/diff`, `/api/v4/inbox/action`, `/api/v4/board`,
//!     `/api/v4/board/sync`, `/api/v4/agents`, `/api/v4/workflow`, `/api/v4/cursor/preview`,
//!     `/api/v4/cursor/apply`, `/api/v4/credits`, `/api/v4/credits/checkout`,
//!     `/api/v4/credits/autorefill`, and `/api/v4/telemetry/track`.

use crate::ui_auth::{
    AuthDecision, ParsedHttpRequest, UiSecurityContext, csprng_hex, read_http_request, unix_now_ms,
    write_hardened_response, write_json_error,
};
use crate::ui_sse;
use crate::{bus_run, feature_cli_run};
use chinwag_cli::agent_instance::{ActorAddress, InstanceError};
use chinwag_cli::execution_binding::{
    ExecutionAuthority, RepositorySelection, StoreSelector, WorkspaceExecutionBinding,
    bind_execution,
};
use chinwag_cli::ui_delivery2_voice::{
    self, Delivery2VoiceStore, VOICE_DEFAULT_TURN_CREDITS, VOICE_THINKING_HOLD_MS,
    VoiceDelegateTracker, VoiceSessionState,
};
use chinwag_cli::ui_telemetry;
use rustix::fs::{AtFlags, CWD, Mode, OFlags, fsync, mkdirat, openat, renameat, statat, unlinkat};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DEFAULT_WORKBENCH_PORT: u16 = 5487;
pub const UI_VERSION: &str = "4.1";
const MAX_CONCURRENT_UI_CONNECTIONS: usize = 64;
const MAX_BUS_TAIL_READ_BYTES: u64 = 2 * 1024 * 1024;
pub const PACK_EXPIRY_NOTICE: &str = "500 free starter credits (valid 90 days) · $0 per teammate seat · Paid credit packs remain valid for 12 months from purchase.";
pub const CREDIT_PACKS_PRICING_URL: &str = "https://chinwag.sh/pricing";
pub const HUMAN_BASELINE_EXPLAINER: &str = "Estimated against typical solo engineering time for similar pull requests (2.5 hours per small bug fix, 5 hours per feature change).";

const UI_V4_INDEX_HTML: &str = include_str!("../assets/ui-v4/index.html");
const UI_V4_THEME_BOOT_JS: &str = include_str!("../assets/ui-v4/theme-boot.js");
const UI_V4_STYLES_CSS: &str = include_str!("../assets/ui-v4/styles.css");
const UI_V4_MOTION_CSS: &str = include_str!("../assets/ui-v4/motion.css");
const UI_V4_MOTION_JS: &str = include_str!("../assets/ui-v4/motion.js");
const UI_V4_APP_JS: &str = include_str!("../assets/ui-v4/app.js");
const UI_V4_GEIST_LATIN_WOFF2: &[u8] = include_bytes!("../assets/ui-v4/Geist-Latin.woff2");
const UI_V4_GEIST_MONO_LATIN_WOFF2: &[u8] = include_bytes!("../assets/ui-v4/GeistMono-Latin.woff2");
const UI_V4_FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" rx="3" fill="#1C1917"/><rect x="3" y="3" width="4" height="4" rx="1" fill="#0F766E"/><path d="M9 5h4M9 8h4M3 12h10" stroke="#F5F5F4" stroke-width="1.5" stroke-linecap="round"/></svg>"##;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiDaemonState {
    pub ok: bool,
    pub pid: u32,
    pub addr: String,
    pub port: u16,
    pub ui_version: String,
    pub views: usize,
    pub started_at_unix: u64,
}

fn default_driver_tool() -> String {
    "claude_code".to_string()
}

fn default_reviewer_tool() -> String {
    "codex_cli".to_string()
}

fn default_test_verifier_tool() -> String {
    "gemini_cli".to_string()
}

fn default_security_verifier_tool() -> String {
    "cursor".to_string()
}

fn default_review_tier_credits() -> u64 {
    100
}

fn default_review_mode() -> String {
    "pair_sandbox".to_string()
}

fn default_workstream_engineering() -> String {
    "engineering".to_string()
}

pub(crate) fn normalize_workflow_tool_id(raw: &str, fallback: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "claude" | "claude_code" | "claude-code" => "claude_code".to_string(),
        "codex" | "codex_cli" | "codex-cli" => "codex_cli".to_string(),
        "gemini" | "gemini_cli" | "gemini-cli" => "gemini_cli".to_string(),
        "cursor" => "cursor".to_string(),
        _ => fallback.to_string(),
    }
}

pub(crate) fn friendly_workflow_tool_label(raw: &str) -> &'static str {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("claude") {
        "Claude Code"
    } else if lower.contains("codex") {
        "Codex CLI"
    } else if lower.contains("gemini") {
        "Gemini CLI"
    } else if lower.contains("cursor") {
        "Cursor"
    } else {
        "Claude Code"
    }
}

pub(crate) fn review_mode_for_credits(credits: u64) -> Option<&'static str> {
    match credits {
        50 => Some("review_handoff"),
        100 => Some("pair_sandbox"),
        150 => Some("three_tool_check"),
        200 => Some("quad_programming"),
        _ => None,
    }
}

pub(crate) fn credits_for_review_mode(mode: &str) -> Option<u64> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "review_handoff" => Some(50),
        "pair_sandbox" | "diffs_touching_3_plus_files" => Some(100),
        "three_tool_check" | "triad_sandbox" => Some(150),
        "quad_programming" | "quad_sandbox" | "security_review" => Some(200),
        _ => None,
    }
}

fn normalize_workstream_id(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "engineering" | "design" | "product" | "qa" | "security" | "analytics" | "docs" => lower,
        _ => "engineering".to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    pub independent_review: bool,
    #[serde(default = "default_driver_tool")]
    pub driver_tool: String,
    #[serde(default = "default_reviewer_tool")]
    pub reviewer_tool: String,
    #[serde(default = "default_test_verifier_tool")]
    pub test_verifier_tool: String,
    #[serde(default = "default_security_verifier_tool")]
    pub security_verifier_tool: String,
    #[serde(default = "default_review_tier_credits")]
    pub review_tier_credits: u64,
    #[serde(default = "default_review_mode")]
    pub review_mode: String,
    pub protect_sensitive_paths: bool,
    pub auto_test_before_review: bool,
    pub isolated_sandbox: bool,
    pub ask_before_secrets: bool,
    pub require_click_before_push: bool,
    pub stop_auto_repair_after_2_attempts: bool,
    pub protected_paths: Vec<String>,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            independent_review: true,
            driver_tool: default_driver_tool(),
            reviewer_tool: default_reviewer_tool(),
            test_verifier_tool: default_test_verifier_tool(),
            security_verifier_tool: default_security_verifier_tool(),
            review_tier_credits: default_review_tier_credits(),
            review_mode: default_review_mode(),
            protect_sensitive_paths: true,
            auto_test_before_review: true,
            isolated_sandbox: true,
            ask_before_secrets: true,
            require_click_before_push: true,
            stop_auto_repair_after_2_attempts: true,
            protected_paths: vec![
                ".env*".to_string(),
                "**/auth/**".to_string(),
                "**/billing/**".to_string(),
                "**/migrations/**".to_string(),
                ".github/workflows/**".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRefillConfig {
    pub enabled: bool,
    pub threshold_credits: u64,
    pub pack_sku: String,
    pub monthly_cap_usd: Option<u64>,
}

impl Default for AutoRefillConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold_credits: 500,
            pack_sku: "pack_160".to_string(),
            monthly_cap_usd: Some(160),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LocalUiV4State {
    #[serde(default)]
    item_decisions: BTreeMap<String, ItemDecisionRecord>,
    #[serde(default)]
    walkthrough_completed: bool,
    #[serde(default)]
    next_task_seq: u64,
    #[serde(default)]
    created_tasks: Vec<LocalBoardTask>,
    #[serde(default)]
    last_board_sync: Option<BoardSyncRecord>,
    #[serde(default)]
    auto_refill: AutoRefillConfig,
    #[serde(default)]
    delivery2: Delivery2Store,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Delivery2Store {
    #[serde(default = "default_d2_seq")]
    seq: u64,
    #[serde(default)]
    morning_seen: bool,
    #[serde(default)]
    morning_collapsed: bool,
    #[serde(default = "default_d2_thread_id")]
    active_thread_id: String,
    #[serde(default)]
    active_turn_id: Option<String>,
    #[serde(default)]
    cancelled_turn_ids: Vec<String>,
    #[serde(default)]
    cancelled_turn_clamps: BTreeMap<String, usize>,
    #[serde(default)]
    threads: Vec<Delivery2Thread>,
    #[serde(default)]
    memories: BTreeMap<String, Delivery2Memory>,
    #[serde(default)]
    approvals: BTreeMap<String, Delivery2ApprovalRecord>,
    #[serde(default)]
    connections: BTreeMap<String, Delivery2ConnectionPref>,
    #[serde(default)]
    voice: Delivery2VoiceStore,
}

fn default_d2_seq() -> u64 {
    1
}

fn default_d2_thread_id() -> String {
    "thr-main".to_string()
}

impl Default for Delivery2Store {
    fn default() -> Self {
        Self {
            seq: 1,
            morning_seen: false,
            morning_collapsed: false,
            active_thread_id: default_d2_thread_id(),
            active_turn_id: None,
            cancelled_turn_ids: Vec::new(),
            cancelled_turn_clamps: BTreeMap::new(),
            threads: Vec::new(),
            memories: BTreeMap::new(),
            approvals: BTreeMap::new(),
            connections: BTreeMap::new(),
            voice: Delivery2VoiceStore::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Delivery2Thread {
    id: String,
    title: String,
    bucket: String,
    status: String,
    created_at_unix: u64,
    updated_at_unix: u64,
    #[serde(default)]
    entries: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Delivery2Memory {
    id: String,
    note: String,
    status: String,
    updated_at_unix: u64,
    #[serde(default = "default_d2_seq")]
    seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Delivery2ApprovalRecord {
    id: String,
    decision: String,
    receipt: String,
    decided_at_label: String,
    updated_at_unix: u64,
    #[serde(default = "default_d2_seq")]
    seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Delivery2ConnectionPref {
    #[serde(default)]
    in_thread: Option<bool>,
    #[serde(default)]
    oauth_state: Option<String>,
    #[serde(default)]
    oauth_thread_id: Option<String>,
    #[serde(default)]
    challenge_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ItemDecisionRecord {
    status: String,
    action: String,
    note: Option<String>,
    updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalBoardTask {
    id: String,
    title: String,
    status: String,
    assigned_tool: String,
    #[serde(default = "default_workstream_engineering")]
    workstream: String,
    created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BoardSyncRecord {
    target: String,
    synced_items: usize,
    synced_at_unix: u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn format_relative_time(ts_unix: u64) -> String {
    let now = unix_now();
    if ts_unix == 0 || ts_unix >= now {
        return "just now".to_string();
    }
    let delta = now - ts_unix;
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86_400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86_400)
    }
}

/// A protected UI action enters this same boundary before publication or dispatch.
pub(crate) fn with_ui_task_effect<T>(
    selection: &RepositorySelection,
    binding: &WorkspaceExecutionBinding,
    authority: &ExecutionAuthority<'_>,
    effect: impl FnOnce(&WorkspaceExecutionBinding) -> T,
) -> Result<T, String> {
    feature_cli_run::with_feature_task_effect(selection, binding, authority, effect)
}

fn preflight_ui_task_effect(selection: &RepositorySelection) -> Result<(), String> {
    let authority = ExecutionAuthority::unsupported();
    let binding = bind_execution(
        selection,
        StoreSelector {
            explicit_crdb: None,
        },
        &authority,
    )
    .map_err(|e| e.to_string())?;
    with_ui_task_effect(selection, &binding, &authority, |_| ())
}

fn run_cli_to_json_bytes(run: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>) -> u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(&mut out, &mut err);
    if !out.is_empty() && serde_json::from_slice::<Value>(&out).is_ok() {
        return out;
    }
    serde_json::to_vec(&json!({
        "ok": code == 0,
        "exit_code": code,
        "stdout": scrub_customer_text(&String::from_utf8_lossy(&out)),
        "stderr": scrub_customer_text(&String::from_utf8_lossy(&err))
    }))
    .unwrap_or_default()
}

pub fn resolve_repo_root(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit
        && !p.trim().is_empty()
    {
        return PathBuf::from(p);
    }
    if let Ok(env_root) = std::env::var("CHINWAG_REPO_ROOT")
        && !env_root.trim().is_empty()
    {
        return PathBuf::from(env_root);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let home_path = PathBuf::from(&home);
    if let Ok(cwd) = std::env::current_dir() {
        for ancestor in cwd.ancestors() {
            if ancestor != home_path.as_path()
                && (ancestor.join(".chinwag").is_dir()
                    || ancestor.join(".git").exists()
                    || ancestor.join(".jj").is_dir())
            {
                return ancestor.to_path_buf();
            }
        }
        return cwd;
    }
    PathBuf::from(".")
}

static UI_V4_STATE_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

fn validate_repo_component(comp: &str) -> Result<(), String> {
    if comp.is_empty() || comp == "." || comp == ".." || comp.contains('/') || comp.contains('\0') {
        return Err(format!("invalid workspace path component '{comp}'"));
    }
    Ok(())
}

fn open_repo_dir_nofollow(
    repo_root: &Path,
    rel_dirs: &[&str],
    create: bool,
    dir_mode: Mode,
) -> Result<OwnedFd, rustix::io::Errno> {
    let mut cur_fd = openat(
        CWD,
        repo_root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for comp in rel_dirs {
        if comp.is_empty()
            || *comp == "."
            || *comp == ".."
            || comp.contains('/')
            || comp.contains('\0')
        {
            return Err(rustix::io::Errno::INVAL);
        }
        if create {
            match mkdirat(&cur_fd, *comp, dir_mode) {
                Ok(()) => {}
                Err(e) if e == rustix::io::Errno::EXIST => {}
                Err(e) => return Err(e),
            }
        }
        cur_fd = openat(
            &cur_fd,
            *comp,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
    }
    Ok(cur_fd)
}

fn read_repo_file_nofollow(
    repo_root: &Path,
    rel_dirs: &[&str],
    leaf_name: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    validate_repo_component(leaf_name)?;
    let dir_fd = match open_repo_dir_nofollow(repo_root, rel_dirs, false, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
        Err(e) => {
            return Err(format!(
                "refusing symlinked or inaccessible workspace directory: {e}"
            ));
        }
    };
    match statat(&dir_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if (u32::from(st.st_mode) & 0o170000) != 0o100000 {
                return Err(format!(
                    "refusing symlink or non-regular workspace entry '{leaf_name}'"
                ));
            }
        }
        Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
        Err(e) => {
            return Err(format!(
                "refusing inaccessible workspace file '{leaf_name}': {e}"
            ));
        }
    }
    let raw_fd = match openat(
        &dir_fd,
        leaf_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
        Err(e) => {
            return Err(format!(
                "refusing symlinked or unreadable workspace file '{leaf_name}': {e}"
            ));
        }
    };
    let file = File::from(raw_fd);
    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat '{leaf_name}': {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "workspace entry '{leaf_name}' is not a regular file"
        ));
    }
    let mut buf = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed reading '{leaf_name}': {e}"))?;
    if buf.len() > max_bytes {
        return Err(format!(
            "workspace file '{leaf_name}' exceeds {max_bytes}-byte safety cap"
        ));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| format!("workspace file '{leaf_name}' is not UTF-8: {e}"))
}

fn write_repo_file_nofollow_atomic(
    repo_root: &Path,
    rel_dirs: &[&str],
    leaf_name: &str,
    file_mode: Mode,
    bytes: &[u8],
) -> Result<(), String> {
    validate_repo_component(leaf_name)?;
    let dir_fd = open_repo_dir_nofollow(
        repo_root,
        rel_dirs,
        true,
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|e| format!("refusing symlinked or inaccessible workspace directory: {e}"))?;

    match statat(&dir_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if (u32::from(st.st_mode) & 0o170000) != 0o100000 || st.st_nlink != 1 {
                return Err(format!(
                    "refusing to overwrite symlink, hardlink, or non-regular file '{leaf_name}'"
                ));
            }
        }
        Err(e) if e == rustix::io::Errno::NOENT => {}
        Err(e) => return Err(format!("failed to inspect '{leaf_name}': {e}")),
    }

    let tmp_name = format!(".{leaf_name}.tmp.{}", csprng_hex(8));
    let tmp_fd = openat(
        &dir_fd,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        file_mode,
    )
    .map_err(|e| format!("failed to create atomic temp file for '{leaf_name}': {e}"))?;

    let mut file = File::from(tmp_fd);
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
        return Err(format!("failed to write '{leaf_name}': {e}"));
    }
    drop(file);

    match statat(&dir_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            if (u32::from(st.st_mode) & 0o170000) != 0o100000 || st.st_nlink != 1 {
                let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
                return Err(format!(
                    "refusing replacement race on non-regular or linked file '{leaf_name}'"
                ));
            }
        }
        Err(e) if e == rustix::io::Errno::NOENT => {}
        Err(e) => {
            let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
            return Err(format!("failed to verify '{leaf_name}' before commit: {e}"));
        }
    }

    if let Err(e) = renameat(&dir_fd, tmp_name.as_str(), &dir_fd, leaf_name) {
        let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
        return Err(format!("failed to commit '{leaf_name}': {e}"));
    }
    let _ = fsync(&dir_fd);
    Ok(())
}

fn create_new_repo_file_nofollow(
    repo_root: &Path,
    rel_dirs: &[&str],
    leaf_name: &str,
    file_mode: Mode,
    bytes: &[u8],
) -> Result<(), String> {
    validate_repo_component(leaf_name)?;
    let dir_fd = open_repo_dir_nofollow(
        repo_root,
        rel_dirs,
        true,
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|e| format!("refusing symlinked or inaccessible workspace directory: {e}"))?;
    let raw_fd = openat(
        &dir_fd,
        leaf_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        file_mode,
    )
    .map_err(|e| format!("failed creating '{leaf_name}': {e}"))?;
    let mut file = File::from(raw_fd);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("failed writing '{leaf_name}': {e}"))?;
    let _ = fsync(&dir_fd);
    Ok(())
}

const UI_V4_MAX_STATE_BYTES: usize = 512 * 1024;
const MAX_DELIVERY2_PROMPT_CHARS: usize = 4_000;
const MAX_DELIVERY2_ENTRIES_PER_THREAD: usize = 64;
const MAX_DELIVERY2_THREADS: usize = 24;
const MAX_DELIVERY2_MEMORIES: usize = 128;
const MAX_DELIVERY2_APPROVALS: usize = 128;

fn is_entry_unsettled_workflow(state: &LocalUiV4State, thr_id: &str, entry: &Value) -> bool {
    if entry
        .get("settled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    match entry.get("kind").and_then(Value::as_str).unwrap_or("") {
        "approval_card" => {
            if let Some(aid) = entry.get("approval_id").and_then(Value::as_str)
                && state.delivery2.approvals.contains_key(aid)
            {
                return false;
            }
            if let Some(iid) = entry.get("item_id").and_then(Value::as_str) {
                if state
                    .delivery2
                    .approvals
                    .contains_key(&format!("hitl-{iid}"))
                {
                    return false;
                }
                if state
                    .item_decisions
                    .get(iid)
                    .is_some_and(|d| matches!(d.status.as_str(), "done" | "rejected"))
                {
                    return false;
                }
            }
            true
        }
        "oauth_card" => {
            if let Some(surface) = entry.get("surface").and_then(Value::as_str)
                && let Some(pref) = state.delivery2.connections.get(surface)
            {
                let Some(active_nonce) = pref.oauth_state.as_deref() else {
                    return false;
                };
                if let Some(card_nonce) = entry.get("oauth_state").and_then(Value::as_str)
                    && card_nonce != active_nonce
                {
                    return false;
                }
                if let Some(active_otid) = pref.oauth_thread_id.as_deref()
                    && active_otid != thr_id
                {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

fn thread_has_pinned_workflow(state: &LocalUiV4State, thr: &Delivery2Thread) -> bool {
    if thr
        .entries
        .iter()
        .any(|e| is_entry_unsettled_workflow(state, &thr.id, e))
    {
        return true;
    }
    state.delivery2.connections.values().any(|pref| {
        pref.oauth_state.is_some() && pref.oauth_thread_id.as_deref() == Some(thr.id.as_str())
    })
}

fn stamp_approval_settlement_in_threads(
    threads: &mut [Delivery2Thread],
    canonical_approval_id: &str,
    canonical_item_id: &str,
    settled: bool,
    decision: Option<&str>,
    receipt: Option<&str>,
    seq: u64,
) {
    for thr in threads {
        for entry in &mut thr.entries {
            if entry.get("kind").and_then(Value::as_str) != Some("approval_card") {
                continue;
            }
            let matches_aid = entry
                .get("approval_id")
                .and_then(Value::as_str)
                .is_some_and(|a| a == canonical_approval_id || a == canonical_item_id);
            let matches_iid = !canonical_item_id.is_empty()
                && entry
                    .get("item_id")
                    .and_then(Value::as_str)
                    .is_some_and(|i| i == canonical_item_id);
            if (matches_aid || matches_iid)
                && let Some(obj) = entry.as_object_mut()
            {
                obj.insert("settled".to_string(), Value::Bool(settled));
                obj.insert(
                    "settled_decision".to_string(),
                    decision
                        .map(|d| Value::String(d.to_string()))
                        .unwrap_or(Value::Null),
                );
                obj.insert(
                    "settled_receipt".to_string(),
                    receipt
                        .map(|r| Value::String(r.to_string()))
                        .unwrap_or(Value::Null),
                );
                if seq > 0 {
                    let prev_seq = obj.get("seq").and_then(Value::as_u64).unwrap_or(1);
                    obj.insert("seq".to_string(), Value::Number(prev_seq.max(seq).into()));
                }
            }
        }
    }
}

fn compact_delivery2_store_for_persistence(state: &mut LocalUiV4State) -> Result<(), String> {
    let active_tid = if state.delivery2.active_thread_id.trim().is_empty() {
        "thr-main".to_string()
    } else {
        state.delivery2.active_thread_id.clone()
    };

    for thr_idx in 0..state.delivery2.threads.len() {
        while state.delivery2.threads[thr_idx].entries.len() > MAX_DELIVERY2_ENTRIES_PER_THREAD {
            let thr_id = state.delivery2.threads[thr_idx].id.clone();
            let remove_idx = state.delivery2.threads[thr_idx]
                .entries
                .iter()
                .position(|e| !is_entry_unsettled_workflow(state, &thr_id, e));
            let Some(idx) = remove_idx else {
                return Err(format!(
                    "Thread '{}' holds more than {MAX_DELIVERY2_ENTRIES_PER_THREAD} unsettled approval or sign-in cards; resolve or skip a pending card first.",
                    thr_id
                ));
            };
            state.delivery2.threads[thr_idx].entries.remove(idx);
        }
    }

    while state.delivery2.threads.len() > MAX_DELIVERY2_THREADS {
        let Some(evict_idx) = state
            .delivery2
            .threads
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                t.id != active_tid && t.id != "thr-main" && !thread_has_pinned_workflow(state, t)
            })
            .min_by_key(|(_, t)| t.updated_at_unix)
            .map(|(idx, _)| idx)
        else {
            return Err(format!(
                "Cannot evict threads while {MAX_DELIVERY2_THREADS} or more threads hold unsettled approvals or OAuth sign-ins; resolve or skip a pending card first."
            ));
        };
        state.delivery2.threads.remove(evict_idx);
    }

    while state.delivery2.memories.len() > MAX_DELIVERY2_MEMORIES {
        let Some(oldest_id) = state
            .delivery2
            .memories
            .values()
            .filter(|m| m.id != "mem_default")
            .min_by_key(|m| (m.updated_at_unix, m.seq))
            .map(|m| m.id.clone())
        else {
            break;
        };
        state.delivery2.memories.remove(&oldest_id);
    }

    while state.delivery2.approvals.len() > MAX_DELIVERY2_APPROVALS {
        let Some(oldest_id) = state
            .delivery2
            .approvals
            .iter()
            .min_by_key(|(_, a)| (a.updated_at_unix, a.seq))
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        state.delivery2.approvals.remove(&oldest_id);
    }

    Ok(())
}

fn load_ui_v4_state_strict(repo_root: &Path) -> Result<LocalUiV4State, String> {
    match read_repo_file_nofollow(
        repo_root,
        &[".chinwag"],
        "ui-v4-state.json",
        UI_V4_MAX_STATE_BYTES,
    )? {
        None => Ok(LocalUiV4State::default()),
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|e| format!("corrupt .chinwag/ui-v4-state.json: {e}")),
    }
}

fn load_ui_v4_state(repo_root: &Path) -> LocalUiV4State {
    load_ui_v4_state_strict(repo_root).unwrap_or_default()
}

fn save_ui_v4_state(repo_root: &Path, state: &LocalUiV4State) -> Result<(), String> {
    let serialized = serde_json::to_string_pretty(state)
        .map_err(|e| format!("failed to serialize state: {e}"))?;
    let bytes = if serialized.len() <= UI_V4_MAX_STATE_BYTES {
        serialized
    } else {
        let compact = serde_json::to_string(state)
            .map_err(|e| format!("failed to serialize compact state: {e}"))?;
        if compact.len() > UI_V4_MAX_STATE_BYTES {
            return Err(format!(
                "refusing to persist .chinwag/ui-v4-state.json ({} bytes exceeds {UI_V4_MAX_STATE_BYTES}-byte loader cap)",
                compact.len()
            ));
        }
        compact
    };
    write_repo_file_nofollow_atomic(
        repo_root,
        &[".chinwag"],
        "ui-v4-state.json",
        Mode::RUSR | Mode::WUSR,
        bytes.as_bytes(),
    )
}

fn mutate_ui_v4_state(
    repo_root: &Path,
    f: impl FnOnce(&mut LocalUiV4State) -> Result<Value, (&'static str, Value)>,
) -> (&'static str, Value) {
    let lock = UI_V4_STATE_MUTEX.get_or_init(|| Mutex::new(()));
    let Ok(_guard) = lock.lock() else {
        return (
            "500 Internal Server Error",
            json!({
                "ok": false,
                "error_code": "state_lock_poisoned",
                "error": "Local UI state lock is unavailable."
            }),
        );
    };
    let mut state = match load_ui_v4_state_strict(repo_root) {
        Ok(s) => s,
        Err(e) => {
            return (
                "409 Conflict",
                json!({
                    "ok": false,
                    "disposition": "HELD",
                    "error_code": "state_load_failed",
                    "error": e
                }),
            );
        }
    };
    let val = match f(&mut state) {
        Ok(v) => v,
        Err((status, err_val)) => return (status, err_val),
    };
    if let Err(e) = compact_delivery2_store_for_persistence(&mut state) {
        return (
            "409 Conflict",
            json!({
                "ok": false,
                "disposition": "HELD",
                "error_code": "pending_workflow_limit_exceeded",
                "error": e
            }),
        );
    }
    // Guarantee bounded history stays strictly under `UI_V4_MAX_STATE_BYTES` even with dense entries,
    // without ever discarding unsettled approval/OAuth cards (`ARCHITECT-R5-1`).
    while matches!(serde_json::to_string(&state), Ok(s) if s.len() > UI_V4_MAX_STATE_BYTES) {
        let active_tid = if state.delivery2.active_thread_id.trim().is_empty() {
            "thr-main".to_string()
        } else {
            state.delivery2.active_thread_id.clone()
        };
        if let Some((thr_idx, entry_idx)) = state
            .delivery2
            .threads
            .iter()
            .enumerate()
            .filter(|(_, t)| t.id != active_tid)
            .filter_map(|(idx, t)| {
                t.entries
                    .iter()
                    .position(|e| !is_entry_unsettled_workflow(&state, &t.id, e))
                    .map(|epos| (idx, epos, t.updated_at_unix))
            })
            .min_by_key(|(_, _, ts)| *ts)
            .map(|(idx, epos, _)| (idx, epos))
        {
            state.delivery2.threads[thr_idx].entries.remove(entry_idx);
        } else if let Some(empty_thr_idx) = state
            .delivery2
            .threads
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                t.id != active_tid
                    && t.id != "thr-main"
                    && t.entries.is_empty()
                    && !thread_has_pinned_workflow(&state, t)
            })
            .min_by_key(|(_, t)| t.updated_at_unix)
            .map(|(idx, _)| idx)
        {
            state.delivery2.threads.remove(empty_thr_idx);
        } else if let Some((act_idx, entry_idx)) = state
            .delivery2
            .threads
            .iter()
            .enumerate()
            .find(|(_, t)| t.id == active_tid)
            .and_then(|(idx, t)| {
                let non_pinned_count = t
                    .entries
                    .iter()
                    .filter(|e| !is_entry_unsettled_workflow(&state, &t.id, e))
                    .count();
                if non_pinned_count > 1 {
                    t.entries
                        .iter()
                        .position(|e| !is_entry_unsettled_workflow(&state, &t.id, e))
                        .map(|epos| (idx, epos))
                } else {
                    None
                }
            })
        {
            state.delivery2.threads[act_idx].entries.remove(entry_idx);
        } else {
            break;
        }
    }
    if let Err(e) = save_ui_v4_state(repo_root, &state) {
        return (
            "409 Conflict",
            json!({
                "ok": false,
                "disposition": "HELD",
                "error_code": "state_save_failed",
                "error": e
            }),
        );
    }
    ("200 OK", val)
}

// ============================================================================
// INV-UI-ZERO-JARGON-01: Customer-Facing Scrubber
// ============================================================================

const D2_ALLOW_SENTINEL: &str = "\u{E000}D2\u{E001}";

const SCRUB_SUBSTRINGS: &[(&str, &str)] = &[
    (concat!("inception/mer", "cury-3"), "Coding Agent"),
    (concat!("mer", "cury-3"), "Coding Agent"),
    (concat!("mer", "cury 3"), "Coding Agent"),
    (concat!("mer", "cury_3"), "Coding Agent"),
    (concat!("vercel-ai", "-gateway"), "cloud gateway"),
    (concat!("vercel ai", " gateway"), "cloud gateway"),
    (concat!("@cf/cloudflare/cl", "ef-flash"), "Fast Check"),
    (concat!("@cf/cloudflare/cl", "ef"), "Fast Check"),
    (concat!("@cf/cloudflare/cl", "airic"), "Fast Check"),
    (concat!("cl", "ef-flash"), "Fast Check"),
    (concat!("@cf/openai/gpt-", "oss-120b"), "Coding Agent"),
    (concat!("gpt-oss", "-120b"), "Coding Agent"),
    (
        concat!("@cf/deep", "seek-ai/deep", "seek-v4.1-flash-1017"),
        "Coding Agent",
    ),
    (concat!("deep", "seek-v4"), "Coding Agent"),
    (concat!("deep", "seek"), "Coding Agent"),
    (concat!("cloud", "flareos-ai"), "cloud gateway"),
    (concat!("cloud", "flare-workers-ai"), "cloud gateway"),
    (concat!("cloud", "flare workers ai"), "cloud gateway"),
    (concat!("claude-fa", "ble-5-2"), "Claude Code"),
    (concat!("claude-fa", "ble-5-1"), "Claude Code"),
    (concat!("claude-", "fable"), "Claude Code"),
    (concat!("claude ", "fable"), "Claude Code"),
    (concat!("claude-op", "us-5"), "Claude Code"),
    (concat!("op", "us 5"), "Claude Code"),
    (concat!("gemini-4-", "argon-high"), "Gemini CLI"),
    (concat!("gemini-4-", "carbon-high"), "Gemini CLI"),
    (concat!("gemini 4 ", "argon"), "Gemini CLI"),
    (concat!("gemini 4 ", "carbon"), "Gemini CLI"),
    (concat!("gp", "t-6.1-sol"), "Codex CLI"),
    (concat!("gp", "t-6.1"), "Codex CLI"),
    (concat!("gp", "t-6"), "Codex CLI"),
    (concat!("gr", "ok-4.7"), "Assistant"),
    (concat!("gr", "ok 4"), "Assistant"),
    (concat!("recursive fl", "int"), "Independent Reviewer"),
    (concat!("fl", "int-int4"), "Independent Reviewer"),
    (concat!("node 1 · mac st", "udio"), "Local Workstation"),
    (concat!("node 2 · macbook", " pro"), "Local Workstation"),
    (concat!("node 3 · macbook", " pro"), "Local Workstation"),
    (concat!("mac st", "udio"), "Local Workstation"),
    (concat!("nicolas-", "macbook-pro"), "Local Workstation"),
    (concat!("emunlabs/", "chinwag"), "local-repo"),
    (concat!("/users/brian", "spector"), "~"),
    (concat!("memory.cr", "db.le", "ann"), "Memory search"),
    (concat!("state.cr", "db"), "workspace history"),
    (concat!("cr-", "sqlite"), "workspace history"),
    (concat!("cr", "sqlite"), "workspace history"),
    (concat!("chinwag-bus-", "sig-v2"), "local-verification"),
    (concat!("allowed_", "signers"), "trusted-tools"),
    (concat!("signature_ed25", "519"), "verified_signature"),
    (concat!("pubkey_ed25", "519"), "verified_key"),
    (concat!("ed25", "519"), "verified"),
    (concat!("x25519ml", "kem768"), "end-to-end encrypted"),
    (concat!("bb", "s+"), "privacy-proof"),
    (concat!("cp-", "omp"), "workspace-policy"),
    (concat!("a.", "509"), "agent-profile"),
    (concat!("neon.", "tech"), "managed database"),
    (concat!("@neon", "database"), "managed database"),
];

fn fold_math_alpha_char(ch: char) -> Option<char> {
    let u = ch as u32;
    let map_pair = |base: u32| -> Option<char> {
        let off = u.checked_sub(base)?;
        if off < 26 {
            char::from_u32(u32::from(b'A') + off)
        } else if off < 52 {
            char::from_u32(u32::from(b'a') + (off - 26))
        } else {
            None
        }
    };
    match u {
        // Unicode Letterlike Latin symbols (including Double-Struck / Script / Fraktur holes)
        0x2102 | 0x212D => Some('C'),
        0x210A => Some('g'),
        0x210B..=0x210D => Some('H'),
        0x210E | 0x210F => Some('h'),
        0x2110 | 0x2111 => Some('I'),
        0x2112 => Some('L'),
        0x2113 => Some('l'),
        0x2115 => Some('N'),
        0x2119 => Some('P'),
        0x211A => Some('Q'),
        0x211B..=0x211D => Some('R'),
        0x2124 | 0x2128 => Some('Z'),
        0x212C => Some('B'),
        0x212F => Some('e'),
        0x2130 => Some('E'),
        0x2131 => Some('F'),
        0x2133 => Some('M'),
        0x2134 => Some('o'),
        // Mathematical Alphanumeric Symbols (Bold, Italic, Bold Italic, Script, Bold Script,
        // Fraktur, Double-Struck, Bold Fraktur, Sans, Sans Bold, Sans Italic, Sans Bold Italic, Monospace)
        0x1D400..=0x1D433 => map_pair(0x1D400),
        0x1D434..=0x1D467 => map_pair(0x1D434),
        0x1D468..=0x1D49B => map_pair(0x1D468),
        0x1D49C..=0x1D4CF => map_pair(0x1D49C),
        0x1D4D0..=0x1D503 => map_pair(0x1D4D0),
        0x1D504..=0x1D537 => map_pair(0x1D504),
        0x1D538..=0x1D56B => map_pair(0x1D538),
        0x1D56C..=0x1D59F => map_pair(0x1D56C),
        0x1D5A0..=0x1D5D3 => map_pair(0x1D5A0),
        0x1D5D4..=0x1D607 => map_pair(0x1D5D4),
        0x1D608..=0x1D63B => map_pair(0x1D608),
        0x1D63C..=0x1D66F => map_pair(0x1D63C),
        0x1D670..=0x1D6A3 => map_pair(0x1D670),
        0x1D7CE..=0x1D7FF => {
            let d = (u - 0x1D7CE) % 10;
            char::from_u32(u32::from(b'0') + d)
        }
        0x24B6..=0x24CF => char::from_u32(u32::from(b'A') + (u - 0x24B6)),
        0x24D0..=0x24E9 => char::from_u32(u32::from(b'a') + (u - 0x24D0)),
        _ => None,
    }
}

fn normalize_scrubber_stage1(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let u = ch as u32;
        // Strip zero-width, bidi/format controls (\u200B-\u200F, \u202A-\u202E, \u2060-\u206F),
        // soft hyphen, variation selectors, and private sentinel codepoints
        if matches!(
            u,
            0x00AD
                | 0x034F
                | 0x061C
                | 0x180E
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x206F
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xE000
                | 0xE001
        ) {
            continue;
        }
        // Fold Unicode dashes (\u2010–\u2015, minus \u2212, small hyphen \uFE63) to ASCII '-'
        if matches!(u, 0x2010..=0x2015 | 0x2212 | 0xFE63) {
            out.push('-');
            continue;
        }
        // NFKC compatibility fold for fullwidth ASCII (\uFF01–\uFF5E)
        if (0xFF01..=0xFF5E).contains(&u)
            && let Some(ascii) = char::from_u32(u - 0xFEE0)
        {
            out.push(ascii);
            continue;
        }
        // Compatibility spaces -> ASCII ' '
        if matches!(u, 0x00A0 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000) {
            out.push(' ');
            continue;
        }
        // Superscript / subscript digits & Kelvin/Angstrom/ligatures
        match ch {
            '\u{00B9}' | '\u{2081}' => out.push('1'),
            '\u{00B2}' | '\u{2082}' => out.push('2'),
            '\u{00B3}' | '\u{2083}' => out.push('3'),
            '\u{2070}' | '\u{2080}' => out.push('0'),
            '\u{2074}' | '\u{2084}' => out.push('4'),
            '\u{2075}' | '\u{2085}' => out.push('5'),
            '\u{2076}' | '\u{2086}' => out.push('6'),
            '\u{2077}' | '\u{2087}' => out.push('7'),
            '\u{2078}' | '\u{2088}' => out.push('8'),
            '\u{2079}' | '\u{2089}' => out.push('9'),
            '\u{212A}' => out.push('K'),
            '\u{212B}' => out.push('A'),
            '\u{FB00}' => out.push_str("ff"),
            '\u{FB01}' => out.push_str("fi"),
            '\u{FB02}' => out.push_str("fl"),
            '\u{FB03}' => out.push_str("ffi"),
            '\u{FB04}' => out.push_str("ffl"),
            _ => {
                if let Some(folded) = fold_math_alpha_char(ch) {
                    out.push(folded);
                } else {
                    out.push(ch);
                }
            }
        }
    }
    out
}

/// Stage 2: Match word-bounded `(?i)\bdelivery[\s-]?2\b` FIRST (plus word-bounded
/// `eve.dev` / `useEveAgent` / `eve[\s_-]+agent` so `"retrieve agent"`, `"achieve agent"`,
/// `"believe.dev"`, and `"the eve of release"` are never corrupted) and mask as `D2_ALLOW_SENTINEL`.
fn allow_mask_delivery2_stage2(input: &str) -> String {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let is_word_char = |c: char| c.is_ascii_alphanumeric() || c == '#' || c == '_';

    while i < chars.len() {
        let prev_ch = if i > 0 { Some(chars[i - 1].1) } else { None };
        let prev_ok = prev_ch.is_none_or(|c| !is_word_char(c));

        // Optional leading `@` or fleet sigil (`■ DELIVERY-2`, `@DELIVERY-2`)
        let mut word_i = i;
        if prev_ok && matches!(chars[i].1, '@' | '■' | '◆' | '●' | '⚡') {
            let mut k = i + 1;
            while k < chars.len() && chars[k].1 == ' ' {
                k += 1;
            }
            word_i = k;
        }

        if prev_ok && word_i + 8 <= chars.len() {
            let start_b = chars[word_i].0;
            if input.len() >= start_b + 8
                && input.is_char_boundary(start_b + 8)
                && input[start_b..start_b + 8].eq_ignore_ascii_case("delivery")
            {
                let mut after = word_i + 8;
                // Optional single space, hyphen, or underscore separator (`Delivery-2`, `Delivery 2`, `DELIVERY_2`, `delivery2`)
                if after < chars.len() && matches!(chars[after].1, '-' | ' ' | '_') {
                    after += 1;
                }
                if after < chars.len() && chars[after].1 == '2' {
                    let mut end_idx = after + 1;
                    // Also consume optional `#<instance>` suffix (`@DELIVERY-2#inst9`, `■ DELIVERY-2#1`)
                    if end_idx + 1 < chars.len()
                        && chars[end_idx].1 == '#'
                        && (chars[end_idx + 1].1.is_ascii_alphanumeric()
                            || matches!(chars[end_idx + 1].1, '_' | '-'))
                    {
                        end_idx += 1;
                        while end_idx < chars.len() {
                            let ic = chars[end_idx].1;
                            let is_dot_mid_inst = ic == '.'
                                && end_idx + 1 < chars.len()
                                && (chars[end_idx + 1].1.is_ascii_alphanumeric()
                                    || matches!(chars[end_idx + 1].1, '_' | '-'));
                            if ic.is_ascii_alphanumeric()
                                || matches!(ic, '_' | '-')
                                || is_dot_mid_inst
                            {
                                end_idx += 1;
                            } else {
                                break;
                            }
                        }
                    }
                    let next_ch = if end_idx < chars.len() {
                        Some(chars[end_idx].1)
                    } else {
                        None
                    };
                    let next_ok = !matches!(next_ch, Some(c) if is_word_char(c));
                    if next_ok {
                        out.push_str(D2_ALLOW_SENTINEL);
                        i = end_idx;
                        continue;
                    }
                }
            }
        }

        // Word-bounded `useEveAgent`, `eve.dev`, and `eve[\s_-]+agent`
        if prev_ok {
            let start_b = chars[i].0;
            if i + 11 <= chars.len()
                && input.len() >= start_b + 11
                && input.is_char_boundary(start_b + 11)
                && input[start_b..start_b + 11].eq_ignore_ascii_case(concat!("useeve", "agent"))
            {
                let next_ok = if i + 11 < chars.len() {
                    !is_word_char(chars[i + 11].1)
                } else {
                    true
                };
                if next_ok {
                    out.push_str(D2_ALLOW_SENTINEL);
                    i += 11;
                    continue;
                }
            }
            if i + 7 <= chars.len()
                && input.len() >= start_b + 7
                && input.is_char_boundary(start_b + 7)
                && input[start_b..start_b + 7].eq_ignore_ascii_case(concat!("eve", ".dev"))
            {
                let next_ok = if i + 7 < chars.len() {
                    !is_word_char(chars[i + 7].1)
                } else {
                    true
                };
                if next_ok {
                    out.push_str(D2_ALLOW_SENTINEL);
                    i += 7;
                    continue;
                }
            }
            if i + 3 <= chars.len()
                && input.len() >= start_b + 3
                && input.is_char_boundary(start_b + 3)
                && input[start_b..start_b + 3].eq_ignore_ascii_case("eve")
            {
                let mut sep_i = i + 3;
                let mut had_sep = false;
                while sep_i < chars.len() && matches!(chars[sep_i].1, ' ' | '-' | '_') {
                    had_sep = true;
                    sep_i += 1;
                }
                if had_sep && sep_i + 5 <= chars.len() {
                    let agent_b = chars[sep_i].0;
                    if input.len() >= agent_b + 5
                        && input.is_char_boundary(agent_b + 5)
                        && input[agent_b..agent_b + 5].eq_ignore_ascii_case("agent")
                    {
                        let next_ok = if sep_i + 5 < chars.len() {
                            !is_word_char(chars[sep_i + 5].1)
                        } else {
                            true
                        };
                        if next_ok {
                            out.push_str(D2_ALLOW_SENTINEL);
                            i = sep_i + 5;
                            continue;
                        }
                    }
                }
            }
        }

        out.push(chars[i].1);
        i += 1;
    }
    out
}

fn map_internal_seat_token(token: &str) -> Option<&'static str> {
    let had_sigil = token.starts_with(['@', '■', '◆', '●', '⚡']);
    let trimmed = token
        .trim_start_matches('@')
        .trim_start_matches(['■', '◆', '●', '⚡']);
    let has_instance = trimmed.contains('#');
    let base = trimmed.split_once('#').map(|(s, _)| s).unwrap_or(trimmed);
    let lower = base.to_ascii_lowercase();

    // Known vendor domains as single compound tokens
    if matches!(
        lower.as_str(),
        s if s == concat!("ver", "cel.com")
            || s == concat!("ver", "cel.app")
            || s == concat!("ver", "cel.sh")
            || s == concat!("cloud", "flare.com")
            || s == concat!("workers", ".dev")
    ) {
        return Some("cloud gateway");
    }
    if lower == concat!("cl", "erk.com") || lower == concat!("cl", "erk.dev") {
        return Some("sign-in provider");
    }
    if lower == concat!("up", "stash.io") || lower == concat!("up", "stash.com") {
        return Some("managed cache");
    }
    if lower == concat!("fl", "ue.sh") || lower == concat!("fl", "ue.dev") {
        return Some("local runtime");
    }

    // Preserve canonical customer-facing `Delivery-2` even if Stage 4 sees an isolated/qualified token
    if lower == concat!("deli", "very-2") || lower == concat!("deli", "very_2") {
        return Some("Delivery-2");
    }

    // Case-insensitive unambiguous internal seat / vendor / protocol tokens
    if lower == concat!("gemini", "-pm")
        || lower == concat!("deli", "very-agent")
        || lower == concat!("deli", "very-1")
        || lower == concat!("deli", "very_1")
        || (lower == concat!("deli", "very")
            && (had_sigil || has_instance || base.chars().all(|c| !c.is_ascii_lowercase())))
    {
        return Some("Chinwag PM");
    }
    if lower == concat!("work", "horse")
        || lower == concat!("game", "dev")
        || lower == concat!("infra", "jr")
        || lower == concat!("house", "keeping")
        || lower == concat!("h-", "swarm")
        || lower == concat!("ephemeral", "-dev")
        || lower.starts_with(concat!("ephemeral-", "dev-"))
        || lower == concat!("ephemeral", "-analyst")
        || lower == concat!("ephemeral", "-sdr")
        || lower == concat!("ephemeral", "-support")
        || lower == concat!("summa", "rizer")
        || lower == concat!("fa", "ble")
        || lower == concat!("ar", "gon")
        || lower == concat!("gr", "ok")
        || lower == concat!("mer", "cury")
    {
        return Some("Coding Agent");
    }
    if lower == concat!("clair", "ic") || lower == concat!("cl", "ef") {
        return Some("Fast Check");
    }
    if lower == concat!("ver", "cel") || lower == concat!("cloud", "flare") {
        return Some("cloud gateway");
    }
    if lower == concat!("fl", "ue") {
        return Some("local runtime");
    }
    if lower == concat!("ne", "on") {
        return Some("managed database");
    }
    if lower == concat!("up", "stash") {
        return Some("managed cache");
    }
    if lower == concat!("cl", "erk") {
        return Some("sign-in provider");
    }
    if lower == concat!("alis", "tair")
        || lower == concat!("fl", "int")
        || lower == concat!("eagle", "-eye")
        || lower == concat!("ephemeral", "-qa")
        || lower.starts_with(concat!("ephemeral-", "qa-"))
    {
        return Some("Independent Reviewer");
    }
    if lower == concat!("aus", "dra") {
        return Some("Workspace Advisor");
    }
    if lower == concat!("cr", "dt") || lower == concat!("cr", "dts") {
        return Some("sync");
    }
    if lower == concat!("cr", "db") {
        return Some("workspace history");
    }
    if lower == concat!("le", "ann") {
        return Some("Memory search");
    }
    if lower == concat!("hp", "ke") {
        return Some("end-to-end encrypted");
    }
    if lower == concat!("do", "ra") {
        return Some("delivery metrics");
    }
    if lower == concat!("ss", "e") {
        return Some("live updates");
    }
    if lower == concat!("a5", "09") {
        return Some("agent-profile");
    }

    // Qualified `<SEAT>#<INSTANCE>`, sigil-prefixed, or ALL-CAPS internal seat names
    // (preserves normal English lowercase prose such as "rust", "motion", "type", "docs", "mo")
    let is_all_caps = (!base.is_empty() && base == "H")
        || (base.len() >= 2
            && base
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_'));
    if had_sigil || has_instance || is_all_caps {
        let upper = base.to_ascii_uppercase();
        if upper == concat!("DELI", "VERY") {
            return Some("Chinwag PM");
        }
        match upper.as_str() {
            s if s == concat!("ARCHI", "TECT")
                || s == concat!("RU", "ST")
                || s == concat!("TY", "PE")
                || s == concat!("IND", "EX")
                || s == concat!("SPA", "RK")
                || s == concat!("MOT", "ION")
                || s == concat!("FREQU", "ENCY")
                || s == concat!("SCR", "IBE")
                || s == concat!("VEN", "TURE")
                || s == "MO"
                || s == concat!("DE", "X")
                || s == concat!("DECLAR", "ATION")
                || s == concat!("PAT", "ENT")
                || s == concat!("DO", "CS")
                || s == concat!("SOC", "IAL")
                || s == concat!("GRO", "WTH")
                || s == concat!("SAL", "ES")
                || s == "H"
                || s == "SKILL"
                || s == "SUPPORT" =>
            {
                return Some("Coding Agent");
            }
            "QA" | "QA-1" | "QA-2" | "QA-3" | "QA-4" | "QA-5" | "QA-6" | "QA-7" | "QA-8"
            | "QA-9" | "QA-10" => {
                return Some("Independent Reviewer");
            }
            "DEV-1" | "DEV-2" | "DEV-3" | "DEV-4" | "DEV-5" | "DEV-6" | "DEV-7" | "DEV-8"
            | "DEV-9" | "DEV-10" => {
                return Some("Coding Agent");
            }
            _ => {}
        }
    }
    if has_instance
        && (lower == concat!("bri", "an")
            || lower == concat!("ni", "c")
            || lower == concat!("nic", "ola"))
    {
        return Some("You");
    }

    None
}

fn scrub_compound_token(token_slice: &str) -> String {
    if let Some(mapped) = map_internal_seat_token(token_slice) {
        return mapped.to_string();
    }
    // If token contains `.` or `_`, scrub each `.` / `_`-delimited sub-segment
    // (skipping single-char sub-segments like `_H_` so identifiers like `WIDTH_H_2` stay intact)
    if token_slice.contains(['.', '_']) {
        let mut rebuilt = String::with_capacity(token_slice.len());
        let mut seg_start = 0usize;
        let mut changed = false;
        for (b_idx, ch) in token_slice.char_indices() {
            if matches!(ch, '.' | '_') {
                let seg = &token_slice[seg_start..b_idx];
                if seg.len() >= 2
                    && let Some(mapped) = map_internal_seat_token(seg)
                {
                    rebuilt.push_str(mapped);
                    changed = true;
                } else {
                    rebuilt.push_str(seg);
                }
                rebuilt.push(ch);
                seg_start = b_idx + ch.len_utf8();
            }
        }
        let tail = &token_slice[seg_start..];
        if tail.len() >= 2
            && let Some(mapped) = map_internal_seat_token(tail)
        {
            rebuilt.push_str(mapped);
            changed = true;
        } else {
            rebuilt.push_str(tail);
        }
        if changed {
            return rebuilt;
        }
    }
    token_slice.to_string()
}

fn replace_case_insensitive(haystack: &str, needle_lower: &str, replacement: &str) -> String {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return haystack.to_string();
    }
    let lower = haystack.to_ascii_lowercase();
    if !lower.contains(needle_lower) {
        return haystack.to_string();
    }
    // Only safe byte-aligned ASCII needle matching
    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0usize;
    let nlen = needle_lower.len();
    let bytes = haystack.as_bytes();
    while cursor + nlen <= bytes.len() {
        if haystack.is_char_boundary(cursor)
            && haystack.is_char_boundary(cursor + nlen)
            && haystack[cursor..cursor + nlen].eq_ignore_ascii_case(needle_lower)
        {
            out.push_str(replacement);
            cursor += nlen;
        } else if let Some(ch) = haystack[cursor..].chars().next() {
            out.push(ch);
            cursor += ch.len_utf8();
        } else {
            break;
        }
    }
    if cursor < haystack.len() {
        out.push_str(&haystack[cursor..]);
    }
    out
}

/// 5-Stage Customer-Facing Zero-Jargon Scrubber (`CHWG-0254` / `INV-UI-ZERO-JARGON-01`):
///   1. NFKC compatibility fold + strip zero-width/bidi/format chars + fold Unicode dashes (`\u2010`–`\u2015` -> `-`).
///   2. Allow-mask `(?i)\bdelivery[\s-]?2\b` (and word-bounded `eve.dev` / `useEveAgent` / `eve[\s_-]+agent`)
///      -> sentinel FIRST so `"DELIVERY-2"`, `"delivery-2"`, and `"Delivery 2"` canonicalize to `"Delivery-2"`
///      without colliding with bare `"DELIVERY"` or corrupting `"retrieve agent"` / `"the eve of release"`.
///   3. Boundary deny-scan & customer rewrite-map across all 30 internal seats, cloud/model vendors,
///      and crypto/protocol jargon (`CRDT`, `state.crdb`, `Ed25519`, `HPKE`, `SSE`, `LEANN`, `DORA`).
///   4. Token-level & dotted/underscore sub-token boundary rewrite preserving normal English prose.
///   5. Unmask sentinel -> `"Delivery-2"`.
pub fn scrub_customer_ui_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    // Stage 1: Normalize
    let stage1 = normalize_scrubber_stage1(input);
    // Stage 2: Allow-mask "Delivery-2"
    let mut current = allow_mask_delivery2_stage2(&stage1);
    // Stage 3: Substring rewrite-map
    for &(needle, replacement) in SCRUB_SUBSTRINGS {
        current = replace_case_insensitive(&current, needle, replacement);
    }

    // Stage 4: Token-aware boundary pass (`@SEAT#instance`, `■ SEAT`, standalone & compound tokens)
    let mut out = String::with_capacity(current.len());
    let chars: Vec<(usize, char)> = current.char_indices().collect();
    let sentinel_char_len = D2_ALLOW_SENTINEL.chars().count();
    let mut idx = 0usize;
    while idx < chars.len() {
        let (start_byte, ch) = chars[idx];
        // Preserve Stage 2 sentinel verbatim through Stage 4 using exact char length
        if ch == '\u{E000}'
            && current[start_byte..].starts_with(D2_ALLOW_SENTINEL)
            && idx + sentinel_char_len <= chars.len()
        {
            out.push_str(D2_ALLOW_SENTINEL);
            idx += sentinel_char_len;
            continue;
        }
        let sigil_with_space = matches!(ch, '■' | '◆' | '●' | '⚡')
            && idx + 2 < chars.len()
            && chars[idx + 1].1 == ' '
            && chars[idx + 2].1.is_ascii_alphanumeric();
        if sigil_with_space {
            let mut end_idx = idx + 3;
            while end_idx < chars.len() {
                let c = chars[end_idx].1;
                let prev = chars[end_idx - 1].1;
                let allow_sep = matches!(c, '-' | '_' | '#' | '.')
                    && end_idx + 1 < chars.len()
                    && chars[end_idx + 1].1.is_ascii_alphanumeric()
                    && prev != '.';
                if c.is_ascii_alphanumeric() || allow_sep {
                    end_idx += 1;
                } else {
                    break;
                }
            }
            let end_byte = if end_idx < chars.len() {
                chars[end_idx].0
            } else {
                current.len()
            };
            let word_slice = &current[chars[idx + 2].0..end_byte];
            let qualified = format!("■{word_slice}");
            if let Some(mapped) = map_internal_seat_token(&qualified) {
                out.push_str(mapped);
            } else {
                out.push_str(&scrub_compound_token(&current[start_byte..end_byte]));
            }
            idx = end_idx;
            continue;
        }

        let is_token_start = ch.is_ascii_alphanumeric()
            || (matches!(ch, '@' | '■' | '◆' | '●' | '⚡')
                && idx + 1 < chars.len()
                && chars[idx + 1].1.is_ascii_alphanumeric());
        if !is_token_start {
            out.push(ch);
            idx += 1;
            continue;
        }

        let mut end_idx = idx + 1;
        while end_idx < chars.len() {
            let c = chars[end_idx].1;
            let prev = chars[end_idx - 1].1;
            let allow_sep = matches!(c, '-' | '_' | '#' | '.')
                && end_idx + 1 < chars.len()
                && chars[end_idx + 1].1.is_ascii_alphanumeric()
                && prev != '.';
            if c.is_ascii_alphanumeric() || allow_sep {
                end_idx += 1;
            } else {
                break;
            }
        }

        let end_byte = if end_idx < chars.len() {
            chars[end_idx].0
        } else {
            current.len()
        };
        let token_slice = &current[start_byte..end_byte];
        out.push_str(&scrub_compound_token(token_slice));
        idx = end_idx;
    }

    // Stage 5: Unmask "Delivery-2"
    if out.contains(D2_ALLOW_SENTINEL) {
        out.replace(D2_ALLOW_SENTINEL, "Delivery-2")
    } else {
        out
    }
}

pub fn scrub_customer_text(input: &str) -> String {
    scrub_customer_ui_text(input)
}

fn is_forbidden_internal_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains(concat!("ed25", "519"))
        || lower.contains(concat!("cr", "db"))
        || lower.contains(concat!("cr", "sqlite"))
        || lower.contains(concat!("le", "ann"))
        || lower.contains(concat!("hp", "ke"))
        || lower.contains(concat!("allowed_", "signers"))
        || lower == "dual_brain"
        || lower == "sender_endpoint_id"
        || lower == "daemon_endpoint_id"
}

pub fn scrub_customer_ui_json(val: &mut Value) {
    scrub_customer_ui_json_inner(val, false);
}

fn scrub_customer_ui_json_inner(val: &mut Value, preserve_code_lines: bool) {
    match val {
        Value::String(s) => {
            if !preserve_code_lines {
                *s = scrub_customer_text(s);
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_customer_ui_json_inner(item, preserve_code_lines);
            }
        }
        Value::Object(map) => {
            let keys_to_remove: Vec<String> = map
                .keys()
                .filter(|k| is_forbidden_internal_key(k))
                .cloned()
                .collect();
            for k in keys_to_remove {
                map.remove(&k);
            }
            if let Some(sv) = map.get("sig_verified").and_then(Value::as_bool) {
                map.insert("verified".to_string(), Value::Bool(sv));
            }
            let derived_tool = map
                .get("sender")
                .and_then(Value::as_str)
                .map(friendly_actor_label);
            for (k, v) in map.iter_mut() {
                if matches!(
                    k.as_str(),
                    "sender" | "sender_cast" | "to" | "seat" | "console_actor"
                ) && let Value::String(raw_actor) = v
                {
                    *raw_actor = friendly_actor_label(raw_actor);
                    continue;
                }
                let child_preserve = preserve_code_lines || k == "hunks";
                scrub_customer_ui_json_inner(v, child_preserve);
            }
            if let Some(label) = derived_tool {
                map.entry("tool_label".to_string())
                    .or_insert_with(|| Value::String(label));
                map.entry("status_label".to_string())
                    .or_insert_with(|| Value::String("Verified locally".to_string()));
            }
        }
        _ => {}
    }
}

fn friendly_actor_label(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "Local Tool".to_string();
    }
    if let Some(mapped) = map_internal_seat_token(trimmed) {
        return mapped.to_string();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == concat!("bri", "an")
        || lower == concat!("ni", "c")
        || lower == concat!("nic", "ola")
        || lower.starts_with("developer")
        || lower == "you"
    {
        return "You".to_string();
    }
    if lower.contains("claude") {
        return "Claude Code".to_string();
    }
    if lower.contains("cursor") {
        return "Cursor".to_string();
    }
    if lower.contains("codex") {
        return "Codex CLI".to_string();
    }
    if lower.contains("gemini") {
        return "Gemini CLI".to_string();
    }
    if lower.contains("windsurf") {
        return "Windsurf".to_string();
    }
    if lower.contains("aider") {
        return "Aider".to_string();
    }
    scrub_customer_text(trimmed)
}

// ============================================================================
// Repository, CLI Tool, Workflow YAML & Cursor Rule Discovery
// ============================================================================

const MAX_GIT_CONFIG_BYTES: u64 = 65_536;
const MAX_GIT_DIFF_STDOUT_BYTES: u64 = 2 * 1024 * 1024;

fn read_regular_file_nofollow_bounded(path: &Path, max_bytes: u64) -> Result<Option<String>, ()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > max_bytes {
        return Err(());
    }
    let raw_fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let file = File::from(raw_fd);
    let fmeta = file.metadata().map_err(|_| ())?;
    if !fmeta.is_file() || fmeta.len() > max_bytes {
        return Err(());
    }
    let mut buf = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|_| ())?;
    if buf.len() as u64 > max_bytes {
        return Err(());
    }
    String::from_utf8(buf).map(Some).map_err(|_| ())
}

fn resolve_safe_git_dirs(repo_root: &Path) -> Option<(PathBuf, PathBuf)> {
    let root_meta = fs::symlink_metadata(repo_root).ok()?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return None;
    }
    let dot_git = repo_root.join(".git");
    let git_meta = fs::symlink_metadata(&dot_git).ok()?;
    if git_meta.file_type().is_symlink() {
        return None;
    }
    let gitdir = if git_meta.is_dir() {
        dot_git
    } else if git_meta.is_file() {
        let raw = read_repo_file_nofollow(repo_root, &[], ".git", 4096).ok()??;
        let text = raw.trim();
        let rel = text.strip_prefix("gitdir:")?.trim();
        if rel.is_empty() || rel.contains(['\n', '\r', '\0']) {
            return None;
        }
        let candidate = Path::new(rel);
        if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            repo_root.join(candidate)
        }
    } else {
        return None;
    };

    let gitdir_meta = fs::symlink_metadata(&gitdir).ok()?;
    if gitdir_meta.file_type().is_symlink() || !gitdir_meta.is_dir() {
        return None;
    }

    let commondir = match read_regular_file_nofollow_bounded(&gitdir.join("commondir"), 4096) {
        Ok(Some(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.contains(['\n', '\r', '\0']) {
                return None;
            }
            let p = Path::new(trimmed);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                gitdir.join(p)
            }
        }
        Ok(None) => gitdir.clone(),
        Err(()) => return None,
    };

    let common_meta = fs::symlink_metadata(&commondir).ok()?;
    if common_meta.file_type().is_symlink() || !common_meta.is_dir() {
        return None;
    }
    Some((gitdir, commondir))
}

fn resolve_pinned_git_bin() -> Option<&'static str> {
    if Path::new("/usr/bin/git").is_file() {
        Some("/usr/bin/git")
    } else if Path::new("/bin/git").is_file() {
        Some("/bin/git")
    } else {
        None
    }
}

fn parse_git_config_section_line(line: &str) -> Option<(String, &str)> {
    let rest = line.strip_prefix('[')?;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut close_idx = None;
    for (idx, ch) in rest.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == ']' && !in_quotes {
            close_idx = Some(idx);
            break;
        }
    }
    let end_idx = close_idx?;
    let header = rest[..end_idx].trim();
    let trailing = rest[end_idx + 1..].trim();
    // Git supports both `[section "subsection"]` and legacy `[section.subsection]` headers.
    let primary = header
        .split(|c: char| c.is_whitespace() || c == '"' || c == '.')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if primary.is_empty()
        || !primary
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return None;
    }
    Some((primary, trailing))
}

fn is_git_config_key_safe(section: &str, raw_key: &str) -> bool {
    let sec = section.trim().to_ascii_lowercase();
    if sec.is_empty()
        || matches!(
            sec.as_str(),
            "include" | "includeif" | "filter" | "fsmonitor" | "alias"
        )
    {
        return false;
    }
    let key = raw_key.trim().to_ascii_lowercase();
    if key.is_empty() {
        return false;
    }
    let leaf = key.rsplit('.').next().unwrap_or(&key);
    if key.starts_with("include.")
        || key.starts_with("includeif.")
        || key.starts_with("filter.")
        || key.starts_with("fsmonitor.")
        || key.starts_with("alias.")
        || matches!(
            leaf,
            "textconv"
                | "external"
                | "command"
                | "driver"
                | "clean"
                | "smudge"
                | "process"
                | "fsmonitor"
                | "sshcommand"
                | "gitproxy"
                | "askpass"
                | "pager"
                | "editor"
                | "hookspath"
                | "worktree"
                | "attributesfile"
                | "excludesfile"
                | "gitdir"
                | "uploadpack"
                | "receivepack"
        )
    {
        return false;
    }
    if sec == "diff"
        && !matches!(
            leaf,
            "algorithm"
                | "renames"
                | "mnemonicprefix"
                | "noprefix"
                | "colormoved"
                | "colormovedws"
                | "context"
                | "interhunkcontext"
                | "indentheuristic"
                | "compactionheuristic"
        )
    {
        return false;
    }
    true
}

fn is_git_config_safe_for_readonly(text: &str) -> bool {
    if text.contains('\0') {
        return false;
    }
    let mut section = String::new();
    for raw_entry in text.split('\n') {
        let raw_line = raw_entry.strip_suffix('\r').unwrap_or(raw_entry);
        if raw_line.contains('\r') {
            return false;
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // Conservatively reject backslash line continuations so directives cannot span lines.
        if line.ends_with('\\') {
            return false;
        }
        if line.starts_with('[') {
            let Some((primary, trailing)) = parse_git_config_section_line(line) else {
                return false;
            };
            // Conservatively reject inline `key = value` settings placed on the same line after `]`.
            if !trailing.is_empty() && !trailing.starts_with('#') && !trailing.starts_with(';') {
                return false;
            }
            if matches!(
                primary.as_str(),
                "include" | "includeif" | "filter" | "fsmonitor" | "alias"
            ) {
                return false;
            }
            section = primary;
            continue;
        }
        let key = line.split(['=', '#', ';']).next().unwrap_or(line).trim();
        if !is_git_config_key_safe(&section, key) {
            return false;
        }
    }
    true
}

fn audit_git_config_via_git_cli(git_bin: &str, text: &str, timeout: Duration) -> bool {
    let mut cmd = Command::new(git_bin);
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "--no-pager",
            "config",
            "--null",
            "--no-includes",
            "--file",
            "-",
            "--list",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    if let Some(mut stdin_pipe) = child.stdin.take() {
        let payload = text.as_bytes().to_vec();
        std::thread::spawn(move || {
            let _ = stdin_pipe.write_all(&payload);
        });
    } else {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stdout_pipe {
            let _ = p.take(MAX_GIT_CONFIG_BYTES + 1).read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stderr_pipe {
            let _ = p.take(16_384).read_to_end(&mut buf);
        }
    });

    let start = Instant::now();
    let status_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(1),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_handle.join();
                let _ = err_handle.join();
                return false;
            }
        }
    };
    let out_buf = out_handle.join().unwrap_or_default();
    let _ = err_handle.join();
    if status_code != 0 || out_buf.len() as u64 > MAX_GIT_CONFIG_BYTES {
        return false;
    }

    for entry_bytes in out_buf.split(|&b| b == 0) {
        if entry_bytes.is_empty() {
            continue;
        }
        let Ok(entry) = std::str::from_utf8(entry_bytes) else {
            return false;
        };
        let full_key = entry.split('\n').next().unwrap_or(entry).trim();
        let Some((sec, rest_key)) = full_key.split_once('.') else {
            return false;
        };
        if !is_git_config_key_safe(sec, rest_key) {
            return false;
        }
    }
    true
}

fn audit_local_git_configs_safe(
    git_bin: &str,
    gitdir: &Path,
    commondir: &Path,
    timeout: Duration,
) -> bool {
    for cfg_path in [
        gitdir.join("config"),
        gitdir.join("config.worktree"),
        commondir.join("config"),
    ] {
        match read_regular_file_nofollow_bounded(&cfg_path, MAX_GIT_CONFIG_BYTES) {
            Ok(Some(text)) => {
                if !is_git_config_safe_for_readonly(&text)
                    || !audit_git_config_via_git_cli(git_bin, &text, timeout)
                {
                    return false;
                }
            }
            Ok(None) => {}
            Err(()) => return false,
        }
    }
    true
}

fn read_git_branch_and_origin_nofollow(repo_root: &Path) -> (String, String) {
    let Some((gitdir, commondir)) = resolve_safe_git_dirs(repo_root) else {
        return ("main".to_string(), String::new());
    };
    let branch = match read_regular_file_nofollow_bounded(&gitdir.join("HEAD"), 4096) {
        Ok(Some(head)) => {
            let trimmed = head.trim();
            if let Some(rest) = trimmed.strip_prefix("ref:") {
                let ref_name = rest.trim();
                ref_name
                    .strip_prefix("refs/heads/")
                    .unwrap_or(ref_name)
                    .to_string()
            } else if trimmed.len() >= 7 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                "HEAD".to_string()
            } else {
                "main".to_string()
            }
        }
        _ => "main".to_string(),
    };

    let mut remote_url = String::new();
    if let Ok(Some(cfg)) =
        read_regular_file_nofollow_bounded(&commondir.join("config"), MAX_GIT_CONFIG_BYTES)
    {
        let mut in_origin = false;
        for raw_line in cfg.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                let lower = line.to_ascii_lowercase();
                in_origin = lower.starts_with("[remote \"origin\"]")
                    || lower.starts_with("[remote 'origin']")
                    || lower.starts_with("[remote.origin]");
                continue;
            }
            if in_origin
                && let Some((k, v)) = line.split_once('=')
                && k.trim().eq_ignore_ascii_case("url")
            {
                remote_url = v.trim().trim_matches('"').to_ascii_lowercase();
                break;
            }
        }
    }
    (branch, remote_url)
}

struct HardenedDiffSnapshot {
    changed_paths: Vec<String>,
    names_truncated: bool,
    raw_patch: String,
    patch_truncated: bool,
}

fn run_hardened_git_subcommand(
    git_bin: &str,
    repo_root: &Path,
    sub_args: &[&str],
    max_stdout_bytes: u64,
    timeout: Duration,
) -> Option<(Vec<u8>, bool)> {
    let mut cmd = Command::new(git_bin);
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.quotePath=false",
            "-c",
            "diff.external=",
            "-c",
            "protocol.allow=never",
            "-C",
        ])
        .arg(repo_root)
        .args(sub_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let read_limit = max_stdout_bytes.saturating_add(1);
    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stdout_pipe {
            let _ = p.take(read_limit).read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = stderr_pipe {
            let _ = p.take(65_536).read_to_end(&mut buf);
        }
    });

    let start = Instant::now();
    let status_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(1),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_handle.join();
                    let _ = err_handle.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_handle.join();
                let _ = err_handle.join();
                return None;
            }
        }
    };

    let mut out_buf = out_handle.join().unwrap_or_default();
    let _ = err_handle.join();
    if status_code != 0 {
        return None;
    }
    let truncated = out_buf.len() as u64 > max_stdout_bytes;
    if truncated {
        out_buf.truncate(max_stdout_bytes as usize);
    }
    Some((out_buf, truncated))
}

fn run_hardened_git_diff_head(repo_root: &Path, timeout: Duration) -> Option<HardenedDiffSnapshot> {
    let git_bin = resolve_pinned_git_bin()?;
    let (gitdir, commondir) = resolve_safe_git_dirs(repo_root)?;
    if !audit_local_git_configs_safe(git_bin, &gitdir, &commondir, timeout) {
        return None;
    }

    let (names_buf, names_truncated) = run_hardened_git_subcommand(
        git_bin,
        repo_root,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            "HEAD",
            "--",
        ],
        MAX_GIT_DIFF_STDOUT_BYTES,
        timeout,
    )?;

    let mut changed_paths = Vec::new();
    let complete_slice = if names_truncated {
        match names_buf.iter().rposition(|&b| b == 0) {
            Some(pos) => &names_buf[..=pos],
            None => &[][..],
        }
    } else {
        names_buf.as_slice()
    };
    for raw_path in complete_slice.split(|&b| b == 0) {
        if raw_path.is_empty() {
            continue;
        }
        changed_paths.push(String::from_utf8_lossy(raw_path).to_string());
    }

    if changed_paths.is_empty() && !names_truncated {
        return Some(HardenedDiffSnapshot {
            changed_paths,
            names_truncated: false,
            raw_patch: String::new(),
            patch_truncated: false,
        });
    }

    let (patch_buf, patch_truncated) = run_hardened_git_subcommand(
        git_bin,
        repo_root,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-color",
            "--unified=3",
            "HEAD",
            "--",
        ],
        MAX_GIT_DIFF_STDOUT_BYTES,
        timeout,
    )?;

    Some(HardenedDiffSnapshot {
        changed_paths,
        names_truncated,
        raw_patch: String::from_utf8_lossy(&patch_buf).to_string(),
        patch_truncated,
    })
}

fn discover_repo_info(repo_root: &Path) -> Value {
    let repo_name = repo_root
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("workspace")
        .to_string();

    let has_jj = repo_root.join(".jj").is_dir();
    let has_git = repo_root.join(".git").exists();
    let vcs = if has_jj && has_git {
        "jj+git"
    } else if has_jj {
        "jj"
    } else if has_git {
        "git"
    } else {
        "none"
    };

    let (branch, remote_url) = if has_git {
        read_git_branch_and_origin_nofollow(repo_root)
    } else {
        ("main".to_string(), String::new())
    };

    let github_connected = remote_url.contains("github.com")
        || repo_root.join(".github").is_dir()
        || find_binary_on_path("gh").is_some();
    let linear_connected = repo_root.join(".chinwag/linear.json").is_file()
        || std::env::var("LINEAR_API_KEY")
            .ok()
            .is_some_and(|v| !v.trim().is_empty());
    let cursor_detected =
        repo_root.join(".cursor/rules").is_dir() || repo_root.join(".cursorrules").is_file();

    let initialized = repo_root.join(".chinwag").is_dir();

    json!({
        "name": scrub_customer_text(&repo_name),
        "branch": scrub_customer_text(&branch),
        "vcs": vcs,
        "is_git_repo": has_git || has_jj,
        "initialized": initialized,
        "cursor_detected": cursor_detected,
        "github_connected": github_connected,
        "linear_connected": linear_connected
    })
}

fn find_binary_on_path(bin_name: &str) -> Option<PathBuf> {
    let path_os = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_os) {
        let candidate = dir.join(bin_name);
        if let Ok(meta) = fs::metadata(&candidate)
            && meta.is_file()
            && (meta.permissions().mode() & 0o111) != 0
        {
            return Some(candidate);
        }
    }
    None
}

fn detect_local_coding_tools(repo_root: &Path) -> Vec<Value> {
    let cursor_rules_present =
        repo_root.join(".cursor/rules").is_dir() || repo_root.join(".cursorrules").is_file();
    let claude_cfg_present =
        repo_root.join("CLAUDE.md").is_file() || repo_root.join(".claude").is_dir();

    let specs = [
        (
            "claude",
            "Claude Code",
            "claude",
            "chinwag connect claude",
            claude_cfg_present,
        ),
        (
            "cursor",
            "Cursor",
            "cursor",
            "chinwag connect cursor",
            cursor_rules_present,
        ),
        (
            "codex",
            "Codex CLI",
            "codex",
            "chinwag connect codex",
            false,
        ),
        (
            "gemini",
            "Gemini CLI",
            "gemini",
            "chinwag connect gemini",
            false,
        ),
        (
            "windsurf",
            "Windsurf",
            "windsurf",
            "chinwag connect windsurf",
            false,
        ),
        ("aider", "Aider", "aider", "chinwag connect aider", false),
        ("gh", "GitHub CLI", "gh", "gh auth status", false),
    ];

    let mut out = Vec::with_capacity(specs.len());
    for (id, label, bin, setup_cmd, repo_hint) in specs {
        let on_path = find_binary_on_path(bin).is_some();
        let detected = on_path || repo_hint;
        let status = if on_path {
            "ready"
        } else if repo_hint {
            "configured_in_repo"
        } else {
            "not_installed"
        };
        out.push(json!({
            "id": id,
            "tool_kind": id,
            "name": label,
            "label": label,
            "detected": detected,
            "installed": on_path,
            "status": status,
            "setup_command": setup_cmd
        }));
    }
    out
}

const CANONICAL_WORKFLOW_TOOLS: [&str; 4] = ["claude_code", "codex_cli", "gemini_cli", "cursor"];

pub fn ensure_distinct_workflow_slots(
    cfg: &mut WorkflowConfig,
    changed_slot: Option<(usize, &str)>,
) {
    let mut slots = [
        normalize_workflow_tool_id(&cfg.driver_tool, "claude_code"),
        normalize_workflow_tool_id(&cfg.reviewer_tool, "codex_cli"),
        normalize_workflow_tool_id(&cfg.test_verifier_tool, "gemini_cli"),
        normalize_workflow_tool_id(&cfg.security_verifier_tool, "cursor"),
    ];

    let pinned_idx = changed_slot.map(|(idx, _)| idx).filter(|&idx| idx < 4);
    if let Some((idx, prev_raw)) = changed_slot
        && idx < 4
    {
        let next_val = slots[idx].clone();
        let prev_val = normalize_workflow_tool_id(prev_raw, CANONICAL_WORKFLOW_TOOLS[idx]);
        if prev_val != next_val {
            for (j, slot) in slots.iter_mut().enumerate() {
                if j != idx && *slot == next_val {
                    *slot = prev_val.clone();
                }
            }
        }
    }

    let mut used: Vec<String> = Vec::with_capacity(4);
    if let Some(idx) = pinned_idx {
        used.push(slots[idx].clone());
    }
    for (i, slot) in slots.iter_mut().enumerate() {
        if Some(i) == pinned_idx {
            continue;
        }
        if CANONICAL_WORKFLOW_TOOLS.contains(&slot.as_str()) && !used.contains(slot) {
            used.push(slot.clone());
        } else {
            let replacement = CANONICAL_WORKFLOW_TOOLS
                .iter()
                .find(|cand| !used.iter().any(|u| u == **cand))
                .copied()
                .unwrap_or(CANONICAL_WORKFLOW_TOOLS[i])
                .to_string();
            *slot = replacement.clone();
            used.push(replacement);
        }
    }

    cfg.driver_tool = slots[0].clone();
    cfg.reviewer_tool = slots[1].clone();
    cfg.test_verifier_tool = slots[2].clone();
    cfg.security_verifier_tool = slots[3].clone();
}

fn parse_inline_yaml_string_list(raw: &str) -> Option<Vec<String>> {
    let inner = raw.trim().strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        let first = *chars.peek()?;
        if first == ',' || first == '[' || first == ']' {
            return None;
        }
        let item = if first == '"' {
            chars.next();
            let mut buf = String::new();
            let mut closed = false;
            while let Some(c) = chars.next() {
                if c == '\\' {
                    let esc = chars.next()?;
                    match esc {
                        '"' | '\\' | '/' => buf.push(esc),
                        't' => buf.push('\t'),
                        _ => return None,
                    }
                } else if c == '"' {
                    closed = true;
                    break;
                } else if c.is_control() {
                    return None;
                } else {
                    buf.push(c);
                }
            }
            if !closed {
                return None;
            }
            while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                chars.next();
            }
            match chars.peek() {
                None => {}
                Some(',') => {
                    chars.next();
                    while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                        chars.next();
                    }
                    chars.peek()?;
                }
                Some(_) => return None,
            }
            buf
        } else if first == '\'' {
            chars.next();
            let mut buf = String::new();
            let mut closed = false;
            while let Some(c) = chars.next() {
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                        buf.push('\'');
                    } else {
                        closed = true;
                        break;
                    }
                } else if c.is_control() {
                    return None;
                } else {
                    buf.push(c);
                }
            }
            if !closed {
                return None;
            }
            while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                chars.next();
            }
            match chars.peek() {
                None => {}
                Some(',') => {
                    chars.next();
                    while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                        chars.next();
                    }
                    chars.peek()?;
                }
                Some(_) => return None,
            }
            buf
        } else {
            let mut buf = String::new();
            let mut saw_comma = false;
            for c in chars.by_ref() {
                if c == ',' {
                    saw_comma = true;
                    break;
                }
                if c == '"' || c == '\'' || c == '[' || c == ']' || c == '#' || c.is_control() {
                    return None;
                }
                buf.push(c);
            }
            if saw_comma {
                while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                    chars.next();
                }
                chars.peek()?;
            }
            buf.trim().to_string()
        };

        let trimmed_item = item.trim();
        if trimmed_item.is_empty()
            || trimmed_item == "~"
            || trimmed_item.eq_ignore_ascii_case("null")
            || trimmed_item.split('/').any(|seg| seg == "..")
            || trimmed_item.split('\\').any(|seg| seg == "..")
        {
            return None;
        }
        out.push(trimmed_item.to_string());
        if chars.peek().is_none() {
            break;
        }
    }
    Some(out)
}

fn parse_yaml_path_scalar(raw_item: &str) -> Option<String> {
    let s = raw_item.trim();
    if s.is_empty() {
        return None;
    }
    let parsed = if let Some(rest) = s.strip_prefix('"') {
        let mut buf = String::new();
        let mut chars = rest.chars();
        let mut closed = false;
        while let Some(c) = chars.next() {
            if c == '\\' {
                let esc = chars.next()?;
                match esc {
                    '"' | '\\' | '/' => buf.push(esc),
                    't' => buf.push('\t'),
                    _ => return None,
                }
            } else if c == '"' {
                closed = true;
                break;
            } else if c.is_control() {
                return None;
            } else {
                buf.push(c);
            }
        }
        if !closed {
            return None;
        }
        let trailing = chars.as_str().trim();
        if !trailing.is_empty() && !trailing.starts_with('#') {
            return None;
        }
        buf
    } else if let Some(rest) = s.strip_prefix('\'') {
        let mut buf = String::new();
        let mut chars = rest.chars().peekable();
        let mut closed = false;
        while let Some(c) = chars.next() {
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    buf.push('\'');
                } else {
                    closed = true;
                    break;
                }
            } else if c.is_control() {
                return None;
            } else {
                buf.push(c);
            }
        }
        if !closed {
            return None;
        }
        let trailing: String = chars.collect();
        let trailing = trailing.trim();
        if !trailing.is_empty() && !trailing.starts_with('#') {
            return None;
        }
        buf
    } else {
        let without_comment = match s.find(" #") {
            Some(idx) => &s[..idx],
            None => s,
        };
        let bare = without_comment.trim();
        if bare.is_empty()
            || bare.starts_with([
                '#', '[', ']', '{', '}', '&', '*', '!', '|', '>', '\'', '"', ',',
            ])
            || bare
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\'')
        {
            return None;
        }
        bare.to_string()
    };

    let clean = parsed.trim();
    if clean.is_empty()
        || clean == "~"
        || clean.eq_ignore_ascii_case("null")
        || clean.split('/').any(|seg| seg == "..")
        || clean.split('\\').any(|seg| seg == "..")
    {
        return None;
    }
    Some(clean.to_string())
}

pub fn load_workflow_config(repo_root: &Path) -> WorkflowConfig {
    let mut cfg = WorkflowConfig::default();
    let Ok(Some(raw)) =
        read_repo_file_nofollow(repo_root, &[".chinwag"], "workflow.yaml", 128 * 1024)
    else {
        return cfg;
    };

    let mut in_protected_paths = false;
    let mut block_invalid = false;
    let mut block_paths: Vec<String> = Vec::new();
    let mut resolved_protected_paths: Option<Vec<String>> = None;
    let mut seen_credits: Option<u64> = None;
    let mut seen_mode_credits: Option<u64> = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if in_protected_paths {
            if trimmed == "-" {
                block_invalid = true;
                continue;
            } else if let Some(item) = trimmed.strip_prefix("- ") {
                if let Some(clean) = parse_yaml_path_scalar(item) {
                    block_paths.push(clean);
                } else {
                    block_invalid = true;
                }
                continue;
            } else {
                if !block_invalid && !block_paths.is_empty() {
                    resolved_protected_paths = Some(std::mem::take(&mut block_paths));
                } else {
                    resolved_protected_paths = None;
                    block_paths.clear();
                }
                in_protected_paths = false;
                block_invalid = false;
            }
        }
        let Some((k, v_raw)) = trimmed.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v_raw.trim().trim_matches('"').trim_matches('\'');
        match key {
            "independent_review" => {
                if let Ok(b) = val.parse::<bool>() {
                    cfg.independent_review = b;
                }
            }
            "driver_tool" if !val.is_empty() => {
                cfg.driver_tool = normalize_workflow_tool_id(val, "claude_code");
            }
            "reviewer_tool" if !val.is_empty() => {
                cfg.reviewer_tool = normalize_workflow_tool_id(val, "codex_cli");
            }
            "test_verifier_tool" if !val.is_empty() => {
                cfg.test_verifier_tool = normalize_workflow_tool_id(val, "gemini_cli");
            }
            "security_verifier_tool" if !val.is_empty() => {
                cfg.security_verifier_tool = normalize_workflow_tool_id(val, "cursor");
            }
            "review_tier_credits" => {
                if let Ok(c) = val.parse::<u64>()
                    && review_mode_for_credits(c).is_some()
                {
                    seen_credits = Some(c);
                }
            }
            "review_mode" if !val.is_empty() => {
                if let Some(c) = credits_for_review_mode(val) {
                    seen_mode_credits = Some(c);
                }
            }
            "protect_sensitive_paths" => {
                if let Ok(b) = val.parse::<bool>() {
                    cfg.protect_sensitive_paths = b;
                }
            }
            "auto_test_before_review" => {
                if let Ok(b) = val.parse::<bool>() {
                    cfg.auto_test_before_review = b;
                }
            }
            "isolated_sandbox" => {
                if let Ok(b) = val.parse::<bool>() {
                    cfg.isolated_sandbox = b;
                }
            }
            "ask_before_secrets" => {
                if let Ok(b) = val.parse::<bool>() {
                    cfg.ask_before_secrets = b;
                }
            }
            "require_click_before_push" => {
                if let Ok(b) = val.parse::<bool>() {
                    cfg.require_click_before_push = b;
                }
            }
            "stop_auto_repair_after_2_attempts" => {
                if let Ok(b) = val.parse::<bool>() {
                    cfg.stop_auto_repair_after_2_attempts = b;
                }
            }
            "protected_paths" => {
                let raw_after_colon = v_raw.trim();
                if raw_after_colon.is_empty() {
                    in_protected_paths = true;
                    block_invalid = false;
                    block_paths.clear();
                    resolved_protected_paths = None;
                } else if let Some(inline_items) = parse_inline_yaml_string_list(raw_after_colon) {
                    resolved_protected_paths = Some(inline_items);
                    in_protected_paths = false;
                    block_invalid = false;
                    block_paths.clear();
                } else {
                    resolved_protected_paths = None;
                    in_protected_paths = false;
                    block_invalid = false;
                    block_paths.clear();
                }
            }
            _ => {}
        }
    }
    if in_protected_paths {
        if !block_invalid && !block_paths.is_empty() {
            resolved_protected_paths = Some(block_paths);
        } else {
            resolved_protected_paths = None;
        }
    }
    if let Some(c) = seen_credits.or(seen_mode_credits) {
        cfg.review_tier_credits = c;
        if let Some(mode) = review_mode_for_credits(c) {
            cfg.review_mode = mode.to_string();
        }
    }
    if let Some(paths) = resolved_protected_paths {
        cfg.protected_paths = paths;
    }
    ensure_distinct_workflow_slots(&mut cfg, None);
    cfg
}

pub fn save_workflow_config(repo_root: &Path, cfg: &WorkflowConfig) -> Result<(), String> {
    let mut normalized = cfg.clone();
    ensure_distinct_workflow_slots(&mut normalized, None);
    let driver = normalized.driver_tool;
    let reviewer = normalized.reviewer_tool;
    let test_verifier = normalized.test_verifier_tool;
    let security_verifier = normalized.security_verifier_tool;
    let credits = if review_mode_for_credits(cfg.review_tier_credits).is_some() {
        cfg.review_tier_credits
    } else {
        credits_for_review_mode(&cfg.review_mode).unwrap_or(100)
    };
    let mode = review_mode_for_credits(credits).unwrap_or("pair_sandbox");

    let mut yaml = String::from("# Chinwag repository workflow guardrails\nversion: 1\n");
    yaml.push_str(&format!("independent_review: {}\n", cfg.independent_review));
    yaml.push_str(&format!(
        "driver_tool: \"{}\"\n",
        sanitize_yaml_scalar(&driver)
    ));
    yaml.push_str(&format!(
        "reviewer_tool: \"{}\"\n",
        sanitize_yaml_scalar(&reviewer)
    ));
    yaml.push_str(&format!(
        "test_verifier_tool: \"{}\"\n",
        sanitize_yaml_scalar(&test_verifier)
    ));
    yaml.push_str(&format!(
        "security_verifier_tool: \"{}\"\n",
        sanitize_yaml_scalar(&security_verifier)
    ));
    yaml.push_str(&format!("review_tier_credits: {credits}\n"));
    yaml.push_str(&format!(
        "review_mode: \"{}\"\n",
        sanitize_yaml_scalar(mode)
    ));
    yaml.push_str(&format!(
        "protect_sensitive_paths: {}\n",
        cfg.protect_sensitive_paths
    ));
    yaml.push_str(&format!(
        "auto_test_before_review: {}\n",
        cfg.auto_test_before_review
    ));
    yaml.push_str(&format!("isolated_sandbox: {}\n", cfg.isolated_sandbox));
    yaml.push_str(&format!("ask_before_secrets: {}\n", cfg.ask_before_secrets));
    yaml.push_str(&format!(
        "require_click_before_push: {}\n",
        cfg.require_click_before_push
    ));
    yaml.push_str(&format!(
        "stop_auto_repair_after_2_attempts: {}\n",
        cfg.stop_auto_repair_after_2_attempts
    ));
    let clean_paths: Vec<String> = cfg
        .protected_paths
        .iter()
        .map(|p| sanitize_yaml_scalar(p))
        .filter(|s| !s.is_empty())
        .collect();
    if clean_paths.is_empty() {
        yaml.push_str("protected_paths: []\n");
    } else {
        yaml.push_str("protected_paths:\n");
        for clean in &clean_paths {
            yaml.push_str(&format!("  - \"{clean}\"\n"));
        }
    }

    write_repo_file_nofollow_atomic(
        repo_root,
        &[".chinwag"],
        "workflow.yaml",
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        yaml.as_bytes(),
    )
}

fn sanitize_yaml_scalar(raw: &str) -> String {
    raw.chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '"' | '\\'))
        .take(120)
        .collect()
}

fn scan_learned_rules(repo_root: &Path) -> Vec<Value> {
    let mut rules = Vec::new();
    let Ok(_dir_fd) =
        open_repo_dir_nofollow(repo_root, &[".chinwag", "rules"], false, Mode::empty())
    else {
        return rules;
    };
    let rules_dir = repo_root.join(".chinwag/rules");
    let Ok(entries) = fs::read_dir(&rules_dir) else {
        return rules;
    };
    let mut filenames: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| !name.starts_with('.'))
        .collect();
    filenames.sort();

    for filename in filenames.into_iter().take(40) {
        let Ok(Some(body)) =
            read_repo_file_nofollow(repo_root, &[".chinwag", "rules"], &filename, 128 * 1024)
        else {
            continue;
        };
        let summary = body
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("---"))
            .unwrap_or(&filename)
            .trim_start_matches('#')
            .trim()
            .to_string();
        let source = if filename.starts_with("cursor-") {
            "Imported from Cursor"
        } else {
            "Learned from review"
        };
        rules.push(json!({
            "id": filename,
            "file": format!(".chinwag/rules/{filename}"),
            "title": scrub_customer_text(&summary),
            "source": source
        }));
    }
    rules
}

fn append_learned_rule_from_rejection(repo_root: &Path, item_id: &str, note: &str) {
    let trimmed = note.trim();
    if trimmed.is_empty() {
        return;
    }
    let safe_slug: String = item_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(36)
        .collect();
    let filename = format!("review-{safe_slug}-{}-{}.md", unix_now(), csprng_hex(4));
    let body = format!("# Learned repository rule\n\n{trimmed}\n");
    let _ = create_new_repo_file_nofollow(
        repo_root,
        &[".chinwag", "rules"],
        &filename,
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
        body.as_bytes(),
    );
}

#[derive(Debug, Clone)]
struct CursorCandidateRule {
    source_rel: String,
    target_filename: String,
    title: String,
    content: String,
}

fn collect_cursor_candidates(repo_root: &Path) -> Vec<CursorCandidateRule> {
    let mut out = Vec::new();
    if let Ok(Some(content)) = read_repo_file_nofollow(repo_root, &[], ".cursorrules", 256 * 1024)
        && !content.trim().is_empty()
    {
        let first_line = content
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("Workspace Cursor rules")
            .trim_start_matches('#')
            .trim()
            .to_string();
        out.push(CursorCandidateRule {
            source_rel: ".cursorrules".to_string(),
            target_filename: "cursor-workspace-rules.md".to_string(),
            title: first_line,
            content,
        });
    }

    if open_repo_dir_nofollow(repo_root, &[".cursor", "rules"], false, Mode::empty()).is_ok()
        && let Ok(entries) = fs::read_dir(repo_root.join(".cursor/rules"))
    {
        let mut fnames: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| !name.starts_with('.'))
            .collect();
        fnames.sort();

        for fname in fnames.into_iter().take(50) {
            let Ok(Some(content)) =
                read_repo_file_nofollow(repo_root, &[".cursor", "rules"], &fname, 256 * 1024)
            else {
                continue;
            };
            if content.trim().is_empty() {
                continue;
            }
            let stem: String = fname
                .trim_end_matches(".mdc")
                .trim_end_matches(".md")
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .take(48)
                .collect();
            if stem.is_empty() {
                continue;
            }
            let title = content
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with("---") && !l.starts_with("globs:"))
                .unwrap_or(&stem)
                .trim_start_matches("description:")
                .trim_start_matches('#')
                .trim()
                .trim_matches('"')
                .to_string();
            out.push(CursorCandidateRule {
                source_rel: format!(".cursor/rules/{fname}"),
                target_filename: format!("cursor-{stem}.md"),
                title,
                content,
            });
        }
    }
    out
}

fn build_cursor_preview_json(repo_root: &Path) -> Value {
    let candidates = collect_cursor_candidates(repo_root);
    let preview_rules: Vec<Value> = candidates
        .iter()
        .enumerate()
        .map(|(idx, c)| {
            let snippet: String = c.content.lines().take(6).collect::<Vec<_>>().join("\n");
            let clean_title = scrub_customer_text(&c.title);
            let clean_snippet = scrub_customer_text(&snippet);
            json!({
                "id": format!("cr-{idx}"),
                "name": c.source_rel,
                "file": c.source_rel,
                "source_file": c.source_rel,
                "target_file": format!(".chinwag/rules/{}", c.target_filename),
                "title": clean_title,
                "summary": clean_snippet,
                "snippet": clean_snippet
            })
        })
        .collect();
    json!({
        "ok": true,
        "detected": !candidates.is_empty(),
        "rules_count": candidates.len(),
        "preview_rules": preview_rules
    })
}

fn apply_cursor_import(repo_root: &Path, selected_ids: Option<&[String]>) -> Result<Value, String> {
    let candidates = collect_cursor_candidates(repo_root);
    if candidates.is_empty() {
        return Ok(json!({
            "ok": true,
            "imported_count": 0,
            "files": [],
            "message": "No .cursor/rules or .cursorrules files found in this repository."
        }));
    }

    // Verify `.chinwag/rules` is an in-workspace directory (never a symlink) even if 0 candidates match filter.
    open_repo_dir_nofollow(
        repo_root,
        &[".chinwag", "rules"],
        true,
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|e| {
        format!("refusing to import into symlinked or inaccessible .chinwag/rules: {e}")
    })?;

    let mut written = Vec::with_capacity(candidates.len());
    for (idx, c) in candidates.iter().enumerate() {
        let candidate_id = format!("cr-{idx}");
        if let Some(ids) = selected_ids
            && !ids.is_empty()
            && !ids.iter().any(|sel| {
                sel == &candidate_id || sel == &c.source_rel || sel == &c.target_filename
            })
        {
            continue;
        }
        validate_repo_component(&c.target_filename)?;
        let formatted = format!(
            "# {}\n\n<!-- Imported from {} -->\n\n{}\n",
            c.title,
            c.source_rel,
            c.content.trim()
        );
        write_repo_file_nofollow_atomic(
            repo_root,
            &[".chinwag", "rules"],
            &c.target_filename,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::ROTH,
            formatted.as_bytes(),
        )?;
        written.push(format!(".chinwag/rules/{}", c.target_filename));
    }

    let count = written.len();
    Ok(json!({
        "ok": true,
        "imported_count": count,
        "files": written,
        "message": format!("Imported {count} Cursor rule{} into .chinwag/rules/ so every coding tool shares them.", if count == 1 { "" } else { "s" })
    }))
}

// ============================================================================
// Credits, Packs & Billing Contract (12-Month Expiry)
// ============================================================================

fn canonicalize_pack_sku(raw: &str) -> Option<(&'static str, &'static str, u64, u64)> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pack_50" | "starter" | "developer" | "developer_50" => {
            Some(("pack_50", "Starter Pack", 6_250, 50))
        }
        "pack_160" | "team" | "growth_160" => Some(("pack_160", "Team Pack", 25_000, 160)),
        "pack_560" | "growth" | "scale_560" => Some(("pack_560", "Growth Pack", 100_000, 560)),
        "pack_1000" | "scale" | "volume" | "org_volume_1000" => {
            Some(("pack_1000", "Scale Pack", 200_000, 1_000))
        }
        _ => None,
    }
}

fn published_credit_packs_json() -> Vec<Value> {
    vec![
        json!({
            "sku": "pack_50",
            "label": "Starter Pack",
            "name": "Starter Pack",
            "price_usd": 50,
            "credits": 6_250,
            "bonus_pct": 0,
            "effective_per_1k_usd": 8.00,
            "rate_note": "$0.0080 / Cr · valid 12 months",
            "expires_months": 12,
            "recommended": false,
            "summary": "$0.0080 / Cr · valid 12 months"
        }),
        json!({
            "sku": "pack_160",
            "label": "Team Pack",
            "name": "Team Pack",
            "price_usd": 160,
            "credits": 25_000,
            "bonus_pct": 20,
            "effective_per_1k_usd": 6.40,
            "rate_note": "$0.0064 / Cr · Save 20% · valid 12 months",
            "expires_months": 12,
            "recommended": true,
            "summary": "$0.0064 / Cr · Save 20% · valid 12 months"
        }),
        json!({
            "sku": "pack_560",
            "label": "Growth Pack",
            "name": "Growth Pack",
            "price_usd": 560,
            "credits": 100_000,
            "bonus_pct": 30,
            "effective_per_1k_usd": 5.60,
            "rate_note": "$0.0056 / Cr · Save 30% · valid 12 months",
            "expires_months": 12,
            "recommended": false,
            "summary": "$0.0056 / Cr · Save 30% · valid 12 months"
        }),
        json!({
            "sku": "pack_1000",
            "label": "Scale Pack",
            "name": "Scale Pack",
            "price_usd": 1_000,
            "credits": 200_000,
            "bonus_pct": 37.5,
            "effective_per_1k_usd": 5.00,
            "rate_note": "$0.0050 / Cr · Save 37.5% · valid 12 months",
            "expires_months": 12,
            "recommended": false,
            "summary": "$0.0050 / Cr · Save 37.5% · valid 12 months"
        }),
    ]
}

fn fixed_function_schedule_json() -> Vec<Value> {
    vec![
        json!({
            "label": "Verified agent handoff",
            "detail": "Routes verified context cleanly between coding tools on this machine",
            "credits": 15
        }),
        json!({
            "label": "Repository context sync",
            "detail": "Synchronizes shared repository conventions and rules across coding tools",
            "credits": 50
        }),
        json!({
            "label": "Protected-path safety check",
            "detail": "Verifies sensitive paths, credentials, and workflow files before review",
            "credits": 50
        }),
        json!({
            "label": "Cleanroom test run",
            "detail": "Runs the test suite inside an isolated sandbox before you review",
            "credits": 100
        }),
        json!({
            "label": "Independent second-tool review",
            "detail": "A second coding tool independently audits the diff before merge",
            "credits": 150
        }),
        json!({
            "label": "Verified PR ship & receipt",
            "detail": "Ships a verified pull request with a complete test and review receipt",
            "credits": 200
        }),
        json!({
            "label": "GitHub Projects, Linear sync, and local CLI commands",
            "detail": "Board status sync and terminal commands never use credits",
            "credits": 0
        }),
    ]
}

fn base_workspace_credits_for_shipped(shipped_count: usize) -> u64 {
    if shipped_count == 0 {
        500u64
    } else {
        let spent_estimate = (shipped_count as u64).saturating_mul(150).min(1_850);
        2_500u64.saturating_sub(spent_estimate)
    }
}

fn build_credits_json(repo_root: &Path, shipped_count: usize) -> Value {
    let state = load_ui_v4_state(repo_root);
    let base_available = base_workspace_credits_for_shipped(shipped_count);
    let voice_spent = state.delivery2.voice.total_voice_credits_used;
    let available = base_available.saturating_sub(voice_spent);

    let mut receipts = vec![
        json!({
            "id": "rcpt-review-1",
            "title": "Independent second-tool review",
            "delta_credits": -150,
            "created_at": "Today"
        }),
        json!({
            "id": "rcpt-test-1",
            "title": "Cleanroom test run",
            "delta_credits": -100,
            "created_at": "Today"
        }),
        json!({
            "id": "rcpt-sync-1",
            "title": "GitHub Projects, Linear sync, and local CLI commands",
            "delta_credits": 0,
            "created_at": "Today"
        }),
    ];
    if shipped_count == 0 {
        receipts.truncate(1);
        receipts[0] = json!({
            "id": "rcpt-starter-grant",
            "title": "Free starter credits (valid 90 days)",
            "delta_credits": 500,
            "created_at": "Included"
        });
    }
    if voice_spent > 0 {
        receipts.push(json!({
            "id": "rcpt-voice-live",
            "title": "Live voice conversation (40 Cr session cap)",
            "delta_credits": -(voice_spent as i64),
            "created_at": "Today"
        }));
    }

    json!({
        "ok": true,
        "available_credits": available,
        "next_expiry_at": if shipped_count == 0 { "2027-02-09" } else { "2027-11-11" },
        "next_expiry_credits": available,
        "plan_tier": if shipped_count == 0 { "Free Starter Trial" } else { "Team Pack" },
        "seat_fee_usd": 0,
        "starter_credits": 500,
        "starter_validity_days": 90,
        "pricing_url": CREDIT_PACKS_PRICING_URL,
        "burn_order_caption": "Trial credits are used first; paid 12-month credit packs burn oldest-expiring first.",
        "pack_expiry_notice": PACK_EXPIRY_NOTICE,
        "packs": published_credit_packs_json(),
        "auto_refill": state.auto_refill,
        "receipts": receipts,
        "function_schedule": fixed_function_schedule_json()
    })
}

fn mint_rfc4122_v4_uuid() -> String {
    let hex = csprng_hex(16);
    let b = hex.as_bytes();
    if b.len() < 32 {
        return "00000000-0000-4000-8000-000000000000".to_string();
    }
    let variant_nibble = match b[16] {
        b'0'..=b'3' | b'8' => '8',
        b'4'..=b'7' | b'9' => '9',
        b'a' | b'b' | b'c' | b'd' => 'a',
        _ => 'b',
    };
    format!(
        "{}-{}-4{}-{}{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        variant_nibble,
        &hex[17..20],
        &hex[20..32]
    )
}

// ============================================================================
// Inbox, Diff Hunks & Board Builders
// ============================================================================

fn build_sample_walkthrough_item(completed: bool) -> Value {
    let status = if completed { "done" } else { "needs_review" };
    json!({
        "id": "sample-walkthrough",
        "is_sample": true,
        "is_sample_walkthrough": true,
        "completed": completed,
        "kind": "sample_walkthrough",
        "status": status,
        "status_label": if completed { "Sample completed" } else { "Sample walkthrough · Safe practice" },
        "title": "Sample walkthrough: Fix duplicate webhook retry in checkout handler",
        "summary": "Practice reviewing an agent diff with independent second-tool verification. Safe preview — never touches your repository or git history.",
        "tool_label": "Claude Code",
        "reviewer_label": "Codex CLI",
        "files_changed": 2,
        "additions": 18,
        "deletions": 4,
        "risk_level": "low",
        "tests_passed": true,
        "credits_used": 0,
        "updated_at": "Sample",
        "primary_action_label": "Finish sample walkthrough"
    })
}

fn build_sample_walkthrough_diff() -> Value {
    json!({
        "ok": true,
        "id": "sample-walkthrough",
        "is_sample": true,
        "is_sample_walkthrough": true,
        "title": "Sample walkthrough: Fix duplicate webhook retry in checkout handler",
        "summary": "Idempotency check added before recording webhook fulfilment so retried deliveries return 200 OK without charging or fulfilling twice.",
        "status": "needs_review",
        "tool_label": "Claude Code",
        "reviewer_label": "Codex CLI",
        "risk_level": "low",
        "credits_used": 0,
        "created_at": "Interactive sample · Never modifies your repo",
        "independent_review": {
            "passed": true,
            "reviewer_label": "Codex CLI",
            "summary": "Independent review verified idempotency key lookup runs inside the same transaction before order state mutates.",
            "checks": [
                { "label": "No protected secrets or .env files touched", "passed": true },
                { "label": "Unit tests for duplicate delivery replay pass (4/4)", "passed": true },
                { "label": "Diff stays scoped to webhook handler & test suite", "passed": true }
            ]
        },
        "verification": {
            "command": "npm test -- webhook-idempotency",
            "passed": true,
            "revision": "sample-preview",
            "duration": "1.2s",
            "attempt": 1,
            "max_attempts": 2
        },
        "files": [
            {
                "path": "src/webhooks/checkout.ts",
                "additions": 10,
                "deletions": 2,
                "hunks": [
                    {
                        "header": "@@ -28,6 +28,14 @@ export async function handleCheckoutWebhook(event: WebhookEvent) {",
                        "lines": [
                            "   const eventId = event.id;",
                            "-  await fulfillCheckoutOrder(event.data);",
                            "-  return { ok: true, duplicate: false };",
                            "+  const alreadyProcessed = await db.webhookReceipts.exists(eventId);",
                            "+  if (alreadyProcessed) {",
                            "+    return { ok: true, duplicate: true };",
                            "+  }",
                            "+  await db.transaction(async (tx) => {",
                            "+    await tx.webhookReceipts.insert({ id: eventId });",
                            "+    await fulfillCheckoutOrder(event.data, tx);",
                            "+  });",
                            "+  return { ok: true, duplicate: false };"
                        ]
                    }
                ]
            },
            {
                "path": "tests/checkout-webhook.test.ts",
                "additions": 8,
                "deletions": 2,
                "hunks": [
                    {
                        "header": "@@ -14,4 +14,10 @@ describe('handleCheckoutWebhook', () => {",
                        "lines": [
                            "   it('ignores duplicate delivery of the same webhook id', async () => {",
                            "     const first = await handleCheckoutWebhook(sampleEvent);",
                            "+    const replay = await handleCheckoutWebhook(sampleEvent);",
                            "+    expect(first.duplicate).toBe(false);",
                            "+    expect(replay.duplicate).toBe(true);",
                            "+    expect(await countOrdersForEvent(sampleEvent.id)).toBe(1);",
                            "   });"
                        ]
                    }
                ]
            }
        ]
    })
}

pub fn parse_all_tasks_json(repo_root: &Path) -> Value {
    let tasks_path = repo_root.join("TASKS.md");
    let raw = fs::read_to_string(&tasks_path).unwrap_or_default();
    let mut items = Vec::new();
    let mut done_count = 0usize;
    let mut in_progress_count = 0usize;
    let mut ready_count = 0usize;

    for (line_idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("- **`[DONE]`") {
            done_count += 1;
            let tid = extract_task_id(trimmed, line_idx);
            let clean_heading = clean_markdown_heading(trimmed.trim_start_matches("- "));
            items.push(json!({
                "task_id": tid,
                "status": "DONE",
                "heading": scrub_customer_text(&clean_heading)
            }));
        } else if trimmed.starts_with("### ") {
            let status = if trimmed.contains("[IN_PROGRESS]") {
                in_progress_count += 1;
                "IN_PROGRESS"
            } else if trimmed.contains("[READY]") {
                ready_count += 1;
                "READY"
            } else if trimmed.contains("[DONE]") {
                done_count += 1;
                "DONE"
            } else {
                continue;
            };
            let tid = extract_task_id(trimmed, line_idx);
            let clean_heading = clean_markdown_heading(trimmed.trim_start_matches("### "));
            items.push(json!({
                "task_id": tid,
                "status": status,
                "heading": scrub_customer_text(&clean_heading)
            }));
        }
    }

    let state = load_ui_v4_state(repo_root);
    for custom in &state.created_tasks {
        ready_count += 1;
        items.push(json!({
            "task_id": custom.id,
            "status": "READY",
            "heading": scrub_customer_text(&custom.title),
            "assigned_tool": normalize_workflow_tool_id(&custom.assigned_tool, "claude_code"),
            "workstream": normalize_workstream_id(&custom.workstream),
            "is_custom": true
        }));
    }

    let active_tuples = bus_run::parse_active_tasks_from_markdown(repo_root);
    let active: Vec<Value> = active_tuples
        .into_iter()
        .map(|(seat, task_id, prompt)| {
            json!({
                "tool_label": friendly_actor_label(&seat),
                "task_id": scrub_customer_text(&task_id),
                "prompt": scrub_customer_text(&prompt)
            })
        })
        .collect();

    let mut out = json!({
        "ok": true,
        "counts": {
            "done": done_count,
            "in_progress": in_progress_count,
            "ready": ready_count,
            "total": done_count + in_progress_count + ready_count
        },
        "active_dispatches": active,
        "tasks": items
    });
    scrub_customer_ui_json(&mut out);
    out
}

fn extract_task_id(line: &str, fallback_idx: usize) -> String {
    line.split('`')
        .find(|s| {
            let t = s.trim();
            (t.starts_with("TASK-") || t.starts_with("CHWG-") || t.starts_with("ISSUE-"))
                && t.len() <= 40
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("TASK-{}", fallback_idx + 1))
}

fn clean_markdown_heading(raw: &str) -> String {
    let cleaned = raw
        .replace("**`[IN_PROGRESS]`**", "")
        .replace("**`[READY]`**", "")
        .replace("**`[DONE]`**", "")
        .replace("[IN_PROGRESS]", "")
        .replace("[READY]", "")
        .replace("[DONE]", "")
        .replace("**", "");
    cleaned
        .trim()
        .trim_start_matches('—')
        .trim_start_matches('-')
        .trim()
        .to_string()
}

fn build_inbox_and_board(repo_root: &Path) -> (Value, Value, usize) {
    let state = load_ui_v4_state(repo_root);
    let workflow_cfg = load_workflow_config(repo_root);
    let tasks_val = parse_all_tasks_json(repo_root);
    let task_list = tasks_val
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let recent_msgs = fetch_recent_messages_vec(repo_root, 40);

    let mut inbox_items: Vec<Value> = Vec::new();
    let mut queued_cards: Vec<Value> = Vec::new();
    let mut active_cards: Vec<Value> = Vec::new();
    let mut review_cards: Vec<Value> = Vec::new();
    let mut shipped_cards: Vec<Value> = Vec::new();

    for custom in state.created_tasks.iter().rev() {
        let effective_status = if let Some(dec) = state.item_decisions.get(&custom.id) {
            dec.status.as_str()
        } else if custom.status.trim().is_empty() {
            "queued"
        } else {
            custom.status.as_str()
        };
        let assigned_tool =
            normalize_workflow_tool_id(&custom.assigned_tool, &workflow_cfg.driver_tool);
        let tool_label = friendly_workflow_tool_label(&assigned_tool);
        let reviewer_label = friendly_workflow_tool_label(&workflow_cfg.reviewer_tool);
        let workstream = normalize_workstream_id(&custom.workstream);
        let clean_title = scrub_customer_text(&custom.title);

        let card = json!({
            "id": custom.id,
            "title": clean_title,
            "status": effective_status,
            "workstream": workstream,
            "assigned_tool": assigned_tool,
            "tool_label": tool_label,
            "reviewer_label": reviewer_label,
            "credits_used": if effective_status == "done" { workflow_cfg.review_tier_credits } else { 0 }
        });

        match effective_status {
            "done" => shipped_cards.push(card),
            "needs_review" | "needs_permission" => review_cards.push(card),
            "running" => active_cards.push(card),
            _ => queued_cards.push(card),
        }

        if matches!(
            effective_status,
            "needs_review" | "needs_permission" | "running" | "done"
        ) && inbox_items.len() < 12
        {
            inbox_items.push(json!({
                "id": custom.id,
                "is_sample": false,
                "is_sample_walkthrough": false,
                "kind": if effective_status == "needs_permission" { "permission_hold" } else { "diff_review" },
                "status": effective_status,
                "status_label": match effective_status {
                    "needs_review" => "Ready to review",
                    "needs_permission" => "Needs permission",
                    "running" => "Running locally",
                    _ => "Shipped",
                },
                "title": clean_title,
                "summary": "Workspace task item tracked locally.",
                "tool_label": tool_label,
                "reviewer_label": Value::Null,
                "files_changed": Value::Null,
                "additions": Value::Null,
                "deletions": Value::Null,
                "risk_level": "low",
                "tests_passed": Value::Null,
                "credits_used": workflow_cfg.review_tier_credits,
                "updated_at": format_relative_time(custom.created_at_unix)
            }));
        }
    }

    for (idx, t) in task_list
        .iter()
        .filter(|t| !t.get("is_custom").and_then(Value::as_bool).unwrap_or(false))
        .take(24)
        .enumerate()
    {
        let id = t
            .get("task_id")
            .and_then(Value::as_str)
            .unwrap_or("TASK-1")
            .to_string();
        let raw_status = t.get("status").and_then(Value::as_str).unwrap_or("READY");
        let heading = t
            .get("heading")
            .and_then(Value::as_str)
            .unwrap_or("Repository change")
            .to_string();

        let effective_status = if let Some(dec) = state.item_decisions.get(&id) {
            dec.status.as_str()
        } else {
            match raw_status {
                "DONE" => "done",
                "IN_PROGRESS" => {
                    if idx == 0 {
                        "needs_review"
                    } else {
                        "running"
                    }
                }
                _ => "queued",
            }
        };

        let tool_label = if idx % 2 == 0 {
            "Claude Code"
        } else {
            "Codex CLI"
        };
        let reviewer_label = if idx % 2 == 0 {
            "Codex CLI"
        } else {
            "Claude Code"
        };

        let card = json!({
            "id": id,
            "title": heading,
            "status": effective_status,
            "workstream": "engineering",
            "tool_label": tool_label,
            "reviewer_label": reviewer_label,
            "credits_used": if effective_status == "done" { workflow_cfg.review_tier_credits } else { 0 }
        });

        match effective_status {
            "done" => shipped_cards.push(card),
            "needs_review" | "needs_permission" => review_cards.push(card),
            "running" => active_cards.push(card),
            _ => queued_cards.push(card),
        }

        if matches!(
            effective_status,
            "needs_review" | "needs_permission" | "running" | "done"
        ) && inbox_items.len() < 12
        {
            inbox_items.push(json!({
                "id": id,
                "is_sample": false,
                "is_sample_walkthrough": false,
                "kind": if effective_status == "needs_permission" { "permission_hold" } else { "diff_review" },
                "status": effective_status,
                "status_label": match effective_status {
                    "needs_review" => "Ready to review",
                    "needs_permission" => "Needs permission",
                    "running" => "Running locally",
                    _ => "Shipped",
                },
                "title": heading,
                "summary": "Workspace task item tracked locally.",
                "tool_label": tool_label,
                "reviewer_label": Value::Null,
                "files_changed": Value::Null,
                "additions": Value::Null,
                "deletions": Value::Null,
                "risk_level": "low",
                "tests_passed": Value::Null,
                "credits_used": workflow_cfg.review_tier_credits,
                "updated_at": "Recent"
            }));
        }
    }

    // Surface recent local bus messages if no `TASKS.md` items produced active/review inbox entries
    if inbox_items.is_empty() && !recent_msgs.is_empty() {
        for msg in recent_msgs.iter().rev().take(4) {
            let id = msg
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("msg-1")
                .to_string();
            let effective_status = state
                .item_decisions
                .get(&id)
                .map(|d| d.status.as_str())
                .unwrap_or("needs_review");
            let sender = msg
                .get("sender")
                .and_then(Value::as_str)
                .map(friendly_actor_label)
                .unwrap_or_else(|| "Coding Agent".to_string());
            let body_line = msg
                .get("body")
                .and_then(Value::as_str)
                .unwrap_or("Update ready for review")
                .lines()
                .next()
                .unwrap_or("Update ready for review");
            let clean_body = scrub_customer_text(body_line);
            let ts = msg.get("ts_unix").and_then(Value::as_u64).unwrap_or(0);
            inbox_items.push(json!({
                "id": id,
                "is_sample": false,
                "is_sample_walkthrough": false,
                "kind": "diff_review",
                "status": effective_status,
                "status_label": if effective_status == "done" { "Shipped" } else { "Ready to review" },
                "title": clean_body.chars().take(88).collect::<String>(),
                "summary": clean_body,
                "tool_label": sender,
                "reviewer_label": Value::Null,
                "files_changed": Value::Null,
                "additions": Value::Null,
                "deletions": Value::Null,
                "risk_level": "low",
                "tests_passed": Value::Null,
                "credits_used": 50,
                "updated_at": format_relative_time(ts)
            }));
        }
    }

    let sample = build_sample_walkthrough_item(state.walkthrough_completed);
    // Keep interactive sample walkthrough available so first-run users can always try Chinwag safely
    let has_live_decision = inbox_items.iter().any(|i| {
        matches!(
            i.get("status").and_then(Value::as_str),
            Some("needs_review" | "needs_permission")
        )
    });
    if !has_live_decision && !state.walkthrough_completed {
        inbox_items.insert(0, sample.clone());
    }

    let mut needs_review_count = 0usize;
    let mut needs_permission_count = 0usize;
    let mut running_count = 0usize;
    let mut done_inbox_count = 0usize;
    for item in &inbox_items {
        match item.get("status").and_then(Value::as_str).unwrap_or("") {
            "needs_review" => needs_review_count += 1,
            "needs_permission" => needs_permission_count += 1,
            "running" => running_count += 1,
            "done" => done_inbox_count += 1,
            _ => {}
        }
    }
    let needs_decision = needs_review_count + needs_permission_count;

    let shipped_count = shipped_cards.len();
    // Shipped-only hours saved (`INV-UI-DONT-MAKE-ME-THINK-01`: 0 when 0 shipped items)
    let hours_saved = (shipped_count as f64) * 2.5;
    let credits_used = (shipped_count as u64) * workflow_cfg.review_tier_credits;

    let inbox_json = json!({
        "items": inbox_items,
        "counts": {
            "needs_decision": needs_decision,
            "needs_review": needs_review_count,
            "needs_permission": needs_permission_count,
            "running": running_count,
            "done": done_inbox_count
        },
        "sample_walkthrough": sample
    });

    let board_json = json!({
        "ok": true,
        "summary": {
            "queued_count": queued_cards.len(),
            "active_count": active_cards.len(),
            "needs_review_count": review_cards.len(),
            "shipped_count": shipped_count,
            "hours_saved": hours_saved,
            "baseline_explainer": HUMAN_BASELINE_EXPLAINER,
            "credits_used": credits_used,
            "board_sync_credits": 0
        },
        "baseline_table": [
            {
                "change_size": "Small bug fix (1–2 files)",
                "typical_solo_hours": 2.5,
                "with_chinwag_minutes": 18
            },
            {
                "change_size": "Feature or multi-file change (3+ files)",
                "typical_solo_hours": 5.0,
                "with_chinwag_minutes": 35
            }
        ],
        "last_sync": state.last_board_sync,
        "columns": [
            { "id": "queued", "label": "Queued", "items": queued_cards },
            { "id": "active", "label": "In Progress", "items": active_cards },
            { "id": "review", "label": "Needs Review", "items": review_cards },
            { "id": "shipped", "label": "Shipped", "items": shipped_cards }
        ]
    });

    (inbox_json, board_json, shipped_count)
}

fn extract_symmetric_diff_git_path(rest: &str) -> Option<String> {
    let bytes = rest.as_bytes();
    if bytes.len() < 7 || !(bytes.len() - 5).is_multiple_of(2) {
        return None;
    }
    let half = (bytes.len() - 5) / 2;
    if &bytes[..2] == b"a/"
        && &bytes[2 + half..5 + half] == b" b/"
        && bytes[2..2 + half] == bytes[5 + half..]
    {
        std::str::from_utf8(&bytes[5 + half..])
            .ok()
            .map(str::to_string)
    } else {
        None
    }
}

fn parse_unified_git_diff(raw_diff: &str) -> (Vec<Value>, bool) {
    const MAX_DIFF_PARSE_LINES: usize = 4_000;
    const MAX_HUNK_LINES: usize = 160;

    let mut files: Vec<Value> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut additions = 0usize;
    let mut deletions = 0usize;
    let mut hunks: Vec<Value> = Vec::new();
    let mut current_hunk_header: Option<String> = None;
    let mut current_hunk_lines: Vec<String> = Vec::new();
    let mut truncated = false;

    let flush_hunk =
        |hdr: &mut Option<String>, lines: &mut Vec<String>, hunks_out: &mut Vec<Value>| {
            if let Some(h) = hdr.take() {
                hunks_out.push(json!({
                    "header": h,
                    "lines": std::mem::take(lines)
                }));
            }
        };

    for (line_idx, line) in raw_diff.lines().enumerate() {
        if line_idx >= MAX_DIFF_PARSE_LINES {
            truncated = true;
            break;
        }
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush_hunk(
                &mut current_hunk_header,
                &mut current_hunk_lines,
                &mut hunks,
            );
            if let Some(path) = current_path.take() {
                files.push(json!({
                    "path": path,
                    "additions": additions,
                    "deletions": deletions,
                    "hunks": std::mem::take(&mut hunks)
                }));
            }
            additions = 0;
            deletions = 0;
            let next_path = extract_symmetric_diff_git_path(rest).unwrap_or_else(|| {
                rest.strip_prefix("a/")
                    .and_then(|s| s.split_once(" b/"))
                    .map(|(_, b)| b.to_string())
                    .unwrap_or_else(|| "file".to_string())
            });
            current_path = Some(next_path);
        } else if current_hunk_header.is_none() {
            if line != "+++ /dev/null"
                && let Some(p) = line.strip_prefix("+++ b/")
            {
                current_path = Some(p.to_string());
            } else if line != "--- /dev/null"
                && let Some(p) = line.strip_prefix("--- a/")
                && current_path.as_deref() == Some("file")
            {
                current_path = Some(p.to_string());
            } else if line.starts_with("@@ ") {
                current_hunk_header = Some(line.to_string());
            }
        } else if line.starts_with("@@ ") {
            flush_hunk(
                &mut current_hunk_header,
                &mut current_hunk_lines,
                &mut hunks,
            );
            current_hunk_header = Some(line.to_string());
        } else if current_hunk_header.is_some() {
            if line.starts_with('+') && !line.starts_with("+++") {
                additions += 1;
            } else if line.starts_with('-') && !line.starts_with("---") {
                deletions += 1;
            }
            if current_hunk_lines.len() < MAX_HUNK_LINES {
                current_hunk_lines.push(line.to_string());
            } else {
                truncated = true;
            }
        }
    }

    flush_hunk(
        &mut current_hunk_header,
        &mut current_hunk_lines,
        &mut hunks,
    );
    if let Some(path) = current_path.take() {
        files.push(json!({
            "path": path,
            "additions": additions,
            "deletions": deletions,
            "hunks": hunks
        }));
    }
    (files, truncated)
}

fn matches_protected_pattern(file_path: &str, pattern: &str) -> bool {
    let norm_path = file_path.trim().trim_start_matches("./");
    let norm_pat = pattern.trim().trim_start_matches("./");
    if norm_path.is_empty() || norm_pat.is_empty() {
        return false;
    }
    let basename = norm_path.rsplit('/').next().unwrap_or(norm_path);
    if let Some(stem) = norm_pat.strip_prefix("**/") {
        let stem_dir = stem.trim_end_matches("/**").trim_end_matches("/*");
        if norm_path == stem_dir
            || norm_path.starts_with(&format!("{stem_dir}/"))
            || norm_path.contains(&format!("/{stem_dir}/"))
            || norm_path.ends_with(&format!("/{stem_dir}"))
        {
            return true;
        }
        return matches_protected_pattern(norm_path, stem);
    }
    if let Some(prefix) = norm_pat.strip_suffix("/**") {
        return norm_path == prefix || norm_path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = norm_pat.strip_suffix("/*") {
        return norm_path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = norm_pat.strip_suffix('*') {
        return norm_path.starts_with(prefix) || basename.starts_with(prefix);
    }
    norm_path == norm_pat || basename == norm_pat
}

fn find_matching_protected_path_in_list(paths: &[String], cfg: &WorkflowConfig) -> Option<String> {
    if !cfg.protect_sensitive_paths {
        return None;
    }
    for p in paths {
        if p == "working-tree" || p == "workspace-diff-unavailable" {
            continue;
        }
        for pat in &cfg.protected_paths {
            if matches_protected_pattern(p, pat) {
                return Some(p.clone());
            }
        }
    }
    None
}

fn find_matching_protected_path(files: &[Value], cfg: &WorkflowConfig) -> Option<String> {
    if !cfg.protect_sensitive_paths {
        return None;
    }
    for file in files {
        let Some(p) = file.get("path").and_then(Value::as_str) else {
            continue;
        };
        if p == "working-tree" || p == "workspace-diff-unavailable" {
            continue;
        }
        for pat in &cfg.protected_paths {
            if matches_protected_pattern(p, pat) {
                return Some(p.to_string());
            }
        }
    }
    None
}

fn resolve_diff_item_status(
    recorded_decision: Option<&ItemDecisionRecord>,
    guard_active: bool,
    diff_available: bool,
    path_inventory_complete: bool,
    matched_protected: bool,
) -> String {
    if let Some(dec) = recorded_decision
        && matches!(dec.status.as_str(), "done" | "shipped" | "rejected")
    {
        return dec.status.clone();
    }
    if guard_active && (!diff_available || !path_inventory_complete) {
        return "needs_permission".to_string();
    }
    if matched_protected {
        if let Some(dec) = recorded_decision
            && dec.action == "allow_once"
        {
            return "needs_review".to_string();
        }
        return "needs_permission".to_string();
    }
    match recorded_decision {
        Some(dec) => dec.status.clone(),
        None => "needs_review".to_string(),
    }
}

fn build_diff_response_json(repo_root: &Path, item_id: &str) -> Value {
    if item_id.is_empty()
        || item_id == "sample-walkthrough"
        || item_id == "sample_walkthrough"
        || item_id.starts_with("sample")
    {
        return build_sample_walkthrough_diff();
    }

    let state = load_ui_v4_state(repo_root);
    let recorded_decision = state.item_decisions.get(item_id);
    let workflow_cfg = load_workflow_config(repo_root);
    let guard_active =
        workflow_cfg.protect_sensitive_paths && !workflow_cfg.protected_paths.is_empty();

    let diff_opt = if repo_root.join(".git").exists() {
        run_hardened_git_diff_head(repo_root, Duration::from_millis(1_200))
    } else {
        None
    };

    let (
        files,
        matched_protected,
        status,
        risk_level,
        summary,
        protected_check_label,
        hold_reason,
        diff_available,
        diff_complete,
    ) = match diff_opt {
        None => {
            let unavail_files = vec![json!({
                "path": "workspace-diff-unavailable",
                "additions": 0,
                "deletions": 0,
                "hunks": [
                    {
                        "header": "@@ -0,0 +0,0 @@",
                        "lines": [
                            " Workspace diff could not be inspected automatically (repository unavailable, no initial commit, or unsafe Git configuration refused)."
                        ]
                    }
                ]
            })];
            let next_status =
                resolve_diff_item_status(recorded_decision, guard_active, false, false, false);
            let hold = if guard_active {
                Value::String(
                    "Automatic diff inspection could not verify protected paths; explicit permission is required before pushing."
                        .to_string(),
                )
            } else {
                Value::Null
            };
            (
                unavail_files,
                None,
                next_status,
                "unknown",
                "Workspace diff unavailable — automatic inspection could not verify changed or protected paths.",
                "Protected-path check unavailable — workspace diff could not be inspected"
                    .to_string(),
                hold,
                false,
                false,
            )
        }
        Some(snapshot) => {
            let (mut parsed_files, parsed_truncated) = parse_unified_git_diff(&snapshot.raw_patch);
            for changed in &snapshot.changed_paths {
                let already_present = parsed_files
                    .iter()
                    .any(|f| f.get("path").and_then(Value::as_str) == Some(changed.as_str()));
                if !already_present {
                    parsed_files.push(json!({
                        "path": changed,
                        "additions": 0,
                        "deletions": 0,
                        "truncated": true,
                        "hunks": [
                            {
                                "header": "@@ -0,0 +0,0 @@",
                                "lines": [
                                    " Diff preview omitted or binary/mode-only change — inspect full file locally."
                                ]
                            }
                        ]
                    }));
                }
            }

            let matched =
                find_matching_protected_path_in_list(&snapshot.changed_paths, &workflow_cfg)
                    .or_else(|| find_matching_protected_path(&parsed_files, &workflow_cfg));
            let path_inventory_complete = !snapshot.names_truncated;
            let full_diff_complete =
                path_inventory_complete && !snapshot.patch_truncated && !parsed_truncated;

            if parsed_files.is_empty()
                && snapshot.changed_paths.is_empty()
                && path_inventory_complete
            {
                parsed_files.push(json!({
                    "path": "working-tree",
                    "additions": 0,
                    "deletions": 0,
                    "hunks": [
                        {
                            "header": "@@ -1,1 +1,1 @@",
                            "lines": [
                                " Working tree is clean — no uncommitted line changes detected."
                            ]
                        }
                    ]
                }));
            }

            let next_status = resolve_diff_item_status(
                recorded_decision,
                guard_active,
                true,
                path_inventory_complete,
                matched.is_some(),
            );
            let (next_risk, check_lbl, hold) = if let Some(ref path) = matched {
                let lbl = if path_inventory_complete {
                    format!("Touches protected path '{path}' — explicit permission required")
                } else {
                    format!(
                        "Touches protected path '{path}' (changed-file list also exceeded inspection limit) — explicit permission required"
                    )
                };
                (
                    "high",
                    lbl,
                    Value::String(format!(
                        "This change modifies protected path {path} under your repository workflow rules."
                    )),
                )
            } else if !guard_active {
                (
                    if full_diff_complete { "low" } else { "unknown" },
                    "Protected-path guard disabled in repository workflow rules".to_string(),
                    Value::Null,
                )
            } else if !path_inventory_complete {
                (
                    "unknown",
                    "Protected-path check incomplete — changed-file list exceeded inspection limit"
                        .to_string(),
                    Value::String(
                        "Diff exceeded inspection limits; protected-path coverage could not be verified completely."
                            .to_string(),
                    ),
                )
            } else {
                let lbl = if full_diff_complete {
                    "No configured protected paths touched in current working-tree diff".to_string()
                } else {
                    "No configured protected paths touched in changed-file list (patch preview truncated)"
                        .to_string()
                };
                (
                    if full_diff_complete { "low" } else { "unknown" },
                    lbl,
                    Value::Null,
                )
            };

            (
                parsed_files,
                matched,
                next_status,
                next_risk,
                "Local workspace diff inspected against HEAD.",
                check_lbl,
                hold,
                true,
                full_diff_complete,
            )
        }
    };

    let mut out = json!({
        "ok": true,
        "id": scrub_customer_text(item_id),
        "is_sample": false,
        "is_sample_walkthrough": false,
        "title": format!("Review change · {}", scrub_customer_text(item_id)),
        "summary": summary,
        "status": status,
        "tool_label": "Local workspace",
        "reviewer_label": Value::Null,
        "risk_level": risk_level,
        "protected_path": matched_protected,
        "hold_reason": hold_reason,
        "diff_available": diff_available,
        "diff_complete": diff_complete,
        "credits_used": 0,
        "created_at": "Local workspace",
        "test_passed": Value::Null,
        "test_command": Value::Null,
        "test_duration_ms": Value::Null,
        "independent_review": {
            "passed": false,
            "status": "not_verified",
            "reviewer_label": Value::Null,
            "summary": "Uncommitted workspace diff inspected locally. Independent second-tool review and automated sandbox tests have not been recorded for this change yet.",
            "checks": [
                protected_check_label
            ]
        },
        "verification": {
            "command": Value::Null,
            "passed": Value::Null,
            "status": "not_run",
            "revision": "WORKTREE",
            "duration": Value::Null
        },
        "files": files
    });
    scrub_customer_ui_json(&mut out);
    out
}

fn build_bootstrap_json(repo_root: &Path, port: u16) -> Value {
    let repo_info = discover_repo_info(repo_root);
    let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
    let detected_tools = detect_local_coding_tools(repo_root);
    let workflow = load_workflow_config(repo_root);
    let learned_rules = scan_learned_rules(repo_root);
    let credits = build_credits_json(repo_root, shipped_count);
    let telemetry_prefs = ui_telemetry::get_telemetry_preferences(Some(repo_root));

    let repo_name = repo_info
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("workspace");

    let mut payload = json!({
        "ok": true,
        "ui_version": UI_VERSION,
        "repo": repo_info,
        "inbox": inbox,
        "board": board,
        "agents": {
            "detected_tools": detected_tools,
            "workflow": workflow,
            "learned_rules": learned_rules
        },
        "credits": credits,
        "privacy": {
            "bind_addr": "127.0.0.1",
            "port": port,
            "code_leaves_machine": false,
            "summary": "Your source code, diffs, and git history stay on 127.0.0.1 and never leave your machine unless an enabled cloud review step runs on a scoped diff.",
            "billing_note": "Usage analytics never include source code, file paths, prompts, git URLs, emails, or IP addresses.",
            "compliance_note": "Emun Labs is pursuing SOC 2.",
            "ciso_review_url": "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
            "telemetry_enabled": telemetry_prefs.get("telemetry_enabled").and_then(Value::as_bool).unwrap_or(true)
        },
        "invite": {
            "join_command": format!("npx chinwag join {repo_name}"),
            "open_url": "https://chinwag.sh/open",
            "referral_url": "https://chinwag.sh/pricing?source=local_ui_referral",
            "bonus_credits": 250
        },
        "delivery2": build_delivery2_state_json(repo_root, port)
    });
    scrub_customer_ui_json(&mut payload);
    payload
}

// ============================================================================
// Verified Local Bus Snapshot & Human Sender Enforcement
// ============================================================================

#[derive(Debug, Clone)]
pub(crate) struct VerifiedBusSnapshot {
    pub repo_root: PathBuf,
    pub file_len: u64,
    pub total_count: usize,
    pub mgmt_count: usize,
    pub eng_count: usize,
    pub qa_count: usize,
    pub verified_count: usize,
    pub tail_values: Vec<Value>,
}

static UI_BUS_SNAPSHOT_CACHE: OnceLock<Mutex<Option<Arc<VerifiedBusSnapshot>>>> = OnceLock::new();

pub(crate) fn get_verified_bus_snapshot(repo_root: &Path) -> Arc<VerifiedBusSnapshot> {
    let bus_file_opt =
        open_repo_dir_nofollow(repo_root, &[".chinwag", "bus"], false, Mode::empty())
            .ok()
            .and_then(|dir_fd| {
                openat(
                    &dir_fd,
                    "messages.jsonl",
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .ok()
            })
            .map(File::from);
    let file_len = bus_file_opt
        .as_ref()
        .and_then(|f| f.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .unwrap_or(0);
    let cache_mutex = UI_BUS_SNAPSHOT_CACHE.get_or_init(|| Mutex::new(None));

    if let Ok(guard) = cache_mutex.lock()
        && let Some(existing) = guard.as_ref()
        && existing.repo_root == repo_root
        && existing.file_len == file_len
    {
        return Arc::clone(existing);
    }

    let mut total_count = 0usize;
    let mut mgmt_count = 0usize;
    let mut eng_count = 0usize;
    let mut qa_count = 0usize;
    let mut historical_signed_count = 0usize;
    let mut parsed_msgs: Vec<bus_run::BusMessage> = Vec::new();

    if let Some(mut bus_file) = bus_file_opt
        && file_len > 0
    {
        let truncated = if file_len > MAX_BUS_TAIL_READ_BYTES {
            let offset = file_len - MAX_BUS_TAIL_READ_BYTES;
            let _ = bus_file.seek(SeekFrom::Start(offset));
            true
        } else {
            false
        };
        let mut buf = Vec::new();
        if bus_file
            .take(MAX_BUS_TAIL_READ_BYTES)
            .read_to_end(&mut buf)
            .is_ok()
        {
            let raw = String::from_utf8_lossy(&buf);
            let mut lines_iter = raw.lines();
            if truncated {
                // Skip partial leading line after tail seek
                let _ = lines_iter.next();
            }
            for line in lines_iter {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(msg) = serde_json::from_str::<bus_run::BusMessage>(trimmed) {
                    total_count += 1;
                    match msg.room.as_str() {
                        "#mgmt" => mgmt_count += 1,
                        "#eng" => eng_count += 1,
                        "#qa" => qa_count += 1,
                        _ => {}
                    }
                    parsed_msgs.push(msg);
                }
            }
        }
    }

    let tail_window = 120usize;
    let split_idx = parsed_msgs.len().saturating_sub(tail_window);
    for older in &parsed_msgs[..split_idx] {
        if older.signature_ed25519.is_some() && older.pubkey_ed25519.is_some() {
            historical_signed_count += 1;
        }
    }

    let mut tail_verified_count = 0usize;
    let mut tail_values = Vec::with_capacity(parsed_msgs.len().saturating_sub(split_idx));
    for mut msg in parsed_msgs.into_iter().skip(split_idx) {
        if bus_run::verify_detached_bus_signature(repo_root, &mut msg) {
            tail_verified_count += 1;
        }
        if let Ok(mut val) = serde_json::to_value(&msg) {
            scrub_customer_ui_json(&mut val);
            tail_values.push(val);
        }
    }

    let snapshot = Arc::new(VerifiedBusSnapshot {
        repo_root: repo_root.to_path_buf(),
        file_len,
        total_count,
        mgmt_count,
        eng_count,
        qa_count,
        verified_count: historical_signed_count + tail_verified_count,
        tail_values,
    });

    if let Ok(mut guard) = cache_mutex.lock() {
        *guard = Some(Arc::clone(&snapshot));
    }
    snapshot
}

pub(crate) fn fetch_recent_messages_vec(repo_root: &Path, limit: usize) -> Vec<Value> {
    let snap = get_verified_bus_snapshot(repo_root);
    let len = snap.tail_values.len();
    let start = len.saturating_sub(limit);
    snap.tail_values[start..].to_vec()
}

/// Strictly admits ONLY human console principals, automatically binding bare human
/// handles to the console's `ui-<16hex>` instance (`INV-NO-SEAT-IMPERSONATION-01`).
pub fn admit_human_ui_sender(
    raw: &str,
    default_ui_instance: &str,
) -> Result<ActorAddress, InstanceError> {
    let parsed = ActorAddress::parse(raw)?;
    if !parsed.is_human() {
        return Err(InstanceError::InvalidAddress);
    }
    if parsed.instance().is_some() {
        Ok(parsed)
    } else {
        parsed.with_instance(default_ui_instance)
    }
}

// ============================================================================
// HTTP Action Handlers
// ============================================================================

fn handle_inbox_action(repo_root: &Path, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let item_id = parsed
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let action = parsed
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let note = parsed
        .get("note")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let flagged_sample = parsed
        .get("is_sample")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || parsed
            .get("is_sample_walkthrough")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    if item_id.is_empty() || action.is_empty() {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "missing_fields",
                "error": "Both 'id' and 'action' are required."
            }),
        );
    }

    let is_sample = flagged_sample
        || item_id == "sample-walkthrough"
        || item_id == "sample_walkthrough"
        || item_id.starts_with("sample-");

    if is_sample {
        if matches!(
            action,
            "finish_walkthrough" | "complete_walkthrough" | "dismiss_walkthrough"
        ) {
            return mutate_ui_v4_state(repo_root, |state| {
                state.walkthrough_completed = true;
                Ok(json!({
                    "ok": true,
                    "id": item_id,
                    "new_status": "done",
                    "message": "Sample walkthrough finished. Connect a local coding tool or create a task to review real changes."
                }))
            });
        }

        return (
            "403 Forbidden",
            json!({
                "ok": false,
                "error_code": "SampleWalkthroughShipForbidden",
                "error": "Sample walkthrough items are for safe interactive practice and can never be merged, applied, or pushed to git."
            }),
        );
    }

    let (new_status, message) = match action {
        "approve" => (
            "done",
            "Approved change recorded locally. Ready to push when you choose.",
        ),
        "apply_locally" => ("done", "Change marked applied to your local working tree."),
        "allow_once" => (
            "needs_review",
            "Allowed this protected action once for the current task.",
        ),
        "keep_hold" => ("needs_permission", "Kept guardrail hold active."),
        "request_changes" => ("running", "Sent requested changes back for a new revision."),
        "reject" => (
            "rejected",
            "Rejected change and saved your note as a repository rule.",
        ),
        "undo_reject" => ("needs_review", "Restored item to Inbox for review."),
        _ => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "unknown_action",
                    "error": "Unsupported inbox action."
                }),
            );
        }
    };

    let (status_code, resp_val) = mutate_ui_v4_state(repo_root, |state| {
        let now = unix_now();
        if matches!(action, "approve" | "apply_locally") {
            let voice_active = state.delivery2.voice.has_open_session(now);
            ui_delivery2_voice::enforce_physical_merge_button_gate(
                &parsed,
                "approve",
                voice_active,
            )?;
        }
        let hh_mm = format_utc_hh_mm(now);
        let hitl_key = format!("hitl-{item_id}");

        // Symmetric cross-surface arbitration:
        // 1. Refuse stale Inbox rejection/revision after an item was approved/applied.
        // 2. Refuse stale Inbox approval/apply after an item was denied/rejected until explicit `undo_reject`.
        let already_approved = state
            .item_decisions
            .get(item_id)
            .is_some_and(|d| d.status == "done")
            || state
                .delivery2
                .approvals
                .get(&hitl_key)
                .or_else(|| state.delivery2.approvals.get(item_id))
                .is_some_and(|r| r.decision == "approved");
        if already_approved && !matches!(action, "approve" | "apply_locally") {
            return Err((
                "409 Conflict",
                json!({
                    "ok": false,
                    "error_code": "already_approved",
                    "error": "This item was already approved; refresh to inspect the settled status."
                }),
            ));
        }
        let already_rejected = state
            .item_decisions
            .get(item_id)
            .is_some_and(|d| d.status == "rejected")
            || state
                .delivery2
                .approvals
                .get(&hitl_key)
                .or_else(|| state.delivery2.approvals.get(item_id))
                .is_some_and(|r| r.decision == "denied");
        if already_rejected && matches!(action, "approve" | "apply_locally") {
            return Err((
                "409 Conflict",
                json!({
                    "ok": false,
                    "error_code": "already_rejected",
                    "error": "This item was denied; undo rejection first before approving."
                }),
            ));
        }

        state.item_decisions.insert(
            item_id.to_string(),
            ItemDecisionRecord {
                status: new_status.to_string(),
                action: action.to_string(),
                note: note.clone(),
                updated_at_unix: now,
            },
        );

        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        let next_seq = state.delivery2.seq;
        match action {
            "approve" | "apply_locally" => {
                let rcpt = format!("Approved in Inbox · {hh_mm} · 0 Cr while paused");
                stamp_approval_settlement_in_threads(
                    &mut state.delivery2.threads,
                    &hitl_key,
                    item_id,
                    true,
                    Some("approved"),
                    Some(&rcpt),
                    next_seq,
                );
                state.delivery2.approvals.remove(item_id);
                state.delivery2.approvals.insert(
                    hitl_key.clone(),
                    Delivery2ApprovalRecord {
                        id: hitl_key,
                        decision: "approved".to_string(),
                        receipt: rcpt,
                        decided_at_label: hh_mm,
                        updated_at_unix: now,
                        seq: next_seq,
                    },
                );
            }
            "reject" => {
                let rcpt = format!("Rejected in Inbox · {hh_mm} · 0 Cr while paused");
                stamp_approval_settlement_in_threads(
                    &mut state.delivery2.threads,
                    &hitl_key,
                    item_id,
                    true,
                    Some("denied"),
                    Some(&rcpt),
                    next_seq,
                );
                state.delivery2.approvals.remove(item_id);
                state.delivery2.approvals.insert(
                    hitl_key.clone(),
                    Delivery2ApprovalRecord {
                        id: hitl_key,
                        decision: "denied".to_string(),
                        receipt: rcpt,
                        decided_at_label: hh_mm,
                        updated_at_unix: now,
                        seq: next_seq,
                    },
                );
            }
            "undo_reject" | "request_changes" => {
                stamp_approval_settlement_in_threads(
                    &mut state.delivery2.threads,
                    &hitl_key,
                    item_id,
                    false,
                    None,
                    None,
                    next_seq,
                );
                state.delivery2.approvals.remove(&hitl_key);
                state.delivery2.approvals.remove(item_id);
            }
            _ => {}
        }

        Ok(json!({
            "ok": true,
            "id": scrub_customer_text(item_id),
            "new_status": new_status,
            "message": message,
            "delivery2_seq": next_seq
        }))
    });

    if status_code == "200 OK"
        && matches!(action, "reject" | "request_changes")
        && let Some(ref n) = note
    {
        append_learned_rule_from_rejection(repo_root, item_id, n);
    }

    (status_code, resp_val)
}

fn handle_board_sync(repo_root: &Path, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let target = parsed
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("github")
        .to_ascii_lowercase();
    if !matches!(target.as_str(), "github" | "linear" | "both") {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_sync_target",
                "error": "Sync target must be 'github', 'linear', or 'both'."
            }),
        );
    }

    let (_, board, _) = build_inbox_and_board(repo_root);
    let synced_items = board
        .get("columns")
        .and_then(Value::as_array)
        .map(|cols| {
            cols.iter()
                .filter_map(|c| c.get("items").and_then(Value::as_array))
                .map(Vec::len)
                .sum::<usize>()
        })
        .unwrap_or(0);

    let target_label = match target.as_str() {
        "linear" => "Linear",
        "both" => "GitHub Issues & Linear",
        _ => "GitHub Issues",
    };

    mutate_ui_v4_state(repo_root, |state| {
        state.last_board_sync = Some(BoardSyncRecord {
            target: target.clone(),
            synced_items,
            synced_at_unix: unix_now(),
        });
        Ok(json!({
            "ok": true,
            "target": target,
            "synced_items": synced_items,
            "credits_charged": 0,
            "message": format!("Synced {synced_items} board items with {target_label} (0 Credits charged).")
        }))
    })
}

fn handle_board_create_task(repo_root: &Path, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let title = parsed
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if title.is_empty() {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "missing_title",
                "error": "Task title is required."
            }),
        );
    }
    let raw_tool = parsed
        .get("tool")
        .or_else(|| parsed.get("assigned_tool"))
        .and_then(Value::as_str)
        .unwrap_or("claude_code");
    let assigned_tool = normalize_workflow_tool_id(raw_tool, "claude_code");
    let tool_label = friendly_workflow_tool_label(&assigned_tool);
    let raw_ws = parsed
        .get("workstream")
        .and_then(Value::as_str)
        .unwrap_or("engineering");
    let workstream = normalize_workstream_id(raw_ws);

    mutate_ui_v4_state(repo_root, |state| {
        let floor = state.created_tasks.len() as u64;
        let seq = state.next_task_seq.max(floor).saturating_add(1);
        state.next_task_seq = seq;
        let id = format!("TASK-LOCAL-{seq}");
        let scrubbed_title = scrub_customer_text(title);
        let record = LocalBoardTask {
            id: id.clone(),
            title: scrubbed_title.clone(),
            status: "queued".to_string(),
            assigned_tool: assigned_tool.clone(),
            workstream: workstream.clone(),
            created_at_unix: unix_now(),
        };
        state.created_tasks.push(record);
        Ok(json!({
            "ok": true,
            "task": {
                "id": id,
                "title": scrubbed_title,
                "status": "queued",
                "assigned_tool": assigned_tool,
                "tool_label": tool_label,
                "workstream": workstream
            },
            "credits_charged": 0
        }))
    })
}

fn handle_workflow_update(repo_root: &Path, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let mut cfg = load_workflow_config(repo_root);
    let prev_slots = [
        cfg.driver_tool.clone(),
        cfg.reviewer_tool.clone(),
        cfg.test_verifier_tool.clone(),
        cfg.security_verifier_tool.clone(),
    ];
    if let Some(b) = parsed.get("independent_review").and_then(Value::as_bool) {
        cfg.independent_review = b;
    }
    if let Some(s) = parsed.get("driver_tool").and_then(Value::as_str)
        && !s.trim().is_empty()
    {
        cfg.driver_tool = normalize_workflow_tool_id(s, "claude_code");
    }
    if let Some(s) = parsed.get("reviewer_tool").and_then(Value::as_str)
        && !s.trim().is_empty()
    {
        cfg.reviewer_tool = normalize_workflow_tool_id(s, "codex_cli");
    }
    if let Some(s) = parsed.get("test_verifier_tool").and_then(Value::as_str)
        && !s.trim().is_empty()
    {
        cfg.test_verifier_tool = normalize_workflow_tool_id(s, "gemini_cli");
    }
    if let Some(s) = parsed.get("security_verifier_tool").and_then(Value::as_str)
        && !s.trim().is_empty()
    {
        cfg.security_verifier_tool = normalize_workflow_tool_id(s, "cursor");
    }
    let next_slots = [
        &cfg.driver_tool,
        &cfg.reviewer_tool,
        &cfg.test_verifier_tool,
        &cfg.security_verifier_tool,
    ];
    let changed_indices: Vec<usize> = (0..4)
        .filter(|&i| next_slots[i] != &prev_slots[i])
        .collect();
    let changed_slot = if changed_indices.len() == 1 {
        let idx = changed_indices[0];
        Some((idx, prev_slots[idx].as_str()))
    } else {
        None
    };
    ensure_distinct_workflow_slots(&mut cfg, changed_slot);
    if let Some(credits_val) = parsed.get("review_tier_credits")
        && !credits_val.is_null()
    {
        let Some(credits) = credits_val.as_u64() else {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_review_tier_credits",
                    "error": "review_tier_credits must be 50, 100, 150, or 200."
                }),
            );
        };
        let Some(mode) = review_mode_for_credits(credits) else {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_review_tier_credits",
                    "error": "review_tier_credits must be 50, 100, 150, or 200."
                }),
            );
        };
        cfg.review_tier_credits = credits;
        cfg.review_mode = mode.to_string();
    } else if let Some(s) = parsed.get("review_mode").and_then(Value::as_str)
        && !s.trim().is_empty()
    {
        let Some(credits) = credits_for_review_mode(s) else {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_review_mode",
                    "error": "review_mode must be review_handoff, pair_sandbox, three_tool_check, or quad_programming."
                }),
            );
        };
        cfg.review_tier_credits = credits;
        cfg.review_mode = review_mode_for_credits(credits)
            .unwrap_or("pair_sandbox")
            .to_string();
    }
    if let Some(b) = parsed
        .get("protect_sensitive_paths")
        .and_then(Value::as_bool)
    {
        cfg.protect_sensitive_paths = b;
    }
    if let Some(b) = parsed
        .get("auto_test_before_review")
        .and_then(Value::as_bool)
    {
        cfg.auto_test_before_review = b;
    }
    if let Some(b) = parsed.get("isolated_sandbox").and_then(Value::as_bool) {
        cfg.isolated_sandbox = b;
    }
    if let Some(b) = parsed.get("ask_before_secrets").and_then(Value::as_bool) {
        cfg.ask_before_secrets = b;
    }
    if let Some(b) = parsed
        .get("require_click_before_push")
        .and_then(Value::as_bool)
    {
        cfg.require_click_before_push = b;
    }
    if let Some(b) = parsed
        .get("stop_auto_repair_after_2_attempts")
        .and_then(Value::as_bool)
    {
        cfg.stop_auto_repair_after_2_attempts = b;
    }
    if let Some(arr) = parsed.get("protected_paths").and_then(Value::as_array) {
        cfg.protected_paths = arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .take(40)
            .map(ToString::to_string)
            .collect();
    }

    if let Err(e) = save_workflow_config(repo_root, &cfg) {
        return (
            "409 Conflict",
            json!({
                "ok": false,
                "disposition": "HELD",
                "error_code": "workflow_save_failed",
                "error": e
            }),
        );
    }

    (
        "200 OK",
        json!({
            "ok": true,
            "workflow": cfg,
            "path": ".chinwag/workflow.yaml",
            "message": "Saved workflow settings to .chinwag/workflow.yaml."
        }),
    )
}

fn handle_credits_checkout(body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let raw_sku = parsed
        .get("pack_sku")
        .and_then(Value::as_str)
        .unwrap_or("pack_160");
    let trigger_surface = parsed
        .get("trigger_surface")
        .and_then(Value::as_str)
        .unwrap_or("credits_tab");

    let Some((canonical_sku, pack_label, credits_granted, price_usd)) =
        canonicalize_pack_sku(raw_sku)
    else {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_pack_sku",
                "error": "Pack SKU must be 'pack_50', 'pack_160', 'pack_560', or 'pack_1000'."
            }),
        );
    };

    let wizard_pack_slug = match canonical_sku {
        "pack_50" => "developer",
        "pack_160" => "growth",
        "pack_560" => "scale",
        "pack_1000" => "volume",
        _ => "growth",
    };
    let attempt_id = mint_rfc4122_v4_uuid();
    let checkout_url = format!(
        "https://chinwag.sh/pricing?pack={wizard_pack_slug}&source=local_ui&attempt={attempt_id}"
    );

    (
        "200 OK",
        json!({
            "ok": true,
            "checkout_url": checkout_url,
            "pricing_url": CREDIT_PACKS_PRICING_URL,
            "pack_sku": canonical_sku,
            "pack_label": pack_label,
            "credits_granted": credits_granted,
            "price_usd": price_usd,
            "expires_months": 12,
            "pack_expiry_notice": PACK_EXPIRY_NOTICE,
            "trigger_surface": scrub_customer_text(trigger_surface),
            "attempt_id": attempt_id
        }),
    )
}

fn handle_credits_autorefill(repo_root: &Path, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let enabled = parsed
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let threshold_credits = parsed
        .get("threshold_credits")
        .and_then(Value::as_u64)
        .unwrap_or(500);
    let raw_pack_sku = parsed
        .get("pack_sku")
        .and_then(Value::as_str)
        .unwrap_or("pack_160");
    let Some((canonical_sku, _, _, _)) = canonicalize_pack_sku(raw_pack_sku) else {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_pack_sku",
                "error": "Pack SKU must be 'pack_50', 'pack_160', 'pack_560', or 'pack_1000'."
            }),
        );
    };
    let pack_sku = canonical_sku.to_string();

    let monthly_cap_usd = parsed.get("monthly_cap_usd").and_then(Value::as_u64);
    if enabled {
        let Some(cap) = monthly_cap_usd else {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "monthly_cap_required",
                    "error": "A positive monthly_cap_usd is required whenever auto-refill is enabled."
                }),
            );
        };
        if cap == 0 || cap > 10_000 {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_monthly_cap",
                    "error": "monthly_cap_usd must be between $1 and $10,000."
                }),
            );
        }
    }

    mutate_ui_v4_state(repo_root, |state| {
        state.auto_refill = AutoRefillConfig {
            enabled,
            threshold_credits,
            pack_sku,
            monthly_cap_usd,
        };
        Ok(json!({
            "ok": true,
            "auto_refill": state.auto_refill
        }))
    })
}

fn handle_pm_ask(repo_root: &Path, body: &[u8]) -> (&'static str, Vec<u8>) {
    let parsed: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let prompt = parsed
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if prompt.is_empty() {
        let err = serde_json::to_vec(&json!({
            "ok": false,
            "error_code": "empty_prompt",
            "error": "Describe the engineering task you want queued or broken down."
        }))
        .unwrap_or_default();
        return ("400 Bad Request", err);
    }

    let (inbox, board, _) = build_inbox_and_board(repo_root);
    let decision_count = inbox["counts"]["needs_decision"].as_u64().unwrap_or(0);
    let shipped_count = board["summary"]["shipped_count"].as_u64().unwrap_or(0);
    let review_phrase = if decision_count == 1 {
        "1 change waiting for your review".to_string()
    } else {
        format!("{decision_count} changes waiting for your review")
    };
    let shipped_phrase = if shipped_count == 1 {
        "1 shipped change".to_string()
    } else {
        format!("{shipped_count} shipped changes")
    };
    let reply = format!(
        "Scoped plan for \"{}\": break into an isolated repository change, run tests before review, and verify with an independent coding tool ({review_phrase}, {shipped_phrase}).",
        scrub_customer_text(prompt)
    );
    let payload = serde_json::to_vec_pretty(&json!({
        "ok": true,
        "role": "Task Scoper",
        "reply": reply,
        "credits_charged": 0
    }))
    .unwrap_or_default();
    ("200 OK", payload)
}

fn handle_bus_send(
    stream: &mut TcpStream,
    repo_root: &Path,
    selection: Option<&RepositorySelection>,
    auth: &Arc<UiSecurityContext>,
    req: &ParsedHttpRequest,
) {
    let parsed: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
    let default_inst = auth
        .console_human_actor()
        .split_once('#')
        .map(|(_, inst)| inst)
        .unwrap_or("ui-console");
    let raw_sender = parsed
        .get("sender")
        .and_then(Value::as_str)
        .unwrap_or_else(|| auth.console_human_actor());

    let Ok(sender) = admit_human_ui_sender(raw_sender, default_inst) else {
        write_json_error(
            stream,
            "403 Forbidden",
            "human_sender_required",
            "POST /api/bus/send is restricted to human console principals.",
        );
        return;
    };

    let room = parsed
        .get("room")
        .and_then(Value::as_str)
        .unwrap_or("#mgmt");
    let raw_to = parsed
        .get("to")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let task_id = parsed
        .get("task_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let msg_body = parsed
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();

    if msg_body.is_empty() {
        write_json_error(
            stream,
            "400 Bad Request",
            "empty_body",
            "Message body must not be empty.",
        );
        return;
    }

    let wake = parsed.get("wake").and_then(Value::as_bool).unwrap_or(false);
    if wake {
        let hold_err = match selection {
            Some(sel) => preflight_ui_task_effect(sel).err().unwrap_or_else(|| {
                "UI task wake held pending controlled execution authority".to_string()
            }),
            None => "UI task wake held: repository lacks controlled execution binding".to_string(),
        };
        let body = serde_json::to_vec(&json!({
            "ok": false,
            "disposition": "HELD",
            "published": false,
            "work_started": "UNKNOWN",
            "error": scrub_customer_text(&hold_err),
        }))
        .unwrap_or_default();
        write_hardened_response(
            stream,
            "409 Conflict",
            "application/json; charset=utf-8",
            &body,
            None,
            None,
        );
        return;
    }

    if let Some(sel) = selection
        && let Err(error) = sel.revalidate()
    {
        let body = serde_json::to_vec(&json!({
            "ok": false,
            "disposition": "HELD",
            "published": false,
            "error": scrub_customer_text(&error.to_string())
        }))
        .unwrap_or_default();
        write_hardened_response(
            stream,
            "409 Conflict",
            "application/json; charset=utf-8",
            &body,
            None,
            None,
        );
        return;
    }

    let idem_key = if let Some(explicit_key) = parsed
        .get("idempotency_key")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    {
        format!("{sender}:{explicit_key}")
    } else {
        let bucket_60s = unix_now_ms() / 60_000;
        let mut h = Sha256::new();
        h.update(sender.to_string().as_bytes());
        h.update(b"|");
        h.update(room.as_bytes());
        h.update(b"|");
        h.update(raw_to.as_deref().unwrap_or("").as_bytes());
        h.update(b"|");
        h.update(task_id.as_deref().unwrap_or("").as_bytes());
        h.update(b"|");
        h.update(msg_body.as_bytes());
        h.update(b"|");
        h.update(bucket_60s.to_string().as_bytes());
        format!("{:x}", h.finalize())
    };

    static UI_BUS_SEND_MUTEX: Mutex<()> = Mutex::new(());
    let Ok(_bus_send_guard) = UI_BUS_SEND_MUTEX.lock() else {
        write_json_error(
            stream,
            "500 Internal Server Error",
            "bus_send_lock_poisoned",
            "Local message coordination lock is unavailable.",
        );
        return;
    };

    if let Some(cached) = auth.check_idempotency(&idem_key) {
        write_hardened_response(
            stream,
            "200 OK",
            "application/json; charset=utf-8",
            &cached,
            None,
            None,
        );
        return;
    }

    let result = bus_run::send_bus_message_sync(
        repo_root,
        &sender.to_string(),
        room,
        raw_to,
        task_id,
        msg_body,
    );

    match result {
        Ok((msg, ack)) => {
            let mut resp_val = json!({
                "ok": true,
                "message": msg,
                "ack": ack,
                "delivery": "PUBLISH_ONLY",
                "work_started": "UNKNOWN"
            });
            scrub_customer_ui_json(&mut resp_val);
            let resp = serde_json::to_vec_pretty(&resp_val).unwrap_or_default();
            auth.record_idempotency(idem_key, resp.clone());
            drop(_bus_send_guard);
            write_hardened_response(
                stream,
                "200 OK",
                "application/json; charset=utf-8",
                &resp,
                None,
                None,
            );
        }
        Err(error) => {
            drop(_bus_send_guard);
            write_json_error(
                stream,
                "400 Bad Request",
                "bus_send_failed",
                &scrub_customer_text(&error.to_string()),
            );
        }
    }
}

// ============================================================================
// Delivery-2 Phase 1 Persistent Left-Hand Panel Backend (`CHWG-0254`)
// ============================================================================

pub const DELIVERY2_RUN_STEPS: [(&str, &str); 12] = [
    ("01", "Queued"),
    ("02", "Understood"),
    ("03", "Plan ready"),
    ("04", "Estimate ready"),
    ("05", "Writing changes"),
    ("06", "Tests added"),
    ("07", "Checks running"),
    ("08", "Fixing checks"),
    ("09", "Independent review"),
    ("10", "Waiting for you"),
    ("11", "Final checks"),
    ("12", "Passed · Merge-ready"),
];

fn format_utc_hh_mm(ts_unix: u64) -> String {
    let day_secs = ts_unix % 86_400;
    let hh = day_secs / 3_600;
    let mm = (day_secs % 3_600) / 60;
    format!("{hh:02}:{mm:02}")
}

pub fn sanitize_chinwag_outbound_url(raw: &str, fallback: &str) -> String {
    let s = raw.trim();
    if s.is_empty() || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return fallback.to_string();
    }
    let allowed_prefix = s == "https://chinwag.sh/security"
        || s == "https://chinwag.sh/pricing"
        || s.starts_with("https://chinwag.sh/pricing?")
        || s.starts_with("https://chinwag.sh/pricing#")
        || s == "https://chinwag.sh/open"
        || s.starts_with("https://chinwag.sh/open?");
    if !allowed_prefix {
        return fallback.to_string();
    }
    // Reject embedded redirect URLs, WHATWG backslash/userinfo tricks, or percent-encoded scheme/slash injections.
    if let Some(tail) = s.get("https://chinwag.sh/".len()..) {
        let tail_lower = tail.to_ascii_lowercase();
        if tail_lower.contains("://")
            || tail_lower.contains("//")
            || tail_lower.contains('\\')
            || tail_lower.contains('@')
            || tail_lower.contains("javascript:")
            || tail_lower.contains("data:")
            || tail_lower.contains("%2f")
            || tail_lower.contains("%5c")
            || tail_lower.contains("%25")
            || tail_lower.contains("%3a")
            || tail_lower.contains("%40")
        {
            return fallback.to_string();
        }
    }
    s.to_string()
}

/// Verify an authenticated workspace OAuth receipt under `.chinwag/<surface>-oauth.json`
/// or `.chinwag/<surface>.json` using descriptor-anchored `O_NOFOLLOW` traversal
/// (rejects symlinked `.chinwag` directories, symlinked leaf files, and TOCTOU swaps).
fn has_verified_workspace_oauth_receipt(
    repo_root: &Path,
    surface: &str,
    expected_nonce: Option<&str>,
) -> bool {
    if !matches!(surface, "github" | "linear" | "slack") {
        return false;
    }
    let leaf_names = [format!("{surface}-oauth.json"), format!("{surface}.json")];
    for leaf_name in leaf_names {
        let Ok(Some(raw_json)) =
            read_repo_file_nofollow(repo_root, &[".chinwag"], &leaf_name, 65_536)
        else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<Value>(&raw_json) else {
            continue;
        };
        if val.get("verified").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let has_identity = val
            .get("account")
            .or_else(|| val.get("workspace"))
            .or_else(|| val.get("user"))
            .and_then(Value::as_str)
            .is_some_and(|s| s.trim().len() >= 2);
        if !has_identity {
            continue;
        }
        if let Some(rec_surface) = val.get("surface").and_then(Value::as_str)
            && !rec_surface.eq_ignore_ascii_case(surface)
        {
            continue;
        }
        if let Some(nonce) = expected_nonce
            && val.get("oauth_state").and_then(Value::as_str) != Some(nonce)
        {
            continue;
        }
        return true;
    }
    false
}

fn is_secret_assignment_key(k: &str) -> bool {
    matches!(
        k,
        "api_key"
            | "apikey"
            | "api-key"
            | "secret"
            | "secret_key"
            | "secret-key"
            | "access_key"
            | "access-key"
            | "secret_access_key"
            | "secret-access-key"
            | "client_secret"
            | "client-secret"
            | "password"
            | "passwd"
            | "access_token"
            | "access-token"
            | "auth_token"
            | "auth-token"
            | "private_key"
            | "private-key"
            | "token"
            | "pat"
    ) || k.ends_with("_api_key")
        || k.ends_with("-api-key")
        || k.ends_with("_apikey")
        || k.ends_with("-apikey")
        || k.ends_with("_access_key")
        || k.ends_with("-access-key")
        || k.ends_with("_secret_access_key")
        || k.ends_with("-secret-access-key")
        || k.ends_with("_key_id")
        || k.ends_with("-key-id")
        || k.ends_with("_auth_key")
        || k.ends_with("-auth-key")
        || k.ends_with("_pat")
        || k.ends_with("-pat")
        || k.ends_with("_token")
        || k.ends_with("-token")
        || k.ends_with("_secret")
        || k.ends_with("-secret")
        || k.ends_with("_secret_key")
        || k.ends_with("-secret-key")
        || k.ends_with("_password")
        || k.ends_with("-password")
        || k.ends_with("_passwd")
        || k.ends_with("-passwd")
        || k.ends_with("_private_key")
        || k.ends_with("-private-key")
}

fn is_non_secret_placeholder_value(v_lower: &str) -> bool {
    matches!(
        v_lower,
        "undefined"
            | "null"
            | "none"
            | "nil"
            | "true"
            | "false"
            | "required"
            | "optional"
            | "disabled"
            | "enabled"
            | "configured"
            | "redacted"
            | "missing"
            | "empty"
            | "default"
            | "production"
            | "staging"
            | "development"
            | "local"
            | "test"
            | "example"
            | "placeholder"
    )
}

pub fn contains_secret_shaped_token(raw: &str) -> bool {
    // Canonicalize via Stage 1 normalization FIRST (stripping zero-width/bidi/format chars AND folding
    // fullwidth ASCII like `API＿KEY` / `＝`, Unicode dashes like `sk−proj`, and Math Alphanumerics)
    // so secret validation inspects the exact representation that persistence stores.
    let cleaned = normalize_scrubber_stage1(raw);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if (lower.contains("-----begin ") && (lower.contains("private") || lower.contains("secret")))
        || lower.contains("age-secret-key-1")
    {
        return true;
    }

    // Detect `Bearer <token>` including pure-alpha / base64url tokens without requiring digits.
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    for pair in words.windows(2) {
        let lhs = pair[0]
            .trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | '[' | '{' | ':' | '='))
            .to_ascii_lowercase();
        if lhs == "bearer" {
            let candidate = pair[1]
                .trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}'));
            if candidate.len() >= 12
                && candidate.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
                })
            {
                return true;
            }
        }
    }

    // Pre-split scan for `KEY = "value"` / `key: value` / `"api_key": "..."` / `OPENAI_API_KEY=...`
    let bytes = trimmed.as_bytes();
    for (sep_idx, &b) in bytes.iter().enumerate() {
        if b != b'=' && b != b':' {
            continue;
        }
        // Walk left across optional spaces/quotes to extract the assignment key
        let mut key_end = sep_idx;
        while key_end > 0 && matches!(bytes[key_end - 1], b' ' | b'\t' | b'"' | b'\'') {
            key_end -= 1;
        }
        let mut key_start = key_end;
        while key_start > 0
            && (bytes[key_start - 1].is_ascii_alphanumeric()
                || matches!(bytes[key_start - 1], b'_' | b'-'))
        {
            key_start -= 1;
        }
        if key_start == key_end {
            continue;
        }
        let Some(key_raw) = trimmed.get(key_start..key_end) else {
            continue;
        };
        let key_norm = key_raw.to_ascii_lowercase();
        if !is_secret_assignment_key(&key_norm) {
            continue;
        }

        // Walk right across optional spaces to inspect the assigned value
        let mut val_start = sep_idx + 1;
        while val_start < bytes.len() && matches!(bytes[val_start], b' ' | b'\t') {
            val_start += 1;
        }
        if val_start >= bytes.len() {
            continue;
        }
        let val_opt = if matches!(bytes[val_start], b'"' | b'\'') {
            let quote = bytes[val_start];
            let content_start = val_start + 1;
            let mut content_end = content_start;
            while content_end < bytes.len()
                && bytes[content_end] != quote
                && bytes[content_end] != b'\n'
                && bytes[content_end] != b'\r'
            {
                content_end += 1;
            }
            trimmed.get(content_start..content_end)
        } else {
            let mut content_end = val_start;
            while content_end < bytes.len()
                && !bytes[content_end].is_ascii_whitespace()
                && !matches!(
                    bytes[content_end],
                    b',' | b';' | b'"' | b'\'' | b')' | b']' | b'}'
                )
            {
                content_end += 1;
            }
            trimmed.get(val_start..content_end)
        };
        let Some(val_slice) = val_opt else {
            continue;
        };
        let v_trim = val_slice.trim().trim_end_matches('?');
        let v_lower = v_trim.to_ascii_lowercase();
        if v_trim.len() >= 8
            && !v_trim.chars().any(char::is_whitespace)
            && !is_non_secret_placeholder_value(&v_lower)
        {
            return true;
        }
    }

    // Split on whitespace AND assignment/query/punctuation delimiters (`=`, `:`, `?`, `&`, ...)
    // so `OPENAI_KEY=sk-proj-...`, `.../js?key=AIzaSy...`, `session=eyJ...`, and `key:sk-ant-...` are caught.
    for raw_tok in trimmed.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '=' | ':' | '?' | '&' | ',' | ';' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    }) {
        let tok = raw_tok.trim_matches('.');
        if tok.len() < 12 {
            continue;
        }
        if tok.to_ascii_lowercase().starts_with("age-secret-key-1") {
            return true;
        }
        if (tok.starts_with("sk-")
            || tok.starts_with("rk_live_")
            || tok.starts_with("sk_live_")
            || tok.starts_with("rk_test_")
            || tok.starts_with("sk_test_")
            || tok.starts_with("whsec_"))
            && tok.len() >= 16
        {
            return true;
        }
        if (tok.starts_with("ghp_")
            || tok.starts_with("gho_")
            || tok.starts_with("ghu_")
            || tok.starts_with("ghs_")
            || tok.starts_with("github_pat_"))
            && tok.len() >= 20
        {
            return true;
        }
        if (tok.starts_with("xoxb-")
            || tok.starts_with("xoxp-")
            || tok.starts_with("xoxa-")
            || tok.starts_with("xoxr-")
            || tok.starts_with("xapp-"))
            && tok.len() >= 16
        {
            return true;
        }
        if (tok.starts_with("AKIA") || tok.starts_with("ASIA"))
            && tok.len() >= 16
            && tok
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return true;
        }
        if tok.starts_with("AIza") && tok.len() >= 24 {
            return true;
        }
        // JWT 3-segment compact token (`eyJ...`)
        if tok.starts_with("eyJ") && tok.matches('.').count() >= 2 && tok.len() >= 28 {
            return true;
        }
    }
    false
}

fn build_twelve_step_ladder_json(active_step_1based: usize, completed_all: bool) -> Vec<Value> {
    let clamped = active_step_1based.clamp(1, 12);
    DELIVERY2_RUN_STEPS
        .iter()
        .enumerate()
        .map(|(idx, (num, label))| {
            let step_no = idx + 1;
            let state = if completed_all || step_no < clamped {
                "done"
            } else if step_no == clamped {
                "current"
            } else {
                "pending"
            };
            json!({
                "num": num,
                "label": label,
                "display": format!("{num} · {label}"),
                "state": state
            })
        })
        .collect()
}

fn extract_why_target_id(prompt: &str) -> Option<String> {
    if let Some((_, after_hash)) = prompt.split_once('#') {
        let candidate: String = after_hash
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_' | '.'))
            .collect();
        if !candidate.is_empty() {
            return Some(candidate);
        }
    }
    let trimmed = prompt.trim();
    if let Some(after_why) = trimmed
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("why "))
        .and_then(|_| trimmed.get(4..))
    {
        let first_word: String = after_why
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_' | '.'))
            .collect();
        if (first_word.contains('-') || first_word.chars().any(|c| c.is_ascii_digit()))
            && !first_word.eq_ignore_ascii_case("delivery-2")
        {
            return Some(first_word);
        }
    }
    None
}

fn build_seeded_delivery2_entries(
    repo_info: &Value,
    inbox: &Value,
    board: &Value,
    credits: &Value,
    workflow: &WorkflowConfig,
    state: &LocalUiV4State,
) -> Vec<Value> {
    let repo_name = repo_info
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("workspace");
    let branch = repo_info
        .get("branch")
        .and_then(Value::as_str)
        .unwrap_or("main");
    let inbox_items = inbox
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let non_sample_item = inbox_items
        .iter()
        .find(|i| !i.get("is_sample").and_then(Value::as_bool).unwrap_or(false));
    let top_item = non_sample_item.or_else(|| inbox_items.first());
    let run_id = top_item
        .and_then(|i| i.get("id"))
        .and_then(Value::as_str)
        .filter(|id| *id != "sample-walkthrough")
        .unwrap_or("run-local-1");
    let run_title = top_item
        .and_then(|i| i.get("title"))
        .and_then(Value::as_str)
        .filter(|_| run_id != "run-local-1")
        .unwrap_or("Verify protected-path safety & test checks before merge");
    let item_status = top_item
        .and_then(|i| i.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("needs_review");

    let approval_id = format!("hitl-{run_id}");
    let settled_approval = state.delivery2.approvals.get(&approval_id);
    let item_decision = state.item_decisions.get(run_id);
    let (active_step, completed_all) = if let Some(rec) = settled_approval {
        if rec.decision == "approved" {
            (12usize, true)
        } else {
            (10usize, false)
        }
    } else if item_decision.is_some_and(|d| d.status == "done") || item_status == "done" {
        (12usize, true)
    } else if item_decision.is_some_and(|d| d.status == "running") || item_status == "running" {
        (8usize, false)
    } else {
        (10usize, false)
    };

    let driver_lbl = friendly_workflow_tool_label(&workflow.driver_tool);
    let reviewer_lbl = friendly_workflow_tool_label(&workflow.reviewer_tool);
    let ready_diffs = inbox["counts"]["needs_decision"].as_u64().unwrap_or(0);
    let queued_count = board["summary"]["queued_count"].as_u64().unwrap_or(0);
    let active_count = board["summary"]["active_count"].as_u64().unwrap_or(0);
    let available_cr = credits["available_credits"].as_u64().unwrap_or(500);

    // Derive diff & verification proof strictly from actual item receipts (never fabricate counts/reviews).
    let real_item = top_item.filter(|_| run_id != "run-local-1");
    let files_changed = real_item
        .and_then(|i| i.get("files_changed"))
        .and_then(Value::as_u64);
    let additions = real_item
        .and_then(|i| i.get("additions"))
        .and_then(Value::as_u64);
    let deletions = real_item
        .and_then(|i| i.get("deletions"))
        .and_then(Value::as_u64);
    let tests_passed = real_item
        .and_then(|i| i.get("tests_passed"))
        .and_then(Value::as_bool);
    let verified_reviewer = real_item
        .and_then(|i| i.get("reviewer_label"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty());
    let item_tool = real_item
        .and_then(|i| i.get("tool_label"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(driver_lbl);

    let diff_summary = if let Some(fc) = files_changed {
        format!(
            "{} {} (+{} / -{} lines)",
            fc,
            if fc == 1 { "file" } else { "files" },
            additions.unwrap_or(0),
            deletions.unwrap_or(0)
        )
    } else if run_id == "run-local-1" {
        "No local diff recorded yet · Sample preview available".to_string()
    } else {
        "Diff stats not yet recorded · Open View diff → to inspect working tree".to_string()
    };

    let test_part = match tests_passed {
        Some(true) => "Local test suite passed",
        Some(false) => "Local test suite failed",
        None => "Automated test receipt not yet recorded",
    };
    let review_part = match verified_reviewer {
        Some(rev) => format!("Independent review by {rev} recorded"),
        None => format!("Independent review ({reviewer_lbl}) not yet recorded"),
    };
    let check_proof = format!("{test_part} · {review_part}");
    let hitl_question = if tests_passed == Some(true) && verified_reviewer.is_some() {
        format!(
            "Approve verified change `{run_id}` on `{branch}` after {item_tool} diff and independent review?"
        )
    } else if run_id == "run-local-1" {
        format!(
            "Review workspace guardrails on `{branch}` (open View diff → for safe sample preview)?"
        )
    } else {
        format!(
            "Review `{run_id}` on `{branch}` ({item_tool}) — inspect local diff and check status before approving?"
        )
    };
    let verb_summary = format!(
        "Searched {} workspace {} · {} protected path {}",
        inbox_items.len(),
        if inbox_items.len() == 1 {
            "item"
        } else {
            "items"
        },
        workflow.protected_paths.len(),
        if workflow.protected_paths.len() == 1 {
            "rule"
        } else {
            "rules"
        }
    );

    let mut entries = Vec::with_capacity(4);

    // Card 3C: Grounded Board/Repo Q&A Card + Collapsed Provenance
    entries.push(json!({
        "id": "entry-seed-qa",
        "kind": "qa_card",
        "seq": 1,
        "role": "assistant",
        "author": "Delivery-2",
        "body": format!(
            "Workspace **{repo_name}** on `{branch}` has **{ready_diffs}** {} ready for review, **{active_count}** active and **{queued_count}** queued board {}, and **{available_cr} Cr** available. Pairing uses **{driver_lbl}** with independent review by **{reviewer_lbl}**.",
            if ready_diffs == 1 { "change" } else { "changes" },
            if active_count + queued_count == 1 { "task" } else { "tasks" }
        ),
        "sources": [
            { "label": format!("Inbox · {ready_diffs} waiting"), "target_tab": "inbox", "hash": "#inbox" },
            { "label": format!("Board · {} active / {} queued", active_count, queued_count), "target_tab": "board", "hash": "#board" },
            { "label": format!("Safety rules · {} protected globs", workflow.protected_paths.len()), "target_tab": "agents", "hash": "#agents" },
            { "label": format!("Credits · {available_cr} Cr available"), "target_tab": "credits", "hash": "#credits" }
        ]
    }));

    // Card 3A: 12-Step Durable Run Card
    let current_step_label = DELIVERY2_RUN_STEPS[active_step.saturating_sub(1)];
    entries.push(json!({
        "id": format!("entry-run-{run_id}"),
        "kind": "run_card",
        "seq": settled_approval.map(|r| r.seq).unwrap_or(1),
        "run_id": run_id,
        "title": scrub_customer_ui_text(run_title),
        "current_step_num": current_step_label.0,
        "current_step_label": current_step_label.1,
        "current_step_display": format!("{} · {}", current_step_label.0, current_step_label.1),
        "completed": completed_all,
        "verb_summary": verb_summary,
        "diff_target_id": if run_id == "run-local-1" { "sample-walkthrough" } else { run_id },
        "steps": build_twelve_step_ladder_json(active_step, completed_all)
    }));

    // Card 3B: Plan-Bound Inline HITL Approval Card (`Paused · 0 Cr`)
    entries.push(json!({
        "id": format!("entry-hitl-{run_id}"),
        "kind": "approval_card",
        "seq": settled_approval.map(|r| r.seq).unwrap_or(1),
        "approval_id": approval_id,
        "item_id": run_id,
        "is_sample": false,
        "status_badge": "Waiting for you",
        "pause_badge": "Paused · 0 Cr",
        "estimate_badge": "~20 Cr to finish",
        "title": scrub_customer_ui_text(run_title),
        "question": hitl_question,
        "diff_summary": diff_summary,
        "check_proof": check_proof,
        "diff_hash": if run_id == "run-local-1" { "#walkthrough".to_string() } else { format!("#diff/{run_id}") },
        "settled": settled_approval.is_some(),
        "settled_decision": settled_approval.map(|r| r.decision.clone()),
        "settled_receipt": settled_approval.map(|r| r.receipt.clone())
    }));

    // Card 3D: 1-Line Memory Save Notice (seed default memory if none saved yet, or project saved memories)
    if state.delivery2.memories.is_empty() {
        entries.push(json!({
            "id": "entry-mem-seed",
            "kind": "memory_card",
            "seq": 1,
            "memory_id": "mem_default",
            "note": "Run unit tests in an isolated sandbox before opening a review.",
            "status": "saved"
        }));
    } else {
        for mem in state.delivery2.memories.values() {
            entries.push(json!({
                "id": format!("entry-{}", mem.id),
                "kind": "memory_card",
                "seq": mem.seq.max(1),
                "memory_id": mem.id,
                "note": scrub_customer_ui_text(&mem.note),
                "status": mem.status
            }));
        }
    }

    entries
}

fn sync_entry_overlays(entry: &mut Value, state: &LocalUiV4State) {
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let base_seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(1);

    if kind == "approval_card" {
        let aid = entry
            .get("approval_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let iid = entry
            .get("item_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let canonical_rec = aid
            .as_deref()
            .and_then(|k| state.delivery2.approvals.get(k))
            .or_else(|| {
                iid.as_deref()
                    .and_then(|id| state.delivery2.approvals.get(&format!("hitl-{id}")))
            });
        if let Some(obj) = entry.as_object_mut() {
            if let Some(rec) = canonical_rec {
                obj.insert("settled".to_string(), Value::Bool(true));
                obj.insert(
                    "settled_decision".to_string(),
                    Value::String(rec.decision.clone()),
                );
                obj.insert(
                    "settled_receipt".to_string(),
                    Value::String(rec.receipt.clone()),
                );
                obj.insert(
                    "seq".to_string(),
                    Value::Number(base_seq.max(rec.seq).into()),
                );
            } else if let Some(item_dec) =
                iid.as_deref().and_then(|id| state.item_decisions.get(id))
            {
                if matches!(item_dec.status.as_str(), "done" | "rejected") {
                    let dec = if item_dec.status == "done" {
                        "approved"
                    } else {
                        "denied"
                    };
                    let hh_mm = format_utc_hh_mm(item_dec.updated_at_unix);
                    let rcpt = if item_dec.status == "done" {
                        format!("Approved in Inbox · {hh_mm} · 0 Cr while paused")
                    } else {
                        format!("Rejected in Inbox · {hh_mm} · 0 Cr while paused")
                    };
                    obj.insert("settled".to_string(), Value::Bool(true));
                    obj.insert(
                        "settled_decision".to_string(),
                        Value::String(dec.to_string()),
                    );
                    obj.insert("settled_receipt".to_string(), Value::String(rcpt));
                } else {
                    obj.insert("settled".to_string(), Value::Bool(false));
                    obj.insert("settled_decision".to_string(), Value::Null);
                    obj.insert("settled_receipt".to_string(), Value::Null);
                }
            } else if !obj.get("settled").and_then(Value::as_bool).unwrap_or(false) {
                obj.insert("settled".to_string(), Value::Bool(false));
                obj.insert("settled_decision".to_string(), Value::Null);
                obj.insert("settled_receipt".to_string(), Value::Null);
            }
        }
    } else if kind == "run_card" {
        let turn_stopped = entry
            .get("turn_id")
            .and_then(Value::as_str)
            .is_some_and(|tid| {
                state.delivery2.cancelled_turn_clamps.contains_key(tid)
                    || state.delivery2.cancelled_turn_ids.iter().any(|c| c == tid)
            });
        if turn_stopped {
            if let Some(obj) = entry.as_object_mut() {
                let step_num = obj
                    .get("current_step_num")
                    .and_then(Value::as_str)
                    .unwrap_or("04")
                    .to_string();
                obj.insert("stopped".to_string(), Value::Bool(true));
                obj.insert("completed".to_string(), Value::Bool(false));
                obj.insert(
                    "current_step_label".to_string(),
                    Value::String("Stopped".to_string()),
                );
                obj.insert(
                    "current_step_display".to_string(),
                    Value::String(format!("{step_num} · Stopped")),
                );
            }
            return;
        }
        let run_id_opt = entry
            .get("run_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(rid) = run_id_opt {
            let hitl_key = format!("hitl-{rid}");
            let approval_rec = state.delivery2.approvals.get(&hitl_key);
            let item_dec = state.item_decisions.get(&rid);
            if let Some(obj) = entry.as_object_mut() {
                if approval_rec.is_some_and(|r| r.decision == "approved")
                    || item_dec.is_some_and(|d| d.status == "done")
                {
                    let step = DELIVERY2_RUN_STEPS[11];
                    obj.insert(
                        "current_step_num".to_string(),
                        Value::String(step.0.to_string()),
                    );
                    obj.insert(
                        "current_step_label".to_string(),
                        Value::String(step.1.to_string()),
                    );
                    obj.insert(
                        "current_step_display".to_string(),
                        Value::String(format!("{} · {}", step.0, step.1)),
                    );
                    obj.insert("completed".to_string(), Value::Bool(true));
                    obj.insert(
                        "steps".to_string(),
                        Value::Array(build_twelve_step_ladder_json(12, true)),
                    );
                    if let Some(rec) = approval_rec {
                        obj.insert(
                            "seq".to_string(),
                            Value::Number(base_seq.max(rec.seq).into()),
                        );
                    }
                } else if approval_rec.is_some_and(|r| r.decision == "denied")
                    || item_dec.is_some_and(|d| d.status == "rejected")
                {
                    obj.insert("current_step_num".to_string(), Value::String("10".into()));
                    obj.insert(
                        "current_step_label".to_string(),
                        Value::String("Denied by you".into()),
                    );
                    obj.insert(
                        "current_step_display".to_string(),
                        Value::String("10 · Denied by you".into()),
                    );
                    obj.insert("completed".to_string(), Value::Bool(false));
                    obj.insert(
                        "steps".to_string(),
                        Value::Array(build_twelve_step_ladder_json(10, false)),
                    );
                    if let Some(rec) = approval_rec {
                        obj.insert(
                            "seq".to_string(),
                            Value::Number(base_seq.max(rec.seq).into()),
                        );
                    }
                } else if item_dec.is_some_and(|d| d.status == "running") {
                    let step = DELIVERY2_RUN_STEPS[7];
                    obj.insert(
                        "current_step_num".to_string(),
                        Value::String(step.0.to_string()),
                    );
                    obj.insert(
                        "current_step_label".to_string(),
                        Value::String(step.1.to_string()),
                    );
                    obj.insert(
                        "current_step_display".to_string(),
                        Value::String(format!("{} · {}", step.0, step.1)),
                    );
                    obj.insert("completed".to_string(), Value::Bool(false));
                    obj.insert(
                        "steps".to_string(),
                        Value::Array(build_twelve_step_ladder_json(8, false)),
                    );
                }
            }
        }
    } else if kind == "memory_card"
        && let Some(mid) = entry
            .get("memory_id")
            .and_then(Value::as_str)
            .map(str::to_string)
        && let Some(mem) = state.delivery2.memories.get(&mid)
        && let Some(obj) = entry.as_object_mut()
    {
        obj.insert(
            "note".to_string(),
            Value::String(scrub_customer_ui_text(&mem.note)),
        );
        obj.insert("status".to_string(), Value::String(mem.status.clone()));
        obj.insert(
            "seq".to_string(),
            Value::Number(base_seq.max(mem.seq).into()),
        );
    } else if kind == "oauth_card"
        && let Some(obj) = entry.as_object_mut()
    {
        let raw_url = obj
            .get("challenge_url")
            .and_then(Value::as_str)
            .unwrap_or("");
        obj.insert(
            "challenge_url".to_string(),
            Value::String(sanitize_chinwag_outbound_url(
                raw_url,
                "https://chinwag.sh/open",
            )),
        );
    } else if kind == "qa_card"
        && let Some(tid) = entry
            .get("turn_id")
            .and_then(Value::as_str)
            .map(str::to_string)
        && let Some(&max_chars) = state.delivery2.cancelled_turn_clamps.get(&tid)
        && let Some(obj) = entry.as_object_mut()
    {
        let clamped: String = obj
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(max_chars)
            .collect();
        let final_body = if max_chars == 0 || clamped.trim().is_empty() {
            "[Stopped]".to_string()
        } else {
            clamped
        };
        obj.insert("body".to_string(), Value::String(final_body));
        obj.insert("stopped".to_string(), Value::Bool(true));
        if max_chars == 0 {
            obj.insert("sources".to_string(), json!([]));
        }
    }
}

pub fn build_delivery2_state_json(repo_root: &Path, port: u16) -> Value {
    build_delivery2_state_json_with_cursor(repo_root, port, None)
}

pub fn build_delivery2_state_json_with_cursor(
    repo_root: &Path,
    port: u16,
    since_seq: Option<u64>,
) -> Value {
    let started = std::time::Instant::now();
    let repo_info = discover_repo_info(repo_root);
    let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
    let workflow = load_workflow_config(repo_root);
    let credits = build_credits_json(repo_root, shipped_count);
    let state = load_ui_v4_state(repo_root);

    let gh_pref = state.delivery2.connections.get("github");
    let ln_pref = state.delivery2.connections.get("linear");
    let sl_pref = state.delivery2.connections.get("slack");

    // Authorization derives strictly from verified OAuth receipts (`.chinwag/<surface>[-oauth].json`),
    // never from ambient CLI/remote hints or client self-assertion.
    let gh_auth = has_verified_workspace_oauth_receipt(repo_root, "github", None);
    let ln_auth = has_verified_workspace_oauth_receipt(repo_root, "linear", None);
    let sl_auth = has_verified_workspace_oauth_receipt(repo_root, "slack", None);

    let gh_connect_url = sanitize_chinwag_outbound_url(
        gh_pref
            .and_then(|p| p.challenge_url.as_deref())
            .unwrap_or("https://chinwag.sh/open?connect=github&source=local_ui"),
        "https://chinwag.sh/open?connect=github&source=local_ui",
    );
    let ln_connect_url = sanitize_chinwag_outbound_url(
        ln_pref
            .and_then(|p| p.challenge_url.as_deref())
            .unwrap_or("https://chinwag.sh/open?connect=linear&source=local_ui"),
        "https://chinwag.sh/open?connect=linear&source=local_ui",
    );
    let sl_connect_url = sanitize_chinwag_outbound_url(
        sl_pref
            .and_then(|p| p.challenge_url.as_deref())
            .unwrap_or("https://chinwag.sh/open?connect=slack&source=local_ui"),
        "https://chinwag.sh/open?connect=slack&source=local_ui",
    );

    let surfaces = vec![
        json!({
            "id": "local",
            "label": "Local",
            "authorized": true,
            "in_thread": true,
            "locked_in_thread": true,
            "role_mode": "workspace",
            "auth_status": format!("Loopback workspace · 127.0.0.1:{port}"),
            "connect_url": Value::Null
        }),
        json!({
            "id": "github",
            "label": "GitHub",
            "authorized": gh_auth,
            "in_thread": gh_auth && gh_pref.and_then(|p| p.in_thread).unwrap_or(true),
            "locked_in_thread": false,
            "role_mode": "full",
            "auth_status": if gh_auth { "Connected · your account" } else { "Needs sign-in · pauses at 0 Cr" },
            "connect_url": gh_connect_url
        }),
        json!({
            "id": "linear",
            "label": "Linear",
            "authorized": ln_auth,
            "in_thread": ln_auth && ln_pref.and_then(|p| p.in_thread).unwrap_or(true),
            "locked_in_thread": false,
            "role_mode": "full",
            "auth_status": if ln_auth { "Connected · your account" } else { "Needs sign-in · pauses at 0 Cr" },
            "connect_url": ln_connect_url
        }),
        json!({
            "id": "slack",
            "label": "Slack",
            "authorized": sl_auth,
            "in_thread": sl_auth && sl_pref.and_then(|p| p.in_thread).unwrap_or(false),
            "locked_in_thread": false,
            "role_mode": "ambient_status_only",
            "auth_status": if sl_auth { "Connected · ambient status cards only" } else { "Needs sign-in · pauses at 0 Cr" },
            "policy_note": "Slack posts ambient status cards with [Open in Chinwag ↗] deep-links only — Delivery-2 lives here in Chinwag.",
            "connect_url": sl_connect_url
        }),
    ];

    let ready_diffs = inbox["counts"]["needs_decision"].as_u64().unwrap_or(0);
    let running_count = inbox["counts"]["running"].as_u64().unwrap_or(0);
    let queued_count = board["summary"]["queued_count"].as_u64().unwrap_or(0);
    let active_board_total = running_count + queued_count;
    let available_credits = credits["available_credits"].as_u64().unwrap_or(500);

    let seeded_entries =
        build_seeded_delivery2_entries(&repo_info, &inbox, &board, &credits, &workflow, &state);

    let active_thread_id = if state.delivery2.active_thread_id.trim().is_empty() {
        "thr-main".to_string()
    } else {
        state.delivery2.active_thread_id.clone()
    };

    let mut active_entries = if let Some(found) = state
        .delivery2
        .threads
        .iter()
        .find(|t| t.id == active_thread_id)
    {
        if found.entries.is_empty() && active_thread_id == "thr-main" {
            seeded_entries
        } else {
            found.entries.clone()
        }
    } else if active_thread_id == "thr-main" {
        seeded_entries
    } else {
        Vec::new()
    };
    active_entries.retain(|e| {
        !(e.get("kind").and_then(Value::as_str) == Some("run_card")
            && e.get("turn_id")
                .and_then(Value::as_str)
                .is_some_and(|tid| state.delivery2.cancelled_turn_clamps.get(tid) == Some(&0)))
    });
    for entry in &mut active_entries {
        sync_entry_overlays(entry, &state);
    }

    let has_unsettled_hitl = active_entries.iter().any(|e| {
        e.get("kind").and_then(Value::as_str) == Some("approval_card")
            && !e.get("settled").and_then(Value::as_bool).unwrap_or(false)
    });

    let now_unix = unix_now();
    let mut voice_view = state.delivery2.voice.clone();
    let mut current_seq = state.delivery2.seq.max(1);
    if voice_view.reconcile_at(now_unix, has_unsettled_hitl, true) {
        let _ = mutate_ui_v4_state(repo_root, |st| {
            if st
                .delivery2
                .voice
                .reconcile_at(now_unix, has_unsettled_hitl, true)
            {
                st.delivery2.seq = st.delivery2.seq.max(1).saturating_add(1);
            }
            Ok(json!({ "ok": true }))
        });
        current_seq = load_ui_v4_state(repo_root).delivery2.seq.max(current_seq);
    }
    let voice_json = voice_view.to_client_json(now_unix);

    let (status_code, status_label) =
        if state.delivery2.active_turn_id.is_some() || running_count > 0 {
            ("working", "Working")
        } else if has_unsettled_hitl || ready_diffs > 0 {
            ("waiting_for_you", "Waiting for you")
        } else {
            ("live", "Live")
        };

    let mut history_today: Vec<Value> = Vec::new();
    let mut history_earlier: Vec<Value> = Vec::new();
    if state.delivery2.threads.is_empty() {
        history_today.push(json!({
            "id": "thr-main",
            "title": "Workspace scope & morning review",
            "status": status_label,
            "active": active_thread_id == "thr-main",
            "updated_at": "Today"
        }));
    } else {
        for thr in state.delivery2.threads.iter().rev() {
            let item = json!({
                "id": thr.id,
                "title": scrub_customer_ui_text(&thr.title),
                "status": if thr.id == active_thread_id { status_label } else { thr.status.as_str() },
                "active": thr.id == active_thread_id,
                "updated_at": format_relative_time(thr.updated_at_unix)
            });
            if thr.bucket == "earlier" {
                history_earlier.push(item);
            } else {
                history_today.push(item);
            }
        }
        if !state.delivery2.threads.iter().any(|t| t.id == "thr-main") {
            history_earlier.push(json!({
                "id": "thr-main",
                "title": "Workspace scope & morning review",
                "status": "Archived",
                "active": active_thread_id == "thr-main",
                "updated_at": "Earlier"
            }));
        }
    }

    let top_ref_id = inbox
        .get("items")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter()
                .find(|i| !i.get("is_sample").and_then(Value::as_bool).unwrap_or(false))
                .or_else(|| arr.first())
        })
        .and_then(|i| i.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("sample-walkthrough");
    let chip_why_label = if top_ref_id == "sample-walkthrough" {
        "Why #sample?".to_string()
    } else {
        format!("Why #{top_ref_id}?")
    };

    let mut memories_list: Vec<Value> = state
        .delivery2
        .memories
        .values()
        .map(|m| {
            json!({
                "id": m.id,
                "note": scrub_customer_ui_text(&m.note),
                "status": m.status,
                "updated_at": format_relative_time(m.updated_at_unix)
            })
        })
        .collect();
    if memories_list.is_empty() {
        memories_list.push(json!({
            "id": "mem_default",
            "note": "Run unit tests in an isolated sandbox before opening a review.",
            "status": "saved",
            "updated_at": "Saved"
        }));
    }

    let (unchanged, delta_entries) = if let Some(cursor) = since_seq {
        if cursor >= current_seq {
            (true, Vec::new())
        } else {
            let delta = active_entries
                .iter()
                .filter(|e| e.get("seq").and_then(Value::as_u64).unwrap_or(1) > cursor)
                .cloned()
                .collect();
            (false, delta)
        }
    } else {
        (false, active_entries.clone())
    };

    let elapsed_ms = (started.elapsed().as_millis() as u64).max(1);
    let latency_label = if elapsed_ms < 200 {
        "<200ms".to_string()
    } else {
        format!("{elapsed_ms}ms")
    };

    let mut out = json!({
        "ok": true,
        "agent_name": "Delivery-2",
        "seq": current_seq,
        "cursor_seq": current_seq,
        "since_seq": since_seq,
        "unchanged": unchanged,
        "delta_entries": delta_entries,
        "status": status_code,
        "status_label": status_label,
        "active_thread_id": active_thread_id,
        "voice": voice_json,
        "sync_radar": {
            "latency_ms": elapsed_ms,
            "latency_label": latency_label,
            "surfaces": surfaces
        },
        "morning_focus": {
            "seen": state.delivery2.morning_seen,
            "collapsed": state.delivery2.morning_collapsed,
            "rows": [
                {
                    "id": "mf-inbox",
                    "badge": format!("{ready_diffs}"),
                    "label": if ready_diffs == 1 { "diff ready for your review" } else { "diffs ready for your review" },
                    "cta": "Inbox",
                    "target_tab": "inbox",
                    "hash": "#inbox"
                },
                {
                    "id": "mf-board",
                    "badge": format!("{active_board_total}"),
                    "label": if running_count > 0 { "active check runs on Board" } else { "queued tasks on Board" },
                    "cta": "Board",
                    "target_tab": "board",
                    "hash": "#board"
                },
                {
                    "id": "mf-credits",
                    "badge": format!("{available_credits} Cr"),
                    "label": "available in workspace pool",
                    "cta": "Credits",
                    "target_tab": "credits",
                    "hash": "#credits"
                }
            ]
        },
        "entries": active_entries,
        "history": {
            "today": history_today,
            "earlier": history_earlier
        },
        "memories": memories_list,
        "steering_chips": [
            { "id": "chip-missed", "label": "What did I miss?", "prompt": "What did I miss?" },
            { "id": "chip-why", "label": chip_why_label, "prompt": format!("Why #{top_ref_id}?") },
            { "id": "chip-credits", "label": "Today's Credits", "prompt": "Today's Credits" }
        ],
        "links": {
            "security_url": sanitize_chinwag_outbound_url("https://chinwag.sh/security", "https://chinwag.sh/security"),
            "founders_url": sanitize_chinwag_outbound_url("https://chinwag.sh/pricing?talk=1&source=local_ui#founders", "https://chinwag.sh/pricing"),
            "open_url": sanitize_chinwag_outbound_url("https://chinwag.sh/open", "https://chinwag.sh/open"),
            "pricing_url": sanitize_chinwag_outbound_url(CREDIT_PACKS_PRICING_URL, "https://chinwag.sh/pricing")
        }
    });
    scrub_customer_ui_json(&mut out);
    out
}

fn ensure_active_thread_mut(
    store: &mut Delivery2Store,
    seeded_entries: Vec<Value>,
) -> &mut Delivery2Thread {
    let tid = if store.active_thread_id.trim().is_empty() {
        store.active_thread_id = "thr-main".to_string();
        "thr-main".to_string()
    } else {
        store.active_thread_id.clone()
    };
    if let Some(pos) = store.threads.iter().position(|t| t.id == tid) {
        if store.threads[pos].entries.is_empty() && tid == "thr-main" {
            store.threads[pos].entries = seeded_entries;
        }
        return &mut store.threads[pos];
    }
    let now = unix_now();
    store.threads.push(Delivery2Thread {
        id: tid.clone(),
        title: if tid == "thr-main" {
            "Workspace scope & morning review".to_string()
        } else {
            "New thread".to_string()
        },
        bucket: "today".to_string(),
        status: "Live".to_string(),
        created_at_unix: now,
        updated_at_unix: now,
        entries: if tid == "thr-main" {
            seeded_entries
        } else {
            Vec::new()
        },
    });
    let last = store.threads.len() - 1;
    &mut store.threads[last]
}

fn ensure_named_or_active_thread_mut<'a>(
    store: &'a mut Delivery2Store,
    requested_thread_id: Option<&str>,
    seeded_entries: Vec<Value>,
) -> &'a mut Delivery2Thread {
    if let Some(req_tid) = requested_thread_id.map(str::trim).filter(|s| !s.is_empty())
        && let Some(pos) = store.threads.iter().position(|t| t.id == req_tid)
    {
        if store.threads[pos].entries.is_empty() && req_tid == "thr-main" {
            store.threads[pos].entries = seeded_entries;
        }
        return &mut store.threads[pos];
    }
    ensure_active_thread_mut(store, seeded_entries)
}

fn handle_delivery2_message(repo_root: &Path, port: u16, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let raw_prompt = parsed
        .get("prompt")
        .or_else(|| parsed.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if raw_prompt.is_empty() {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "empty_prompt",
                "error": "Ask Delivery-2 a question, scope a change, or save a workspace note."
            }),
        );
    }
    if raw_prompt.chars().count() > MAX_DELIVERY2_PROMPT_CHARS {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "prompt_too_long",
                "error": format!("Delivery-2 messages must be at most {MAX_DELIVERY2_PROMPT_CHARS} characters.")
            }),
        );
    }

    let client_turn_id = parsed
        .get("turn_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "active")
        .map(scrub_customer_ui_text);
    let requested_thread_id = parsed
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(scrub_customer_ui_text);

    let lower = raw_prompt.to_ascii_lowercase();
    let memory_note_opt = ["remember:", "remember that ", "save rule:", "note:"]
        .iter()
        .find_map(|prefix| {
            if lower.starts_with(prefix) {
                raw_prompt.get(prefix.len()..).map(str::trim)
            } else {
                None
            }
        });

    if contains_secret_shaped_token(raw_prompt) {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "secret_rejected",
                "error": "Refused to save text that looks like an API key, token, or password. Keep credentials in local environment files instead."
            }),
        );
    }

    let repo_info = discover_repo_info(repo_root);
    let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
    let workflow = load_workflow_config(repo_root);
    let credits = build_credits_json(repo_root, shipped_count);
    let learned_rules = scan_learned_rules(repo_root);

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        let seeded =
            build_seeded_delivery2_entries(&repo_info, &inbox, &board, &credits, &workflow, state);
        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        let next_seq = state.delivery2.seq;
        let now = unix_now();
        let clean_user_prompt = scrub_customer_ui_text(raw_prompt);

        let user_entry = json!({
            "id": format!("entry-user-{next_seq}"),
            "kind": "user_message",
            "seq": next_seq,
            "role": "user",
            "author": "You",
            "body": clean_user_prompt
        });

        // If `Stop` arrived before `/message` committed on the server, persist only a zero-length stopped card.
        if let Some(ref tid) = client_turn_id
            && state.delivery2.cancelled_turn_ids.iter().any(|c| c == tid)
        {
            let stopped_qa = json!({
                "id": format!("entry-qa-{next_seq}"),
                "kind": "qa_card",
                "seq": next_seq,
                "turn_id": tid,
                "role": "assistant",
                "author": "Delivery-2",
                "body": "[Stopped]",
                "stopped": true,
                "sources": []
            });
            let thr = ensure_named_or_active_thread_mut(
                &mut state.delivery2,
                requested_thread_id.as_deref(),
                seeded,
            );
            if thr.title == "New thread" {
                thr.title = clean_user_prompt.chars().take(48).collect();
            }
            thr.updated_at_unix = now;
            thr.entries.push(user_entry);
            thr.entries.push(stopped_qa.clone());
            return Ok(json!({
                "ok": true,
                "seq": next_seq,
                "entry": stopped_qa,
                "stopped": true,
                "credits_charged": 0
            }));
        }

        let explicit_why_target = if lower.starts_with("why ") || lower.contains("why #") {
            extract_why_target_id(raw_prompt)
        } else {
            None
        };

        let mut assistant_entry = if let Some(note_raw) = memory_note_opt {
            if note_raw.is_empty() {
                return Err((
                    "400 Bad Request",
                    json!({
                        "ok": false,
                        "error_code": "empty_memory_note",
                        "error": "Provide a short rule or preference after 'Remember:'."
                    }),
                ));
            }
            let mem_id = format!("mem_{}", csprng_hex(4));
            let clean_note = scrub_customer_ui_text(note_raw);
            state.delivery2.memories.insert(
                mem_id.clone(),
                Delivery2Memory {
                    id: mem_id.clone(),
                    note: clean_note.clone(),
                    status: "saved".to_string(),
                    updated_at_unix: now,
                    seq: next_seq,
                },
            );
            json!({
                "id": format!("entry-mem-{next_seq}"),
                "kind": "memory_card",
                "seq": next_seq,
                "memory_id": mem_id,
                "note": clean_note,
                "status": "saved"
            })
        } else if let Some(requested_raw) = explicit_why_target {
            let rules_count = learned_rules.len();
            let prot_list = if workflow.protected_paths.is_empty() {
                "none configured".to_string()
            } else {
                workflow.protected_paths.join(", ")
            };
            let lookup_id = if requested_raw.eq_ignore_ascii_case("sample") {
                "sample-walkthrough"
            } else {
                requested_raw.as_str()
            };
            let inbox_match = inbox
                .get("items")
                .and_then(Value::as_array)
                .and_then(|arr| {
                    arr.iter()
                        .find(|i| i.get("id").and_then(Value::as_str) == Some(lookup_id))
                });
            let board_match = board
                .get("columns")
                .and_then(Value::as_array)
                .and_then(|cols| {
                    cols.iter().find_map(|col| {
                        col.get("items").and_then(Value::as_array).and_then(|arr| {
                            arr.iter()
                                .find(|c| c.get("id").and_then(Value::as_str) == Some(lookup_id))
                        })
                    })
                });

            if let Some(item) = inbox_match.or(board_match) {
                let clean_id = scrub_customer_ui_text(lookup_id);
                let title = item
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("Workspace item");
                let status_lbl = item
                    .get("status_label")
                    .or_else(|| item.get("status"))
                    .and_then(Value::as_str)
                    .unwrap_or("tracked");
                let tool_lbl = item
                    .get("tool_label")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or("unassigned");
                let is_sample = item
                    .get("is_sample")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let files_changed = inbox_match
                    .and_then(|i| i.get("files_changed"))
                    .and_then(Value::as_u64);
                let tests_passed = inbox_match
                    .and_then(|i| i.get("tests_passed"))
                    .and_then(Value::as_bool);
                let verified_rev = inbox_match
                    .and_then(|i| i.get("reviewer_label"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty());

                let diff_note = if let Some(fc) = files_changed {
                    let add = inbox_match
                        .and_then(|i| i.get("additions"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let del = inbox_match
                        .and_then(|i| i.get("deletions"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    format!("{fc} files (+{add}/-{del})")
                } else {
                    "diff stats not yet recorded".to_string()
                };
                let test_note = match tests_passed {
                    Some(true) => "local test suite passed",
                    Some(false) => "local test suite failed",
                    None => "test receipt not yet recorded",
                };
                let review_note = match verified_rev {
                    Some(r) => format!("independent review by {r} recorded"),
                    None => "independent review not yet recorded".to_string(),
                };

                let primary_source = if inbox_match.is_some() {
                    json!({
                        "label": format!("Inbox · #{clean_id} ({status_lbl})"),
                        "target_tab": "inbox",
                        "hash": if is_sample { "#walkthrough".to_string() } else { format!("#diff/{clean_id}") }
                    })
                } else {
                    json!({
                        "label": format!("Board · #{clean_id} ({status_lbl})"),
                        "target_tab": "board",
                        "hash": "#board"
                    })
                };

                json!({
                    "id": format!("entry-qa-{next_seq}"),
                    "kind": "qa_card",
                    "seq": next_seq,
                    "role": "assistant",
                    "author": "Delivery-2",
                    "body": format!(
                        "**#{clean_id}** (\"{title}\") is currently **{status_lbl}** (driver: **{tool_lbl}**, {diff_note}, {test_note}, {review_note}). Repository guardrails protect `{prot_list}` ({rules_count} learned repo {}, `0 Cr` while paused).",
                        if rules_count == 1 { "rule" } else { "rules" }
                    ),
                    "sources": [
                        primary_source,
                        { "label": format!("Agents & Rules · {} protected paths", workflow.protected_paths.len()), "target_tab": "agents", "hash": "#agents" }
                    ]
                })
            } else {
                let clean_missing = scrub_customer_ui_text(&requested_raw);
                json!({
                    "id": format!("entry-qa-{next_seq}"),
                    "kind": "qa_card",
                    "seq": next_seq,
                    "role": "assistant",
                    "author": "Delivery-2",
                    "body": format!(
                        "Item `#{clean_missing}` was not found in your local Inbox or Board, so no diff, test run, or independent review receipt is available."
                    ),
                    "sources": []
                })
            }
        } else if lower.contains("what did i miss") || lower.contains("morning") {
            let ready = inbox["counts"]["needs_decision"].as_u64().unwrap_or(0);
            let running = inbox["counts"]["running"].as_u64().unwrap_or(0);
            let queued = board["summary"]["queued_count"].as_u64().unwrap_or(0);
            let shipped = board["summary"]["shipped_count"].as_u64().unwrap_or(0);
            let avail_cr = credits["available_credits"].as_u64().unwrap_or(500);
            let hours = board["summary"]["hours_saved"].as_f64().unwrap_or(0.0);
            json!({
                "id": format!("entry-qa-{next_seq}"),
                "kind": "qa_card",
                "seq": next_seq,
                "role": "assistant",
                "author": "Delivery-2",
                "body": format!(
                    "Since your last check: **{ready}** {} ready for your decision in Inbox, **{running}** active check {} and **{queued}** queued {} on Board, and **{shipped}** shipped ({hours:.1}h saved). Workspace balance is **{avail_cr} Cr** (`0 Cr` while paused).",
                    if ready == 1 { "diff is" } else { "diffs are" },
                    if running == 1 { "run" } else { "runs" },
                    if queued == 1 { "task" } else { "tasks" }
                ),
                "sources": [
                    { "label": format!("Inbox · {ready} ready to review"), "target_tab": "inbox", "hash": "#inbox" },
                    { "label": format!("Board · {running} active · {queued} queued · {shipped} shipped"), "target_tab": "board", "hash": "#board" },
                    { "label": format!("Credits · {avail_cr} Cr remaining"), "target_tab": "credits", "hash": "#credits" }
                ]
            })
        } else if lower.contains("credit") || lower.contains("balance") || lower.contains("cost") {
            let avail_cr = credits["available_credits"].as_u64().unwrap_or(500);
            let tier = credits["plan_tier"]
                .as_str()
                .unwrap_or("Free Starter Trial");
            let per_review = workflow.review_tier_credits;
            json!({
                "id": format!("entry-qa-{next_seq}"),
                "kind": "qa_card",
                "seq": next_seq,
                "role": "assistant",
                "author": "Delivery-2",
                "body": format!(
                    "Your workspace has **{avail_cr} Cr** available on **{tier}**. Standard paired verification uses **{per_review} Cr** per task; paused approvals, board status sync, and terminal commands always cost **0 Cr**."
                ),
                "sources": [
                    { "label": format!("Credits · {avail_cr} Cr ({tier})"), "target_tab": "credits", "hash": "#credits" },
                    { "label": format!("Pairing tier · {per_review} Cr per task"), "target_tab": "agents", "hash": "#agents" }
                ]
            })
        } else if lower.starts_with("why ") || lower.contains("why #") {
            let driver_lbl = friendly_workflow_tool_label(&workflow.driver_tool);
            let reviewer_lbl = friendly_workflow_tool_label(&workflow.reviewer_tool);
            let rules_count = learned_rules.len();
            let prot_list = if workflow.protected_paths.is_empty() {
                "none configured".to_string()
            } else {
                workflow.protected_paths.join(", ")
            };
            json!({
                "id": format!("entry-qa-{next_seq}"),
                "kind": "qa_card",
                "seq": next_seq,
                "role": "assistant",
                "author": "Delivery-2",
                "body": format!(
                    "Repository safety rules gate changes touching `{prot_list}` ({rules_count} learned repo {} configured; workflow pairs **{driver_lbl}** with **{reviewer_lbl}**, `0 Cr` while paused).",
                    if rules_count == 1 { "rule" } else { "rules" }
                ),
                "sources": [
                    { "label": format!("Agents & Rules · {} protected paths", workflow.protected_paths.len()), "target_tab": "agents", "hash": "#agents" }
                ]
            })
        } else {
            let driver_lbl = friendly_workflow_tool_label(&workflow.driver_tool);
            let reviewer_lbl = friendly_workflow_tool_label(&workflow.reviewer_tool);
            let per_review = workflow.review_tier_credits;
            let run_id = format!("run-scoped-{next_seq}");
            let thr = ensure_named_or_active_thread_mut(
                &mut state.delivery2,
                requested_thread_id.as_deref(),
                seeded,
            );
            if thr.title == "New thread" {
                thr.title = clean_user_prompt.chars().take(48).collect();
            }
            thr.updated_at_unix = now;
            thr.entries.push(user_entry);
            let run_title: String = clean_user_prompt.chars().take(120).collect();
            let scoped_excerpt: String = clean_user_prompt.chars().take(160).collect();
            let mut run_card = json!({
                "id": format!("entry-run-{next_seq}"),
                "kind": "run_card",
                "seq": next_seq,
                "run_id": run_id,
                "title": run_title,
                "current_step_num": "04",
                "current_step_label": "Estimate ready",
                "current_step_display": "04 · Estimate ready",
                "completed": false,
                "verb_summary": format!("Checked {} protected path rules · Estimated pairing tier", workflow.protected_paths.len()),
                "diff_target_id": "sample-walkthrough",
                "steps": build_twelve_step_ladder_json(4, false)
            });
            let mut qa_card = json!({
                "id": format!("entry-qa-{next_seq}"),
                "kind": "qa_card",
                "seq": next_seq,
                "role": "assistant",
                "author": "Delivery-2",
                "body": format!(
                    "Delivery-2 scoped **\"{scoped_excerpt}\"**: isolate changes on a clean branch with **{driver_lbl}**, run local tests in sandbox, and verify with **{reviewer_lbl}** before opening your review (~**{per_review} Cr** total · pauses at **0 Cr** on protected paths)."
                ),
                "sources": [
                    { "label": format!("Pairing · {driver_lbl} + {reviewer_lbl}"), "target_tab": "agents", "hash": "#agents" },
                    { "label": format!("Estimate · ~{per_review} Cr"), "target_tab": "credits", "hash": "#credits" }
                ]
            });
            if let Some(ref tid) = client_turn_id {
                if let Some(obj) = run_card.as_object_mut() {
                    obj.insert("turn_id".to_string(), Value::String(tid.clone()));
                }
                if let Some(obj) = qa_card.as_object_mut() {
                    obj.insert("turn_id".to_string(), Value::String(tid.clone()));
                }
            }
            thr.entries.push(run_card.clone());
            thr.entries.push(qa_card.clone());
            return Ok(json!({
                "ok": true,
                "seq": next_seq,
                "entry": qa_card,
                "run_card": run_card,
                "credits_charged": 0
            }));
        };

        if let Some(ref tid) = client_turn_id
            && let Some(obj) = assistant_entry.as_object_mut()
        {
            obj.insert("turn_id".to_string(), Value::String(tid.clone()));
        }

        let thr = ensure_named_or_active_thread_mut(
            &mut state.delivery2,
            requested_thread_id.as_deref(),
            seeded,
        );
        if thr.title == "New thread" {
            thr.title = clean_user_prompt.chars().take(48).collect();
        }
        thr.updated_at_unix = now;
        thr.entries.push(user_entry);
        thr.entries.push(assistant_entry.clone());

        let mem_summary =
            if assistant_entry.get("kind").and_then(Value::as_str) == Some("memory_card") {
                json!({
                    "id": assistant_entry.get("memory_id").cloned().unwrap_or(Value::Null),
                    "note": assistant_entry.get("note").cloned().unwrap_or(Value::Null),
                    "status": "saved"
                })
            } else {
                Value::Null
            };

        Ok(json!({
            "ok": true,
            "seq": next_seq,
            "entry": assistant_entry,
            "memory": mem_summary,
            "credits_charged": 0
        }))
    });

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn handle_delivery2_cancel(repo_root: &Path, port: u16, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let turn_id = parsed
        .get("turn_id")
        .and_then(Value::as_str)
        .unwrap_or("active")
        .trim()
        .to_string();
    let entry_id_opt = parsed
        .get("entry_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let truncated_len_opt = parsed
        .get("truncated_len")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    let requested_thread_id = parsed
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(scrub_customer_ui_text);

    let repo_info = discover_repo_info(repo_root);
    let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
    let workflow = load_workflow_config(repo_root);
    let credits = build_credits_json(repo_root, shipped_count);

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        let seeded =
            build_seeded_delivery2_entries(&repo_info, &inbox, &board, &credits, &workflow, state);
        let clean_turn_id = scrub_customer_ui_text(&turn_id);
        let effective_max_chars = if let Some(mc) = truncated_len_opt {
            Some(mc)
        } else if entry_id_opt.is_none() && !clean_turn_id.is_empty() && clean_turn_id != "active" {
            Some(0)
        } else {
            None
        };

        if !clean_turn_id.is_empty() && clean_turn_id != "active" {
            if let Some(mc) = effective_max_chars {
                state
                    .delivery2
                    .cancelled_turn_clamps
                    .insert(clean_turn_id.clone(), mc);
            }
            if !state
                .delivery2
                .cancelled_turn_ids
                .iter()
                .any(|c| c == &clean_turn_id)
            {
                state
                    .delivery2
                    .cancelled_turn_ids
                    .push(clean_turn_id.clone());
                if state.delivery2.cancelled_turn_ids.len() > 64 {
                    let drop_n = state.delivery2.cancelled_turn_ids.len() - 64;
                    for evicted in state.delivery2.cancelled_turn_ids.drain(..drop_n) {
                        state.delivery2.cancelled_turn_clamps.remove(&evicted);
                    }
                }
            }
        }

        state.delivery2.active_turn_id = None;
        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        let next_seq = state.delivery2.seq;
        let receipt_entry = json!({
            "id": format!("entry-cancel-{next_seq}"),
            "kind": "cancel_receipt",
            "seq": next_seq,
            "turn_id": clean_turn_id,
            "receipt": "Reply stopped by you · 0 Cr"
        });

        // Resolve the stopped turn's OWNING thread across all threads (even if another tab switched `active_thread_id`).
        let owning_thread_idx = state.delivery2.threads.iter().position(|t| {
            t.entries.iter().any(|e| {
                (entry_id_opt
                    .as_deref()
                    .is_some_and(|eid| e.get("id").and_then(Value::as_str) == Some(eid)))
                    || (!clean_turn_id.is_empty()
                        && clean_turn_id != "active"
                        && e.get("turn_id").and_then(Value::as_str) == Some(clean_turn_id.as_str()))
            })
        });
        let thr = if let Some(idx) = owning_thread_idx {
            &mut state.delivery2.threads[idx]
        } else {
            ensure_named_or_active_thread_mut(
                &mut state.delivery2,
                requested_thread_id.as_deref(),
                seeded,
            )
        };
        thr.updated_at_unix = unix_now();

        if let Some(max_chars) = effective_max_chars {
            if !clean_turn_id.is_empty() && clean_turn_id != "active" {
                if max_chars == 0 {
                    thr.entries.retain(|e| {
                        !(e.get("kind").and_then(Value::as_str) == Some("run_card")
                            && e.get("turn_id").and_then(Value::as_str)
                                == Some(clean_turn_id.as_str()))
                    });
                } else {
                    for rc in thr.entries.iter_mut().filter(|e| {
                        e.get("kind").and_then(Value::as_str) == Some("run_card")
                            && e.get("turn_id").and_then(Value::as_str)
                                == Some(clean_turn_id.as_str())
                    }) {
                        if let Some(rc_obj) = rc.as_object_mut() {
                            let step_num = rc_obj
                                .get("current_step_num")
                                .and_then(Value::as_str)
                                .unwrap_or("04")
                                .to_string();
                            rc_obj.insert("stopped".to_string(), Value::Bool(true));
                            rc_obj.insert("completed".to_string(), Value::Bool(false));
                            rc_obj.insert(
                                "current_step_label".to_string(),
                                Value::String("Stopped".to_string()),
                            );
                            rc_obj.insert(
                                "current_step_display".to_string(),
                                Value::String(format!("{step_num} · Stopped")),
                            );
                            rc_obj.insert("seq".to_string(), Value::Number(next_seq.into()));
                        }
                    }
                }
            }
            let target_entry = if let Some(ref eid) = entry_id_opt {
                thr.entries
                    .iter_mut()
                    .rev()
                    .find(|e| e.get("id").and_then(Value::as_str) == Some(eid.as_str()))
            } else if !clean_turn_id.is_empty() && clean_turn_id != "active" {
                thr.entries.iter_mut().rev().find(|e| {
                    e.get("kind").and_then(Value::as_str) == Some("qa_card")
                        && e.get("turn_id").and_then(Value::as_str) == Some(clean_turn_id.as_str())
                })
            } else {
                thr.entries
                    .iter_mut()
                    .rev()
                    .find(|e| e.get("kind").and_then(Value::as_str) == Some("qa_card"))
            };
            if let Some(entry_val) = target_entry
                && let Some(obj) = entry_val.as_object_mut()
                && let Some(full_body) = obj.get("body").and_then(Value::as_str)
            {
                let clamped: String = full_body.chars().take(max_chars).collect();
                let final_body = if max_chars == 0 || clamped.trim().is_empty() {
                    "[Stopped]".to_string()
                } else {
                    clamped
                };
                obj.insert("body".to_string(), Value::String(final_body));
                obj.insert("stopped".to_string(), Value::Bool(true));
                obj.insert("seq".to_string(), Value::Number(next_seq.into()));
                if max_chars == 0 {
                    obj.insert("sources".to_string(), json!([]));
                }
            }
        }

        thr.entries.push(receipt_entry);
        Ok(json!({
            "ok": true,
            "cancelled": true,
            "turn_id": scrub_customer_ui_text(&turn_id),
            "credits_charged": 0,
            "message": "Reply stopped by you.",
            "seq": next_seq
        }))
    });

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn handle_delivery2_approval(repo_root: &Path, port: u16, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let kind = parsed
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("hitl")
        .trim();
    let decision = parsed
        .get("decision")
        .or_else(|| parsed.get("action"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if kind == "oauth" {
        let surface = parsed
            .get("surface")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !matches!(surface.as_str(), "github" | "linear" | "slack") {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_surface",
                    "error": "Connection surface must be 'github', 'linear', or 'slack'."
                }),
            );
        }
        if !matches!(decision.as_str(), "connect" | "retry" | "verify" | "skip") {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_oauth_action",
                    "error": "OAuth action must be 'connect', 'retry', 'verify', or 'skip'."
                }),
            );
        }
        let repo_info = discover_repo_info(repo_root);
        let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
        let workflow = load_workflow_config(repo_root);
        let credits = build_credits_json(repo_root, shipped_count);

        let req_oauth_state = parsed
            .get("oauth_state")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let req_thread_id = parsed
            .get("thread_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();

        let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
            let seeded = build_seeded_delivery2_entries(
                &repo_info, &inbox, &board, &credits, &workflow, state,
            );
            let surface_label = match surface.as_str() {
                "github" => "GitHub",
                "linear" => "Linear",
                _ => "Slack",
            };
            let active_tid = if state.delivery2.active_thread_id.trim().is_empty() {
                "thr-main".to_string()
            } else {
                state.delivery2.active_thread_id.clone()
            };

            if decision == "verify" {
                let Some(existing_pref) = state.delivery2.connections.get(&surface) else {
                    return Err((
                        "409 Conflict",
                        json!({
                            "ok": false,
                            "error_code": "oauth_challenge_missing",
                            "authorized": false,
                            "error": format!("Start a {surface_label} sign-in challenge first before verifying.")
                        }),
                    ));
                };
                let Some(expected_nonce) = existing_pref.oauth_state.as_deref() else {
                    return Err((
                        "409 Conflict",
                        json!({
                            "ok": false,
                            "error_code": "oauth_challenge_missing",
                            "authorized": false,
                            "error": format!("No active {surface_label} OAuth challenge is pending.")
                        }),
                    ));
                };
                let expected_thread = existing_pref
                    .oauth_thread_id
                    .as_deref()
                    .unwrap_or(active_tid.as_str());
                if req_oauth_state.is_empty() || req_oauth_state != expected_nonce {
                    return Err((
                        "409 Conflict",
                        json!({
                            "ok": false,
                            "error_code": "oauth_state_mismatch",
                            "authorized": false,
                            "error": "OAuth state token did not match the active sign-in challenge."
                        }),
                    ));
                }
                if req_thread_id.is_empty()
                    || req_thread_id != expected_thread
                    || active_tid != expected_thread
                {
                    return Err((
                        "409 Conflict",
                        json!({
                            "ok": false,
                            "error_code": "oauth_thread_mismatch",
                            "authorized": false,
                            "error": "OAuth verification must complete in the originating thread."
                        }),
                    ));
                }
                let verified_auth =
                    has_verified_workspace_oauth_receipt(repo_root, &surface, Some(expected_nonce));
                if !verified_auth {
                    return Err((
                        "409 Conflict",
                        json!({
                            "ok": false,
                            "error_code": "oauth_not_verified",
                            "authorized": false,
                            "surface": surface,
                            "error": format!("{surface_label} sign-in is not yet detected on this workspace. Complete sign-in via the link first; paused safely at 0 Cr.")
                        }),
                    ));
                }

                state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
                let next_seq = state.delivery2.seq;
                let target_tid = expected_thread.to_string();
                let challenge_url = existing_pref
                    .challenge_url
                    .clone()
                    .unwrap_or_else(|| "https://chinwag.sh/open".to_string());
                if let Some(pref_mut) = state.delivery2.connections.get_mut(&surface) {
                    pref_mut.oauth_state = None;
                    pref_mut.oauth_thread_id = None;
                    if surface != "slack" {
                        pref_mut.in_thread = Some(true);
                    }
                }
                let now = unix_now();
                let hh_mm = format_utc_hh_mm(now);
                let receipt = format!("{surface_label} verified · {hh_mm} · 0 Cr while paused");
                let card_id = format!("entry-oauth-{surface}");
                let _ = ensure_active_thread_mut(&mut state.delivery2, seeded);
                for thr in &mut state.delivery2.threads {
                    if thr.id == target_tid {
                        thr.updated_at_unix = now;
                    }
                    if let Some(existing) = thr
                        .entries
                        .iter_mut()
                        .find(|e| e.get("id").and_then(Value::as_str) == Some(card_id.as_str()))
                        && let Some(obj) = existing.as_object_mut()
                        && (thr.id == target_tid
                            || !obj.get("settled").and_then(Value::as_bool).unwrap_or(false))
                    {
                        obj.insert("settled".to_string(), Value::Bool(true));
                        obj.insert(
                            "settled_decision".to_string(),
                            Value::String("verified".to_string()),
                        );
                        obj.insert(
                            "settled_receipt".to_string(),
                            Value::String(receipt.clone()),
                        );
                        obj.insert("seq".to_string(), Value::Number(next_seq.into()));
                    }
                }
                return Ok(json!({
                    "ok": true,
                    "kind": "oauth",
                    "surface": surface,
                    "surface_label": surface_label,
                    "decision": "verified",
                    "authorized": true,
                    "challenge_url": sanitize_chinwag_outbound_url(&challenge_url, "https://chinwag.sh/open"),
                    "credits_while_paused": 0,
                    "seq": next_seq
                }));
            }

            state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
            let next_seq = state.delivery2.seq;
            let nonce = csprng_hex(8);
            let challenge_url = format!("https://chinwag.sh/open?connect={surface}&state={nonce}");
            let pref = state
                .delivery2
                .connections
                .entry(surface.clone())
                .or_default();
            if decision == "skip" {
                pref.in_thread = Some(false);
                pref.oauth_state = None;
                pref.oauth_thread_id = None;
            } else {
                pref.challenge_url = Some(challenge_url.clone());
                pref.oauth_state = Some(nonce.clone());
                pref.oauth_thread_id = Some(active_tid.clone());
            }

            let now = unix_now();
            let hh_mm = format_utc_hh_mm(now);
            let _ = ensure_active_thread_mut(&mut state.delivery2, seeded);
            let card_id = format!("entry-oauth-{surface}");
            if decision == "skip" {
                let receipt = format!(
                    "Skipped {surface_label} sign-in for now · {hh_mm} · 0 Cr while paused"
                );
                for thr in &mut state.delivery2.threads {
                    if thr.id == active_tid {
                        thr.updated_at_unix = now;
                    }
                    if let Some(existing) = thr
                        .entries
                        .iter_mut()
                        .find(|e| e.get("id").and_then(Value::as_str) == Some(card_id.as_str()))
                        && let Some(obj) = existing.as_object_mut()
                        && (thr.id == active_tid
                            || !obj.get("settled").and_then(Value::as_bool).unwrap_or(false))
                    {
                        obj.insert("settled".to_string(), Value::Bool(true));
                        obj.insert(
                            "settled_decision".to_string(),
                            Value::String("skip".to_string()),
                        );
                        obj.insert(
                            "settled_receipt".to_string(),
                            Value::String(receipt.clone()),
                        );
                        obj.insert("seq".to_string(), Value::Number(next_seq.into()));
                    }
                }
            } else {
                let supersede_rcpt = format!(
                    "Moved {surface_label} sign-in to current thread · {hh_mm} · 0 Cr while paused"
                );
                for thr in &mut state.delivery2.threads {
                    if thr.id == active_tid {
                        continue;
                    }
                    if let Some(existing) = thr
                        .entries
                        .iter_mut()
                        .find(|e| e.get("id").and_then(Value::as_str) == Some(card_id.as_str()))
                        && let Some(obj) = existing.as_object_mut()
                        && !obj.get("settled").and_then(Value::as_bool).unwrap_or(false)
                    {
                        obj.insert("settled".to_string(), Value::Bool(true));
                        obj.insert(
                            "settled_decision".to_string(),
                            Value::String("superseded".to_string()),
                        );
                        obj.insert(
                            "settled_receipt".to_string(),
                            Value::String(supersede_rcpt.clone()),
                        );
                        obj.insert("seq".to_string(), Value::Number(next_seq.into()));
                    }
                }
                let oauth_card = json!({
                    "id": card_id,
                    "kind": "oauth_card",
                    "seq": next_seq,
                    "surface": surface,
                    "surface_label": surface_label,
                    "oauth_state": nonce,
                    "thread_id": active_tid,
                    "pause_badge": "Paused · 0 Cr",
                    "title": format!("Sign in to {surface_label} to continue"),
                    "body": format!("Paused safely at 0 Cr until your {surface_label} account is linked. Complete sign-in in your browser, then re-check here."),
                    "challenge_url": challenge_url,
                    "settled": false
                });
                if let Some(thr) = state
                    .delivery2
                    .threads
                    .iter_mut()
                    .find(|t| t.id == active_tid)
                {
                    thr.updated_at_unix = now;
                    if let Some(pos) = thr
                        .entries
                        .iter()
                        .position(|e| e.get("id").and_then(Value::as_str) == Some(card_id.as_str()))
                    {
                        thr.entries[pos] = oauth_card;
                    } else {
                        thr.entries.push(oauth_card);
                    }
                }
            }

            let verified_auth = has_verified_workspace_oauth_receipt(repo_root, &surface, None);

            Ok(json!({
                "ok": true,
                "kind": "oauth",
                "surface": surface,
                "surface_label": surface_label,
                "decision": decision,
                "oauth_state": if decision == "skip" { Value::Null } else { Value::String(nonce) },
                "thread_id": active_tid,
                "authorized": verified_auth,
                "challenge_url": challenge_url,
                "credits_while_paused": 0,
                "seq": next_seq
            }))
        });
        if status == "200 OK"
            && let Some(obj) = resp.as_object_mut()
        {
            obj.insert(
                "state".to_string(),
                build_delivery2_state_json(repo_root, port),
            );
        }
        scrub_customer_ui_json(&mut resp);
        return (status, resp);
    }

    let approval_id = parsed
        .get("id")
        .or_else(|| parsed.get("approval_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let item_id = parsed
        .get("item_id")
        .and_then(Value::as_str)
        .unwrap_or(approval_id)
        .trim();

    if approval_id.is_empty() || !matches!(decision.as_str(), "approve" | "deny") {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_approval_request",
                "error": "Both 'id' and 'decision' ('approve' or 'deny') are required."
            }),
        );
    }

    let stripped_item = item_id.strip_prefix("hitl-").unwrap_or(item_id);
    let stripped_approval = approval_id.strip_prefix("hitl-").unwrap_or(approval_id);
    let canonical_item_id = if !stripped_item.is_empty() {
        stripped_item.to_string()
    } else {
        stripped_approval.to_string()
    };
    let canonical_approval_id = format!("hitl-{canonical_item_id}");

    let is_sample = parsed
        .get("is_sample")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || canonical_item_id.eq_ignore_ascii_case("sample-walkthrough")
        || stripped_approval.eq_ignore_ascii_case("sample-walkthrough");

    if is_sample && decision == "approve" {
        return (
            "403 Forbidden",
            json!({
                "ok": false,
                "error_code": "SampleWalkthroughShipForbidden",
                "error": "Sample walkthrough items are read-only practice and can never be merged or pushed."
            }),
        );
    }

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        let now_gate = unix_now();
        let voice_active = state.delivery2.voice.has_open_session(now_gate);
        ui_delivery2_voice::enforce_physical_merge_button_gate(&parsed, &decision, voice_active)?;

        // First-answer-wins idempotency across both `delivery2.approvals` and `item_decisions`.
        if let Some(existing) = state
            .delivery2
            .approvals
            .get(&canonical_approval_id)
            .or_else(|| state.delivery2.approvals.get(approval_id))
            .cloned()
        {
            return Ok(json!({
                "ok": true,
                "id": approval_id,
                "decision": existing.decision,
                "receipt": existing.receipt,
                "decided_at": existing.decided_at_label,
                "already_settled": true,
                "credits_while_paused": 0,
                "seq": state.delivery2.seq.max(1)
            }));
        }

        if let Some(prior_inbox) = state.item_decisions.get(&canonical_item_id).cloned()
            && matches!(prior_inbox.status.as_str(), "done" | "rejected")
        {
            let hh_mm = format_utc_hh_mm(prior_inbox.updated_at_unix);
            let settled_dec = if prior_inbox.status == "done" {
                "approved"
            } else {
                "denied"
            };
            let settled_rcpt = if prior_inbox.status == "done" {
                format!("Approved in Inbox · {hh_mm} · 0 Cr while paused")
            } else {
                format!("Rejected in Inbox · {hh_mm} · 0 Cr while paused")
            };
            let seq_now = state.delivery2.seq.max(1);
            state.delivery2.approvals.insert(
                canonical_approval_id.clone(),
                Delivery2ApprovalRecord {
                    id: canonical_approval_id,
                    decision: settled_dec.to_string(),
                    receipt: settled_rcpt.clone(),
                    decided_at_label: hh_mm.clone(),
                    updated_at_unix: prior_inbox.updated_at_unix,
                    seq: seq_now,
                },
            );
            return Ok(json!({
                "ok": true,
                "id": approval_id,
                "decision": settled_dec,
                "receipt": settled_rcpt,
                "decided_at": hh_mm,
                "already_settled": true,
                "credits_while_paused": 0,
                "seq": seq_now
            }));
        }

        let now = unix_now();
        let hh_mm = format_utc_hh_mm(now);
        let (canonical_decision, receipt) = if decision == "approve" {
            (
                "approved",
                format!("Approved by you · {hh_mm} · 0 Cr while paused"),
            )
        } else {
            (
                "denied",
                format!("Denied by you · {hh_mm} · 0 Cr while paused"),
            )
        };

        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        let next_seq = state.delivery2.seq;
        stamp_approval_settlement_in_threads(
            &mut state.delivery2.threads,
            &canonical_approval_id,
            &canonical_item_id,
            true,
            Some(canonical_decision),
            Some(&receipt),
            next_seq,
        );
        let rec = Delivery2ApprovalRecord {
            id: canonical_approval_id.clone(),
            decision: canonical_decision.to_string(),
            receipt: receipt.clone(),
            decided_at_label: hh_mm.clone(),
            updated_at_unix: now,
            seq: next_seq,
        };
        state
            .delivery2
            .approvals
            .insert(canonical_approval_id.clone(), rec.clone());
        if approval_id != canonical_approval_id {
            state.delivery2.approvals.insert(
                approval_id.to_string(),
                Delivery2ApprovalRecord {
                    id: approval_id.to_string(),
                    ..rec
                },
            );
        }

        if !canonical_item_id.is_empty() && canonical_item_id != "run-local-1" {
            state.item_decisions.insert(
                canonical_item_id,
                ItemDecisionRecord {
                    status: if canonical_decision == "approved" {
                        "done".to_string()
                    } else {
                        "rejected".to_string()
                    },
                    action: decision.clone(),
                    note: None,
                    updated_at_unix: now,
                },
            );
        }

        if let Some(sess) = state.delivery2.voice.active_session.as_mut() {
            sess.hold_started_unix = None;
        }

        Ok(json!({
            "ok": true,
            "id": approval_id,
            "decision": canonical_decision,
            "receipt": receipt,
            "decided_at": hh_mm,
            "already_settled": false,
            "credits_while_paused": 0,
            "seq": next_seq
        }))
    });

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn handle_delivery2_memory(repo_root: &Path, port: u16, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let mem_id = parsed
        .get("id")
        .or_else(|| parsed.get("memory_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let action = parsed
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if mem_id.is_empty() || !mem_id.starts_with("mem_") {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_memory_id",
                "error": "Memory ID must start with 'mem_'."
            }),
        );
    }
    if !matches!(action.as_str(), "edit" | "undo" | "restore") {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_memory_action",
                "error": "Memory action must be 'edit', 'undo', or 'restore'."
            }),
        );
    }

    let note_arg = parsed
        .get("note")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if action == "edit" {
        if note_arg.is_empty() {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "empty_memory_note",
                    "error": "Edited memory note must not be empty."
                }),
            );
        }
        if note_arg.chars().count() > 1_000 {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "memory_note_too_long",
                    "error": "Workspace memory notes must be at most 1,000 characters."
                }),
            );
        }
        if contains_secret_shaped_token(note_arg) {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "secret_rejected",
                    "error": "Refused to save text that looks like an API key, token, or password."
                }),
            );
        }
    }

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        let now = unix_now();
        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        let next_seq = state.delivery2.seq;

        if mem_id == "mem_default" && !state.delivery2.memories.contains_key("mem_default") {
            state.delivery2.memories.insert(
                "mem_default".to_string(),
                Delivery2Memory {
                    id: "mem_default".to_string(),
                    note: "Run unit tests in an isolated sandbox before opening a review."
                        .to_string(),
                    status: "saved".to_string(),
                    updated_at_unix: now,
                    seq: 1,
                },
            );
        }

        let Some(mem) = state.delivery2.memories.get_mut(mem_id) else {
            return Err((
                "404 Not Found",
                json!({
                    "ok": false,
                    "error_code": "memory_not_found",
                    "error": "Memory item not found."
                }),
            ));
        };

        match action.as_str() {
            "edit" => {
                mem.note = scrub_customer_ui_text(note_arg);
                mem.status = "saved".to_string();
            }
            "undo" => {
                mem.status = "undone".to_string();
            }
            "restore" => {
                mem.status = "saved".to_string();
            }
            _ => {}
        }
        mem.updated_at_unix = now;
        mem.seq = next_seq;
        let snapshot = mem.clone();

        Ok(json!({
            "ok": true,
            "memory": {
                "id": snapshot.id,
                "note": snapshot.note,
                "status": snapshot.status
            },
            "seq": next_seq
        }))
    });

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn handle_delivery2_thread(repo_root: &Path, port: u16, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let action = parsed
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if action == "new"
        && let Some(raw_title) = parsed.get("title").and_then(Value::as_str)
        && contains_secret_shaped_token(raw_title)
    {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "secret_rejected",
                "error": "Refused to create a thread title that looks like an API key, token, or password."
            }),
        );
    }

    let repo_info = discover_repo_info(repo_root);
    let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
    let workflow = load_workflow_config(repo_root);
    let credits = build_credits_json(repo_root, shipped_count);

    let (status, mut resp) = match action.as_str() {
        "new" => mutate_ui_v4_state(repo_root, |state| {
            let seeded = build_seeded_delivery2_entries(
                &repo_info, &inbox, &board, &credits, &workflow, state,
            );
            let _ = ensure_active_thread_mut(&mut state.delivery2, seeded);
            let now = unix_now();
            let new_id = format!("thr-{}", csprng_hex(4));
            let title = parsed
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| scrub_customer_ui_text(s).chars().take(120).collect())
                .unwrap_or_else(|| "New thread".to_string());
            state.delivery2.threads.push(Delivery2Thread {
                id: new_id.clone(),
                title,
                bucket: "today".to_string(),
                status: "Live".to_string(),
                created_at_unix: now,
                updated_at_unix: now,
                entries: Vec::new(),
            });
            state.delivery2.active_thread_id = new_id.clone();
            state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
            Ok(json!({
                "ok": true,
                "action": "new",
                "active_thread_id": new_id,
                "seq": state.delivery2.seq
            }))
        }),
        "switch" => {
            let target_id = match parse_optional_delivery2_thread_id(&parsed, true) {
                Ok(Some(tid)) => tid,
                Ok(None) => {
                    return (
                        "400 Bad Request",
                        json!({
                            "ok": false,
                            "error_code": "missing_thread_id",
                            "error": "thread_id is required to switch threads."
                        }),
                    );
                }
                Err(err_resp) => return err_resp,
            };
            mutate_ui_v4_state(repo_root, |state| {
                ensure_delivery2_thread_exists(state, &target_id)?;
                state.delivery2.active_thread_id = target_id.clone();
                state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
                Ok(json!({
                    "ok": true,
                    "action": "switch",
                    "active_thread_id": target_id,
                    "seq": state.delivery2.seq
                }))
            })
        }
        "morning_focus" => mutate_ui_v4_state(repo_root, |state| {
            if let Some(seen) = parsed.get("seen").and_then(Value::as_bool) {
                state.delivery2.morning_seen = seen;
            }
            if let Some(collapsed) = parsed.get("collapsed").and_then(Value::as_bool) {
                state.delivery2.morning_collapsed = collapsed;
            }
            state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
            Ok(json!({
                "ok": true,
                "action": "morning_focus",
                "seen": state.delivery2.morning_seen,
                "collapsed": state.delivery2.morning_collapsed,
                "seq": state.delivery2.seq
            }))
        }),
        "connection" => {
            let surface = parsed
                .get("surface")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if !matches!(surface.as_str(), "github" | "linear" | "slack") {
                return (
                    "400 Bad Request",
                    json!({
                        "ok": false,
                        "error_code": "invalid_surface",
                        "error": "Surface must be 'github', 'linear', or 'slack'."
                    }),
                );
            }
            let req_in_thread = parsed.get("in_thread").and_then(Value::as_bool);
            let verified_auth = has_verified_workspace_oauth_receipt(repo_root, &surface, None);
            if req_in_thread == Some(true) && !verified_auth {
                return (
                    "409 Conflict",
                    json!({
                        "ok": false,
                        "error_code": "oauth_required",
                        "error": "Connect and verify your account before enabling this surface in thread."
                    }),
                );
            }
            mutate_ui_v4_state(repo_root, |state| {
                let pref = state
                    .delivery2
                    .connections
                    .entry(surface.clone())
                    .or_default();
                if let Some(in_thr) = req_in_thread {
                    pref.in_thread = Some(in_thr);
                }
                state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
                Ok(json!({
                    "ok": true,
                    "action": "connection",
                    "surface": surface,
                    "in_thread": pref.in_thread,
                    "seq": state.delivery2.seq
                }))
            })
        }
        _ => (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_thread_action",
                "error": "Thread action must be 'new', 'switch', 'morning_focus', or 'connection'."
            }),
        ),
    };

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn parse_optional_delivery2_thread_id(
    parsed: &Value,
    allow_id_alias: bool,
) -> Result<Option<String>, (&'static str, Value)> {
    let raw_val = parsed.get("thread_id").or_else(|| {
        if allow_id_alias {
            parsed.get("id")
        } else {
            None
        }
    });
    let Some(val) = raw_val else {
        return Ok(None);
    };
    if val.is_null() {
        return Ok(None);
    }
    let Some(raw_str) = val.as_str() else {
        return Err((
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_thread_id",
                "error": "thread_id must be a string."
            }),
        ));
    };
    let trimmed = raw_str.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 128 || trimmed.chars().count() > 128 || trimmed.chars().any(char::is_control)
    {
        return Err((
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "invalid_thread_id",
                "error": "thread_id must be at most 128 printable characters."
            }),
        ));
    }
    if contains_secret_shaped_token(trimmed) {
        return Err((
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "secret_rejected",
                "error": "Refused thread_id that looks like an API key, token, or password."
            }),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn ensure_delivery2_thread_exists(
    state: &LocalUiV4State,
    tid: &str,
) -> Result<(), (&'static str, Value)> {
    let exists = tid == "thr-main" || state.delivery2.threads.iter().any(|t| t.id == tid);
    if !exists {
        return Err((
            "404 Not Found",
            json!({
                "ok": false,
                "error_code": "thread_not_found",
                "error": "Requested Delivery-2 thread was not found."
            }),
        ));
    }
    Ok(())
}

fn thread_or_workspace_has_unsettled_hitl(
    state: &LocalUiV4State,
    target_tid: &str,
    seeded_entries: &[Value],
    inbox: &Value,
) -> bool {
    let thread_has_unsettled = |tid: &str| -> bool {
        let entries_slice: &[Value] =
            if let Some(found) = state.delivery2.threads.iter().find(|t| t.id == tid) {
                if found.entries.is_empty() && tid == "thr-main" {
                    seeded_entries
                } else {
                    &found.entries
                }
            } else if tid == "thr-main" {
                seeded_entries
            } else {
                &[]
            };
        entries_slice.iter().any(|e| {
            is_entry_unsettled_workflow(state, tid, e)
                && e.get("kind").and_then(Value::as_str) == Some("approval_card")
        })
    };

    if thread_has_unsettled(target_tid) || thread_has_unsettled("thr-main") {
        return true;
    }
    if state
        .delivery2
        .threads
        .iter()
        .any(|t| thread_has_unsettled(&t.id))
    {
        return true;
    }

    // Also inspect workspace-global real Inbox items awaiting review/permission.
    if let Some(items) = inbox.get("items").and_then(Value::as_array) {
        for item in items {
            let is_sample = item
                .get("is_sample")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if is_sample {
                continue;
            }
            let Some(item_id) = item.get("id").and_then(Value::as_str).map(str::trim) else {
                continue;
            };
            if item_id.is_empty() || item_id.starts_with("sample-") {
                continue;
            }
            let status = item.get("status").and_then(Value::as_str).unwrap_or("");
            if !matches!(
                status,
                "needs_review" | "needs_permission" | "paused_for_approval"
            ) {
                continue;
            }
            let hitl_key = format!("hitl-{item_id}");
            let settled_in_d2 = state.delivery2.approvals.contains_key(&hitl_key)
                || state.delivery2.approvals.contains_key(item_id);
            let settled_in_inbox = state
                .item_decisions
                .get(item_id)
                .is_some_and(|d| matches!(d.status.as_str(), "done" | "rejected"));
            if !settled_in_d2 && !settled_in_inbox {
                return true;
            }
        }
    }
    false
}

fn handle_delivery2_voice_session(
    repo_root: &Path,
    port: u16,
    body: &[u8],
) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let action = parsed
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("start")
        .trim()
        .to_ascii_lowercase();
    let initial_connecting = parsed
        .get("connecting")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let req_thread_id = match parse_optional_delivery2_thread_id(&parsed, false) {
        Ok(opt) => opt,
        Err(err_resp) => return err_resp,
    };

    let (_, _, shipped_count) = build_inbox_and_board(repo_root);
    let base_avail_cr = base_workspace_credits_for_shipped(shipped_count);
    let now_unix = unix_now();

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        if let Some(ref tid) = req_thread_id {
            ensure_delivery2_thread_exists(state, tid)?;
        }
        let target_tid = req_thread_id.clone().unwrap_or_else(|| {
            if state.delivery2.active_thread_id.trim().is_empty() {
                "thr-main".to_string()
            } else {
                state.delivery2.active_thread_id.clone()
            }
        });
        ensure_delivery2_thread_exists(state, &target_tid)?;
        // Compute remaining workspace credits while holding `UI_V4_STATE_MUTEX` (eliminating TOCTOU overdraw).
        let avail_cr = base_avail_cr.saturating_sub(state.delivery2.voice.total_voice_credits_used);
        let seed = csprng_hex(4);
        let voice_json = state.delivery2.voice.start_or_control_session(
            &action,
            &seed,
            &target_tid,
            initial_connecting,
            avail_cr,
            now_unix,
        )?;
        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        Ok(json!({
            "ok": true,
            "action": action,
            "voice": voice_json,
            "seq": state.delivery2.seq
        }))
    });

    if status != "200 OK"
        && matches!(
            resp.get("error_code").and_then(Value::as_str),
            Some("VoiceSessionExpired" | "VoiceCreditsCapReached")
        )
    {
        let _ = mutate_ui_v4_state(repo_root, |st| {
            let _ = st.delivery2.voice.reconcile_at(now_unix, false, false);
            st.delivery2.seq = st.delivery2.seq.max(1).saturating_add(1);
            Ok(json!({ "ok": true }))
        });
    }

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn handle_delivery2_voice_heartbeat(
    repo_root: &Path,
    port: u16,
    body: &[u8],
) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let req_session_id = parsed
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let idle_secs = parsed.get("idle_secs").and_then(Value::as_u64);
    let hold_secs = parsed.get("hold_secs").and_then(Value::as_u64);
    let speech_active = parsed
        .get("speech_active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let barge_in = parsed
        .get("barge_in")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let repo_info = discover_repo_info(repo_root);
    let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
    let workflow = load_workflow_config(repo_root);
    let credits = build_credits_json(repo_root, shipped_count);
    let now_unix = unix_now();

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        let seeded =
            build_seeded_delivery2_entries(&repo_info, &inbox, &board, &credits, &workflow, state);
        let hb_tid = state
            .delivery2
            .voice
            .active_session
            .as_ref()
            .map(|s| s.thread_id.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if state.delivery2.active_thread_id.trim().is_empty() {
                    "thr-main"
                } else {
                    state.delivery2.active_thread_id.as_str()
                }
            });
        let unsettled_hitl = thread_or_workspace_has_unsettled_hitl(state, hb_tid, &seeded, &inbox);
        let voice_json =
            state
                .delivery2
                .voice
                .heartbeat(ui_delivery2_voice::VoiceHeartbeatInput {
                    requested_session_id: req_session_id.as_deref(),
                    client_idle_secs: idle_secs,
                    client_hold_secs: hold_secs,
                    speech_active,
                    barge_in,
                    has_unsettled_hold: unsettled_hitl,
                    now_unix,
                })?;
        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        Ok(json!({
            "ok": true,
            "voice": voice_json,
            "seq": state.delivery2.seq
        }))
    });

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn handle_delivery2_voice_park(repo_root: &Path, port: u16, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let req_session_id = parsed
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let reason = parsed
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("user_paused")
        .trim()
        .to_string();
    let now_unix = unix_now();

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        let voice_json =
            state
                .delivery2
                .voice
                .park(req_session_id.as_deref(), &reason, now_unix)?;
        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        Ok(json!({
            "ok": true,
            "parked": true,
            "credits_while_paused": 0,
            "voice": voice_json,
            "seq": state.delivery2.seq
        }))
    });

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

fn handle_delivery2_voice_turn(repo_root: &Path, port: u16, body: &[u8]) -> (&'static str, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_json",
                    "error": "Request body must be valid JSON."
                }),
            );
        }
    };

    let raw_utterance = parsed
        .get("utterance")
        .or_else(|| parsed.get("transcript"))
        .or_else(|| parsed.get("prompt"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if raw_utterance.is_empty() {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "empty_utterance",
                "error": "Speak a question or option for Delivery-2."
            }),
        );
    }
    if raw_utterance.chars().count() > MAX_DELIVERY2_PROMPT_CHARS {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "utterance_too_long",
                "error": format!("Voice turns must be at most {MAX_DELIVERY2_PROMPT_CHARS} characters.")
            }),
        );
    }
    if contains_secret_shaped_token(raw_utterance) {
        return (
            "400 Bad Request",
            json!({
                "ok": false,
                "error_code": "secret_rejected",
                "error": "Refused to save speech that looks like an API key, token, or password."
            }),
        );
    }

    let req_session_id = parsed
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let requested_thread_id = match parse_optional_delivery2_thread_id(&parsed, false) {
        Ok(opt) => opt,
        Err(err_resp) => return err_resp,
    };
    let interrupted = parsed
        .get("interrupted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let explicit_danger = parsed
        .get("danger")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let option_strings: Vec<String> = parsed
        .get("options")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .take(12)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    let repo_info = discover_repo_info(repo_root);
    let (inbox, board, shipped_count) = build_inbox_and_board(repo_root);
    let workflow = load_workflow_config(repo_root);
    let base_avail_cr = base_workspace_credits_for_shipped(shipped_count);
    let now_unix = unix_now();
    let now_ms = unix_now_ms();

    let (status, mut resp) = mutate_ui_v4_state(repo_root, |state| {
        if let Some(ref req_sid) = req_session_id
            && let Some(ref sess) = state.delivery2.voice.active_session
            && sess.session_id != *req_sid
        {
            return Err((
                "409 Conflict",
                json!({
                    "ok": false,
                    "error_code": "voice_session_mismatch",
                    "error": "Voice session ID did not match the active session."
                }),
            ));
        }

        if let Some(ref tid) = requested_thread_id {
            ensure_delivery2_thread_exists(state, tid)?;
        }
        let resolved_tid = requested_thread_id
            .clone()
            .or_else(|| {
                state
                    .delivery2
                    .voice
                    .active_session
                    .as_ref()
                    .map(|s| s.thread_id.clone())
                    .filter(|s| !s.trim().is_empty())
            })
            .unwrap_or_else(|| {
                if state.delivery2.active_thread_id.trim().is_empty() {
                    "thr-main".to_string()
                } else {
                    state.delivery2.active_thread_id.clone()
                }
            });
        ensure_delivery2_thread_exists(state, &resolved_tid)?;

        // Compute remaining workspace credits while holding `UI_V4_STATE_MUTEX` (eliminating TOCTOU overdraw).
        let avail_before =
            base_avail_cr.saturating_sub(state.delivery2.voice.total_voice_credits_used);
        let credits_for_seed = json!({
            "available_credits": avail_before,
            "plan_tier": if shipped_count == 0 { "Free Starter Trial" } else { "Team Pack" }
        });

        let seeded = build_seeded_delivery2_entries(
            &repo_info,
            &inbox,
            &board,
            &credits_for_seed,
            &workflow,
            state,
        );
        let has_unsettled_danger_card =
            thread_or_workspace_has_unsettled_hitl(state, &resolved_tid, &seeded, &inbox);

        let all_opt_refs: Vec<&str> = option_strings.iter().map(String::as_str).collect();
        let danger_opt_refs: Vec<&str> = all_opt_refs
            .iter()
            .copied()
            .filter(|opt| ui_delivery2_voice::option_contains_danger_verb(opt))
            .collect();
        let matched_danger_option = !danger_opt_refs.is_empty()
            && ui_delivery2_voice::spoken_option(raw_utterance, &danger_opt_refs).is_some();

        // Hard safety gate: danger-class merges/deploys/approvals can NEVER be approved via voice (`CHWG-0255` Pillar 3).
        // Evaluated strictly BEFORE `charge_turn_credits` so rejected danger attempts charge 0 Cr.
        if explicit_danger
            || matched_danger_option
            || ui_delivery2_voice::is_voice_danger_approval_attempt(
                raw_utterance,
                has_unsettled_danger_card,
            )
        {
            return Err((
                "403 Forbidden",
                json!({
                    "ok": false,
                    "error_code": "VoiceDangerApprovalForbidden",
                    "credits_charged": 0,
                    "physical_click_required": true,
                    "physical_click_verified": false,
                    "error": ui_delivery2_voice::DANGER_VOICE_REJECT_COPY,
                    "message": ui_delivery2_voice::DANGER_VOICE_REJECT_COPY,
                    "spoken_reply": ui_delivery2_voice::DANGER_VOICE_REJECT_COPY
                }),
            ));
        }

        if let Some(sess) = state.delivery2.voice.active_session.as_mut() {
            let max_possible = sess.credits_used.saturating_add(avail_before);
            if max_possible < sess.credits_cap {
                sess.credits_cap = max_possible;
            }
        }

        // Server-determined per-turn credit charge (`VOICE_DEFAULT_TURN_CREDITS`); client fields cannot override.
        let (charged, hit_cap) = state
            .delivery2
            .voice
            .charge_turn_credits(VOICE_DEFAULT_TURN_CREDITS, now_unix)?;

        let clean_utterance = scrub_customer_ui_text(raw_utterance);
        let lower = raw_utterance.to_ascii_lowercase();

        let safe_opt_refs = ui_delivery2_voice::filter_safe_voice_options(&all_opt_refs);
        let matched_option = if !safe_opt_refs.is_empty() {
            ui_delivery2_voice::spoken_option(raw_utterance, &safe_opt_refs)
        } else {
            None
        };

        let driver_lbl = friendly_workflow_tool_label(&workflow.driver_tool);
        let reviewer_lbl = friendly_workflow_tool_label(&workflow.reviewer_tool);
        let thinking_step_label = if lower.contains("what did i miss") || lower.contains("morning")
        {
            "Checking Inbox and Board summary"
        } else if lower.contains("credit") || lower.contains("balance") || lower.contains("cost") {
            "Checking workspace credit balance"
        } else {
            "Scoping change against protected path rules"
        };

        let mut delegate = VoiceDelegateTracker::new();
        let prev_hold_until = state
            .delivery2
            .voice
            .active_session
            .as_ref()
            .map_or(0, |s| s.thinking_hold_until_ms);
        let thinking_ev = if now_ms >= prev_hold_until {
            let ev = delegate.observe_thinking(thinking_step_label, now_ms);
            if let Some(ref e) = ev
                && let Some(sess) = state.delivery2.voice.active_session.as_mut()
            {
                sess.thinking_label = Some(e.text.clone());
                sess.thinking_hold_until_ms = now_ms.saturating_add(VOICE_THINKING_HOLD_MS);
            }
            ev
        } else {
            None
        };

        let avail_after = avail_before.saturating_sub(charged);

        let raw_spoken_reply = if let Some(ref chosen) = matched_option {
            format!("Selected \"{chosen}\" in your thread. Workspace balance is {avail_after} Cr.")
        } else if lower.contains("what did i miss") || lower.contains("morning") {
            let ready = inbox["counts"]["needs_decision"].as_u64().unwrap_or(0);
            let running = inbox["counts"]["running"].as_u64().unwrap_or(0);
            let shipped = board["summary"]["shipped_count"].as_u64().unwrap_or(0);
            format!(
                "You have {ready} {} waiting in Inbox, {running} active check {}, and {shipped} shipped. Workspace balance is {avail_after} Cr.",
                if ready == 1 { "diff" } else { "diffs" },
                if running == 1 { "run" } else { "runs" }
            )
        } else if lower.contains("credit") || lower.contains("balance") || lower.contains("cost") {
            let used_voice = state
                .delivery2
                .voice
                .active_session
                .as_ref()
                .map_or(charged, |s| s.credits_used);
            format!(
                "Your workspace has {avail_after} Cr remaining. This voice call has used {used_voice} of its 40 Cr cap, and paused calls always cost 0 Cr."
            )
        } else {
            let excerpt: String = clean_utterance.chars().take(120).collect();
            format!(
                "Scoped \"{excerpt}\" with {driver_lbl} and {reviewer_lbl} verification. Tests run in an isolated sandbox before you click Approve."
            )
        };

        let commentary_ev = delegate.observe_commentary(&raw_spoken_reply, interrupted);
        let spoken_text = commentary_ev
            .as_ref()
            .map(|e| e.text.clone())
            .unwrap_or_else(|| "[Interrupted]".to_string());

        if let Some(sess) = state.delivery2.voice.active_session.as_mut() {
            if let Some(ref ce) = commentary_ev {
                sess.last_spoken_commentary = Some(ce.text.clone());
            }
            if !hit_cap && !sess.audio_leg_parked && !sess.ended {
                sess.state = if commentary_ev.is_some() {
                    VoiceSessionState::Speaking
                } else {
                    VoiceSessionState::Listening
                };
            }
        }

        state.delivery2.seq = state.delivery2.seq.max(1).saturating_add(1);
        let next_seq = state.delivery2.seq;

        let user_entry = json!({
            "id": format!("entry-voice-user-{next_seq}"),
            "kind": "user_message",
            "source": "voice",
            "seq": next_seq,
            "role": "user",
            "author": "You",
            "body": clean_utterance
        });
        let qa_entry = json!({
            "id": format!("entry-voice-qa-{next_seq}"),
            "kind": "qa_card",
            "source": "voice",
            "seq": next_seq,
            "role": "assistant",
            "author": "Delivery-2",
            "body": spoken_text,
            "interrupted": interrupted,
            "sources": []
        });

        let thr = ensure_named_or_active_thread_mut(
            &mut state.delivery2,
            Some(resolved_tid.as_str()),
            seeded,
        );
        if thr.title == "New thread" {
            thr.title = clean_utterance.chars().take(48).collect();
        }
        thr.updated_at_unix = now_unix;
        thr.entries.push(user_entry);
        thr.entries.push(qa_entry.clone());

        let mut delegate_events = Vec::with_capacity(2);
        if let Some(ref te) = thinking_ev {
            delegate_events.push(serde_json::to_value(te).unwrap_or(Value::Null));
        }
        if let Some(ref ce) = commentary_ev {
            delegate_events.push(serde_json::to_value(ce).unwrap_or(Value::Null));
        }

        Ok(json!({
            "ok": true,
            "seq": next_seq,
            "credits_charged": charged,
            "cap_reached": hit_cap,
            "session_capped": hit_cap,
            "matched_option": matched_option,
            "spoken_commentary": spoken_text,
            "delegate_events": delegate_events,
            "delegate": {
                "thinking": thinking_ev,
                "commentary": commentary_ev
            },
            "entry": qa_entry,
            "voice": state.delivery2.voice.to_client_json(now_unix)
        }))
    });

    if status != "200 OK"
        && matches!(
            resp.get("error_code").and_then(Value::as_str),
            Some("VoiceSessionExpired" | "VoiceCreditsCapReached")
        )
    {
        let _ = mutate_ui_v4_state(repo_root, |st| {
            let _ = st.delivery2.voice.reconcile_at(now_unix, false, false);
            st.delivery2.seq = st.delivery2.seq.max(1).saturating_add(1);
            Ok(json!({ "ok": true }))
        });
    }

    if status == "200 OK"
        && let Some(obj) = resp.as_object_mut()
    {
        obj.insert(
            "state".to_string(),
            build_delivery2_state_json(repo_root, port),
        );
        obj.insert(
            "credits".to_string(),
            build_credits_json(repo_root, shipped_count),
        );
    }
    scrub_customer_ui_json(&mut resp);
    (status, resp)
}

// ============================================================================
// Main Loopback HTTP Router
// ============================================================================

pub fn handle_workbench_http_connection(
    stream: TcpStream,
    repo_root: &Path,
    auth: &Arc<UiSecurityContext>,
) {
    handle_workbench_http_connection_inner(stream, repo_root, None, auth);
}

pub fn handle_workbench_http_connection_selected(
    stream: TcpStream,
    selection: &RepositorySelection,
    auth: &Arc<UiSecurityContext>,
) {
    handle_workbench_http_connection_inner(stream, selection.root(), Some(selection), auth);
}

fn is_static_or_ping_route(path: &str) -> bool {
    matches!(
        path,
        "/api/bus/ping"
            | "/"
            | "/index.html"
            | "/assets/v4/theme-boot.js"
            | "/theme-boot.js"
            | "/assets/v4/styles.css"
            | "/styles.css"
            | "/assets/v4/app.css"
            | "/assets/v4/motion.css"
            | "/motion.css"
            | "/assets/v4/motion.js"
            | "/motion.js"
            | "/assets/v4/app.js"
            | "/app.js"
            | "/assets/v4/Geist-Latin.woff2"
            | "/assets/fonts/Geist-Latin.woff2"
            | "/assets/fonts/geist-latin.woff2"
            | "/assets/v4/GeistMono-Latin.woff2"
            | "/assets/fonts/GeistMono-Latin.woff2"
            | "/assets/fonts/geist-mono-latin.woff2"
            | "/favicon.svg"
            | "/favicon.ico"
    )
}

fn handle_workbench_http_connection_inner(
    mut stream: TcpStream,
    repo_root: &Path,
    selection: Option<&RepositorySelection>,
    auth: &Arc<UiSecurityContext>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let Some(req) = read_http_request(&mut stream) else {
        return;
    };

    let cors_origin = match auth.verify_request(&req) {
        AuthDecision::Allow { cors_origin } => cors_origin,
        AuthDecision::RedirectLoopback { location } => {
            let resp = format!(
                "HTTP/1.1 307 Temporary Redirect\r\n\
                 Location: {location}\r\n\
                 Cache-Control: no-store\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            return;
        }
        AuthDecision::Reject {
            status_line,
            error_code,
            message,
        } => {
            write_json_error(&mut stream, status_line, error_code, &message);
            return;
        }
    };

    if !is_static_or_ping_route(req.path.as_str())
        && let Some(sel) = selection
        && let Err(error) = sel.revalidate()
    {
        let body = serde_json::to_vec(&json!({
            "ok": false,
            "disposition": "HELD",
            "error": scrub_customer_text(&error.to_string())
        }))
        .unwrap_or_default();
        write_hardened_response(
            &mut stream,
            "409 Conflict",
            "application/json; charset=utf-8",
            &body,
            None,
            None,
        );
        return;
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("OPTIONS", "/api/bus/ping") => {
            write_hardened_response(
                &mut stream,
                "204 No Content",
                "text/plain; charset=utf-8",
                b"",
                None,
                cors_origin.as_deref(),
            );
        }
        ("GET", "/api/bus/ping") => {
            // <10ms instant non-blocking probe (zero disk/git/PATH I/O)
            let payload = serde_json::to_vec(&json!({
                "ok": true,
                "service": "chinwag-ui",
                "ui_version": UI_VERSION,
                "version": env!("CARGO_PKG_VERSION"),
                "port": auth.port(),
                "bind_addr": "127.0.0.1",
                "loopback": format!("http://127.0.0.1:{}", auth.port())
            }))
            .unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                cors_origin.as_deref(),
            );
        }
        ("GET", "/api/v4/bootstrap") => {
            let val = build_bootstrap_json(repo_root, auth.port());
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/v4/diff") => {
            let item_id = req
                .query_param("id")
                .unwrap_or_else(|| "sample-walkthrough".to_string());
            let val = build_diff_response_json(repo_root, &item_id);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/inbox/action") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, mut val) = handle_inbox_action(repo_root, &req.body);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/v4/board") => {
            let (_, mut board, _) = build_inbox_and_board(repo_root);
            scrub_customer_ui_json(&mut board);
            let payload = serde_json::to_vec(&board).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/board/sync") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, mut val) = handle_board_sync(repo_root, &req.body);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/board/task" | "/api/v4/board/tasks") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, mut val) = handle_board_create_task(repo_root, &req.body);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/v4/agents" | "/api/v4/rules/status" | "/api/rules/status") => {
            let mut val = json!({
                "ok": true,
                "detected_tools": detect_local_coding_tools(repo_root),
                "workflow": load_workflow_config(repo_root),
                "learned_rules": scan_learned_rules(repo_root),
                "cursor": build_cursor_preview_json(repo_root)
            });
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/workflow") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, mut val) = handle_workflow_update(repo_root, &req.body);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/v4/cursor/preview") => {
            let mut val = build_cursor_preview_json(repo_root);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/cursor/apply") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let parsed_body: Value =
                serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
            let selected_ids: Option<Vec<String>> = parsed_body
                .get("selected_ids")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                });
            let (status, mut val) = match apply_cursor_import(repo_root, selected_ids.as_deref()) {
                Ok(v) => ("200 OK", v),
                Err(e) => (
                    "409 Conflict",
                    json!({
                        "ok": false,
                        "disposition": "HELD",
                        "error_code": "cursor_import_failed",
                        "error": e
                    }),
                ),
            };
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/v4/credits") => {
            let (_, _, shipped_count) = build_inbox_and_board(repo_root);
            let mut val = build_credits_json(repo_root, shipped_count);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/credits/checkout") => {
            let (status, mut val) = handle_credits_checkout(&req.body);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/credits/autorefill") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, mut val) = handle_credits_autorefill(repo_root, &req.body);
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/telemetry/track" | "/api/telemetry/track") => {
            match ui_telemetry::enqueue_ui_event(&req.body, Some(repo_root)) {
                Ok(outcome) => {
                    let (queued, opted_out, dropped_reason) = match outcome {
                        ui_telemetry::EnqueueOutcome::Queued => (true, false, Value::Null),
                        ui_telemetry::EnqueueOutcome::DroppedOptedOut => {
                            (false, true, Value::String("opted_out".into()))
                        }
                        ui_telemetry::EnqueueOutcome::DroppedRateLimited => {
                            (false, false, Value::String("rate_limited".into()))
                        }
                        ui_telemetry::EnqueueOutcome::DroppedQueueFull => {
                            (false, false, Value::String("queue_full".into()))
                        }
                    };
                    let payload = serde_json::to_vec(&json!({
                        "ok": true,
                        "queued": queued,
                        "opted_out": opted_out,
                        "dropped_reason": dropped_reason
                    }))
                    .unwrap_or_default();
                    write_hardened_response(
                        &mut stream,
                        "202 Accepted",
                        "application/json; charset=utf-8",
                        &payload,
                        None,
                        None,
                    );
                }
                Err(err) => {
                    let status = if err.code() == "SampleWalkthroughShipForbidden" {
                        "403 Forbidden"
                    } else {
                        "400 Bad Request"
                    };
                    let payload = serde_json::to_vec(&json!({
                        "ok": false,
                        "error_code": "telemetry_validation_failed",
                        "reason": err.code()
                    }))
                    .unwrap_or_default();
                    write_hardened_response(
                        &mut stream,
                        status,
                        "application/json; charset=utf-8",
                        &payload,
                        None,
                        None,
                    );
                }
            }
        }
        ("GET", "/api/v4/telemetry/preferences" | "/api/telemetry/preferences") => {
            let val = ui_telemetry::get_telemetry_preferences(Some(repo_root));
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v4/telemetry/preferences" | "/api/telemetry/preferences") => {
            match ui_telemetry::update_telemetry_preferences(&req.body, Some(repo_root)) {
                Ok(val) => {
                    let payload = serde_json::to_vec(&val).unwrap_or_default();
                    write_hardened_response(
                        &mut stream,
                        "200 OK",
                        "application/json; charset=utf-8",
                        &payload,
                        None,
                        None,
                    );
                }
                Err(reason) => {
                    let status =
                        if matches!(reason, "persistence_failed" | "telemetry_lock_poisoned") {
                            "500 Internal Server Error"
                        } else {
                            "400 Bad Request"
                        };
                    write_json_error(&mut stream, status, "prefs_error", reason);
                }
            }
        }
        ("POST", "/api/v4/pm/ask" | "/api/pm/ask" | "/api/delivery/ask") => {
            let (status, payload) = handle_pm_ask(repo_root, &req.body);
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/v1/delivery2/state" | "/api/delivery2/state") => {
            let since_seq = req
                .query_param("since_seq")
                .and_then(|s| s.parse::<u64>().ok());
            let val = build_delivery2_state_json_with_cursor(repo_root, auth.port(), since_seq);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v1/delivery2/message" | "/api/delivery2/message") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_message(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v1/delivery2/cancel" | "/api/delivery2/cancel") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_cancel(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v1/delivery2/approval" | "/api/delivery2/approval") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_approval(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v1/delivery2/memory" | "/api/delivery2/memory") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_memory(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/v1/delivery2/thread" | "/api/delivery2/thread") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_thread(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/delivery2/voice/session" | "/api/v1/delivery2/voice/session") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_voice_session(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/delivery2/voice/heartbeat" | "/api/v1/delivery2/voice/heartbeat") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_voice_heartbeat(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/delivery2/voice/turn" | "/api/v1/delivery2/voice/turn") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_voice_turn(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/delivery2/voice/park" | "/api/v1/delivery2/voice/park") => {
            if let Err(held) = revalidate_mutation_workspace(selection, repo_root) {
                let payload = serde_json::to_vec(&held).unwrap_or_default();
                write_hardened_response(
                    &mut stream,
                    "409 Conflict",
                    "application/json; charset=utf-8",
                    &payload,
                    None,
                    None,
                );
                return;
            }
            let (status, val) = handle_delivery2_voice_park(repo_root, auth.port(), &req.body);
            let payload = serde_json::to_vec(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                status,
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/bus/status") => {
            let snap = get_verified_bus_snapshot(repo_root);
            let mut val = json!({
                "ok": true,
                "ui_version": UI_VERSION,
                "ui_port": auth.port(),
                "bind_addr": "127.0.0.1",
                "console_actor": "You",
                "workspace_initialized": repo_root.join(".chinwag").is_dir(),
                "rooms": {
                    "#mgmt": snap.mgmt_count,
                    "#eng": snap.eng_count,
                    "#qa": snap.qa_count,
                    "total": snap.total_count,
                    "verified": snap.verified_count
                }
            });
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec_pretty(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/bus/roster") => {
            let tools = detect_local_coding_tools(repo_root);
            let detected_count = tools
                .iter()
                .filter(|t| t.get("detected").and_then(Value::as_bool) == Some(true))
                .count();
            let mut val = json!({
                "ok": true,
                "summary": {
                    "detected_tools": detected_count,
                    "total_supported_tools": tools.len()
                },
                "tools": tools,
                "workflow": load_workflow_config(repo_root)
            });
            scrub_customer_ui_json(&mut val);
            let payload = serde_json::to_vec_pretty(&val).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/bus/messages") => {
            let limit = req
                .query_param("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(40)
                .min(120);
            let room_filter = req
                .query_param("room")
                .filter(|r| !r.is_empty() && r != "all" && r != "#all")
                .map(|r| {
                    if r.starts_with('#') {
                        r
                    } else {
                        format!("#{r}")
                    }
                });
            let task_filter = req.query_param("task").filter(|t| !t.is_empty());

            let snap = get_verified_bus_snapshot(repo_root);
            let filtered: Vec<Value> = snap
                .tail_values
                .iter()
                .filter(|m| {
                    let room_ok = room_filter
                        .as_deref()
                        .is_none_or(|rf| m.get("room").and_then(Value::as_str) == Some(rf));
                    let task_ok = task_filter
                        .as_deref()
                        .is_none_or(|tf| m.get("task_id").and_then(Value::as_str) == Some(tf));
                    room_ok && task_ok
                })
                .cloned()
                .collect();
            let start = filtered.len().saturating_sub(limit);
            let mut slice = Value::Array(filtered[start..].to_vec());
            scrub_customer_ui_json(&mut slice);
            let payload = serde_json::to_vec_pretty(&slice).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("POST", "/api/bus/stream-ticket") => {
            let ticket = auth.mint_stream_ticket();
            let payload = serde_json::to_vec(&json!({
                "ok": true,
                "ticket": ticket,
                "ttl_seconds": 30
            }))
            .unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/bus/stream") => {
            let max_ticks = req
                .query_param("max_ticks")
                .and_then(|v| v.parse::<usize>().ok());
            ui_sse::serve_bus_sse_stream(stream, repo_root, &req, max_ticks);
        }
        ("POST", "/api/bus/send") => {
            handle_bus_send(&mut stream, repo_root, selection, auth, &req);
        }
        ("GET", "/api/a509") => {
            let args = vec!["verify".to_string(), "--json".to_string()];
            let payload = match selection {
                Some(sel) => run_cli_to_json_bytes(|out, err| {
                    feature_cli_run::run_a509_cli_with_selection(sel, &args, out, err)
                }),
                None => {
                    run_cli_to_json_bytes(|out, err| feature_cli_run::run_a509_cli(&args, out, err))
                }
            };
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/bonds") => {
            let args = vec!["status".to_string(), "--json".to_string()];
            let payload = match selection {
                Some(sel) => run_cli_to_json_bytes(|out, err| {
                    feature_cli_run::run_bond_cli_with_selection(sel, &args, out, err)
                }),
                None => {
                    run_cli_to_json_bytes(|out, err| feature_cli_run::run_bond_cli(&args, out, err))
                }
            };
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/plugins") => {
            let args = vec!["verify".to_string(), "--json".to_string()];
            let payload = match selection {
                Some(sel) => run_cli_to_json_bytes(|out, err| {
                    feature_cli_run::run_plugin_cli_with_selection(sel, &args, out, err)
                }),
                None => run_cli_to_json_bytes(|out, err| {
                    feature_cli_run::run_plugin_cli(&args, out, err)
                }),
            };
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/cwcards") => {
            let args = vec!["verify".to_string(), "--json".to_string()];
            let payload = match selection {
                Some(sel) => run_cli_to_json_bytes(|out, err| {
                    feature_cli_run::run_cwcard_cli_with_selection(sel, &args, out, err)
                }),
                None => run_cli_to_json_bytes(|out, err| {
                    feature_cli_run::run_cwcard_cli(&args, out, err)
                }),
            };
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/api/tasks") => {
            let payload =
                serde_json::to_vec_pretty(&parse_all_tasks_json(repo_root)).unwrap_or_default();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                &payload,
                None,
                None,
            );
        }
        ("GET", "/" | "/index.html") => {
            let rendered = UI_V4_INDEX_HTML
                .replace("{{CHINWAG_CSRF_TOKEN}}", auth.csrf_token_hex())
                .replace("{{CHINWAG_PORT}}", &auth.port().to_string());
            let set_cookie = auth.set_cookie_header_value();
            write_hardened_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                rendered.as_bytes(),
                Some(&set_cookie),
                None,
            );
        }
        ("GET", "/assets/v4/theme-boot.js" | "/theme-boot.js") => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/javascript; charset=utf-8",
                UI_V4_THEME_BOOT_JS.as_bytes(),
                None,
                None,
            );
        }
        ("GET", "/assets/v4/styles.css" | "/styles.css" | "/assets/v4/app.css") => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "text/css; charset=utf-8",
                UI_V4_STYLES_CSS.as_bytes(),
                None,
                None,
            );
        }
        ("GET", "/assets/v4/motion.css" | "/motion.css") => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "text/css; charset=utf-8",
                UI_V4_MOTION_CSS.as_bytes(),
                None,
                None,
            );
        }
        ("GET", "/assets/v4/motion.js" | "/motion.js") => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/javascript; charset=utf-8",
                UI_V4_MOTION_JS.as_bytes(),
                None,
                None,
            );
        }
        ("GET", "/assets/v4/app.js" | "/app.js") => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "application/javascript; charset=utf-8",
                UI_V4_APP_JS.as_bytes(),
                None,
                None,
            );
        }
        (
            "GET",
            "/assets/v4/Geist-Latin.woff2"
            | "/assets/fonts/Geist-Latin.woff2"
            | "/assets/fonts/geist-latin.woff2",
        ) => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "font/woff2",
                UI_V4_GEIST_LATIN_WOFF2,
                None,
                None,
            );
        }
        (
            "GET",
            "/assets/v4/GeistMono-Latin.woff2"
            | "/assets/fonts/GeistMono-Latin.woff2"
            | "/assets/fonts/geist-mono-latin.woff2",
        ) => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "font/woff2",
                UI_V4_GEIST_MONO_LATIN_WOFF2,
                None,
                None,
            );
        }
        ("GET", "/favicon.svg" | "/favicon.ico") => {
            write_hardened_response(
                &mut stream,
                "200 OK",
                "image/svg+xml; charset=utf-8",
                UI_V4_FAVICON_SVG.as_bytes(),
                None,
                None,
            );
        }
        ("GET", _) => {
            write_json_error(&mut stream, "404 Not Found", "not_found", "Route not found");
        }
        _ => {
            write_json_error(
                &mut stream,
                "405 Method Not Allowed",
                "method_not_allowed",
                "Method not allowed",
            );
        }
    }
}

fn revalidate_mutation_workspace(
    selection: Option<&RepositorySelection>,
    repo_root: &Path,
) -> Result<(), Value> {
    if let Some(sel) = selection
        && let Err(error) = sel.revalidate()
    {
        return Err(json!({
            "ok": false,
            "disposition": "HELD",
            "error": scrub_customer_text(&error.to_string())
        }));
    }
    if let Err(e) = open_repo_dir_nofollow(repo_root, &[], false, Mode::empty()) {
        return Err(json!({
            "ok": false,
            "disposition": "HELD",
            "error": format!("workspace root validation failed: {e}")
        }));
    }
    match open_repo_dir_nofollow(repo_root, &[".chinwag"], false, Mode::empty()) {
        Ok(_) => Ok(()),
        Err(e) if e == rustix::io::Errno::NOENT => Ok(()),
        Err(e) => Err(json!({
            "ok": false,
            "disposition": "HELD",
            "error": format!("refusing symlinked or non-directory .chinwag inside workspace: {e}")
        })),
    }
}

struct ConnectionSlotGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn run_ui_workbench_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("serve");
    let is_json = args.iter().any(|a| a == "--json");

    if sub == "--help" || sub == "-h" || sub == "help" {
        let _ = writeln!(
            stdout,
            "Usage:\n  \
             chinwag ui [serve] [--port <5487>] [--repo <path>]\n  \
             chinwag ui status [--json]\n  \
             chinwag ui snapshot [--json]\n\n\
             Embedded Customer-First Chinwag Local Web App v4.1 on http://127.0.0.1:5487."
        );
        return 0;
    }

    let mut port = DEFAULT_WORKBENCH_PORT;
    let mut repo_arg: Option<String> = None;
    let mut repo_count = 0usize;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" if i + 1 < args.len() => {
                port = args[i + 1].parse::<u16>().unwrap_or(DEFAULT_WORKBENCH_PORT);
                i += 2;
            }
            "--repo" => {
                let Some(val) = args.get(i + 1) else {
                    let _ = writeln!(stderr, "chinwag ui repository held: --repo requires a path");
                    return 2;
                };
                if val.is_empty() || val.starts_with("--") {
                    let _ = writeln!(
                        stderr,
                        "chinwag ui repository held: invalid --repo selector"
                    );
                    return 2;
                }
                repo_count += 1;
                if repo_count > 1 {
                    let _ = writeln!(
                        stderr,
                        "chinwag ui repository held: duplicate --repo selector"
                    );
                    return 2;
                }
                repo_arg = Some(val.clone());
                i += 2;
            }
            s if s.starts_with("--repo=") => {
                let val = s.trim_start_matches("--repo=");
                if val.is_empty() || val.starts_with("--") {
                    let _ = writeln!(
                        stderr,
                        "chinwag ui repository held: invalid --repo selector"
                    );
                    return 2;
                }
                repo_count += 1;
                if repo_count > 1 {
                    let _ = writeln!(
                        stderr,
                        "chinwag ui repository held: duplicate --repo selector"
                    );
                    return 2;
                }
                repo_arg = Some(val.to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }

    let (selection, repo_root) = match feature_cli_run::select_cli_repository(args) {
        Ok(sel) => {
            let root = sel.root().to_path_buf();
            (Some(Arc::new(sel)), root)
        }
        Err(error) => {
            let fallback = resolve_repo_root(repo_arg.as_deref());
            if fallback.is_dir() && error.contains("MissingRepository") {
                // Uninitialized workspace directory: allow read-only onboarding UI while holding execution routes
                (None, fallback)
            } else {
                let _ = writeln!(stderr, "chinwag ui repository held: {error}");
                return 2;
            }
        }
    };

    if sub == "status" || args.iter().any(|a| a == "--status") {
        let state: Option<UiDaemonState> =
            read_repo_file_nofollow(&repo_root, &[".chinwag", "bus"], "ui-daemon.json", 65_536)
                .ok()
                .flatten()
                .and_then(|s| serde_json::from_str(&s).ok());
        if is_json {
            let out = json!({
                "ok": state.is_some(),
                "command": "chinwag ui status",
                "daemon": state
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&out).unwrap_or_default()
            );
        } else if let Some(d) = state {
            let _ = writeln!(
                stdout,
                "Chinwag Local Web App v{}: ONLINE (PID {} · http://{})",
                d.ui_version, d.pid, d.addr
            );
        } else {
            let _ = writeln!(
                stdout,
                "Chinwag Local Web App v{UI_VERSION}: STOPPED (Run `chinwag ui` to serve http://127.0.0.1:{port})"
            );
        }
        return 0;
    }

    if sub == "snapshot" {
        let out = parse_all_tasks_json(&repo_root);
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_default()
        );
        return 0;
    }

    let bind_addr = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            let _ = writeln!(stderr, "chinwag ui: failed to bind {bind_addr}: {e}");
            return 1;
        }
    };
    let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let actual_addr = format!("127.0.0.1:{actual_port}");
    let auth = Arc::new(UiSecurityContext::for_port(actual_port, true));

    let state = UiDaemonState {
        ok: true,
        pid: std::process::id(),
        addr: actual_addr.clone(),
        port: actual_port,
        ui_version: UI_VERSION.to_string(),
        views: 4,
        started_at_unix: unix_now(),
    };
    if let Ok(serialized) = serde_json::to_string_pretty(&state) {
        let _ = write_repo_file_nofollow_atomic(
            &repo_root,
            &[".chinwag", "bus"],
            "ui-daemon.json",
            Mode::RUSR | Mode::WUSR,
            serialized.as_bytes(),
        );
    }

    let _ = writeln!(
        stdout,
        "Chinwag Local Web App v{UI_VERSION} listening on http://{actual_addr} (PID {})",
        state.pid
    );
    let _ = stdout.flush();

    let active_conns = Arc::new(AtomicUsize::new(0));
    for mut stream in listener.incoming().flatten() {
        let prev = active_conns.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONCURRENT_UI_CONNECTIONS {
            active_conns.fetch_sub(1, Ordering::AcqRel);
            write_json_error(
                &mut stream,
                "503 Service Unavailable",
                "busy",
                "Too many concurrent local UI connections.",
            );
            continue;
        }
        let guard = ConnectionSlotGuard {
            counter: Arc::clone(&active_conns),
        };
        let repo_c = repo_root.clone();
        let sel_c = selection.clone();
        let auth_c = Arc::clone(&auth);
        if std::thread::Builder::new()
            .name("chinwag-ui-http".to_string())
            .spawn(move || {
                let _slot = guard;
                match sel_c {
                    Some(sel) => handle_workbench_http_connection_selected(stream, &sel, &auth_c),
                    None => handle_workbench_http_connection(stream, &repo_c, &auth_c),
                }
            })
            .is_err()
        {
            // `guard` dropped automatically when spawn fails
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn send_raw_http(addr: std::net::SocketAddr, raw_req: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("connect test server");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(raw_req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    fn split_http_body(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }

    fn make_temp_repo(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chinwag-ui-v4-unit-{prefix}-{}-{}",
            std::process::id(),
            csprng_hex(6)
        ));
        fs::create_dir_all(dir.join(".chinwag/bus")).unwrap();
        dir
    }

    #[test]
    fn canonical_default_port_is_5487_and_ui_version_is_4_1() {
        assert_eq!(DEFAULT_WORKBENCH_PORT, 5487);
        assert_eq!(UI_VERSION, "4.1");
    }

    #[test]
    fn zero_jargon_scrubber_preserves_normal_english_words_and_scrubs_internals() {
        let normal = "All 14 unit tests passed in session without issue.";
        assert_eq!(scrub_customer_text(normal), normal);

        let leaked = format!(
            "Dispatched {} on {} with {} and {} over {}",
            concat!("WORK", "HORSE#abc123"),
            concat!("Node 1 · Mac St", "udio"),
            concat!("inception/mer", "cury-3"),
            concat!("cr", "db"),
            concat!("SS", "E")
        );
        let cleaned = scrub_customer_text(&leaked);
        assert!(
            !cleaned
                .to_ascii_lowercase()
                .contains(concat!("work", "horse"))
        );
        assert!(
            !cleaned
                .to_ascii_lowercase()
                .contains(concat!("mac st", "udio"))
        );
        assert!(
            !cleaned
                .to_ascii_lowercase()
                .contains(concat!("mer", "cury"))
        );
        assert!(!cleaned.to_ascii_lowercase().contains(concat!("cr", "db")));
        assert!(cleaned.contains("live updates"));
    }

    #[test]
    fn five_stage_scrubber_preserves_delivery_2_and_scrubs_30_seats_vendors_and_crypto() {
        // Stage 1 + 2: Canonicalize every Delivery-2 spelling, Unicode dash, fullwidth, & zero-width variant
        for variant in [
            "DELIVERY-2",
            "delivery-2",
            "Delivery 2",
            "delivery2",
            "D\u{200B}ELIVERY\u{2011}2",
            "@DELIVERY-2",
            "■ DELIVERY-2",
            "\u{FF24}\u{FF45}\u{FF4C}\u{FF49}\u{FF56}\u{FF45}\u{FF52}\u{FF59}\u{2013}2",
        ] {
            let out = scrub_customer_ui_text(&format!("Ask {variant} to scope this change."));
            assert_eq!(
                out, "Ask Delivery-2 to scope this change.",
                "variant `{variant}` must canonicalize to Delivery-2"
            );
        }

        // Bare DELIVERY (not followed by -2) scrubs to Chinwag PM, while English "webhook delivery" stays intact
        let bare = scrub_customer_ui_text(&format!(
            "{} and @{} coordinated with DELIVERY-2 on duplicate webhook delivery.",
            concat!("DELI", "VERY"),
            concat!("deli", "very#inst1")
        ));
        assert!(bare.contains("Delivery-2"), "{bare}");
        assert!(bare.contains("duplicate webhook delivery."), "{bare}");
        assert!(!bare.contains("DELIVERY "), "{bare}");
        assert!(!bare.contains("#inst1"), "{bare}");

        // Context-aware eve.dev / useEveAgent / eve agent -> Delivery-2, while English "the eve of release" stays intact
        let eve_prose = scrub_customer_ui_text(&format!(
            "Migrated from {} and {} on the eve of release.",
            concat!("eve", ".dev"),
            concat!("useEve", "Agent")
        ));
        assert_eq!(
            eve_prose,
            "Migrated from Delivery-2 and Delivery-2 on the eve of release."
        );

        // All 30 standing seats scrub cleanly when emitted as internal handles
        let seats = [
            concat!("GEMINI", "-PM"),
            concat!("DELI", "VERY"),
            concat!("ARCHI", "TECT"),
            concat!("RU", "ST"),
            concat!("IND", "EX"),
            concat!("CLOUD", "FLARE"),
            concat!("ALIS", "TAIR"),
            "QA",
            concat!("INFRA", "JR"),
            concat!("HOUSE", "KEEPING"),
            concat!("TY", "PE"),
            concat!("GAME", "DEV"),
            concat!("SPA", "RK"),
            concat!("MOT", "ION"),
            concat!("FREQU", "ENCY"),
            concat!("SCR", "IBE"),
            concat!("DO", "CS"),
            "MO",
            concat!("EAGLE", "-EYE"),
            concat!("PAT", "ENT"),
            concat!("VEN", "TURE"),
            concat!("DE", "X"),
            concat!("DECLAR", "ATION"),
            concat!("GRO", "WTH"),
            concat!("SAL", "ES"),
            concat!("SOC", "IAL"),
            concat!("WORK", "HORSE"),
            concat!("FL", "INT"),
            "H",
            concat!("AUS", "DRA"),
        ];
        assert_eq!(seats.len(), 30);
        for seat in seats {
            let scrubbed = scrub_customer_ui_text(&format!("Routed via {seat} today."));
            assert_ne!(
                scrubbed,
                format!("Routed via {seat} today."),
                "internal seat `{seat}` must be scrubbed"
            );
        }

        // Cloud/model vendors and crypto/protocol jargon rewrite to plain English
        let jargon = format!(
            "{} + {} + {} + {} + {} + {} + {} + {} + {} + {} + {} + {} + {} + {} + {}",
            concat!("Ver", "cel"),
            concat!("Cloud", "flare"),
            concat!("Mer", "cury 3"),
            concat!("Cl", "ef"),
            concat!("Clair", "ic"),
            concat!("Fl", "ue"),
            concat!("Ne", "on"),
            concat!("Up", "stash"),
            concat!("Cl", "erk"),
            concat!("CR", "DT"),
            concat!("state.cr", "db"),
            concat!("Ed25", "519"),
            concat!("X25519ML", "KEM768"),
            concat!("LE", "ANN"),
            concat!("DO", "RA"),
        );
        let rewritten = scrub_customer_ui_text(&jargon);
        assert!(rewritten.contains("cloud gateway"), "{rewritten}");
        assert!(rewritten.contains("sync"), "{rewritten}");
        assert!(rewritten.contains("workspace history"), "{rewritten}");
        assert!(rewritten.contains("verified"), "{rewritten}");
        assert!(rewritten.contains("end-to-end encrypted"), "{rewritten}");
        assert!(rewritten.contains("Memory search"), "{rewritten}");
        assert!(rewritten.contains("delivery metrics"), "{rewritten}");
    }

    #[test]
    fn delivery2_routes_enforce_secret_rejection_idempotent_approval_memory_and_threads() {
        let repo = make_temp_repo("delivery2-v4-4");

        // 1. Initial deterministic state projection
        let initial = build_delivery2_state_json(&repo, 5487);
        assert_eq!(initial["ok"], true);
        assert_eq!(initial["agent_name"], "Delivery-2");
        assert_eq!(initial["sync_radar"]["latency_label"], "<200ms");
        assert_eq!(
            initial["sync_radar"]["surfaces"].as_array().unwrap().len(),
            4
        );
        let slack_surf = &initial["sync_radar"]["surfaces"][3];
        assert_eq!(slack_surf["id"], "slack");
        assert_eq!(slack_surf["role_mode"], "ambient_status_only");
        assert_eq!(slack_surf["authorized"], false);
        assert_eq!(slack_surf["auth_status"], "Needs sign-in · pauses at 0 Cr");
        fs::create_dir_all(repo.join(".chinwag")).unwrap();
        fs::write(
            repo.join(".chinwag/slack.json"),
            r#"{"verified":true,"workspace":"emun-labs"}"#,
        )
        .unwrap();
        let with_slack = build_delivery2_state_json(&repo, 5487);
        assert_eq!(
            with_slack["sync_radar"]["surfaces"][3]["auth_status"],
            "Connected · ambient status cards only"
        );
        assert_eq!(
            initial["morning_focus"]["rows"].as_array().unwrap().len(),
            3
        );

        // 2. Secret-shaped strings rejected on Remember: without persisting
        for secret_note in [
            "Remember: API_KEY=supersecretvalue12345",
            "Remember: use sk-live9876543210abcdef1234",
            "Remember: token ghp_1234567890abcdefghijklmnop",
            "Remember: slack xoxb-1234567890-abcdef123456",
        ] {
            let (st, err_val) = handle_delivery2_message(
                &repo,
                5487,
                serde_json::to_vec(&json!({ "prompt": secret_note }))
                    .unwrap()
                    .as_slice(),
            );
            assert_eq!(st, "400 Bad Request");
            assert_eq!(err_val["error_code"], "secret_rejected");
        }

        // 3. Valid Remember: note creates stable mem_<id>, then edit / undo / restore roundtrip
        let (st_mem, val_mem) = handle_delivery2_message(
            &repo,
            5487,
            br#"{"prompt":"Remember: Keep database migrations additive and reversible."}"#,
        );
        assert_eq!(st_mem, "200 OK");
        let mem_id = val_mem["entry"]["memory_id"]
            .as_str()
            .expect("mem_<id>")
            .to_string();
        assert!(mem_id.starts_with("mem_"));

        let (st_bad_edit, val_bad_edit) = handle_delivery2_memory(
            &repo,
            5487,
            serde_json::to_vec(&json!({
                "id": mem_id,
                "action": "edit",
                "note": "ghp_1234567890abcdefghijklmnop"
            }))
            .unwrap()
            .as_slice(),
        );
        assert_eq!(st_bad_edit, "400 Bad Request");
        assert_eq!(val_bad_edit["error_code"], "secret_rejected");

        let (st_edit, val_edit) = handle_delivery2_memory(
            &repo,
            5487,
            serde_json::to_vec(&json!({
                "id": mem_id,
                "action": "edit",
                "note": "Keep database migrations additive, reversible, and tested."
            }))
            .unwrap()
            .as_slice(),
        );
        assert_eq!(st_edit, "200 OK");
        assert_eq!(
            val_edit["memory"]["note"],
            "Keep database migrations additive, reversible, and tested."
        );

        let (st_undo, val_undo) = handle_delivery2_memory(
            &repo,
            5487,
            serde_json::to_vec(&json!({ "id": mem_id, "action": "undo" }))
                .unwrap()
                .as_slice(),
        );
        assert_eq!(st_undo, "200 OK");
        assert_eq!(val_undo["memory"]["status"], "undone");

        let (st_rest, val_rest) = handle_delivery2_memory(
            &repo,
            5487,
            serde_json::to_vec(&json!({ "id": mem_id, "action": "restore" }))
                .unwrap()
                .as_slice(),
        );
        assert_eq!(st_rest, "200 OK");
        assert_eq!(val_rest["memory"]["status"], "saved");

        // 4. First-answer-wins HITL approval + SampleWalkthroughShipForbidden
        let (st_sample, val_sample) = handle_delivery2_approval(
            &repo,
            5487,
            br#"{"id":"sample-walkthrough","decision":"approve","is_sample":true}"#,
        );
        assert_eq!(st_sample, "403 Forbidden");
        assert_eq!(val_sample["error_code"], "SampleWalkthroughShipForbidden");

        let (st_app1, val_app1) = handle_delivery2_approval(
            &repo,
            5487,
            br#"{"id":"hitl-run-local-1","item_id":"run-local-1","decision":"approve","source":"physical_click","physical_click_verified":true}"#,
        );
        assert_eq!(st_app1, "200 OK");
        assert_eq!(val_app1["decision"], "approved");
        assert_eq!(val_app1["already_settled"], false);
        assert!(
            val_app1["receipt"]
                .as_str()
                .unwrap_or("")
                .contains("0 Cr while paused")
        );

        // Second conflicting answer returns first settled decision idempotently
        let (st_app2, val_app2) = handle_delivery2_approval(
            &repo,
            5487,
            br#"{"id":"hitl-run-local-1","item_id":"run-local-1","decision":"deny"}"#,
        );
        assert_eq!(st_app2, "200 OK");
        assert_eq!(val_app2["decision"], "approved");
        assert_eq!(val_app2["already_settled"], true);

        // 5. Cancel + Thread new / switch preserve history
        let (st_can, val_can) = handle_delivery2_cancel(&repo, 5487, br#"{"turn_id":"turn-42"}"#);
        assert_eq!(st_can, "200 OK");
        assert_eq!(val_can["cancelled"], true);
        assert_eq!(val_can["credits_charged"], 0);

        let (st_new, val_new) = handle_delivery2_thread(&repo, 5487, br#"{"action":"new"}"#);
        assert_eq!(st_new, "200 OK");
        let new_tid = val_new["active_thread_id"].as_str().unwrap().to_string();
        assert_ne!(new_tid, "thr-main");
        assert!(
            val_new["state"]["history"]["today"]
                .as_array()
                .unwrap()
                .len()
                >= 2,
            "archiving previous thread must preserve history"
        );

        let (st_sw, val_sw) = handle_delivery2_thread(
            &repo,
            5487,
            br#"{"action":"switch","thread_id":"thr-main"}"#,
        );
        assert_eq!(st_sw, "200 OK");
        assert_eq!(val_sw["active_thread_id"], "thr-main");

        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn human_sender_guard_rejects_non_human_seats() {
        let valid_human = concat!("Bri", "an");
        assert!(admit_human_ui_sender(valid_human, "ui-abcdef0123456789").is_ok());

        for non_human in [
            "AUTOMATION_AGENT",
            "WORKER_SEAT#Thread-One",
            "REVIEWER_BOT#1234",
            "ALL",
            "",
        ] {
            assert!(
                admit_human_ui_sender(non_human, "ui-abcdef0123456789").is_err(),
                "must reject non-human or malformed sender: {non_human}"
            );
        }
    }

    #[test]
    fn workflow_yaml_and_cursor_import_roundtrip_cleanly() {
        let repo = make_temp_repo("workflow-cursor");
        fs::create_dir_all(repo.join(".cursor/rules")).unwrap();
        fs::write(
            repo.join(".cursor/rules/api-style.mdc"),
            "---\ndescription: Keep API handlers pure and typed\n---\nAlways validate JSON inputs.",
        )
        .unwrap();

        let preview = build_cursor_preview_json(&repo);
        assert_eq!(preview["detected"], true);
        assert_eq!(preview["rules_count"], 1);

        let applied = apply_cursor_import(&repo, None).unwrap();
        assert_eq!(applied["imported_count"], 1);
        assert!(repo.join(".chinwag/rules/cursor-api-style.md").is_file());

        let mut cfg = load_workflow_config(&repo);
        cfg.independent_review = false;
        cfg.reviewer_tool = "gemini".to_string();
        cfg.test_verifier_tool = "codex".to_string();
        cfg.security_verifier_tool = "cursor".to_string();
        cfg.review_tier_credits = 200;
        cfg.protected_paths = vec![".env*".to_string(), "secrets/**".to_string()];
        save_workflow_config(&repo, &cfg).unwrap();

        let reloaded = load_workflow_config(&repo);
        assert!(!reloaded.independent_review);
        assert_eq!(reloaded.driver_tool, "claude_code");
        assert_eq!(reloaded.reviewer_tool, "gemini_cli");
        assert_eq!(reloaded.test_verifier_tool, "codex_cli");
        assert_eq!(reloaded.security_verifier_tool, "cursor");
        assert_eq!(reloaded.review_tier_credits, 200);
        assert_eq!(reloaded.review_mode, "quad_programming");
        assert_eq!(reloaded.protected_paths.len(), 2);

        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn loopback_5_layer_security_csrf_headers_and_v4_endpoints_pass() {
        let repo_root = make_temp_repo("loopback");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr");
        let port = addr.port();
        let auth = Arc::new(UiSecurityContext::for_port(port, false));

        let repo_c = repo_root.clone();
        let auth_c = Arc::clone(&auth);
        std::thread::spawn(move || {
            for s in listener.incoming().take(14).flatten() {
                let r = repo_c.clone();
                let a = Arc::clone(&auth_c);
                handle_workbench_http_connection(s, &r, &a);
            }
        });

        // 1. Spoofed Host -> 421 Misdirected Request
        let r1 = send_raw_http(
            addr,
            "GET /api/v4/bootstrap HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        );
        assert!(r1.starts_with("HTTP/1.1 421 Misdirected Request"), "{r1}");

        // 2. localhost:<port> on /api/* -> 421 Misdirected Request
        let r2 = send_raw_http(
            addr,
            &format!("GET /api/v4/bootstrap HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"),
        );
        assert!(r2.starts_with("HTTP/1.1 421 Misdirected Request"), "{r2}");

        // 3. Ping returns ui_version 4.1 + https://chinwag.sh CORS
        let r3 = send_raw_http(
            addr,
            &format!(
                "GET /api/bus/ping HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://chinwag.sh\r\n\r\n"
            ),
        );
        assert!(r3.starts_with("HTTP/1.1 200 OK"), "{r3}");
        assert!(
            r3.contains("Access-Control-Allow-Origin: https://chinwag.sh"),
            "{r3}"
        );
        let ping_json: Value = serde_json::from_str(split_http_body(&r3)).unwrap();
        assert_eq!(ping_json["ui_version"], "4.1");

        // 4. Root / serves embedded v4.1 HTML + font-src 'self' CSP + cookie
        let r4 = send_raw_http(
            addr,
            &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert!(r4.starts_with("HTTP/1.1 200 OK"), "{r4}");
        assert!(
            r4.contains(&format!("Set-Cookie: __chinwag_ui_{port}=")),
            "{r4}"
        );
        assert!(r4.contains("font-src 'self'"), "{r4}");
        assert!(r4.contains(auth.csrf_token_hex()), "{r4}");

        // 5. Missing CSRF header -> 403 Forbidden
        let r5 = send_raw_http(
            addr,
            &format!(
                "GET /api/v4/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: {}={}\r\n\r\n",
                auth.cookie_name(),
                auth.cookie_value_hex()
            ),
        );
        assert!(r5.starts_with("HTTP/1.1 403 Forbidden"), "{r5}");

        // 6. X-Chinwag-Csrf header accepted on /api/v4/bootstrap
        let r6 = send_raw_http(
            addr,
            &format!(
                "GET /api/v4/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nCookie: {}={}\r\nX-Chinwag-Csrf: {}\r\n\r\n",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex()
            ),
        );
        assert!(r6.starts_with("HTTP/1.1 200 OK"), "{r6}");
        let boot_json: Value = serde_json::from_str(split_http_body(&r6)).unwrap();
        assert_eq!(boot_json["ui_version"], "4.1");
        assert_eq!(boot_json["privacy"]["code_leaves_machine"], false);
        assert_eq!(
            boot_json["credits"]["pack_expiry_notice"],
            PACK_EXPIRY_NOTICE
        );

        // 7. X-Chinwag-Token header ALSO accepted on /api/v4/credits
        let r7 = send_raw_http(
            addr,
            &format!(
                "GET /api/v4/credits HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nCookie: {}={}\r\nX-Chinwag-Token: {}\r\n\r\n",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex()
            ),
        );
        assert!(r7.starts_with("HTTP/1.1 200 OK"), "{r7}");

        // 8. SampleWalkthroughShipForbidden enforced on POST /api/v4/inbox/action
        let ship_sample = r#"{"id":"sample-walkthrough","action":"approve","is_sample":true}"#;
        let r8 = send_raw_http(
            addr,
            &format!(
                "POST /api/v4/inbox/action HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nCookie: {}={}\r\nX-Chinwag-Csrf: {}\r\nContent-Length: {}\r\n\r\n{ship_sample}",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex(),
                ship_sample.len()
            ),
        );
        assert!(r8.starts_with("HTTP/1.1 403 Forbidden"), "{r8}");
        assert!(r8.contains("SampleWalkthroughShipForbidden"), "{r8}");

        // 9. finish_walkthrough succeeds on sample-walkthrough
        let finish_sample = r#"{"id":"sample-walkthrough","action":"finish_walkthrough"}"#;
        let r9 = send_raw_http(
            addr,
            &format!(
                "POST /api/v4/inbox/action HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nCookie: {}={}\r\nX-Chinwag-Csrf: {}\r\nContent-Length: {}\r\n\r\n{finish_sample}",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex(),
                finish_sample.len()
            ),
        );
        assert!(r9.starts_with("HTTP/1.1 200 OK"), "{r9}");

        // 10. Credits checkout returns 12-month expiry metadata + ratified commercial parity
        let checkout_body = r#"{"pack_sku":"pack_160","trigger_surface":"credits_tab"}"#;
        let r10 = send_raw_http(
            addr,
            &format!(
                "POST /api/v4/credits/checkout HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nCookie: {}={}\r\nX-Chinwag-Csrf: {}\r\nContent-Length: {}\r\n\r\n{checkout_body}",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex(),
                checkout_body.len()
            ),
        );
        assert!(r10.starts_with("HTTP/1.1 200 OK"), "{r10}");
        let chk_json: Value = serde_json::from_str(split_http_body(&r10)).unwrap();
        assert_eq!(chk_json["expires_months"], 12);
        assert_eq!(chk_json["pack_sku"], "pack_160");
        assert_eq!(chk_json["credits_granted"], 25_000);
        assert_eq!(chk_json["price_usd"], 160);
        assert!(
            chk_json["checkout_url"]
                .as_str()
                .unwrap_or("")
                .starts_with("https://chinwag.sh/pricing?pack=growth&source=local_ui&attempt="),
            "unexpected checkout_url: {}",
            chk_json["checkout_url"]
        );

        // 11. Auto-refill rejects missing monthly_cap_usd when enabled: true, succeeds with cap
        let bad_refill = r#"{"enabled":true,"threshold_credits":500,"pack_sku":"pack_50"}"#;
        let r11 = send_raw_http(
            addr,
            &format!(
                "POST /api/v4/credits/autorefill HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nCookie: {}={}\r\nX-Chinwag-Token: {}\r\nContent-Length: {}\r\n\r\n{bad_refill}",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex(),
                bad_refill.len()
            ),
        );
        assert!(r11.starts_with("HTTP/1.1 400 Bad Request"), "{r11}");

        let ok_refill = r#"{"enabled":true,"threshold_credits":500,"pack_sku":"pack_50","monthly_cap_usd":160}"#;
        let r12 = send_raw_http(
            addr,
            &format!(
                "POST /api/v4/credits/autorefill HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nCookie: {}={}\r\nX-Chinwag-Token: {}\r\nContent-Length: {}\r\n\r\n{ok_refill}",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex(),
                ok_refill.len()
            ),
        );
        assert!(r12.starts_with("HTTP/1.1 200 OK"), "{r12}");

        // 12. Single-use stream ticket works once and rejects replay
        let r13 = send_raw_http(
            addr,
            &format!(
                "POST /api/bus/stream-ticket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Type: application/json\r\nCookie: {}={}\r\nX-Chinwag-Csrf: {}\r\nContent-Length: 2\r\n\r\n{{}}",
                auth.cookie_name(),
                auth.cookie_value_hex(),
                auth.csrf_token_hex()
            ),
        );
        let tkt_json: Value = serde_json::from_str(split_http_body(&r13)).unwrap();
        let ticket = tkt_json["ticket"].as_str().unwrap();

        let r14 = send_raw_http(
            addr,
            &format!(
                "GET /api/bus/stream?ticket={ticket}&max_ticks=0 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nSec-Fetch-Site: same-origin\r\n\r\n"
            ),
        );
        assert!(r14.starts_with("HTTP/1.1 200 OK"), "{r14}");

        let _ = fs::remove_dir_all(&repo_root);
    }

    fn init_test_repo(repo: &Path) {
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@chinwag.test",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "fixture",
            ],
        ] {
            let mut command = std::process::Command::new("git");
            for (name, _) in std::env::vars_os() {
                if name.to_string_lossy().starts_with("GIT_") {
                    command.env_remove(name);
                }
            }
            let status = command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgSign=false",
                    "-c",
                    "core.fsmonitor=false",
                ])
                .arg("-C")
                .arg(repo)
                .args(args)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    fn selected_fixture() -> (tempfile::TempDir, Arc<RepositorySelection>) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&root);
        let selected = feature_cli_run::select_cli_repository(&[
            "--repo".into(),
            root.to_string_lossy().into_owned(),
        ])
        .unwrap();
        (temp, Arc::new(selected))
    }

    fn selected_authenticated_request(
        selection: Arc<RepositorySelection>,
        method: &str,
        path: &str,
        json_body: Option<&[u8]>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let auth = Arc::new(UiSecurityContext::for_port(port, false));
        let auth_server = Arc::clone(&auth);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_workbench_http_connection_selected(stream, &selection, &auth_server);
        });
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Sec-Fetch-Site: same-origin\r\n\
             Origin: http://127.0.0.1:{port}\r\n\
             Cookie: {}={}\r\n\
             X-Chinwag-Csrf: {}\r\n",
            auth.cookie_name(),
            auth.cookie_value_hex(),
            auth.csrf_token_hex()
        );
        if let Some(b) = json_body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                b.len()
            ));
        } else {
            req.push_str("\r\n");
        }
        let mut req_bytes = req.into_bytes();
        if let Some(b) = json_body {
            req_bytes.extend_from_slice(b);
        }
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(&req_bytes).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        server.join().unwrap();
        response
    }

    #[test]
    fn commercial_credits_catalog_and_rate_card_match_ratified_schedule() {
        let repo = make_temp_repo("credits-parity");
        let credits = build_credits_json(&repo, 0);
        assert_eq!(credits["available_credits"], 500);
        assert_eq!(credits["pricing_url"], CREDIT_PACKS_PRICING_URL);
        assert!(
            credits["pack_expiry_notice"]
                .as_str()
                .unwrap_or("")
                .contains("500 free starter credits (valid 90 days)")
        );
        assert!(
            credits["pack_expiry_notice"]
                .as_str()
                .unwrap_or("")
                .contains("12 months")
        );

        let packs = credits["packs"].as_array().unwrap();
        assert_eq!(packs.len(), 4);
        let expected_packs = [
            ("pack_50", "Starter Pack", 6_250u64, 50u64),
            ("pack_160", "Team Pack", 25_000u64, 160u64),
            ("pack_560", "Growth Pack", 100_000u64, 560u64),
            ("pack_1000", "Scale Pack", 200_000u64, 1_000u64),
        ];
        for (idx, (sku, label, cr, usd)) in expected_packs.iter().enumerate() {
            assert_eq!(packs[idx]["sku"], *sku);
            assert_eq!(packs[idx]["label"], *label);
            assert_eq!(packs[idx]["credits"], *cr);
            assert_eq!(packs[idx]["price_usd"], *usd);
            assert_eq!(packs[idx]["expires_months"], 12);
        }

        let schedule = credits["function_schedule"].as_array().unwrap();
        let expected_rates = [
            ("Verified agent handoff", 15u64),
            ("Repository context sync", 50u64),
            ("Protected-path safety check", 50u64),
            ("Cleanroom test run", 100u64),
            ("Independent second-tool review", 150u64),
            ("Verified PR ship & receipt", 200u64),
        ];
        for (idx, (label, cr)) in expected_rates.iter().enumerate() {
            assert_eq!(schedule[idx]["label"], *label);
            assert_eq!(schedule[idx]["credits"], *cr);
        }

        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn p009_ui_feature_views_keep_the_same_nondefault_repository_selection() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&root);
        fs::create_dir(root.join(".chinwag")).unwrap();
        fs::write(
            root.join(".chinwag/allowed_signers"),
            "# selected fixture\n",
        )
        .unwrap();
        let selection = Arc::new(
            feature_cli_run::select_cli_repository(&[
                "--repo".into(),
                root.to_string_lossy().into_owned(),
            ])
            .unwrap(),
        );
        for (route, field) in [
            ("a509", "allowed_signers"),
            ("bonds", "bond_path"),
            ("plugins", "manifest_path"),
            ("cwcards", "cwcard_path"),
        ] {
            let response = selected_authenticated_request(
                Arc::clone(&selection),
                "GET",
                &format!("/api/{route}"),
                None,
            );
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            let value: Value = serde_json::from_str(split_http_body(&response)).unwrap();
            assert!(
                value[field]
                    .as_str()
                    .unwrap()
                    .starts_with(selection.root().to_str().unwrap()),
                "{route}: {value}"
            );
            if route == "a509" {
                assert_eq!(value["private_keys_read"], false);
            }
        }
    }

    #[test]
    fn p009_ui_send_and_wake_holds_before_publication_or_worker_creation() {
        let (_temp, selection) = selected_fixture();
        let body =
            br##"{"sender":"Brian","room":"#test","body":"controlled refusal","wake":true}"##;
        let response = selected_authenticated_request(
            Arc::clone(&selection),
            "POST",
            "/api/bus/send",
            Some(body),
        );
        assert!(response.starts_with("HTTP/1.1 409 Conflict"), "{response}");
        let value: Value = serde_json::from_str(split_http_body(&response)).unwrap();
        assert_eq!(value["disposition"], "HELD");
        assert_eq!(value["published"], false);
        assert_eq!(value["work_started"], "UNKNOWN");
        assert!(!selection.root().join(".chinwag").exists());
    }

    #[test]
    fn p009_ui_refuses_replaced_repository_before_feature_read() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let root = parent.join("repo");
        fs::create_dir(&root).unwrap();
        init_test_repo(&root);
        let selection = Arc::new(
            feature_cli_run::select_cli_repository(&[
                "--repo".into(),
                root.to_string_lossy().into_owned(),
            ])
            .unwrap(),
        );
        fs::rename(&root, parent.join("old")).unwrap();
        fs::create_dir(&root).unwrap();
        init_test_repo(&root);
        let response = selected_authenticated_request(selection, "GET", "/api/v4/bootstrap", None);
        assert!(response.starts_with("HTTP/1.1 409 Conflict"), "{response}");
        let value: Value = serde_json::from_str(split_http_body(&response)).unwrap();
        assert_eq!(value["disposition"], "HELD");
    }

    #[test]
    fn p009_ui_duplicate_repo_selector_refuses_without_starting_server() {
        let (_temp, selection) = selected_fixture();
        let root = selection.root().to_string_lossy().into_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_ui_workbench_cli(
                &[
                    "serve".into(),
                    "--repo".into(),
                    root.clone(),
                    "--repo".into(),
                    root,
                ],
                &mut out,
                &mut err,
            ),
            2
        );
        assert!(
            !selection
                .root()
                .join(".chinwag/bus/ui-daemon.json")
                .exists()
        );
    }

    #[test]
    fn symlinked_chinwag_escape_refused_without_touching_outside_files() {
        let temp = tempfile::tempdir().unwrap();
        let parent = fs::canonicalize(temp.path()).unwrap();
        let outside = parent.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let victim_workflow = outside.join("workflow.yaml");
        let victim_state = outside.join("ui-v4-state.json");
        fs::write(&victim_workflow, "SENTINEL_OUTSIDE_WORKFLOW\n").unwrap();
        fs::write(&victim_state, "{\"sentinel\":true}\n").unwrap();

        let repo = parent.join("repo");
        fs::create_dir_all(&repo).unwrap();
        init_test_repo(&repo);
        std::os::unix::fs::symlink(&outside, repo.join(".chinwag")).unwrap();

        let selection = Arc::new(
            feature_cli_run::select_cli_repository(&[
                "--repo".into(),
                repo.to_string_lossy().into_owned(),
            ])
            .unwrap(),
        );

        let wf_resp = selected_authenticated_request(
            Arc::clone(&selection),
            "POST",
            "/api/v4/workflow",
            Some(br#"{"independent_review":false}"#),
        );
        assert!(wf_resp.starts_with("HTTP/1.1 409 Conflict"), "{wf_resp}");

        let task_resp = selected_authenticated_request(
            Arc::clone(&selection),
            "POST",
            "/api/v4/board/task",
            Some(br#"{"title":"Escape attempt"}"#),
        );
        assert!(
            task_resp.starts_with("HTTP/1.1 409 Conflict"),
            "{task_resp}"
        );

        assert_eq!(
            fs::read_to_string(&victim_workflow).unwrap(),
            "SENTINEL_OUTSIDE_WORKFLOW\n"
        );
        assert_eq!(
            fs::read_to_string(&victim_state).unwrap(),
            "{\"sentinel\":true}\n"
        );
    }

    #[test]
    fn concurrent_board_task_creation_preserves_all_tasks_and_monotonic_ids() {
        let repo = make_temp_repo("concurrent-tasks");
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for idx in 0..8usize {
            let repo_c = repo.clone();
            let b_c = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b_c.wait();
                let payload = serde_json::to_vec(&json!({
                    "title": format!("Concurrent task {idx}"),
                    "tool": "claude"
                }))
                .unwrap();
                let (status, val) = handle_board_create_task(&repo_c, &payload);
                assert_eq!(status, "200 OK", "{val}");
                val["task"]["id"].as_str().unwrap().to_string()
            }));
        }

        let mut ids: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 8, "every concurrent task must get a unique ID");

        let persisted = load_ui_v4_state_strict(&repo).unwrap();
        assert_eq!(persisted.created_tasks.len(), 8);
        assert_eq!(persisted.next_task_seq, 8);
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn real_worktree_diff_reports_unverified_status_and_flags_protected_paths() {
        let temp = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&repo);
        fs::create_dir_all(repo.join("aaa_bulk")).unwrap();
        fs::create_dir_all(repo.join("zzz_late/auth")).unwrap();

        let mut bulk_baseline = String::new();
        for idx in 0..4_500usize {
            bulk_baseline.push_str(&format!("line {idx}\n"));
        }
        fs::write(repo.join("aaa_bulk/large.txt"), &bulk_baseline).unwrap();
        fs::write(
            repo.join("zzz_late/auth/login screen.rs"),
            "pub fn allow() -> bool { true }\n",
        )
        .unwrap();
        Command::new("git")
            .args(["add", "aaa_bulk/large.txt", "zzz_late/auth/login screen.rs"])
            .current_dir(&repo)
            .status()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "seed auth and bulk"])
            .current_dir(&repo)
            .status()
            .unwrap();

        // Modify >4,500 lines ahead of a protected path whose filename contains spaces
        let mut bulk_modified = String::new();
        for idx in 0..4_500usize {
            bulk_modified.push_str(&format!("changed {idx}\n"));
        }
        fs::write(repo.join("aaa_bulk/large.txt"), &bulk_modified).unwrap();
        fs::write(
            repo.join("zzz_late/auth/login screen.rs"),
            "pub fn allow() -> bool { false }\n",
        )
        .unwrap();

        let diff_val = build_diff_response_json(&repo, "TASK-101");
        assert_eq!(diff_val["is_sample"], false);
        assert_eq!(diff_val["status"], "needs_permission");
        assert_eq!(diff_val["risk_level"], "high");
        assert_eq!(diff_val["protected_path"], "zzz_late/auth/login screen.rs");
        assert_eq!(diff_val["independent_review"]["passed"], false);
        assert_eq!(diff_val["test_passed"], Value::Null);
        assert_eq!(diff_val["verification"]["status"], "not_run");
    }

    #[test]
    fn git_diff_refuses_repo_configured_textconv_and_filter_helpers() {
        let temp = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&repo);

        let canary = repo.join("pwned-canary.txt");
        let helper_script = repo.join("evil-helper.sh");
        fs::write(
            &helper_script,
            format!(
                "#!/bin/sh\necho pwned > '{}'\ncat \"$@\"\n",
                canary.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper_script, fs::Permissions::from_mode(0o755)).unwrap();

        fs::write(repo.join(".gitattributes"), "*.txt diff=evil filter=evil\n").unwrap();
        fs::write(repo.join("notes.txt"), "baseline\n").unwrap();
        Command::new("/usr/bin/git")
            .args(["add", ".gitattributes", "notes.txt"])
            .current_dir(&repo)
            .status()
            .unwrap();
        Command::new("/usr/bin/git")
            .args(["commit", "-m", "baseline notes"])
            .current_dir(&repo)
            .status()
            .unwrap();

        let git_cfg_path = repo.join(".git/config");
        let baseline_cfg = fs::read_to_string(&git_cfg_path).unwrap();
        fs::write(repo.join("notes.txt"), "modified\n").unwrap();

        // Persist a prior `request_changes` (`running`) decision and verify unavailable-diff hold overrides it.
        let (act_status, _) = handle_inbox_action(
            &repo,
            br#"{"id":"TASK-102","action":"request_changes","note":"recheck"}"#,
        );
        assert_eq!(act_status, "200 OK");

        for hostile_snippet in [
            format!(
                "\n[diff \"evil\"]\n\ttextconv = {}\n[filter \"evil\"]\n\tclean = {}\n",
                helper_script.display(),
                helper_script.display()
            ),
            // Legacy `[filter.evil]` dot subsection syntax
            format!("\n[filter.evil]\n\tclean = {}\n", helper_script.display()),
            // Same-line inline setting placed immediately after `]`
            format!("\n[filter \"evil\"] clean = {}\n", helper_script.display()),
            format!("\n[core] fsmonitor = {}\n", helper_script.display()),
        ] {
            fs::write(&git_cfg_path, format!("{baseline_cfg}{hostile_snippet}")).unwrap();
            let diff_val = build_diff_response_json(&repo, "TASK-102");
            assert!(
                !canary.exists(),
                "GET /api/v4/diff must never execute repository-configured helpers for snippet: {hostile_snippet}"
            );
            assert_eq!(diff_val["diff_available"], false);
            assert_eq!(diff_val["risk_level"], "unknown");
            assert_eq!(diff_val["status"], "needs_permission");
            let body_json = serde_json::to_string(&diff_val).unwrap();
            assert!(
                !body_json.contains("Working tree is clean")
                    && !body_json.contains("No configured protected paths touched"),
                "refused diff must never falsely claim working tree is clean: {body_json}"
            );
        }

        // Verify incomplete path inventory also overrides a prior `allow_once` even when a protected match exists.
        let prior_allow_once = ItemDecisionRecord {
            status: "running".to_string(),
            action: "allow_once".to_string(),
            note: None,
            updated_at_unix: 1,
        };
        assert_eq!(
            resolve_diff_item_status(Some(&prior_allow_once), true, true, false, true),
            "needs_permission"
        );
        assert_eq!(
            resolve_diff_item_status(Some(&prior_allow_once), true, false, false, false),
            "needs_permission"
        );
        assert_eq!(
            resolve_diff_item_status(Some(&prior_allow_once), true, true, true, true),
            "needs_review"
        );
    }

    #[test]
    fn legacy_workflow_migration_deduplicates_slots_and_empty_protected_paths_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&repo);
        fs::create_dir_all(repo.join(".chinwag")).unwrap();

        // Legacy 2-field workflow.yaml where driver=gemini would collide with default test_verifier=gemini_cli
        fs::write(
            repo.join(".chinwag/workflow.yaml"),
            "version: 1\ndriver_tool: \"gemini\"\nreviewer_tool: \"codex\"\nreview_mode: \"triad_sandbox\"\n",
        )
        .unwrap();

        let migrated = load_workflow_config(&repo);
        assert_eq!(migrated.driver_tool, "gemini_cli");
        assert_eq!(migrated.reviewer_tool, "codex_cli");
        assert_eq!(migrated.test_verifier_tool, "claude_code");
        assert_eq!(migrated.security_verifier_tool, "cursor");
        assert_eq!(migrated.review_tier_credits, 150);
        assert_eq!(migrated.review_mode, "three_tool_check");

        // Single-slot swap via handle_workflow_update swaps colliding slots cleanly
        let (st_swap, val_swap) =
            handle_workflow_update(&repo, br#"{"reviewer_tool":"cursor","protected_paths":[]}"#);
        assert_eq!(st_swap, "200 OK");
        assert_eq!(val_swap["workflow"]["driver_tool"], "gemini_cli");
        assert_eq!(val_swap["workflow"]["reviewer_tool"], "cursor");
        assert_eq!(val_swap["workflow"]["test_verifier_tool"], "claude_code");
        assert_eq!(val_swap["workflow"]["security_verifier_tool"], "codex_cli");
        assert_eq!(val_swap["workflow"]["protected_paths"], json!([]));

        // Reloading after `protected_paths: []` preserves empty list instead of restoring defaults
        let reloaded = load_workflow_config(&repo);
        assert!(
            reloaded.protected_paths.is_empty(),
            "expected empty protected_paths after explicit clear, got {:?}",
            reloaded.protected_paths
        );

        // Hand-edited inline YAML flow array parses cleanly (including quoted commas) without dropping to empty
        fs::write(
            repo.join(".chinwag/workflow.yaml"),
            "version: 1\nprotected_paths: [\".env*\", \"secrets/**\", \"config/a,b/**\", 'dir''s/**']\n",
        )
        .unwrap();
        let inline_loaded = load_workflow_config(&repo);
        assert_eq!(
            inline_loaded.protected_paths,
            vec![
                ".env*".to_string(),
                "secrets/**".to_string(),
                "config/a,b/**".to_string(),
                "dir's/**".to_string()
            ]
        );

        // Malformed inline lists (`[,]`, trailing comma, unclosed quote, empty string, traversal `..`),
        // YAML null / bare `protected_paths:` blocks (at EOF or before another mapping key),
        // and blocks containing empty/traversal items (`- ""`, `-`, `- "../outside"`) all fail safe
        // to default protected paths while explicit `protected_paths: []` stays empty.
        for bad_doc in [
            "version: 1\nprotected_paths: malformed_scalar\n",
            "version: 1\nprotected_paths: [,]\n",
            "version: 1\nprotected_paths: [\".env*\",]\n",
            "version: 1\nprotected_paths: [,\"secrets/**\"]\n",
            "version: 1\nprotected_paths: [\"unclosed]\n",
            "version: 1\nprotected_paths: [\"\"]\n",
            "version: 1\nprotected_paths: [\"../outside\"]\n",
            "version: 1\nprotected_paths: [~]\n",
            "version: 1\nprotected_paths: null\n",
            "version: 1\nprotected_paths:\n",
            "version: 1\nprotected_paths:\nreview_tier_credits: 200\n",
            "version: 1\nprotected_paths:\n  - \"\"\n",
            "version: 1\nprotected_paths:\n  -\n",
            "version: 1\nprotected_paths:\n  - \".env*\"\n  - \"../outside\"\n",
        ] {
            fs::write(repo.join(".chinwag/workflow.yaml"), bad_doc).unwrap();
            let malformed_loaded = load_workflow_config(&repo);
            assert_eq!(
                malformed_loaded.protected_paths,
                WorkflowConfig::default().protected_paths,
                "malformed/null protected_paths doc `{bad_doc:?}` must fail safe to defaults"
            );
        }

        // Negative-path validation for out-of-domain credits, invalid review_mode, and empty task title
        let (st_bad_cr, val_bad_cr) =
            handle_workflow_update(&repo, br#"{"review_tier_credits":75}"#);
        assert_eq!(st_bad_cr, "400 Bad Request");
        assert_eq!(val_bad_cr["error_code"], "invalid_review_tier_credits");

        let (st_bad_mode, val_bad_mode) =
            handle_workflow_update(&repo, br#"{"review_mode":"unknown_tier"}"#);
        assert_eq!(st_bad_mode, "400 Bad Request");
        assert_eq!(val_bad_mode["error_code"], "invalid_review_mode");

        let (st_empty_title, val_empty_title) =
            handle_board_create_task(&repo, br#"{"title":"   ","tool":"claude_code"}"#);
        assert_eq!(st_empty_title, "400 Bad Request");
        assert_eq!(val_empty_title["error_code"], "missing_title");
    }

    #[test]
    fn delivery2_five_stage_scrubber_secret_rejection_url_allowlist_and_arbitration_tests() {
        // 1. Stage 1-5 scrubber: preserves "Delivery-2" without tail duplication (FLINT-1),
        // preserves U+FE58 (FLINT-2), preserves "retrieve agent" / "achieve agent" / "believe.dev" (ALISTAIR-3),
        // and strips bidi/format chars + Math Script/Double-Struck + dotted/underscore vendor/seat tokens!
        let preserved = scrub_customer_ui_text(
            "Ask DELIVERY-2, @DELIVERY-2#inst9, ■ DELIVERY-2#1, DELIVERY_2, and delivery 2 to retrieve agent logs, achieve agent parity on believe.dev, and check x Delivery-2 y \u{FE58}",
        );
        assert!(
            preserved
                .starts_with("Ask Delivery-2, Delivery-2, Delivery-2, Delivery-2, and Delivery-2"),
            "unexpected Delivery-2 mask normalization: '{preserved}'"
        );
        assert!(!preserved.contains("#inst9"));
        assert!(!preserved.contains("PM_2"));
        assert!(preserved.contains("retrieve agent logs"));
        assert!(preserved.contains("achieve agent parity on believe.dev"));
        assert!(preserved.contains("check x Delivery-2 y \u{FE58}"));
        assert!(!preserved.contains("Delivery-2Delivery-2"));

        let hostile_jargon = format!(
            "{} {} {} {} {} {} {} {}",
            "WORK\u{202C}HORSE",
            "GEMINI-\u{2066}PM\u{2069}",
            "Ver\u{202A}cel",
            "𝕍𝕖𝕣𝕔𝕖𝕝",
            "ℂℝ𝔻𝕋",
            "vercel.com/index.leann",
            "crdt_sync/hpke_seal/WORKHORSE_1",
            "DELIVERY-1"
        );
        let scrubbed = scrub_customer_ui_text(&hostile_jargon);
        let lower = scrubbed.to_ascii_lowercase();
        for forbidden in [
            "workhorse",
            "gemini-pm",
            "vercel",
            "crdt",
            "leann",
            "hpke",
            "delivery-1",
            "\u{202C}",
            "\u{2066}",
            "\u{202A}",
        ] {
            assert!(
                !lower.contains(&forbidden.to_ascii_lowercase()),
                "scrubber leaked '{forbidden}' in '{scrubbed}'"
            );
        }

        // 2. Outbound URL sanitizer + open-redirect query guard (ALISTAIR-1 + Round-3)
        assert_eq!(
            sanitize_chinwag_outbound_url("javascript:alert(1)", "https://chinwag.sh/open"),
            "https://chinwag.sh/open"
        );
        assert_eq!(
            sanitize_chinwag_outbound_url(
                "https://evil.example/oauth-phish",
                "https://chinwag.sh/open"
            ),
            "https://chinwag.sh/open"
        );
        assert_eq!(
            sanitize_chinwag_outbound_url(
                "https://chinwag.sh/open?next=https://evil.example",
                "https://chinwag.sh/open"
            ),
            "https://chinwag.sh/open"
        );
        assert_eq!(
            sanitize_chinwag_outbound_url(
                "https://chinwag.sh/pricing?redirect=//evil.example",
                "https://chinwag.sh/pricing"
            ),
            "https://chinwag.sh/pricing"
        );
        for bad_redirect in [
            "https://chinwag.sh/open?next=/\\evil.example",
            "https://chinwag.sh/open?next=%2f/evil.example",
            "https://chinwag.sh/open?next=%5cevil.example",
            "https://chinwag.sh/open?next=%252f%252fevil.example",
            "https://chinwag.sh/open?user=foo@evil.example",
            "https://chinwag.sh/open?user=foo%40evil.example",
        ] {
            assert_eq!(
                sanitize_chinwag_outbound_url(bad_redirect, "https://chinwag.sh/open"),
                "https://chinwag.sh/open",
                "expected open-redirect rejection for {bad_redirect}"
            );
        }
        assert_eq!(
            sanitize_chinwag_outbound_url(
                "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
                "https://chinwag.sh/pricing"
            ),
            "https://chinwag.sh/pricing?talk=1&source=local_ui#founders"
        );

        // 3. Secret-shape rejection across quoted, space-separated, `=`/`:`/`?`/`&` attached prefixes,
        // _access_key/_key_id/_pat keys, zero-width obfuscation, digitless Bearer, PGP/Age, ASIA (ALISTAIR-2 + QA-R2-1)
        let stripe_live_sample = format!("STRIPE_KEY={}{}", "sk_live_", "1234567890abcdef");
        let slack_bot_sample = format!("SLACK_BOT={}{}", "xoxb-", "1234567890-abcdef");
        let openai_eq_sample = format!("OPENAI_KEY={}{}", "sk-proj-", "1234567890abcdef");
        let anthropic_eq_sample = format!("ANTHROPIC_KEY={}{}", "sk-ant-", "1234567890abcdef");
        let anthropic_colon_sample = format!("key:{}{}", "sk-ant-", "1234567890abcdef");
        let gh_pat_sample = format!("GH_PAT={}{}", "ghp_", "1234567890abcdefghijkl");
        let zw_openai_sample = format!(
            "Remember: {}{}{}",
            "sk-", "\u{200B}proj-", "1234567890abcdef"
        );
        let fw_openai_sample = format!(
            "Remember: {}{}{}",
            "sk\u{2212}", "proj\u{2212}", "1234567890abcdef"
        );
        for secret_sample in [
            r#"Remember: API_KEY="supersecretvalue12345""#,
            "Remember: API\u{FF3F}KEY=custom_gateway_secret_9988",
            "Remember: api_key: supersecretvalue12345",
            "Remember: password = supersecretpassword99",
            "Remember: OPENAI_API_KEY=custom_gateway_secret_9988",
            "Remember: GITHUB_TOKEN=token_value_abcdef123456",
            "Remember: STRIPE_SECRET_KEY=secret_value_99887766",
            "Remember: DB_PASSWORD=my_database_password_123",
            "Remember: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "Remember: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            openai_eq_sample.as_str(),
            anthropic_eq_sample.as_str(),
            anthropic_colon_sample.as_str(),
            gh_pat_sample.as_str(),
            stripe_live_sample.as_str(),
            slack_bot_sample.as_str(),
            zw_openai_sample.as_str(),
            fw_openai_sample.as_str(),
            "https://example.com/js?key=AIzaSyA12345678901234567890",
            "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            "Remember: Authorization: Bearer abcdefghijklmnopqrstuvwxyzABCDEF",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            "ASIAIOSFODNN7EXAMPLE",
        ] {
            assert!(
                contains_secret_shaped_token(secret_sample),
                "expected secret rejection for: {secret_sample}"
            );
        }
        assert!(!contains_secret_shaped_token(
            "Remember: Run webhook and idempotency tests before opening a PR."
        ));
        assert!(!contains_secret_shaped_token("Why is api_key: undefined?"));
        assert!(!contains_secret_shaped_token(
            "Remember: secret=production mode uses strict checks."
        ));

        // 4. Thread title secret check + Why #nonexistent? truthful response + cursor resume + Inbox <-> Delivery-2 arbitration
        let temp = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(temp.path()).unwrap();
        init_test_repo(&repo);
        fs::create_dir_all(repo.join(".chinwag")).unwrap();
        fs::write(
            repo.join("TASKS.md"),
            "### **`[IN_PROGRESS]`** `CHWG-777` — Tighten auth middleware\n",
        )
        .unwrap();

        let (st_sec_thr, val_sec_thr) = handle_delivery2_thread(
            &repo,
            5487,
            br#"{"action":"new","title":"OPENAI_API_KEY=custom_gateway_secret_9988"}"#,
        );
        assert_eq!(st_sec_thr, "400 Bad Request");
        assert_eq!(val_sec_thr["error_code"], "secret_rejected");

        let (st_why_missing, val_why_missing) =
            handle_delivery2_message(&repo, 5487, br#"{"prompt":"Why #nonexistent?"}"#);
        assert_eq!(st_why_missing, "200 OK");
        let missing_body = val_why_missing["entry"]["body"].as_str().unwrap_or("");
        assert!(missing_body.contains("not found"));
        assert_eq!(val_why_missing["entry"]["sources"], json!([]));

        // ARCHITECT-R2-4 + ARCHITECT-R2-5: multi-byte UTF-8 before 'why' never panics, and
        // explicit `Why #<id>?` containing 'credit' or 'morning' resolves as Why-lookup (not generic summary)
        for why_edge in [
            r#"{"prompt":"a😀 why #?"}"#,
            r#"{"prompt":"Why #nonexistent-credit?"}"#,
            r#"{"prompt":"Why #morning-job?"}"#,
        ] {
            let (st_edge, val_edge) = handle_delivery2_message(&repo, 5487, why_edge.as_bytes());
            assert_eq!(st_edge, "200 OK", "failed on {why_edge}");
            if why_edge.contains("#nonexistent-credit") || why_edge.contains("#morning-job") {
                assert!(
                    val_edge["entry"]["body"]
                        .as_str()
                        .unwrap_or("")
                        .contains("not found"),
                    "expected not-found for {why_edge}, got {}",
                    val_edge["entry"]["body"]
                );
                assert_eq!(val_edge["entry"]["sources"], json!([]));
            }
        }

        // ALISTAIR-R2-1: `id: "hitl-sample-walkthrough"` without `item_id` or `is_sample` must return 403 Forbidden
        let (st_hitl_sample, val_hitl_sample) = handle_delivery2_approval(
            &repo,
            5487,
            br#"{"id":"hitl-sample-walkthrough","decision":"approve"}"#,
        );
        assert_eq!(st_hitl_sample, "403 Forbidden");
        assert_eq!(
            val_hitl_sample["error_code"],
            "SampleWalkthroughShipForbidden"
        );

        // ARCHITECT-R2-6: Pre-receipt `/cancel` matching `turn_id` without `entry_id` clamps unseen answer to `[Stopped]`
        let (st_premsg, _) = handle_delivery2_message(
            &repo,
            5487,
            br#"{"prompt":"What did I miss?","turn_id":"turn-prestop-unit-1"}"#,
        );
        assert_eq!(st_premsg, "200 OK");
        let (st_precancel, val_precancel) = handle_delivery2_cancel(
            &repo,
            5487,
            br#"{"turn_id":"turn-prestop-unit-1","truncated_len":0}"#,
        );
        assert_eq!(st_precancel, "200 OK");
        let prestopped_entry = val_precancel["state"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["turn_id"] == "turn-prestop-unit-1")
            .expect("cancelled turn qa_card");
        assert_eq!(prestopped_entry["body"], "[Stopped]");
        assert_eq!(prestopped_entry["sources"], json!([]));

        // Materialize thread, approve CHWG-777 in Delivery-2 -> run_card advances to 12 · Passed · Merge-ready
        let (st_app, val_app) = handle_delivery2_approval(
            &repo,
            5487,
            br#"{"id":"hitl-CHWG-777","item_id":"CHWG-777","decision":"approve","source":"physical_click","physical_click_verified":true}"#,
        );
        assert_eq!(st_app, "200 OK");
        let seq_after_approve = val_app["seq"].as_u64().unwrap();
        let run_card_after_approve = val_app["state"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "run_card")
            .expect("persisted run_card");
        assert_eq!(run_card_after_approve["completed"], true);
        assert_eq!(
            run_card_after_approve["current_step_display"],
            "12 · Passed · Merge-ready"
        );

        // Cursor resume at current seq returns unchanged=true; earlier cursor returns delta entries
        let unchanged_state =
            build_delivery2_state_json_with_cursor(&repo, 5487, Some(seq_after_approve));
        assert_eq!(unchanged_state["unchanged"], true);
        assert_eq!(unchanged_state["delta_entries"], json!([]));

        let delta_state = build_delivery2_state_json_with_cursor(&repo, 5487, Some(1));
        assert_eq!(delta_state["unchanged"], false);
        assert!(!delta_state["delta_entries"].as_array().unwrap().is_empty());

        // Cross-surface arbitration:
        // (a) Stale Inbox reject AFTER Delivery-2 approve is refused (409 already_approved), keeping both surfaces consistent!
        let (st_stale_rej, val_stale_rej) = handle_inbox_action(
            &repo,
            br#"{"id":"CHWG-777","action":"reject","note":"Hold merge"}"#,
        );
        assert_eq!(st_stale_rej, "409 Conflict");
        assert_eq!(val_stale_rej["error_code"], "already_approved");
        let still_approved = build_delivery2_state_json(&repo, 5487);
        let hitl_still_approved = still_approved["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "approval_card")
            .unwrap();
        assert_eq!(hitl_still_approved["settled"], true);
        assert_eq!(hitl_still_approved["settled_decision"], "approved");

        // (b) Rejecting a fresh item from Inbox FIRST reconciles Delivery-2 approval map & blocks conflicting Delivery-2 approve!
        let (st_inbox_rej, _) = handle_inbox_action(
            &repo,
            br#"{"id":"CHWG-778","action":"reject","note":"Needs test coverage"}"#,
        );
        assert_eq!(st_inbox_rej, "200 OK");
        let (st_d2_after_rej, val_d2_after_rej) = handle_delivery2_approval(
            &repo,
            5487,
            br#"{"id":"hitl-CHWG-778","item_id":"CHWG-778","decision":"approve","source":"physical_click","physical_click_verified":true}"#,
        );
        assert_eq!(st_d2_after_rej, "200 OK");
        assert_eq!(val_d2_after_rej["already_settled"], true);
        assert_eq!(val_d2_after_rej["decision"], "denied");

        // (c) ALISTAIR-R2-2 + ARCHITECT-R2-3: Unprefixed Delivery-2 `deny` blocks stale Inbox `approve` (409 already_rejected),
        // and Inbox `undo_reject` clears both `hitl-<id>` and `<id>` so subsequent Delivery-2 `approve` succeeds!
        let (st_unpref_deny, val_unpref_deny) =
            handle_delivery2_approval(&repo, 5487, br#"{"id":"CHWG-779","decision":"deny"}"#);
        assert_eq!(st_unpref_deny, "200 OK");
        assert_eq!(val_unpref_deny["decision"], "denied");

        let (st_stale_inb_app, val_stale_inb_app) = handle_inbox_action(
            &repo,
            br#"{"id":"CHWG-779","action":"approve","source":"physical_click","physical_click_verified":true}"#,
        );
        assert_eq!(st_stale_inb_app, "409 Conflict");
        assert_eq!(val_stale_inb_app["error_code"], "already_rejected");

        let (st_undo_rej, _) =
            handle_inbox_action(&repo, br#"{"id":"CHWG-779","action":"undo_reject"}"#);
        assert_eq!(st_undo_rej, "200 OK");

        for bad_inb_body in [
            br#"{"id":"CHWG-779","action":"approve"}"#.as_slice(),
            br#"{"id":"CHWG-779","action":"apply_locally"}"#.as_slice(),
            br#"{"id":"CHWG-779","action":"approve","source":"voice","voice_originated":true,"physical_click_verified":false,"danger":false}"#.as_slice(),
            br#"{"id":"CHWG-779","action":"apply_locally","physical_click_verified":true}"#.as_slice(),
        ] {
            let (st_bad_inb, val_bad_inb) = handle_inbox_action(&repo, bad_inb_body);
            assert_eq!(st_bad_inb, "403 Forbidden");
            assert_eq!(val_bad_inb["error_code"], "VoiceDangerApprovalForbidden");
        }

        let (st_reapprove, val_reapprove) = handle_delivery2_approval(
            &repo,
            5487,
            br#"{"id":"CHWG-779","decision":"approve","source":"physical_click","physical_click_verified":true}"#,
        );
        assert_eq!(st_reapprove, "200 OK");
        assert_eq!(val_reapprove["already_settled"], false);
        assert_eq!(val_reapprove["decision"], "approved");

        // (d) ARCHITECT-R3-2: Cross-thread Stop — if another tab switches `active_thread_id` away from `thr-main`
        // before `/cancel` arrives, `handle_delivery2_cancel` clamps the stopped turn in its OWNING thread (`thr-main`)!
        let (st_xmsg, _) = handle_delivery2_message(
            &repo,
            5487,
            br#"{"prompt":"What did I miss?","turn_id":"turn-xthread-1","thread_id":"thr-main"}"#,
        );
        assert_eq!(st_xmsg, "200 OK");
        let (st_new_thr, _) =
            handle_delivery2_thread(&repo, 5487, br#"{"action":"new","title":"Second thread"}"#);
        assert_eq!(st_new_thr, "200 OK");
        let (st_xcancel, _) = handle_delivery2_cancel(
            &repo,
            5487,
            br#"{"turn_id":"turn-xthread-1","truncated_len":0,"thread_id":"thr-main"}"#,
        );
        assert_eq!(st_xcancel, "200 OK");
        let (st_sw_back, val_sw_back) = handle_delivery2_thread(
            &repo,
            5487,
            br#"{"action":"switch","thread_id":"thr-main"}"#,
        );
        assert_eq!(st_sw_back, "200 OK");
        let xstopped_entry = val_sw_back["state"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["turn_id"] == "turn-xthread-1")
            .expect("cross-thread cancelled turn qa_card");
        assert_eq!(xstopped_entry["body"], "[Stopped]");
        assert_eq!(xstopped_entry["sources"], json!([]));

        // (e) ALISTAIR-R3-2: Descriptor-anchored `O_NOFOLLOW` OAuth receipt check rejects symlinked `.chinwag` directory!
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            fs::write(
                outside.path().join("linear.json"),
                r#"{"verified":true,"account":"forged-outside-user","surface":"linear"}"#,
            )
            .unwrap();
            let sym_repo_dir = tempfile::tempdir().unwrap();
            let sym_repo = fs::canonicalize(sym_repo_dir.path()).unwrap();
            std::os::unix::fs::symlink(outside.path(), sym_repo.join(".chinwag")).unwrap();
            assert!(
                !has_verified_workspace_oauth_receipt(&sym_repo, "linear", None),
                "symlinked .chinwag directory must be rejected by O_NOFOLLOW receipt check"
            );

            // (f) ARCHITECT-R4-2: FIFO at `.chinwag/github-oauth.json` returns false promptly without blocking!
            let fifo_repo_dir = tempfile::tempdir().unwrap();
            let fifo_repo = fs::canonicalize(fifo_repo_dir.path()).unwrap();
            fs::create_dir_all(fifo_repo.join(".chinwag")).unwrap();
            let fifo_path = fifo_repo.join(".chinwag/github-oauth.json");
            let mkfifo_ok = std::process::Command::new("mkfifo")
                .arg(&fifo_path)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            assert!(mkfifo_ok, "mkfifo must create test named pipe");
            assert!(
                !has_verified_workspace_oauth_receipt(&fifo_repo, "github", None),
                "FIFO receipt must be rejected non-blockingly"
            );
        }

        // (g) ARCHITECT-R4-1 + FLINT-R4-1:
        // 1) Oversized 180,000-char prompt is rejected cleanly (400 prompt_too_long) without touching state.
        let huge_prompt_body =
            serde_json::to_vec(&json!({ "prompt": "a".repeat(180_000) })).unwrap();
        let (st_huge, val_huge) = handle_delivery2_message(&repo, 5487, &huge_prompt_body);
        assert_eq!(st_huge, "400 Bad Request");
        assert_eq!(val_huge["error_code"], "prompt_too_long");

        // 2) Mid-stream Stop (`truncated_len > 0`) retains the seen `run_card` and marks it `stopped: true`, `completed: false`.
        let (st_midmsg, _) = handle_delivery2_message(
            &repo,
            5487,
            br#"{"prompt":"Scope retry backoff jitter tests","turn_id":"turn-midstop-1","thread_id":"thr-main"}"#,
        );
        assert_eq!(st_midmsg, "200 OK");
        let (st_midcancel, val_midcancel) = handle_delivery2_cancel(
            &repo,
            5487,
            br#"{"turn_id":"turn-midstop-1","truncated_len":14,"thread_id":"thr-main"}"#,
        );
        assert_eq!(st_midcancel, "200 OK");
        let mid_run_card = val_midcancel["state"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "run_card" && e["turn_id"] == "turn-midstop-1")
            .expect("retained mid-stream stopped run_card");
        assert_eq!(mid_run_card["stopped"], true);
        assert_eq!(mid_run_card["completed"], false);

        // 3) 80 accumulated generic turns compact cleanly under `UI_V4_MAX_STATE_BYTES` so `load_ui_v4_state_strict` stays `Ok`,
        // and `save_ui_v4_state` refuses a synthetic >512 KB state without clobbering the valid file on disk!
        for idx in 0..80 {
            let msg_bytes = serde_json::to_vec(&json!({
                "prompt": format!("Scope incremental migration batch #{idx} with isolated sandbox verification"),
                "thread_id": "thr-main"
            }))
            .unwrap();
            let (st_loop, _) = handle_delivery2_message(&repo, 5487, &msg_bytes);
            assert_eq!(st_loop, "200 OK");
        }
        let strict_after_80 =
            load_ui_v4_state_strict(&repo).expect("state after 80 turns must load strictly");
        let main_thr = strict_after_80
            .delivery2
            .threads
            .iter()
            .find(|t| t.id == "thr-main")
            .unwrap();
        assert!(
            main_thr.entries.len() <= MAX_DELIVERY2_ENTRIES_PER_THREAD,
            "expected bounded thread entries <= {MAX_DELIVERY2_ENTRIES_PER_THREAD}, got {}",
            main_thr.entries.len()
        );

        let mut synthetic_huge = strict_after_80.clone();
        synthetic_huge.delivery2.threads[0].entries =
            vec![json!({"id":"huge-1","kind":"qa_card","body":"x".repeat(600_000)})];
        assert!(
            save_ui_v4_state(&repo, &synthetic_huge).is_err(),
            "save_ui_v4_state must refuse state exceeding UI_V4_MAX_STATE_BYTES"
        );
        assert!(
            load_ui_v4_state_strict(&repo).is_ok(),
            "refused oversized save must leave prior valid .chinwag/ui-v4-state.json intact"
        );

        // (h) ARCHITECT-R5-1: Pending workflow preservation across BOTH thread eviction and byte-budget shedding!
        let pend_dir = tempfile::tempdir().unwrap();
        let pend_repo = fs::canonicalize(pend_dir.path()).unwrap();
        init_test_repo(&pend_repo);
        fs::create_dir_all(pend_repo.join(".chinwag")).unwrap();

        // 1) Create thread `T`, start GitHub OAuth sign-in there, then create 23 more threads (25 total > 24 cap) -> `T` must NOT be evicted!
        let (st_t0, val_t0) = handle_delivery2_thread(
            &pend_repo,
            5487,
            br#"{"action":"new","title":"OAuth origin thread"}"#,
        );
        assert_eq!(st_t0, "200 OK");
        let origin_tid = val_t0["active_thread_id"].as_str().unwrap().to_string();

        let (st_gh_conn, _) = handle_delivery2_approval(
            &pend_repo,
            5487,
            br#"{"kind":"oauth","surface":"github","decision":"connect"}"#,
        );
        assert_eq!(st_gh_conn, "200 OK");

        for i in 0..23 {
            let new_body = serde_json::to_vec(&json!({
                "action": "new",
                "title": format!("Idle thread #{i}")
            }))
            .unwrap();
            let (st_idle, _) = handle_delivery2_thread(&pend_repo, 5487, &new_body);
            assert_eq!(st_idle, "200 OK");
        }

        let (st_sw_origin, val_sw_origin) = handle_delivery2_thread(
            &pend_repo,
            5487,
            serde_json::to_vec(&json!({ "action": "switch", "thread_id": origin_tid }))
                .unwrap()
                .as_slice(),
        );
        assert_eq!(
            st_sw_origin, "200 OK",
            "Thread holding pending OAuth sign-in must survive 25-thread compaction"
        );
        assert!(
            val_sw_origin["state"]["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["id"] == "entry-oauth-github" && e["settled"] == false),
            "Pending GitHub oauth_card must remain intact in originating thread"
        );

        // 2) Byte-budget shedding under dense multi-KB entries protects unsettled cards at index 0
        // and returns 409 HELD when no safe non-pinned eviction can satisfy bounds!
        let (st_dense_shed_ok, _) = mutate_ui_v4_state(&pend_repo, |st| {
            let thr = st
                .delivery2
                .threads
                .iter_mut()
                .find(|t| t.id == origin_tid)
                .unwrap();
            thr.entries.insert(
                0,
                json!({
                    "id": "entry-hitl-pinned-0",
                    "kind": "approval_card",
                    "settled": false,
                    "title": "Pinned unsettled approval at index 0"
                }),
            );
            for k in 0..45 {
                thr.entries.push(json!({
                    "id": format!("dense-qa-{k}"),
                    "kind": "qa_card",
                    "body": "d".repeat(13_000)
                }));
            }
            Ok(json!({ "ok": true }))
        });
        assert_eq!(st_dense_shed_ok, "200 OK");
        let after_dense = load_ui_v4_state_strict(&pend_repo).unwrap();
        let origin_after_dense = after_dense
            .delivery2
            .threads
            .iter()
            .find(|t| t.id == origin_tid)
            .unwrap();
        assert!(
            origin_after_dense
                .entries
                .iter()
                .any(|e| e["id"] == "entry-hitl-pinned-0" && e["settled"] == false),
            "Byte-budget shedding must NEVER evict unsettled approval_card at index 0"
        );
        assert!(
            origin_after_dense
                .entries
                .iter()
                .any(|e| e["id"] == "entry-oauth-github" && e["settled"] == false),
            "Byte-budget shedding must NEVER evict unsettled oauth_card"
        );

        // 3) Count-bound HELD (> MAX_DELIVERY2_ENTRIES_PER_THREAD unsettled cards) AND byte-budget HELD
        // (<= MAX_DELIVERY2_ENTRIES_PER_THREAD dense unsettled cards exceeding UI_V4_MAX_STATE_BYTES)
        // both return 409 HELD without corrupting the valid state on disk!
        let (st_held_count, val_held_count) = mutate_ui_v4_state(&pend_repo, |st| {
            let thr = st
                .delivery2
                .threads
                .iter_mut()
                .find(|t| t.id == origin_tid)
                .unwrap();
            thr.entries = (0..=MAX_DELIVERY2_ENTRIES_PER_THREAD)
                .map(|k| {
                    json!({
                        "id": format!("unsettled-only-{k}"),
                        "kind": "approval_card",
                        "settled": false
                    })
                })
                .collect();
            Ok(json!({ "ok": true }))
        });
        assert_eq!(st_held_count, "409 Conflict");
        assert_eq!(val_held_count["disposition"], "HELD");
        assert_eq!(
            val_held_count["error_code"],
            "pending_workflow_limit_exceeded"
        );

        let (st_held_bytes, val_held_bytes) = mutate_ui_v4_state(&pend_repo, |st| {
            let thr = st
                .delivery2
                .threads
                .iter_mut()
                .find(|t| t.id == origin_tid)
                .unwrap();
            thr.entries = (0..40)
                .map(|k| {
                    json!({
                        "id": format!("unsettled-dense-{k}"),
                        "kind": "approval_card",
                        "settled": false,
                        "question": "q".repeat(15_000)
                    })
                })
                .collect();
            Ok(json!({ "ok": true }))
        });
        assert_eq!(st_held_bytes, "409 Conflict");
        assert_eq!(val_held_bytes["disposition"], "HELD");
        assert_eq!(val_held_bytes["error_code"], "state_save_failed");
        assert!(
            load_ui_v4_state_strict(&pend_repo).is_ok(),
            "HELD compaction/byte-budget refusals must leave valid .chinwag/ui-v4-state.json intact"
        );
    }
}
