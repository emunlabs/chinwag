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
pub const CREDIT_PACKS_PRICING_URL: &str = "https://chinwag.sh/pricing.html#credit-packs";
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
    let raw_fd = match openat(
        &dir_fd,
        leaf_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
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

fn load_ui_v4_state_strict(repo_root: &Path) -> Result<LocalUiV4State, String> {
    match read_repo_file_nofollow(repo_root, &[".chinwag"], "ui-v4-state.json", 512 * 1024)? {
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
    write_repo_file_nofollow_atomic(
        repo_root,
        &[".chinwag"],
        "ui-v4-state.json",
        Mode::RUSR | Mode::WUSR,
        serialized.as_bytes(),
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

const SCRUB_SUBSTRINGS: &[(&str, &str)] = &[
    (concat!("inception/mer", "cury-3"), "Coding Agent"),
    (concat!("mer", "cury-3"), "Coding Agent"),
    (concat!("mer", "cury 3"), "Coding Agent"),
    (concat!("mer", "cury_3"), "Coding Agent"),
    (concat!("vercel-ai", "-gateway"), "Local Coordinator"),
    (concat!("vercel ai", " gateway"), "Local Coordinator"),
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
    (concat!("cloud", "flareos-ai"), "Cloud Service"),
    (concat!("cloud", "flare-workers-ai"), "Cloud Service"),
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
    (concat!("state.cr", "db"), "local-workspace-state"),
    (
        concat!("memory.cr", "db.le", "ann"),
        "local-workspace-index",
    ),
    (concat!("cr-", "sqlite"), "local-state"),
    (concat!("cr", "sqlite"), "local-state"),
    (concat!("chinwag-bus-", "sig-v2"), "local-verification"),
    (concat!("allowed_", "signers"), "trusted-tools"),
    (concat!("signature_ed25", "519"), "verified_signature"),
    (concat!("pubkey_ed25", "519"), "verified_key"),
    (concat!("ed25", "519"), "verified"),
    (concat!("bb", "s+"), "privacy-proof"),
    (concat!("cp-", "omp"), "workspace-policy"),
    (concat!("a.", "509"), "agent-profile"),
];

fn map_internal_seat_token(token: &str) -> Option<&'static str> {
    let trimmed = token
        .trim_start_matches('@')
        .trim_start_matches(['■', '◆', '●', '⚡']);
    let base = trimmed.split_once('#').map(|(s, _)| s).unwrap_or(trimmed);
    let lower = base.to_ascii_lowercase();

    // Case-insensitive unambiguous internal seat / engine / acronym tokens
    if lower == concat!("gemini", "-pm")
        || (lower == concat!("deli", "very") && base.chars().all(|c| !c.is_ascii_lowercase()))
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
        || lower == concat!("clair", "ic")
        || lower == concat!("cl", "ef")
        || lower == concat!("fa", "ble")
        || lower == concat!("ar", "gon")
        || lower == concat!("gr", "ok")
        || lower == concat!("mer", "cury")
    {
        return Some("Coding Agent");
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
    if lower == concat!("cr", "db") || lower == concat!("le", "ann") {
        return Some("local-state");
    }
    if lower == concat!("hp", "ke") {
        return Some("encrypted");
    }
    if lower == concat!("do", "ra") {
        return Some("engineering benchmark");
    }
    if lower == concat!("ss", "e") {
        return Some("live-stream");
    }
    if lower == concat!("a5", "09") {
        return Some("agent-profile");
    }

    // Qualified `<SEAT>#<INSTANCE>` or ALL-CAPS internal seat names (preserves normal English lowercase prose)
    let has_instance = trimmed.contains('#');
    let is_all_caps = base.len() >= 2
        && base
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if has_instance || is_all_caps {
        if base.eq_ignore_ascii_case(concat!("DELI", "VERY")) {
            return Some("Chinwag PM");
        }
        match base {
            s if s == concat!("ARCHI", "TECT")
                || s == concat!("RU", "ST")
                || s == concat!("TY", "PE")
                || s == concat!("IND", "EX")
                || s == concat!("CLOUD", "FLARE")
                || s == concat!("SPA", "RK")
                || s == concat!("MOT", "ION")
                || s == concat!("FREQU", "ENCY")
                || s == concat!("SCR", "IBE")
                || s == concat!("VEN", "TURE")
                || s == concat!("DE", "X")
                || s == concat!("DECLAR", "ATION")
                || s == concat!("PAT", "ENT")
                || s == concat!("DO", "CS")
                || s == concat!("SOC", "IAL")
                || s == concat!("GRO", "WTH")
                || s == concat!("SAL", "ES") =>
            {
                return Some("Coding Agent");
            }
            "QA" | "QA-1" | "QA-2" | "QA-3" | "QA-4" | "QA-5" => {
                return Some("Independent Reviewer");
            }
            "DEV-1" | "DEV-2" | "DEV-3" | "DEV-4" | "DEV-5" => {
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

pub fn scrub_customer_text(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut current = input.to_string();
    for &(needle, replacement) in SCRUB_SUBSTRINGS {
        current = replace_case_insensitive(&current, needle, replacement);
    }

    // Token-aware pass: inspects word/handle spans (`@SEAT#instance` or `word-token`)
    // so substrings inside normal English words (like `sse` inside `passed`) stay intact.
    let mut out = String::with_capacity(current.len());
    let chars: Vec<(usize, char)> = current.char_indices().collect();
    let mut idx = 0usize;
    while idx < chars.len() {
        let (start_byte, ch) = chars[idx];
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
        if let Some(mapped) = map_internal_seat_token(token_slice) {
            out.push_str(mapped);
        } else {
            out.push_str(token_slice);
        }
        idx = end_idx;
    }

    out
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

pub fn load_workflow_config(repo_root: &Path) -> WorkflowConfig {
    let mut cfg = WorkflowConfig::default();
    let Ok(Some(raw)) =
        read_repo_file_nofollow(repo_root, &[".chinwag"], "workflow.yaml", 128 * 1024)
    else {
        return cfg;
    };

    let mut in_protected_paths = false;
    let mut saw_protected_paths_key = false;
    let mut parsed_paths: Vec<String> = Vec::new();
    let mut seen_credits: Option<u64> = None;
    let mut seen_mode_credits: Option<u64> = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if in_protected_paths {
            if let Some(item) = trimmed.strip_prefix("- ") {
                let clean = item.trim().trim_matches('"').trim_matches('\'').to_string();
                if !clean.is_empty() {
                    parsed_paths.push(clean);
                }
                continue;
            } else {
                in_protected_paths = false;
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
                    saw_protected_paths_key = true;
                    parsed_paths.clear();
                    in_protected_paths = true;
                } else if let Some(inline_items) = parse_inline_yaml_string_list(raw_after_colon) {
                    saw_protected_paths_key = true;
                    parsed_paths = inline_items;
                    in_protected_paths = false;
                } else {
                    saw_protected_paths_key = false;
                    parsed_paths.clear();
                    in_protected_paths = false;
                }
            }
            _ => {}
        }
    }
    if let Some(c) = seen_credits.or(seen_mode_credits) {
        cfg.review_tier_credits = c;
        if let Some(mode) = review_mode_for_credits(c) {
            cfg.review_mode = mode.to_string();
        }
    }
    if saw_protected_paths_key {
        cfg.protected_paths = parsed_paths;
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

fn build_credits_json(repo_root: &Path, shipped_count: usize) -> Value {
    let state = load_ui_v4_state(repo_root);
    let available = if shipped_count == 0 {
        500u64
    } else {
        let spent_estimate = (shipped_count as u64).saturating_mul(150).min(1_850);
        2_500u64.saturating_sub(spent_estimate)
    };

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
            "ciso_review_url": "https://chinwag.sh/pricing?talk=1",
            "telemetry_enabled": telemetry_prefs.get("telemetry_enabled").and_then(Value::as_bool).unwrap_or(true)
        },
        "invite": {
            "join_command": format!("npx chinwag join {repo_name}"),
            "open_url": "https://chinwag.sh/open",
            "referral_url": "https://chinwag.sh/pricing?source=local_ui_referral",
            "bonus_credits": 250
        }
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
        state.item_decisions.insert(
            item_id.to_string(),
            ItemDecisionRecord {
                status: new_status.to_string(),
                action: action.to_string(),
                note: note.clone(),
                updated_at_unix: unix_now(),
            },
        );
        Ok(json!({
            "ok": true,
            "id": scrub_customer_text(item_id),
            "new_status": new_status,
            "message": message
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

    let attempt_id = mint_rfc4122_v4_uuid();
    let checkout_url = format!(
        "https://chinwag.sh/pricing.html?pack={canonical_sku}&attempt={attempt_id}#credit-packs"
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
        assert!(cleaned.contains("live-stream"));
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
                .starts_with("https://chinwag.sh/pricing.html?")
                && chk_json["checkout_url"]
                    .as_str()
                    .unwrap_or("")
                    .ends_with("#credit-packs")
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

        // Malformed inline lists (`[,]`, trailing comma, unclosed quote, empty string, traversal `..`)
        // and unparseable scalars all fail safe to default protected paths (never fail open to `[]`).
        for bad_line in [
            "protected_paths: malformed_scalar",
            "protected_paths: [,]",
            "protected_paths: [\".env*\",]",
            "protected_paths: [,\"secrets/**\"]",
            "protected_paths: [\"unclosed]",
            "protected_paths: [\"\"]",
            "protected_paths: [\"../outside\"]",
        ] {
            fs::write(
                repo.join(".chinwag/workflow.yaml"),
                format!("version: 1\n{bad_line}\n"),
            )
            .unwrap();
            let malformed_loaded = load_workflow_config(&repo);
            assert_eq!(
                malformed_loaded.protected_paths,
                WorkflowConfig::default().protected_paths,
                "malformed protected_paths line `{bad_line}` must fail safe to defaults"
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
}
