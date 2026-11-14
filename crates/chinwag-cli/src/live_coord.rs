//! Universal model-agnostic live coordination (`CHWG-0250` · `INV-UNIVERSAL-COORDINATION-01`).
//!
//! Implements all three universal protocol boundaries directly inside the `chinwag` binary
//! with zero `$HOME` vendor dotfile hooks (`~/.claude`, `~/.gemini`, `~/.codex`) and zero
//! mandatory external daemon on single-host workspaces:
//! 1. Transactional Auto-Beacons (`TASK_CREATED`, `CLAIM_ACQUIRED`, `PR_OPENED`, `PR_MERGED`,
//!    `RELEASE_BUILT`) persisted atomically with `agent_claims` + `leases` in `.chinwag/state.crdb`.
//! 2. Live CLI/MCP Session Leases & `<1ms` `[chinwag-bus-delta]` piggybacking via SQLite header
//!    change counter + `PRAGMA data_version`.
//! 3. Repo-local Git claim-check floor (`post-checkout`, `pre-commit`, `reference-transaction`)
//!    + `.chinwag/ACTIVE_WORK.md` for raw Git-only local/open-weight models.
#![forbid(unsafe_code)]

use crate::agent_instance::ActorAddress;
use crate::bus_federation::{BusMessage, FederationSink, SinkDisposition};
use crate::bus_store::NativeJournalSink;
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    CrdbHeaderStamp, Rows, SnapshotSession, Value as SqlValue, fast_crdb_header_stamp,
    replacement::{
        LIVE_SESSION_LEASE_CLAIM_ID, LiveCoordBeaconRecord, LiveSessionLeaseRecord, WriteOwner,
        WriteSession,
    },
};
use chinwag_swarm::identity::{Identity, parse_allowed_signers};
use iroh::SecretKey;
use rand::{TryRngCore, rngs::OsRng};
use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags, fstat, openat, statat};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const INV_UNIVERSAL_COORDINATION: &str = "INV-UNIVERSAL-COORDINATION-01";
pub const ACTIVE_WORK_REL_PATH: &str = ".chinwag/ACTIVE_WORK.md";
const CLI_CURSOR_FILE: &str = "live_cli_cursors.json";
const DEFAULT_CLAIM_TTL_MS: i64 = 2 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL_MS: i64 = 15 * 60 * 1000;
const HOOK_SENTINEL: &str = "# chinwag-live-coord-hook-v1";
const MAX_DELTA_LINE_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BeaconKind {
    #[serde(rename = "TASK_CREATED")]
    TaskCreated,
    #[serde(rename = "CLAIM_ACQUIRED")]
    ClaimAcquired,
    #[serde(rename = "PR_OPENED")]
    PrOpened,
    #[serde(rename = "PR_MERGED")]
    PrMerged,
    #[serde(rename = "RELEASE_BUILT")]
    ReleaseBuilt,
}

impl BeaconKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskCreated => "TASK_CREATED",
            Self::ClaimAcquired => "CLAIM_ACQUIRED",
            Self::PrOpened => "PR_OPENED",
            Self::PrMerged => "PR_MERGED",
            Self::ReleaseBuilt => "RELEASE_BUILT",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "TASK_CREATED" | "TASK-CREATED" => Some(Self::TaskCreated),
            "CLAIM_ACQUIRED" | "CLAIM-ACQUIRED" => Some(Self::ClaimAcquired),
            "PR_OPENED" | "PR-OPENED" => Some(Self::PrOpened),
            "PR_MERGED" | "PR-MERGED" => Some(Self::PrMerged),
            "RELEASE_BUILT" | "RELEASE-BUILT" => Some(Self::ReleaseBuilt),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AutoBeaconRequest {
    pub id: Option<String>,
    pub kind: Option<BeaconKind>,
    pub actor: Option<String>,
    pub ticket_id: String,
    pub worktree: Option<String>,
    pub branch_ref: Option<String>,
    pub claimed_paths: Vec<String>,
    pub pr_number: Option<u64>,
    pub pr_url: Option<String>,
    pub commit_sha: Option<String>,
    pub release_binary: Option<String>,
    pub summary: Option<String>,
    pub lease_ttl_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconCommitReceipt {
    pub ok: bool,
    pub invariant: String,
    pub beacon_id: String,
    pub kind: String,
    pub seq: u64,
    pub db_version: i64,
    pub actor: String,
    pub ticket_id: String,
    pub worktree: String,
    pub branch_ref: String,
    pub claimed_paths: Vec<String>,
    pub claims_upserted: usize,
    pub claims_released: usize,
    pub sig_verified: bool,
    pub journal_mirrored: bool,
    pub active_work_updated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveClaimView {
    pub claim_id: String,
    pub path_glob: String,
    pub ticket_id: String,
    pub owner_actor: String,
    pub worktree: String,
    pub branch_ref: String,
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSessionLeaseView {
    pub lease_id: String,
    pub actor_instance: String,
    pub pid: u32,
    pub worktree: String,
    pub last_seen_seq: u64,
    pub updated_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconView {
    pub seq: u64,
    pub beacon_id: String,
    pub kind: String,
    pub actor: String,
    pub ticket_id: String,
    pub worktree: String,
    pub branch_ref: String,
    pub claimed_paths: Vec<String>,
    pub sig_verified: bool,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimConflict {
    pub candidate_path: String,
    pub claimed_glob: String,
    pub owner_actor: String,
    pub ticket_id: String,
    pub worktree: String,
    pub branch_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHookInstallReceipt {
    pub hooks_dir: String,
    pub installed_hooks: Vec<String>,
    pub chained_existing_hooks: Vec<String>,
    pub active_work_path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct CliCursorStateFile {
    #[serde(default)]
    cursors: BTreeMap<String, CliCursorEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CliCursorEntry {
    actor_instance: String,
    pid: u32,
    worktree: String,
    last_seen_seq: u64,
    sqlite_change_counter: u32,
    crdb_ino: u64,
    crdb_size: u64,
    updated_at_ms: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

fn git_bin() -> OsString {
    if let Some(bin) = std::env::var_os("CHINWAG_GIT_BIN")
        && !bin.is_empty()
    {
        return bin;
    }
    OsString::from("git")
}

fn csprng_hex_16() -> Result<String, String> {
    let mut bytes = [0_u8; 8];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("csprng_unavailable: {e}"))?;
    Ok(hex_bytes(&bytes))
}

/// Resolves and validates the caller's `ActorAddress`, strictly rejecting any `--from`
/// override that conflicts with an active `CHINWAG_ACTOR` environment binding
/// (`INV-NO-SEAT-IMPERSONATION-01` & `INV-THREAD-ID-01`).
pub fn resolve_verified_actor(explicit: Option<&str>) -> Result<ActorAddress, String> {
    let explicit_clean = explicit.map(str::trim).filter(|s| !s.is_empty());
    let env_clean = std::env::var("CHINWAG_ACTOR")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    if let Some(ref env_raw) = env_clean {
        let env_addr = ActorAddress::parse(env_raw)
            .and_then(ActorAddress::require_instance)
            .map_err(|e| format!("invalid_env_chinwag_actor: {e}"))?;
        if let Some(exp_raw) = explicit_clean {
            let exp_addr = ActorAddress::parse(exp_raw)
                .and_then(ActorAddress::require_instance)
                .map_err(|e| format!("invalid_explicit_actor: {e}"))?;
            if exp_addr != env_addr {
                return Err(
                    "refusing_actor_impersonation: --from conflicts with bound CHINWAG_ACTOR (INV-NO-SEAT-IMPERSONATION-01)"
                        .to_owned(),
                );
            }
        }
        return Ok(env_addr);
    }

    if let Some(exp_raw) = explicit_clean {
        return ActorAddress::parse(exp_raw)
            .and_then(ActorAddress::require_instance)
            .map_err(|e| format!("invalid_explicit_actor: {e}"));
    }

    ActorAddress::parse(&format!("LOCAL-CLI#pid-{}", std::process::id()))
        .and_then(ActorAddress::require_instance)
        .map_err(|e| format!("invalid_default_actor: {e}"))
}

pub fn resolve_current_actor(explicit: Option<&str>) -> String {
    resolve_verified_actor(explicit)
        .map(|a| a.to_string())
        .unwrap_or_else(|_| format!("LOCAL-CLI#pid-{}", std::process::id()))
}

/// Scrubs secret tokens, auth headers, PEM key blocks, and absolute user/temp filesystem
/// paths before persisting or displaying coordination text (`INV-PUBLIC-BOARD-REDACTION-01`).
pub fn scrub_coord_text(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let begin_marker = concat!("-----BEGIN ", "");
    let end_marker = concat!("-----END ", "");
    let mut text = raw.to_owned();
    while let Some(b_idx) = text.find(begin_marker) {
        if let Some(rel_end) = text[b_idx..].find(end_marker) {
            let after_end = b_idx + rel_end;
            let tail_end = text[after_end..]
                .find("-----")
                .and_then(|first| {
                    let s = after_end + first + 5;
                    text[s..].find("-----").map(|second| s + second + 5)
                })
                .unwrap_or(text.len());
            text.replace_range(b_idx..tail_end, "[REDACTED:PRIVATE_KEY_BLOCK]");
        } else {
            text.replace_range(b_idx.., "[REDACTED:PRIVATE_KEY_BLOCK]");
            break;
        }
    }

    let prefixes: &[(&str, &str)] = &[
        (concat!("sk", "-ant-"), "[REDACTED:API_KEY]"),
        (concat!("sk", "-proj-"), "[REDACTED:API_KEY]"),
        (concat!("sk", "-live-"), "[REDACTED:API_KEY]"),
        (concat!("sk", "-"), "[REDACTED:API_KEY]"),
        (concat!("gh", "p_"), "[REDACTED:GH_TOKEN]"),
        (concat!("gh", "o_"), "[REDACTED:GH_TOKEN]"),
        (concat!("gh", "s_"), "[REDACTED:GH_TOKEN]"),
        (concat!("github", "_pat_"), "[REDACTED:GH_PAT]"),
        (concat!("xa", "i-"), "[REDACTED:API_KEY]"),
        (concat!("xo", "xb-"), "[REDACTED:SLACK_TOKEN]"),
        (concat!("xo", "xp-"), "[REDACTED:SLACK_TOKEN]"),
        (concat!("xo", "xa-"), "[REDACTED:SLACK_TOKEN]"),
        (concat!("xo", "xr-"), "[REDACTED:SLACK_TOKEN]"),
        (concat!("AK", "IA"), "[REDACTED:AWS_ACCESS_KEY]"),
        (concat!("chwg", "_phantom_"), "[REDACTED:PHANTOM_TOKEN]"),
    ];
    let sensitive_keys = [
        "authorization",
        "x-api-key",
        "api-key",
        "api_key",
        "apikey",
        "secret-key",
        "secret_key",
        "client-secret",
        "client_secret",
        "private-key",
        "private_key",
        "access-token",
        "access_token",
        "refresh-token",
        "refresh_token",
        "auth-token",
        "auth_token",
        "password",
        "passwd",
        "set-cookie",
        "cookie",
        "secret",
        "token",
    ];

    let mut out_tokens = Vec::new();
    let mut redact_next_auth_token = false;
    for tok in text.split_whitespace() {
        let trim_punct =
            tok.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '('));
        if redact_next_auth_token {
            redact_next_auth_token = false;
            out_tokens.push("[REDACTED:AUTH]".to_owned());
            continue;
        }
        let lower = trim_punct.to_ascii_lowercase();
        if matches!(lower.as_str(), "bearer" | "basic") {
            redact_next_auth_token = true;
            out_tokens.push(tok.to_owned());
            continue;
        }
        if let Some((k, v)) = trim_punct
            .split_once('=')
            .or_else(|| trim_punct.split_once(':'))
        {
            let k_low = k.trim().to_ascii_lowercase();
            if sensitive_keys
                .iter()
                .any(|sk| k_low == *sk || k_low.ends_with(sk))
            {
                if v.trim().is_empty() {
                    redact_next_auth_token = true;
                    out_tokens.push(format!("{k}=[REDACTED:SECRET]"));
                } else {
                    out_tokens.push(format!("{k}=[REDACTED:SECRET]"));
                }
                continue;
            }
        }
        let mut matched_prefix: Option<&str> = None;
        for (pfx, label) in prefixes {
            if trim_punct.starts_with(pfx) && trim_punct.len() >= pfx.len() + 8 {
                matched_prefix = Some(label);
                break;
            }
        }
        if let Some(label) = matched_prefix {
            out_tokens.push(label.to_owned());
            continue;
        }
        out_tokens.push(scrub_host_path_token(tok));
    }
    out_tokens.join(" ")
}

fn scrub_host_path_token(token: &str) -> String {
    let mut current = token.to_owned();
    for root in [
        "/private/var/folders/",
        "/var/folders/",
        "/Users/",
        "/home/",
    ] {
        while let Some(idx) = current.find(root) {
            let after_root = idx + root.len();
            let rest = &current[after_root..];
            let end_rel = rest
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | '|' | '`')
                })
                .unwrap_or(rest.len());
            let full_slice = &rest[..end_rel];
            let leaf = full_slice
                .rsplit('/')
                .find(|seg| !seg.is_empty())
                .unwrap_or("workspace");
            let replacement = format!("<worktree>/{leaf}");
            current.replace_range(idx..(after_root + end_rel), &replacement);
        }
    }
    current
}

/// Converts a worktree path into a host-redacted, repository-relative or `worktree:<leaf>` label
/// so `/Users/<user>/...` and `/home/<user>/...` never leak into CRDB, JSONL, or Markdown.
pub fn sanitize_worktree_label(store_root: &Path, worktree: &Path) -> String {
    let sr_canon = fs::canonicalize(store_root).unwrap_or_else(|_| store_root.to_path_buf());
    let wt_canon = fs::canonicalize(worktree).unwrap_or_else(|_| worktree.to_path_buf());
    if wt_canon == sr_canon {
        return ".".to_owned();
    }
    if let Ok(rel) = wt_canon.strip_prefix(&sr_canon) {
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        if !rel_s.is_empty() {
            return scrub_coord_text(&rel_s);
        }
    }
    let leaf = wt_canon
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("linked");
    format!("worktree:{}", scrub_coord_text(leaf))
}

fn worktree_cursor_key(actor: &str, worktree: &Path) -> String {
    let wt_canon = fs::canonicalize(worktree).unwrap_or_else(|_| worktree.to_path_buf());
    let digest = Sha256::digest(wt_canon.to_string_lossy().as_bytes());
    format!("{actor}@wt-{}", &hex_bytes(&digest)[..16])
}

/// Resolves the canonical repository root that holds `.chinwag/state.crdb`
/// (transparently bridging linked Git worktrees to their common repository root).
pub fn resolve_coord_store_root(candidate: &Path) -> PathBuf {
    let abs = fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
    if abs.join(".chinwag").join("state.crdb").is_file() {
        return abs;
    }
    if let Ok(selected) =
        crate::execution_binding::select_repository(crate::execution_binding::RepoSelectors {
            explicit_repo: Some(&abs),
            environment_repo: None,
            cwd: &abs,
        })
    {
        if let Some(common) = selected.common_worktree_root()
            && common.join(".chinwag").join("state.crdb").is_file()
        {
            return common.to_path_buf();
        }
        let exec = selected.execution_root();
        if exec.join(".chinwag").join("state.crdb").is_file() {
            return exec.to_path_buf();
        }
    }
    abs
}

fn infer_repo_id(repo_root: &Path) -> String {
    if let Ok(out) = Command::new(git_bin())
        .args([
            "-C",
            &repo_root.to_string_lossy(),
            "config",
            "--get",
            "remote.origin.url",
        ])
        .output()
        && out.status.success()
    {
        let raw = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let trimmed = raw.trim_end_matches(".git");
        if let Some(idx) = trimmed.rfind(':') {
            let tail = &trimmed[idx + 1..];
            if tail.contains('/') && !tail.starts_with("//") {
                return tail.trim_start_matches('/').to_owned();
            }
        }
        let parts: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() >= 2 {
            return format!("{}/{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        }
    }
    repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("local-repo")
        .to_owned()
}

fn infer_branch_ref(worktree: &Path) -> String {
    if let Ok(out) = Command::new(git_bin())
        .args([
            "-C",
            &worktree.to_string_lossy(),
            "symbolic-ref",
            "-q",
            "HEAD",
        ])
        .output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !s.is_empty() {
            return s;
        }
    }
    if let Ok(out) = Command::new(git_bin())
        .args([
            "-C",
            &worktree.to_string_lossy(),
            "symbolic-ref",
            "-q",
            "refs/remotes/origin/HEAD",
        ])
        .output()
        && out.status.success()
    {
        let sym = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if let Some(branch) = sym.strip_prefix("refs/remotes/origin/")
            && !branch.is_empty()
        {
            return format!("refs/heads/{branch}");
        }
    }
    if let Ok(def_branch) = std::env::var("CHINWAG_DEFAULT_BRANCH") {
        let trimmed = def_branch.trim();
        if !trimmed.is_empty() {
            if trimmed.starts_with("refs/") {
                return trimmed.to_owned();
            }
            return format!("refs/heads/{trimmed}");
        }
    }
    "HEAD".to_owned()
}

fn clear_stale_crdb_locks(store_root: &Path) {
    crate::memory_run::clear_stale_crdb_operation_artifacts(store_root);
}

/// Canonical length-prefixed 7-field `chinwag-bus-sig-v2` signing payload, identical to
/// `bus_run::canonical_signing_payload` (`BUS-HARDEN-04`).
pub fn canonical_bus_signing_payload(msg: &BusMessage) -> String {
    let to = msg.to.as_deref().unwrap_or("");
    let task = msg.task_id.as_deref().unwrap_or("");
    let ts = msg.ts_unix.to_string();
    format!(
        "chinwag-bus-sig-v2|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}",
        msg.id.len(),
        msg.id,
        ts.len(),
        ts,
        msg.sender.len(),
        msg.sender,
        to.len(),
        to,
        msg.room.len(),
        msg.room,
        task.len(),
        task,
        msg.body.len(),
        msg.body
    )
}

fn compute_bus_v1_digest(
    ts_unix: u64,
    room: &str,
    sender: &str,
    sender_endpoint_id: &str,
    to: Option<&str>,
    task_id: Option<&str>,
    body: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "chinwag-bus-v1|{ts_unix}|{room}|{sender}|{sender_endpoint_id}|{}|{}|{body}",
        to.unwrap_or(""),
        task_id.unwrap_or("")
    ));
    hex_bytes(&hasher.finalize())
}

fn load_actor_signing_secret(addr: &ActorAddress) -> Option<SecretKey> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let signing_dir = home.join(".chinwag").join("signing");
    let slug = addr.seat().to_ascii_lowercase();
    if slug.is_empty()
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    {
        return None;
    }

    let ssh_key_path = signing_dir.join(format!("{slug}_ed25519"));
    if let Ok(fd) = openat(
        CWD,
        &ssh_key_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) && let Ok(st) = fstat(&fd)
        && FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
        && st.st_nlink == 1
        && (st.st_mode & 0o7777) == 0o600
        && st.st_uid == rustix::process::geteuid().as_raw()
    {
        drop(fd);
        if let Ok(identity) = Identity::from_ssh_signing_file(&ssh_key_path) {
            return Some(identity.iroh_secret_key());
        }
    }

    let raw_key_path = signing_dir.join(format!("{slug}_ed25519.key"));
    if let Ok(fd) = openat(
        CWD,
        &raw_key_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) && let Ok(st) = fstat(&fd)
        && FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
        && st.st_nlink == 1
        && (st.st_mode & 0o7777) == 0o600
        && st.st_uid == rustix::process::geteuid().as_raw()
    {
        let mut raw_bytes = Zeroizing::new(Vec::with_capacity(32));
        if File::from(fd).take(64).read_to_end(&mut raw_bytes).is_ok() && raw_bytes.len() == 32 {
            let mut seed = Zeroizing::new([0_u8; 32]);
            seed.copy_from_slice(&raw_bytes);
            return Some(SecretKey::from_bytes(&seed));
        }
    }

    None
}

#[derive(Clone, Debug)]
struct RepoAllowedSignerEntry {
    seat_upper: Option<String>,
    principal_prefix_upper: Option<String>,
    pubkey_bytes: [u8; 32],
}

fn load_repo_allowed_signers(store_root: &Path) -> Vec<RepoAllowedSignerEntry> {
    let allowed_path = store_root.join(".chinwag").join("allowed_signers");
    let Ok(fd) = openat(
        CWD,
        &allowed_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return Vec::new();
    };
    let Ok(st) = fstat(&fd) else {
        return Vec::new();
    };
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Vec::new();
    }
    let mut content = String::new();
    if File::from(fd)
        .take(512 * 1024)
        .read_to_string(&mut content)
        .is_err()
    {
        return Vec::new();
    }

    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parsed = parse_allowed_signers(trimmed);
        let first_tok = trimmed.split_whitespace().next().unwrap_or("");
        let principal_prefix_upper = first_tok
            .split(',')
            .next()
            .map(|p| p.split('@').next().unwrap_or(p).trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty());
        for (seat_opt, pubkey_bytes) in parsed {
            entries.push(RepoAllowedSignerEntry {
                seat_upper: seat_opt,
                principal_prefix_upper: principal_prefix_upper.clone(),
                pubkey_bytes,
            });
        }
    }
    entries
}

fn entry_matches_seat(entry: &RepoAllowedSignerEntry, seat_upper: &str) -> bool {
    if let Some(ref s) = entry.seat_upper {
        return s.eq_ignore_ascii_case(seat_upper);
    }
    entry
        .principal_prefix_upper
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case(seat_upper))
}

/// Builds a canonical `BusMessage`, signs it over `chinwag-bus-sig-v2` when the actor's
/// `0600` key is present, verifies against repo-configurable `<store_root>/.chinwag/allowed_signers`,
/// and fails closed if `actor` claims a seat registered in `.chinwag/allowed_signers` without a
/// valid matching `Ed25519` signature!
fn build_and_verify_beacon_bus_message(
    store_root: &Path,
    addr: &ActorAddress,
    msg_id: &str,
    ts_unix: u64,
    ticket_id: &str,
    body: &str,
) -> Result<(BusMessage, bool), String> {
    let actor_str = addr.to_string();
    let seat_upper = addr.seat().to_ascii_uppercase();
    let repo_signers = load_repo_allowed_signers(store_root);
    let matching_repo_entries: Vec<&RepoAllowedSignerEntry> = repo_signers
        .iter()
        .filter(|e| entry_matches_seat(e, &seat_upper))
        .collect();
    let seat_registered_in_repo = !matching_repo_entries.is_empty();

    let secret_opt = load_actor_signing_secret(addr);
    let sender_ep = secret_opt
        .as_ref()
        .map(|sk| sk.public().to_string())
        .unwrap_or_else(|| "local-crdb".to_owned());
    let task_opt = (!ticket_id.is_empty()).then(|| ticket_id.to_owned());
    let digest_sha256 = compute_bus_v1_digest(
        ts_unix,
        "#all",
        &actor_str,
        &sender_ep,
        None,
        task_opt.as_deref(),
        body,
    );
    let mut msg = BusMessage {
        id: msg_id.to_owned(),
        seq: 0,
        ts_unix,
        ts_iso: ts_unix.to_string(),
        room: "#all".to_owned(),
        sender: actor_str,
        sender_cast: if addr.is_human() {
            "●".to_owned()
        } else {
            "■".to_owned()
        },
        sender_endpoint_id: sender_ep,
        to: None,
        task_id: task_opt,
        body: body.to_owned(),
        digest_sha256,
        pubkey_ed25519: None,
        signature_ed25519: None,
        sig_verified: false,
    };

    if let Some(secret) = secret_opt {
        let payload = canonical_bus_signing_payload(&msg);
        let sig = secret.sign(payload.as_bytes());
        let pubkey = secret.public();
        msg.pubkey_ed25519 = Some(pubkey.to_string());
        msg.signature_ed25519 = Some(hex_bytes(&sig.to_bytes()));

        let self_ok = pubkey.verify(payload.as_bytes(), &sig).is_ok();
        let in_repo_allowed = matching_repo_entries
            .iter()
            .any(|e| bool::from(e.pubkey_bytes.ct_eq(pubkey.as_bytes())));
        if self_ok && in_repo_allowed {
            msg.sig_verified = true;
        }
    }

    if seat_registered_in_repo && !msg.sig_verified {
        return Err(format!(
            "unverified_registered_seat_signature: seat `{}` is registered in .chinwag/allowed_signers without a valid matching Ed25519 signature",
            addr.seat()
        ));
    }

    let env_merger_match = std::env::var("CHINWAG_AUTHORIZED_MERGER_SEATS")
        .ok()
        .is_some_and(|raw| {
            raw.split(',')
                .map(str::trim)
                .any(|s| !s.is_empty() && s.eq_ignore_ascii_case(addr.seat()))
        });
    let authorized_merger =
        msg.sig_verified && (addr.is_human() || env_merger_match || repo_signers.len() == 1);

    Ok((msg, authorized_merger))
}

fn mirror_verified_beacon_to_journal(store_root: &Path, msg: &BusMessage) -> bool {
    if !msg.sig_verified {
        return false;
    }
    let Ok(canon_root) = fs::canonicalize(store_root) else {
        return false;
    };
    let Ok(mut sink) = NativeJournalSink::open(&canon_root) else {
        return false;
    };
    matches!(
        sink.persist_if_absent(msg),
        Ok(SinkDisposition::Stored { .. } | SinkDisposition::ExactReplay { .. })
    )
}

/// Atomically emits a signed coordination beacon (`TASK_CREATED`, `CLAIM_ACQUIRED`,
/// `PR_OPENED`, `PR_MERGED`, `RELEASE_BUILT`) into `.chinwag/state.crdb`, updates
/// `agent_claims` + `leases` in the same SQLite transaction, mirrors to `.chinwag/bus/messages.jsonl`
/// via `NativeJournalSink` when `sig_verified`, and refreshes `.chinwag/ACTIVE_WORK.md`.
pub fn emit_transactional_beacon(
    repo_or_worktree: &Path,
    req: &AutoBeaconRequest,
) -> Result<BeaconCommitReceipt, String> {
    let kind = req.kind.ok_or_else(|| "missing_beacon_kind".to_owned())?;
    let store_root = resolve_coord_store_root(repo_or_worktree);
    if !store_root.join(".chinwag").join("state.crdb").is_file() {
        return Err("crdb_store_not_initialized".to_owned());
    }
    clear_stale_crdb_locks(&store_root);

    let actor_addr = resolve_verified_actor(req.actor.as_deref())?;
    let actor = actor_addr.to_string();

    let worktree_path = req
        .worktree
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            fs::canonicalize(repo_or_worktree).unwrap_or_else(|_| repo_or_worktree.to_path_buf())
        });
    let worktree_label = sanitize_worktree_label(&store_root, &worktree_path);
    let raw_branch = req
        .branch_ref
        .clone()
        .unwrap_or_else(|| infer_branch_ref(&worktree_path));
    let branch_ref = scrub_coord_text(&raw_branch);
    let clean_ticket = scrub_coord_text(req.ticket_id.trim());
    let clean_summary = req.summary.as_deref().map(scrub_coord_text);
    let clean_pr_url = req.pr_url.as_deref().map(scrub_coord_text);
    let repo_id = scrub_coord_text(&infer_repo_id(&store_root));
    let created_at_ms = now_ms();
    let ts_unix = unix_secs();
    let ttl_ms = req.lease_ttl_ms.unwrap_or(DEFAULT_CLAIM_TTL_MS).max(1_000);
    let expires_at_ms = created_at_ms.saturating_add(ttl_ms);

    let mut claimed_paths: Vec<String> = req
        .claimed_paths
        .iter()
        .map(|s| scrub_coord_text(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();
    claimed_paths.sort();
    claimed_paths.dedup();

    let beacon_id = req.id.clone().unwrap_or_else(|| {
        let mut h = Sha256::new();
        h.update(kind.as_str().as_bytes());
        h.update(b"|");
        h.update(actor.as_bytes());
        h.update(b"|");
        h.update(clean_ticket.as_bytes());
        h.update(b"|");
        h.update(worktree_label.as_bytes());
        h.update(created_at_ms.to_be_bytes());
        let d = h.finalize();
        format!("bcn-{}-{}", created_at_ms, hex_bytes(&d[..6]))
    });

    let human_body = format!(
        "[AUTO-BEACON · {}] {} {} | actor={} | worktree={} | branch={} | paths={}",
        INV_UNIVERSAL_COORDINATION,
        kind.as_str(),
        if clean_ticket.is_empty() {
            "-"
        } else {
            &clean_ticket
        },
        actor,
        worktree_label,
        branch_ref,
        if claimed_paths.is_empty() {
            "-".to_owned()
        } else {
            claimed_paths.join(",")
        }
    );
    let (bus_msg, authorized_merger) = build_and_verify_beacon_bus_message(
        &store_root,
        &actor_addr,
        &beacon_id,
        ts_unix,
        &clean_ticket,
        &human_body,
    )?;
    let sig_verified = bus_msg.sig_verified;

    let payload_val = json!({
        "schema": "chinwag.live_coord.beacon.v1",
        "invariant": INV_UNIVERSAL_COORDINATION,
        "kind": kind.as_str(),
        "actor": &actor,
        "repo_id": &repo_id,
        "ticket_id": &clean_ticket,
        "worktree": &worktree_label,
        "branch_ref": &branch_ref,
        "claimed_paths": &claimed_paths,
        "pr_number": req.pr_number,
        "pr_url": clean_pr_url,
        "commit_sha": req.commit_sha,
        "release_binary": req.release_binary,
        "summary": clean_summary,
        "body": &human_body,
        "pubkey_ed25519": &bus_msg.pubkey_ed25519,
        "signature_ed25519": &bus_msg.signature_ed25519,
        "sig_verified": sig_verified,
        "authorized_merger": authorized_merger,
        "created_at_ms": created_at_ms,
        "lease_expires_at_ms": expires_at_ms,
    });
    let payload_json = serde_json::to_string(&payload_val).map_err(|e| e.to_string())?;
    let event_hash = format!(
        "sha256:{}",
        hex_bytes(&Sha256::digest(payload_json.as_bytes()))
    );

    let crdb_rec = LiveCoordBeaconRecord::try_new(
        beacon_id.clone(),
        kind.as_str().to_owned(),
        actor.clone(),
        repo_id,
        branch_ref.clone(),
        worktree_label.clone(),
        clean_ticket.clone(),
        claimed_paths.clone(),
        payload_json,
        event_hash,
        expires_at_ms,
        created_at_ms,
    )
    .map_err(str::to_owned)?;

    let owner = WriteOwner::acquire_existing_private_fixture(&store_root)
        .map_err(|e| format!("acquire_write_owner: {}", e.reason))?;
    let session = WriteSession::from_owner(owner).map_err(|e| format!("write_session: {e}"))?;
    let prepared = session
        .prepare_live_coord_beacon(crdb_rec, || false)
        .map_err(|e| format!("prepare_live_coord_beacon: {e}"))?;
    let completion = prepared
        .commit(false)
        .map_err(|e| format!("commit_live_coord_beacon: {e}"))?;
    if completion.is_error() {
        return Err(format!("crdb_beacon_refused: {}", completion.response()));
    }
    let resp = completion.response();
    let seq = resp["seq"].as_u64().unwrap_or(1);
    let claims_upserted = resp["claims_upserted"].as_u64().unwrap_or(0) as usize;
    let claims_released = resp["claims_released"].as_u64().unwrap_or(0) as usize;
    let new_db_version = completion.observation().new_db_version();

    // Advance the emitter's own CLI cursor ONLY when there are no unread intervening beacons
    // from peers (`prev_seq + 1 == seq`); otherwise preserve `prev_seq` so external beacons
    // in `(prev_seq..seq)` are delivered on the next delta check while `b.actor != actor`
    // still suppresses self-echo.
    if let Some(stamp) = fast_crdb_header_stamp(&store_root) {
        let cursors = load_cli_cursors(&store_root);
        let key = worktree_cursor_key(&actor, &worktree_path);
        let prev_seq = cursors.cursors.get(&key).map(|c| c.last_seen_seq);
        if prev_seq.unwrap_or(0).saturating_add(1) == seq {
            let _ = update_cli_cursor(
                &store_root,
                &actor,
                &worktree_path,
                &worktree_label,
                seq,
                stamp,
            );
        }
    }

    let mut final_bus_msg = bus_msg;
    final_bus_msg.seq = seq;
    let journal_mirrored = mirror_verified_beacon_to_journal(&store_root, &final_bus_msg);

    let mut active_work_updated = render_and_write_active_work(&store_root).is_ok();
    if worktree_path != store_root && worktree_path.is_dir() {
        active_work_updated |= copy_active_work_to_worktree(&store_root, &worktree_path).is_ok();
    }

    Ok(BeaconCommitReceipt {
        ok: true,
        invariant: INV_UNIVERSAL_COORDINATION.to_owned(),
        beacon_id,
        kind: kind.as_str().to_owned(),
        seq,
        db_version: new_db_version,
        actor,
        ticket_id: clean_ticket,
        worktree: worktree_label,
        branch_ref,
        claimed_paths,
        claims_upserted,
        claims_released,
        sig_verified,
        journal_mirrored,
        active_work_updated,
    })
}

/// Deterministic, replay-safe CRDB auto-beacon hook for `task_writer::commit_task_write`
/// transitions when `.chinwag/state.crdb` is present.
pub fn emit_task_writer_transition_beacon(
    repo_root: &Path,
    operation_id: &str,
    task_id: &str,
    canonical_task_path: &str,
    next_status_str: &str,
    signer_principal: &str,
) -> Result<(), String> {
    let kind = match next_status_str {
        "todo" => BeaconKind::TaskCreated,
        "in-progress" => BeaconKind::ClaimAcquired,
        "done-pending-review" => BeaconKind::PrOpened,
        "done" => BeaconKind::PrMerged,
        _ => return Ok(()),
    };
    let store_root = resolve_coord_store_root(repo_root);
    if !store_root.join(".chinwag").join("state.crdb").is_file() {
        return Ok(());
    }
    let actor_opt = if std::env::var_os("CHINWAG_ACTOR")
        .is_some_and(|v| !v.to_string_lossy().trim().is_empty())
    {
        None
    } else if ActorAddress::parse(signer_principal)
        .and_then(ActorAddress::require_instance)
        .is_ok()
    {
        Some(signer_principal.to_owned())
    } else {
        let sanitized: String = signer_principal
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let clean = sanitized.trim_matches('.');
        if clean.is_empty() {
            None
        } else {
            let bounded = &clean[..clean.len().min(96)];
            Some(format!("WRITER#{bounded}"))
        }
    };
    let op_slug: String = operation_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-'))
        .take(96)
        .collect();
    let det_id = (!op_slug.is_empty()).then(|| format!("bcn-tw-{op_slug}"));
    let req = AutoBeaconRequest {
        id: det_id,
        kind: Some(kind),
        actor: actor_opt,
        ticket_id: task_id.to_owned(),
        worktree: Some(repo_root.to_string_lossy().into_owned()),
        claimed_paths: if kind == BeaconKind::ClaimAcquired {
            vec![canonical_task_path.to_owned()]
        } else {
            Vec::new()
        },
        ..Default::default()
    };
    emit_transactional_beacon(&store_root, &req).map(|_| ())
}

/// Snapshot tuple returned by [`read_live_coord_snapshot`]:
/// `(pragma_data_version, db_version, active_claims, active_session_leases, recent_beacons)`.
pub type LiveCoordSnapshot = (
    i64,
    i64,
    Vec<ActiveClaimView>,
    Vec<ActiveSessionLeaseView>,
    Vec<StoredBeaconView>,
);

/// Reads active claims, live session leases, and stored beacons from `.chinwag/state.crdb`.
pub fn read_live_coord_snapshot(repo_or_worktree: &Path) -> Result<LiveCoordSnapshot, String> {
    let store_root = resolve_coord_store_root(repo_or_worktree);
    if !store_root.join(".chinwag").join("state.crdb").is_file() {
        return Ok((0, 0, Vec::new(), Vec::new(), Vec::new()));
    }
    clear_stale_crdb_locks(&store_root);
    let owner = ReadOwner::acquire_existing_private_fixture(&store_root)
        .map_err(|e| format!("acquire_read_owner: {}", e.reason))?;
    let session = SnapshotSession::from_owner(owner).map_err(|e| e.to_string())?;
    let now = now_ms();
    let versions = session.pragma_data_and_db_version().unwrap_or((0, 0));
    let claims_leases = session.live_coord_claims_and_leases(now);
    let beacons_res = session.live_coord_beacons();
    session.finish().map_err(|e| e.to_string())?;

    let (claim_rows, lease_rows) = claims_leases.map_err(|e| e.to_string())?;
    let beacon_rows = beacons_res.map_err(|e| e.to_string())?;

    let mut lease_by_claim: BTreeMap<String, (String, String, i64)> = BTreeMap::new();
    let mut session_leases = Vec::new();
    for row in &lease_rows {
        let [
            SqlValue::Text(lease_id),
            SqlValue::Text(claim_id),
            SqlValue::Text(owner_actor),
            SqlValue::Text(meta_str),
            SqlValue::Integer(expires_at_ms),
            SqlValue::Integer(observed_at_ms),
        ] = row.as_slice()
        else {
            continue;
        };
        if *expires_at_ms < now {
            continue;
        }
        let meta: Value = serde_json::from_str(meta_str).unwrap_or_else(|_| json!({}));
        if claim_id == LIVE_SESSION_LEASE_CLAIM_ID {
            session_leases.push(ActiveSessionLeaseView {
                lease_id: lease_id.clone(),
                actor_instance: owner_actor.clone(),
                pid: meta["pid"].as_u64().unwrap_or(0) as u32,
                worktree: meta["worktree"].as_str().unwrap_or("").to_owned(),
                last_seen_seq: meta["last_seen_seq"].as_u64().unwrap_or(0),
                updated_at_ms: *observed_at_ms,
                expires_at_ms: *expires_at_ms,
            });
        } else {
            let wt = meta["worktree"]
                .as_str()
                .unwrap_or(meta_str.as_str())
                .to_owned();
            let br = meta["branch_ref"].as_str().unwrap_or("").to_owned();
            lease_by_claim.insert(claim_id.clone(), (wt, br, *expires_at_ms));
        }
    }

    let mut active_claims = Vec::new();
    for row in &claim_rows {
        let [
            SqlValue::Text(claim_id),
            SqlValue::Text(file_path),
            SqlValue::Text(ticket_id),
            SqlValue::Text(owner_actor),
            SqlValue::Text(_auth_hash),
            SqlValue::Integer(observed_at_ms),
        ] = row.as_slice()
        else {
            continue;
        };
        let Some((worktree, branch_ref, expires_at_ms)) = lease_by_claim.get(claim_id) else {
            continue;
        };
        active_claims.push(ActiveClaimView {
            claim_id: claim_id.clone(),
            path_glob: file_path.clone(),
            ticket_id: ticket_id.clone(),
            owner_actor: owner_actor.clone(),
            worktree: worktree.clone(),
            branch_ref: branch_ref.clone(),
            observed_at_ms: *observed_at_ms,
            expires_at_ms: *expires_at_ms,
        });
    }

    let beacons = parse_stored_beacons(&beacon_rows);
    Ok((
        versions.0,
        versions.1,
        active_claims,
        session_leases,
        beacons,
    ))
}

fn parse_stored_beacons(rows: &Rows) -> Vec<StoredBeaconView> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let [
            SqlValue::Text(id),
            SqlValue::Text(actor),
            SqlValue::Text(role),
            SqlValue::Text(body),
            SqlValue::Integer(created_at_ms),
        ] = row.as_slice()
        else {
            continue;
        };
        let (seq_str, kind_str) = role.split_once(':').unwrap_or(("0", role.as_str()));
        let seq = seq_str.parse::<u64>().unwrap_or(0);
        let parsed: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
        let ticket_id = parsed["ticket_id"].as_str().unwrap_or("").to_owned();
        let worktree = parsed["worktree"].as_str().unwrap_or("").to_owned();
        let branch_ref = parsed["branch_ref"].as_str().unwrap_or("").to_owned();
        let sig_verified = parsed["sig_verified"].as_bool().unwrap_or(false);
        let claimed_paths = parsed["claimed_paths"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        out.push(StoredBeaconView {
            seq,
            beacon_id: id.clone(),
            kind: kind_str.to_owned(),
            actor: actor.clone(),
            ticket_id,
            worktree,
            branch_ref,
            claimed_paths,
            sig_verified,
            created_at_ms: *created_at_ms,
        });
    }
    out.sort_by_key(|b| b.seq);
    out
}

/// Persists a live session lease `(actor_instance, pid, worktree, last_seen_seq)` directly in `.chinwag/state.crdb`.
pub fn register_session_lease_crdb(
    repo_or_worktree: &Path,
    actor_override: Option<&str>,
    last_seen_seq_override: Option<u64>,
) -> Result<Value, String> {
    let store_root = resolve_coord_store_root(repo_or_worktree);
    clear_stale_crdb_locks(&store_root);
    let actor = resolve_verified_actor(actor_override)?.to_string();
    let pid = std::process::id();
    let worktree = sanitize_worktree_label(&store_root, repo_or_worktree);
    let seq = match last_seen_seq_override {
        Some(s) => s,
        None => {
            let (_, _, _, _, beacons) = read_live_coord_snapshot(&store_root)?;
            beacons.iter().map(|b| b.seq).max().unwrap_or(0)
        }
    };
    let now = now_ms();
    let expires = now.saturating_add(DEFAULT_SESSION_TTL_MS);
    let rec = LiveSessionLeaseRecord::try_new(actor, pid, worktree, seq, now, expires)
        .map_err(str::to_owned)?;
    let owner = WriteOwner::acquire_existing_private_fixture(&store_root)
        .map_err(|e| format!("acquire_write_owner: {}", e.reason))?;
    let session = WriteSession::from_owner(owner).map_err(|e| e.to_string())?;
    let prepared = session
        .prepare_live_session_lease(rec, || false)
        .map_err(|e| e.to_string())?;
    let completion = prepared.commit(false).map_err(|e| e.to_string())?;
    if completion.is_error() {
        Err(completion.response().to_string())
    } else {
        let _ = render_and_write_active_work(&store_root);
        Ok(completion.response().clone())
    }
}

fn load_cli_cursors(store_root: &Path) -> CliCursorStateFile {
    let path = store_root.join(".chinwag").join(CLI_CURSOR_FILE);
    let Ok(fd) = openat(
        CWD,
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return CliCursorStateFile::default();
    };
    let mut raw = String::new();
    if File::from(fd).read_to_string(&mut raw).is_err() {
        return CliCursorStateFile::default();
    }
    serde_json::from_str(&raw).unwrap_or_default()
}

fn update_cli_cursor(
    store_root: &Path,
    actor: &str,
    worktree_path: &Path,
    worktree_label: &str,
    last_seen_seq: u64,
    stamp: CrdbHeaderStamp,
) -> Result<(), String> {
    let chinwag_dir = store_root.join(".chinwag");
    if !chinwag_dir.is_dir() {
        return Ok(());
    }
    let mut state = load_cli_cursors(store_root);
    let key = worktree_cursor_key(actor, worktree_path);
    state.cursors.insert(
        key,
        CliCursorEntry {
            actor_instance: actor.to_owned(),
            pid: std::process::id(),
            worktree: worktree_label.to_owned(),
            last_seen_seq,
            sqlite_change_counter: stamp.sqlite_change_counter,
            crdb_ino: stamp.ino,
            crdb_size: stamp.size,
            updated_at_ms: now_ms(),
        },
    );
    write_private_regular_file_atomic(
        &chinwag_dir.join(CLI_CURSOR_FILE),
        &serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?,
        0o600,
    )
}

/// Checks `.chinwag/state.crdb` in `<1ms` (using the 100-byte SQLite header change counter
/// fast path) and emits `[chinwag-bus-delta]` + any active crisis banner to `stderr`.
pub fn emit_live_coord_delta_if_any(
    repo_or_worktree: &Path,
    stderr: &mut dyn Write,
) -> Option<Value> {
    let store_root = resolve_coord_store_root(repo_or_worktree);
    crate::board::emit_active_crisis_alert_if_any(&store_root, stderr);

    let stamp = fast_crdb_header_stamp(&store_root)?;
    let actor = resolve_current_actor(None);
    let worktree_label = sanitize_worktree_label(&store_root, repo_or_worktree);
    let key = worktree_cursor_key(&actor, repo_or_worktree);
    let cursors = load_cli_cursors(&store_root);

    if let Some(existing) = cursors.cursors.get(&key)
        && existing.sqlite_change_counter == stamp.sqlite_change_counter
        && existing.crdb_ino == stamp.ino
        && existing.crdb_size == stamp.size
    {
        return None;
    }

    let from_seq = cursors
        .cursors
        .get(&key)
        .map(|c| c.last_seen_seq)
        .unwrap_or(0);
    let has_prior_cursor = cursors.cursors.contains_key(&key);

    let Ok((data_version, db_version, _, _, beacons)) = read_live_coord_snapshot(&store_root)
    else {
        return None;
    };
    let max_seq = beacons.iter().map(|b| b.seq).max().unwrap_or(from_seq);
    let _ = update_cli_cursor(
        &store_root,
        &actor,
        repo_or_worktree,
        &worktree_label,
        max_seq,
        stamp,
    );

    // If this is the very first CLI invocation by an anonymous/new cursor and no explicit
    // CHINWAG_ACTOR was bound, avoid spamming historical beacons; when CHINWAG_ACTOR IS set
    // or a cursor already exists, deliver all external beacons > from_seq!
    if !has_prior_cursor && std::env::var_os("CHINWAG_ACTOR").is_none() {
        return None;
    }

    let unread: Vec<&StoredBeaconView> = beacons
        .iter()
        .filter(|b| b.seq > from_seq && b.actor != actor)
        .collect();
    if unread.is_empty() {
        return None;
    }

    let mut snippets = Vec::with_capacity(unread.len().min(8));
    for b in unread.iter().take(8) {
        let paths = if b.claimed_paths.is_empty() {
            String::new()
        } else {
            format!(" [{}]", scrub_coord_text(&b.claimed_paths.join(",")))
        };
        let ticket = if b.ticket_id.is_empty() {
            "-".to_owned()
        } else {
            scrub_coord_text(&b.ticket_id)
        };
        snippets.push(format!(
            "#{} {} {} by {}{}",
            b.seq, b.kind, ticket, b.actor, paths
        ));
    }
    if unread.len() > 8 {
        snippets.push(format!("+{} more", unread.len() - 8));
    }
    let line = truncate_utf8(
        &scrub_coord_text(&format!(
            "[chinwag-bus-delta · {INV_UNIVERSAL_COORDINATION}] seq {}..={} (data_v={data_version}, db_v={db_version}): {}",
            from_seq.saturating_add(1),
            max_seq,
            snippets.join("; ")
        )),
        MAX_DELTA_LINE_BYTES,
    );
    let _ = writeln!(stderr, "{line}");

    Some(json!({
        "invariant": INV_UNIVERSAL_COORDINATION,
        "from_seq_exclusive": from_seq,
        "through_seq_inclusive": max_seq,
        "data_version": data_version,
        "db_version": db_version,
        "summary": line,
        "beacons": unread,
    }))
}

pub fn emit_live_coord_delta_from_cwd(stderr: &mut dyn Write) -> Option<Value> {
    if let Ok(repo_env) = std::env::var("CHINWAG_REPO_ROOT") {
        let p = PathBuf::from(repo_env);
        if p.exists() {
            return emit_live_coord_delta_if_any(&p, stderr);
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        return emit_live_coord_delta_if_any(&cwd, stderr);
    }
    None
}

/// Renders `.chinwag/ACTIVE_WORK.md` (`0600`) so raw local/open-weight models with zero
/// MCP or `chinwag` CLI calls see active path claims, session leases, and recent beacons.
pub fn render_active_work_markdown(
    claims: &[ActiveClaimView],
    sessions: &[ActiveSessionLeaseView],
    beacons: &[StoredBeaconView],
) -> String {
    let mut out = String::from(
        "# Chinwag Active Work & Claimed Surfaces (`INV-UNIVERSAL-COORDINATION-01`)\n\n\
         > **DO NOT EDIT OVERLAPPING CLAIMED PATHS.** Repo-local Git hooks (`pre-commit`,\n\
         > `post-checkout`, `reference-transaction`) enforce these claims via `chinwag bus check-claims`.\n\n",
    );

    out.push_str("## Active Path Claims\n\n");
    if claims.is_empty() {
        out.push_str("_No active path claims._\n\n");
    } else {
        out.push_str("| Ticket | Owner Actor | Path Glob | Branch | Worktree |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for c in claims {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` |\n",
                if c.ticket_id.is_empty() {
                    "-".to_owned()
                } else {
                    scrub_coord_text(&c.ticket_id)
                },
                scrub_coord_text(&c.owner_actor),
                scrub_coord_text(&c.path_glob),
                if c.branch_ref.is_empty() {
                    "-".to_owned()
                } else {
                    scrub_coord_text(&c.branch_ref)
                },
                if c.worktree.is_empty() {
                    "-".to_owned()
                } else {
                    scrub_coord_text(&c.worktree)
                },
            ));
        }
        out.push('\n');
    }

    out.push_str("## Live MCP & CLI Session Leases\n\n");
    if sessions.is_empty() {
        out.push_str("_No active session leases._\n\n");
    } else {
        out.push_str("| Actor Instance | PID | Last Seen Seq | Worktree |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for s in sessions {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` |\n",
                scrub_coord_text(&s.actor_instance),
                s.pid,
                s.last_seen_seq,
                scrub_coord_text(&s.worktree)
            ));
        }
        out.push('\n');
    }

    out.push_str("## Recent Coordination Beacons\n\n");
    if beacons.is_empty() {
        out.push_str("_No beacons recorded yet._\n");
    } else {
        let start = beacons.len().saturating_sub(15);
        for b in beacons[start..].iter().rev() {
            let paths = if b.claimed_paths.is_empty() {
                String::new()
            } else {
                format!(
                    " — paths: `{}`",
                    scrub_coord_text(&b.claimed_paths.join(", "))
                )
            };
            out.push_str(&format!(
                "- **#{} `{}`** `{}` by `{}` (`{}`){}\n",
                b.seq,
                b.kind,
                if b.ticket_id.is_empty() {
                    "-".to_owned()
                } else {
                    scrub_coord_text(&b.ticket_id)
                },
                scrub_coord_text(&b.actor),
                if b.branch_ref.is_empty() {
                    "HEAD".to_owned()
                } else {
                    scrub_coord_text(&b.branch_ref)
                },
                paths
            ));
        }
    }
    out
}

pub fn render_and_write_active_work(repo_or_worktree: &Path) -> Result<PathBuf, String> {
    let store_root = resolve_coord_store_root(repo_or_worktree);
    let (_, _, claims, sessions, beacons) = read_live_coord_snapshot(&store_root)?;
    let md = render_active_work_markdown(&claims, &sessions, &beacons);
    let target = store_root.join(".chinwag").join("ACTIVE_WORK.md");
    if store_root.join(".chinwag").is_dir() {
        write_private_regular_file_atomic(&target, md.as_bytes(), 0o600)?;
    }
    sync_linked_worktrees_floor(&store_root, None, Some(&md));
    Ok(target)
}

fn ensure_private_worktree_chinwag_dir(worktree: &Path) -> Result<PathBuf, String> {
    let dir = worktree.join(".chinwag");
    if let Ok(st) = statat(CWD, &dir, AtFlags::SYMLINK_NOFOLLOW) {
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            return Err("refusing_non_directory_worktree_chinwag".to_owned());
        }
    } else {
        fs::create_dir(&dir).map_err(|e| format!("create_worktree_chinwag: {e}"))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod_worktree_chinwag: {e}"))?;
    }
    Ok(dir)
}

fn copy_active_work_to_worktree(store_root: &Path, worktree: &Path) -> Result<(), String> {
    let src = store_root.join(".chinwag").join("ACTIVE_WORK.md");
    let bytes = fs::read(&src).map_err(|e| e.to_string())?;
    let cw_dir = ensure_private_worktree_chinwag_dir(worktree)?;
    let dst = cw_dir.join("ACTIVE_WORK.md");
    write_private_regular_file_atomic(&dst, &bytes, 0o600)
}

fn write_private_regular_file_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "missing_parent_directory".to_owned())?;
    let parent_st =
        statat(CWD, parent, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| format!("parent_stat: {e}"))?;
    if FileType::from_raw_mode(parent_st.st_mode) != FileType::Directory {
        return Err("parent_not_directory".to_owned());
    }
    if let Ok(existing_st) = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW) {
        let ft = FileType::from_raw_mode(existing_st.st_mode);
        if ft == FileType::Symlink || ft != FileType::RegularFile {
            return Err("refusing_symlink_or_nonregular_target".to_owned());
        }
        if existing_st.st_nlink > 1 {
            return Err("refusing_hardlinked_target".to_owned());
        }
    }
    let nonce = csprng_hex_16()?;
    let tmp_name = format!(
        ".{}.tmp.{}.{nonce}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("coord"),
        std::process::id(),
    );
    let tmp_path = parent.join(tmp_name);
    let fd = openat(
        CWD,
        &tmp_path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode as _),
    )
    .map_err(|e| format!("open_tmp: {e}"))?;
    let mut file = File::from(fd);
    if let Err(e) = file
        .set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("write_tmp: {e}"));
    }
    drop(file);
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("rename_tmp: {e}")
    })
}

fn walk_dir_components_nofollow(base: &Path, rel_or_abs: &Path) -> Result<PathBuf, String> {
    let mut cur = if rel_or_abs.is_absolute() {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
    };
    for comp in rel_or_abs.components() {
        match comp {
            Component::RootDir => {
                cur = PathBuf::from("/");
            }
            Component::CurDir => {}
            Component::ParentDir => {
                let cst = statat(CWD, &cur, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| "missing_gitdir_ancestor".to_owned())?;
                if FileType::from_raw_mode(cst.st_mode) != FileType::Directory {
                    return Err("refusing_symlink_in_gitdir_or_commondir".to_owned());
                }
                if !cur.pop() {
                    return Err("refusing_root_escape_in_commondir".to_owned());
                }
            }
            Component::Normal(seg) => {
                cur.push(seg);
                let cst = statat(CWD, &cur, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| "missing_gitdir_or_commondir_target".to_owned())?;
                if FileType::from_raw_mode(cst.st_mode) != FileType::Directory {
                    return Err("refusing_symlink_or_non_directory_in_gitdir".to_owned());
                }
            }
            Component::Prefix(_) => {
                return Err("refusing_prefix_in_gitdir".to_owned());
            }
        }
    }
    Ok(cur)
}

fn reject_forbidden_home_git_dir(git_dir: &Path) -> Result<(), String> {
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        if git_dir == home {
            return Err("refusing_home_root_as_git_dir".to_owned());
        }
        for forbidden_rel in [".claude", ".gemini", ".codex", ".config"] {
            if git_dir.starts_with(home.join(forbidden_rel)) {
                return Err("refusing_global_home_dotfile_hooks_dir".to_owned());
            }
        }
    }
    Ok(())
}

fn resolve_git_common_dir(repo_root: &Path) -> Result<Option<PathBuf>, String> {
    let repo_canon = fs::canonicalize(repo_root).map_err(|e| format!("canon_repo_root: {e}"))?;
    let dot_git = repo_canon.join(".git");
    let st = match statat(CWD, &dot_git, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(format!("stat_dot_git: {e}")),
    };
    let git_dir = match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory => dot_git,
        FileType::RegularFile => {
            if st.st_nlink > 1 {
                return Err("refusing_hardlinked_dot_git".to_owned());
            }
            let raw = fs::read_to_string(&dot_git).map_err(|e| e.to_string())?;
            let rel_or_abs = raw
                .trim()
                .strip_prefix("gitdir:")
                .map(str::trim)
                .ok_or_else(|| "invalid_gitdir_pointer".to_owned())?;
            if rel_or_abs.starts_with('~') {
                return Err("refusing_tilde_gitdir_pointer".to_owned());
            }
            let resolved = walk_dir_components_nofollow(&repo_canon, Path::new(rel_or_abs))?;
            // Linked worktree gitdirs point at `<common>/.git/worktrees/<name>`; Git executes hooks
            // from `<common>/.git/hooks` unless overridden. Walk `commondir` with SYMLINK_NOFOLLOW.
            let commondir_file = resolved.join("commondir");
            if let Ok(cst) = statat(CWD, &commondir_file, AtFlags::SYMLINK_NOFOLLOW) {
                if FileType::from_raw_mode(cst.st_mode) == FileType::Symlink {
                    return Err("refusing_symlink_commondir_file".to_owned());
                }
                if FileType::from_raw_mode(cst.st_mode) == FileType::RegularFile
                    && let Ok(common_rel) = fs::read_to_string(&commondir_file)
                {
                    let trimmed = common_rel.trim();
                    if trimmed.starts_with('~') {
                        return Err("refusing_tilde_commondir".to_owned());
                    }
                    walk_dir_components_nofollow(&resolved, Path::new(trimmed))?
                } else {
                    resolved
                }
            } else {
                resolved
            }
        }
        _ => return Err("refusing_symlink_or_special_dot_git".to_owned()),
    };
    reject_forbidden_home_git_dir(&git_dir)?;
    Ok(Some(git_dir))
}

fn resolve_contained_hooks_path(
    repo_root: &Path,
    repo_canon: &Path,
    raw_cfg: &str,
    create_missing: bool,
) -> Result<PathBuf, String> {
    let trimmed = raw_cfg.trim();
    if trimmed.starts_with('~') {
        return Err("refusing_tilde_core_hooks_path".to_owned());
    }
    let cfg_path = Path::new(trimmed);
    if cfg_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("refusing_parent_traversal_core_hooks_path".to_owned());
    }
    let rel = if cfg_path.is_absolute() {
        cfg_path
            .strip_prefix(repo_canon)
            .or_else(|_| cfg_path.strip_prefix(repo_root))
            .map_err(|_| "refusing_external_core_hooks_path".to_owned())?
    } else {
        cfg_path
    };
    let mut normal_segs = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => {
                if seg == "~" {
                    return Err("refusing_tilde_core_hooks_path".to_owned());
                }
                normal_segs.push(seg);
            }
            Component::CurDir => {}
            _ => return Err("refusing_invalid_core_hooks_path".to_owned()),
        }
    }
    if normal_segs.is_empty() {
        return Err("refusing_repo_root_as_hooks_path".to_owned());
    }

    let mut cur = repo_canon.to_path_buf();
    let mut missing_ancestor = false;
    for seg in normal_segs {
        cur.push(seg);
        if missing_ancestor {
            continue;
        }
        match statat(CWD, &cur, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => {
                let ft = FileType::from_raw_mode(st.st_mode);
                if ft == FileType::Symlink {
                    return Err("refusing_symlink_in_core_hooks_path".to_owned());
                }
                if ft != FileType::Directory {
                    return Err("refusing_non_directory_hooks_path".to_owned());
                }
            }
            Err(rustix::io::Errno::NOENT) => {
                if create_missing {
                    fs::create_dir(&cur).map_err(|e| format!("create_hooks_dir_component: {e}"))?;
                    fs::set_permissions(&cur, fs::Permissions::from_mode(0o700))
                        .map_err(|e| format!("chmod_hooks_dir_component: {e}"))?;
                } else {
                    missing_ancestor = true;
                }
            }
            Err(e) => {
                return Err(format!("stat_hooks_dir_component: {e}"));
            }
        }
    }
    Ok(cur)
}

fn read_configured_core_hooks_path(repo_canon: &Path) -> Result<Option<String>, String> {
    if let Ok(raw_out) = Command::new(git_bin())
        .args([
            "-C",
            &repo_canon.to_string_lossy(),
            "config",
            "--get",
            "core.hooksPath",
        ])
        .output()
        && raw_out.status.success()
    {
        let raw_cfg = String::from_utf8_lossy(&raw_out.stdout).trim().to_owned();
        if raw_cfg.starts_with('~') {
            return Err("refusing_tilde_core_hooks_path".to_owned());
        }
        if !raw_cfg.is_empty() {
            if let Ok(path_out) = Command::new(git_bin())
                .args([
                    "-C",
                    &repo_canon.to_string_lossy(),
                    "config",
                    "--type=path",
                    "--get",
                    "core.hooksPath",
                ])
                .output()
                && path_out.status.success()
            {
                let expanded = String::from_utf8_lossy(&path_out.stdout).trim().to_owned();
                if expanded.starts_with('~') {
                    return Err("refusing_tilde_core_hooks_path".to_owned());
                }
                let exp_path = Path::new(&expanded);
                if exp_path.is_absolute() && !exp_path.starts_with(repo_canon) {
                    return Err("refusing_external_core_hooks_path".to_owned());
                }
            }
            return Ok(Some(raw_cfg));
        }
    }
    Ok(None)
}

fn resolve_repo_local_git_hooks_dir(repo_root: &Path) -> Result<PathBuf, String> {
    let git_dir = resolve_git_common_dir(repo_root)?.ok_or_else(|| "missing_dot_git".to_owned())?;
    let repo_canon = fs::canonicalize(repo_root).map_err(|e| format!("canon_repo_root: {e}"))?;
    reject_forbidden_home_git_dir(&git_dir)?;

    if let Some(raw_cfg) = read_configured_core_hooks_path(&repo_canon)? {
        return resolve_contained_hooks_path(repo_root, &repo_canon, &raw_cfg, true);
    }

    let hooks_dir = git_dir.join("hooks");
    if let Ok(hst) = statat(CWD, &hooks_dir, AtFlags::SYMLINK_NOFOLLOW) {
        if FileType::from_raw_mode(hst.st_mode) != FileType::Directory {
            return Err("refusing_non_directory_hooks_path".to_owned());
        }
    } else {
        fs::create_dir(&hooks_dir).map_err(|e| format!("create_hooks_dir: {e}"))?;
        fs::set_permissions(&hooks_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod_hooks_dir: {e}"))?;
    }
    Ok(hooks_dir)
}

fn build_hook_script(hook_name: &str, fallback_exe: Option<&Path>) -> String {
    let fallback_clause = fallback_exe
        .and_then(|p| p.to_str())
        .filter(|s| !s.contains('\'') && !s.contains('\n'))
        .map(|s| {
            format!("if [ -z \"$CHINWAG_BIN\" ] && [ -x '{s}' ]; then CHINWAG_BIN='{s}'; fi\n")
        })
        .unwrap_or_default();

    let invoke_line = match hook_name {
        "pre-commit" => {
            "if [ -z \"$CHINWAG_BIN\" ] || [ ! -x \"$CHINWAG_BIN\" ]; then\n  echo \"chinwag pre-commit BLOCKED [INV-UNIVERSAL-COORDINATION-01]: chinwag binary unavailable; refusing unverified commit\" >&2\n  exit 1\nfi\n\"$CHINWAG_BIN\" bus check-claims --hook pre-commit --staged || exit $?"
        }
        "post-checkout" => {
            "if [ -n \"$CHINWAG_BIN\" ] && [ -x \"$CHINWAG_BIN\" ]; then\n  \"$CHINWAG_BIN\" bus check-claims --hook post-checkout --checkout \"${1:-}\" \"${2:-}\" >/dev/null || true\nfi"
        }
        "reference-transaction" => {
            "if [ \"$1\" = \"prepared\" ]; then\n  if [ -z \"$CHINWAG_BIN\" ] || [ ! -x \"$CHINWAG_BIN\" ]; then\n    cat >/dev/null || true\n    echo \"chinwag reference-transaction BLOCKED [INV-UNIVERSAL-COORDINATION-01]: chinwag binary unavailable; refusing unverified ref update\" >&2\n    exit 1\n  fi\n  \"$CHINWAG_BIN\" bus check-claims --hook reference-transaction --state prepared --stdin-ref-tx >/dev/null || exit $?\nelif [ \"$1\" = \"committed\" ] && [ -n \"$CHINWAG_BIN\" ] && [ -x \"$CHINWAG_BIN\" ]; then\n  cat >/dev/null || true\n  \"$CHINWAG_BIN\" bus check-claims --hook reference-transaction --state committed >/dev/null || true\nelse\n  cat >/dev/null || true\nfi"
        }
        _ => "",
    };

    format!(
        "#!/bin/sh\n\
         {HOOK_SENTINEL}\n\
         # Repo-local Chinwag claim-check floor ({INV_UNIVERSAL_COORDINATION}).\n\
         # Zero $HOME vendor dotfile hooks required.\n\
         HOOK_DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n\
         if [ -x \"$HOOK_DIR/{hook_name}.pre-chinwag\" ]; then\n\
           \"$HOOK_DIR/{hook_name}.pre-chinwag\" \"$@\" || exit $?\n\
         fi\n\
         {fallback_clause}\
         CHINWAG_BIN=\"${{CHINWAG_BIN:-$(command -v chinwag 2>/dev/null || true)}}\"\n\
         {invoke_line}\n\
         exit 0\n"
    )
}

/// Read-only preflight check ensuring repo-local Git hooks can be safely installed inside
/// `repo_root` without mutating any directories or files before `.chinwag/state.crdb` creation.
pub fn validate_repo_local_git_hooks_precondition(repo_root: &Path) -> Result<(), String> {
    let Some(git_dir) = resolve_git_common_dir(repo_root)? else {
        return Ok(());
    };
    let repo_canon = fs::canonicalize(repo_root).map_err(|e| format!("canon_repo_root: {e}"))?;
    reject_forbidden_home_git_dir(&git_dir)?;
    let hooks_dir = if let Some(raw_cfg) = read_configured_core_hooks_path(&repo_canon)? {
        resolve_contained_hooks_path(repo_root, &repo_canon, &raw_cfg, false)?
    } else {
        git_dir.join("hooks")
    };
    if let Ok(hst) = statat(CWD, &hooks_dir, AtFlags::SYMLINK_NOFOLLOW) {
        if FileType::from_raw_mode(hst.st_mode) != FileType::Directory {
            return Err("refusing_non_directory_hooks_path".to_owned());
        }
        for hook_name in ["post-checkout", "pre-commit", "reference-transaction"] {
            for candidate_name in [hook_name.to_owned(), format!("{hook_name}.pre-chinwag")] {
                let hp = hooks_dir.join(&candidate_name);
                if let Ok(est) = statat(CWD, &hp, AtFlags::SYMLINK_NOFOLLOW)
                    && FileType::from_raw_mode(est.st_mode) == FileType::Symlink
                {
                    return Err(format!("refusing_symlink_hook:{candidate_name}"));
                }
            }
        }
    }
    Ok(())
}

/// Installs repo-local Git claim-check hooks (`post-checkout`, `pre-commit`, `reference-transaction`)
/// and initializes `.chinwag/ACTIVE_WORK.md` (`0600`). Zero `$HOME` dotfile hooks touched.
pub fn install_repo_local_claim_floor(repo_root: &Path) -> Result<GitHookInstallReceipt, String> {
    let hooks_dir = resolve_repo_local_git_hooks_dir(repo_root)?;
    let fallback_exe = std::env::current_exe().ok().filter(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("chinwag"))
    });

    let mut installed = Vec::new();
    let mut chained = Vec::new();
    for hook_name in ["post-checkout", "pre-commit", "reference-transaction"] {
        let hook_path = hooks_dir.join(hook_name);
        if let Ok(existing_st) = statat(CWD, &hook_path, AtFlags::SYMLINK_NOFOLLOW) {
            if FileType::from_raw_mode(existing_st.st_mode) == FileType::Symlink {
                return Err(format!("refusing_symlink_hook:{hook_name}"));
            }
            if let Ok(existing_body) = fs::read_to_string(&hook_path)
                && !existing_body.contains(HOOK_SENTINEL)
            {
                let backup_path = hooks_dir.join(format!("{hook_name}.pre-chinwag"));
                if let Ok(bst) = statat(CWD, &backup_path, AtFlags::SYMLINK_NOFOLLOW) {
                    if FileType::from_raw_mode(bst.st_mode) == FileType::Symlink {
                        return Err(format!("refusing_symlink_hook:{hook_name}.pre-chinwag"));
                    }
                } else {
                    write_private_regular_file_atomic(
                        &backup_path,
                        existing_body.as_bytes(),
                        0o700,
                    )?;
                    chained.push(hook_name.to_owned());
                }
            }
        }
        let script = build_hook_script(hook_name, fallback_exe.as_deref());
        write_private_regular_file_atomic(&hook_path, script.as_bytes(), 0o700)?;
        installed.push(hook_name.to_owned());
    }

    let _active_work = render_and_write_active_work(repo_root)?;
    sync_linked_worktrees_floor(repo_root, fallback_exe.as_deref(), None);
    let hooks_rel = fs::canonicalize(repo_root)
        .ok()
        .and_then(|rc| hooks_dir.strip_prefix(&rc).ok().map(|p| p.to_path_buf()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| sanitize_worktree_label(repo_root, &hooks_dir));
    Ok(GitHookInstallReceipt {
        hooks_dir: hooks_rel,
        installed_hooks: installed,
        chained_existing_hooks: chained,
        active_work_path: ACTIVE_WORK_REL_PATH.to_owned(),
    })
}

/// Deterministic glob/path overlap matcher for repo-relative paths.
pub fn path_matches_claim_glob(candidate_path: &str, claim_glob: &str) -> bool {
    let path = candidate_path
        .trim()
        .trim_start_matches("./")
        .trim_matches('/');
    let glob = claim_glob.trim().trim_start_matches("./").trim_matches('/');
    if path.is_empty() || glob.is_empty() {
        return false;
    }
    if glob == "*" || glob == "**" || path == glob {
        return true;
    }
    if let Some(prefix) = glob.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = glob.strip_suffix("/*") {
        if let Some(rest) = path.strip_prefix(&format!("{prefix}/")) {
            return !rest.contains('/');
        }
        return false;
    }
    if !glob.contains('*') {
        return path == glob
            || path.starts_with(&format!("{glob}/"))
            || glob.starts_with(&format!("{path}/"));
    }
    wildcard_match(glob.as_bytes(), path.as_bytes())
}

fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut pi, mut ti) = (0_usize, 0_usize);
    let (mut star_pi, mut star_ti) = (None::<usize>, 0_usize);
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            while pi < pattern.len() && pattern[pi] == b'*' {
                pi += 1;
            }
            star_pi = Some(pi);
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

fn list_git_worktrees(store_root: &Path) -> Vec<PathBuf> {
    let Ok(out) = Command::new(git_bin())
        .args([
            "-C",
            &store_root.to_string_lossy(),
            "worktree",
            "list",
            "--porcelain",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn sync_linked_worktrees_floor(
    repo_or_worktree: &Path,
    fallback_exe_override: Option<&Path>,
    active_md_opt: Option<&str>,
) {
    let store_root = resolve_coord_store_root(repo_or_worktree);
    let Ok(store_canon) = fs::canonicalize(&store_root) else {
        return;
    };
    let rel_hooks_cfg = read_configured_core_hooks_path(&store_canon)
        .ok()
        .flatten()
        .filter(|cfg| Path::new(cfg).is_relative());
    let fallback_exe = fallback_exe_override.map(Path::to_path_buf).or_else(|| {
        std::env::current_exe().ok().filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("chinwag"))
        })
    });

    let owned_md;
    let md_bytes: Option<&[u8]> = if let Some(md) = active_md_opt {
        Some(md.as_bytes())
    } else if let Ok(existing) = fs::read(store_canon.join(".chinwag").join("ACTIVE_WORK.md")) {
        owned_md = existing;
        Some(owned_md.as_slice())
    } else {
        None
    };

    for wt in list_git_worktrees(&store_canon) {
        let Ok(wt_canon) = fs::canonicalize(&wt) else {
            continue;
        };
        if wt_canon == store_canon || !wt_canon.is_dir() {
            continue;
        }
        if let Some(bytes) = md_bytes
            && store_canon.join(".chinwag").join("state.crdb").is_file()
            && let Ok(cw_dir) = ensure_private_worktree_chinwag_dir(&wt_canon)
        {
            let _ = write_private_regular_file_atomic(&cw_dir.join("ACTIVE_WORK.md"), bytes, 0o600);
        }
        if let Some(ref rel_cfg) = rel_hooks_cfg
            && let Ok(wt_hooks_dir) =
                resolve_contained_hooks_path(&wt_canon, &wt_canon, rel_cfg, true)
        {
            let store_hooks_dir = store_canon.join(rel_cfg);
            for hook_name in ["post-checkout", "pre-commit", "reference-transaction"] {
                let pre_name = format!("{hook_name}.pre-chinwag");
                let src_pre = store_hooks_dir.join(&pre_name);
                let dst_pre = wt_hooks_dir.join(&pre_name);
                if statat(CWD, &src_pre, AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::RegularFile)
                    && !statat(CWD, &dst_pre, AtFlags::SYMLINK_NOFOLLOW)
                        .is_ok_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::Symlink)
                    && let Ok(pre_bytes) = fs::read(&src_pre)
                {
                    let _ = write_private_regular_file_atomic(&dst_pre, &pre_bytes, 0o700);
                }

                let hp = wt_hooks_dir.join(hook_name);
                if statat(CWD, &hp, AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::Symlink)
                {
                    continue;
                }
                let src_hp = store_hooks_dir.join(hook_name);
                if statat(CWD, &src_hp, AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::RegularFile)
                    && let Ok(src_bytes) = fs::read(&src_hp)
                {
                    let _ = write_private_regular_file_atomic(&hp, &src_bytes, 0o700);
                } else {
                    let script = build_hook_script(hook_name, fallback_exe.as_deref());
                    let _ = write_private_regular_file_atomic(&hp, script.as_bytes(), 0o700);
                }
            }
        }
    }
}

fn parse_nul_name_status(raw: &[u8]) -> Vec<String> {
    let mut fields = raw.split(|&b| b == 0).filter(|s| !s.is_empty());
    let mut paths = Vec::new();
    while let Some(status_bytes) = fields.next() {
        let status = String::from_utf8_lossy(status_bytes);
        let first = status.as_bytes().first().copied().unwrap_or(b'M');
        if matches!(first, b'R' | b'C') {
            if let Some(old_p) = fields.next() {
                let s = String::from_utf8_lossy(old_p).into_owned();
                if !s.is_empty() {
                    paths.push(s);
                }
            }
            if let Some(new_p) = fields.next() {
                let s = String::from_utf8_lossy(new_p).into_owned();
                if !s.is_empty() {
                    paths.push(s);
                }
            }
        } else if let Some(p) = fields.next() {
            let s = String::from_utf8_lossy(p).into_owned();
            if !s.is_empty() {
                paths.push(s);
            }
        }
    }
    paths
}

fn is_valid_non_zero_oid(oid: &str) -> bool {
    let trimmed = oid.trim();
    trimmed.len() >= 7
        && trimmed.len() <= 64
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
        && trimmed.bytes().any(|b| b != b'0')
}

fn diff_tree_paths(worktree: &Path, old_oid: &str, new_oid: &str) -> Vec<String> {
    if !is_valid_non_zero_oid(old_oid) || !is_valid_non_zero_oid(new_oid) || old_oid == new_oid {
        return Vec::new();
    }
    let Ok(out) = Command::new(git_bin())
        .args([
            "-c",
            "core.quotePath=false",
            "-C",
            &worktree.to_string_lossy(),
            "diff",
            "--name-status",
            "-z",
            old_oid,
            new_oid,
            "--",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_nul_name_status(&out.stdout)
}

fn ref_tx_stdin_paths(worktree: &Path) -> Vec<String> {
    let mut buf = String::new();
    let _ = std::io::stdin().take(256 * 1024).read_to_string(&mut buf);
    let mut paths = Vec::new();
    for line in buf.lines() {
        let mut parts = line.split_whitespace();
        let (Some(old_oid), Some(new_oid), Some(refname)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if refname.starts_with("refs/heads/") {
            paths.extend(diff_tree_paths(worktree, old_oid, new_oid));
        }
    }
    paths
}

fn staged_git_paths(worktree: &Path) -> Vec<String> {
    let Ok(out) = Command::new(git_bin())
        .args([
            "-c",
            "core.quotePath=false",
            "-C",
            &worktree.to_string_lossy(),
            "diff",
            "--cached",
            "--name-status",
            "-z",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_nul_name_status(&out.stdout)
}

pub fn evaluate_claim_conflicts(
    claims: &[ActiveClaimView],
    current_actor: &str,
    _current_worktree: &Path,
    candidate_paths: &[String],
) -> Vec<ClaimConflict> {
    let mut conflicts = Vec::new();
    for path in candidate_paths {
        for claim in claims {
            // Only the exact authenticated owner actor may commit to a claimed path.
            if claim.owner_actor == current_actor {
                continue;
            }
            if path_matches_claim_glob(path, &claim.path_glob) {
                conflicts.push(ClaimConflict {
                    candidate_path: path.clone(),
                    claimed_glob: claim.path_glob.clone(),
                    owner_actor: claim.owner_actor.clone(),
                    ticket_id: claim.ticket_id.clone(),
                    worktree: claim.worktree.clone(),
                    branch_ref: claim.branch_ref.clone(),
                });
            }
        }
    }
    conflicts
}

/// CLI entrypoint for `chinwag bus <check-claims|emit-beacon|session-lease|install-hooks> ...`.
pub fn run_bus_live_coord_cli(
    sub: &str,
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match sub {
        "check-claims" => run_check_claims_cmd(args, stdout, stderr),
        "emit-beacon" => run_emit_beacon_cmd(args, stdout, stderr),
        "session-lease" => run_session_lease_cmd(args, stdout, stderr),
        "install-hooks" => run_install_hooks_cmd(args, stdout, stderr),
        _ => {
            let _ = writeln!(stderr, "chinwag bus: unknown live-coord subcommand `{sub}`");
            2
        }
    }
}

fn resolve_worktree_arg(repo_arg: Option<&str>) -> Result<PathBuf, String> {
    if let Some(explicit) = repo_arg {
        return Ok(PathBuf::from(explicit));
    }
    if let Ok(env_repo) = std::env::var("CHINWAG_REPO_ROOT")
        && !env_repo.trim().is_empty()
    {
        return Ok(PathBuf::from(env_repo));
    }
    std::env::current_dir().map_err(|e| e.to_string())
}

fn run_check_claims_cmd(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut repo_arg: Option<String> = None;
    let mut actor_arg: Option<String> = None;
    let mut hook_arg: Option<String> = None;
    let mut state_arg: Option<String> = None;
    let mut staged = false;
    let mut stdin_ref_tx = false;
    let mut checkout_oids: Option<(String, String)> = None;
    let mut explicit_paths: Vec<String> = Vec::new();
    let mut is_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                let _ = writeln!(
                    stdout,
                    "Usage: chinwag bus check-claims [--repo <path>] [--from <actor>] [--staged] [--checkout <old> <new>] [--stdin-ref-tx] [--paths <p1,p2>] [--hook <name>] [--json]"
                );
                return 0;
            }
            "--repo" | "--worktree" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--from" | "--actor" if i + 1 < args.len() => {
                actor_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--hook" if i + 1 < args.len() => {
                hook_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--state" if i + 1 < args.len() => {
                state_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--staged" => {
                staged = true;
                i += 1;
            }
            "--stdin-ref-tx" => {
                stdin_ref_tx = true;
                i += 1;
            }
            "--checkout" if i + 2 < args.len() => {
                checkout_oids = Some((args[i + 1].clone(), args[i + 2].clone()));
                i += 3;
            }
            "--paths" if i + 1 < args.len() => {
                explicit_paths.extend(
                    args[i + 1]
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                );
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            flag if flag.starts_with('-') => {
                let _ = writeln!(
                    stderr,
                    "chinwag bus check-claims: invalid argument `{flag}`"
                );
                return 2;
            }
            pos => {
                explicit_paths.push(pos.to_owned());
                i += 1;
            }
        }
    }

    let worktree = match resolve_worktree_arg(repo_arg.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "chinwag bus check-claims: {e}");
            return 2;
        }
    };
    let store_root = resolve_coord_store_root(&worktree);
    let bus_delta = emit_live_coord_delta_if_any(&worktree, stderr);

    let (data_version, db_version, claims, sessions, beacons) =
        match read_live_coord_snapshot(&store_root) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(stderr, "chinwag bus check-claims: {e}");
                return 1;
            }
        };

    // Keep `.chinwag/ACTIVE_WORK.md` fresh on every checkout / ref-transaction / claim check.
    let md = render_active_work_markdown(&claims, &sessions, &beacons);
    if store_root.join(".chinwag").is_dir() {
        let _ = write_private_regular_file_atomic(
            &store_root.join(".chinwag").join("ACTIVE_WORK.md"),
            md.as_bytes(),
            0o600,
        );
    }
    if worktree != store_root
        && store_root.join(".chinwag").join("state.crdb").is_file()
        && worktree.is_dir()
        && let Ok(cw_dir) = ensure_private_worktree_chinwag_dir(&worktree)
    {
        let _ =
            write_private_regular_file_atomic(&cw_dir.join("ACTIVE_WORK.md"), md.as_bytes(), 0o600);
    }
    sync_linked_worktrees_floor(&store_root, None, Some(&md));

    let mut candidate_paths = explicit_paths;
    if staged {
        candidate_paths.extend(staged_git_paths(&worktree));
    }
    if stdin_ref_tx {
        candidate_paths.extend(ref_tx_stdin_paths(&worktree));
    }
    if let Some((ref old_oid, ref new_oid)) = checkout_oids {
        candidate_paths.extend(diff_tree_paths(&worktree, old_oid, new_oid));
    }
    candidate_paths.sort();
    candidate_paths.dedup();

    let actor = match resolve_verified_actor(actor_arg.as_deref()) {
        Ok(addr) => addr.to_string(),
        Err(e) => {
            let _ = writeln!(stderr, "chinwag bus check-claims: {e}");
            return 1;
        }
    };
    let conflicts = evaluate_claim_conflicts(&claims, &actor, &worktree, &candidate_paths);
    let warn_only = hook_arg.as_deref() == Some("post-checkout")
        || (hook_arg.as_deref() == Some("reference-transaction")
            && state_arg.as_deref() != Some("prepared"));
    let ok = conflicts.is_empty() || warn_only;

    if !conflicts.is_empty() {
        let label = if warn_only { "WARNING" } else { "BLOCKED" };
        for c in &conflicts {
            let _ = writeln!(
                stderr,
                "chinwag claim-check {label} [{INV_UNIVERSAL_COORDINATION}]: `{}` overlaps claimed glob `{}` owned by {} ({}) — see {}",
                c.candidate_path,
                c.claimed_glob,
                c.owner_actor,
                if c.ticket_id.is_empty() {
                    "active claim"
                } else {
                    &c.ticket_id
                },
                ACTIVE_WORK_REL_PATH
            );
        }
    } else if matches!(
        hook_arg.as_deref(),
        Some("post-checkout" | "reference-transaction")
    ) && !claims.is_empty()
    {
        let _ = writeln!(
            stderr,
            "[chinwag-active-work · {INV_UNIVERSAL_COORDINATION}] {} active path claim(s) recorded in {}",
            claims.len(),
            ACTIVE_WORK_REL_PATH
        );
    }

    let payload = json!({
        "ok": ok,
        "invariant": INV_UNIVERSAL_COORDINATION,
        "actor": actor,
        "hook": hook_arg,
        "data_version": data_version,
        "db_version": db_version,
        "checked_paths": candidate_paths,
        "active_claims_count": claims.len(),
        "active_sessions_count": sessions.len(),
        "conflicts": conflicts,
        "active_work_path": ACTIVE_WORK_REL_PATH,
        "bus_delta": bus_delta,
    });
    if is_json {
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else if ok {
        let _ = writeln!(
            stdout,
            "chinwag claim-check: ok ({} path(s) checked against {} active claim(s))",
            payload["checked_paths"].as_array().map_or(0, Vec::len),
            claims.len()
        );
    }
    if ok { 0 } else { 1 }
}

fn run_emit_beacon_cmd(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut repo_arg: Option<String> = None;
    let mut req = AutoBeaconRequest::default();
    let mut is_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                let _ = writeln!(
                    stdout,
                    "Usage: chinwag bus emit-beacon --kind <TASK_CREATED|CLAIM_ACQUIRED|PR_OPENED|PR_MERGED|RELEASE_BUILT> [--repo <path>] [--from <SEAT#INSTANCE>] [--task <TICKET_ID>] [--worktree <path>] [--branch <ref>] [--surfaces <g1,g2>] [--pr <num>] [--pr-url <url>] [--commit <sha>] [--binary <name>] [--json]"
                );
                return 0;
            }
            "--repo" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--kind" if i + 1 < args.len() => {
                req.kind = BeaconKind::parse(&args[i + 1]);
                if req.kind.is_none() {
                    let _ = writeln!(
                        stderr,
                        "chinwag bus emit-beacon: invalid --kind `{}`",
                        args[i + 1]
                    );
                    return 2;
                }
                i += 2;
            }
            "--from" | "--actor" if i + 1 < args.len() => {
                req.actor = Some(args[i + 1].clone());
                i += 2;
            }
            "--task" | "--ticket" if i + 1 < args.len() => {
                req.ticket_id = args[i + 1].clone();
                i += 2;
            }
            "--worktree" if i + 1 < args.len() => {
                req.worktree = Some(args[i + 1].clone());
                i += 2;
            }
            "--branch" if i + 1 < args.len() => {
                req.branch_ref = Some(args[i + 1].clone());
                i += 2;
            }
            "--surfaces" | "--paths" if i + 1 < args.len() => {
                req.claimed_paths.extend(
                    args[i + 1]
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned),
                );
                i += 2;
            }
            "--pr" if i + 1 < args.len() => {
                req.pr_number = args[i + 1].parse().ok();
                i += 2;
            }
            "--pr-url" if i + 1 < args.len() => {
                req.pr_url = Some(args[i + 1].clone());
                i += 2;
            }
            "--commit" if i + 1 < args.len() => {
                req.commit_sha = Some(args[i + 1].clone());
                i += 2;
            }
            "--binary" if i + 1 < args.len() => {
                req.release_binary = Some(args[i + 1].clone());
                i += 2;
            }
            "--summary" if i + 1 < args.len() => {
                req.summary = Some(args[i + 1].clone());
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            flag => {
                let _ = writeln!(stderr, "chinwag bus emit-beacon: invalid argument `{flag}`");
                return 2;
            }
        }
    }

    let worktree = match resolve_worktree_arg(repo_arg.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "chinwag bus emit-beacon: {e}");
            return 2;
        }
    };
    let _ = emit_live_coord_delta_if_any(&worktree, stderr);

    match emit_transactional_beacon(&worktree, &req) {
        Ok(receipt) => {
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&receipt).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "[{}] #{} {} {} by {} (db_v={}, claims +{} -{})",
                    receipt.invariant,
                    receipt.seq,
                    receipt.kind,
                    if receipt.ticket_id.is_empty() {
                        "-"
                    } else {
                        &receipt.ticket_id
                    },
                    receipt.actor,
                    receipt.db_version,
                    receipt.claims_upserted,
                    receipt.claims_released
                );
            }
            0
        }
        Err(err) => {
            let _ = writeln!(stderr, "chinwag bus emit-beacon: {err}");
            1
        }
    }
}

fn run_session_lease_cmd(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut repo_arg: Option<String> = None;
    let mut actor_arg: Option<String> = None;
    let mut seq_arg: Option<u64> = None;
    let mut is_json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" | "--worktree" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--from" | "--actor" if i + 1 < args.len() => {
                actor_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--last-seen-seq" if i + 1 < args.len() => {
                seq_arg = args[i + 1].parse().ok();
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let worktree = match resolve_worktree_arg(repo_arg.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "chinwag bus session-lease: {e}");
            return 2;
        }
    };
    match register_session_lease_crdb(&worktree, actor_arg.as_deref(), seq_arg) {
        Ok(val) => {
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&val).unwrap_or_default()
                );
            } else {
                let _ = writeln!(stdout, "session lease registered: {val}");
            }
            0
        }
        Err(e) => {
            let _ = writeln!(stderr, "chinwag bus session-lease: {e}");
            1
        }
    }
}

fn run_install_hooks_cmd(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let mut repo_arg: Option<String> = None;
    let mut is_json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let repo = match resolve_worktree_arg(repo_arg.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "chinwag bus install-hooks: {e}");
            return 2;
        }
    };
    match install_repo_local_claim_floor(&repo) {
        Ok(receipt) => {
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&receipt).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "installed repo-local claim hooks: {} ({})",
                    receipt.installed_hooks.join(", "),
                    receipt.hooks_dir
                );
            }
            0
        }
        Err(e) => {
            let _ = writeln!(stderr, "chinwag bus install-hooks: {e}");
            1
        }
    }
}
