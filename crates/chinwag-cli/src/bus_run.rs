#![forbid(unsafe_code)]

//! Multi-party `iroh` QUIC messaging bus (`ALPN: chinwag/bus/1`) +
//! `■ PRODUCT` Utilization Governor & `■ DELIVERY` Work-Stream Router.
//!
//! Includes Phase 1.1 & Phase 1.2 Hardening (`TASK-08`..`TASK-18`):
//! - `BUS-HARDEN-01` & `BUS-HARDEN-04`: Detached `Ed25519` message signatures (`pubkey_ed25519`,
//!   `signature_ed25519`, `sig_verified`) verified against `.chinwag/allowed_signers` over the
//!   7-field canonical payload (`id`, `ts_unix`, `sender`, `to`, `room`, `task_id`, `body`).
//! - `BUS-HARDEN-02` & `BUS-HARDEN-05`: Multi-interface `0.0.0.0:44330` QUIC binding with dynamic
//!   non-loopback IPv4 discovery (`ifconfig`) and fail-loudly port binding.
//! - `BUS-HARDEN-03`: Advisory `flock` on `.chinwag/bus/bus.lock` + `PRAGMA busy_timeout=5000;`.
//! - `CHWG-CONTINUOUS-LOOP-01` & `CHWG-DYNAMIC-TASKS-PARSER-01`: Autonomous 45s governor that
//!   dynamically parses `[IN_PROGRESS]` and `[READY]` items from `TASKS.md`.

use chinwag_cli::agent_instance::{self, ActorAddress, InstanceError};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, Signature, TransportAddr,
    address_lookup::memory::MemoryLookup, endpoint::presets,
};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

pub const BUS_ALPN: &[u8] = b"chinwag/bus/1";
const DEFAULT_BUS_PORT: u16 = 44330;
const MAX_FRAME_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusMessage {
    pub id: String,
    pub seq: u64,
    pub ts_unix: u64,
    pub ts_iso: String,
    pub room: String,
    pub sender: String,
    pub sender_cast: String,
    pub sender_endpoint_id: String,
    pub to: Option<String>,
    pub task_id: Option<String>,
    pub body: String,
    pub digest_sha256: String,
    #[serde(default)]
    pub pubkey_ed25519: Option<String>,
    #[serde(default)]
    pub signature_ed25519: Option<String>,
    #[serde(default)]
    pub sig_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum BusFrame {
    Publish { message: BusMessage },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusAck {
    pub ok: bool,
    pub seq: u64,
    pub message_id: String,
    pub daemon_endpoint_id: String,
    pub transport: String,
    pub room: String,
    pub subscribers_notified: usize,
    pub sig_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub ok: bool,
    pub pid: u32,
    pub endpoint_id: String,
    pub bound_sockets: Vec<String>,
    pub alpns: Vec<String>,
    pub repo_root: String,
    pub tasks_md: String,
    pub messages_jsonl: String,
    pub started_at: u64,
    pub last_heartbeat: u64,
    pub total_messages: u64,
    pub product_governor: String,
    pub delivery_router: String,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns local wall-clock timestamp with explicit timezone offset and zone name
/// (e.g. `2026-10-29T18:15:12-0500 CDT`).
fn iso_now() -> String {
    let output = Command::new("/bin/date")
        .args(["+%Y-%m-%dT%H:%M:%S%z %Z"])
        .output();
    if let Ok(out) = output
        && out.status.success()
    {
        return String::from_utf8_lossy(&out.stdout).trim().to_string();
    }
    format!("{}", unix_now())
}

fn resolve_repo_root(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let home_path = PathBuf::from(&home);
    if let Ok(cwd) = std::env::current_dir() {
        for ancestor in cwd.ancestors() {
            if ancestor != home_path
                && ancestor.join(".chinwag").is_dir()
                && (ancestor.join(".git").exists() || ancestor.join("TASKS.md").exists())
            {
                return ancestor.to_path_buf();
            }
        }
    }
    PathBuf::from(format!("{home}/WORKSPACE/chinwag"))
}

fn bus_dir(repo_root: &Path) -> PathBuf {
    let dir = repo_root.join(".chinwag").join("bus");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

fn messages_jsonl_path(repo_root: &Path) -> PathBuf {
    bus_dir(repo_root).join("messages.jsonl")
}

fn daemon_json_path(repo_root: &Path) -> PathBuf {
    bus_dir(repo_root).join("daemon.json")
}

fn bus_lock_path(repo_root: &Path) -> PathBuf {
    bus_dir(repo_root).join("bus.lock")
}

/// Executes `f` while holding an exclusive advisory `flock` on `.chinwag/bus/bus.lock` (`BUS-HARDEN-03`).
fn with_bus_file_lock<T>(repo_root: &Path, f: impl FnOnce() -> T) -> T {
    let lock_path = bus_lock_path(repo_root);
    if let Ok(lock_file) = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
    {
        let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
        let _ = flock(&lock_file, FlockOperation::LockExclusive);
        let res = f();
        let _ = flock(&lock_file, FlockOperation::Unlock);
        return res;
    }
    f()
}

fn load_or_create_daemon_secret(repo_root: &Path) -> SecretKey {
    let key_path = bus_dir(repo_root).join("daemon_secret.key");
    if let Ok(bytes) = fs::read(&key_path)
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return SecretKey::from_bytes(&arr);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"chinwag-iroh-bus-hub-v1:");
    hasher.update(repo_root.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    let _ = fs::write(&key_path, arr);
    let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    SecretKey::from_bytes(&arr)
}

fn base_seat_str(actor: &str) -> &str {
    actor.split('#').next().unwrap_or(actor)
}

pub fn resolve_actor_with_instance(
    raw_actor: &str,
    explicit_instance: Option<&str>,
) -> Result<String, InstanceError> {
    agent_instance::resolve_from_environment(raw_actor, explicit_instance)
        .map(|address| address.to_string())
}

/// Internal supervisor actors share one CSPRNG process instance. Public agent
/// sends must provide their conversation context through the CLI boundary.
fn service_actor(seat: &str) -> Result<String, InstanceError> {
    static INSTANCE: OnceLock<Result<String, InstanceError>> = OnceLock::new();
    let instance = INSTANCE
        .get_or_init(agent_instance::new_instance_id)
        .as_ref()
        .map_err(|error| *error)?;
    agent_instance::resolve_actor(seat, Some(instance), None).map(|address| address.to_string())
}

fn send_service_message_sync(
    repo_root: &Path,
    service: &str,
    room: &str,
    to: Option<String>,
    task_id: Option<String>,
    body: &str,
) -> Result<(BusMessage, BusAck), InstanceError> {
    send_bus_message_sync(repo_root, &service_actor(service)?, room, to, task_id, body)
}

fn seat_slug_clean(actor: &str) -> String {
    base_seat_str(actor)
        .trim()
        .trim_start_matches('●')
        .trim_start_matches('■')
        .trim_start_matches('◆')
        .trim_start_matches('@')
        .trim()
        .to_lowercase()
}

fn valid_seat_slug(actor: &str) -> Option<String> {
    let s = seat_slug_clean(actor);
    if s.is_empty()
        || s.starts_with('-')
        || s.contains("..")
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(s)
}

fn os_csprng_32_bytes() -> [u8; 32] {
    let mut arr = [0u8; 32];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        use std::io::Read as _;
        let _ = f.read_exact(&mut arr);
    }
    arr
}

/// Loads the seat's real OpenSSH Ed25519 signing key (`~/.chinwag/signing/<seat>_ed25519`)
/// or raw 32-byte CSPRNG seed (`~/.chinwag/signing/<seat>_ed25519.key`) for detached message signing (`BUS-HARDEN-01` & `BUS-HARDEN-06`).
/// Never derives a predictable key from the public seat name and rejects any path-traversal or invalid seat slug (`FLINT #213 F2`).
pub fn actor_signing_secret(actor: &str) -> Result<SecretKey, InstanceError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let signing_dir = PathBuf::from(format!("{home}/.chinwag/signing"));
    actor_signing_secret_at(actor, &signing_dir)
}

fn actor_signing_secret_at(actor: &str, signing_dir: &Path) -> Result<SecretKey, InstanceError> {
    ActorAddress::parse(actor)?;
    let slug = valid_seat_slug(actor).ok_or(InstanceError::InvalidAddress)?;
    let ssh_key_path = signing_dir.join(format!("{slug}_ed25519"));
    let resolved_path = fs::canonicalize(&ssh_key_path).unwrap_or(ssh_key_path);
    if let Ok(identity) = chinwag_swarm::identity::Identity::from_ssh_signing_file(&resolved_path) {
        return Ok(identity.iroh_secret_key());
    }

    let raw_key_path = signing_dir.join(format!("{slug}_ed25519.key"));
    if let Ok(bytes) = fs::read(&raw_key_path)
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(SecretKey::from_bytes(&arr));
    }

    Err(InstanceError::SigningIdentityUnavailable)
}

fn actor_transport_secret(_actor: &str) -> SecretKey {
    SecretKey::from_bytes(&os_csprng_32_bytes())
}

/// Unambiguous length-prefixed 7-field canonical signing payload binding
/// `id`, `ts_unix`, `sender`, `to`, `room`, `task_id`, and `body` (`BUS-HARDEN-04`).
pub fn canonical_signing_payload(msg: &BusMessage) -> String {
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

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

fn hex_to_64_bytes(hex_str: &str) -> Option<[u8; 64]> {
    if hex_str.len() != 128 || !hex_str.is_ascii() {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        let byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
        *slot = byte;
    }
    Some(out)
}

/// Signs `msg` with the seat's Ed25519 `SecretKey` and populates `pubkey_ed25519`, `signature_ed25519`, and `sig_verified`.
pub fn sign_bus_message(msg: &mut BusMessage, secret: &SecretKey) {
    let payload = canonical_signing_payload(msg);
    let sig = secret.sign(payload.as_bytes());
    let pubkey_hex = secret.public().to_string();
    let sig_hex = bytes_to_hex(&sig.to_bytes());
    msg.pubkey_ed25519 = Some(pubkey_hex);
    msg.signature_ed25519 = Some(sig_hex);
    msg.sig_verified = true;
}

/// Verifies both (a) the detached Ed25519 signature over the 7-field `canonical_signing_payload` and
/// (b) that `pubkey_ed25519` is registered for `msg.sender` in `<repo_root>/.chinwag/allowed_signers` (`BUS-HARDEN-04`).
/// Fails closed if `.chinwag/allowed_signers` is missing, unreadable, empty, or does not map `pubkey` to `msg.sender`.
pub fn verify_detached_bus_signature(repo_root: &Path, msg: &mut BusMessage) -> bool {
    if ActorAddress::parse(&msg.sender).is_err()
        || msg
            .to
            .as_deref()
            .is_some_and(|to| agent_instance::parse_recipients(to).is_err())
    {
        msg.sig_verified = false;
        return false;
    }
    let (Some(pub_str), Some(sig_str)) = (
        msg.pubkey_ed25519.as_deref(),
        msg.signature_ed25519.as_deref(),
    ) else {
        msg.sig_verified = false;
        return false;
    };
    let Ok(pubkey) = pub_str.parse::<EndpointId>() else {
        msg.sig_verified = false;
        return false;
    };
    let Some(sig_bytes) = hex_to_64_bytes(sig_str) else {
        msg.sig_verified = false;
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    let payload7 = canonical_signing_payload(msg);
    if pubkey.verify(payload7.as_bytes(), &sig).is_err() {
        msg.sig_verified = false;
        return false;
    }

    let allowed_path = repo_root.join(".chinwag").join("allowed_signers");
    let Ok(allowed_raw) = fs::read_to_string(&allowed_path) else {
        msg.sig_verified = false;
        return false;
    };
    let signers = chinwag_swarm::identity::parse_allowed_signers(&allowed_raw);
    if signers.is_empty() {
        msg.sig_verified = false;
        return false;
    }
    let sender_norm = base_seat_str(&msg.sender).trim().to_uppercase();
    let in_allowed = signers.iter().any(|(seat_opt, bytes)| {
        bytes == pubkey.as_bytes()
            && seat_opt
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(&sender_norm))
    });
    if !in_allowed {
        msg.sig_verified = false;
        return false;
    }

    msg.sig_verified = true;
    true
}

fn normalize_actor(raw: &str) -> Result<(String, String), InstanceError> {
    let address = ActorAddress::parse(raw)?;
    let cast = if address.is_human() { "●" } else { "■" };
    Ok((address.to_string(), cast.to_owned()))
}

fn normalize_room(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        "#eng".to_string()
    } else if t.starts_with('#') {
        t.to_lowercase()
    } else {
        format!("#{}", t.to_lowercase())
    }
}

fn read_all_messages_unlocked(repo_root: &Path) -> Vec<BusMessage> {
    let path = messages_jsonl_path(repo_root);
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(mut msg) = serde_json::from_str::<BusMessage>(trimmed) {
            let _ = verify_detached_bus_signature(repo_root, &mut msg);
            out.push(msg);
        }
    }
    out
}

fn read_all_messages(repo_root: &Path) -> Vec<BusMessage> {
    with_bus_file_lock(repo_root, || read_all_messages_unlocked(repo_root))
}

fn append_message_to_disk_and_crdb(repo_root: &Path, msg: &BusMessage) -> u64 {
    let mut verified_msg = msg.clone();
    let _ = verify_detached_bus_signature(repo_root, &mut verified_msg);

    with_bus_file_lock(repo_root, || {
        let existing = read_all_messages_unlocked(repo_root);
        if let Some(found) = existing.iter().find(|m| m.id == verified_msg.id) {
            return found.seq;
        }
        let next_seq = existing.last().map(|m| m.seq + 1).unwrap_or(1);
        verified_msg.seq = next_seq;

        let path = messages_jsonl_path(repo_root);
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path)
            && let Ok(line) = serde_json::to_string(&verified_msg)
        {
            let _ = writeln!(file, "{line}");
        }

        // Mirror into .chinwag/bus/bus.sqlite with PRAGMA busy_timeout=5000; (`BUS-HARDEN-03`)
        let bus_db = bus_dir(repo_root).join("bus.sqlite");
        let sender_display = format!("{} {}", verified_msg.sender_cast, verified_msg.sender);
        let item_key = verified_msg
            .task_id
            .clone()
            .unwrap_or_else(|| "CHWG-IROH-BUS-1".to_string());
        let pubkey_str = verified_msg.pubkey_ed25519.clone().unwrap_or_default();
        let sig_str = verified_msg.signature_ed25519.clone().unwrap_or_default();
        let sig_ok_int = if verified_msg.sig_verified { 1 } else { 0 };

        let init_sql = "PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS bus_messages (id TEXT PRIMARY KEY, seq INTEGER, ts_iso TEXT, room TEXT, sender TEXT, sender_endpoint_id TEXT, recipient TEXT, task_id TEXT, body TEXT, digest_sha256 TEXT, pubkey_ed25519 TEXT, signature_ed25519 TEXT, sig_verified INTEGER DEFAULT 0);";
        let _ = Command::new("/usr/bin/sqlite3")
            .arg(&bus_db)
            .arg(init_sql)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        for col_sql in [
            "PRAGMA busy_timeout=5000; ALTER TABLE bus_messages ADD COLUMN pubkey_ed25519 TEXT;",
            "PRAGMA busy_timeout=5000; ALTER TABLE bus_messages ADD COLUMN signature_ed25519 TEXT;",
            "PRAGMA busy_timeout=5000; ALTER TABLE bus_messages ADD COLUMN sig_verified INTEGER DEFAULT 0;",
        ] {
            let _ = Command::new("/usr/bin/sqlite3")
                .arg(&bus_db)
                .arg(col_sql)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let insert_sql = format!(
            "PRAGMA busy_timeout=5000; INSERT OR REPLACE INTO bus_messages (id, seq, ts_iso, room, sender, sender_endpoint_id, recipient, task_id, body, digest_sha256, pubkey_ed25519, signature_ed25519, sig_verified) VALUES ('{}', {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', {});",
            verified_msg.id.replace('\'', "''"),
            verified_msg.seq,
            verified_msg.ts_iso.replace('\'', "''"),
            verified_msg.room.replace('\'', "''"),
            sender_display.replace('\'', "''"),
            verified_msg.sender_endpoint_id.replace('\'', "''"),
            verified_msg
                .to
                .clone()
                .unwrap_or_default()
                .replace('\'', "''"),
            item_key.replace('\'', "''"),
            verified_msg.body.replace('\'', "''"),
            verified_msg.digest_sha256.replace('\'', "''"),
            pubkey_str.replace('\'', "''"),
            sig_str.replace('\'', "''"),
            sig_ok_int,
        );
        let _ = Command::new("/usr/bin/sqlite3")
            .arg(&bus_db)
            .arg(&insert_sql)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        next_seq
    })
}

fn compute_message_digest(
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
    let bytes = hasher.finalize();
    bytes_to_hex(&bytes)
}

fn read_daemon_state(repo_root: &Path) -> Option<DaemonState> {
    if let Ok(remote_addr) = std::env::var("CHINWAG_BUS_ADDR") {
        let trimmed = remote_addr.trim();
        if !trimmed.is_empty() {
            let endpoint_id = std::env::var("CHINWAG_BUS_ENDPOINT_ID")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| load_or_create_daemon_secret(repo_root).public().to_string());
            return Some(DaemonState {
                ok: true,
                pid: 0,
                endpoint_id,
                bound_sockets: vec![trimmed.to_string()],
                alpns: vec![
                    "chinwag/bus/1".to_string(),
                    "chinwag/agent-dispatch/1".to_string(),
                ],
                repo_root: repo_root.to_string_lossy().to_string(),
                tasks_md: repo_root.join("TASKS.md").to_string_lossy().to_string(),
                messages_jsonl: messages_jsonl_path(repo_root).to_string_lossy().to_string(),
                started_at: 0,
                last_heartbeat: unix_now(),
                total_messages: 0,
                product_governor: "REMOTE".to_string(),
                delivery_router: format!("REMOTE ({trimmed})"),
            });
        }
    }
    let raw = fs::read_to_string(daemon_json_path(repo_root)).ok()?;
    let state: DaemonState = serde_json::from_str(&raw).ok()?;
    let status = Command::new("/bin/kill")
        .args(["-0", &state.pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if status.success() { Some(state) } else { None }
}

fn write_daemon_state(repo_root: &Path, state: &DaemonState) {
    let path = daemon_json_path(repo_root);
    if let Ok(text) = serde_json::to_string_pretty(state) {
        let _ = fs::write(&path, text);
    }
}

/// Dynamically discovers active (`UP` + `RUNNING`) non-loopback IPv4 addresses on this host via `/sbin/ifconfig` (`BUS-HARDEN-05`).
pub fn discover_non_loopback_ipv4() -> Vec<String> {
    let mut ips = Vec::new();
    let Ok(out) = Command::new("/sbin/ifconfig").output() else {
        return ips;
    };
    if !out.status.success() {
        return ips;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut iface_active = false;
    for line in text.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains("flags=") {
            let has_up = line.contains("<UP,") || line.contains(",UP,") || line.contains(",UP>");
            let has_running = line.contains("RUNNING");
            iface_active = has_up && has_running;
        }
        if !iface_active {
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ")
            && let Some(ip_tok) = rest.split_whitespace().next()
            && let Ok(ipv4) = ip_tok.parse::<std::net::Ipv4Addr>()
            && !ipv4.is_loopback()
            && !ipv4.is_unspecified()
            && !ips.iter().any(|existing| existing == ip_tok)
        {
            ips.push(ip_tok.to_string());
        }
    }
    ips
}

/// Binds on `0.0.0.0:{port}` when `port != 0` and fails loudly if the requested port
/// cannot be bound (`BUS-HARDEN-05` — no silent fallback to an unrequested random port).
async fn bind_bus_endpoint(
    secret: SecretKey,
    port: u16,
    lookup: MemoryLookup,
) -> Result<Endpoint, String> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .clear_address_lookup()
        .address_lookup(lookup)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![
            BUS_ALPN.to_vec(),
            chinwag_swarm::dispatch_wire::ALPN.to_vec(),
        ]);
    if port != 0 {
        let addr: SocketAddr = format!("0.0.0.0:{port}")
            .parse()
            .map_err(|e| format!("invalid socket addr: {e}"))?;
        builder = builder
            .clear_ip_transports()
            .bind_addr(addr)
            .map_err(|e| format!("bind_addr failed on {addr}: {e}"))?;
    }
    builder
        .bind()
        .await
        .map_err(|e| format!("endpoint bind failed on port {port}: {e}"))
}

async fn publish_over_iroh_quic(
    daemon: &DaemonState,
    actor_secret: SecretKey,
    msg: &BusMessage,
) -> Result<BusAck, String> {
    let daemon_id: EndpointId = daemon
        .endpoint_id
        .parse()
        .map_err(|e| format!("invalid daemon endpoint_id: {e}"))?;
    let target_str = std::env::var("CHINWAG_BUS_ADDR").ok().unwrap_or_else(|| {
        let first = daemon
            .bound_sockets
            .first()
            .cloned()
            .unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_BUS_PORT}"));
        if let Some(port_part) = first.strip_prefix("0.0.0.0:") {
            format!("127.0.0.1:{port_part}")
        } else {
            first
        }
    });
    let sock: SocketAddr = target_str
        .parse()
        .map_err(|e| format!("invalid daemon socket addr: {e}"))?;

    let lookup = MemoryLookup::new();
    let addr = EndpointAddr::from_parts(daemon_id, [TransportAddr::Ip(sock)]);
    lookup.set_endpoint_info(addr.clone());

    let client = bind_bus_endpoint(actor_secret, 0, lookup).await?;
    let connect_res = tokio::time::timeout(Duration::from_secs(3), client.connect(addr, BUS_ALPN))
        .await
        .map_err(|_| "iroh QUIC connect timeout".to_string())?
        .map_err(|e| format!("iroh QUIC connect error: {e}"))?;

    let (mut send, mut recv) = connect_res
        .open_bi()
        .await
        .map_err(|e| format!("open_bi failed: {e}"))?;

    let frame = BusFrame::Publish {
        message: msg.clone(),
    };
    let payload = serde_json::to_vec(&frame).map_err(|e| e.to_string())?;
    send.write_all(&payload)
        .await
        .map_err(|e| format!("write_all failed: {e}"))?;
    let _ = send.finish();

    let resp_bytes =
        tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(MAX_FRAME_BYTES))
            .await
            .map_err(|_| "read ack timeout".to_string())?
            .map_err(|e| format!("read ack error: {e}"))?;

    client.close().await;
    serde_json::from_slice::<BusAck>(&resp_bytes).map_err(|e| format!("invalid ack json: {e}"))
}

fn format_local_wall_clock(ts_iso: &str) -> String {
    if ts_iso.len() >= 19 {
        let hms = &ts_iso[11..19];
        if ts_iso.ends_with('Z')
            && let Ok(utc_hr) = hms[0..2].parse::<u32>()
        {
            let local_hr = (utc_hr + 24 - 5) % 24;
            return format!("{:02}:{} CDT", local_hr, &hms[3..8]);
        }
        if let Some(zone) = ts_iso.split_whitespace().nth(1) {
            return format!("{hms} {zone}");
        }
        return format!("{hms} CDT");
    }
    ts_iso.to_string()
}

fn format_bus_line(m: &BusMessage) -> String {
    let short_ep = if m.sender_endpoint_id.len() >= 12 {
        format!(
            "{}..{}",
            &m.sender_endpoint_id[..6],
            &m.sender_endpoint_id[m.sender_endpoint_id.len() - 4..]
        )
    } else {
        m.sender_endpoint_id.clone()
    };
    let time_local = format_local_wall_clock(&m.ts_iso);
    let sig_badge = if m.sig_verified { " ✓ed25519" } else { "" };
    let task_badge = m
        .task_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|t| format!(" [{t}]"))
        .unwrap_or_default();
    let to_badge =
        m.to.as_deref()
            .filter(|s| !s.is_empty())
            .map(|t| format!(" -> @{t}"))
            .unwrap_or_default();
    format!(
        "#{:03} [{}] [{}] [{} {} · iroh:{}{}]{}{}: {}",
        m.seq,
        time_local,
        m.room,
        m.sender_cast,
        m.sender,
        short_ep,
        sig_badge,
        task_badge,
        to_badge,
        m.body
    )
}

/// Dynamically parses `[IN_PROGRESS]` and `[READY]` tasks (`(seat, task_id, prompt)`) from `TASKS.md`
/// (`TASK-18` / `CHWG-DYNAMIC-TASKS-PARSER-01`).
pub fn parse_active_tasks_from_markdown(repo_root: &Path) -> Vec<(String, String, String)> {
    let tasks_path = repo_root.join("TASKS.md");
    let Ok(raw) = fs::read_to_string(&tasks_path) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    let mut current_task_id: Option<String> = None;
    let mut current_title = String::new();
    let mut current_seat: Option<String> = None;
    let mut current_scope = Vec::new();

    let flush = |results: &mut Vec<(String, String, String)>,
                 task_id: &mut Option<String>,
                 title: &mut String,
                 seat: &mut Option<String>,
                 scope: &mut Vec<String>| {
        if let (Some(tid), Some(s)) = (task_id.take(), seat.take()) {
            let scope_str = scope.join(" ");
            let prompt = format!(
                "{tid} from TASKS.md ({title}): {scope_str} Execute verification and return a concise technical receipt."
            );
            results.push((s, tid, prompt));
        }
        title.clear();
        scope.clear();
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("### ") {
            flush(
                &mut results,
                &mut current_task_id,
                &mut current_title,
                &mut current_seat,
                &mut current_scope,
            );
            let is_active = trimmed.contains("`[IN_PROGRESS]`") || trimmed.contains("`[READY]`");
            if is_active {
                // Extract `TASK-XX` token
                for part in trimmed.split('`') {
                    if part.starts_with("TASK-") {
                        current_task_id = Some(part.to_string());
                        break;
                    }
                }
                current_title = trimmed.trim_start_matches("### ").to_string();
            }
            continue;
        }
        if current_task_id.is_some() {
            if trimmed.starts_with("- **Owner:**") {
                let upper = trimmed.to_uppercase();
                for candidate in ["TYPE", "RUST", "ARCHITECT", "FLINT", "ALISTAIR", "QA"] {
                    if upper.contains(candidate) {
                        current_seat = Some(candidate.to_string());
                        break;
                    }
                }
            } else if trimmed.starts_with("- **Scope:**")
                || trimmed.starts_with("- **Files:**")
                || trimmed.starts_with("1.")
                || trimmed.starts_with("2.")
            {
                current_scope.push(trimmed.to_string());
            }
        }
    }
    flush(
        &mut results,
        &mut current_task_id,
        &mut current_title,
        &mut current_seat,
        &mut current_scope,
    );
    results
}

/// Autonomous `■ PRODUCT` + `■ DELIVERY` Backlog Governor (`CHWG-CONTINUOUS-LOOP-01` + `CHWG-DYNAMIC-TASKS-PARSER-01`).
fn dispatch_continuous_backlog_wave(repo_root: &Path, target_seat: &str) -> Vec<String> {
    let mut spawned = Vec::new();
    let target = target_seat.to_uppercase();
    let parsed_tasks = parse_active_tasks_from_markdown(repo_root);

    let mut dispatched_seats = std::collections::BTreeSet::new();
    for (seat, task_id, prompt) in parsed_tasks {
        if dispatched_seats.contains(&seat) {
            continue;
        }
        if target == "ALL"
            || target == seat
            || (target == "GPT" && (seat == "RUST" || seat == "ARCHITECT" || seat == "ALISTAIR"))
        {
            if is_seat_worker_active(repo_root, &seat) {
                dispatched_seats.insert(seat);
                continue;
            }
            if spawn_seat_workstream(repo_root, &seat, &task_id, &prompt) {
                spawned.push(format!("■ {seat} (-> {task_id})"));
                dispatched_seats.insert(seat);
            }
        }
    }
    spawned
}

fn seat_pid_path(repo_root: &Path, seat: &str) -> PathBuf {
    let workers = bus_dir(repo_root).join("workers");
    if seat.contains('#') {
        workers
            .join("instances")
            .join(format!("{}.pid", worker_file_component(seat)))
    } else {
        workers.join(format!("{}.pid", seat.to_ascii_lowercase()))
    }
}

fn is_seat_worker_active(repo_root: &Path, seat: &str) -> bool {
    if seat.contains('#') {
        return pid_file_is_active(&seat_pid_path(repo_root, seat));
    }
    let legacy = seat_pid_path(repo_root, seat);
    if pid_file_is_active(&legacy) {
        return true;
    }
    let instances = bus_dir(repo_root).join("workers").join("instances");
    let Ok(entries) = fs::read_dir(instances) else {
        return false;
    };
    let prefix = format!("{}--", seat.to_ascii_lowercase());
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".pid"))
            && pid_file_is_active(&entry.path())
        {
            return true;
        }
    }
    false
}

fn worker_file_component(actor: &str) -> String {
    let digest = Sha256::digest(actor.as_bytes());
    format!(
        "{}--{}",
        base_seat_str(actor).to_ascii_lowercase(),
        bytes_to_hex(&digest)
    )
}

struct WorkerRegistration {
    path: PathBuf,
    file: File,
}

impl WorkerRegistration {
    fn acquire(repo_root: &Path, actor: &str) -> std::io::Result<Self> {
        let path = seat_pid_path(repo_root, actor);
        fs::create_dir_all(path.parent().ok_or(std::io::ErrorKind::InvalidInput)?)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let mut registration = Self { path, file };
        writeln!(registration.file, "{}", std::process::id())?;
        Ok(registration)
    }
}

impl Drop for WorkerRegistration {
    fn drop(&mut self) {
        if let (Ok(held), Ok(current)) = (self.file.metadata(), self.path.symlink_metadata())
            && current.is_file()
            && held.dev() == current.dev()
            && held.ino() == current.ino()
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn pid_file_is_active(pid_file: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(pid_file) else {
        return false;
    };
    let Ok(pid) = raw.trim().parse::<u32>() else {
        return false;
    };
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn run_daemon_loop(repo_root: PathBuf, port: u16, stdout: &mut dyn Write) -> u8 {
    let secret = load_or_create_daemon_secret(&repo_root);
    let lookup = MemoryLookup::new();
    let endpoint = match bind_bus_endpoint(secret, port, lookup).await {
        Ok(ep) => ep,
        Err(e) => {
            let _ = writeln!(
                stdout,
                "chinwag bus daemon failed to bind iroh endpoint: {e}"
            );
            return 1;
        }
    };

    let endpoint_id = endpoint.id().to_string();
    let actual_sockets = endpoint.bound_sockets();
    let actual_port = actual_sockets.first().map(|s| s.port()).unwrap_or(port);

    let mut bound_sockets: Vec<String> =
        actual_sockets.into_iter().map(|s| s.to_string()).collect();
    let loopback_sock = format!("127.0.0.1:{actual_port}");
    if !bound_sockets.contains(&loopback_sock) {
        bound_sockets.push(loopback_sock);
    }
    for ip in discover_non_loopback_ipv4() {
        let candidate = format!("{ip}:{actual_port}");
        if !bound_sockets.contains(&candidate) {
            bound_sockets.push(candidate);
        }
    }

    let started_at = unix_now();
    let tasks_md = repo_root.join("TASKS.md").to_string_lossy().to_string();
    let messages_jsonl = messages_jsonl_path(&repo_root)
        .to_string_lossy()
        .to_string();

    let initial_count = read_all_messages(&repo_root).len() as u64;
    let state = Arc::new(Mutex::new(DaemonState {
        ok: true,
        pid: std::process::id(),
        endpoint_id: endpoint_id.clone(),
        bound_sockets: bound_sockets.clone(),
        alpns: vec![
            "chinwag/bus/1".to_string(),
            "chinwag/agent-dispatch/1".to_string(),
        ],
        repo_root: repo_root.to_string_lossy().to_string(),
        tasks_md,
        messages_jsonl,
        started_at,
        last_heartbeat: started_at,
        total_messages: initial_count,
        product_governor: "ACTIVE (CHWG-CONTINUOUS-LOOP-01 · Dynamic TASKS.md 45s Governor)"
            .to_string(),
        delivery_router: "ACTIVE (Ed25519+allowed_signers Verified Router on 0.0.0.0:44330)"
            .to_string(),
    }));
    if let Ok(guard) = state.lock() {
        write_daemon_state(&repo_root, &guard);
    }

    let _ = writeln!(
        stdout,
        "⚡ chinwag iroh multi-party bus daemon ONLINE\n\
         • EndpointId: {endpoint_id}\n\
         • Bound QUIC: {}\n\
         • ALPNs:      chinwag/bus/1, chinwag/agent-dispatch/1\n\
         • Tasks File: {}/TASKS.md",
        bound_sockets.join(", "),
        repo_root.display()
    );
    let _ = stdout.flush();

    let (tx, _rx) = broadcast::channel::<BusMessage>(256);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
    let mut governor_tick = tokio::time::interval(Duration::from_secs(45));
    governor_tick.tick().await;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = heartbeat.tick() => {
                let count = read_all_messages(&repo_root).len() as u64;
                if let Ok(mut guard) = state.lock() {
                    guard.last_heartbeat = unix_now();
                    guard.total_messages = count;
                    write_daemon_state(&repo_root, &guard);
                }
            }
            _ = governor_tick.tick() => {
                let repo_gov = repo_root.clone();
                tokio::task::spawn_blocking(move || {
                    let spawned = dispatch_continuous_backlog_wave(&repo_gov, "ALL");
                    if !spawned.is_empty() {
                        let _ = send_service_message_sync(
                            &repo_gov,
                            "PRODUCT",
                            "#mgmt",
                            Some("DELIVERY".to_string()),
                            Some("TASK-18".to_string()),
                            &format!(
                                "■ PRODUCT × ■ DELIVERY Autonomous Governor (CHWG-DYNAMIC-TASKS-PARSER-01): Dynamically parsed TASKS.md and dispatched {} seat(s) ({}) under 0% idle tolerance.",
                                spawned.len(),
                                spawned.join(", ")
                            ),
                        );
                    }
                });
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                let repo_clone = repo_root.clone();
                let state_clone = state.clone();
                let tx_clone = tx.clone();
                let daemon_ep = endpoint_id.clone();
                tokio::spawn(async move {
                    let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), incoming).await else {
                        return;
                    };
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                        return;
                    };
                    let Ok(Ok(bytes)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        recv.read_to_end(MAX_FRAME_BYTES),
                    ).await else {
                        return;
                    };
                    if let Ok(BusFrame::Publish { mut message }) = serde_json::from_slice::<BusFrame>(&bytes) {
                        let sig_ok = verify_detached_bus_signature(&repo_clone, &mut message);
                        if !sig_ok {
                            let ack = BusAck {
                                ok: false,
                                seq: 0,
                                message_id: message.id,
                                daemon_endpoint_id: daemon_ep,
                                transport: "iroh-quic/chinwag-bus-1 (rejected: invalid_signature)".to_string(),
                                room: message.room,
                                subscribers_notified: 0,
                                sig_verified: false,
                            };
                            if let Ok(ack_bytes) = serde_json::to_vec(&ack) {
                                let _ = send.write_all(&ack_bytes).await;
                                let _ = send.finish();
                                let _ = tokio::time::timeout(Duration::from_secs(2), send.stopped()).await;
                            }
                            return;
                        }
                        let seq = append_message_to_disk_and_crdb(&repo_clone, &message);
                        message.seq = seq;
                        let subs = tx_clone.send(message.clone()).unwrap_or(0);
                        if let Ok(mut guard) = state_clone.lock() {
                            guard.last_heartbeat = unix_now();
                            guard.total_messages = seq;
                            write_daemon_state(&repo_clone, &guard);
                        }
                        let ack = BusAck {
                            ok: true,
                            seq,
                            message_id: message.id,
                            daemon_endpoint_id: daemon_ep,
                            transport: "iroh-quic/chinwag-bus-1".to_string(),
                            room: message.room,
                            subscribers_notified: subs,
                            sig_verified: sig_ok,
                        };
                        if let Ok(ack_bytes) = serde_json::to_vec(&ack) {
                            let _ = send.write_all(&ack_bytes).await;
                            let _ = send.finish();
                            let _ = tokio::time::timeout(Duration::from_secs(2), send.stopped()).await;
                        }
                    }
                });
            }
        }
    }

    endpoint.close().await;
    0
}

pub fn send_bus_message_sync(
    repo_root: &Path,
    from: &str,
    room: &str,
    to: Option<String>,
    task_id: Option<String>,
    body: &str,
) -> Result<(BusMessage, BusAck), InstanceError> {
    let address = ActorAddress::parse(from)?.require_instance()?;
    let (sender, sender_cast) = normalize_actor(&address.to_string())?;
    let to = to
        .map(|target| {
            agent_instance::parse_recipients(&target).map(|targets| {
                targets
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
        })
        .transpose()?;
    let room_norm = normalize_room(room);
    let signing_secret = actor_signing_secret(&sender)?;
    let transport_secret = actor_transport_secret(&sender);
    let sender_endpoint_id = signing_secret.public().to_string();
    let ts_unix = unix_now();
    let ts_iso = iso_now();
    let digest = compute_message_digest(
        ts_unix,
        &room_norm,
        &sender,
        &sender_endpoint_id,
        to.as_deref(),
        task_id.as_deref(),
        body,
    );
    let msg_id = format!("bus-{}-{}", ts_unix, &digest[..8]);

    let mut msg = BusMessage {
        id: msg_id.clone(),
        seq: 0,
        ts_unix,
        ts_iso,
        room: room_norm.clone(),
        sender: sender.clone(),
        sender_cast: sender_cast.clone(),
        sender_endpoint_id,
        to,
        task_id: task_id.clone(),
        body: body.to_string(),
        digest_sha256: digest,
        pubkey_ed25519: None,
        signature_ed25519: None,
        sig_verified: false,
    };
    sign_bus_message(&mut msg, &signing_secret);
    if !verify_detached_bus_signature(repo_root, &mut msg) {
        return Err(InstanceError::SigningIdentityUnavailable);
    }

    if let Some(daemon) = read_daemon_state(repo_root)
        && let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        && let Ok(ack) = rt.block_on(publish_over_iroh_quic(&daemon, transport_secret, &msg))
    {
        if !ack.ok || !ack.sig_verified || ack.message_id != msg.id {
            return Err(InstanceError::PublicationRejected);
        }
        msg.seq = ack.seq;
        msg.sig_verified = ack.sig_verified;
        return Ok((msg, ack));
    }

    let seq = append_message_to_disk_and_crdb(repo_root, &msg);
    msg.seq = seq;
    let ack = BusAck {
        ok: true,
        seq,
        message_id: msg_id,
        daemon_endpoint_id: load_or_create_daemon_secret(repo_root).public().to_string(),
        transport: "local-crdb+jsonl (daemon starting)".to_string(),
        room: room_norm,
        subscribers_notified: 0,
        sig_verified: msg.sig_verified,
    };
    Ok((msg, ack))
}

fn run_worker_sync(
    repo_root: &Path,
    seat: &str,
    task_id: &str,
    prompt: &str,
    caller_opt: Option<&str>,
) -> u8 {
    let identities = (|| -> Result<(ActorAddress, String), InstanceError> {
        let mut child = ActorAddress::parse(seat)?;
        if child.instance().is_none() {
            child = child.with_instance(&agent_instance::new_instance_id()?)?;
        }
        let parent = caller_opt.ok_or(InstanceError::MissingInstance)?;
        Ok((
            child.require_instance()?,
            resolve_actor_with_instance(parent, None)?,
        ))
    })();
    let Ok((child, caller)) = identities else {
        return 2;
    };
    let base_seat = child.seat().to_owned();
    let worker_instance = child.to_string();
    let Ok(_registration) = WorkerRegistration::acquire(repo_root, &worker_instance) else {
        return 2;
    };
    let parent_clause = format!(" (spawned by {caller})");
    let reply_to = Some(caller.clone());

    let _ = send_bus_message_sync(
        repo_root,
        &worker_instance,
        "#eng",
        reply_to.clone(),
        Some(task_id.to_string()),
        &format!(
            "ACK from ■ {worker_instance}{parent_clause}: Executing work stream on {task_id} now."
        ),
    );

    let mut out_buf: Vec<u8> = Vec::new();
    let mut err_buf: Vec<u8> = Vec::new();
    let crdb_str = repo_root
        .join(".chinwag/state.crdb")
        .to_string_lossy()
        .to_string();
    let sender_for_dispatch = caller.as_str();
    if let chinwag_cli::Dispatch::AgentDispatch(req) = chinwag_cli::dispatch(
        std::ffi::OsStr::new("chinwag"),
        [
            "agent-dispatch",
            "--agent",
            &worker_instance,
            "--item",
            task_id,
            "--sender",
            sender_for_dispatch,
            "--crdb",
            &crdb_str,
            "--body",
            prompt,
        ],
    ) {
        let _ =
            chinwag_cli::run_agent_dispatch(req, &mut std::io::empty(), &mut out_buf, &mut err_buf);
    }

    let raw_out = String::from_utf8_lossy(&out_buf).trim().to_string();
    let reply_text = serde_json::from_str::<Value>(&raw_out)
        .ok()
        .and_then(|v| {
            v.get("reply")
                .and_then(|r| r.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| {
            if !raw_out.is_empty() {
                raw_out
            } else {
                String::from_utf8_lossy(&err_buf).trim().to_string()
            }
        });

    let collapsed = reply_text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    // Full-length 1800-char bus receipt so engineering/audit findings are never clipped (`TASK-15`)
    let summary: String = collapsed.chars().take(1800).collect();

    let target_room = if base_seat.eq_ignore_ascii_case("QA") {
        "#qa"
    } else {
        "#eng"
    };
    let _ = send_bus_message_sync(
        repo_root,
        &worker_instance,
        target_room,
        reply_to,
        Some(task_id.to_string()),
        &format!("COMPLETED {task_id}: {summary}"),
    );

    let short_summary: String = collapsed.chars().take(1800).collect();
    let _ = send_service_message_sync(
        repo_root,
        "DELIVERY",
        "#mgmt",
        Some("Brian".to_string()),
        Some(task_id.to_string()),
        &format!(
            "■ DELIVERY Receipt: ■ {worker_instance}{parent_clause} completed {task_id} -> {short_summary}"
        ),
    );
    0
}

fn spawn_seat_workstream(repo_root: &Path, seat: &str, task_id: &str, prompt: &str) -> bool {
    let Ok(parent) = service_actor("DELIVERY") else {
        return false;
    };
    let child = ActorAddress::parse(seat).and_then(|child| {
        if child.instance().is_some() {
            Ok(child)
        } else {
            child.with_instance(&agent_instance::new_instance_id()?)
        }
    });
    let Ok(child) = child else {
        return false;
    };
    let seat = child.to_string();
    let logs_dir = bus_dir(repo_root).join("workers");
    let _ = fs::create_dir_all(&logs_dir);
    let log_file = logs_dir.join(format!(
        "{}--{}.log",
        worker_file_component(&seat),
        bytes_to_hex(&Sha256::digest(task_id.as_bytes()))
    ));
    let bin_chinwag = "/Users/brianspector/.local/bin/chinwag";

    if let Ok(out_file) = OpenOptions::new().create(true).append(true).open(&log_file)
        && let Ok(err_file) = out_file.try_clone()
    {
        return Command::new(bin_chinwag)
            .args([
                "bus",
                "worker",
                "--repo",
                &repo_root.to_string_lossy(),
                "--seat",
                &seat,
                "--from",
                &parent,
                "--task",
                task_id,
                "--message",
                prompt,
            ])
            .env(
                "PATH",
                "/opt/homebrew/opt/rustup/bin:/Users/brianspector/.local/bin:/opt/homebrew/bin:/usr/bin:/bin",
            )
            .env("RUSTUP_TOOLCHAIN", "1.97.1")
            .env("RUSTC", "/opt/homebrew/opt/rustup/bin/rustc")
            .env("CARGO", "/opt/homebrew/opt/rustup/bin/cargo")
            .env("RUSTDOC", "/opt/homebrew/opt/rustup/bin/rustdoc")
            .env(
                "CHINWAG_PRIVATE_CRSQL_INPUTS",
                "/Users/brianspector/.chinwag-native-inputs",
            )
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(err_file))
            .spawn()
            .is_ok();
    }
    false
}

fn print_bus_help(stdout: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stdout,
        r#"Usage:
  chinwag bus instance
  chinwag bus status [--json]
  chinwag bus daemon [--port <44330>] [--repo <path>]
  chinwag bus send --from <SEAT#INSTANCE> [--room <ROOM>] [--to <ADDRESS,...>] [--task <TASK-ID>] [--json] --message <BODY>
  chinwag bus send --from <SEAT> --instance <INSTANCE> [options] --message <BODY>
  chinwag bus inbox --for <SEAT#INSTANCE|SEAT> [--limit <N>] [--json]
  chinwag bus tail [--room <ROOM>] [--task <TASK-ID>] [--limit <N>] [-f] [--json]
  chinwag bus worker --seat <SEAT> --from <CALLER#INSTANCE> --task <TASK-ID> --message <BODY>
  chinwag bus wake [--seat <SEAT|ALL>]

Agent sends require a stable conversation instance via --from, --instance or inherited conversation context.
Use 'bus instance' once to allocate a full random ID, then reuse it for that conversation.
A base-seat recipient is an explicit seat broadcast; a base-seat inbox aggregates that seat's instances.
--wake with a base-seat recipient creates a new child instance. Send to an existing instance without --wake.
Use one --to with a comma-separated list. Repeated --to/-t flags fail before publication.
A legacy ACK acknowledges publication only: completion_scope=PUBLISH_ONLY, durability UNKNOWN.
subscribers_notified counts broadcast receivers; it proves neither processing nor task start.
Existing-conversation scheduling has no supported adapter in this binary and reports UNSUPPORTED.
"#
    );
    0
}

pub fn run_bus_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    if sub == "--help" || sub == "-h" || sub == "help" {
        return print_bus_help(stdout);
    }

    let mut repo_arg: Option<String> = None;
    let mut from_arg: Option<String> = None;
    let mut instance_arg: Option<String> = None;
    let mut room_arg: Option<String> = None;
    let mut to_arg: Option<String> = None;
    let mut task_arg: Option<String> = None;
    let mut for_arg: Option<String> = None;
    let mut seat_arg: Option<String> = None;
    let mut summary_arg: Option<String> = None;
    let mut wake_on_send = false;
    let mut limit_arg: usize = 30;
    let mut port_arg: u16 = DEFAULT_BUS_PORT;
    let mut follow = false;
    let mut is_json = false;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--help" | "-h" => return print_bus_help(stdout),
            "--" => {
                positionals.extend_from_slice(&args[i + 1..]);
                break;
            }
            "--repo" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--from" | "-s" | "--sender" if i + 1 < args.len() => {
                from_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--instance" | "--thread" | "--thread-id" if i + 1 < args.len() => {
                if instance_arg.replace(args[i + 1].clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag bus: conflicting_actor_instance");
                    return 2;
                }
                i += 2;
            }
            "--room" | "--channel" | "-c" if i + 1 < args.len() => {
                room_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--to" | "-t" if i + 1 < args.len() => {
                if to_arg.replace(args[i + 1].clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag bus: duplicate_recipient_flag; use one --to with a comma-separated recipient list");
                    return 2;
                }
                i += 2;
            }
            "--task" | "--item" | "--ticket" | "-k" if i + 1 < args.len() => {
                task_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--for" | "--actor" if i + 1 < args.len() => {
                for_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--seat" | "--agent" if i + 1 < args.len() => {
                seat_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--summary" | "--title" | "--subject" if i + 1 < args.len() => {
                summary_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--wake" | "--dispatch" => {
                wake_on_send = true;
                i += 1;
            }
            "--limit" | "-n" if i + 1 < args.len() => {
                limit_arg = args[i + 1].parse().unwrap_or(30);
                i += 2;
            }
            "--port" | "-p" if i + 1 < args.len() => {
                port_arg = args[i + 1].parse().unwrap_or(DEFAULT_BUS_PORT);
                i += 2;
            }
            "-f" | "--follow" => {
                follow = true;
                i += 1;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            "--message" | "--body" | "--prompt" | "-m" if i + 1 < args.len() => {
                positionals.push(args[i + 1].clone());
                i += 2;
            }
            flag if flag.starts_with('-') => {
                let _ = writeln!(stderr, "chinwag bus: invalid_arguments");
                return 2;
            }
            _ => {
                positionals.push(args[i].clone());
                i += 1;
            }
        }
    }

    let repo_root = resolve_repo_root(repo_arg.as_deref());

    match sub {
        "instance" | "new-instance" => match agent_instance::new_instance_id() {
            Ok(instance) => {
                let _ = writeln!(stdout, "{instance}");
                0
            }
            Err(error) => {
                let _ = writeln!(stderr, "chinwag bus: {error}");
                2
            }
        },
        "worker" => {
            let seat_raw = seat_arg
                .or_else(|| from_arg.clone())
                .unwrap_or_else(|| "RUST".to_string());
            let seat = if let Some(ref inst) = instance_arg {
                match resolve_actor_with_instance(&seat_raw, Some(inst)) {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = writeln!(stderr, "chinwag bus: {error}");
                        return 2;
                    }
                }
            } else {
                seat_raw
            };
            let caller = from_arg.or_else(|| std::env::var("CHINWAG_ACTOR").ok());
            let task = task_arg.unwrap_or_else(|| "TASK-15".to_string());
            let mut prompt = positionals.join(" ").trim().to_string();
            if prompt.is_empty()
                && let Some(s) = summary_arg
            {
                prompt = s;
            }
            run_worker_sync(&repo_root, &seat, &task, &prompt, caller.as_deref())
        }
        "daemon" => {
            let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            else {
                let _ = writeln!(stderr, "chinwag bus: failed to initialize tokio runtime");
                return 1;
            };
            rt.block_on(run_daemon_loop(repo_root, port_arg, stdout))
        }
        "send" | "pub" | "publish" | "post" => {
            let pos_body = positionals.join(" ").trim().to_string();
            let body = match (summary_arg, pos_body.is_empty()) {
                (Some(s), true) => s,
                (Some(s), false) => format!("{s} — {pos_body}"),
                (None, _) => pos_body,
            };
            if body.is_empty() {
                let _ = writeln!(
                    stderr,
                    "Usage: chinwag bus send [--from <SEAT#THREAD_ID>] [--instance <THREAD_ID>] [--room <#mgmt|#eng>] [--to <@SEAT>] [--task <TASK-ID>] [--wake] \"<MESSAGE>\""
                );
                return 2;
            }
            let sender_raw = from_arg.or_else(|| std::env::var("CHINWAG_ACTOR").ok());
            let Some(sender_raw) = sender_raw else {
                let _ = writeln!(stderr, "chinwag bus: actor_required");
                return 2;
            };
            let sender = match resolve_actor_with_instance(&sender_raw, instance_arg.as_deref()) {
                Ok(value) => value,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus: {error}");
                    return 2;
                }
            };
            if wake_on_send {
                let Some(targets) = to_arg.as_deref() else {
                    let _ = writeln!(stderr, "chinwag bus: wake_target_required");
                    return 2;
                };
                let Ok(targets) = agent_instance::parse_recipients(targets) else {
                    let _ = writeln!(stderr, "chinwag bus: invalid_actor_instance");
                    return 2;
                };
                if targets.iter().any(|target| target.instance().is_some()) {
                    let _ = writeln!(stderr, "chinwag bus: existing_instance_wake_unsupported");
                    return 2;
                }
            }
            let room = room_arg.unwrap_or_else(|| "#mgmt".to_string());
            let result = send_bus_message_sync(
                &repo_root,
                &sender,
                &room,
                to_arg.clone(),
                task_arg.clone(),
                &body,
            );
            let (msg, ack) = match result {
                Ok(value) => value,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus: {error}");
                    return 2;
                }
            };
            if is_json {
                let out = json!({
                    "ok": true,
                    "completion_scope": "PUBLISH_ONLY",
                    "delivery": chinwag_cli::bus_delivery::legacy_publication_report(
                        &msg.id,
                        &msg.digest_sha256,
                        msg.to.as_deref(),
                        chinwag_cli::bus_delivery::PublicationAck {
                            message_id: &ack.message_id,
                            ok: ack.ok,
                            signature_verified: ack.sig_verified,
                        },
                    ),
                    "message": msg,
                    "ack": ack
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&out).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "{}\n  ↳ Publication acknowledged via {} (daemon iroh:{}, sig_verified={})\n  Completion scope: PUBLISH_ONLY; persistence: UNKNOWN; processing: UNKNOWN (existing-conversation control unsupported)",
                    format_bus_line(&msg),
                    ack.transport,
                    &ack.daemon_endpoint_id[..12.min(ack.daemon_endpoint_id.len())],
                    ack.sig_verified
                );
            }
            if wake_on_send && let Some(ref targets) = to_arg {
                let task_for_wake = task_arg.unwrap_or_else(|| "CHWG-BUS-WAKE".to_string());
                for raw_target in targets.split(',') {
                    let clean_seat = raw_target
                        .trim()
                        .trim_start_matches('@')
                        .trim_start_matches('■')
                        .trim();
                    let base_target = base_seat_str(clean_seat);
                    if !base_target.is_empty()
                        && !base_target.eq_ignore_ascii_case("ALL")
                        && !base_target.eq_ignore_ascii_case("BRIAN")
                        && !base_target.eq_ignore_ascii_case("NIC")
                    {
                        let _ = run_worker_sync(
                            &repo_root,
                            clean_seat,
                            &task_for_wake,
                            &body,
                            Some(&sender),
                        );
                    }
                }
            }
            0
        }
        "tail" | "log" | "messages" => {
            let filter_room = room_arg
                .as_deref()
                .filter(|r| *r != "all" && *r != "#all")
                .map(normalize_room);
            let all = read_all_messages(&repo_root);
            let filtered: Vec<BusMessage> = all
                .into_iter()
                .filter(|m| {
                    filter_room.as_ref().is_none_or(|r| &m.room == r)
                        && task_arg
                            .as_ref()
                            .is_none_or(|t| m.task_id.as_deref() == Some(t.as_str()))
                })
                .collect();
            let start = filtered.len().saturating_sub(limit_arg);
            let slice = &filtered[start..];

            if is_json && !follow {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&slice).unwrap_or_default()
                );
                return 0;
            }

            for m in slice {
                let _ = writeln!(stdout, "{}", format_bus_line(m));
            }
            let _ = stdout.flush();

            if follow {
                let mut last_seq = slice.last().map(|m| m.seq).unwrap_or(0);
                loop {
                    std::thread::sleep(Duration::from_millis(450));
                    let current = read_all_messages(&repo_root);
                    for m in current {
                        if m.seq > last_seq
                            && filter_room.as_ref().is_none_or(|r| &m.room == r)
                            && task_arg
                                .as_ref()
                                .is_none_or(|t| m.task_id.as_deref() == Some(t.as_str()))
                        {
                            let _ = writeln!(stdout, "{}", format_bus_line(&m));
                            let _ = stdout.flush();
                            last_seq = m.seq;
                        }
                    }
                }
            }
            0
        }
        "inbox" => {
            let target_raw = for_arg
                .or_else(|| positionals.first().cloned())
                .unwrap_or_else(|| "Brian".to_string());
            let target = ActorAddress::parse(&target_raw).and_then(|target| {
                if let Some(instance) = instance_arg.as_deref() {
                    target.with_instance(instance)
                } else {
                    Ok(target)
                }
            });
            let target = match target {
                Ok(value) => value,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus: {error}");
                    return 2;
                }
            };
            let all = read_all_messages(&repo_root);
            let matching: Vec<BusMessage> = all
                .into_iter()
                .filter(|m| {
                    m.sig_verified
                        && (agent_instance::inbox_matches(&target, m.to.as_deref(), &m.body)
                            || (target.is_human() && m.room == "#mgmt"))
                })
                .collect();
            let start = matching.len().saturating_sub(limit_arg);
            let slice = &matching[start..];
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&slice).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "📬 Chinwag iroh Bus Inbox for {} ({} messages):",
                    target,
                    slice.len()
                );
                for m in slice {
                    let _ = writeln!(stdout, "  {}", format_bus_line(m));
                }
            }
            0
        }
        "wake" | "route" => {
            let target_seat = seat_arg
                .or_else(|| positionals.first().cloned())
                .unwrap_or_else(|| "ALL".to_string())
                .to_uppercase();

            let _ = send_service_message_sync(
                &repo_root,
                "PRODUCT",
                "#mgmt",
                Some("DELIVERY".to_string()),
                Some("TASK-18".to_string()),
                &format!(
                    "■ PRODUCT Utilization Governor (CHWG-DYNAMIC-TASKS-PARSER-01): Dynamically parsed TASKS.md (target={target_seat}) and enforcing 0% idle tolerance across ■ RUST, ■ ARCHITECT, ■ FLINT, ■ ALISTAIR, and ■ QA."
                ),
            );

            let spawned = dispatch_continuous_backlog_wave(&repo_root, &target_seat);

            let result = send_service_message_sync(
                &repo_root,
                "DELIVERY",
                "#eng",
                None,
                Some("TASK-18".to_string()),
                &format!(
                    "■ DELIVERY Work-Stream Router: Dispatched {} live worker stream(s) ({}). Streaming Ed25519+allowed_signers verified progress (1800-char full receipts) to #eng, #qa, and #mgmt.",
                    spawned.len(),
                    if spawned.is_empty() {
                        "all target seats already executing".to_string()
                    } else {
                        spawned.join(", ")
                    }
                ),
            );
            let (_, ack) = match result {
                Ok(value) => value,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus: {error}");
                    return 2;
                }
            };

            let out = json!({
                "ok": true,
                "command": "chinwag bus wake",
                "spawned_workstreams": spawned,
                "bus_seq": ack.seq,
                "daemon_endpoint_id": ack.daemon_endpoint_id,
                "sig_verified": ack.sig_verified
            });
            if is_json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&out).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "🚀 ■ PRODUCT + ■ DELIVERY woke {} work stream(s) on the iroh bus:\n  • {}",
                    spawned.len(),
                    if spawned.is_empty() {
                        "All target seats currently active".to_string()
                    } else {
                        spawned.join("\n  • ")
                    }
                );
            }
            0
        }
        "roster" | "top" => {
            let all = read_all_messages(&repo_root);
            let active_tasks = parse_active_tasks_from_markdown(&repo_root);
            let seats = [
                ("RUST", "Codex - GPT-6.1-SOL Ultra"),
                ("ARCHITECT", "Codex - GPT-6.1-SOL Ultra"),
                ("GAMEDEV", "Codex - GPT-6.1-SOL Ultra"),
                ("WORKHORSE", "Codex - GPT-6.1-SOL Max (Node 2)"),
                ("FLINT", "Recursive Flint MLX 262k (Node 2)"),
                ("H", "Codex - GPT-6.1-SOL Ultra (Node 3)"),
                ("AUSDRA", "Codex - GPT-6.1-SOL Ultra (Node 3)"),
                ("TYPE", "Codex - GPT-6.1-SOL High"),
                (
                    "DEV-1",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral Dev 1)",
                ),
                (
                    "DEV-2",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral Dev 2)",
                ),
                (
                    "DEV-3",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral Dev 3)",
                ),
                (
                    "DEV-4",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral Dev 4)",
                ),
                (
                    "DEV-5",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral Dev 5)",
                ),
                (
                    "QA-1",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral QA 1)",
                ),
                (
                    "QA-2",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral QA 2)",
                ),
                (
                    "QA-3",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral QA 3)",
                ),
                (
                    "QA-4",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral QA 4)",
                ),
                (
                    "QA-5",
                    "DeepSeek V4.1 Flash 1017 (Workers AI, Ephemeral QA 5)",
                ),
                ("ALISTAIR", "Gemini 4 Argon High"),
                ("EAGLE-EYE", "Gemini 4 Argon High"),
                ("PATENT", "Gemini 4 Argon High"),
                ("QA", "Gemini 4 Argon High"),
                ("GEMINI-PM", "Gemini 4 Argon High"),
                ("DELIVERY", "Gemini 4 Argon High"),
                ("BRIAN", "Principal Founder & CEO"),
                ("NIC", "Co-Founder & CCO"),
            ];

            let mut rows = Vec::new();
            for (seat, engine) in seats {
                let worker_active = is_seat_worker_active(&repo_root, seat);
                let assigned_task = active_tasks
                    .iter()
                    .find(|(s, _, _)| s.eq_ignore_ascii_case(seat))
                    .map(|(_, tid, _)| tid.clone())
                    .unwrap_or_else(|| "-".to_string());
                let msg_count = all
                    .iter()
                    .filter(|m| base_seat_str(&m.sender).eq_ignore_ascii_case(seat))
                    .count();
                let last_msg = all
                    .iter()
                    .rev()
                    .find(|m| base_seat_str(&m.sender).eq_ignore_ascii_case(seat));
                let last_ts = last_msg
                    .map(|m| format_local_wall_clock(&m.ts_iso))
                    .unwrap_or_else(|| "-".to_string());
                let last_tid = last_msg
                    .and_then(|m| m.task_id.clone())
                    .unwrap_or_else(|| "-".to_string());
                let status = if worker_active {
                    "WORKING"
                } else if seat == "PRODUCT" {
                    "GOVERNOR_ON"
                } else if seat == "DELIVERY" {
                    "ROUTER_ON"
                } else {
                    "STANDBY"
                };
                rows.push(json!({
                    "seat": seat,
                    "engine": engine,
                    "status": status,
                    "assigned_task": assigned_task,
                    "message_count": msg_count,
                    "last_receipt_cdt": last_ts,
                    "last_task_id": last_tid
                }));
            }

            if is_json {
                let out = json!({
                    "ok": true,
                    "command": "chinwag bus roster",
                    "seats": rows
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&out).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "📊 Chinwag 10-Seat Swarm Utilization Roster (INV-UTIL-01 · Central Time CDT):\n  \
                     {:<11} {:<24} {:<12} {:<10} {:<6} {:<14} LAST_TASK",
                    "SEAT", "ENGINE", "STATE", "ASSIGNED", "MSGS", "LAST_RECEIPT"
                );
                for r in &rows {
                    let _ = writeln!(
                        stdout,
                        "  ■ {:<9} {:<24} {:<12} {:<10} {:<6} {:<14} {}",
                        r["seat"].as_str().unwrap_or(""),
                        r["engine"].as_str().unwrap_or(""),
                        r["status"].as_str().unwrap_or(""),
                        r["assigned_task"].as_str().unwrap_or(""),
                        r["message_count"].as_u64().unwrap_or(0),
                        r["last_receipt_cdt"].as_str().unwrap_or(""),
                        r["last_task_id"].as_str().unwrap_or("")
                    );
                }
            }
            0
        }
        _ => {
            let daemon = read_daemon_state(&repo_root);
            let all = read_all_messages(&repo_root);
            let mgmt_count = all.iter().filter(|m| m.room == "#mgmt").count();
            let eng_count = all.iter().filter(|m| m.room == "#eng").count();
            let qa_count = all.iter().filter(|m| m.room == "#qa").count();
            let verified_count = all.iter().filter(|m| m.sig_verified).count();
            let tasks_path = repo_root.join("TASKS.md");

            if is_json {
                let out: Value = json!({
                    "ok": daemon.is_some(),
                    "daemon": daemon,
                    "rooms": {
                        "#mgmt": mgmt_count,
                        "#eng": eng_count,
                        "#qa": qa_count,
                        "total": all.len(),
                        "ed25519_verified": verified_count
                    },
                    "tasks_md": tasks_path.to_string_lossy(),
                    "messages_jsonl": messages_jsonl_path(&repo_root).to_string_lossy()
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&out).unwrap_or_default()
                );
                return 0;
            }

            if let Some(d) = daemon {
                let _ = writeln!(
                    stdout,
                    "🟢 Chinwag iroh Multi-Party Bus: ONLINE (PID {})\n\
                     • Hub EndpointId:     {}\n\
                     • Bound QUIC Sockets: {}\n\
                     • Active ALPNs:       {}\n\
                     • ■ PRODUCT Governor: {}\n\
                     • ■ DELIVERY Router:  {}\n\
                     • Room Message Count: {} total (#mgmt: {}, #eng: {}, #qa: {}, ✓ed25519: {})\n\
                     • Canonical Board:    {}",
                    d.pid,
                    d.endpoint_id,
                    d.bound_sockets.join(", "),
                    d.alpns.join(", "),
                    d.product_governor,
                    d.delivery_router,
                    all.len(),
                    mgmt_count,
                    eng_count,
                    qa_count,
                    verified_count,
                    tasks_path.display()
                );
            } else {
                let fallback_ep = load_or_create_daemon_secret(&repo_root)
                    .public()
                    .to_string();
                let _ = writeln!(
                    stdout,
                    "🟡 Chinwag iroh Multi-Party Bus: DAEMON STOPPED (Run `chinwag bus daemon` to bind QUIC)\n\
                     • Provisioned EndpointId: {}\n\
                     • Stored Bus Messages:    {} (#mgmt: {}, #eng: {}, #qa: {}, ✓ed25519: {})\n\
                     • Canonical Board:        {}",
                    fallback_ep,
                    all.len(),
                    mgmt_count,
                    eng_count,
                    qa_count,
                    verified_count,
                    tasks_path.display()
                );
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer01_receipt_transcript_matches_existing_bus_signature_and_wire() {
        let secret = SecretKey::from_bytes(&[9; 32]);
        let mut msg = BusMessage {
            id: "receipt:1".into(), seq: 1, ts_unix: 123, ts_iso: String::new(),
            sender: "QA#ExactCase".into(), sender_cast: String::new(),
            sender_endpoint_id: secret.public().to_string(), to: Some("WORKHORSE#owner".into()),
            room: "#é".into(), task_id: Some("C1".into()), body: "🙂|receipt".into(),
            digest_sha256: "ab".repeat(32), pubkey_ed25519: None,
            signature_ed25519: None, sig_verified: false,
        };
        sign_bus_message(&mut msg, &secret);
        let view = chinwag_cli::bus_delivery::ProcessingEnvelope {
            id: msg.id.clone(), timestamp: msg.ts_unix, sender: msg.sender.clone(),
            recipient: msg.to.clone().unwrap(), room: msg.room.clone(), task: msg.task_id.clone(),
            body: msg.body.clone(), signature: hex_to_64_bytes(msg.signature_ed25519.as_ref().unwrap()).unwrap(),
        };
        assert_eq!(view.signing_payload(), canonical_signing_payload(&msg));
        secret.public().verify(view.signing_payload().as_bytes(), &Signature::from_bytes(&view.signature)).unwrap();
        let bytes = serde_json::to_vec(&msg).unwrap();
        let decoded: BusMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical_signing_payload(&decoded), view.signing_payload());
        let ack = BusAck { ok: true, seq: 1, message_id: msg.id, daemon_endpoint_id: String::new(),
            transport: "controlled".into(), room: msg.room, subscribers_notified: 1, sig_verified: true };
        let ack_json = serde_json::to_value(ack).unwrap();
        assert_eq!(ack_json.as_object().unwrap().len(), 8);
        assert_eq!(ack_json["subscribers_notified"], 1);
        assert!(ack_json.get("delivery").is_none());
    }

    #[test]
    fn consumer01_duplicate_to_is_rejected_before_any_publication() {
        let repo = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args = [
            "send", "--repo", repo.path().to_str().unwrap(),
            "--to", "GEMINI-PM#one", "-t", "DELIVERY#two",
            "--message", "must not publish",
        ].map(str::to_owned);
        assert_eq!(run_bus_cli(&args, &mut out, &mut err), 2);
        assert!(String::from_utf8(err).unwrap().contains("duplicate_recipient_flag"));
        assert!(out.is_empty());
        assert_eq!(fs::read_dir(repo.path()).unwrap().count(), 0);
    }

    fn fixture_key(signing_dir: &Path, seat: &str) -> SecretKey {
        fs::create_dir_all(signing_dir).unwrap();
        let slug = valid_seat_slug(seat).unwrap();
        let path = signing_dir.join(format!("{slug}_ed25519.key"));
        fs::write(&path, [7_u8; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        actor_signing_secret_at(seat, signing_dir).unwrap()
    }

    #[test]
    fn detached_ed25519_bus_signature_verifies_allowed_signers_and_rejects_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let secret = fixture_key(&temp.path().join("fixture-signing"), "ARCHITECT");
        let mut msg = BusMessage {
            id: "bus-1793250000-deadbeef".to_string(),
            seq: 1,
            ts_unix: 1_793_250_000,
            ts_iso: "2026-10-29T18:15:00-0500 CDT".to_string(),
            room: "#eng".to_string(),
            sender: "ARCHITECT".to_string(),
            sender_cast: "■".to_string(),
            sender_endpoint_id: secret.public().to_string(),
            to: Some("RUST".to_string()),
            task_id: Some("TASK-15".to_string()),
            body: "Verified detached Ed25519 signature + allowed_signers".to_string(),
            digest_sha256: "deadbeef".repeat(8),
            pubkey_ed25519: None,
            signature_ed25519: None,
            sig_verified: false,
        };
        sign_bus_message(&mut msg, &secret);

        // Missing .chinwag/allowed_signers -> must fail closed
        assert!(!verify_detached_bus_signature(temp.path(), &mut msg));

        // Populate .chinwag/allowed_signers for ARCHITECT
        let ssh_pub = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
            *secret.public().as_bytes(),
        ));
        let openssh_line = ssh_pub.to_openssh().unwrap();
        let chinwag_dir = temp.path().join(".chinwag");
        fs::create_dir_all(&chinwag_dir).unwrap();
        fs::write(
            chinwag_dir.join("allowed_signers"),
            format!(
                "architect-agent@chinwag.sh namespaces=\"git\" {openssh_line} chinwag ARCHITECT\n"
            ),
        )
        .unwrap();

        // Valid 7-field signature + registered seat in allowed_signers passes
        assert!(verify_detached_bus_signature(temp.path(), &mut msg));

        // Tamper with task_id -> 7-field signature must fail closed
        let mut tampered_task = msg.clone();
        tampered_task.task_id = Some("TASK-99".to_string());
        assert!(!verify_detached_bus_signature(
            temp.path(),
            &mut tampered_task
        ));

        // Colon-shifting between task_id and body -> length-prefixed payload must fail closed
        let mut colon_shift = msg.clone();
        colon_shift.task_id = Some("TASK-15:Verified".to_string());
        colon_shift.body = " detached Ed25519 signature + allowed_signers".to_string();
        assert!(!verify_detached_bus_signature(
            temp.path(),
            &mut colon_shift
        ));

        // Tamper with body -> verification must fail closed
        msg.body.push_str(" tampered");
        assert!(!verify_detached_bus_signature(temp.path(), &mut msg));
    }

    #[test]
    fn dynamic_tasks_md_parser_extracts_in_progress_and_ready_items() {
        let temp = tempfile::tempdir().unwrap();
        let sample = "# TASKS\n\
            ### `[DONE]` `TASK-01` — Old Task\n\
            - **Owner:** `■ RUST`\n\
            ### `[IN_PROGRESS]` `TASK-15` — Hardened Bus Signatures\n\
            - **Owner:** `■ RUST` (`GPT / Codex`)\n\
            - **Scope:** Verify 7-field Ed25519 signature and allowed_signers.\n\
            ### `[READY]` `TASK-16` — Dynamic Interface Discovery\n\
            - **Owner:** `■ ARCHITECT`\n\
            - **Scope:** Discover active non-loopback IPv4 interfaces.\n";
        fs::write(temp.path().join("TASKS.md"), sample).unwrap();
        let parsed = parse_active_tasks_from_markdown(temp.path());
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "RUST");
        assert_eq!(parsed[0].1, "TASK-15");
        assert_eq!(parsed[1].0, "ARCHITECT");
        assert_eq!(parsed[1].1, "TASK-16");
    }

    #[test]
    fn local_wall_clock_converts_legacy_utc_and_preserves_cdt() {
        assert_eq!(
            format_local_wall_clock("2026-10-29T23:04:04Z"),
            "18:04:04 CDT"
        );
        assert_eq!(
            format_local_wall_clock("2026-10-29T18:06:12-0500 CDT"),
            "18:06:12 CDT"
        );
    }

    #[test]
    fn p0_acceptance_signed_legacy_completion_cannot_mutate_or_promote_tasks() {
        use std::os::unix::fs::MetadataExt;

        for body in ["COMPLETED TASK-15", "[DONE] TASK-15"] {
            let temp = tempfile::tempdir().unwrap();
            let secret = fixture_key(&temp.path().join("fixture-signing"), "RUST");
            let ssh_pub = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
                *secret.public().as_bytes(),
            ));
            let chinwag = temp.path().join(".chinwag");
            fs::create_dir_all(&chinwag).unwrap();
            fs::write(
                chinwag.join("allowed_signers"),
                format!(
                    "rust-agent@chinwag.sh namespaces=\"git\" {} chinwag RUST\n",
                    ssh_pub.to_openssh().unwrap()
                ),
            )
            .unwrap();
            let sample = "# TASKS\n### [IN_PROGRESS] TASK-15 — original task\n- **Owner:** RUST\n### [READY] TASK-22 — next task\n- **Owner:** RUST\n";
            let tasks_path = temp.path().join("TASKS.md");
            fs::write(&tasks_path, sample).unwrap();
            fs::set_permissions(&tasks_path, fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::metadata(&tasks_path).unwrap();
            let mut msg = BusMessage {
                id: "bus-1793250000-p006-legacy-fixture".to_string(),
                seq: 0,
                ts_unix: 1_793_250_000,
                ts_iso: "2026-10-29T18:15:00-0500 CDT".to_string(),
                room: "#eng".to_string(),
                sender: "RUST".to_string(),
                sender_cast: "■".to_string(),
                sender_endpoint_id: secret.public().to_string(),
                to: Some("ARCHITECT".to_string()),
                task_id: Some("TASK-15".to_string()),
                body: body.to_string(),
                digest_sha256: "deadbeef".repeat(8),
                pubkey_ed25519: None,
                signature_ed25519: None,
                sig_verified: false,
            };
            sign_bus_message(&mut msg, &secret);
            assert!(verify_detached_bus_signature(temp.path(), &mut msg));
            assert_eq!(append_message_to_disk_and_crdb(temp.path(), &msg), 1);
            let stored = read_all_messages(temp.path());
            assert_eq!(stored.len(), 1);
            assert!(stored[0].sig_verified);
            assert_eq!(stored[0].body, body);
            assert_eq!(fs::read(&tasks_path).unwrap(), sample.as_bytes());
            let after = fs::metadata(&tasks_path).unwrap();
            assert_eq!(
                (
                    after.dev(),
                    after.ino(),
                    after.uid(),
                    after.mode(),
                    after.nlink()
                ),
                (
                    before.dev(),
                    before.ino(),
                    before.uid(),
                    before.mode(),
                    before.nlink()
                )
            );
        }
    }

    #[test]
    fn actor_signing_secret_never_derives_predictable_seed_from_seat_name() {
        let t1 = actor_transport_secret("EPHEMERAL");
        let t2 = actor_transport_secret("EPHEMERAL");
        assert_ne!(t1.to_bytes(), t2.to_bytes());

        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(b"chinwag-iroh-bus-seat-ed25519-v1:ephemeral_probe");
        let legacy_digest = legacy_hasher.finalize();
        let unique_seat = format!("ephemeral_probe_{}", std::process::id());
        let temp = tempfile::tempdir().unwrap();
        let signing = fixture_key(temp.path(), &unique_seat);
        assert_ne!(&signing.to_bytes()[..], &legacy_digest[..]);
        assert!(actor_signing_secret_at("MISSING", temp.path()).is_err());
        assert!(!temp.path().join("missing_ed25519.key").exists());
    }

    #[test]
    fn thread_instance_id_signs_with_base_seat_key_and_verifies_against_allowed_signers() {
        let temp = tempfile::tempdir().unwrap();
        let signing_dir = temp.path().join("fixture-signing");
        let secret = fixture_key(&signing_dir, "GEMINI-PM#f19f15");
        let base_secret = actor_signing_secret_at("GEMINI-PM", &signing_dir).unwrap();
        assert_eq!(secret.public(), base_secret.public());

        let (norm_sender, cast) = normalize_actor("gemini-pm#f19f15").unwrap();
        assert_eq!(norm_sender, "GEMINI-PM#f19f15");
        assert_eq!(cast, "■");

        let mut msg = BusMessage {
            id: "bus-1793250001-beefcafe".to_string(),
            seq: 1,
            ts_unix: 1_793_250_001,
            ts_iso: "2026-11-04T00:50:00-0600 CST".to_string(),
            room: "#mgmt".to_string(),
            sender: norm_sender,
            sender_cast: cast,
            sender_endpoint_id: secret.public().to_string(),
            to: Some("WORKHORSE#prd-01".to_string()),
            task_id: Some("CHWG-PRD-FINAL".to_string()),
            body: "Thread-scoped message from GEMINI-PM#f19f15 to WORKHORSE#prd-01".to_string(),
            digest_sha256: "beefcafe".repeat(8),
            pubkey_ed25519: None,
            signature_ed25519: None,
            sig_verified: false,
        };
        sign_bus_message(&mut msg, &secret);

        let ssh_pub = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
            *secret.public().as_bytes(),
        ));
        let openssh_line = ssh_pub.to_openssh().unwrap();
        let chinwag_dir = temp.path().join(".chinwag");
        fs::create_dir_all(&chinwag_dir).unwrap();
        fs::write(
            chinwag_dir.join("allowed_signers"),
            format!(
                "gemini-pm-agent@chinwag.sh namespaces=\"git\" {openssh_line} chinwag GEMINI-PM\n"
            ),
        )
        .unwrap();

        assert!(verify_detached_bus_signature(temp.path(), &mut msg));

        // Tampering with the #instance suffix invalidates the 7-field Ed25519 signature
        let mut spoofed_instance = msg.clone();
        spoofed_instance.sender = "GEMINI-PM#other99".to_string();
        assert!(!verify_detached_bus_signature(
            temp.path(),
            &mut spoofed_instance
        ));

        let mut spoofed_recipient = msg.clone();
        spoofed_recipient.to = Some("WORKHORSE#prd-02".to_owned());
        assert!(!verify_detached_bus_signature(
            temp.path(),
            &mut spoofed_recipient
        ));

        // Even a valid seat signature cannot make malformed addresses routable.
        let mut malformed = msg.clone();
        malformed.sender = "GEMINI-PM#bad/tag".to_owned();
        sign_bus_message(&mut malformed, &secret);
        assert!(!verify_detached_bus_signature(temp.path(), &mut malformed));

        let mut wrong_seat = msg.clone();
        wrong_seat.sender = "WORKHORSE#f19f15".to_owned();
        sign_bus_message(&mut wrong_seat, &secret);
        assert!(!verify_detached_bus_signature(temp.path(), &mut wrong_seat));

        // Read the actual CLI inbox from an isolated signed fixture journal.
        let mut journal = Vec::new();
        for (seq, to, body) in [
            (1, Some("WORKHORSE#one"), "own"),
            (2, Some("WORKHORSE#one-sibling"), "quote @WORKHORSE#one"),
            (3, Some("WORKHORSE"), "seat broadcast"),
            (4, Some("ALL"), "all broadcast"),
            (5, None, "@WORKHORSE#one mention"),
            (6, None, "@WORKHORSE#one-sibling mention"),
        ] {
            let mut row = msg.clone();
            row.id = format!("fixture-{seq}");
            row.seq = seq;
            row.to = to.map(str::to_owned);
            row.body = body.to_owned();
            sign_bus_message(&mut row, &secret);
            journal.push(serde_json::to_string(&row).unwrap());
        }
        let mut forged = msg.clone();
        forged.id = "forged".to_owned();
        forged.seq = 7;
        forged.to = Some("WORKHORSE#one".to_owned());
        journal.push(serde_json::to_string(&forged).unwrap());
        let path = messages_jsonl_path(temp.path());
        fs::write(path, journal.join("\n") + "\n").unwrap();
        for (query, expected) in [
            ("WORKHORSE#one", vec![1, 3, 4, 5]),
            ("WORKHORSE", vec![1, 2, 3, 4, 5, 6]),
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                run_bus_cli(
                    &[
                        "inbox".into(),
                        "--repo".into(),
                        temp.path().to_string_lossy().into_owned(),
                        "--for".into(),
                        query.into(),
                        "--json".into()
                    ],
                    &mut out,
                    &mut err
                ),
                0
            );
            let rows: Vec<BusMessage> = serde_json::from_slice(&out).unwrap();
            assert_eq!(rows.iter().map(|row| row.seq).collect::<Vec<_>>(), expected);
            assert!(rows.iter().all(|row| row.sig_verified));
        }
    }

    #[test]
    fn worker_files_are_owned_by_the_exact_instance() {
        let temp = tempfile::tempdir().unwrap();
        let a = seat_pid_path(temp.path(), "WORKHORSE#one");
        let b = seat_pid_path(temp.path(), "WORKHORSE#two");
        let case_distinct = seat_pid_path(temp.path(), "WORKHORSE#ONE");
        assert_ne!(a, b);
        assert_ne!(a, case_distinct);
        let first = WorkerRegistration::acquire(temp.path(), "WORKHORSE#one").unwrap();
        assert!(WorkerRegistration::acquire(temp.path(), "WORKHORSE#one").is_err());
        let sibling = WorkerRegistration::acquire(temp.path(), "WORKHORSE#two").unwrap();
        drop(first);
        assert!(!a.exists());
        assert!(b.exists());
        drop(sibling);

        let original = WorkerRegistration::acquire(temp.path(), "WORKHORSE#one").unwrap();
        fs::remove_file(&a).unwrap();
        fs::write(&a, "replacement must survive").unwrap();
        drop(original);
        assert_eq!(fs::read_to_string(a).unwrap(), "replacement must survive");
    }

    #[test]
    fn retained_worker_logs_do_not_mark_idle_seats_active() {
        let temp = tempfile::tempdir().unwrap();
        let workers = bus_dir(temp.path()).join("workers");
        fs::create_dir_all(&workers).unwrap();
        let component = worker_file_component("WORKHORSE#retained");
        for index in 0..4097 {
            fs::write(
                workers.join(format!("{component}--{index}.log")),
                "retained",
            )
            .unwrap();
        }
        assert!(!is_seat_worker_active(temp.path(), "WORKHORSE"));
        assert!(!is_seat_worker_active(temp.path(), "WORKHORSE#retained"));

        let registration = WorkerRegistration::acquire(temp.path(), "WORKHORSE#live").unwrap();
        assert!(is_seat_worker_active(temp.path(), "WORKHORSE"));
        assert!(is_seat_worker_active(temp.path(), "WORKHORSE#live"));
        assert!(!is_seat_worker_active(temp.path(), "WORKHORSE#other"));
        drop(registration);
        assert!(!is_seat_worker_active(temp.path(), "WORKHORSE"));
    }

    #[test]
    fn seat_activity_preserves_legacy_pid_and_ignores_other_instance_entries() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = seat_pid_path(temp.path(), "WORKHORSE");
        let workers = bus_dir(temp.path()).join("workers");
        assert_eq!(legacy, workers.join("workhorse.pid"));
        fs::create_dir_all(&workers).unwrap();
        fs::write(&legacy, std::process::id().to_string()).unwrap();
        assert!(is_seat_worker_active(temp.path(), "WORKHORSE"));
        assert!(!is_seat_worker_active(temp.path(), "WORKHORSE#one"));
        fs::remove_file(&legacy).unwrap();

        let registration = WorkerRegistration::acquire(temp.path(), "ARCHITECT#one").unwrap();
        assert_eq!(
            registration.path.parent(),
            Some(workers.join("instances").as_path())
        );
        assert!(is_seat_worker_active(temp.path(), "ARCHITECT"));
        assert!(!is_seat_worker_active(temp.path(), "WORKHORSE"));
        let stale = seat_pid_path(temp.path(), "WORKHORSE#stale");
        fs::write(&stale, "invalid-pid").unwrap();
        fs::write(stale.with_extension("log"), "retained").unwrap();
        assert!(!is_seat_worker_active(temp.path(), "WORKHORSE"));
        drop(registration);
        assert!(!is_seat_worker_active(temp.path(), "ARCHITECT"));
    }

    #[test]
    fn subcommand_help_does_not_publish_or_start_a_worker() {
        for subcommand in ["send", "worker", "wake", "inbox"] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let args = vec![subcommand.to_owned(), "--help".to_owned()];
            assert_eq!(run_bus_cli(&args, &mut out, &mut err), 0);
            assert!(String::from_utf8(out).unwrap().starts_with("Usage:"));
            assert!(err.is_empty());
        }
    }

    #[test]
    fn missing_or_unknown_flags_cannot_become_message_text() {
        for flag in ["--instance", "--from", "--unknown"] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let args = vec!["send".to_owned(), flag.to_owned()];
            assert_eq!(run_bus_cli(&args, &mut out, &mut err), 2);
            assert!(out.is_empty());
        }
    }
}
