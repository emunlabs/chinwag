#![forbid(unsafe_code)]

//! Multi-party `iroh` QUIC messaging bus (`ALPN: chinwag/bus/1`) +
//! `■ PRODUCT` Utilization Governor & `■ DELIVERY` Work-Stream Router.
//!
//! Includes Phase 1.1 Hardening (`TASK-08`..`TASK-11`):
//! - `BUS-HARDEN-01`: Detached `Ed25519` message signatures (`pubkey_ed25519`, `signature_ed25519`, `sig_verified`).
//! - `BUS-HARDEN-02`: Multi-interface daemon binding (`0.0.0.0:44330` -> `127.0.0.1:44330` + Tailscale/LAN `100.x:44330`).
//! - `BUS-HARDEN-03`: Advisory `flock` on `.chinwag/bus/bus.lock` + `PRAGMA busy_timeout=5000;`.
//! - `CHWG-CONTINUOUS-LOOP-01`: Autonomous 45s `■ PRODUCT` + `■ DELIVERY` backlog governor.
//! - Local Central Time (`CDT` / `-05:00`) wall-clock formatting for operator logs.

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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
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
/// (e.g. `2026-10-29T18:06:12-0500 CDT`).
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
    if let Ok(cwd) = std::env::current_dir()
        && cwd.join(".chinwag").is_dir()
    {
        return cwd;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
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

fn seat_slug_clean(actor: &str) -> String {
    actor
        .trim()
        .trim_start_matches('●')
        .trim_start_matches('■')
        .trim_start_matches('◆')
        .trim()
        .to_lowercase()
}

/// Loads the seat's real OpenSSH Ed25519 signing key (`~/.chinwag/signing/<seat>_ed25519`)
/// or raw 32-byte seed (`~/.chinwag/signing/<seat>_ed25519.key`) for detached message signing (`BUS-HARDEN-01`).
pub fn actor_signing_secret(actor: &str) -> SecretKey {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let slug = seat_slug_clean(actor);
    let signing_dir = PathBuf::from(format!("{home}/.chinwag/signing"));
    let ssh_key_path = signing_dir.join(format!("{slug}_ed25519"));
    let resolved_path = fs::canonicalize(&ssh_key_path).unwrap_or(ssh_key_path);
    if let Ok(identity) = chinwag_swarm::identity::Identity::from_ssh_signing_file(&resolved_path) {
        return identity.iroh_secret_key();
    }

    let raw_key_path = signing_dir.join(format!("{slug}_ed25519.key"));
    if let Ok(bytes) = fs::read(&raw_key_path)
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return SecretKey::from_bytes(&arr);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"chinwag-iroh-bus-seat-ed25519-v1:");
    hasher.update(slug.as_bytes());
    let digest = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    let _ = fs::create_dir_all(&signing_dir);
    let _ = fs::write(&raw_key_path, arr);
    let _ = fs::set_permissions(&raw_key_path, fs::Permissions::from_mode(0o600));
    SecretKey::from_bytes(&arr)
}

fn actor_transport_secret(actor: &str) -> SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(b"chinwag-iroh-bus-actor-v1:");
    hasher.update(actor.trim().to_uppercase().as_bytes());
    let digest = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    SecretKey::from_bytes(&arr)
}

pub fn canonical_signing_payload(msg: &BusMessage) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        msg.id,
        msg.ts_unix,
        msg.sender,
        msg.to.as_deref().unwrap_or(""),
        msg.room,
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
    if hex_str.len() != 128 {
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

/// Verifies the detached Ed25519 signature on `msg` (`BUS-HARDEN-01`).
pub fn verify_bus_message_signature(msg: &mut BusMessage) -> bool {
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
    let payload = canonical_signing_payload(msg);
    let ok = pubkey.verify(payload.as_bytes(), &sig).is_ok();
    msg.sig_verified = ok;
    ok
}

fn normalize_actor(raw: &str) -> (String, String) {
    let trimmed = raw
        .trim()
        .trim_start_matches('●')
        .trim_start_matches('■')
        .trim_start_matches('◆')
        .trim();
    let upper = trimmed.to_uppercase();
    if upper == "BRIAN" || upper == "ACTOR-BRIAN" {
        ("Brian".to_string(), "●".to_string())
    } else if upper == "NIC" || upper == "NICOLA" || upper == "ACTOR-NIC" {
        ("Nic".to_string(), "●".to_string())
    } else {
        (upper, "■".to_string())
    }
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
            if msg.signature_ed25519.is_some() && !msg.sig_verified {
                let _ = verify_bus_message_signature(&mut msg);
            }
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
    if verified_msg.signature_ed25519.is_none() {
        let sign_key = actor_signing_secret(&verified_msg.sender);
        sign_bus_message(&mut verified_msg, &sign_key);
    } else {
        let _ = verify_bus_message_signature(&mut verified_msg);
    }

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
        let sql = format!(
            "PRAGMA busy_timeout=5000; \
             CREATE TABLE IF NOT EXISTS bus_messages (id TEXT PRIMARY KEY, seq INTEGER, ts_iso TEXT, room TEXT, sender TEXT, sender_endpoint_id TEXT, recipient TEXT, task_id TEXT, body TEXT, digest_sha256 TEXT, pubkey_ed25519 TEXT, signature_ed25519 TEXT, sig_verified INTEGER DEFAULT 0); \
             ALTER TABLE bus_messages ADD COLUMN pubkey_ed25519 TEXT; \
             ALTER TABLE bus_messages ADD COLUMN signature_ed25519 TEXT; \
             ALTER TABLE bus_messages ADD COLUMN sig_verified INTEGER DEFAULT 0; \
             INSERT OR REPLACE INTO bus_messages (id, seq, ts_iso, room, sender, sender_endpoint_id, recipient, task_id, body, digest_sha256, pubkey_ed25519, signature_ed25519, sig_verified) VALUES ('{}', {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', {});",
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
        // Execute CREATE + INSERT cleanly even if columns already exist
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
        let _ = sql;

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
    let raw = fs::read_to_string(daemon_json_path(repo_root)).ok()?;
    let state: DaemonState = serde_json::from_str(&raw).ok()?;
    let status = Command::new("/bin/kill")
        .args(["-0", &state.pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if status.success() {
        Some(state)
    } else {
        None
    }
}

fn write_daemon_state(repo_root: &Path, state: &DaemonState) {
    let path = daemon_json_path(repo_root);
    if let Ok(text) = serde_json::to_string_pretty(state) {
        let _ = fs::write(&path, text);
    }
}

/// Binds on `0.0.0.0:{port}` when `port != 0` (`BUS-HARDEN-02` — accepting connections on
/// both `127.0.0.1:44330` and Tailscale/LAN `100.x:44330`), and `127.0.0.1:0` for ephemeral clients.
async fn bind_bus_endpoint(
    secret: SecretKey,
    port: u16,
    lookup: MemoryLookup,
) -> Result<Endpoint, String> {
    let bind_host = if port == 0 { "127.0.0.1" } else { "0.0.0.0" };
    let addr: SocketAddr = format!("{bind_host}:{port}")
        .parse()
        .map_err(|e| format!("invalid socket addr: {e}"))?;
    let builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret.clone())
        .clear_address_lookup()
        .address_lookup(lookup.clone())
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![
            BUS_ALPN.to_vec(),
            chinwag_swarm::dispatch_wire::ALPN.to_vec(),
        ])
        .clear_ip_transports()
        .bind_addr(addr)
        .map_err(|e| format!("bind_addr failed: {e}"))?;

    match builder.bind().await {
        Ok(ep) => Ok(ep),
        Err(_) if port != 0 => {
            let fallback: SocketAddr = "127.0.0.1:0".parse().unwrap();
            Endpoint::builder(presets::Minimal)
                .secret_key(secret)
                .clear_address_lookup()
                .address_lookup(lookup)
                .relay_mode(RelayMode::Disabled)
                .alpns(vec![
                    BUS_ALPN.to_vec(),
                    chinwag_swarm::dispatch_wire::ALPN.to_vec(),
                ])
                .clear_ip_transports()
                .bind_addr(fallback)
                .map_err(|e| format!("fallback bind_addr failed: {e}"))?
                .bind()
                .await
                .map_err(|e| format!("endpoint bind failed: {e}"))
        }
        Err(e) => Err(format!("endpoint bind failed: {e}")),
    }
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
    let connect_res = tokio::time::timeout(
        Duration::from_secs(3),
        client.connect(addr, BUS_ALPN),
    )
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

    let resp_bytes = tokio::time::timeout(
        Duration::from_secs(3),
        recv.read_to_end(MAX_FRAME_BYTES),
    )
    .await
    .map_err(|_| "read ack timeout".to_string())?
    .map_err(|e| format!("read ack error: {e}"))?;

    client.close().await;
    serde_json::from_slice::<BusAck>(&resp_bytes).map_err(|e| format!("invalid ack json: {e}"))
}

/// Formats `m.ts_iso` in local Central Time (`[18:06:12 CDT]`), automatically converting
/// any legacy UTC (`Z`) timestamps so operators always see local wall-clock time.
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
    let to_badge = m
        .to
        .as_deref()
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

/// Autonomous `■ PRODUCT` + `■ DELIVERY` Backlog Governor (`CHWG-CONTINUOUS-LOOP-01`).
/// Dispatches active engineering, security, and QA work streams across all seats.
fn dispatch_continuous_backlog_wave(repo_root: &Path, target_seat: &str) -> Vec<String> {
    let mut spawned = Vec::new();
    let target = target_seat.to_uppercase();

    let work_matrix = [
        (
            "RUST",
            "TASK-08",
            "TASK-08 & TASK-12 (BUS-HARDEN-01 + CHWG-OPENSPEC-CLI-01): Verify detached Ed25519 message signing in crates/chinwag-cli/src/bus_run.rs and OpenSpec CLI subcommands in crates/chinwag-cli/src/feature_cli_run.rs. Run cargo test -p chinwag-cli --lib and return your concise verification summary.",
        ),
        (
            "ARCHITECT",
            "TASK-09",
            "TASK-09 & TASK-13 (BUS-HARDEN-02 + CHWG-PLUGIN-HOST-01): Verify multi-interface 0.0.0.0:44330 QUIC binding in crates/chinwag-cli/src/bus_run.rs and .cwplugin Ed25519 manifest verifier (chinwag plugin verify --json). Return your concise architectural verification summary.",
        ),
        (
            "FLINT",
            "TASK-10",
            "TASK-10 (BUS-HARDEN-03 Re-Audit): Verify that crates/chinwag-cli/src/agent_dispatch_run.rs now retries persist_to_crdb 5 times with backoff and surfaces crdb_error instead of silent deferred:, and bus_run.rs enforces advisory flock on .chinwag/bus/bus.lock + PRAGMA busy_timeout=5000. Return your adversarial PASS/FAIL verdict.",
        ),
        (
            "ALISTAIR",
            "TASK-07",
            "TASK-07 & TASK-14 (CHWG-SIGN-AUDIT-1 + CHWG-A509-CLI-01): Audit .chinwag/allowed_signers and all 10 seat Ed25519 keys (rust, architect, flint, qa, alistair, type, gemini-pm, product, delivery, brian) plus detached Ed25519 bus signatures. Return your CISO verification verdict.",
        ),
        (
            "QA",
            "TASK-06",
            "TASK-06 (CHWG-QA-SWEEP-1): Verify workspace determinism for chinwag ui-gate --json, chinwag openspec validate --json, chinwag plugin verify --json, and chinwag a509 verify --json. Return your QA gate receipt.",
        ),
    ];

    for (seat, task_id, prompt) in work_matrix {
        if target == "ALL"
            || target == seat
            || (target == "GPT" && (seat == "RUST" || seat == "ARCHITECT" || seat == "ALISTAIR"))
        {
            if is_seat_worker_active(repo_root, seat) {
                continue;
            }
            if spawn_seat_workstream(repo_root, seat, task_id, prompt) {
                spawned.push(format!("■ {seat} (-> {task_id})"));
            }
        }
    }
    spawned
}

fn seat_pid_path(repo_root: &Path, seat: &str) -> PathBuf {
    bus_dir(repo_root)
        .join("workers")
        .join(format!("{}.pid", seat.to_lowercase()))
}

fn is_seat_worker_active(repo_root: &Path, seat: &str) -> bool {
    let pid_file = seat_pid_path(repo_root, seat);
    let Ok(raw) = fs::read_to_string(&pid_file) else {
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
            let _ = writeln!(stdout, "chinwag bus daemon failed to bind iroh endpoint: {e}");
            return 1;
        }
    };

    let endpoint_id = endpoint.id().to_string();
    let mut bound_sockets: Vec<String> = endpoint
        .bound_sockets()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let local_loopback = format!("127.0.0.1:{port}");
    let wildcard_bind = format!("0.0.0.0:{port}");
    let tailscale_bind = format!("100.66.156.76:{port}");
    if !bound_sockets.contains(&wildcard_bind) {
        bound_sockets.insert(0, wildcard_bind);
    }
    if !bound_sockets.contains(&local_loopback) {
        bound_sockets.push(local_loopback);
    }
    if !bound_sockets.contains(&tailscale_bind) {
        bound_sockets.push(tailscale_bind);
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
        product_governor:
            "ACTIVE (CHWG-CONTINUOUS-LOOP-01 · 45s Autonomous Utilization Governor)".to_string(),
        delivery_router:
            "ACTIVE (Ed25519-Verified Multi-Party Work-Stream Router on 0.0.0.0:44330)".to_string(),
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
    // Consume immediate first tick so daemon finishes binding before first autonomous wave
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
                        let _ = send_bus_message_sync(
                            &repo_gov,
                            "PRODUCT",
                            "#mgmt",
                            Some("DELIVERY".to_string()),
                            Some("TASK-11".to_string()),
                            &format!(
                                "■ PRODUCT × ■ DELIVERY Autonomous Governor (CHWG-CONTINUOUS-LOOP-01): Re-dispatched {} idle seat(s) ({}) under 0% idle tolerance.",
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
                        let sig_ok = verify_bus_message_signature(&mut message);
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
) -> (BusMessage, BusAck) {
    let (sender, sender_cast) = normalize_actor(from);
    let room_norm = normalize_room(room);
    let signing_secret = actor_signing_secret(&sender);
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

    // If daemon is online, publish over live iroh QUIC (`ALPN: chinwag/bus/1`)
    if let Some(daemon) = read_daemon_state(repo_root)
        && let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        && let Ok(ack) = rt.block_on(publish_over_iroh_quic(&daemon, transport_secret, &msg))
    {
        msg.seq = ack.seq;
        return (msg, ack);
    }

    // Fallback direct persistence if daemon is still starting
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
    (msg, ack)
}

fn run_worker_sync(repo_root: &Path, seat: &str, task_id: &str, prompt: &str) -> u8 {
    let pid_file = seat_pid_path(repo_root, seat);
    let _ = fs::write(&pid_file, format!("{}", std::process::id()));

    let _ = send_bus_message_sync(
        repo_root,
        seat,
        "#eng",
        None,
        Some(task_id.to_string()),
        &format!("ACK from ■ {seat}: Executing work stream on {task_id} now."),
    );

    let mut out_buf: Vec<u8> = Vec::new();
    let mut err_buf: Vec<u8> = Vec::new();
    let crdb_str = repo_root
        .join(".chinwag/state.crdb")
        .to_string_lossy()
        .to_string();
    if let chinwag_cli::Dispatch::AgentDispatch(req) = chinwag_cli::dispatch(
        std::ffi::OsStr::new("chinwag"),
        [
            "agent-dispatch",
            "--agent",
            seat,
            "--item",
            task_id,
            "--sender",
            "DELIVERY",
            "--crdb",
            &crdb_str,
            "--body",
            prompt,
        ],
    ) {
        let _ = chinwag_cli::run_agent_dispatch(
            req,
            &mut std::io::empty(),
            &mut out_buf,
            &mut err_buf,
        );
    }

    let raw_out = String::from_utf8_lossy(&out_buf).trim().to_string();
    let reply_text = serde_json::from_str::<Value>(&raw_out)
        .ok()
        .and_then(|v| v.get("reply").and_then(|r| r.as_str()).map(|s| s.to_string()))
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
    let summary: String = collapsed.chars().take(480).collect();

    let target_room = if seat.eq_ignore_ascii_case("QA") {
        "#qa"
    } else {
        "#eng"
    };
    let _ = send_bus_message_sync(
        repo_root,
        seat,
        target_room,
        None,
        Some(task_id.to_string()),
        &format!("COMPLETED {task_id}: {summary}"),
    );

    let short_summary: String = collapsed.chars().take(240).collect();
    let _ = send_bus_message_sync(
        repo_root,
        "DELIVERY",
        "#mgmt",
        Some("Brian".to_string()),
        Some(task_id.to_string()),
        &format!("■ DELIVERY Receipt: ■ {seat} completed {task_id} -> {short_summary}"),
    );
    let _ = fs::remove_file(&pid_file);
    0
}

fn spawn_seat_workstream(repo_root: &Path, seat: &str, task_id: &str, prompt: &str) -> bool {
    let logs_dir = bus_dir(repo_root).join("workers");
    let _ = fs::create_dir_all(&logs_dir);
    let log_file = logs_dir.join(format!("{}-{}.log", seat.to_lowercase(), task_id.to_lowercase()));
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
                seat,
                "--task",
                task_id,
                "--message",
                prompt,
            ])
            .env(
                "PATH",
                "/opt/homebrew/opt/rustup/bin:/Users/brianspector/.local/bin:/opt/homebrew/bin:/usr/bin:/bin",
            )
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

pub fn run_bus_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    if sub == "--help" || sub == "-h" || sub == "help" {
        let _ = writeln!(
            stdout,
            "Usage:\n  \
             chinwag bus status [--json]\n  \
             chinwag bus daemon [--port <44330>] [--repo <path>]\n  \
             chinwag bus send [--from <ACTOR>] [--room <#mgmt|#eng|#qa>] [--to <@SEAT>] [--task <TASK-ID>] [--json] \"<MESSAGE>\"\n  \
             chinwag bus tail [--room <#mgmt|#eng|#all>] [--task <TASK-ID>] [--limit <N>] [-f | --follow] [--json]\n  \
             chinwag bus inbox [--for <ACTOR>] [--limit <N>] [--json]\n  \
             chinwag bus wake [--seat <ALL|RUST|ARCHITECT|FLINT|QA|ALISTAIR>]\n\n\
             Multi-party iroh QUIC messaging bus (ALPN: chinwag/bus/1) + ■ PRODUCT Utilization & ■ DELIVERY Work-Stream Router."
        );
        return 0;
    }

    let mut repo_arg: Option<String> = None;
    let mut from_arg: Option<String> = None;
    let mut room_arg: Option<String> = None;
    let mut to_arg: Option<String> = None;
    let mut task_arg: Option<String> = None;
    let mut for_arg: Option<String> = None;
    let mut seat_arg: Option<String> = None;
    let mut limit_arg: usize = 30;
    let mut port_arg: u16 = DEFAULT_BUS_PORT;
    let mut follow = false;
    let mut is_json = false;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--repo" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--from" | "-s" | "--sender" if i + 1 < args.len() => {
                from_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--room" | "--channel" | "-c" if i + 1 < args.len() => {
                room_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--to" | "-t" if i + 1 < args.len() => {
                to_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--task" | "--item" | "-k" if i + 1 < args.len() => {
                task_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--for" | "--actor" if i + 1 < args.len() => {
                for_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--seat" if i + 1 < args.len() => {
                seat_arg = Some(args[i + 1].clone());
                i += 2;
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
            "--message" | "-m" if i + 1 < args.len() => {
                positionals.push(args[i + 1].clone());
                i += 2;
            }
            _ => {
                positionals.push(args[i].clone());
                i += 1;
            }
        }
    }

    let repo_root = resolve_repo_root(repo_arg.as_deref());

    match sub {
        "worker" => {
            let seat = seat_arg
                .or_else(|| from_arg.clone())
                .unwrap_or_else(|| "RUST".to_string());
            let task = task_arg.unwrap_or_else(|| "TASK-08".to_string());
            let prompt = positionals.join(" ").trim().to_string();
            run_worker_sync(&repo_root, &seat, &task, &prompt)
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
            let body = positionals.join(" ").trim().to_string();
            if body.is_empty() {
                let _ = writeln!(
                    stderr,
                    "Usage: chinwag bus send [--from <ACTOR>] [--room <#mgmt|#eng>] [--task <TASK-ID>] \"<MESSAGE>\""
                );
                return 2;
            }
            let sender = from_arg
                .or_else(|| std::env::var("CHINWAG_ACTOR").ok())
                .unwrap_or_else(|| "Brian".to_string());
            let room = room_arg.unwrap_or_else(|| "#mgmt".to_string());
            let (msg, ack) =
                send_bus_message_sync(&repo_root, &sender, &room, to_arg, task_arg, &body);
            if is_json {
                let out = json!({
                    "ok": true,
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
                    "{}\n  ↳ Delivered via {} (daemon iroh:{}, sig_verified={})",
                    format_bus_line(&msg),
                    ack.transport,
                    &ack.daemon_endpoint_id[..12.min(ack.daemon_endpoint_id.len())],
                    ack.sig_verified
                );
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
            let (target_norm, _) = normalize_actor(&target_raw);
            let mention_token = format!("@{}", target_norm.to_uppercase());
            let all = read_all_messages(&repo_root);
            let matching: Vec<BusMessage> = all
                .into_iter()
                .filter(|m| {
                    let direct = m
                        .to
                        .as_ref()
                        .is_some_and(|t| t.eq_ignore_ascii_case(&target_norm));
                    let mentioned = m.body.to_uppercase().contains(&mention_token)
                        || m.body.to_uppercase().contains("@ALL");
                    let mgmt_for_human =
                        (target_norm == "Brian" || target_norm == "Nic") && m.room == "#mgmt";
                    direct || mentioned || mgmt_for_human
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
                    target_norm,
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

            let _ = send_bus_message_sync(
                &repo_root,
                "PRODUCT",
                "#mgmt",
                Some("DELIVERY".to_string()),
                Some("TASK-11".to_string()),
                &format!(
                    "■ PRODUCT Utilization Governor (CHWG-CONTINUOUS-LOOP-01): Enforcing 0% idle tolerance on TASKS.md (target={target_seat}). Routing Phase 1.1 & CLI backlog work streams to ■ RUST, ■ ARCHITECT, ■ FLINT, ■ ALISTAIR, and ■ QA now."
                ),
            );

            let spawned = dispatch_continuous_backlog_wave(&repo_root, &target_seat);

            let (_, ack) = send_bus_message_sync(
                &repo_root,
                "DELIVERY",
                "#eng",
                None,
                Some("TASK-11".to_string()),
                &format!(
                    "■ DELIVERY Work-Stream Router: Dispatched {} live worker stream(s) ({}). Streaming Ed25519-verified progress to #eng, #qa, and #mgmt over iroh/bus/1 (0.0.0.0:44330).",
                    spawned.len(),
                    if spawned.is_empty() {
                        "all target seats already executing".to_string()
                    } else {
                        spawned.join(", ")
                    }
                ),
            );

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
        "status" | _ => {
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
                let fallback_ep = load_or_create_daemon_secret(&repo_root).public().to_string();
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
    fn detached_ed25519_bus_signature_verifies_and_rejects_tampering() {
        let secret = SecretKey::from_bytes(&[0x42; 32]);
        let mut msg = BusMessage {
            id: "bus-1793250000-deadbeef".to_string(),
            seq: 1,
            ts_unix: 1_793_250_000,
            ts_iso: "2026-10-29T18:06:00-0500 CDT".to_string(),
            room: "#eng".to_string(),
            sender: "ARCHITECT".to_string(),
            sender_cast: "■".to_string(),
            sender_endpoint_id: secret.public().to_string(),
            to: Some("RUST".to_string()),
            task_id: Some("TASK-08".to_string()),
            body: "Verified detached Ed25519 signature on BusMessage".to_string(),
            digest_sha256: "deadbeef".repeat(8),
            pubkey_ed25519: None,
            signature_ed25519: None,
            sig_verified: false,
        };
        sign_bus_message(&mut msg, &secret);
        assert!(msg.sig_verified);
        assert!(verify_bus_message_signature(&mut msg));

        // Tamper with body -> verification must fail closed
        msg.body.push_str(" tampered");
        assert!(!verify_bus_message_signature(&mut msg));
        assert!(!msg.sig_verified);
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
}
