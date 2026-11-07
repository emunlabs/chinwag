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
pub use chinwag_cli::bus_federation::BusMessage;
use chinwag_cli::bus_network::{
    NativeBusHooks, NetworkSelection, PathObservation, local_publisher_path,
};
use chinwag_swarm::room_binding::{DaemonPeerGate, DaemonRoomIdentity};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, Signature, TransportAddr, Watcher,
    address_lookup::memory::MemoryLookup, endpoint::presets,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
#[cfg(test)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

pub const BUS_ALPN: &[u8] = b"chinwag/bus/1";
// Preserve Iroh's normal connection window for an explicitly pinned relay.
// Each original is attempted once; gate freshness is checked before and after.
const FEDERATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_BUS_PORT: u16 = 44330;
const MAX_FRAME_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum BusFrame {
    Publish { message: BusMessage },
    Federate { message: BusMessage },
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

#[derive(Debug, Serialize, Deserialize)]
struct FederationAck {
    publication: BusAck,
    original_digest_sha256: String,
}

/// The original sender signature is unchanged. Metadata not covered by its
/// legacy seven fields must still match the carried original witnesses.
fn valid_federation_original(root: &Path, message: &mut BusMessage) -> bool {
    use subtle::ConstantTimeEq;
    if !verify_detached_bus_signature(root, message) {
        return false;
    }
    let Some(key) = message.pubkey_ed25519.as_deref() else {
        return false;
    };
    let digest = compute_message_digest(
        message.ts_unix,
        &message.room,
        &message.sender,
        &message.sender_endpoint_id,
        message.to.as_deref(),
        message.task_id.as_deref(),
        &message.body,
    );
    bool::from(key.as_bytes().ct_eq(message.sender_endpoint_id.as_bytes()))
        && bool::from(digest.as_bytes().ct_eq(message.digest_sha256.as_bytes()))
}

struct OwnedBusConnection(iroh::endpoint::Connection);
impl Drop for OwnedBusConnection {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"native_frame_finished");
    }
}

#[derive(Debug, Clone, Copy)]
enum FederationFailure {
    PeerUnavailable,
    ConnectDeadline,
    ConnectFailed,
    TransferDeadline,
    TransferOrAckRefused,
}
impl FederationFailure {
    fn category(self) -> &'static str {
        match self {
            Self::PeerUnavailable => "peer_unavailable",
            Self::ConnectDeadline => "connect_deadline",
            Self::ConnectFailed => "connect_failed",
            Self::TransferDeadline => "transfer_deadline",
            Self::TransferOrAckRefused => "transfer_or_ack_refused",
        }
    }
}

async fn forward_original(
    endpoint: &Endpoint,
    selection: &NetworkSelection,
    gate: &DaemonPeerGate,
    message: &BusMessage,
) -> Result<PathObservation, FederationFailure> {
    use subtle::ConstantTimeEq;
    let address = selection
        .current_address(gate)
        .map_err(|_| FederationFailure::PeerUnavailable)?;
    let connection = tokio::time::timeout(
        FEDERATION_CONNECT_TIMEOUT,
        endpoint.connect(address, BUS_ALPN),
    )
    .await
    .map_err(|_| FederationFailure::ConnectDeadline)?
    .map_err(|_| FederationFailure::ConnectFailed)?;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        selection.remote_path(&connection, gate).map_err(|_| ())?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(|_| ())?;
        let payload = serde_json::to_vec(&BusFrame::Federate {
            message: message.clone(),
        })
        .map_err(|_| ())?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(());
        }
        gate.check_peer(connection.remote_id()).map_err(|_| ())?;
        send.write_all(&payload).await.map_err(|_| ())?;
        send.finish().map_err(|_| ())?;
        let bytes = recv.read_to_end(MAX_FRAME_BYTES).await.map_err(|_| ())?;
        let ack: FederationAck = serde_json::from_slice(&bytes).map_err(|_| ())?;
        let publication = &ack.publication;
        if !publication.ok
            || !publication.sig_verified
            || publication.seq == 0
            || publication.message_id != message.id
            || publication.room != message.room
            || !bool::from(
                publication
                    .daemon_endpoint_id
                    .as_bytes()
                    .ct_eq(selection.peer().to_string().as_bytes()),
            )
            || !bool::from(
                ack.original_digest_sha256
                    .as_bytes()
                    .ct_eq(message.digest_sha256.as_bytes()),
            )
        {
            return Err(());
        }
        selection.remote_path(&connection, gate).map_err(|_| ())
    })
    .await
    .map_err(|_| FederationFailure::TransferDeadline)
    .and_then(|result| result.map_err(|_| FederationFailure::TransferOrAckRefused));
    connection.close(0u32.into(), b"native_original_finished");
    result
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

fn resolve_repo_root(
    explicit: Option<&str>,
) -> Result<chinwag_cli::execution_binding::RepositorySelection, String> {
    use chinwag_cli::execution_binding::{RepoSelectors, select_repository};
    let environment = std::env::var_os("CHINWAG_REPO_ROOT");
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    select_repository(RepoSelectors {
        explicit_repo: explicit.map(Path::new),
        environment_repo: environment.as_deref(),
        cwd: &cwd,
    })
    .map_err(|error| error.to_string())
}

fn bus_dir(repo_root: &Path) -> PathBuf {
    // Path lookup is read-only. Mutating entry points first validate/create the
    // owned private directory through bus_identity, without repairing unsafe
    // modes or following a replacement symlink.
    repo_root.join(".chinwag").join("bus")
}

fn messages_jsonl_path(repo_root: &Path) -> PathBuf {
    bus_dir(repo_root).join("messages.jsonl")
}

fn daemon_json_path(repo_root: &Path) -> PathBuf {
    bus_dir(repo_root).join("daemon.json")
}

fn load_or_create_daemon_secret(repo_root: &Path) -> Result<SecretKey, String> {
    // The command's selected repository supplies the root. Resolve its physical
    // path before the identity module opens retained, no-follow directories;
    // never run bus_dir's legacy chmod/create fallback before this validation.
    let root = fs::canonicalize(repo_root).map_err(|_| "daemon identity unavailable".to_owned())?;
    chinwag_cli::bus_identity::load_or_create_daemon_secret(&root).map_err(|e| e.to_string())
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
    use subtle::ConstantTimeEq;
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
        bool::from(bytes.ct_eq(pubkey.as_bytes()))
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
    // This legacy query is observational. It must not create/chmod a lock or
    // silently acquire mutation authority merely to render a history view.
    read_all_messages_unlocked(repo_root)
}

/// The journal is the original durable publication store. Existing SQLite
/// mirrors remain historical observations and are not written through an
/// unchecked external path. Storage never grants processing or work start.
fn persist_local_publication(repo_root: &Path, msg: &BusMessage) -> Result<u64, String> {
    use chinwag_cli::bus_federation::{FederationSink, SinkDisposition};
    let mut verified_msg = msg.clone();
    if !verify_detached_bus_signature(repo_root, &mut verified_msg) {
        return Err("bus publication refused".to_owned());
    }
    let root = fs::canonicalize(repo_root).map_err(|_| "bus persistence unavailable")?;
    let mut sink = chinwag_cli::bus_store::NativeJournalSink::open(&root)
        .map_err(|_| "bus persistence unavailable")?;
    match sink
        .persist_if_absent(&verified_msg)
        .map_err(|_| "bus persistence unknown")?
    {
        SinkDisposition::Stored { local_sequence } => {
            verified_msg.seq = local_sequence;
            Ok(local_sequence)
        }
        SinkDisposition::ExactReplay { local_sequence } => Ok(local_sequence),
        SinkDisposition::Conflict => Err("bus original conflict".to_owned()),
    }
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

/// An explicit remote selection is complete data or an error. Never derive a
/// remote endpoint from our local key, or hide a failed remote send in a new
/// local append.
fn explicit_daemon_route(
    repo_root: &Path,
    address: Option<&str>,
    endpoint: Option<&str>,
) -> Result<DaemonState, ()> {
    let socket: SocketAddr = address.ok_or(())?.parse().map_err(|_| ())?;
    let endpoint: EndpointId = endpoint.ok_or(())?.parse().map_err(|_| ())?;
    if socket.ip().is_unspecified() || socket.port() == 0 {
        return Err(());
    }
    Ok(DaemonState {
        ok: true,
        pid: 0,
        endpoint_id: endpoint.to_string(),
        bound_sockets: vec![socket.to_string()],
        alpns: vec![
            "chinwag/bus/1".to_owned(),
            "chinwag/agent-dispatch/1".to_owned(),
        ],
        repo_root: repo_root.to_string_lossy().into(),
        tasks_md: repo_root.join("TASKS.md").to_string_lossy().into(),
        messages_jsonl: messages_jsonl_path(repo_root).to_string_lossy().into(),
        started_at: 0,
        last_heartbeat: unix_now(),
        total_messages: 0,
        product_governor: "REMOTE_PUBLICATION_ONLY".into(),
        delivery_router: "REMOTE_PUBLICATION_ONLY".into(),
    })
}

fn read_daemon_state(repo_root: &Path) -> Option<DaemonState> {
    let address = std::env::var("CHINWAG_BUS_ADDR").ok();
    let endpoint = std::env::var("CHINWAG_BUS_ENDPOINT_ID").ok();
    if address.is_some() || endpoint.is_some() {
        return explicit_daemon_route(repo_root, address.as_deref(), endpoint.as_deref()).ok();
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

fn write_daemon_state(repo_root: &Path, state: &DaemonState) -> Result<(), ()> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|_| ())?;
    chinwag_cli::bus_state::write_daemon_state_bytes(repo_root, &bytes).map_err(|_| ())
}

/// A stored row is retained even if authority expired during persistence. It
/// cannot authorize a positive ACK after that loss, nor a rollback or retry.
fn confirm_publication_current(
    result: Result<(u64, usize), ()>,
    current: impl FnOnce() -> bool,
) -> Result<(u64, usize), ()> {
    result.and_then(|stored| if current() { Ok(stored) } else { Err(()) })
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
fn configured_bus_bind_addr(port: u16, relay_only: bool) -> Option<SocketAddr> {
    if relay_only {
        Some(([127, 0, 0, 1], port).into())
    } else if port != 0 {
        Some(([0, 0, 0, 0], port).into())
    } else {
        None
    }
}

async fn bind_bus_endpoint(
    secret: SecretKey,
    port: u16,
    lookup: MemoryLookup,
) -> Result<Endpoint, String> {
    bind_configured_bus_endpoint(secret, port, lookup, None).await
}

async fn bind_configured_bus_endpoint(
    secret: SecretKey,
    port: u16,
    lookup: MemoryLookup,
    network: Option<&(NetworkSelection, DaemonPeerGate)>,
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
    let relay_only = network.is_some_and(|(selection, _)| selection.relay_only());
    if let Some((selection, gate)) = network {
        builder = builder
            .relay_mode(
                selection
                    .policy()
                    .relay_mode()
                    .map_err(|_| "relay policy refused")?,
            )
            .hooks(NativeBusHooks::new(selection.clone(), gate.clone()));
    }
    if let Some(addr) = configured_bus_bind_addr(port, relay_only) {
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

fn valid_publication_ack(daemon: &DaemonState, message: &BusMessage, ack: &BusAck) -> bool {
    use subtle::ConstantTimeEq;
    ack.ok
        && ack.sig_verified
        && ack.seq > 0
        && ack.message_id == message.id
        && ack.room == message.room
        && bool::from(
            ack.daemon_endpoint_id
                .as_bytes()
                .ct_eq(daemon.endpoint_id.as_bytes()),
        )
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
    // Explicit environment routes have already been resolved into this state.
    // Never re-read a global selection during an actual transport attempt.
    let sockets = daemon
        .bound_sockets
        .iter()
        .filter_map(|address| address.parse::<SocketAddr>().ok())
        .collect::<Vec<_>>();
    let mut sock = sockets
        .iter()
        .find(|socket| socket.ip().is_loopback())
        .copied()
        .or_else(|| sockets.first().copied())
        .ok_or("daemon socket unavailable")?;
    if sock.ip().is_unspecified() {
        sock.set_ip(if sock.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    if sock.port() == 0 {
        return Err("daemon socket unavailable".into());
    }

    let lookup = MemoryLookup::new();
    let addr = EndpointAddr::from_parts(daemon_id, [TransportAddr::Ip(sock)]);
    lookup.set_endpoint_info(addr.clone());

    let client = bind_bus_endpoint(actor_secret, 0, lookup).await?;
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let connection = client
            .connect(addr, BUS_ALPN)
            .await
            .map_err(|_| "iroh QUIC connect failed".to_owned())?;
        let result = async {
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|_| "open_bi failed".to_owned())?;
            let payload = serde_json::to_vec(&BusFrame::Publish {
                message: msg.clone(),
            })
            .map_err(|_| "frame serialization failed".to_owned())?;
            if payload.len() > MAX_FRAME_BYTES {
                return Err("frame exceeds bound".to_owned());
            }
            send.write_all(&payload)
                .await
                .map_err(|_| "frame write failed".to_owned())?;
            send.finish()
                .map_err(|_| "frame finish failed".to_owned())?;
            let bytes = recv
                .read_to_end(MAX_FRAME_BYTES)
                .await
                .map_err(|_| "publication ACK unavailable".to_owned())?;
            serde_json::from_slice::<BusAck>(&bytes).map_err(|_| "invalid ACK".to_owned())
        }
        .await;
        connection.close(0u32.into(), b"publication_finished");
        result
    })
    .await
    .map_err(|_| "publication timeout".to_owned())
    .and_then(|result| result);
    client.close().await;
    result
}

fn format_local_wall_clock(ts_iso: &str) -> String {
    if let Some(hms) = ts_iso.get(11..19).filter(|hms| {
        let bytes = hms.as_bytes();
        bytes.iter().enumerate().all(|(i, b)| {
            if i == 2 || i == 5 {
                *b == b':'
            } else {
                b.is_ascii_digit()
            }
        }) && &hms[..2] < "24"
            && &hms[3..5] < "60"
            && &hms[6..8] < "60"
    }) {
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
    let short_ep = if m.sender_endpoint_id.is_ascii() && m.sender_endpoint_id.len() >= 12 {
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

/// Bare Markdown headings and advisory PID files cannot create a scheduler claim.
fn scheduler_admission_required(stderr: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stderr,
        "chinwag bus: {}",
        chinwag_cli::task_scheduler::QUALIFIED_ADMISSION_REQUIRED
    );
    2
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

#[cfg(test)]
struct WorkerRegistration {
    path: PathBuf,
    file: File,
}

#[cfg(test)]
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

#[cfg(test)]
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

/// One serial ingress per daemon. The original persistent sink and the bounded
/// replay cache agree before any local notification or peer queue operation.
struct NativePublication {
    ingress: chinwag_cli::bus_federation::BoundedIngress,
    sink: chinwag_cli::bus_store::NativeJournalSink,
}
struct PublicationEffects<'a> {
    local: &'a broadcast::Sender<BusMessage>,
    peer: Option<&'a tokio::sync::mpsc::Sender<BusMessage>>,
    subscribers: usize,
}
impl chinwag_cli::bus_federation::FederationEffects for PublicationEffects<'_> {
    type Error = &'static str;
    fn on_stored(&mut self, message: &BusMessage) -> Result<(), Self::Error> {
        self.subscribers = self.local.send(message.clone()).unwrap_or(0);
        if let Some(peer) = self.peer {
            peer.try_send(message.clone())
                .map_err(|_| "peer queue unavailable after storage")?;
        }
        Ok(())
    }
}
impl NativePublication {
    fn open(root: &Path) -> Result<Self, String> {
        let root = fs::canonicalize(root).map_err(|_| "bus storage unavailable")?;
        Ok(Self {
            ingress: chinwag_cli::bus_federation::BoundedIngress::new(Default::default()),
            sink: chinwag_cli::bus_store::NativeJournalSink::open(&root)
                .map_err(|_| "bus storage unavailable")?,
        })
    }
    fn publish(
        &mut self,
        message: &BusMessage,
        local: &broadcast::Sender<BusMessage>,
        peer: Option<&tokio::sync::mpsc::Sender<BusMessage>>,
    ) -> Result<(u64, usize), String> {
        use chinwag_cli::bus_federation::IngressOutcome;
        let mut effects = PublicationEffects {
            local,
            peer,
            subscribers: 0,
        };
        let outcome = self
            .ingress
            .ingest(message, &mut self.sink, &mut effects)
            .map_err(|_| "publication unknown or refused".to_owned())?;
        let sequence = match outcome {
            IngressOutcome::Stored { local_sequence }
            | IngressOutcome::ExactReplay { local_sequence } => local_sequence,
        };
        Ok((sequence, effects.subscribers))
    }
}

async fn run_daemon_loop(
    repo_root: PathBuf,
    port: u16,
    network_selection: Option<NetworkSelection>,
    no_governors: bool,
    stdout: &mut dyn Write,
    shutdown: impl std::future::Future<Output = ()>,
) -> u8 {
    tokio::pin!(shutdown);
    let secret = match load_or_create_daemon_secret(&repo_root) {
        Ok(secret) => secret,
        Err(error) => {
            let _ = writeln!(stdout, "chinwag bus daemon: {error}");
            return 1;
        }
    };
    let publications = match NativePublication::open(&repo_root) {
        Ok(publications) => Arc::new(Mutex::new(publications)),
        Err(error) => {
            let _ = writeln!(stdout, "chinwag bus daemon: {error}");
            return 1;
        }
    };
    if network_selection.is_some() {
        let known_weak = fs::canonicalize(&repo_root).ok().and_then(|root| {
            chinwag_cli::bus_identity::is_known_legacy_public_id(&root, &secret.public()).ok()
        });
        if known_weak != Some(false) {
            let _ = writeln!(
                stdout,
                "chinwag bus network HELD: existing identity requires explicit owner disposition"
            );
            return 1;
        }
    }
    let network = match network_selection {
        Some(selection) => match selection.pending_gate(secret.public()) {
            Ok(gate) => Some((selection, gate)),
            Err(error) => {
                let _ = writeln!(stdout, "chinwag bus daemon: {error}");
                return 1;
            }
        },
        None => None,
    };
    let lookup = MemoryLookup::new();
    let endpoint =
        match bind_configured_bus_endpoint(secret.clone(), port, lookup.clone(), network.as_ref())
            .await
        {
            Ok(endpoint) => endpoint,
            Err(_) => {
                let _ = writeln!(stdout, "chinwag bus daemon endpoint bind refused");
                return 1;
            }
        };
    // Home-relay selection is diagnostic only. Explicit peer relay addresses
    // can lazily dial a non-home relay, so no HOME selection may gate them.
    if let Some((selection, _)) = &network
        && let Some(expected_relay) = selection.policy().relay_url()
    {
        let statuses = endpoint.home_relay_status().get();
        let selected = statuses
            .iter()
            .find(|status| status.url() == expected_relay);
        let _ = writeln!(
            stdout,
            "{}",
            json!({
                "event": "native_home_relay_observation",
                "endpoint_id": endpoint.id().to_string(),
                "selected_expected_home_relay": selected.is_some(),
                "home_relay_connected": selected.is_some_and(|status| status.is_connected()),
                "scope": "HOME_SELECTION_DIAGNOSTIC_ONLY_NOT_CONNECTIVITY_OR_DELIVERY"
            })
        );
        let _ = stdout.flush();
    }
    let mut room_session = if let Some((selection, gate)) = &network {
        let identity = match DaemonRoomIdentity::for_endpoint(secret, &endpoint) {
            Ok(identity) => identity,
            Err(_) => {
                endpoint.close().await;
                return 1;
            }
        };
        let client = match selection.client() {
            Ok(client) => client,
            Err(_) => {
                endpoint.close().await;
                return 1;
            }
        };
        let addresses = if selection.relay_only() {
            Vec::new()
        } else {
            endpoint
                .bound_sockets()
                .into_iter()
                .filter(|socket| !socket.ip().is_unspecified() && !socket.ip().is_loopback())
                .collect()
        };
        match client
            .open_daemon(&identity, &endpoint, gate.clone(), addresses, lookup)
            .await
        {
            Ok(mut session) => {
                if session.receive_daemon_peer().await.is_err()
                    || selection.current_address(gate).is_err()
                {
                    session.close().await;
                    endpoint.close().await;
                    let _ = writeln!(
                        stdout,
                        "chinwag bus network HELD: current verified peer unavailable"
                    );
                    return 1;
                }
                Some(session)
            }
            Err(error) => {
                endpoint.close().await;
                let _ = writeln!(
                    stdout,
                    "chinwag bus network HELD: compatible coordinator unavailable ({error})"
                );
                return 1;
            }
        }
    } else {
        None
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
    for ip in if network
        .as_ref()
        .is_some_and(|(selection, _)| selection.relay_only())
    {
        Vec::new()
    } else {
        discover_non_loopback_ipv4()
    } {
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
        product_governor: if no_governors {
            "DISABLED_CONTROLLED_INSTANCE"
        } else {
            "RECONCILIATION_ONLY"
        }
        .to_string(),
        delivery_router: chinwag_cli::task_scheduler::QUALIFIED_ADMISSION_REQUIRED.to_owned(),
    }));
    let initial_state = state
        .lock()
        .map_err(|_| ())
        .and_then(|guard| write_daemon_state(&repo_root, &guard));
    if initial_state.is_err() {
        if let Some(session) = &mut room_session {
            session.close().await;
        }
        endpoint.close().await;
        let _ = writeln!(
            stdout,
            "chinwag bus HELD: diagnostic state unsafe or persistence unknown"
        );
        return 1;
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

    let (tx, unused_receiver) = broadcast::channel::<BusMessage>(256);
    // No consumer has subscribed through this daemon path. Keeping an unread
    // internal receiver would inflate subscribers_notified without delivery.
    drop(unused_receiver);
    let (forward_tx, mut forward_rx) = tokio::sync::mpsc::channel::<BusMessage>(128);
    let incoming_slots = Arc::new(tokio::sync::Semaphore::new(32));
    let mut handlers = tokio::task::JoinSet::new();
    let mut forwards = tokio::task::JoinSet::new();
    let (state_error_tx, mut state_error_rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut exit_code = 0;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
    let mut governor_tick = tokio::time::interval(Duration::from_secs(45));
    governor_tick.tick().await;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            Some(()) = state_error_rx.recv() => {
                let _ = writeln!(stdout, "chinwag bus HELD: diagnostic state update failed");
                exit_code = 1;
                break;
            }
            original = forward_rx.recv(), if network.is_some() && forwards.is_empty() => {
                if let (Some(message), Some((selection, gate))) = (original, &network) {
                    let endpoint = endpoint.clone(); let selection = selection.clone(); let gate = gate.clone();
                    forwards.spawn(async move {
                        let result = forward_original(&endpoint, &selection, &gate, &message).await;
                        (message.id, message.digest_sha256, result)
                    });
                }
            }
            finished = forwards.join_next(), if !forwards.is_empty() => {
                if let Some(Ok((id, digest, result))) = finished {
                    let record = match result {
                        Ok(path) => json!({"event":"native_federation_ack", "original_id":id,
                            "original_digest_sha256":digest, "scope":"REMOTE_JOURNAL_PUBLICATION_ONLY",
                            "path":path, "processing":"UNKNOWN", "work_started":"UNKNOWN"}),
                        Err(failure) => json!({"event":"native_federation_unknown", "original_id":id,
                            "original_digest_sha256":digest, "phase":failure.category(), "automatic_retry":false}),
                    };
                    let _ = writeln!(stdout, "{record}"); let _ = stdout.flush();
                }
            }
            update = async {
                match &mut room_session {
                    Some(session) => session.receive_daemon_peer().await,
                    None => std::future::pending().await,
                }
            } => {
                if update.is_err() {
                    let _ = writeln!(stdout, "chinwag bus network HELD: original room session ended");
                    break;
                }
            }
            _ = heartbeat.tick() => {
                let count = read_all_messages(&repo_root).len() as u64;
                let update = state.lock().map_err(|_| ()).and_then(|mut guard| {
                    guard.last_heartbeat = unix_now();
                    guard.total_messages = count;
                    write_daemon_state(&repo_root, &guard)
                });
                if update.is_err() {
                    let _ = writeln!(stdout, "chinwag bus HELD: diagnostic state update failed");
                    exit_code = 1;
                    break;
                }
            }
            _ = governor_tick.tick(), if !no_governors => {
                // Reconciliation is a trigger, not authority to create a new task invocation.
                // This legacy bus has no verified qualified-assignment/lease adapter.
                let update = state.lock().map_err(|_| ()).and_then(|mut guard| {
                    guard.product_governor = format!("RECONCILIATION_ONLY ({})", chinwag_cli::task_scheduler::QUALIFIED_ADMISSION_REQUIRED);
                    guard.delivery_router = chinwag_cli::task_scheduler::QUALIFIED_ADMISSION_REQUIRED.to_owned();
                    write_daemon_state(&repo_root, &guard)
                });
                if update.is_err() {
                    let _ = writeln!(stdout, "chinwag bus HELD: diagnostic state update failed");
                    exit_code = 1;
                    break;
                }
            }
            _ = handlers.join_next(), if !handlers.is_empty() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                let Ok(slot) = incoming_slots.clone().try_acquire_owned() else { drop(incoming); continue; };
                let network = network.clone();
                let peer_queue = forward_tx.clone();
                let repo_clone = repo_root.clone();
                let state_clone = state.clone();
                let tx_clone = tx.clone();
                let publications = publications.clone();
                let daemon_ep = endpoint_id.clone();
                let state_error = state_error_tx.clone();
                handlers.spawn(async move {
                    let _slot = slot;
                    let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), incoming).await else {
                        return;
                    };
                    let owned_connection = OwnedBusConnection(conn);
                    let conn = &owned_connection.0;
                    let Ok(Ok((mut send, mut recv))) = tokio::time::timeout(Duration::from_secs(5), conn.accept_bi()).await else {
                        return;
                    };
                    let Ok(Ok(bytes)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        recv.read_to_end(MAX_FRAME_BYTES),
                    ).await else {
                        return;
                    };
                    if conn.alpn() != BUS_ALPN { conn.close(0x403u32.into(), b"wrong_bus_alpn"); return; }
                    let (mut message, federated) = match serde_json::from_slice::<BusFrame>(&bytes) {
                        Ok(BusFrame::Publish { message }) => (message, false),
                        Ok(BusFrame::Federate { message }) => (message, true),
                        _ => { conn.close(0x403u32.into(), b"bus_frame_refused"); return; }
                    };
                    let path = if federated {
                        match &network {
                            Some((selection, gate)) => selection.remote_path(conn, gate).ok(),
                            None => None,
                        }
                    } else { None };
                    let admitted = if federated { path.is_some() } else { network.is_none() || local_publisher_path(conn) };
                    let signature = if federated { valid_federation_original(&repo_clone, &mut message) }
                        else { verify_detached_bus_signature(&repo_clone, &mut message) };
                    let result = if admitted && signature {
                        // Revalidate AFTER the potentially blocking ingress
                        // lock, at this frame admission boundary. A remote
                        // original is never reflected to its originating peer.
                        let peer = if !federated && network.is_some() { Some(&peer_queue) } else { None };
                        publications.lock().map_err(|_| ())
                            .and_then(|mut ingress| {
                                let current = if federated {
                                    network.as_ref().is_some_and(|(selection, gate)| selection.remote_path(conn, gate).is_ok())
                                } else { network.is_none() || local_publisher_path(conn) };
                                if !current { return Err(()); }
                                ingress.publish(&message, &tx_clone, peer).map_err(|_| ())
                            })
                    } else { Err(()) };
                    let result = result.and_then(|(seq, subscribers)| {
                            let update = state_clone.lock().map_err(|_| ()).and_then(|mut guard| {
                                guard.last_heartbeat = unix_now(); guard.total_messages = seq;
                                write_daemon_state(&repo_clone, &guard)
                            });
                            if update.is_err() { let _ = state_error.try_send(()); return Err(()); }
                            if let Some(path) = &path {
                                eprintln!("{}", json!({"event":"native_original_journaled", "original_id":message.id,
                                    "original_digest_sha256":message.digest_sha256, "path":path,
                                    "scope":"JOURNAL_PUBLICATION_ONLY", "processing":"UNKNOWN", "work_started":"UNKNOWN"}));
                            }
                            Ok((seq, subscribers))
                    });
                    // This is after ALL synchronous persistence/state writes,
                    // immediately before constructing the positive ACK.
                    let result = confirm_publication_current(result, || !federated ||
                        network.as_ref().is_some_and(|(selection, gate)| selection.remote_path(conn, gate).is_ok()));
                    let ack = match result {
                        Ok((seq, subscribers)) => BusAck { ok:true, seq, message_id:message.id.clone(), daemon_endpoint_id:daemon_ep,
                                transport:"iroh-quic/chinwag-bus-1".into(), room:message.room.clone(),
                                subscribers_notified:subscribers, sig_verified:signature },
                        Err(()) => BusAck { ok:false, seq:0, message_id:message.id.clone(), daemon_endpoint_id:daemon_ep,
                            transport:"iroh-quic/chinwag-bus-1 (refused or persistence unknown)".into(),
                            room:message.room.clone(), subscribers_notified:0, sig_verified:signature },
                    };
                    let encoded = if federated { serde_json::to_vec(&FederationAck { publication:ack, original_digest_sha256:message.digest_sha256 }) }
                        else { serde_json::to_vec(&ack) };
                    if let Ok(bytes) = encoded {
                        let _ = tokio::time::timeout(Duration::from_secs(2), async {
                            send.write_all(&bytes).await.map_err(|_| ())?;
                            send.finish().map_err(|_| ())?;
                            send.stopped().await.map_err(|_| ())
                        }).await;
                    }

                });
            }
        }
    }

    if let Some(session) = &mut room_session {
        session.close().await;
    }
    endpoint.close().await;
    // These are this daemon's own handlers, never a foreign review/worker.
    // Abort at their await points and await every original task handle.
    handlers.shutdown().await;
    forwards.shutdown().await;
    exit_code
}

/// Fallback is possible only when no selected-daemon exchange was attempted.
/// Every attempted exchange returns here, including missing/lost/invalid ACKs.
fn complete_publication(
    mut message: BusMessage,
    daemon: Option<&DaemonState>,
    explicit_route: bool,
    exchange: impl FnOnce(&DaemonState, &BusMessage) -> Result<BusAck, String>,
    local: impl FnOnce(&mut BusMessage) -> Result<BusAck, InstanceError>,
) -> Result<(BusMessage, BusAck), InstanceError> {
    let ack = if let Some(daemon) = daemon {
        let ack = exchange(daemon, &message).map_err(|_| {
            eprintln!(
                "{}",
                json!({"event":"bus_publication_outcome_unknown",
                "original_id":message.id, "original_digest_sha256":message.digest_sha256,
                "automatic_retry":false, "reconciliation_required":true})
            );
            InstanceError::PublicationRejected
        })?;
        if !valid_publication_ack(daemon, &message, &ack) {
            return Err(InstanceError::PublicationRejected);
        }
        ack
    } else {
        if explicit_route {
            return Err(InstanceError::PublicationRejected);
        }
        local(&mut message)?
    };
    message.seq = ack.seq;
    message.sig_verified = ack.sig_verified;
    Ok((message, ack))
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

    let daemon = read_daemon_state(repo_root);
    let explicit_route = std::env::var_os("CHINWAG_BUS_ADDR").is_some()
        || std::env::var_os("CHINWAG_BUS_ENDPOINT_ID").is_some();
    complete_publication(
        msg,
        daemon.as_ref(),
        explicit_route,
        |daemon, msg| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "local transport runtime unavailable".to_owned())?;
            rt.block_on(publish_over_iroh_quic(daemon, transport_secret, msg))
        },
        |msg| {
            let fallback_daemon_endpoint_id = load_or_create_daemon_secret(repo_root)
                .map_err(|_| InstanceError::SigningIdentityUnavailable)?
                .public()
                .to_string();
            let seq = persist_local_publication(repo_root, msg)
                .map_err(|_| InstanceError::PublicationRejected)?;
            let ack = BusAck {
                ok: true,
                seq,
                message_id: msg_id,
                daemon_endpoint_id: fallback_daemon_endpoint_id,
                transport: "local-jsonl (daemon unavailable; publish only)".to_string(),
                room: room_norm,
                subscribers_notified: 0,
                sig_verified: msg.sig_verified,
            };
            Ok(ack)
        },
    )
}

fn print_bus_help(stdout: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stdout,
        r#"Usage:
  chinwag bus instance
  chinwag bus status [--json]
  chinwag bus daemon [--port <44330>] [--repo <path>] [--no-governors]
  chinwag bus daemon --network-room-origin <HTTPS> --network-coordinator <PUBLIC-ID> --network-peer <PUBLIC-ID>
    --relay-origin <HTTPS> --expected-relay-origin <HTTPS> --network-configuration <ID> --network-generation <U64> [--relay-only]
  chinwag bus send --from <SEAT#INSTANCE> [--room <ROOM>] [--to <ADDRESS,...>] [--task <TASK-ID>] [--json] --message <BODY>
  chinwag bus send --from <SEAT> --instance <INSTANCE> [options] --message <BODY>
  chinwag bus inbox --for <SEAT#INSTANCE|SEAT> [--limit <N>] [--json]
  chinwag bus tail [--room <ROOM>] [--task <TASK-ID>] [--limit <N>] [-f] [--json]
  chinwag bus worker --seat <SEAT> --from <CALLER#INSTANCE> --task <TASK-ID> --message <BODY>
  chinwag bus wake [--seat <SEAT|ALL>]

Agent sends require a stable conversation instance via --from, --instance or inherited conversation context.
Use 'bus instance' once to allocate a full random ID, then reuse it for that conversation.
A base-seat recipient is an explicit seat broadcast; a base-seat inbox aggregates that seat's instances.
Engineering worker/wake/route dispatch requires a qualified shared-scheduler claim; this legacy CLI returns HELD before publication.
Use one --to with a comma-separated list. Repeated --to/-t flags fail before publication.
A legacy ACK acknowledges publication only: completion_scope=PUBLISH_ONLY, durability UNKNOWN.
subscribers_notified counts broadcast receivers; it proves neither processing nor task start.
Existing-conversation scheduling has no supported adapter in this binary and reports UNSUPPORTED.
"#
    );
    0
}

/// Cooperative admitted-worker seam. Legacy prose/wake commands cannot supply
/// these sealed capabilities. A future host adapter still needs its own proof.
#[allow(dead_code)]
pub(crate) trait BoundBusExecutor {
    fn invoke(
        &mut self,
        binding: &chinwag_cli::execution_binding::WorkspaceExecutionBinding,
        admission: &chinwag_cli::task_writer::ExecutionAdmissionV1,
        writer: &mut chinwag_cli::task_resource_lease::ProtectedWriter<'_>,
    ) -> chinwag_cli::task_scheduler::InvocationOutcome;
}

#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn invoke_admitted_bus_task(
    scheduler: &mut chinwag_cli::task_scheduler::WorkspaceScheduler,
    claim: chinwag_cli::task_scheduler::ClaimedAssignment,
    scheduler_authority: &chinwag_cli::task_scheduler::CurrentAuthority<'_>,
    leases: &mut chinwag_cli::task_resource_lease::ResourceLeaseStore,
    capability: chinwag_cli::task_resource_lease::CommittedWriteLease,
    lease_authority: &chinwag_cli::task_resource_lease::CurrentLeaseAuthority<'_>,
    binding: &chinwag_cli::execution_binding::WorkspaceExecutionBinding,
    execution_authority: &chinwag_cli::execution_binding::ExecutionAuthority<'_>,
    executor: &mut impl BoundBusExecutor,
) -> Result<chinwag_cli::task_scheduler::AdmissionStatus, chinwag_cli::task_scheduler::SchedulerError>
{
    struct Bound<'a, E> {
        binding: &'a chinwag_cli::execution_binding::WorkspaceExecutionBinding,
        executor: &'a mut E,
    }
    impl<E: BoundBusExecutor> chinwag_cli::task_resource_lease::LeasedExecutor for Bound<'_, E> {
        fn invoke(
            &mut self,
            admission: &chinwag_cli::task_writer::ExecutionAdmissionV1,
            writer: &mut chinwag_cli::task_resource_lease::ProtectedWriter<'_>,
        ) -> chinwag_cli::task_scheduler::InvocationOutcome {
            self.executor.invoke(self.binding, admission, writer)
        }
    }
    scheduler.invoke_with_bound_lease(
        claim,
        scheduler_authority,
        leases,
        capability,
        lease_authority,
        binding,
        execution_authority,
        &mut Bound { binding, executor },
    )
}

pub fn run_bus_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    if sub == "--help" || sub == "-h" || sub == "help" {
        return print_bus_help(stdout);
    }

    let mut network_args = std::collections::BTreeMap::<String, String>::new();
    let mut relay_only = false;
    let mut no_governors = false;
    let mut repo_arg: Option<String> = None;
    let mut from_arg: Option<String> = None;
    let mut instance_arg: Option<String> = None;
    let mut room_arg: Option<String> = None;
    let mut to_arg: Option<String> = None;
    let mut task_arg: Option<String> = None;
    let mut for_arg: Option<String> = None;
    let mut _seat_arg: Option<String> = None;
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
            "--network-room-origin"
            | "--network-coordinator"
            | "--network-peer"
            | "--relay-origin"
            | "--expected-relay-origin"
            | "--network-configuration"
            | "--network-generation" => {
                let Some(value) = args.get(i + 1).filter(|value| !value.starts_with("--")) else {
                    let _ = writeln!(stderr, "chinwag bus: incomplete_network_selection");
                    return 2;
                };
                if network_args.insert(a.to_owned(), value.clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag bus: duplicate_network_selection");
                    return 2;
                }
                i += 2;
            }
            "--relay-only" => {
                if relay_only {
                    let _ = writeln!(stderr, "chinwag bus: duplicate_network_selection");
                    return 2;
                }
                relay_only = true;
                i += 1;
            }
            "--no-governors" => {
                if no_governors {
                    let _ = writeln!(stderr, "chinwag bus: duplicate_network_selection");
                    return 2;
                }
                no_governors = true;
                i += 1;
            }
            "--repo" => {
                let Some(value) = args.get(i + 1) else {
                    let _ = writeln!(stderr, "chinwag bus: missing_repository_selector");
                    return 2;
                };
                if repo_arg.replace(value.clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag bus: duplicate_repository_selector");
                    return 2;
                }
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
                    let _ = writeln!(
                        stderr,
                        "chinwag bus: duplicate_recipient_flag; use one --to with a comma-separated recipient list"
                    );
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
                _seat_arg = Some(args[i + 1].clone());
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

    let network_selection = if network_args.is_empty() && !relay_only {
        None
    } else {
        if sub != "daemon" || network_args.len() != 7 {
            let _ = writeln!(stderr, "chinwag bus: incomplete_network_selection");
            return 2;
        }
        let get = |key: &str| network_args.get(key).map(String::as_str).unwrap_or("");
        let Ok(generation) = get("--network-generation").parse() else {
            let _ = writeln!(stderr, "chinwag bus: invalid_network_generation");
            return 2;
        };
        match NetworkSelection::try_new(
            get("--network-room-origin").into(),
            get("--network-coordinator"),
            get("--network-peer"),
            get("--relay-origin"),
            get("--expected-relay-origin"),
            get("--network-configuration").into(),
            generation,
            relay_only,
        ) {
            Ok(selection) => Some(selection),
            Err(_) => {
                let _ = writeln!(stderr, "chinwag bus: network_selection_refused");
                return 2;
            }
        }
    };
    if no_governors && sub != "daemon" {
        let _ = writeln!(stderr, "chinwag bus: invalid_arguments");
        return 2;
    }
    // Identity allocation is independent of repository/task authority.
    if matches!(sub, "instance" | "new-instance") {
        return match agent_instance::new_instance_id() {
            Ok(instance) => {
                let _ = writeln!(stdout, "{instance}");
                0
            }
            Err(error) => {
                let _ = writeln!(stderr, "chinwag bus: {error}");
                2
            }
        };
    }
    // No legacy command can manufacture a current scheduler/binding/lease.
    // Refuse the combined task effect before ordinary publication as well.
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
    if matches!(sub, "worker" | "wake" | "route") || wake_on_send {
        return scheduler_admission_required(stderr);
    }
    let selected = match resolve_repo_root(repo_arg.as_deref()) {
        Ok(selected) => selected,
        Err(error) => {
            let _ = writeln!(stderr, "chinwag bus: repository selection refused: {error}");
            return 2;
        }
    };
    if let Err(error) = selected.revalidate() {
        let _ = writeln!(stderr, "chinwag bus: repository selection refused: {error}");
        return 2;
    }
    let repo_root = selected.execution_root().to_path_buf();

    match sub {
        "worker" => scheduler_admission_required(stderr),
        "daemon" => {
            let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            else {
                let _ = writeln!(stderr, "chinwag bus: failed to initialize tokio runtime");
                return 1;
            };
            rt.block_on(run_daemon_loop(
                repo_root,
                port_arg,
                network_selection,
                no_governors,
                stdout,
                async {
                    let _ = tokio::signal::ctrl_c().await;
                },
            ))
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
        "wake" | "route" => scheduler_admission_required(stderr),
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
                    "PROCESS_OBSERVED"
                } else if seat == "PRODUCT" {
                    "RECONCILIATION_ONLY"
                } else if seat == "DELIVERY" {
                    "ADMISSION_HELD"
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
                let fallback_ep = match load_or_create_daemon_secret(&repo_root) {
                    Ok(secret) => secret.public().to_string(),
                    Err(error) => {
                        let _ = writeln!(stdout, "chinwag bus status: {error}");
                        return 1;
                    }
                };
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
            id: "receipt:1".into(),
            seq: 1,
            ts_unix: 123,
            ts_iso: String::new(),
            sender: "QA#ExactCase".into(),
            sender_cast: String::new(),
            sender_endpoint_id: secret.public().to_string(),
            to: Some("WORKHORSE#owner".into()),
            room: "#é".into(),
            task_id: Some("C1".into()),
            body: "🙂|receipt".into(),
            digest_sha256: "ab".repeat(32),
            pubkey_ed25519: None,
            signature_ed25519: None,
            sig_verified: false,
        };
        sign_bus_message(&mut msg, &secret);
        let view = chinwag_cli::bus_delivery::ProcessingEnvelope {
            id: msg.id.clone(),
            timestamp: msg.ts_unix,
            sender: msg.sender.clone(),
            recipient: msg.to.clone().unwrap(),
            room: msg.room.clone(),
            task: msg.task_id.clone(),
            body: msg.body.clone(),
            signature: hex_to_64_bytes(msg.signature_ed25519.as_ref().unwrap()).unwrap(),
        };
        assert_eq!(view.signing_payload(), canonical_signing_payload(&msg));
        secret
            .public()
            .verify(
                view.signing_payload().as_bytes(),
                &Signature::from_bytes(&view.signature),
            )
            .unwrap();
        let bytes = serde_json::to_vec(&msg).unwrap();
        let decoded: BusMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical_signing_payload(&decoded), view.signing_payload());
        let ack = BusAck {
            ok: true,
            seq: 1,
            message_id: msg.id,
            daemon_endpoint_id: String::new(),
            transport: "controlled".into(),
            room: msg.room,
            subscribers_notified: 1,
            sig_verified: true,
        };
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
            "send",
            "--repo",
            repo.path().to_str().unwrap(),
            "--to",
            "GEMINI-PM#one",
            "-t",
            "DELIVERY#two",
            "--message",
            "must not publish",
        ]
        .map(str::to_owned);
        assert_eq!(run_bus_cli(&args, &mut out, &mut err), 2);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("duplicate_recipient_flag")
        );
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
    fn unsigned_unicode_display_metadata_persists_and_renders_without_panicking() {
        for timestamp in [
            "éééééééééé",
            "0123456789🙂12:34:56Z",
            "🙂",
            "2026-10-29T99:88:77Z",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let mut original = native_publication_fixture(&root);
            original.ts_iso = timestamp.into();
            assert!(valid_federation_original(&root, &mut original));
            assert_eq!(persist_local_publication(&root, &original).unwrap(), 1);
            let stored = read_all_messages(&root);
            assert_eq!(stored.len(), 1);
            assert_eq!(format_local_wall_clock(timestamp), timestamp);
            assert!(format_bus_line(&stored[0]).contains(timestamp));
        }
        // Legacy local endpoint labels are display data too. Never slice a
        // UTF-8 label by unchecked byte offsets, even when it is long enough.
        let temp = tempfile::tempdir().unwrap();
        let mut original = native_publication_fixture(temp.path());
        original.sender_endpoint_id = "🙂🙂🙂🙂".into();
        assert!(format_bus_line(&original).contains("🙂🙂🙂🙂"));
    }

    #[test]
    fn attempted_uncertain_daemon_publication_never_reopens_local_sink() {
        use std::cell::Cell;
        for already_written in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let original = native_publication_fixture(&root);
            let daemon = explicit_daemon_route(
                &root,
                Some("127.0.0.1:44330"),
                Some(&SecretKey::generate().public().to_string()),
            )
            .unwrap();
            // A complete row plus a missing response models both a lost ACK
            // and complete-but-unconfirmed storage. This cut does not claim
            // an actual OS fsync fault or network packet loss was injected.
            if already_written {
                persist_local_publication(&root, &original).unwrap();
            }
            let before = fs::read(messages_jsonl_path(&root)).ok();
            let signed_before = serde_json::to_vec(&original).unwrap();
            let fallback_called = Cell::new(false);
            let result = complete_publication(
                original.clone(),
                Some(&daemon),
                false,
                |_, message| {
                    assert_eq!(serde_json::to_vec(message).unwrap(), signed_before);
                    Err("controlled missing response after attempt".into())
                },
                |message| {
                    fallback_called.set(true);
                    persist_local_publication(&root, message).unwrap();
                    Err(InstanceError::PublicationRejected)
                },
            );
            assert!(matches!(result, Err(InstanceError::PublicationRejected)));
            assert!(!fallback_called.get());
            assert_eq!(fs::read(messages_jsonl_path(&root)).ok(), before);
            assert_eq!(serde_json::to_vec(&original).unwrap(), signed_before);
        }
    }

    #[test]
    fn unattempted_local_publication_remains_available_but_explicit_missing_route_refuses() {
        use std::cell::Cell;
        for explicit in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let original = native_publication_fixture(temp.path());
            let local_called = Cell::new(false);
            let result = complete_publication(
                original,
                None,
                explicit,
                |_, _| panic!("no selected daemon may be contacted"),
                |message| {
                    local_called.set(true);
                    let seq = persist_local_publication(temp.path(), message).unwrap();
                    Ok(BusAck {
                        ok: true,
                        seq,
                        message_id: message.id.clone(),
                        daemon_endpoint_id: "fixture".into(),
                        transport: "local publication".into(),
                        room: message.room.clone(),
                        subscribers_notified: 0,
                        sig_verified: true,
                    })
                },
            );
            assert_eq!(result.is_ok(), !explicit);
            assert_eq!(local_called.get(), !explicit);
            assert_eq!(read_all_messages(temp.path()).len(), usize::from(!explicit));
        }
    }

    #[test]
    fn gate_lost_after_storage_refuses_positive_ack_retains_row_and_never_repeats_effects() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let original = native_publication_fixture(&root);
        let mut ingress = NativePublication::open(&root).unwrap();
        let (tx, mut rx) = broadcast::channel(8);
        let stored = ingress.publish(&original, &tx, None).map_err(|_| ());
        assert_eq!(stored, Ok((1, 1)));
        let before = fs::read(messages_jsonl_path(&root)).unwrap();
        // Production invokes remote_path here, after persistence and state
        // updates. This controlled cut models revocation/deadline crossing.
        assert_eq!(confirm_publication_current(stored, || false), Err(()));
        assert_eq!(rx.try_recv().unwrap().id, original.id);
        assert!(rx.try_recv().is_err());
        let replay = ingress.publish(&original, &tx, None).map_err(|_| ());
        assert_eq!(confirm_publication_current(replay, || false), Err(()));
        assert_eq!(fs::read(messages_jsonl_path(&root)).unwrap(), before);
        assert!(rx.try_recv().is_err());
        assert_eq!(confirm_publication_current(Ok((1, 0)), || true), Ok((1, 0)));
        assert_eq!(
            confirm_publication_current(Err(()), || panic!("failed storage cannot become success")),
            Err(())
        );
    }

    pub(super) fn native_publication_fixture(root: &Path) -> BusMessage {
        let secret = fixture_key(&root.join("fixture-signing"), "RUST");
        fs::create_dir_all(root.join(".chinwag")).unwrap();
        let public = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey(
            *secret.public().as_bytes(),
        ));
        fs::write(
            root.join(".chinwag/allowed_signers"),
            format!(
                "rust@chinwag.sh namespaces=\"git\" {} chinwag RUST\n",
                public.to_openssh().unwrap()
            ),
        )
        .unwrap();
        let mut message = BusMessage {
            id: "bus-network-controlled-original".into(),
            seq: 0,
            ts_unix: 1793250000,
            ts_iso: "controlled-time".into(),
            room: "#eng".into(),
            sender: "RUST#fixture".into(),
            sender_cast: "■".into(),
            sender_endpoint_id: secret.public().to_string(),
            to: Some("QA#fixture".into()),
            task_id: Some("NATIVE-CONTROLLED".into()),
            body: "controlled publication".into(),
            digest_sha256: String::new(),
            pubkey_ed25519: None,
            signature_ed25519: None,
            sig_verified: false,
        };
        message.digest_sha256 = compute_message_digest(
            message.ts_unix,
            &message.room,
            &message.sender,
            &message.sender_endpoint_id,
            message.to.as_deref(),
            message.task_id.as_deref(),
            &message.body,
        );
        sign_bus_message(&mut message, &secret);
        message
    }

    #[test]
    fn native_ingress_broadcasts_once_reopens_and_rejects_conflicting_original() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let message = native_publication_fixture(&root);
        let (tx, mut rx) = broadcast::channel(8);
        let mut ingress = NativePublication::open(&root).unwrap();
        assert_eq!(ingress.publish(&message, &tx, None).unwrap(), (1, 1));
        assert_eq!(rx.try_recv().unwrap().id, message.id);
        assert_eq!(ingress.publish(&message, &tx, None).unwrap(), (1, 0));
        assert!(rx.try_recv().is_err());
        drop(ingress);
        let mut reopened = NativePublication::open(&root).unwrap();
        assert_eq!(reopened.publish(&message, &tx, None).unwrap(), (1, 0));
        assert!(rx.try_recv().is_err());
        let mut conflict = message.clone();
        conflict.body.push_str("conflict");
        assert!(reopened.publish(&conflict, &tx, None).is_err());
        assert!(rx.try_recv().is_err());
        assert_eq!(read_all_messages(&root).len(), 1);
        assert!(!root.join(".chinwag/bus/bus.sqlite").exists());
    }

    #[test]
    fn native_ingress_storage_failure_cannot_broadcast_or_enqueue() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let message = native_publication_fixture(&root);
        let mut ingress = NativePublication::open(&root).unwrap();
        fs::write(root.join(".chinwag/bus/messages.jsonl"), b"incomplete").unwrap();
        fs::set_permissions(
            root.join(".chinwag/bus/messages.jsonl"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let (tx, mut rx) = broadcast::channel(8);
        let (peer, mut queued) = tokio::sync::mpsc::channel(8);
        assert!(ingress.publish(&message, &tx, Some(&peer)).is_err());
        assert!(rx.try_recv().is_err());
        assert!(queued.try_recv().is_err());
        assert_eq!(
            fs::read(root.join(".chinwag/bus/messages.jsonl")).unwrap(),
            b"incomplete"
        );
    }

    #[test]
    fn explicit_remote_route_requires_both_actual_pins_without_local_identity_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint = SecretKey::generate().public().to_string();
        for (address, id) in [
            (Some("127.0.0.1:44330"), None),
            (None, Some(endpoint.as_str())),
            (Some(""), Some(endpoint.as_str())),
            (Some("0.0.0.0:44330"), Some(endpoint.as_str())),
            (Some("127.0.0.1:0"), Some(endpoint.as_str())),
            (Some("127.0.0.1:44330"), Some("invalid")),
        ] {
            assert!(explicit_daemon_route(temp.path(), address, id).is_err());
        }
        let daemon =
            explicit_daemon_route(temp.path(), Some("127.0.0.1:44330"), Some(&endpoint)).unwrap();
        assert_eq!(daemon.endpoint_id, endpoint);
        assert!(!temp.path().join(".chinwag").exists());
        let mut message = native_publication_fixture(temp.path());
        message.seq = 2;
        let mut ack = BusAck {
            ok: true,
            seq: 2,
            message_id: message.id.clone(),
            daemon_endpoint_id: endpoint.clone(),
            transport: "iroh-quic/chinwag-bus-1".into(),
            room: message.room.clone(),
            subscribers_notified: 0,
            sig_verified: true,
        };
        assert!(valid_publication_ack(&daemon, &message, &ack));
        ack.seq = 0;
        assert!(!valid_publication_ack(&daemon, &message, &ack));
        ack.seq = 2;
        ack.daemon_endpoint_id = "different".into();
        assert!(!valid_publication_ack(&daemon, &message, &ack));
        ack.daemon_endpoint_id = endpoint;
        ack.room = "#other".into();
        assert!(!valid_publication_ack(&daemon, &message, &ack));
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
            assert_eq!(persist_local_publication(temp.path(), &msg).unwrap(), 1);
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

        // Ordinary CLI reads still require an actual repository selection.
        assert!(
            Command::new("/usr/bin/git")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args(["init", "--quiet", "--template="])
                .arg(temp.path())
                .status()
                .unwrap()
                .success()
        );
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
        // History path selection is read-only; fixture preparation owns the
        // directory creation rather than relying on an implicit query write.
        fs::create_dir_all(path.parent().unwrap()).unwrap();
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
                        fs::canonicalize(temp.path())
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                        "--for".into(),
                        query.into(),
                        "--json".into()
                    ],
                    &mut out,
                    &mut err
                ),
                0,
                "{}",
                String::from_utf8_lossy(&err)
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
    fn p007_unqualified_engineering_routes_refuse_without_publication_or_spawn() {
        let cases = [
            vec![
                "worker",
                "--seat",
                "RUST#child",
                "--from",
                "WORKHORSE#parent",
                "--task",
                "P0-07",
                "--message",
                "work",
            ],
            vec!["worker", "--seat", "RUST"],
            vec!["wake", "--seat", "RUST"],
            vec!["route", "ALL"],
            vec![
                "send",
                "--from",
                "WORKHORSE#parent",
                "--to",
                "RUST",
                "--wake",
                "--message",
                "work",
            ],
            vec![
                "send",
                "--from",
                "WORKHORSE#parent",
                "--to",
                "RUST",
                "--dispatch",
                "--task",
                "{\"workspace_id\":\"untrusted\"}",
                "--message",
                "work",
            ],
        ];
        for case in cases {
            let repo = tempfile::tempdir().unwrap();
            fs::write(
                repo.path().join("TASKS.md"),
                "### `TASK-01` `[READY]`\n- **Owner:** RUST\n- **Scope:** arbitrary work\n",
            )
            .unwrap();
            let mut args: Vec<String> = case.into_iter().map(str::to_owned).collect();
            args.extend(["--repo".into(), repo.path().to_string_lossy().into_owned()]);
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(run_bus_cli(&args, &mut out, &mut err), 2);
            assert!(out.is_empty());
            assert!(
                String::from_utf8(err)
                    .unwrap()
                    .contains(chinwag_cli::task_scheduler::QUALIFIED_ADMISSION_REQUIRED)
            );
            assert!(!repo.path().join(".chinwag").exists());
        }
    }

    #[test]
    fn p007_existing_instance_wake_error_precedes_scheduler_admission() {
        let repo = tempfile::tempdir().unwrap();
        let args: Vec<String> = [
            "send",
            "--from",
            "WORKHORSE#parent",
            "--to",
            "QA#existing",
            "--wake",
            "--message",
            "work",
            "--repo",
            repo.path().to_str().unwrap(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(run_bus_cli(&args, &mut out, &mut err), 2);
        assert!(out.is_empty());
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("existing_instance_wake_unsupported")
        );
        assert!(!repo.path().join(".chinwag").exists());
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

#[cfg(test)]
#[path = "bus_network_tests.rs"]
mod network_tests;
