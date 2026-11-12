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
use chinwag_cli::bus_observation::{
    FederationObservation, ReceiptCache, RemotePublication, valid_receipt_query,
};
use chinwag_swarm::room::{RoomClient, RoomSession};
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    Publish {
        message: BusMessage,
    },
    Federate {
        message: BusMessage,
    },
    FederationReceipt {
        original_id: String,
        original_digest_sha256: String,
    },
    NetworkPosture,
    JournalSubscribe {
        subscription_id: String,
        timeout_secs: u64,
    },
    JournalUnsubscribe {
        subscription_id: String,
    },
    JournalChanged {
        observed_len: u64,
        observed_inode: u64,
        timeout_secs: u64,
        #[serde(default)]
        subscription_id: Option<String>,
    },
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
fn valid_remote_publication_ack(
    peer: EndpointId,
    message: &BusMessage,
    ack: &FederationAck,
) -> bool {
    use subtle::ConstantTimeEq;
    let publication = &ack.publication;
    publication.ok
        && publication.sig_verified
        && publication.seq > 0
        && publication.message_id == message.id
        && publication.room == message.room
        && bool::from(
            publication
                .daemon_endpoint_id
                .as_bytes()
                .ct_eq(peer.to_string().as_bytes()),
        )
        && bool::from(
            ack.original_digest_sha256
                .as_bytes()
                .ct_eq(message.digest_sha256.as_bytes()),
        )
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
) -> Result<(PathObservation, u64), FederationFailure> {
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
        if !valid_remote_publication_ack(selection.peer(), message, &ack) {
            return Err(());
        }
        let path = selection.remote_path(&connection, gate).map_err(|_| ())?;
        Ok((path, publication.seq))
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

#[cfg(test)]
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

/// Diagnostic row count only: the history reader counts every parseable message
/// even when verification fails. Avoid discarded signature checks on the room
/// owner task; actual message queries and publication still verify signatures.
fn count_parseable_journal_messages(repo_root: &Path) -> usize {
    let Ok(file) = File::open(messages_jsonl_path(repo_root)) else {
        return 0;
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && serde_json::from_str::<BusMessage>(trimmed).is_ok()
        })
        .count()
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

fn explicit_daemon_route_os(
    repo_root: &Path,
    address: Option<&std::ffi::OsStr>,
    endpoint: Option<&std::ffi::OsStr>,
) -> Result<Option<DaemonState>, ()> {
    if address.is_none() && endpoint.is_none() {
        return Ok(None);
    }
    let addr_str = address.ok_or(())?.to_str().ok_or(())?;
    let ep_str = endpoint.ok_or(())?.to_str().ok_or(())?;
    explicit_daemon_route(repo_root, Some(addr_str), Some(ep_str)).map(Some)
}

#[cfg(target_os = "linux")]
fn is_zombie_or_gone_process(pid: u32) -> bool {
    let stat_path = format!("/proc/{pid}/stat");
    let Ok(mut file) = fs::File::open(stat_path) else {
        return true;
    };
    let mut buf = String::new();
    if std::io::Read::by_ref(&mut file)
        .take(4096)
        .read_to_string(&mut buf)
        .is_err()
    {
        return true;
    }
    let Some((_, tail)) = buf.rsplit_once(')') else {
        return true;
    };
    matches!(tail.trim_start().chars().next(), Some('Z' | 'X' | 'x'))
}

#[cfg(not(target_os = "linux"))]
fn is_zombie_or_gone_process(pid: u32) -> bool {
    let pid_arg = pid.to_string();
    for ps_bin in ["/bin/ps", "/usr/bin/ps"] {
        match Command::new(ps_bin)
            .args(["-p", &pid_arg, "-o", "stat="])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(out) => {
                if !out.status.success() {
                    return true;
                }
                let stat = String::from_utf8_lossy(&out.stdout);
                let trimmed = stat.trim();
                return trimmed.is_empty() || trimmed.starts_with('Z');
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return true,
        }
    }
    false
}

fn is_live_positive_daemon_pid(pid: u32) -> bool {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    if raw_pid <= 0 {
        return false;
    }
    let Some(kernel_pid) = rustix::process::Pid::from_raw(raw_pid) else {
        return false;
    };
    if rustix::process::test_kill_process(kernel_pid).is_err() {
        return false;
    }
    !is_zombie_or_gone_process(pid)
}

fn validate_daemon_state_structure(state: &DaemonState) -> Result<(), ()> {
    if !state.ok
        || state.bound_sockets.is_empty()
        || state.endpoint_id.parse::<EndpointId>().is_err()
        || state.started_at > unix_now().saturating_add(60)
        || !state
            .bound_sockets
            .iter()
            .all(|s| s.parse::<SocketAddr>().is_ok_and(|addr| addr.port() != 0))
    {
        return Err(());
    }
    Ok(())
}

fn read_verified_daemon_state_from_selected_root(
    physical_root: &Path,
) -> Result<Option<DaemonState>, ()> {
    let Some(bytes) =
        chinwag_cli::bus_state::read_daemon_state_bytes(physical_root).map_err(|_| ())?
    else {
        return Ok(None);
    };
    let state: DaemonState = serde_json::from_slice(&bytes).map_err(|_| ())?;
    validate_daemon_state_structure(&state)?;
    if is_live_positive_daemon_pid(state.pid) {
        Ok(Some(state))
    } else {
        Ok(None)
    }
}

fn read_daemon_state_strict_with_env(
    repo_root: &Path,
    explicit_addr: Option<&std::ffi::OsStr>,
    explicit_ep: Option<&std::ffi::OsStr>,
) -> Result<Option<DaemonState>, ()> {
    if let Some(route) = explicit_daemon_route_os(repo_root, explicit_addr, explicit_ep)? {
        return Ok(Some(route));
    }
    let meta = fs::symlink_metadata(repo_root).map_err(|_| ())?;
    if meta.file_type().is_symlink() {
        return Err(());
    }
    let physical_root = fs::canonicalize(repo_root).map_err(|_| ())?;
    read_verified_daemon_state_from_selected_root(&physical_root)
}

fn read_daemon_state_strict(repo_root: &Path) -> Result<Option<DaemonState>, ()> {
    let addr = std::env::var_os("CHINWAG_BUS_ADDR");
    let ep = std::env::var_os("CHINWAG_BUS_ENDPOINT_ID");
    read_daemon_state_strict_with_env(repo_root, addr.as_deref(), ep.as_deref())
}

fn read_daemon_state(repo_root: &Path) -> Option<DaemonState> {
    read_daemon_state_strict(repo_root).ok().flatten()
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
            && !ipv4.is_link_local()
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
    let bytes = exchange_local_frame(
        daemon,
        actor_secret,
        &BusFrame::Publish {
            message: msg.clone(),
        },
        false,
    )
    .await?;
    serde_json::from_slice::<BusAck>(&bytes).map_err(|_| "invalid ACK".to_owned())
}

async fn query_local_daemon(daemon: &DaemonState, frame: &BusFrame) -> Result<Value, String> {
    let bytes = exchange_local_frame(daemon, SecretKey::generate(), frame, true).await?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid local observation".to_owned())?;
    if value["daemon_endpoint_id"].as_str() != Some(daemon.endpoint_id.as_str()) {
        return Err("local observation daemon mismatch".into());
    }
    let valid = match frame {
        BusFrame::FederationReceipt {
            original_id,
            original_digest_sha256,
        } => {
            value["schema"] == "chinwag.federation-receipt.v1"
                && value["original_id"] == *original_id
                && value["original_digest_sha256"] == *original_digest_sha256
        }
        BusFrame::NetworkPosture => value["schema"] == "chinwag.network-posture.v1",
        BusFrame::JournalSubscribe {
            subscription_id, ..
        }
        | BusFrame::JournalUnsubscribe { subscription_id } => {
            value["schema"] == "chinwag.bus.journal-subscription.v1"
                && value["subscription_id"] == *subscription_id
        }
        BusFrame::JournalChanged {
            observed_len,
            observed_inode,
            ..
        } => {
            value["schema"] == "chinwag.bus.journal-change.v1"
                && value["observed_len"] == *observed_len
                && value["observed_inode"] == *observed_inode
        }
        _ => false,
    };
    if !valid {
        return Err("local observation correlation mismatch".into());
    }
    Ok(value)
}

async fn send_local_observation(send: &mut iroh::endpoint::SendStream, response: Value) {
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            send.write_all(&bytes).await.map_err(|_| ())?;
            send.finish().map_err(|_| ())?;
            send.stopped().await.map_err(|_| ())
        })
        .await;
    }
}

async fn native_journal_change_hint<T: Clone>(
    sender: &broadcast::Sender<T>,
    timeout: Duration,
    mark_changed: impl FnOnce() -> bool,
) -> bool {
    let mut arrivals = sender.subscribe();
    mark_changed() || tokio::time::timeout(timeout, arrivals.recv()).await.is_ok()
}

#[cfg(test)]
mod native_wait_hint_tests {
    use super::*;
    #[tokio::test]
    async fn bus_wait_subscription_precedes_mark_and_native_timeout_has_no_cursor_lock() {
        let (sender, _) = broadcast::channel::<()>(1);
        // An arrival during the mark observation must already have a receiver.
        assert!(
            native_journal_change_hint(&sender, Duration::from_secs(1), || {
                assert_eq!(sender.send(()).unwrap(), 1);
                false
            })
            .await
        );
        let started = Instant::now();
        assert!(!native_journal_change_hint(&sender, Duration::from_millis(40), || false).await);
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(native_journal_change_hint(&sender, Duration::from_secs(1), || true).await);
    }
}

async fn exchange_local_frame(
    daemon: &DaemonState,
    actor_secret: SecretKey,
    frame: &BusFrame,
    loopback_only: bool,
) -> Result<Vec<u8>, String> {
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
    if loopback_only && !sock.ip().is_loopback() {
        return Err("local query requires loopback daemon route".into());
    }

    let lookup = MemoryLookup::new();
    let addr = EndpointAddr::from_parts(daemon_id, [TransportAddr::Ip(sock)]);
    lookup.set_endpoint_info(addr.clone());

    let client = bind_bus_endpoint(actor_secret, 0, lookup).await?;
    let timeout = match frame {
        BusFrame::JournalChanged { timeout_secs, .. } => timeout_secs.saturating_add(8).min(3608),
        _ => 8,
    };
    let result = tokio::time::timeout(Duration::from_secs(timeout), async {
        let connection = client
            .connect(addr, BUS_ALPN)
            .await
            .map_err(|_| "iroh QUIC connect failed".to_owned())?;
        let result = async {
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|_| "open_bi failed".to_owned())?;
            let payload =
                serde_json::to_vec(frame).map_err(|_| "frame serialization failed".to_owned())?;
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
            Ok(bytes)
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
    receipts: Arc<Mutex<ReceiptCache>>,
}
struct PublicationEffects<'a> {
    local: &'a broadcast::Sender<BusMessage>,
    peer: Option<&'a tokio::sync::mpsc::Sender<BusMessage>>,
    subscribers: usize,
    receipts: &'a Mutex<ReceiptCache>,
}
impl chinwag_cli::bus_federation::FederationEffects for PublicationEffects<'_> {
    type Error = &'static str;
    fn on_stored(&mut self, message: &BusMessage) -> Result<(), Self::Error> {
        self.receipts
            .lock()
            .map_err(|_| "receipt cache unavailable")?
            .begin(&message.id, &message.digest_sha256, self.peer.is_some());
        self.subscribers = self.local.send(message.clone()).unwrap_or(0);
        if let Some(peer) = self.peer
            && peer.try_send(message.clone()).is_err()
        {
            self.receipts
                .lock()
                .map_err(|_| "receipt cache unavailable")?
                .finish(
                    &message.id,
                    &message.digest_sha256,
                    FederationObservation::Unknown {
                        phase: "peer_queue_unavailable".into(),
                    },
                );
            return Err("peer queue unavailable after storage");
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
            receipts: Arc::new(Mutex::new(ReceiptCache::new(256))),
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
            receipts: &self.receipts,
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum RoomOwnerFailure {
    PresenceExpired,
    RenewalUnknown(String),
    ReceiveFailed(String),
}

type RoomOwnerFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = RoomOwnerFailure> + 'a>>;

enum DaemonOutcome {
    Exit(u8),
    Reexec {
        install_path: PathBuf,
        prepared: chinwag_cli::release_sync::PreparedImmutableReexec,
    },
}

use chinwag_cli::release_sync::{
    ReleaseDaemonEvent, ReleaseDaemonJob, ReleaseDaemonScheduler, execute_release_daemon_job,
};

const PENDING_REEXEC_MAX_DRAIN_WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct ReleaseJobQueueGate {
    frozen_for_reexec: bool,
    active_jobs: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnqueueReleaseJobError {
    FrozenForReexec,
    QueueFullOrClosed,
}

struct ReleaseJobSlotGuard(Arc<Mutex<ReleaseJobQueueGate>>);

impl Drop for ReleaseJobSlotGuard {
    fn drop(&mut self) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.active_jobs = guard.active_jobs.saturating_sub(1);
    }
}

fn try_enqueue_release_job(
    tx: &tokio::sync::mpsc::Sender<ReleaseDaemonJob>,
    gate: &Arc<Mutex<ReleaseJobQueueGate>>,
    job: ReleaseDaemonJob,
) -> Result<(), EnqueueReleaseJobError> {
    let mut guard = gate.lock().unwrap_or_else(|e| e.into_inner());
    if guard.frozen_for_reexec {
        return Err(EnqueueReleaseJobError::FrozenForReexec);
    }
    guard.active_jobs = guard.active_jobs.saturating_add(1);
    match tx.try_send(job) {
        Ok(()) => Ok(()),
        Err(_) => {
            guard.active_jobs = guard.active_jobs.saturating_sub(1);
            Err(EnqueueReleaseJobError::QueueFullOrClosed)
        }
    }
}

type ReexecPrepResult = Result<
    chinwag_cli::release_sync::PreparedImmutableReexec,
    chinwag_cli::release_sync::ReleaseSyncError,
>;

#[derive(Clone, Debug)]
struct PendingReexecTarget {
    install_path: PathBuf,
    expected_sha: [u8; 32],
    armed_at: Instant,
    generation: u64,
}

#[derive(Default, Debug)]
struct PendingReexecSlot {
    current: Option<PendingReexecTarget>,
    next_generation: u64,
}

impl PendingReexecSlot {
    fn arm(&mut self, install_path: PathBuf, expected_sha: [u8; 32]) -> u64 {
        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        self.current = Some(PendingReexecTarget {
            install_path,
            expected_sha,
            armed_at: Instant::now(),
            generation,
        });
        generation
    }

    fn arm_if_changed(&mut self, install_path: PathBuf, expected_sha: [u8; 32]) -> bool {
        if let Some(ref cur) = self.current
            && cur.install_path == install_path
            && cur.expected_sha == expected_sha
        {
            return false;
        }
        self.arm(install_path, expected_sha);
        true
    }

    fn clear(&mut self) {
        self.current = None;
    }

    fn is_some(&self) -> bool {
        self.current.is_some()
    }

    fn current(&self) -> Option<&PendingReexecTarget> {
        self.current.as_ref()
    }
}

struct InFlightReexecPrep {
    target_path: PathBuf,
    expected_sha: [u8; 32],
    generation: u64,
    handle: tokio::task::JoinHandle<ReexecPrepResult>,
}

async fn poll_reexec_prep(
    slot: &mut Option<InFlightReexecPrep>,
) -> (
    PathBuf,
    [u8; 32],
    u64,
    Result<ReexecPrepResult, tokio::task::JoinError>,
) {
    match slot.as_mut() {
        Some(in_flight) => {
            let res = (&mut in_flight.handle).await;
            let finished = slot.take().expect("in_flight reexec prep must be present");
            (
                finished.target_path,
                finished.expected_sha,
                finished.generation,
                res,
            )
        }
        None => std::future::pending().await,
    }
}

enum ReexecPrepStepOutcome {
    CommitReexec {
        install_path: PathBuf,
        prepared: chinwag_cli::release_sync::PreparedImmutableReexec,
    },
    RescheduleTimer(Duration),
    StayOnlineDisarmed,
}

#[allow(clippy::too_many_arguments)]
fn complete_reexec_prep_step(
    prep_path: PathBuf,
    prep_sha: [u8; 32],
    prep_generation: u64,
    prep_res: Result<ReexecPrepResult, tokio::task::JoinError>,
    stdout: &mut dyn Write,
    startup_chinwag_sha256: Option<[u8; 32]>,
    forwards_empty: bool,
    forward_queue_empty: bool,
    release_done_rx: &tokio::sync::mpsc::Receiver<ReleaseDaemonEvent>,
    release_job_gate: &Arc<Mutex<ReleaseJobQueueGate>>,
    pending_reexec: &mut PendingReexecSlot,
    reexec_prep_retries: &mut u32,
    backoff_fn: impl FnOnce(u32) -> Duration,
) -> ReexecPrepStepOutcome {
    let cleanup_async = |prepared: chinwag_cli::release_sync::PreparedImmutableReexec| {
        drop(tokio::task::spawn_blocking(move || {
            chinwag_cli::release_sync::cleanup_prepared_reexec(prepared);
        }));
    };
    let cleanup_if_prepared = |res: Result<ReexecPrepResult, tokio::task::JoinError>| {
        if let Ok(Ok(prepared)) = res {
            cleanup_async(prepared);
        }
    };

    // Authoritative generation + target freshness gate BEFORE any result branch
    // can disarm `pending_reexec` or mutate `reexec_prep_retries`: if `pending_reexec`
    // was cleared or superseded by a newer generation while this preparation ran,
    // discard this stale completion without disturbing the active target.
    let Some(cur) = pending_reexec.current().cloned() else {
        cleanup_if_prepared(prep_res);
        *reexec_prep_retries = 0;
        return ReexecPrepStepOutcome::StayOnlineDisarmed;
    };
    if cur.generation != prep_generation
        || cur.install_path != prep_path
        || cur.expected_sha != prep_sha
    {
        cleanup_if_prepared(prep_res);
        *reexec_prep_retries = 0;
        let settle_remaining = Duration::from_millis(350).saturating_sub(cur.armed_at.elapsed());
        return ReexecPrepStepOutcome::RescheduleTimer(
            settle_remaining.max(Duration::from_millis(50)),
        );
    }

    match prep_res {
        Ok(Ok(prepared)) => {
            if Some(prepared.sha256) == startup_chinwag_sha256 {
                cleanup_async(prepared);
                pending_reexec.clear();
                *reexec_prep_retries = 0;
                return ReexecPrepStepOutcome::StayOnlineDisarmed;
            }
            // Linearizable quiescence + freeze: evaluate `active_jobs == 0` AND
            // `release_done_rx.is_empty()` while holding `release_job_gate` so no worker
            // completion or incoming handler enqueue can slip between check and freeze.
            let mut gate_guard = release_job_gate.lock().unwrap_or_else(|e| e.into_inner());
            let worker_idle = gate_guard.active_jobs == 0 && release_done_rx.is_empty();
            if !should_complete_pending_reexec(
                forwards_empty,
                forward_queue_empty,
                worker_idle,
                cur.armed_at.elapsed(),
            ) {
                drop(gate_guard);
                cleanup_async(prepared);
                return ReexecPrepStepOutcome::RescheduleTimer(Duration::from_millis(100));
            }
            gate_guard.frozen_for_reexec = true;
            drop(gate_guard);
            *reexec_prep_retries = 0;
            ReexecPrepStepOutcome::CommitReexec {
                install_path: prep_path,
                prepared,
            }
        }
        Ok(Err(err))
            if err.is_transient_retryable()
                && *reexec_prep_retries
                    < chinwag_cli::release_sync::MAX_RELEASE_SYNC_TRANSIENT_RETRIES =>
        {
            let delay = backoff_fn(*reexec_prep_retries);
            *reexec_prep_retries = reexec_prep_retries.saturating_add(1);
            let _ = writeln!(
                stdout,
                "{}",
                json!({
                    "event": "native_daemon_reexec_retry",
                    "binary": prep_path.to_string_lossy(),
                    "reason": err.to_string(),
                    "next_retry_secs": delay.as_secs()
                })
            );
            let _ = stdout.flush();
            ReexecPrepStepOutcome::RescheduleTimer(delay)
        }
        Ok(Err(err)) => {
            let _ = writeln!(
                stdout,
                "{}",
                json!({
                    "event": "native_daemon_reexec_refused",
                    "binary": prep_path.to_string_lossy(),
                    "reason": err.to_string()
                })
            );
            let _ = stdout.flush();
            pending_reexec.clear();
            *reexec_prep_retries = 0;
            ReexecPrepStepOutcome::StayOnlineDisarmed
        }
        Err(_) => {
            let _ = writeln!(
                stdout,
                "{}",
                json!({
                    "event": "native_daemon_reexec_refused",
                    "binary": prep_path.to_string_lossy(),
                    "reason": "reexec preparation worker panicked"
                })
            );
            let _ = stdout.flush();
            pending_reexec.clear();
            *reexec_prep_retries = 0;
            ReexecPrepStepOutcome::StayOnlineDisarmed
        }
    }
}

fn should_complete_pending_reexec(
    forwards_empty: bool,
    forward_queue_empty: bool,
    release_worker_idle: bool,
    armed_elapsed: Duration,
) -> bool {
    release_worker_idle
        && ((forwards_empty && forward_queue_empty)
            || armed_elapsed >= PENDING_REEXEC_MAX_DRAIN_WAIT)
}

async fn quiesce_release_worker_and_drain_events(
    release_job_tx: &mut Option<tokio::sync::mpsc::Sender<ReleaseDaemonJob>>,
    release_done_tx_keepalive: &mut Option<tokio::sync::mpsc::Sender<ReleaseDaemonEvent>>,
    release_worker_handle: &mut Option<tokio::task::JoinHandle<()>>,
    release_done_rx: &mut tokio::sync::mpsc::Receiver<ReleaseDaemonEvent>,
    mut on_event: impl FnMut(ReleaseDaemonEvent),
) {
    drop(release_job_tx.take());
    drop(release_done_tx_keepalive.take());
    while let Some(ev) = release_done_rx.recv().await {
        on_event(ev);
    }
    if let Some(worker) = release_worker_handle.take() {
        let _ = worker.await;
    }
    while let Ok(ev) = release_done_rx.try_recv() {
        on_event(ev);
    }
}

#[allow(clippy::too_many_arguments)]
fn process_release_daemon_event(
    release_event: ReleaseDaemonEvent,
    stdout: &mut dyn Write,
    repo_root: &Path,
    endpoint_id: &str,
    has_network: bool,
    forward_tx: &tokio::sync::mpsc::Sender<BusMessage>,
    publications: &Mutex<NativePublication>,
    tx: &broadcast::Sender<BusMessage>,
    state: &Mutex<DaemonState>,
    startup_chinwag_sha256: Option<[u8; 32]>,
    tearing_down_for_reexec: bool,
    pending_reexec: &mut PendingReexecSlot,
) -> bool {
    match release_event {
        ReleaseDaemonEvent::Applied { binary, outcome } => match *outcome {
            chinwag_cli::release_sync::ReleaseApplyOutcome::Installed {
                manifest,
                install_path,
                receipt_message,
                ..
            } => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "event": "native_release_sync",
                        "outcome": "installed",
                        "binary": binary,
                        "sha256": manifest.sha256,
                        "git_commit": manifest.git_commit,
                        "rollback": manifest.rollback
                    })
                );
                let _ = stdout.flush();
                if let Some(mut receipt) = receipt_message.map(|b| *b)
                    && verify_detached_bus_signature(repo_root, &mut receipt)
                {
                    let peer = if has_network { Some(forward_tx) } else { None };
                    if let Ok(mut ingress) = publications.lock()
                        && let Ok((seq, _)) = ingress.publish(&receipt, tx, peer)
                        && let Ok(mut guard) = state.lock()
                    {
                        guard.last_heartbeat = unix_now();
                        guard.total_messages = seq;
                        let _ = write_daemon_state(repo_root, &guard);
                    }
                }
                if manifest.binary == "chinwag"
                    && let Some(manifest_sha) =
                        chinwag_cli::release_sync::decode_lowercase_hex_32(&manifest.sha256)
                {
                    if Some(manifest_sha) != startup_chinwag_sha256 || tearing_down_for_reexec {
                        pending_reexec.arm(install_path, manifest_sha);
                        return true;
                    }
                    // Rollback back to the running process's own startup digest while still
                    // in the live loop disarms any stale prior `pending_reexec` target.
                    pending_reexec.clear();
                }
                false
            }
            chinwag_cli::release_sync::ReleaseApplyOutcome::AlreadyInstalled {
                manifest,
                install_path,
            } => {
                let manifest_sha =
                    chinwag_cli::release_sync::decode_lowercase_hex_32(&manifest.sha256);
                let needs_reexec = manifest.binary == "chinwag"
                    && startup_chinwag_sha256.is_some()
                    && manifest_sha.is_some()
                    && manifest_sha != startup_chinwag_sha256;
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "event": "native_release_sync",
                        "outcome": "already_installed",
                        "binary": binary,
                        "sha256": manifest.sha256,
                        "reexec_scheduled": needs_reexec
                    })
                );
                let _ = stdout.flush();
                if manifest.binary == "chinwag"
                    && let Some(manifest_sha) = manifest_sha
                {
                    if needs_reexec {
                        if let Ok(home_dir) = chinwag_cli::release_sync::resolve_home_dir()
                            && let Some(mut receipt) = chinwag_cli::release_sync::build_release_installed_receipt_for_already_installed(
                                &home_dir,
                                &manifest,
                                endpoint_id,
                            )
                            && verify_detached_bus_signature(repo_root, &mut receipt)
                        {
                            let peer = if has_network { Some(forward_tx) } else { None };
                            if let Ok(mut ingress) = publications.lock()
                                && let Ok((seq, _)) = ingress.publish(&receipt, tx, peer)
                                && let Ok(mut guard) = state.lock()
                            {
                                guard.last_heartbeat = unix_now();
                                guard.total_messages = seq;
                                let _ = write_daemon_state(repo_root, &guard);
                            }
                        }
                        return pending_reexec.arm_if_changed(install_path, manifest_sha);
                    } else if tearing_down_for_reexec {
                        return pending_reexec.arm_if_changed(install_path, manifest_sha);
                    } else {
                        pending_reexec.clear();
                    }
                }
                false
            }
            chinwag_cli::release_sync::ReleaseApplyOutcome::SkippedTargetMismatch {
                manifest_target,
                local_target,
            } => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "event": "native_release_sync",
                        "outcome": "skipped_target_mismatch",
                        "manifest_target": manifest_target,
                        "local_target": local_target
                    })
                );
                let _ = stdout.flush();
                false
            }
        },
        ReleaseDaemonEvent::Rejected {
            binary,
            reason,
            retryable,
            next_retry_secs,
        } => {
            let _ = writeln!(
                stdout,
                "{}",
                json!({
                    "event": "native_release_sync_rejected",
                    "binary": binary,
                    "reason": reason,
                    "retryable": retryable,
                    "next_retry_secs": next_retry_secs
                })
            );
            let _ = stdout.flush();
            false
        }
        ReleaseDaemonEvent::Suppressed {
            binary,
            release_key,
            reason,
        } => {
            let _ = writeln!(
                stdout,
                "{}",
                json!({
                    "event": "native_release_sync_suppressed",
                    "binary": binary,
                    "release_key": release_key,
                    "reason": reason
                })
            );
            let _ = stdout.flush();
            false
        }
    }
}

fn build_canonical_daemon_reexec_args(
    bus_args: &[String],
    canonical_repo_root: &Path,
) -> Vec<std::ffi::OsString> {
    let mut out: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("bus"),
        std::ffi::OsString::from("daemon"),
        std::ffi::OsString::from("--repo"),
        canonical_repo_root.as_os_str().to_os_string(),
    ];
    let mut idx = 1;
    while idx < bus_args.len() {
        if bus_args[idx] == "--repo" {
            idx += 2;
            continue;
        }
        out.push(std::ffi::OsString::from(&bus_args[idx]));
        idx += 1;
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
enum ReconnectLoopOutcome<S> {
    Reconnected { session: S, next_attempt: u32 },
    Exhausted { attempts: u32, last_reason: String },
    FatalRefusal(String),
}

async fn attempt_room_reconnect_with_cap<S, F, Fut, B, SleepFn, SleepFut>(
    mut reconnect_attempt: u32,
    initial_reason: String,
    room_events: &tokio::sync::mpsc::Sender<Value>,
    mut backoff_fn: B,
    mut sleep_fn: SleepFn,
    mut try_reconnect: F,
) -> ReconnectLoopOutcome<S>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<S, chinwag_swarm::room::Error>>,
    B: FnMut(u32) -> Duration,
    SleepFn: FnMut(Duration) -> SleepFut,
    SleepFut: std::future::Future<Output = ()>,
{
    let mut reason = initial_reason;
    loop {
        if reconnect_attempt >= chinwag_swarm::room::MAX_CONSECUTIVE_RECONNECT_ATTEMPTS {
            return ReconnectLoopOutcome::Exhausted {
                attempts: reconnect_attempt,
                last_reason: reason,
            };
        }
        let backoff = backoff_fn(reconnect_attempt);
        let _ = room_events.try_send(json!({
            "event": "native_room_reconnect_scheduled",
            "attempt": reconnect_attempt.saturating_add(1),
            "backoff_ms": backoff.as_millis() as u64,
            "reason": reason,
            "scope": "TRANSPORT_ONLY_NOT_TASK_AUTHORITY"
        }));
        sleep_fn(backoff).await;
        match try_reconnect(reconnect_attempt).await {
            Ok(new_session) => {
                return ReconnectLoopOutcome::Reconnected {
                    session: new_session,
                    next_attempt: reconnect_attempt.saturating_add(1),
                };
            }
            Err(error) => {
                if chinwag_swarm::room::is_reconnectable_room_error(&error) {
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    reason = error.to_string();
                } else {
                    return ReconnectLoopOutcome::FatalRefusal(error.to_string());
                }
            }
        }
    }
}

// One persistent owner future: selecting another daemon event must not drop an
// in-flight renewal. Clean WebSocket closures (`code 1000` / DO hibernation /
// transient network resets) and sleep/wake presence expiries reconnect with
// bounded jittered exponential backoff (`250ms` -> `30s`), while explicit
// coordinator/auth/signature/pin refusals fail closed immediately.
#[allow(clippy::too_many_arguments)]
async fn drive_daemon_room(
    session: &mut RoomSession,
    client: &RoomClient,
    identity: &DaemonRoomIdentity,
    endpoint: &Endpoint,
    gate: DaemonPeerGate,
    addresses: Vec<SocketAddr>,
    lookup: MemoryLookup,
    room_events: tokio::sync::mpsc::Sender<Value>,
) -> RoomOwnerFailure {
    let mut reconnect_attempt: u32 = 0;
    let mut reconnecting = false;
    loop {
        let mut disconnect_reason: Option<String> = None;
        match session.daemon_renewal_wait() {
            Ok(wait) => {
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {
                        match client.renew_daemon_presence(identity, session).await {
                            Ok(()) => {
                                reconnect_attempt = 0;
                                reconnecting = false;
                                let _ = room_events.try_send(json!({
                                    "event": "native_transport_presence_renewed",
                                    "scope": "TRANSPORT_ONLY_NOT_TASK_AUTHORITY",
                                    "original_message_replay": false
                                }));
                            }
                            Err(chinwag_swarm::room::Error::DaemonBinding(
                                chinwag_swarm::room_binding::BindingError::Expired,
                            )) => {
                                disconnect_reason = Some("transport presence expired across sleep".to_owned());
                            }
                            Err(error) => {
                                return RoomOwnerFailure::RenewalUnknown(error.to_string());
                            }
                        }
                    }
                    update = session.receive_daemon_peer() => {
                        match update {
                            Ok(_) => {
                                if reconnecting {
                                    reconnect_attempt = 0;
                                    reconnecting = false;
                                    let _ = room_events.try_send(json!({
                                        "event": "native_room_reconnected",
                                        "scope": "TRANSPORT_ONLY_NOT_TASK_AUTHORITY"
                                    }));
                                }
                            }
                            Err(error) => {
                                if chinwag_swarm::room::is_reconnectable_room_error(&error)
                                    || matches!(
                                        error,
                                        chinwag_swarm::room::Error::DaemonBinding(
                                            chinwag_swarm::room_binding::BindingError::Expired
                                        )
                                    )
                                {
                                    disconnect_reason = Some(error.to_string());
                                } else {
                                    return RoomOwnerFailure::ReceiveFailed(error.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Err(chinwag_swarm::room::Error::DaemonBinding(
                chinwag_swarm::room_binding::BindingError::Expired,
            )) => {
                disconnect_reason = Some("transport presence expired across sleep".to_owned());
            }
            Err(_) => return RoomOwnerFailure::PresenceExpired,
        }

        if let Some(reason) = disconnect_reason {
            session.close_for_reconnect().await;
            reconnecting = true;
            match attempt_room_reconnect_with_cap(
                reconnect_attempt,
                reason,
                &room_events,
                chinwag_swarm::room::next_reconnect_backoff,
                tokio::time::sleep,
                |_| {
                    client.reconnect_daemon(
                        identity,
                        endpoint,
                        gate.clone(),
                        addresses.clone(),
                        lookup.clone(),
                    )
                },
            )
            .await
            {
                ReconnectLoopOutcome::Reconnected {
                    session: new_session,
                    next_attempt,
                } => {
                    *session = new_session;
                    reconnect_attempt = next_attempt;
                }
                ReconnectLoopOutcome::Exhausted {
                    attempts,
                    last_reason,
                } => {
                    session.close().await;
                    return RoomOwnerFailure::ReceiveFailed(format!(
                        "reconnect attempts exhausted after {attempts} tries ({last_reason})"
                    ));
                }
                ReconnectLoopOutcome::FatalRefusal(err) => {
                    return RoomOwnerFailure::ReceiveFailed(err);
                }
            }
        }
    }
}

fn daemon_release_sync_enabled(no_release_sync: bool) -> bool {
    !no_release_sync
}

#[cfg(test)]
async fn run_daemon_loop(
    repo_root: PathBuf,
    port: u16,
    network_selection: Option<NetworkSelection>,
    no_governors: bool,
    stdout: &mut dyn Write,
    shutdown: impl std::future::Future<Output = ()>,
) -> u8 {
    run_daemon_loop_inner(
        repo_root,
        port,
        network_selection,
        no_governors,
        stdout,
        shutdown,
        None,
    )
    .await
}

#[cfg(test)]
async fn run_daemon_loop_inner(
    repo_root: PathBuf,
    port: u16,
    network_selection: Option<NetworkSelection>,
    no_governors: bool,
    stdout: &mut dyn Write,
    shutdown: impl std::future::Future<Output = ()>,
    controlled_local_driver: Option<RoomOwnerFuture<'static>>,
) -> u8 {
    // Test-only controlled loop harness (`#[cfg(test)]`): isolates in-process
    // network/recovery tests from mutating real `$HOME/.local/bin`. Production
    // `chinwag bus daemon` calls `run_daemon_loop_reexecable` directly with
    // `daemon_release_sync_enabled(no_release_sync)`.
    const TEST_HARNESS_RELEASE_SYNC: bool = false;
    match run_daemon_loop_reexecable(
        repo_root,
        port,
        network_selection,
        no_governors,
        TEST_HARNESS_RELEASE_SYNC,
        stdout,
        shutdown,
        controlled_local_driver,
    )
    .await
    {
        DaemonOutcome::Exit(code) => code,
        DaemonOutcome::Reexec { prepared, .. } => {
            chinwag_cli::release_sync::cleanup_prepared_reexec(prepared);
            0
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_daemon_loop_reexecable(
    repo_root: PathBuf,
    port: u16,
    network_selection: Option<NetworkSelection>,
    no_governors: bool,
    enable_release_sync: bool,
    stdout: &mut dyn Write,
    shutdown: impl std::future::Future<Output = ()>,
    controlled_local_driver: Option<RoomOwnerFuture<'static>>,
) -> DaemonOutcome {
    // This private seam exercises responsiveness under a pending owner. It
    // cannot replace the real owner or create authority on a networked daemon.
    if controlled_local_driver.is_some() && network_selection.is_some() {
        return DaemonOutcome::Exit(1);
    }
    tokio::pin!(shutdown);
    let secret = match load_or_create_daemon_secret(&repo_root) {
        Ok(secret) => secret,
        Err(error) => {
            let _ = writeln!(stdout, "chinwag bus daemon: {error}");
            return DaemonOutcome::Exit(1);
        }
    };
    let publications = match NativePublication::open(&repo_root) {
        Ok(publications) => Arc::new(Mutex::new(publications)),
        Err(error) => {
            let _ = writeln!(stdout, "chinwag bus daemon: {error}");
            return DaemonOutcome::Exit(1);
        }
    };
    let receipts = match publications.lock() {
        Ok(publication) => publication.receipts.clone(),
        Err(_) => return DaemonOutcome::Exit(1),
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
            return DaemonOutcome::Exit(1);
        }
    }
    let network = match network_selection {
        Some(selection) => match selection.pending_gate(secret.public()) {
            Ok(gate) => Some((selection, gate)),
            Err(error) => {
                let _ = writeln!(stdout, "chinwag bus daemon: {error}");
                return DaemonOutcome::Exit(1);
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
                return DaemonOutcome::Exit(1);
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
    let mut room_credentials = None;
    let mut room_session = if let Some((selection, gate)) = &network {
        let identity = match DaemonRoomIdentity::for_endpoint(secret, &endpoint) {
            Ok(identity) => identity,
            Err(_) => {
                endpoint.close().await;
                return DaemonOutcome::Exit(1);
            }
        };
        let client = match selection.client() {
            Ok(client) => client,
            Err(_) => {
                endpoint.close().await;
                return DaemonOutcome::Exit(1);
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
            .open_daemon(
                &identity,
                &endpoint,
                gate.clone(),
                addresses.clone(),
                lookup.clone(),
            )
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
                    return DaemonOutcome::Exit(1);
                }
                room_credentials = Some((client, identity, gate.clone(), addresses, lookup));
                Some(session)
            }
            Err(error) => {
                endpoint.close().await;
                let _ = writeln!(
                    stdout,
                    "chinwag bus network HELD: compatible coordinator unavailable ({error})"
                );
                return DaemonOutcome::Exit(1);
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

    let initial_count = count_parseable_journal_messages(&repo_root) as u64;
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
        return DaemonOutcome::Exit(1);
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

    let subscriptions = Arc::new(Mutex::new(
        chinwag_cli::bus_wait_subscription::Subscriptions::<BusMessage>::default(),
    ));
    let (tx, unused_receiver) = broadcast::channel::<BusMessage>(256);
    // No consumer has subscribed through this daemon path. Keeping an unread
    // internal receiver would inflate subscribers_notified without delivery.
    drop(unused_receiver);
    let (forward_tx, mut forward_rx) = tokio::sync::mpsc::channel::<BusMessage>(128);
    let incoming_slots = Arc::new(tokio::sync::Semaphore::new(32));
    let mut handlers = tokio::task::JoinSet::new();
    let mut forwards = tokio::task::JoinSet::new();
    let mut forwarding_original = None;
    let (state_error_tx, mut state_error_rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut exit_code = 0;
    let mut pinned_reexec: Option<(PathBuf, chinwag_cli::release_sync::PreparedImmutableReexec)> =
        None;
    let mut reexec_prep_task: Option<InFlightReexecPrep> = None;
    let mut reexec_prep_retries: u32 = 0;
    let mut reexec_requested = false;
    let mut pending_reexec = PendingReexecSlot::default();
    let reexec_sleep = tokio::time::sleep(Duration::from_secs(86_400));
    tokio::pin!(reexec_sleep);
    let startup_chinwag_sha256: Option<[u8; 32]> = std::env::current_exe()
        .ok()
        .and_then(|exe| chinwag_cli::release_sync::local_binary_sha256(&exe));

    let release_reconcile_needed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release_job_gate = Arc::new(Mutex::new(ReleaseJobQueueGate::default()));
    let retry_scheduler = Arc::new(Mutex::new(
        ReleaseDaemonScheduler::new_with_initial_catchup(),
    ));

    let (release_done_tx, mut release_done_rx) =
        tokio::sync::mpsc::channel::<ReleaseDaemonEvent>(32);
    let mut release_done_tx_keepalive = Some(release_done_tx.clone());
    let mut release_worker_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut release_job_tx = if enable_release_sync && controlled_local_driver.is_none() {
        let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<ReleaseDaemonJob>(32);
        if retry_scheduler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .poll_catchup_dispatch(false, Instant::now())
            && try_enqueue_release_job(&job_tx, &release_job_gate, ReleaseDaemonJob::StartupCatchup)
                .is_err()
        {
            retry_scheduler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .on_catchup_send_full();
        }
        let journal_for_worker = messages_jsonl_path(&repo_root);
        let ep_for_worker = endpoint_id.clone();
        let done_tx = release_done_tx;
        let sched_for_worker = retry_scheduler.clone();
        let gate_for_worker = release_job_gate.clone();
        release_worker_handle = Some(tokio::spawn(async move {
            let mut cleaned_stale_reexec = false;
            while let Some(job) = job_rx.recv().await {
                let _job_slot = ReleaseJobSlotGuard(gate_for_worker.clone());
                let is_catchup = matches!(job, ReleaseDaemonJob::StartupCatchup);
                let need_cleanup = !cleaned_stale_reexec;
                let journal_clone = journal_for_worker.clone();
                let ep_clone = ep_for_worker.clone();
                let sched_clone = sched_for_worker.clone();
                let events = tokio::task::spawn_blocking(move || {
                    let home_dir = chinwag_cli::release_sync::resolve_home_dir()?;
                    if need_cleanup {
                        chinwag_cli::release_sync::cleanup_stale_reexec_dirs(&home_dir);
                    }
                    let store =
                        chinwag_cli::release_sync::WranglerR2ArtifactStore::new(home_dir.clone());
                    Ok::<_, chinwag_cli::release_sync::ReleaseSyncError>(
                        execute_release_daemon_job(
                            &home_dir,
                            &journal_clone,
                            &store,
                            &ep_clone,
                            &sched_clone,
                            job,
                        ),
                    )
                })
                .await;
                match events {
                    Ok(Ok(items)) => {
                        cleaned_stale_reexec = true;
                        for event in items {
                            let _ = done_tx.send(event).await;
                        }
                    }
                    Ok(Err(err)) => {
                        let retryable = err.is_transient_retryable();
                        let next_retry_secs = if let Ok(mut sched) = sched_for_worker.lock() {
                            sched
                                .on_worker_env_error(retryable, is_catchup, Instant::now())
                                .map(|d| d.as_secs())
                        } else {
                            None
                        };
                        let _ = done_tx
                            .send(ReleaseDaemonEvent::Rejected {
                                binary: "worker".to_owned(),
                                reason: err.to_string(),
                                retryable,
                                next_retry_secs,
                            })
                            .await;
                    }
                    Err(_) => {
                        if let Ok(mut sched) = sched_for_worker.lock() {
                            sched.on_worker_panic(Instant::now());
                        }
                        let _ = done_tx
                            .send(ReleaseDaemonEvent::Rejected {
                                binary: "worker".to_owned(),
                                reason: "release sync worker panicked".to_owned(),
                                retryable: false,
                                next_retry_secs: None,
                            })
                            .await;
                    }
                }
            }
        }));
        Some(job_tx)
    } else {
        drop(release_done_tx);
        None
    };

    let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
    let mut governor_tick = tokio::time::interval(Duration::from_secs(45));
    governor_tick.tick().await;

    let (room_events_tx, mut room_events_rx) = tokio::sync::mpsc::channel::<Value>(8);
    let endpoint_for_room = endpoint.clone();
    let mut room_driver: RoomOwnerFuture<'_> = match controlled_local_driver {
        Some(driver) => driver,
        None => Box::pin(async {
            let room_events_tx = room_events_tx;
            match (&mut room_session, &room_credentials) {
                (Some(session), Some((client, identity, gate, addresses, lookup))) => {
                    drive_daemon_room(
                        session,
                        client,
                        identity,
                        &endpoint_for_room,
                        gate.clone(),
                        addresses.clone(),
                        lookup.clone(),
                        room_events_tx,
                    )
                    .await
                }
                (None, None) => std::future::pending().await,
                _ => RoomOwnerFailure::PresenceExpired,
            }
        }),
    };
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
            failure = &mut room_driver => {
                let message = match failure {
                    RoomOwnerFailure::PresenceExpired => "chinwag bus network HELD: transport presence expired".to_owned(),
                    RoomOwnerFailure::RenewalUnknown(reason) => format!("chinwag bus network HELD: transport presence renewal unknown or refused: {reason}; no retry"),
                    RoomOwnerFailure::ReceiveFailed(reason) => format!("chinwag bus network HELD: original room receive failed: {reason}; no retry"),
                };
                let _ = writeln!(stdout, "{message}");
                exit_code = 1;
                break;
            }
            Some(event) = room_events_rx.recv() => {
                let _ = writeln!(stdout, "{event}");
                let _ = stdout.flush();
            }
            Some(release_event) = release_done_rx.recv() => {
                if process_release_daemon_event(
                    release_event,
                    stdout,
                    &repo_root,
                    &endpoint_id,
                    network.is_some(),
                    &forward_tx,
                    &publications,
                    &tx,
                    &state,
                    startup_chinwag_sha256,
                    false,
                    &mut pending_reexec,
                ) {
                    reexec_prep_retries = 0;
                    reexec_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + Duration::from_millis(350));
                }
            }
            () = &mut reexec_sleep, if pending_reexec.is_some() && reexec_prep_task.is_none() => {
                if let Some(cur) = pending_reexec.current().cloned() {
                    let release_worker_idle = {
                        let guard = release_job_gate.lock().unwrap_or_else(|e| e.into_inner());
                        guard.active_jobs == 0 && release_done_rx.is_empty()
                    };
                    if should_complete_pending_reexec(
                        forwards.is_empty(),
                        forward_rx.is_empty(),
                        release_worker_idle,
                        cur.armed_at.elapsed(),
                    ) {
                        // Launch immutable snapshot preparation asynchronously in `spawn_blocking`
                        // and select on `reexec_prep_task` completion so the live daemon's owner
                        // loop NEVER suspends polling new connections, heartbeat, shutdown, or
                        // room presence while preparing or checking `release_sync.lock`.
                        let target_for_prep = cur.install_path.clone();
                        let expected_sha = cur.expected_sha;
                        let handle = tokio::task::spawn_blocking(move || {
                            let home_dir = chinwag_cli::release_sync::resolve_home_dir()?;
                            chinwag_cli::release_sync::prepare_immutable_reexec_binary(
                                &home_dir,
                                &target_for_prep,
                                &expected_sha,
                            )
                        });
                        reexec_prep_task = Some(InFlightReexecPrep {
                            target_path: cur.install_path,
                            expected_sha,
                            generation: cur.generation,
                            handle,
                        });
                    } else {
                        reexec_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + Duration::from_millis(100));
                    }
                }
            }
            (prep_path, prep_sha, prep_generation, prep_res) = poll_reexec_prep(&mut reexec_prep_task), if reexec_prep_task.is_some() => {
                match complete_reexec_prep_step(
                    prep_path,
                    prep_sha,
                    prep_generation,
                    prep_res,
                    stdout,
                    startup_chinwag_sha256,
                    forwards.is_empty(),
                    forward_rx.is_empty(),
                    &release_done_rx,
                    &release_job_gate,
                    &mut pending_reexec,
                    &mut reexec_prep_retries,
                    ReleaseDaemonScheduler::backoff_for_attempt,
                ) {
                    ReexecPrepStepOutcome::CommitReexec {
                        install_path,
                        prepared,
                    } => {
                        pinned_reexec = Some((install_path, prepared));
                        reexec_requested = true;
                        break;
                    }
                    ReexecPrepStepOutcome::RescheduleTimer(delay) => {
                        reexec_sleep
                            .as_mut()
                            .reset(tokio::time::Instant::now() + delay);
                    }
                    ReexecPrepStepOutcome::StayOnlineDisarmed => {}
                }
            }
            original = forward_rx.recv(), if network.is_some() && forwards.is_empty() => {
                if let (Some(message), Some((selection, gate))) = (original, &network) {
                    forwarding_original = Some((message.id.clone(), message.digest_sha256.clone()));
                    let endpoint = endpoint.clone(); let selection = selection.clone(); let gate = gate.clone();
                    forwards.spawn(async move {
                        let result = forward_original(&endpoint, &selection, &gate, &message).await;
                        (message, result)
                    });
                }
            }
            finished = forwards.join_next(), if !forwards.is_empty() => {
                if let Some((id, digest)) = forwarding_original.take()
                    && matches!(finished, Some(Err(_)))
                    && let Ok(mut cache) = receipts.lock() {
                        cache.finish(&id, &digest, FederationObservation::Unknown { phase:"forward_worker_lost".into() });
                    }
                if let Some(Ok((message, result))) = finished {
                    let id = &message.id;
                    let digest = &message.digest_sha256;
                    let outcome = match &result {
                        Ok((path, seq)) => {
                            let Some((selection, _)) = &network else { continue; };
                            FederationObservation::RemoteJournalAcknowledged { receipt: RemotePublication {
                                peer_endpoint_id: path.peer_endpoint_id.clone(), remote_sequence: *seq,
                                room: message.room.clone(), configuration_id: selection.configuration_id().into(),
                                configuration_generation: selection.generation(), acknowledged_at_unix: unix_now(),
                                selected_transport: path.selected_transport.into(), remote_address: path.remote_address.clone(),
                            } }
                        }
                        Err(failure) => FederationObservation::Unknown { phase: failure.category().into() },
                    };
                    if let Ok(mut cache) = receipts.lock() { cache.finish(id, digest, outcome); }
                    let record = match result {
                        Ok((path, seq)) => json!({"event":"native_federation_ack", "original_id":id,
                            "original_digest_sha256":digest, "scope":"REMOTE_JOURNAL_PUBLICATION_ONLY",
                            "path":path, "remote_sequence":seq, "processing":"UNKNOWN", "work_started":"UNKNOWN"}),
                        Err(failure) => json!({"event":"native_federation_unknown", "original_id":id,
                            "original_digest_sha256":digest, "phase":failure.category(), "automatic_retry":false}),
                    };
                    let _ = writeln!(stdout, "{record}"); let _ = stdout.flush();
                }
            }
            scheduled = heartbeat.tick() => {
                let tick_late_ms = scheduled.elapsed().as_millis();
                let scan_started = Instant::now();
                let count = count_parseable_journal_messages(&repo_root) as u64;
                let journal_scan_ms = scan_started.elapsed().as_millis();
                let state_started = Instant::now();
                let update = state.lock().map_err(|_| ()).and_then(|mut guard| {
                    guard.last_heartbeat = unix_now();
                    guard.total_messages = count;
                    write_daemon_state(&repo_root, &guard)
                });
                let record = json!({"event":"native_bus_heartbeat_timing",
                    "tick_late_ms":tick_late_ms,"journal_scan_ms":journal_scan_ms,
                    "state_replace_ms":state_started.elapsed().as_millis(),
                    "state_update_ok":update.is_ok(),"scope":"DIAGNOSTIC_NOT_TASK_AUTHORITY"});
                let _ = writeln!(stdout, "{record}");
                let _ = stdout.flush();
                if update.is_err() {
                    let _ = writeln!(stdout, "chinwag bus HELD: diagnostic state update failed");
                    exit_code = 1;
                    break;
                }
                if let Some(job_tx) = &release_job_tx {
                    let overflow_seen =
                        release_reconcile_needed.swap(false, std::sync::atomic::Ordering::SeqCst);
                    let should_send = retry_scheduler
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .poll_catchup_dispatch(overflow_seen, Instant::now());
                    if should_send
                        && try_enqueue_release_job(
                            job_tx,
                            &release_job_gate,
                            ReleaseDaemonJob::StartupCatchup,
                        )
                        .is_err()
                    {
                        retry_scheduler
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .on_catchup_send_full();
                    }
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
                let subscriptions = subscriptions.clone();
                let publications = publications.clone();
                let daemon_ep = endpoint_id.clone();
                let state_error = state_error_tx.clone();
                let receipts = receipts.clone();
                let release_queue = release_job_tx.clone();
                let release_reconcile = release_reconcile_needed.clone();
                let release_gate = release_job_gate.clone();
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
                        Ok(BusFrame::FederationReceipt { original_id, original_digest_sha256 }) => {
                            if !local_publisher_path(conn) || !valid_receipt_query(&original_id, &original_digest_sha256) {
                                conn.close(0x403u32.into(), b"local_query_refused"); return;
                            }
                            let observation = receipts.lock().map(|cache| cache.get(&original_id, &original_digest_sha256))
                                .unwrap_or_else(|_| FederationObservation::Unknown { phase:"cache_unavailable".into() });
                            let response = json!({"schema":"chinwag.federation-receipt.v1", "daemon_endpoint_id":daemon_ep,
                                "original_id":original_id,"original_digest_sha256":original_digest_sha256,
                                "federation":observation,"scope":"REMOTE_JOURNAL_PUBLICATION_ONLY",
                                "retention":"BOUNDED_PROCESS_LOCAL_CACHE_ONLY", "processing":"UNKNOWN",
                                "work_started":"UNKNOWN", "automatic_retry":false});
                            send_local_observation(&mut send, response).await; return;
                        }
                        Ok(BusFrame::NetworkPosture) => {
                            if !local_publisher_path(conn) { conn.close(0x403u32.into(), b"local_query_refused"); return; }
                            let posture = network.as_ref().map(|(selection, gate)| selection.posture(gate))
                                .unwrap_or_else(|| json!({"mode":"LEGACY_LOCAL_ONLY"}));
                            let response = json!({"schema":"chinwag.network-posture.v1", "daemon_endpoint_id":daemon_ep,
                                "network":posture,"scope":"CONFIGURATION_AND_GATE_OBSERVATION_ONLY",
                                "socket_liveness":"UNKNOWN", "current_selected_path":"NOT_OBSERVED",
                                "processing":"UNKNOWN", "work_started":"UNKNOWN"});
                            send_local_observation(&mut send, response).await; return;
                        }
                        Ok(BusFrame::JournalSubscribe { subscription_id, timeout_secs }) => {
                            if !local_publisher_path(conn) || !(1..=3600).contains(&timeout_secs) {
                                conn.close(0x403u32.into(), b"local_wait_refused"); return;
                            }
                            let subscribed = subscriptions.lock().map(|mut table| {
                                table.register(&subscription_id, Duration::from_secs(timeout_secs), &tx_clone)
                            }).unwrap_or(false);
                            send_local_observation(&mut send, json!({"schema":"chinwag.bus.journal-subscription.v1",
                                "daemon_endpoint_id":daemon_ep,"subscription_id":subscription_id,"subscribed":subscribed})).await;
                            return;
                        }
                        Ok(BusFrame::JournalUnsubscribe { subscription_id }) => {
                            if !local_publisher_path(conn) { conn.close(0x403u32.into(), b"local_wait_refused"); return; }
                            if let Ok(mut table) = subscriptions.lock() { table.cancel(&subscription_id); }
                            send_local_observation(&mut send, json!({"schema":"chinwag.bus.journal-subscription.v1",
                                "daemon_endpoint_id":daemon_ep,"subscription_id":subscription_id,"cancelled":true})).await;
                            return;
                        }
                        Ok(BusFrame::JournalChanged { observed_len, observed_inode, timeout_secs, subscription_id }) => {
                            if !local_publisher_path(conn) || !(1..=3600).contains(&timeout_secs) {
                                conn.close(0x403u32.into(), b"local_wait_refused"); return;
                            }
                            // Subscribe before comparing the client's catch-up mark.
                            // No filesystem/state lock spans the asynchronous wait.
                            let registered = if let Some(id) = subscription_id {
                                let receiver = { subscriptions.lock().ok().and_then(|mut table| table.take(&id)) };
                                let Some(receiver) = receiver else { conn.close(0x403u32.into(), b"subscription_missing"); return; };
                                Some(receiver)
                            } else { None };
                            let changed = if let Some(mut receiver) = registered {
                                tokio::time::timeout(Duration::from_secs(timeout_secs), receiver.recv()).await.is_ok()
                            } else { native_journal_change_hint(&tx_clone, Duration::from_secs(timeout_secs), || {
                                let mark = fs::symlink_metadata(messages_jsonl_path(&repo_clone)).ok().map(|m| {
                                    use std::os::unix::fs::MetadataExt;
                                    (m.len(), m.ino())
                                }).unwrap_or((0,0));
                                mark != (observed_len, observed_inode)
                            }).await };
                            let response = json!({"schema":"chinwag.bus.journal-change.v1","daemon_endpoint_id":daemon_ep,
                                "observed_len":observed_len,"observed_inode":observed_inode,"changed":changed,
                                "scope":"LOCAL_CHANGE_HINT_ONLY"});
                            send_local_observation(&mut send, response).await; return;
                        }
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
                    if result.is_ok()
                        && chinwag_cli::release_sync::is_release_built_candidate(&message)
                        && let Some(queue) = &release_queue
                        && try_enqueue_release_job(
                            queue,
                            &release_gate,
                            ReleaseDaemonJob::LiveMessage(Box::new(message.clone())),
                        )
                        .is_err()
                    {
                        release_reconcile.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
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
    // Cancel the one driver (and its renewal guard) before explicit close.
    drop(room_driver);
    if let Some(session) = &mut room_session {
        session.close().await;
    }
    endpoint.close().await;
    handlers.shutdown().await;
    if let Some(in_flight) = reexec_prep_task.take()
        && let Ok(Ok(prepared)) = in_flight.handle.await
    {
        let _ = tokio::task::spawn_blocking(move || {
            chinwag_cli::release_sync::cleanup_prepared_reexec(prepared);
        })
        .await;
    }
    // Quiesce the dedicated release worker cleanly (on re-exec, `release_job_gate`
    // was already atomically frozen at `active_jobs == 0 && release_done_rx.is_empty()`
    // BEFORE closing service, so zero post-close refresh is ever needed; on SIGTERM,
    // any in-flight installation finishes naturally before exit).
    let tearing_down_for_reexec = reexec_requested && exit_code == 0;
    quiesce_release_worker_and_drain_events(
        &mut release_job_tx,
        &mut release_done_tx_keepalive,
        &mut release_worker_handle,
        &mut release_done_rx,
        |release_event| {
            let _ = process_release_daemon_event(
                release_event,
                stdout,
                &repo_root,
                &endpoint_id,
                network.is_some(),
                &forward_tx,
                &publications,
                &tx,
                &state,
                startup_chinwag_sha256,
                tearing_down_for_reexec,
                &mut pending_reexec,
            );
        },
    )
    .await;
    forwards.shutdown().await;
    drop(publications);
    if reexec_requested
        && exit_code == 0
        && let Some((install_path, prepared)) = pinned_reexec.take()
    {
        let _ = writeln!(
            stdout,
            "{}",
            json!({
                "event": "native_daemon_reexec",
                "binary": install_path.to_string_lossy()
            })
        );
        let _ = stdout.flush();
        return DaemonOutcome::Reexec {
            install_path,
            prepared,
        };
    }
    if let Some((_, prepared)) = pinned_reexec.take() {
        let _ = tokio::task::spawn_blocking(move || {
            chinwag_cli::release_sync::cleanup_prepared_reexec(prepared);
        })
        .await;
    }
    DaemonOutcome::Exit(exit_code)
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
        id: msg_id,
        seq: 0,
        ts_unix,
        ts_iso,
        room: room_norm,
        sender,
        sender_cast,
        sender_endpoint_id,
        to,
        task_id,
        body: body.to_string(),
        digest_sha256: digest,
        pubkey_ed25519: None,
        signature_ed25519: None,
        sig_verified: false,
    };
    sign_bus_message(&mut msg, &signing_secret);
    let explicit_route = std::env::var_os("CHINWAG_BUS_ADDR").is_some()
        || std::env::var_os("CHINWAG_BUS_ENDPOINT_ID").is_some();
    let daemon =
        read_daemon_state_strict(repo_root).map_err(|_| InstanceError::PublicationRejected)?;
    publish_prebuilt_bus_message_sync_over_resolved_route(
        repo_root,
        msg,
        transport_secret,
        daemon,
        explicit_route,
    )
}

pub fn publish_prebuilt_bus_message_sync(
    repo_root: &Path,
    msg: BusMessage,
) -> Result<(BusMessage, BusAck), InstanceError> {
    let explicit_route = std::env::var_os("CHINWAG_BUS_ADDR").is_some()
        || std::env::var_os("CHINWAG_BUS_ENDPOINT_ID").is_some();
    let daemon =
        read_daemon_state_strict(repo_root).map_err(|_| InstanceError::PublicationRejected)?;
    let transport_secret = actor_transport_secret(&msg.sender);
    publish_prebuilt_bus_message_sync_over_resolved_route(
        repo_root,
        msg,
        transport_secret,
        daemon,
        explicit_route,
    )
}

#[derive(Debug, Clone)]
struct ResolvedReleasePublishRoute {
    daemon: Option<DaemonState>,
    explicit_route: bool,
}

fn resolve_release_publish_daemon_route(
    selected: &chinwag_cli::execution_binding::RepositorySelection,
) -> Result<ResolvedReleasePublishRoute, InstanceError> {
    let addr = std::env::var_os("CHINWAG_BUS_ADDR");
    let ep = std::env::var_os("CHINWAG_BUS_ENDPOINT_ID");
    resolve_release_publish_daemon_route_with_env(selected, addr.as_deref(), ep.as_deref())
}

fn resolve_release_publish_daemon_route_with_env(
    selected: &chinwag_cli::execution_binding::RepositorySelection,
    explicit_address: Option<&std::ffi::OsStr>,
    explicit_endpoint: Option<&std::ffi::OsStr>,
) -> Result<ResolvedReleasePublishRoute, InstanceError> {
    selected
        .revalidate()
        .map_err(|_| InstanceError::PublicationRejected)?;
    let exec_root = selected.execution_root();
    if let Some(route) = explicit_daemon_route_os(exec_root, explicit_address, explicit_endpoint)
        .map_err(|_| InstanceError::PublicationRejected)?
    {
        return Ok(ResolvedReleasePublishRoute {
            daemon: Some(route),
            explicit_route: true,
        });
    }
    if let Some(local_daemon) = read_verified_daemon_state_from_selected_root(exec_root)
        .map_err(|_| InstanceError::PublicationRejected)?
    {
        return Ok(ResolvedReleasePublishRoute {
            daemon: Some(local_daemon),
            explicit_route: false,
        });
    }
    if selected.is_linked_worktree() {
        let Some(common_root) = selected.common_worktree_root().filter(|p| *p != exec_root) else {
            return Err(InstanceError::PublicationRejected);
        };
        let common_selected = chinwag_cli::execution_binding::select_repository(
            chinwag_cli::execution_binding::RepoSelectors {
                explicit_repo: Some(common_root),
                environment_repo: None,
                cwd: common_root,
            },
        )
        .map_err(|_| InstanceError::PublicationRejected)?;
        common_selected
            .verify_effective_toplevel()
            .map_err(|_| InstanceError::PublicationRejected)?;
        if common_selected.is_linked_worktree()
            || !selected.same_common_git_identity(&common_selected)
        {
            return Err(InstanceError::PublicationRejected);
        }
        let Some(common_daemon) =
            read_verified_daemon_state_from_selected_root(common_selected.execution_root())
                .map_err(|_| InstanceError::PublicationRejected)?
        else {
            // Linked worktree with neither a live local daemon nor a live primary
            // checkout daemon must fail closed rather than creating an orphaned
            // split-brain `messages.jsonl` inside the linked worktree.
            return Err(InstanceError::PublicationRejected);
        };
        return Ok(ResolvedReleasePublishRoute {
            daemon: Some(common_daemon),
            explicit_route: false,
        });
    }
    Ok(ResolvedReleasePublishRoute {
        daemon: None,
        explicit_route: false,
    })
}

fn publish_prebuilt_bus_message_sync_over_resolved_route(
    repo_root: &Path,
    mut msg: BusMessage,
    transport_secret: SecretKey,
    daemon: Option<DaemonState>,
    explicit_route: bool,
) -> Result<(BusMessage, BusAck), InstanceError> {
    if !verify_detached_bus_signature(repo_root, &mut msg) {
        return Err(InstanceError::SigningIdentityUnavailable);
    }

    let msg_id = msg.id.clone();
    let room_norm = msg.room.clone();
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
  chinwag bus recovery diagnose --deployment ABSOLUTE_RECORD_JSON [--offline] --json
  chinwag bus recovery sop --json
  chinwag bus network-status [--repo <path>] --json
  chinwag bus receipt --id <ORIGINAL-ID> --digest <SHA256> [--repo <path>] --json
  chinwag bus daemon [--port <44330>] [--repo <path>] [--no-governors] [--no-release-sync]
  chinwag bus daemon --network-room-origin <HTTPS> --network-coordinator <PUBLIC-ID> --network-peer <PUBLIC-ID>
    --relay-origin <HTTPS> --expected-relay-origin <HTTPS> --network-configuration <ID> --network-generation <U64> [--relay-only]
  chinwag bus send --from <SEAT#INSTANCE> [--room <ROOM>] [--to <ADDRESS,...>] [--task <TASK-ID>] [--json] --message <BODY>
  chinwag bus send --from <SEAT> --instance <INSTANCE> [options] --message <BODY>
  chinwag bus inbox --for <SEAT#INSTANCE|SEAT> [--limit <N>] [--json]
  chinwag bus enroll-host --repo <physical-absolute-path> --for <SEAT#INSTANCE> --grant-file <owner-signed-0600-json> (--current-tail | --since-seq <N> --since-id <ID|GENESIS>)
  chinwag bus wait --repo <physical-absolute-path> --for <SEAT#INSTANCE> [--timeout-secs <1..3600>] --json
  chinwag bus wait-ack --repo <path> --for <SEAT#INSTANCE> --delivery-id <ID> --admission-request-id <ID> --msg-id <ID> --digest-sha256 <SHA256> --handoff-token-file <0600-path> --state <STATE> [--admission-id <ID>] [--turn-id <ID>]
  chinwag bus wait-reconcile --repo <path> --for <SEAT#INSTANCE> --owner-proof-file <owner-signed-0600-json>
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
Native wait emits a durable DATA_ONLY handoff; it does not itself start a host turn.
Owner enrollment/authority signatures and the pinned ~/.chinwag/signing/owner_ed25519.pub are required.
Wait exits: 0 handoff committed, 124 timeout, 75 uncertain/offline/unsupported. Raw tokens in argv are forbidden.
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

#[derive(Default)]
struct NativeWaitSubscription {
    active: std::cell::RefCell<Option<(DaemonState, String)>>,
}
fn wait_query(daemon: &DaemonState, frame: &BusFrame) -> Result<Value, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "WAKE_UNSUPPORTED")?;
    rt.block_on(query_local_daemon(daemon, frame))
        .map_err(|e| format!("WAKE_HOST_OFFLINE_OR_UNSUPPORTED: {e}"))
}
impl NativeWaitSubscription {
    fn cancel(&self) {
        if let Some((daemon, subscription_id)) = self.active.borrow_mut().take() {
            let _ = wait_query(&daemon, &BusFrame::JournalUnsubscribe { subscription_id });
        }
    }
    fn register(&self, repo: &Path, timeout_secs: u64) -> Result<(), String> {
        self.cancel();
        let daemon = read_daemon_state(repo).ok_or("WAKE_HOST_OFFLINE")?;
        let subscription_id = SecretKey::generate().public().to_string();
        let value = wait_query(
            &daemon,
            &BusFrame::JournalSubscribe {
                subscription_id: subscription_id.clone(),
                timeout_secs,
            },
        )?;
        if value["subscribed"] != true {
            return Err("WAKE_SUBSCRIPTION_REFUSED".into());
        }
        *self.active.borrow_mut() = Some((daemon, subscription_id));
        Ok(())
    }
    fn changed(
        &self,
        observed_len: u64,
        observed_inode: u64,
        timeout_secs: u64,
    ) -> Result<bool, String> {
        let (daemon, id) = self
            .active
            .borrow_mut()
            .take()
            .ok_or("WAKE_SUBSCRIPTION_MISSING")?;
        let value = wait_query(
            &daemon,
            &BusFrame::JournalChanged {
                observed_len,
                observed_inode,
                timeout_secs,
                subscription_id: Some(id),
            },
        )?;
        value["changed"]
            .as_bool()
            .ok_or_else(|| "WAKE_UNSUPPORTED".into())
    }
}
impl Drop for NativeWaitSubscription {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub fn run_bus_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if args.first().map(String::as_str) == Some("recovery") {
        return chinwag_cli::bus_recovery_run::run_recovery_cli(&args[1..], stdout, stderr);
    }
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    if matches!(sub, "wait" | "wait-ack" | "enroll-host" | "wait-reconcile") {
        let watcher = NativeWaitSubscription::default();
        return chinwag_cli::bus_wait_cli::run(
            args,
            stdout,
            stderr,
            |repo, timeout| watcher.register(repo, timeout),
            |_, observed_len, observed_inode, timeout_secs| {
                watcher.changed(observed_len, observed_inode, timeout_secs)
            },
        );
    }
    if sub == "--help" || sub == "-h" || sub == "help" {
        return print_bus_help(stdout);
    }

    let mut network_args = std::collections::BTreeMap::<String, String>::new();
    let mut relay_only = false;
    let mut no_governors = false;
    let mut no_release_sync = false;
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
    let mut original_id_arg = None;
    let mut original_digest_arg = None;
    let mut worktree_arg: Option<String> = None;
    let mut branch_arg: Option<String> = None;
    let mut surfaces_arg: Option<String> = None;
    let mut resolve_crisis = false;
    let mut binary_arg: Option<String> = None;
    let mut sha256_arg: Option<String> = None;
    let mut commit_arg: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--id" | "--digest" if sub == "receipt" => {
                let Some(value) = args.get(i + 1) else {
                    return 2;
                };
                let slot = if a == "--id" {
                    &mut original_id_arg
                } else {
                    &mut original_digest_arg
                };
                if slot.replace(value.clone()).is_some() {
                    return 2;
                }
                i += 2;
            }
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
            "--no-release-sync" => {
                if no_release_sync {
                    let _ = writeln!(stderr, "chinwag bus: duplicate_no_release_sync_flag");
                    return 2;
                }
                no_release_sync = true;
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
            "--worktree" if i + 1 < args.len() => {
                worktree_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--branch" if i + 1 < args.len() => {
                branch_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--surfaces" | "--surface-globs" if i + 1 < args.len() => {
                surfaces_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--resolve" | "--clear" => {
                resolve_crisis = true;
                i += 1;
            }
            "--binary" if i + 1 < args.len() => {
                binary_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--sha256" if i + 1 < args.len() => {
                sha256_arg = Some(args[i + 1].clone());
                i += 2;
            }
            "--commit" if i + 1 < args.len() => {
                commit_arg = Some(args[i + 1].clone());
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
    if (no_governors || no_release_sync) && sub != "daemon" {
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
    if !matches!(sub, "receipt" | "network-status" | "crisis" | "all-stop") {
        chinwag_cli::board::emit_active_crisis_alert_if_any(&repo_root, stderr);
    }

    match sub {
        "beacon" | "task-start" => {
            let sender_raw = from_arg.or_else(|| std::env::var("CHINWAG_ACTOR").ok());
            let Some(sender_raw) = sender_raw else {
                let _ = writeln!(stderr, "chinwag bus beacon: actor_required");
                return 2;
            };
            let sender = match resolve_actor_with_instance(&sender_raw, instance_arg.as_deref()) {
                Ok(value) => value,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus beacon: {error}");
                    return 2;
                }
            };
            let ticket_id = task_arg
                .clone()
                .or_else(|| positionals.first().cloned())
                .unwrap_or_else(|| "CHWG-0000".to_string());
            let worktree = worktree_arg.unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| repo_root.clone())
                    .to_string_lossy()
                    .to_string()
            });
            let branch = branch_arg.unwrap_or_else(|| {
                Command::new("git")
                    .args(["-C", &worktree, "rev-parse", "--abbrev-ref", "HEAD"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "main".to_string())
            });
            let mut surface_globs: Vec<String> = surfaces_arg
                .as_deref()
                .map(|raw| {
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if surface_globs.is_empty() {
                let issue_md = repo_root
                    .join(".chinwag/tasks/issues")
                    .join(format!("{ticket_id}.md"));
                if let Ok(raw) = fs::read_to_string(&issue_md)
                    && let Ok(iss) = chinwag_cli::board::AtomicTaskIssue::from_markdown(&raw)
                {
                    surface_globs = iss
                        .file_scope
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
            if surface_globs.is_empty() {
                surface_globs.push("*".to_string());
            }
            let surfaces_joined = surface_globs.join(", ");
            let live_threads =
                chinwag_cli::board::discover_live_thread_instances(&repo_root, Some(&sender));
            let to_recipients = if live_threads.is_empty() {
                None
            } else {
                Some(
                    live_threads
                        .iter()
                        .map(|t| format!("@{t}"))
                        .collect::<Vec<_>>()
                        .join(","),
                )
            };
            let body = format!(
                "[TASK-START BEACON] {sender} started {ticket_id} | worktree: {worktree} | branch: {branch} | surfaces: {surfaces_joined}"
            );
            let (msg, ack) = match send_bus_message_sync(
                &repo_root,
                &sender,
                "#all",
                to_recipients.clone(),
                Some(ticket_id.clone()),
                &body,
            ) {
                Ok(v) => v,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus beacon: {error}");
                    return 2;
                }
            };
            let collisions = chinwag_cli::board::detect_in_flight_surface_collisions(
                &repo_root,
                &ticket_id,
                &sender,
                &surface_globs,
            );
            let mut collision_warnings = Vec::new();
            for col in &collisions {
                let warn_to = if col.other_owner.contains('#') {
                    format!("@{},@ARCHITECT", col.other_owner)
                } else {
                    "@ARCHITECT".to_string()
                };
                let warn_body = format!(
                    "[SURFACE COLLISION WARNING] {sender} ({ticket_id}) and {} ({}) both have 03_IN_FLIGHT work touching overlapping surfaces: {}",
                    col.other_owner,
                    col.other_ticket_id,
                    col.overlapping_globs.join(", ")
                );
                if let Ok((wmsg, _)) = send_bus_message_sync(
                    &repo_root,
                    &sender,
                    "#eng",
                    Some(warn_to),
                    Some(ticket_id.clone()),
                    &warn_body,
                ) {
                    collision_warnings.push(wmsg.id);
                }
            }
            let out = json!({
                "ok": true,
                "invariant": "INV-LIVE-THREAD-WORKTREE-BEACON-01",
                "command": "chinwag bus beacon",
                "sender": sender,
                "ticket_id": ticket_id,
                "worktree": worktree,
                "branch": branch,
                "surfaces": surface_globs,
                "notified_live_threads": live_threads,
                "surface_collisions": collisions,
                "collision_warning_message_ids": collision_warnings,
                "message_id": msg.id,
                "seq": ack.seq,
                "sig_verified": ack.sig_verified,
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
                    "{}\n  ↳ Broadcast to {} live thread(s) ({} surface collision warning(s))",
                    format_bus_line(&msg),
                    live_threads.len(),
                    collisions.len()
                );
            }
            0
        }
        "crisis" | "all-stop" => {
            let sender_raw = from_arg.or_else(|| std::env::var("CHINWAG_ACTOR").ok());
            let Some(sender_raw) = sender_raw else {
                let _ = writeln!(stderr, "chinwag bus crisis: actor_required");
                return 2;
            };
            let sender = match resolve_actor_with_instance(&sender_raw, instance_arg.as_deref()) {
                Ok(value) => value,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus crisis: {error}");
                    return 2;
                }
            };
            let raw_msg = positionals.join(" ").trim().to_string();
            if raw_msg.is_empty() && !resolve_crisis {
                let _ = writeln!(
                    stderr,
                    "Usage: chinwag bus crisis --repo <path> --from <SEAT#INSTANCE> [--task <ID>] [--resolve] \"<message>\""
                );
                return 2;
            }
            let live_threads =
                chinwag_cli::board::discover_live_thread_instances(&repo_root, Some(&sender));
            let to_recipients = if live_threads.is_empty() {
                None
            } else {
                Some(
                    live_threads
                        .iter()
                        .map(|t| format!("@{t}"))
                        .collect::<Vec<_>>()
                        .join(","),
                )
            };
            let prefix = if resolve_crisis {
                "[✅ CRISIS RESOLVED]"
            } else {
                "[🚨 CRISIS ALL-STOP]"
            };
            let body = if raw_msg.is_empty() {
                format!("{prefix} Crisis resolved by {sender}")
            } else {
                format!("{prefix} {raw_msg}")
            };
            let rooms = if resolve_crisis {
                vec!["#all"]
            } else {
                vec!["#all", "#eng", "#mgmt"]
            };
            let mut published_ids = Vec::new();
            for room in rooms {
                match send_bus_message_sync(
                    &repo_root,
                    &sender,
                    room,
                    to_recipients.clone(),
                    task_arg.clone(),
                    &body,
                ) {
                    Ok((m, _)) => published_ids.push(m.id),
                    Err(error) => {
                        let _ = writeln!(stderr, "chinwag bus crisis: {error}");
                        return 2;
                    }
                }
            }
            let record = chinwag_cli::board::ActiveCrisisRecord {
                schema: "chinwag.bus.crisis.v1".to_string(),
                invariant: "INV-CRISIS-ALL-STOP-BROADCAST-01".to_string(),
                active: !resolve_crisis,
                sender: sender.clone(),
                task_id: task_arg.clone(),
                message: if raw_msg.is_empty() {
                    body.clone()
                } else {
                    raw_msg
                },
                ts_unix: unix_now(),
                ts_iso: iso_now(),
                notified_threads: live_threads.clone(),
            };
            let _ = chinwag_cli::board::write_active_crisis(&repo_root, &record);
            let out = json!({
                "ok": true,
                "invariant": "INV-CRISIS-ALL-STOP-BROADCAST-01",
                "command": "chinwag bus crisis",
                "active": record.active,
                "sender": sender,
                "notified_live_threads": live_threads,
                "published_message_ids": published_ids,
                "active_crisis_path": chinwag_cli::board::active_crisis_path(&repo_root).to_string_lossy(),
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
                    "{body}\n  ↳ Multicast to #all, #eng, #mgmt and {} live thread(s) across all models",
                    live_threads.len()
                );
            }
            0
        }
        "release-notes" | "release" => {
            let sender_raw = from_arg.or_else(|| std::env::var("CHINWAG_ACTOR").ok());
            let Some(sender_raw) = sender_raw else {
                let _ = writeln!(stderr, "chinwag bus release-notes: actor_required");
                return 2;
            };
            let sender = match resolve_actor_with_instance(&sender_raw, instance_arg.as_deref()) {
                Ok(value) => value,
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus release-notes: {error}");
                    return 2;
                }
            };
            let binary_name = binary_arg.unwrap_or_else(|| "chinwag".to_string());
            let sha256_hex = sha256_arg.unwrap_or_else(|| "unspecified".to_string());
            let commit_sha = commit_arg.unwrap_or_else(|| "HEAD".to_string());
            let notes = positionals.join(" ").trim().to_string();
            if notes.is_empty() {
                let _ = writeln!(
                    stderr,
                    "Usage: chinwag bus release-notes --repo <path> --from <SEAT#INSTANCE> --binary <chinwag|chinwag-ci> --sha256 <hex> --commit <sha> \"<release-notes>\""
                );
                return 2;
            }
            let live_threads =
                chinwag_cli::board::discover_live_thread_instances(&repo_root, Some(&sender));
            let to_recipients = if live_threads.is_empty() {
                None
            } else {
                Some(
                    live_threads
                        .iter()
                        .map(|t| format!("@{t}"))
                        .collect::<Vec<_>>()
                        .join(","),
                )
            };
            let body = format!(
                "[BINARY-RELEASE-NOTES] binary: {binary_name} | commit: {commit_sha} | sha256: {sha256_hex} | {notes}"
            );
            let mut published_ids = Vec::new();
            for room in ["#all", "#eng"] {
                match send_bus_message_sync(
                    &repo_root,
                    &sender,
                    room,
                    to_recipients.clone(),
                    task_arg.clone(),
                    &body,
                ) {
                    Ok((m, _)) => published_ids.push(m.id),
                    Err(error) => {
                        let _ = writeln!(stderr, "chinwag bus release-notes: {error}");
                        return 2;
                    }
                }
            }
            let out = json!({
                "ok": true,
                "invariant": "INV-BINARY-RELEASE-BROADCAST-01",
                "command": "chinwag bus release-notes",
                "binary": binary_name,
                "commit": commit_sha,
                "sha256": sha256_hex,
                "notified_live_threads": live_threads,
                "published_message_ids": published_ids,
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
                    "{body}\n  ↳ Release notes multicast to #all, #eng and {} live thread(s)",
                    live_threads.len()
                );
            }
            0
        }
        "receipt" | "network-status" => {
            let frame = if sub == "receipt" {
                let (Some(original_id), Some(original_digest_sha256)) =
                    (original_id_arg, original_digest_arg)
                else {
                    let _ = writeln!(
                        stderr,
                        "chinwag bus receipt: exact --id and --digest required"
                    );
                    return 2;
                };
                if !valid_receipt_query(&original_id, &original_digest_sha256) {
                    let _ = writeln!(stderr, "chinwag bus receipt: invalid original identity");
                    return 2;
                }
                BusFrame::FederationReceipt {
                    original_id,
                    original_digest_sha256,
                }
            } else {
                BusFrame::NetworkPosture
            };
            let Some(daemon) = read_daemon_state(&repo_root) else {
                let _ = writeln!(
                    stderr,
                    "chinwag bus: selected local daemon unavailable; observation UNKNOWN"
                );
                return 2;
            };
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return 2;
            };
            match runtime.block_on(query_local_daemon(&daemon, &frame)) {
                Ok(observation) => {
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&observation).unwrap_or_default()
                    );
                    0
                }
                Err(error) => {
                    let _ = writeln!(stderr, "chinwag bus: {error}; observation UNKNOWN");
                    2
                }
            }
        }
        "worker" => scheduler_admission_required(stderr),
        "daemon" => {
            let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            else {
                let _ = writeln!(stderr, "chinwag bus: failed to initialize tokio runtime");
                return 1;
            };
            let outcome = rt.block_on(run_daemon_loop_reexecable(
                repo_root.clone(),
                port_arg,
                network_selection,
                no_governors,
                daemon_release_sync_enabled(no_release_sync),
                stdout,
                async {
                    let _ = tokio::signal::ctrl_c().await;
                },
                None,
            ));
            drop(rt);
            match outcome {
                DaemonOutcome::Exit(code) => code,
                DaemonOutcome::Reexec {
                    install_path,
                    prepared,
                } => {
                    use std::os::unix::process::CommandExt;
                    if let Err(err) = rustix::process::fchdir(&prepared.dir_fd) {
                        let _ =
                            writeln!(stderr, "chinwag bus daemon: re-exec fchdir refused: {err}");
                        chinwag_cli::release_sync::cleanup_prepared_reexec(prepared);
                        return 1;
                    }
                    let reexec_args = build_canonical_daemon_reexec_args(args, &repo_root);
                    let _ = writeln!(
                        stdout,
                        "chinwag bus daemon: re-executing pinned immutable binary {} (source {})",
                        prepared.binary_path.display(),
                        install_path.display()
                    );
                    let _ = stdout.flush();
                    let _ = stderr.flush();
                    let err = Command::new("./chinwag")
                        .arg0("chinwag")
                        .args(&reexec_args)
                        .exec();
                    let _ = writeln!(stderr, "chinwag bus daemon: re-exec failed: {err}");
                    if let Ok(home_dir) = chinwag_cli::release_sync::resolve_home_dir() {
                        let _ = std::env::set_current_dir(&home_dir);
                    }
                    chinwag_cli::release_sync::cleanup_prepared_reexec(prepared);
                    1
                }
            }
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
            if let Some(ref ticket) = task_arg {
                let mark_done = body.contains("COMPLETED") || body.contains("SHIPPED");
                let _ = chinwag_cli::board::upsert_agent_thread_board_card(
                    &repo_root,
                    ticket,
                    &sender,
                    to_arg.as_deref(),
                    &body,
                    mark_done,
                    Some(&msg.digest_sha256),
                    "bus_send",
                );
            }
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

fn print_release_help(stdout: &mut dyn Write) -> u8 {
    let _ = writeln!(
        stdout,
        r#"Usage:
  chinwag release publish --binary <chinwag|chinwag-ci> --source <PATH> [--repo <PATH>] [--from <INFRAJR#INSTANCE>] [--rollback] [--json]
  chinwag release sync [--repo <PATH>] [--json]
  chinwag release status [--json]

Symmetric Bus Release Auto-Installer:
  publish  Verifies codesign & --version, hashes SHA-256 + BLAKE3, uploads content-addressed R2 blob, installs locally, and broadcasts signed RELEASE_BUILT on #all.
  sync     Replays verified INFRAJR RELEASE_BUILT manifests from the local bus journal against content-addressed R2 blobs with pre-exec SHA-256 + BLAKE3 verification.
  status   Reports local ~/.local/bin/{{chinwag,chinwag-ci}} digests and ~/.chinwag/release_sync_state.json monotonic watermarks."#
    );
    0
}

pub fn run_release_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let Some(sub) = args.first().map(String::as_str) else {
        return print_release_help(stdout);
    };
    if matches!(sub, "--help" | "-h" | "help") {
        return print_release_help(stdout);
    }

    let mut binary_arg: Option<String> = None;
    let mut source_arg: Option<String> = None;
    let mut repo_arg: Option<String> = None;
    let mut from_arg: Option<String> = None;
    let mut rollback = false;
    let mut is_json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => return print_release_help(stdout),
            "--json" => {
                is_json = true;
                i += 1;
            }
            "--rollback" if sub == "publish" => {
                rollback = true;
                i += 1;
            }
            "--binary" if sub == "publish" => {
                let Some(val) = args.get(i + 1).filter(|v| !v.starts_with('-')) else {
                    let _ = writeln!(stderr, "chinwag release: --binary requires a value");
                    return 2;
                };
                if binary_arg.replace(val.clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag release: duplicate --binary");
                    return 2;
                }
                i += 2;
            }
            "--source" if sub == "publish" => {
                let Some(val) = args.get(i + 1).filter(|v| !v.starts_with('-')) else {
                    let _ = writeln!(stderr, "chinwag release: --source requires a value");
                    return 2;
                };
                if source_arg.replace(val.clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag release: duplicate --source");
                    return 2;
                }
                i += 2;
            }
            "--repo" if matches!(sub, "publish" | "sync") => {
                let Some(val) = args.get(i + 1).filter(|v| !v.starts_with('-')) else {
                    let _ = writeln!(stderr, "chinwag release: --repo requires a value");
                    return 2;
                };
                if repo_arg.replace(val.clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag release: duplicate --repo");
                    return 2;
                }
                i += 2;
            }
            "--from" if sub == "publish" => {
                let Some(val) = args.get(i + 1).filter(|v| !v.starts_with('-')) else {
                    let _ = writeln!(stderr, "chinwag release: --from requires a value");
                    return 2;
                };
                if from_arg.replace(val.clone()).is_some() {
                    let _ = writeln!(stderr, "chinwag release: duplicate --from");
                    return 2;
                }
                i += 2;
            }
            other => {
                let _ = writeln!(
                    stderr,
                    "chinwag release: unsupported argument `{other}` for subcommand `{sub}`"
                );
                return 2;
            }
        }
    }

    let home_dir = match chinwag_cli::release_sync::resolve_home_dir() {
        Ok(dir) => dir,
        Err(err) => {
            let _ = writeln!(stderr, "chinwag release: {err}");
            return 1;
        }
    };

    match sub {
        "status" => match chinwag_cli::release_sync::collect_release_status_json(&home_dir) {
            Ok(status_val) => {
                if is_json {
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&status_val).unwrap_or_default()
                    );
                } else {
                    let target = status_val["target_triple"].as_str().unwrap_or("unknown");
                    let _ = writeln!(stdout, "Chinwag Symmetric Release Sync ({target})");
                    for bin in chinwag_cli::release_sync::ALLOWED_BINARIES {
                        let disk = &status_val["local_binaries"][bin];
                        let recorded = &status_val["recorded_state"]["binaries"][bin];
                        let present = disk["present"].as_bool().unwrap_or(false);
                        let sha = disk["sha256"].as_str().unwrap_or("absent");
                        let commit = recorded["git_commit"].as_str().unwrap_or("untracked");
                        let _ = writeln!(
                            stdout,
                            "  • {bin}: present={present} sha256={sha} recorded_commit={commit}"
                        );
                    }
                }
                0
            }
            Err(err) => {
                let _ = writeln!(stderr, "chinwag release status: {err}");
                1
            }
        },
        "publish" => {
            let (Some(binary), Some(source)) = (binary_arg.as_deref(), source_arg.as_deref())
            else {
                let _ = writeln!(
                    stderr,
                    "Usage: chinwag release publish --binary <chinwag|chinwag-ci> --source <PATH> [--repo <PATH>] [--from <INFRAJR#INSTANCE>] [--rollback] [--json]"
                );
                return 2;
            };
            if let Err(err) = chinwag_cli::release_sync::validate_binary_name(binary) {
                let _ = writeln!(stderr, "chinwag release publish: {err}");
                return 2;
            }
            let selected = match resolve_repo_root(repo_arg.as_deref()) {
                Ok(selected) => selected,
                Err(error) => {
                    let _ = writeln!(
                        stderr,
                        "chinwag release publish: repository selection refused: {error}"
                    );
                    return 2;
                }
            };
            if let Err(error) = selected.revalidate() {
                let _ = writeln!(
                    stderr,
                    "chinwag release publish: repository selection refused: {error}"
                );
                return 2;
            }
            let repo_root = selected.execution_root().to_path_buf();
            // Preflight daemon route before R2 upload or local `~/.local/bin` mutation so
            // invalid explicit env routes, tampered/symlinked `daemon.json`, or offline
            // linked worktrees fail closed before any side effect.
            if let Err(err) = resolve_release_publish_daemon_route(&selected) {
                let _ = writeln!(
                    stderr,
                    "chinwag release publish: daemon route refused: {err}"
                );
                return 2;
            }
            let store = chinwag_cli::release_sync::WranglerR2ArtifactStore::new(home_dir.clone());
            let req = chinwag_cli::release_sync::PublishReleaseRequest {
                home_dir: &home_dir,
                repo_root: &repo_root,
                binary,
                source_binary_path: Path::new(source),
                explicit_from: from_arg.as_deref(),
                rollback,
                commit_override: None,
            };
            match chinwag_cli::release_sync::publish_release(req, &store, |msg| {
                let route =
                    resolve_release_publish_daemon_route(&selected).map_err(|e| e.to_string())?;
                let transport_secret = actor_transport_secret(&msg.sender);
                publish_prebuilt_bus_message_sync_over_resolved_route(
                    &repo_root,
                    msg.clone(),
                    transport_secret,
                    route.daemon,
                    route.explicit_route,
                )
                .map(|(_, ack)| ack.seq)
                .map_err(|e| e.to_string())
            }) {
                Ok(outcome) => {
                    if is_json {
                        let out = json!({
                            "ok": true,
                            "manifest": outcome.manifest,
                            "install_path": outcome.install_path.to_string_lossy(),
                            "previous_backup_path": outcome.previous_backup_path.as_ref().map(|p| p.to_string_lossy()),
                            "message_id": outcome.release_built_message.id,
                            "bus_seq": outcome.bus_seq,
                            "crate_memory_synced": outcome.crate_memory_synced,
                        });
                        let _ = writeln!(
                            stdout,
                            "{}",
                            serde_json::to_string_pretty(&out).unwrap_or_default()
                        );
                    } else {
                        let _ = writeln!(
                            stdout,
                            "✓ Published RELEASE_BUILT for {} ({} @ {})\n  • SHA-256: {}\n  • BLAKE3:  {}\n  • R2 Key:  r2://{}/{}\n  • Bus Seq: {} ({})",
                            outcome.manifest.binary,
                            outcome.manifest.target_triple,
                            outcome.manifest.git_commit,
                            outcome.manifest.sha256,
                            outcome.manifest.blake3,
                            chinwag_cli::release_sync::R2_BUCKET_NAME,
                            outcome.manifest.artifact_key,
                            outcome.bus_seq,
                            outcome.release_built_message.id
                        );
                    }
                    0
                }
                Err(err) => {
                    let _ = writeln!(stderr, "chinwag release publish: {err}");
                    1
                }
            }
        }
        "sync" => {
            let selected = match resolve_repo_root(repo_arg.as_deref()) {
                Ok(selected) => selected,
                Err(error) => {
                    let _ = writeln!(
                        stderr,
                        "chinwag release sync: repository selection refused: {error}"
                    );
                    return 2;
                }
            };
            if let Err(error) = selected.revalidate() {
                let _ = writeln!(
                    stderr,
                    "chinwag release sync: repository selection refused: {error}"
                );
                return 2;
            }
            let repo_root = selected.execution_root().to_path_buf();
            let local_iroh = read_daemon_state(&repo_root)
                .map(|s| s.endpoint_id)
                .or_else(|| {
                    load_or_create_daemon_secret(&repo_root)
                        .ok()
                        .map(|k| k.public().to_string())
                });
            let store = chinwag_cli::release_sync::WranglerR2ArtifactStore::new(home_dir.clone());
            let journal_path = messages_jsonl_path(&repo_root);
            match chinwag_cli::release_sync::sync_releases_from_journal_per_binary(
                &home_dir,
                &journal_path,
                &store,
                local_iroh.as_deref(),
            ) {
                Ok(reports) => {
                    let mut rows = Vec::new();
                    let mut had_error = false;
                    for report in reports {
                        let binary = report.binary;
                        match report.outcome {
                            Ok(chinwag_cli::release_sync::ReleaseApplyOutcome::Installed {
                                manifest,
                                install_path,
                                receipt_message,
                                ..
                            }) => {
                                if let Some(receipt) = receipt_message {
                                    let _ = publish_prebuilt_bus_message_sync(&repo_root, *receipt);
                                }
                                rows.push(json!({
                                    "binary": binary,
                                    "status": "installed",
                                    "sha256": manifest.sha256,
                                    "git_commit": manifest.git_commit,
                                    "install_path": install_path.to_string_lossy(),
                                }));
                            }
                            Ok(
                                chinwag_cli::release_sync::ReleaseApplyOutcome::AlreadyInstalled {
                                    manifest,
                                    install_path,
                                },
                            ) => {
                                rows.push(json!({
                                    "binary": binary,
                                    "status": "already_installed",
                                    "sha256": manifest.sha256,
                                    "git_commit": manifest.git_commit,
                                    "install_path": install_path.to_string_lossy(),
                                }));
                            }
                            Ok(
                                chinwag_cli::release_sync::ReleaseApplyOutcome::SkippedTargetMismatch {
                                    manifest_target,
                                    local_target,
                                },
                            ) => {
                                rows.push(json!({
                                    "binary": binary,
                                    "status": "skipped_target_mismatch",
                                    "manifest_target": manifest_target,
                                    "local_target": local_target,
                                }));
                            }
                            Err(err) => {
                                had_error = true;
                                if !is_json {
                                    let _ =
                                        writeln!(stderr, "chinwag release sync ({binary}): {err}");
                                }
                                rows.push(json!({
                                    "binary": binary,
                                    "status": "error",
                                    "error": err.to_string(),
                                }));
                            }
                        }
                    }
                    if is_json {
                        let out = json!({
                            "ok": !had_error,
                            "outcomes": rows,
                        });
                        let _ = writeln!(
                            stdout,
                            "{}",
                            serde_json::to_string_pretty(&out).unwrap_or_default()
                        );
                    } else if rows.is_empty() {
                        let _ = writeln!(
                            stdout,
                            "chinwag release sync: no pending RELEASE_BUILT manifests"
                        );
                    } else {
                        for row in &rows {
                            let _ = writeln!(
                                stdout,
                                "  • {}: {} ({})",
                                row["binary"].as_str().unwrap_or("unknown"),
                                row["status"].as_str().unwrap_or("unknown"),
                                row["sha256"].as_str().unwrap_or("-")
                            );
                        }
                    }
                    u8::from(had_error)
                }
                Err(err) => {
                    let _ = writeln!(stderr, "chinwag release sync: {err}");
                    1
                }
            }
        }
        other => {
            let _ = writeln!(stderr, "chinwag release: unknown subcommand `{other}`");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic_count_fixture_row() -> serde_json::Value {
        json!({
            "id": "diagnostic-only", "seq": 1, "ts_unix": 1, "ts_iso": "",
            "room": "#test", "sender": "unregistered actor", "sender_cast": "",
            "sender_endpoint_id": "invalid endpoint", "to": null, "task_id": null,
            "body": "controlled fixture", "digest_sha256": "invalid digest"
        })
    }

    #[test]
    fn diagnostic_journal_count_matches_history_parse_eligibility_not_verification() {
        let repo = tempfile::tempdir().unwrap();
        let path = messages_jsonl_path(repo.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let unsigned = diagnostic_count_fixture_row();
        let mut invalid_signature = unsigned.clone();
        invalid_signature["pubkey_ed25519"] = json!("not a key");
        invalid_signature["signature_ed25519"] = json!("not a signature");
        let mut forged_verified = invalid_signature.clone();
        forged_verified["sig_verified"] = json!(true);
        forged_verified["to"] = json!("invalid recipient");
        let mut wrong_type = unsigned.clone();
        wrong_type["seq"] = json!("one");
        // CRLF, whitespace, rejected shapes, and a final row without newline.
        fs::write(
            &path,
            format!(
                " \r\n{unsigned}\r\nnot-json\n{{}}\n{wrong_type}\n  {invalid_signature}  \n{forged_verified}"
            ),
        )
        .unwrap();
        let history = read_all_messages(repo.path());
        assert_eq!(history.len(), 3);
        assert!(history.iter().all(|message| !message.sig_verified));
        assert_eq!(count_parseable_journal_messages(repo.path()), history.len());
    }

    #[test]
    fn diagnostic_journal_count_stops_at_first_invalid_utf8_line() {
        let repo = tempfile::tempdir().unwrap();
        let path = messages_jsonl_path(repo.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let row = diagnostic_count_fixture_row().to_string();
        let mut bytes = format!("{row}\n").into_bytes();
        bytes.extend_from_slice(b"\xff\n");
        bytes.extend_from_slice(row.as_bytes());
        fs::write(path, bytes).unwrap();
        assert_eq!(count_parseable_journal_messages(repo.path()), 1);
        assert_eq!(read_all_messages(repo.path()).len(), 1);
    }

    #[test]
    fn diagnostic_journal_count_open_failure_matches_empty_history() {
        let repo = tempfile::tempdir().unwrap();
        assert_eq!(count_parseable_journal_messages(repo.path()), 0);
        assert!(read_all_messages(repo.path()).is_empty());
        // Deterministic open failure, independent of the test user's privileges.
        fs::write(repo.path().join(".chinwag"), b"not a directory").unwrap();
        assert_eq!(count_parseable_journal_messages(repo.path()), 0);
        assert!(read_all_messages(repo.path()).is_empty());
    }

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

    #[test]
    fn release_cli_help_status_and_strict_flag_validation() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_release_cli(&["--help".to_owned()], &mut out, &mut err),
            0
        );
        assert!(String::from_utf8(out).unwrap().starts_with("Usage:"));
        assert!(err.is_empty());

        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_release_cli(
                &["status".to_owned(), "--json".to_owned()],
                &mut out,
                &mut err,
            ),
            0
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["schema"], "chinwag.release-status.v1");

        for bad in [
            vec!["unknown-sub"],
            vec!["status", "--bogus"],
            vec!["sync", "--from-r2"],
            vec!["sync", "--no-r2"],
            vec!["publish", "--binary", "../evil", "--source", "/bin/echo"],
            vec!["publish", "--binary"],
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let args: Vec<String> = bad.into_iter().map(str::to_owned).collect();
            assert_eq!(run_release_cli(&args, &mut out, &mut err), 2);
            assert!(out.is_empty());
            assert!(!err.is_empty());
        }
    }

    #[test]
    fn per_binary_retry_scheduler_bounds_chinwag_ci_despite_chinwag_success() {
        use chinwag_cli::release_sync::{
            CURRENT_TARGET_TRIPLE, MAX_RELEASE_SYNC_TRANSIENT_RETRIES, RELEASE_MANIFEST_SCHEMA,
            ReleaseApplyOutcome, ReleaseManifestV1, ReleaseSyncError, expected_artifact_key,
        };

        let sample_manifest =
            |binary: &str, target: &str, sha_byte: u8, epoch: u64, built_at_ms: u64| {
                let sha256 = format!("{sha_byte:02x}").repeat(32);
                let blake3 = format!("{:02x}", sha_byte.wrapping_add(1)).repeat(32);
                let artifact_key = expected_artifact_key(binary, target, &sha256);
                ReleaseManifestV1 {
                    schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
                    binary: binary.to_owned(),
                    target_triple: target.to_owned(),
                    git_commit: "abcd1234abcd1234".to_owned(),
                    commit_epoch: epoch,
                    built_at_ms,
                    sha256,
                    blake3,
                    size_bytes: 4096,
                    artifact_key,
                    rollback: false,
                }
            };

        let mut sched = ReleaseDaemonScheduler::default();
        let mut now = Instant::now();
        let expected_delays = [10u64, 20, 40, 80, 160, 300, 300, 300, 300, 300, 300, 300];
        let mut scheduled_delays = Vec::new();

        let cw_installed = sample_manifest("chinwag", CURRENT_TARGET_TRIPLE, 0x11, 100, 1000);
        let ci_old_installed =
            sample_manifest("chinwag-ci", CURRENT_TARGET_TRIPLE, 0x21, 100, 1000);
        let ci_failing = sample_manifest("chinwag-ci", CURRENT_TARGET_TRIPLE, 0x22, 200, 2000);
        let transient_err = ReleaseSyncError::ArtifactStoreFailed("r2 timeout".to_owned());

        for cycle in 0..20usize {
            // Healthy `chinwag` succeeds (`AlreadyInstalled`) on every cycle, AND foreign-target
            // `SkippedTargetMismatch` + older `AlreadyInstalled` replays for `chinwag-ci` arrive
            // alongside it — NONE may clear or reset `ci_failing`'s retry state!
            sched.on_outcome(&ReleaseApplyOutcome::AlreadyInstalled {
                manifest: cw_installed.clone(),
                install_path: PathBuf::from("/tmp/chinwag"),
            });
            sched.on_outcome(&ReleaseApplyOutcome::SkippedTargetMismatch {
                manifest_target: "x86_64-apple-darwin".to_owned(),
                local_target: CURRENT_TARGET_TRIPLE.to_owned(),
            });
            sched.on_outcome(&ReleaseApplyOutcome::AlreadyInstalled {
                manifest: ci_old_installed.clone(),
                install_path: PathBuf::from("/tmp/chinwag-ci"),
            });

            let delay = sched.on_manifest_failed(&ci_failing, &transient_err, now);
            if cycle < MAX_RELEASE_SYNC_TRANSIENT_RETRIES as usize {
                let d = delay.expect("expected scheduled retry within 12-attempt cap");
                scheduled_delays.push(d.as_secs());
                assert!(!sched.should_dispatch_catchup(now + Duration::from_secs(1)));
                now += d;
                assert!(sched.poll_catchup_dispatch(false, now));
                // Duplicate heartbeat ticks while catchup is queued do not enqueue twice.
                assert!(!sched.poll_catchup_dispatch(false, now));
                // Reset `catchup_queued` as worker execution would:
                let _ = chinwag_cli::release_sync::execute_release_daemon_job(
                    Path::new("/nonexistent"),
                    Path::new("/nonexistent/messages.jsonl"),
                    &chinwag_cli::release_sync::WranglerR2ArtifactStore::new(PathBuf::from(
                        "/nonexistent",
                    )),
                    "ep-test",
                    &Mutex::new(ReleaseDaemonScheduler::default()),
                    ReleaseDaemonJob::StartupCatchup,
                );
                sched.on_catchup_send_full();
            } else {
                assert_eq!(delay, None, "must stop retrying after 12 attempts");
                assert!(!sched.should_dispatch_catchup(now + Duration::from_secs(3600)));
            }
        }
        assert_eq!(scheduled_delays, expected_delays);

        // Publishing a genuinely NEW `chinwag-ci` release grants a fresh budget.
        let ci_newer = sample_manifest("chinwag-ci", CURRENT_TARGET_TRIPLE, 0x23, 300, 3000);
        let fresh = sched.on_manifest_failed(&ci_newer, &transient_err, now);
        assert_eq!(fresh, Some(Duration::from_secs(10)));
        sched.on_outcome(&ReleaseApplyOutcome::Installed {
            manifest: ci_newer,
            install_path: PathBuf::from("/tmp/chinwag-ci"),
            previous_backup_path: None,
            receipt_message: None,
        });
        assert!(!sched.should_dispatch_catchup(now + Duration::from_secs(600)));
    }

    #[test]
    fn retry_scheduler_queue_overflow_persists_until_catchup_dispatched() {
        let mut sched = ReleaseDaemonScheduler::default();
        let now = Instant::now();
        assert!(!sched.should_dispatch_catchup(now));
        assert!(sched.poll_catchup_dispatch(true, now));
        // Simulate `job_tx.try_send` full on heartbeat 1: `on_catchup_send_full` re-arms
        // dispatch while keeping `overflow_reconcile_pending` true for heartbeat 2.
        sched.on_catchup_send_full();
        assert!(sched.should_dispatch_catchup(now + Duration::from_secs(10)));
        assert!(sched.poll_catchup_dispatch(false, now + Duration::from_secs(10)));
    }

    #[test]
    fn pending_reexec_drain_predicate_and_canonical_reexec_args_preserve_repo() {
        assert!(should_complete_pending_reexec(
            true,
            true,
            true,
            Duration::from_millis(350)
        ));
        // Never begin re-exec teardown while the release worker is still busy,
        // even past the 5s forwarding drain ceiling!
        assert!(!should_complete_pending_reexec(
            true,
            true,
            false,
            Duration::from_secs(10)
        ));
        assert!(!should_complete_pending_reexec(
            false,
            true,
            true,
            Duration::from_secs(1)
        ));
        assert!(!should_complete_pending_reexec(
            true,
            false,
            true,
            Duration::from_millis(4999)
        ));
        assert!(should_complete_pending_reexec(
            false,
            false,
            true,
            Duration::from_secs(5)
        ));

        let canonical = Path::new("/tmp/canonical-chinwag-repo");
        let args_relative = vec![
            "daemon".to_owned(),
            "--repo".to_owned(),
            ".".to_owned(),
            "--port".to_owned(),
            "44100".to_owned(),
        ];
        assert_eq!(
            build_canonical_daemon_reexec_args(&args_relative, canonical),
            vec![
                std::ffi::OsString::from("bus"),
                std::ffi::OsString::from("daemon"),
                std::ffi::OsString::from("--repo"),
                std::ffi::OsString::from("/tmp/canonical-chinwag-repo"),
                std::ffi::OsString::from("--port"),
                std::ffi::OsString::from("44100"),
            ]
        );

        let args_omitted = vec!["daemon".to_owned(), "--no-governors".to_owned()];
        assert_eq!(
            build_canonical_daemon_reexec_args(&args_omitted, canonical),
            vec![
                std::ffi::OsString::from("bus"),
                std::ffi::OsString::from("daemon"),
                std::ffi::OsString::from("--repo"),
                std::ffi::OsString::from("/tmp/canonical-chinwag-repo"),
                std::ffi::OsString::from("--no-governors"),
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reexec_quiescence_waits_for_inflight_release_b_and_commits_latest_digest() {
        use chinwag_cli::release_sync::{
            CURRENT_TARGET_TRIPLE, RELEASE_MANIFEST_SCHEMA, ReleaseApplyOutcome, ReleaseManifestV1,
            clear_and_remove_immutable_dir, expected_artifact_key, local_binary_sha256,
            prepare_immutable_reexec_binary,
        };

        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        let bin_dir = home_dir.join(".local/bin");
        let build_dir = temp.path().join("build");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&build_dir).unwrap();

        let compile_signed_macho = |label: &str| -> (PathBuf, [u8; 32], String) {
            let src = build_dir.join(format!("{label}.c"));
            let out = build_dir.join(format!("chinwag-{label}"));
            fs::write(
                &src,
                format!("int main(void) {{ const char *v = \"{label}\"; (void)v; return 0; }}\n"),
            )
            .unwrap();
            let st = std::process::Command::new("/usr/bin/clang")
                .args(["-O2", "-o"])
                .arg(&out)
                .arg(&src)
                .status()
                .unwrap();
            assert!(st.success());
            let cs = std::process::Command::new("/usr/bin/codesign")
                .args(["-s", "-", "--force"])
                .arg(&out)
                .status()
                .unwrap();
            assert!(cs.success());
            let sha = local_binary_sha256(&out).unwrap();
            let sha_hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
            (out, sha, sha_hex)
        };

        let (bin_startup, sha_startup, sha_startup_hex) = compile_signed_macho("startup");
        let (bin_a, sha_a, sha_a_hex) = compile_signed_macho("release_a");
        let (bin_b, sha_b, sha_b_hex) = compile_signed_macho("release_b");
        assert_ne!(sha_a, sha_b);
        assert_ne!(sha_startup, sha_a);
        assert_ne!(sha_startup, sha_b);
        let _ = bin_startup;

        let install_path = bin_dir.join("chinwag");
        let make_manifest =
            |sha_hex: &str, epoch: u64, built_at_ms: u64, path: &Path| ReleaseManifestV1 {
                schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
                binary: "chinwag".to_owned(),
                target_triple: CURRENT_TARGET_TRIPLE.to_owned(),
                git_commit: format!("{epoch:016x}"),
                commit_epoch: epoch,
                built_at_ms,
                sha256: sha_hex.to_owned(),
                blake3: "bb".repeat(32),
                size_bytes: fs::metadata(path).unwrap().len(),
                artifact_key: expected_artifact_key("chinwag", CURRENT_TARGET_TRIPLE, sha_hex),
                rollback: false,
            };
        let manifest_a = make_manifest(&sha_a_hex, 100, 1_700_000_100, &bin_a);
        let manifest_b = make_manifest(&sha_b_hex, 200, 1_700_000_200, &bin_b);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let (selected_path, selected_sha) = rt.block_on(async {
            let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<ReleaseDaemonJob>(8);
            let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<ReleaseDaemonEvent>(8);
            let mut done_tx_keepalive = Some(done_tx.clone());
            let job_gate = Arc::new(Mutex::new(ReleaseJobQueueGate::default()));
            let b_entered_blocking = Arc::new(tokio::sync::Notify::new());

            // Enqueue two consecutive `chinwag` jobs (A then B) via gapless queue gate.
            try_enqueue_release_job(&job_tx, &job_gate, ReleaseDaemonJob::StartupCatchup).unwrap();
            try_enqueue_release_job(&job_tx, &job_gate, ReleaseDaemonJob::StartupCatchup).unwrap();
            assert_eq!(job_gate.lock().unwrap().active_jobs, 2);

            let gate_clone = job_gate.clone();
            let b_entered_clone = b_entered_blocking.clone();
            let install_for_worker = install_path.clone();
            let bin_a_clone = bin_a.clone();
            let bin_b_clone = bin_b.clone();
            let m_a = manifest_a.clone();
            let m_b = manifest_b.clone();

            let mut step = 0usize;
            let mut worker_handle = Some(tokio::spawn(async move {
                while let Some(_job) = job_rx.recv().await {
                    let _guard = ReleaseJobSlotGuard(gate_clone.clone());
                    step += 1;
                    let current_step = step;
                    let dst = install_for_worker.clone();
                    let src_a = bin_a_clone.clone();
                    let src_b = bin_b_clone.clone();
                    let ma = m_a.clone();
                    let mb = m_b.clone();
                    let notify_b = b_entered_clone.clone();

                    let ev = tokio::task::spawn_blocking(move || {
                        if current_step == 1 {
                            let tmp = dst.with_extension("tmp.a");
                            fs::copy(&src_a, &tmp).unwrap();
                            fs::rename(&tmp, &dst).unwrap();
                            ReleaseDaemonEvent::Applied {
                                binary: "chinwag".to_owned(),
                                outcome: Box::new(ReleaseApplyOutcome::Installed {
                                    manifest: ma,
                                    install_path: dst,
                                    previous_backup_path: None,
                                    receipt_message: None,
                                }),
                            }
                        } else {
                            notify_b.notify_one();
                            // Remain inside blocking installation longer than the 350ms re-exec timer!
                            std::thread::sleep(Duration::from_millis(450));
                            let tmp = dst.with_extension("tmp.b");
                            fs::copy(&src_b, &tmp).unwrap();
                            fs::rename(&tmp, &dst).unwrap();
                            ReleaseDaemonEvent::Applied {
                                binary: "chinwag".to_owned(),
                                outcome: Box::new(ReleaseApplyOutcome::Installed {
                                    manifest: mb,
                                    install_path: dst,
                                    previous_backup_path: None,
                                    receipt_message: None,
                                }),
                            }
                        }
                    })
                    .await
                    .unwrap();
                    done_tx.send(ev).await.unwrap();
                }
            }));

            let mut pending_reexec = PendingReexecSlot::default();
            let repo_dir = temp.path().join("repo");
            fs::create_dir_all(repo_dir.join(".chinwag/bus")).unwrap();
            let (bcast_tx, _) = broadcast::channel::<BusMessage>(16);
            let (fwd_tx, _) = tokio::sync::mpsc::channel::<BusMessage>(16);
            let publications = Mutex::new(NativePublication::open(&repo_dir).unwrap());
            let daemon_state = Mutex::new(DaemonState {
                ok: true,
                pid: 1,
                endpoint_id: "ep".into(),
                bound_sockets: vec![],
                alpns: vec![],
                repo_root: repo_dir.to_string_lossy().into_owned(),
                tasks_md: String::new(),
                messages_jsonl: String::new(),
                started_at: 0,
                last_heartbeat: 0,
                total_messages: 0,
                product_governor: String::new(),
                delivery_router: String::new(),
            });
            let mut sink = Vec::new();

            // Consume release A's completion event -> arms `pending_reexec` with A's digest.
            let ev_a = done_rx.recv().await.unwrap();
            assert!(process_release_daemon_event(
                ev_a,
                &mut sink,
                &repo_dir,
                "ep",
                false,
                &fwd_tx,
                &publications,
                &bcast_tx,
                &daemon_state,
                Some(sha_startup),
                false,
                &mut pending_reexec,
            ));
            assert_eq!(pending_reexec.current().unwrap().expected_sha, sha_a);

            // Wait until release B is actively inside `spawn_blocking` and 360ms (> 350ms) has elapsed.
            b_entered_blocking.notified().await;
            tokio::time::sleep(Duration::from_millis(360)).await;
            assert_eq!(
                job_gate.lock().unwrap().active_jobs,
                1,
                "release B should still hold its pending job slot while inside blocking installation"
            );
            assert!(
                !should_complete_pending_reexec(
                    true,
                    true,
                    job_gate.lock().unwrap().active_jobs == 0,
                    Duration::from_millis(360),
                ),
                "live loop must defer re-exec while release B is busy"
            );

            // Now run post-loop quiescence while B is STILL mid-flight inside `spawn_blocking`:
            // it MUST await B's completion, drain B's event, and update `pending_reexec` to `sha_b`!
            let mut job_tx_opt = Some(job_tx);
            quiesce_release_worker_and_drain_events(
                &mut job_tx_opt,
                &mut done_tx_keepalive,
                &mut worker_handle,
                &mut done_rx,
                |ev| {
                    let _ = process_release_daemon_event(
                        ev,
                        &mut sink,
                        &repo_dir,
                        "ep",
                        false,
                        &fwd_tx,
                        &publications,
                        &bcast_tx,
                        &daemon_state,
                        Some(sha_startup),
                        true,
                        &mut pending_reexec,
                    );
                },
            )
            .await;
            assert_eq!(job_gate.lock().unwrap().active_jobs, 0);

            // Also verify rollback back to `sha_startup`: disarms in live loop (`false`),
            // and commits `sha_startup` in teardown mode (`true`)!
            let mut rollback_manifest =
                make_manifest(&sha_startup_hex, 50, 1_700_000_300, &bin_startup);
            rollback_manifest.rollback = true;
            let mut live_pending = PendingReexecSlot::default();
            live_pending.arm(install_path.clone(), sha_a);
            assert!(!process_release_daemon_event(
                ReleaseDaemonEvent::Applied {
                    binary: "chinwag".to_owned(),
                    outcome: Box::new(ReleaseApplyOutcome::Installed {
                        manifest: rollback_manifest.clone(),
                        install_path: install_path.clone(),
                        previous_backup_path: None,
                        receipt_message: None,
                    }),
                },
                &mut sink,
                &repo_dir,
                "ep",
                false,
                &fwd_tx,
                &publications,
                &bcast_tx,
                &daemon_state,
                Some(sha_startup),
                false,
                &mut live_pending,
            ));
            assert!(
                !live_pending.is_some(),
                "rollback to startup digest in live loop must disarm stale pending_reexec"
            );
            let mut teardown_pending = PendingReexecSlot::default();
            teardown_pending.arm(install_path.clone(), sha_a);
            assert!(process_release_daemon_event(
                ReleaseDaemonEvent::Applied {
                    binary: "chinwag".to_owned(),
                    outcome: Box::new(ReleaseApplyOutcome::Installed {
                        manifest: rollback_manifest,
                        install_path: install_path.clone(),
                        previous_backup_path: None,
                        receipt_message: None,
                    }),
                },
                &mut sink,
                &repo_dir,
                "ep",
                false,
                &fwd_tx,
                &publications,
                &bcast_tx,
                &daemon_state,
                Some(sha_startup),
                true,
                &mut teardown_pending,
            ));
            assert_eq!(teardown_pending.current().unwrap().expected_sha, sha_startup);

            let selected = pending_reexec.current().cloned().unwrap();
            (selected.install_path, selected.expected_sha)
        });
        drop(rt);

        assert_eq!(
            selected_sha, sha_b,
            "quiesced re-exec target MUST commit to release B's digest, not stale release A!"
        );
        let prepared =
            prepare_immutable_reexec_binary(&home_dir, &selected_path, &selected_sha).unwrap();
        assert_eq!(
            local_binary_sha256(&prepared.binary_path),
            Some(sha_b),
            "pinned immutable re-exec binary must match release B with zero DigestMismatch"
        );
        drop(prepared.dir_fd);
        clear_and_remove_immutable_dir(&prepared.dir_path);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_reexec_prep_never_suspends_loop_defers_handler_release_b_and_retries_transient_io() {
        use chinwag_cli::release_sync::{
            CURRENT_TARGET_TRIPLE, RELEASE_MANIFEST_SCHEMA, ReleaseApplyOutcome, ReleaseManifestV1,
            ReleaseSyncError, cleanup_prepared_reexec, expected_artifact_key, local_binary_sha256,
            prepare_immutable_reexec_binary,
        };

        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        let bin_dir = home_dir.join(".local/bin");
        let build_dir = temp.path().join("build");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&build_dir).unwrap();

        let compile_signed_macho = |label: &str| -> (PathBuf, [u8; 32], String) {
            let src = build_dir.join(format!("{label}.c"));
            let out = build_dir.join(format!("chinwag-{label}"));
            fs::write(
                &src,
                format!("int main(void) {{ const char *v = \"{label}\"; (void)v; return 0; }}\n"),
            )
            .unwrap();
            let st = std::process::Command::new("/usr/bin/clang")
                .args(["-O2", "-o"])
                .arg(&out)
                .arg(&src)
                .status()
                .unwrap();
            assert!(st.success());
            let cs = std::process::Command::new("/usr/bin/codesign")
                .args(["-s", "-", "--force"])
                .arg(&out)
                .status()
                .unwrap();
            assert!(cs.success());
            let sha = local_binary_sha256(&out).unwrap();
            let sha_hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
            (out, sha, sha_hex)
        };

        let (_bin_startup, sha_startup, _) = compile_signed_macho("loop_startup");
        let (bin_a, sha_a, _sha_a_hex) = compile_signed_macho("loop_a");
        let (bin_b, sha_b, sha_b_hex) = compile_signed_macho("loop_b");
        let install_path = bin_dir.join("chinwag");
        fs::copy(&bin_a, &install_path).unwrap();

        let manifest_b = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
            binary: "chinwag".to_owned(),
            target_triple: CURRENT_TARGET_TRIPLE.to_owned(),
            git_commit: "bbbbbbbbbbbbbbbb".to_owned(),
            commit_epoch: 200,
            built_at_ms: 1_700_000_200,
            sha256: sha_b_hex.clone(),
            blake3: "bb".repeat(32),
            size_bytes: fs::metadata(&bin_b).unwrap().len(),
            artifact_key: expected_artifact_key("chinwag", CURRENT_TARGET_TRIPLE, &sha_b_hex),
            rollback: false,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let (ticks_while_prep_in_flight, committed_sha, log_text) = rt.block_on(async {
            let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<ReleaseDaemonJob>(8);
            let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<ReleaseDaemonEvent>(8);
            let job_gate = Arc::new(Mutex::new(ReleaseJobQueueGate::default()));

            let repo_dir = temp.path().join("repo");
            fs::create_dir_all(repo_dir.join(".chinwag/bus")).unwrap();
            let (bcast_tx, _) = broadcast::channel::<BusMessage>(16);
            let (fwd_tx, _) = tokio::sync::mpsc::channel::<BusMessage>(16);
            let publications = Mutex::new(NativePublication::open(&repo_dir).unwrap());
            let daemon_state = Mutex::new(DaemonState {
                ok: true,
                pid: 1,
                endpoint_id: "ep".into(),
                bound_sockets: vec![],
                alpns: vec![],
                repo_root: repo_dir.to_string_lossy().into_owned(),
                tasks_md: String::new(),
                messages_jsonl: String::new(),
                started_at: 0,
                last_heartbeat: 0,
                total_messages: 0,
                product_governor: String::new(),
                delivery_router: String::new(),
            });

            // Worker installs release B when an active connection handler enqueues it!
            let gate_for_worker = job_gate.clone();
            let dst_for_worker = install_path.clone();
            let src_b_for_worker = bin_b.clone();
            let mb_for_worker = manifest_b.clone();
            let done_for_worker = done_tx.clone();
            let allow_b_finish = Arc::new(tokio::sync::Notify::new());
            let allow_b_clone = allow_b_finish.clone();
            let worker = tokio::spawn(async move {
                if let Some(_job) = job_rx.recv().await {
                    let _slot = ReleaseJobSlotGuard(gate_for_worker);
                    allow_b_clone.notified().await;
                    let tmp = dst_for_worker.with_extension("tmp.loop_b");
                    fs::copy(&src_b_for_worker, &tmp).unwrap();
                    fs::rename(&tmp, &dst_for_worker).unwrap();
                    done_for_worker
                        .send(ReleaseDaemonEvent::Applied {
                            binary: "chinwag".to_owned(),
                            outcome: Box::new(ReleaseApplyOutcome::Installed {
                                manifest: mb_for_worker,
                                install_path: dst_for_worker,
                                previous_backup_path: None,
                                receipt_message: None,
                            }),
                        })
                        .await
                        .unwrap();
                }
            });

            let mut pending_reexec = PendingReexecSlot::default();
            pending_reexec.arm(install_path.clone(), sha_a);
            let mut reexec_prep_task: Option<InFlightReexecPrep> = None;
            let mut reexec_prep_retries = 0u32;
            let mut sink = Vec::new();
            let reexec_sleep = tokio::time::sleep(Duration::from_millis(5));
            tokio::pin!(reexec_sleep);
            let mut heartbeat = tokio::time::interval(Duration::from_millis(15));
            heartbeat.tick().await;

            let prep_a_started = Arc::new(tokio::sync::Notify::new());
            let release_prep_a = Arc::new(std::sync::Barrier::new(2));
            let mut prep_attempt = 0usize;
            let mut ticks_during_prep_a = 0usize;
            let mut handler_enqueued_b = false;
            let committed_prepared;

            loop {
                tokio::select! {
                    _ = heartbeat.tick() => {
                        if reexec_prep_task.is_some() && !handler_enqueued_b {
                            ticks_during_prep_a += 1;
                            if ticks_during_prep_a >= 3 {
                                // Proves the live `tokio::select!` loop was NOT suspended while
                                // `reexec_prep_task` was blocked! Now simulate an active connection
                                // handler enqueueing release B while A's snapshot is being prepared!
                                try_enqueue_release_job(
                                    &job_tx,
                                    &job_gate,
                                    ReleaseDaemonJob::StartupCatchup,
                                )
                                .unwrap();
                                handler_enqueued_b = true;
                                let unblock = release_prep_a.clone();
                                tokio::task::spawn_blocking(move || {
                                    unblock.wait();
                                });
                            }
                        }
                    }
                    Some(ev) = done_rx.recv() => {
                        if process_release_daemon_event(
                            ev,
                            &mut sink,
                            &repo_dir,
                            "ep",
                            false,
                            &fwd_tx,
                            &publications,
                            &bcast_tx,
                            &daemon_state,
                            Some(sha_startup),
                            false,
                            &mut pending_reexec,
                        ) {
                            reexec_prep_retries = 0;
                            reexec_sleep
                                .as_mut()
                                .reset(tokio::time::Instant::now() + Duration::from_millis(10));
                        }
                    }
                    () = &mut reexec_sleep, if pending_reexec.is_some() && reexec_prep_task.is_none() => {
                        let cur = pending_reexec.current().cloned().unwrap();
                        let idle = {
                            let g = job_gate.lock().unwrap();
                            g.active_jobs == 0 && done_rx.is_empty()
                        };
                        if idle {
                            prep_attempt += 1;
                            let attempt = prep_attempt;
                            let home_for_prep = home_dir.clone();
                            let target_for_prep = cur.install_path.clone();
                            let expected_sha = cur.expected_sha;
                            let started_notify = prep_a_started.clone();
                            let barrier_a = release_prep_a.clone();
                            let handle = tokio::task::spawn_blocking(move || {
                                if attempt == 1 {
                                    started_notify.notify_one();
                                    let prepared = prepare_immutable_reexec_binary(
                                        &home_for_prep,
                                        &target_for_prep,
                                        &expected_sha,
                                    )?;
                                    barrier_a.wait();
                                    Ok(prepared)
                                } else if attempt == 2 {
                                    // Simulate a one-shot transient EIO/EMFILE on B's first preparation!
                                    Err(ReleaseSyncError::TransientIo(
                                        "simulated one-shot EMFILE during preparation".into(),
                                    ))
                                } else {
                                    prepare_immutable_reexec_binary(
                                        &home_for_prep,
                                        &target_for_prep,
                                        &expected_sha,
                                    )
                                }
                            });
                            reexec_prep_task = Some(InFlightReexecPrep {
                                target_path: cur.install_path,
                                expected_sha,
                                generation: cur.generation,
                                handle,
                            });
                        } else {
                            // B is currently active in the worker; let B finish in the live loop!
                            allow_b_finish.notify_one();
                            reexec_sleep
                                .as_mut()
                                .reset(tokio::time::Instant::now() + Duration::from_millis(15));
                        }
                    }
                    (prep_path, prep_sha, prep_gen, prep_res) = poll_reexec_prep(&mut reexec_prep_task), if reexec_prep_task.is_some() => {
                        match complete_reexec_prep_step(
                            prep_path,
                            prep_sha,
                            prep_gen,
                            prep_res,
                            &mut sink,
                            Some(sha_startup),
                            true,
                            true,
                            &done_rx,
                            &job_gate,
                            &mut pending_reexec,
                            &mut reexec_prep_retries,
                            |_| Duration::from_millis(10),
                        ) {
                            ReexecPrepStepOutcome::CommitReexec { prepared, .. } => {
                                committed_prepared = prepared;
                                break;
                            }
                            ReexecPrepStepOutcome::RescheduleTimer(delay) => {
                                reexec_sleep
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + delay);
                            }
                            ReexecPrepStepOutcome::StayOnlineDisarmed => {
                                panic!("unexpected disarm during live B upgrade + transient retry");
                            }
                        }
                    }
                }
            }

            // Once `CommitReexec` fired, `job_gate` MUST be atomically frozen so no late
            // connection handler can enqueue work during endpoint/handler teardown!
            assert_eq!(
                try_enqueue_release_job(&job_tx, &job_gate, ReleaseDaemonJob::StartupCatchup),
                Err(EnqueueReleaseJobError::FrozenForReexec)
            );
            drop(job_tx);
            worker.await.unwrap();

            let sha = committed_prepared.sha256;
            cleanup_prepared_reexec(committed_prepared);
            (
                ticks_during_prep_a,
                sha,
                String::from_utf8_lossy(&sink).into_owned(),
            )
        });
        drop(rt);

        assert!(
            ticks_while_prep_in_flight >= 3,
            "owner select! loop must continue polling heartbeats/handlers while preparation runs"
        );
        assert_eq!(
            committed_sha, sha_b,
            "daemon must discard A's pin while B is active, survive transient retry, and commit B"
        );
        assert!(
            log_text.contains("\"native_daemon_reexec_retry\""),
            "transient EIO/EMFILE during preparation must schedule retry instead of refusing: {log_text}"
        );
        assert!(
            !log_text.contains("\"native_daemon_reexec_refused\""),
            "transient error must not trigger terminal refusal: {log_text}"
        );
    }

    #[test]
    fn daemon_room_reconnect_loop_enforces_240_cap_and_fails_closed_on_refusal() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // 1. Continuous WebSocket 1000 closures stop strictly at 240 attempts.
            let (events_tx, mut events_rx) = tokio::sync::mpsc::channel::<Value>(512);
            let mut calls = 0u32;
            let exhausted = attempt_room_reconnect_with_cap::<&'static str, _, _, _, _, _>(
                0,
                "the room WebSocket closed with code 1000".to_owned(),
                &events_tx,
                chinwag_swarm::room::next_reconnect_backoff,
                |_| std::future::ready(()),
                |_| {
                    calls += 1;
                    std::future::ready(Err(chinwag_swarm::room::Error::WebSocketClosed(1000)))
                },
            )
            .await;
            assert_eq!(
                calls,
                chinwag_swarm::room::MAX_CONSECUTIVE_RECONNECT_ATTEMPTS
            );
            assert_eq!(calls, 240);
            assert!(matches!(
                exhausted,
                ReconnectLoopOutcome::Exhausted { attempts: 240, .. }
            ));
            let first_ev = events_rx.recv().await.unwrap();
            assert_eq!(first_ev["event"], "native_room_reconnect_scheduled");
            assert_eq!(first_ev["attempt"], 1);

            // 2. Transient closures followed by success return Reconnected with updated attempt count.
            let (events_tx2, _events_rx2) = tokio::sync::mpsc::channel::<Value>(16);
            let mut calls2 = 0u32;
            let recovered = attempt_room_reconnect_with_cap(
                0,
                "the room WebSocket closed with code 1000".to_owned(),
                &events_tx2,
                |_| Duration::from_millis(1),
                |_| std::future::ready(()),
                |_| {
                    calls2 += 1;
                    if calls2 < 3 {
                        std::future::ready(Err(chinwag_swarm::room::Error::WebSocketClosed(1000)))
                    } else {
                        std::future::ready(Ok("live-session"))
                    }
                },
            )
            .await;
            assert_eq!(
                recovered,
                ReconnectLoopOutcome::Reconnected {
                    session: "live-session",
                    next_attempt: 3,
                }
            );

            // 3. Explicit HTTP 403 coordinator refusal fails closed immediately without retry.
            let (events_tx3, _events_rx3) = tokio::sync::mpsc::channel::<Value>(16);
            let mut calls3 = 0u32;
            let refused = attempt_room_reconnect_with_cap::<&'static str, _, _, _, _, _>(
                0,
                "the room WebSocket closed with code 1000".to_owned(),
                &events_tx3,
                |_| Duration::from_millis(1),
                |_| std::future::ready(()),
                |_| {
                    calls3 += 1;
                    std::future::ready(Err(chinwag_swarm::room::Error::Refused(403)))
                },
            )
            .await;
            assert_eq!(calls3, 1);
            assert!(matches!(refused, ReconnectLoopOutcome::FatalRefusal(_)));
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stale_reexec_prep_errors_and_startup_shortcuts_never_disarm_newer_release_b() {
        use chinwag_cli::release_sync::{
            CURRENT_TARGET_TRIPLE, RELEASE_MANIFEST_SCHEMA, ReleaseApplyOutcome, ReleaseManifestV1,
            ReleaseSyncError, cleanup_prepared_reexec, expected_artifact_key, local_binary_sha256,
            prepare_immutable_reexec_binary,
        };

        let temp = tempfile::tempdir().unwrap();
        let home_dir = temp.path().join("home");
        let bin_dir = home_dir.join(".local/bin");
        let build_dir = temp.path().join("build");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&build_dir).unwrap();

        let compile_signed_macho = |label: &str| -> (PathBuf, [u8; 32], String) {
            let src = build_dir.join(format!("{label}.c"));
            let out = build_dir.join(format!("chinwag-{label}"));
            fs::write(
                &src,
                format!("int main(void) {{ const char *v = \"{label}\"; (void)v; return 0; }}\n"),
            )
            .unwrap();
            let st = std::process::Command::new("/usr/bin/clang")
                .args(["-O2", "-o"])
                .arg(&out)
                .arg(&src)
                .status()
                .unwrap();
            assert!(st.success());
            let cs = std::process::Command::new("/usr/bin/codesign")
                .args(["-s", "-", "--force"])
                .arg(&out)
                .status()
                .unwrap();
            assert!(cs.success());
            let sha = local_binary_sha256(&out).unwrap();
            let sha_hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
            (out, sha, sha_hex)
        };

        let (bin_startup, sha_startup, _) = compile_signed_macho("stale_startup");
        let (bin_a, sha_a, _) = compile_signed_macho("stale_a");
        let (bin_b, sha_b, sha_b_hex) = compile_signed_macho("stale_b");
        let install_path = bin_dir.join("chinwag");
        fs::copy(&bin_a, &install_path).unwrap();

        let manifest_b = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_SCHEMA.to_owned(),
            binary: "chinwag".to_owned(),
            target_triple: CURRENT_TARGET_TRIPLE.to_owned(),
            git_commit: "bbbbbbbbbbbbbbbb".to_owned(),
            commit_epoch: 200,
            built_at_ms: 1_700_000_200,
            sha256: sha_b_hex.clone(),
            blake3: "bb".repeat(32),
            size_bytes: fs::metadata(&bin_b).unwrap().len(),
            artifact_key: expected_artifact_key("chinwag", CURRENT_TARGET_TRIPLE, &sha_b_hex),
            rollback: false,
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let repo_dir = temp.path().join("repo");
            fs::create_dir_all(repo_dir.join(".chinwag/bus")).unwrap();
            let (bcast_tx, _) = broadcast::channel::<BusMessage>(16);
            let (fwd_tx, _) = tokio::sync::mpsc::channel::<BusMessage>(16);
            let (_done_tx, done_rx) = tokio::sync::mpsc::channel::<ReleaseDaemonEvent>(8);
            let job_gate = Arc::new(Mutex::new(ReleaseJobQueueGate::default()));
            let publications = Mutex::new(NativePublication::open(&repo_dir).unwrap());
            let daemon_state = Mutex::new(DaemonState {
                ok: true,
                pid: 1,
                endpoint_id: "ep".into(),
                bound_sockets: vec![],
                alpns: vec![],
                repo_root: repo_dir.to_string_lossy().into_owned(),
                tasks_md: String::new(),
                messages_jsonl: String::new(),
                started_at: 0,
                last_heartbeat: 0,
                total_messages: 0,
                product_governor: String::new(),
                delivery_router: String::new(),
            });

            let mut pending_reexec = PendingReexecSlot::default();
            let gen_a = pending_reexec.arm(install_path.clone(), sha_a);
            let mut retries = 0u32;
            let mut sink = Vec::new();

            // Prepare a startup-digest snapshot up front before B replaces `install_path`.
            let startup_copy = build_dir.join("startup_snapshot_src");
            fs::copy(&bin_startup, &startup_copy).unwrap();
            let stale_startup_prepared =
                prepare_immutable_reexec_binary(&home_dir, &startup_copy, &sha_startup).unwrap();

            // Simulate B completing and being processed by the responsive daemon loop
            // BEFORE A's preparation returns its result!
            fs::copy(&bin_b, &install_path).unwrap();
            assert!(process_release_daemon_event(
                ReleaseDaemonEvent::Applied {
                    binary: "chinwag".to_owned(),
                    outcome: Box::new(ReleaseApplyOutcome::Installed {
                        manifest: manifest_b,
                        install_path: install_path.clone(),
                        previous_backup_path: None,
                        receipt_message: None,
                    }),
                },
                &mut sink,
                &repo_dir,
                "ep",
                false,
                &fwd_tx,
                &publications,
                &bcast_tx,
                &daemon_state,
                Some(sha_startup),
                false,
                &mut pending_reexec,
            ));
            let gen_b = pending_reexec.current().unwrap().generation;
            assert!(gen_b > gen_a);

            // 1. Stale terminal error from A (e.g. codesign timeout after releasing lock)
            //    MUST NOT disarm B or emit terminal refusal for the active target!
            let out_terminal = complete_reexec_prep_step(
                install_path.clone(),
                sha_a,
                gen_a,
                Ok(Err(ReleaseSyncError::CodesignFailed(
                    "timed out after 5000ms".into(),
                ))),
                &mut sink,
                Some(sha_startup),
                true,
                true,
                &done_rx,
                &job_gate,
                &mut pending_reexec,
                &mut retries,
                |_| Duration::from_secs(10),
            );
            assert!(matches!(
                out_terminal,
                ReexecPrepStepOutcome::RescheduleTimer(_)
            ));
            assert_eq!(pending_reexec.current().unwrap().expected_sha, sha_b);
            assert_eq!(pending_reexec.current().unwrap().generation, gen_b);
            assert_eq!(retries, 0);

            // 2. Stale worker panic from A MUST NOT disarm B!
            let panic_join =
                tokio::spawn(async move { panic!("simulated stale prep panic") }).await;
            let out_panic = complete_reexec_prep_step(
                install_path.clone(),
                sha_a,
                gen_a,
                panic_join,
                &mut sink,
                Some(sha_startup),
                true,
                true,
                &done_rx,
                &job_gate,
                &mut pending_reexec,
                &mut retries,
                |_| Duration::from_secs(10),
            );
            assert!(matches!(
                out_panic,
                ReexecPrepStepOutcome::RescheduleTimer(_)
            ));
            assert_eq!(pending_reexec.current().unwrap().expected_sha, sha_b);
            assert_eq!(retries, 0);

            // 3. Stale transient error from A MUST NOT consume B's retry budget!
            let out_transient = complete_reexec_prep_step(
                install_path.clone(),
                sha_a,
                gen_a,
                Ok(Err(ReleaseSyncError::TransientIo("stale EMFILE".into()))),
                &mut sink,
                Some(sha_startup),
                true,
                true,
                &done_rx,
                &job_gate,
                &mut pending_reexec,
                &mut retries,
                |_| Duration::from_secs(10),
            );
            assert!(matches!(
                out_transient,
                ReexecPrepStepOutcome::RescheduleTimer(_)
            ));
            assert_eq!(pending_reexec.current().unwrap().expected_sha, sha_b);
            assert_eq!(retries, 0);

            // 4. Stale `Ok(Ok(prepared))` matching `startup_chinwag_sha256` MUST NOT
            //    trigger the startup-digest shortcut to disarm B!
            let out_startup_shortcut = complete_reexec_prep_step(
                install_path.clone(),
                sha_a,
                gen_a,
                Ok(Ok(stale_startup_prepared)),
                &mut sink,
                Some(sha_startup),
                true,
                true,
                &done_rx,
                &job_gate,
                &mut pending_reexec,
                &mut retries,
                |_| Duration::from_secs(10),
            );
            assert!(matches!(
                out_startup_shortcut,
                ReexecPrepStepOutcome::RescheduleTimer(_)
            ));
            assert_eq!(pending_reexec.current().unwrap().expected_sha, sha_b);

            // 5. Same-digest ABA (`A` gen_1 -> cleared -> `A` gen_3): stale terminal error
            //    from `gen_1` MUST NOT disarm `gen_3` even though `(install_path, sha_a)` matches!
            let mut aba_slot = PendingReexecSlot::default();
            let aba_gen_1 = aba_slot.arm(install_path.clone(), sha_a);
            aba_slot.clear();
            let aba_gen_2 = aba_slot.arm(install_path.clone(), sha_a);
            assert!(aba_gen_2 > aba_gen_1);
            let out_aba = complete_reexec_prep_step(
                install_path.clone(),
                sha_a,
                aba_gen_1,
                Ok(Err(ReleaseSyncError::CodesignFailed("stale gen_1".into()))),
                &mut sink,
                Some(sha_startup),
                true,
                true,
                &done_rx,
                &job_gate,
                &mut aba_slot,
                &mut retries,
                |_| Duration::from_secs(10),
            );
            assert!(matches!(out_aba, ReexecPrepStepOutcome::RescheduleTimer(_)));
            assert_eq!(aba_slot.current().unwrap().generation, aba_gen_2);

            // 6. Finally, B's own current-generation preparation prepares and commits cleanly!
            let prepared_b =
                prepare_immutable_reexec_binary(&home_dir, &install_path, &sha_b).unwrap();
            match complete_reexec_prep_step(
                install_path.clone(),
                sha_b,
                gen_b,
                Ok(Ok(prepared_b)),
                &mut sink,
                Some(sha_startup),
                true,
                true,
                &done_rx,
                &job_gate,
                &mut pending_reexec,
                &mut retries,
                |_| Duration::from_secs(10),
            ) {
                ReexecPrepStepOutcome::CommitReexec { prepared, .. } => {
                    assert_eq!(prepared.sha256, sha_b);
                    cleanup_prepared_reexec(prepared);
                }
                _ => panic!("expected CommitReexec for current generation B"),
            }
        });
    }

    #[test]
    fn no_release_sync_flag_validates_daemon_scope_and_reexec_arg_preservation() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        // `--no-release-sync` on a non-daemon subcommand must fail closed with exit 2.
        let code = run_bus_cli(
            &["status".to_owned(), "--no-release-sync".to_owned()],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 2);

        // Duplicate `--no-release-sync` must fail closed with exit 2.
        out.clear();
        err.clear();
        let dup_code = run_bus_cli(
            &[
                "daemon".to_owned(),
                "--no-release-sync".to_owned(),
                "--no-release-sync".to_owned(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(dup_code, 2);
        assert!(
            String::from_utf8_lossy(&err).contains("duplicate_no_release_sync_flag"),
            "unexpected duplicate flag diagnostic: {}",
            String::from_utf8_lossy(&err)
        );
        assert!(daemon_release_sync_enabled(false));
        assert!(!daemon_release_sync_enabled(true));

        // Canonical re-exec arg builder preserves both `--no-governors` and `--no-release-sync`.
        let canonical = Path::new("/tmp/canonical-repo");
        let args = vec![
            "daemon".to_owned(),
            "--repo".to_owned(),
            "/tmp/old-repo".to_owned(),
            "--port".to_owned(),
            "44330".to_owned(),
            "--no-governors".to_owned(),
            "--no-release-sync".to_owned(),
        ];
        let rebuilt: Vec<String> = build_canonical_daemon_reexec_args(&args, canonical)
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            rebuilt,
            vec![
                "bus",
                "daemon",
                "--repo",
                "/tmp/canonical-repo",
                "--port",
                "44330",
                "--no-governors",
                "--no-release-sync",
            ]
        );
    }

    #[test]
    fn linked_worktree_release_publish_discovers_active_common_repo_daemon() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let primary = base.join("primary-repo");
        fs::create_dir_all(&primary).unwrap();
        assert!(
            Command::new("/usr/bin/git")
                .args(["init", "-q"])
                .current_dir(&primary)
                .status()
                .unwrap()
                .success()
        );
        fs::write(primary.join("README.md"), "seed\n").unwrap();
        assert!(
            Command::new("/usr/bin/git")
                .args(["add", "README.md"])
                .current_dir(&primary)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "seed",
                ])
                .current_dir(&primary)
                .status()
                .unwrap()
                .success()
        );

        let linked = base.join("linked-worktree");
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "wt-branch",
                    linked.to_str().unwrap(),
                ])
                .current_dir(&primary)
                .status()
                .unwrap()
                .success()
        );

        let primary_sel = chinwag_cli::execution_binding::select_repository(
            chinwag_cli::execution_binding::RepoSelectors {
                explicit_repo: Some(&primary),
                environment_repo: None,
                cwd: &primary,
            },
        )
        .unwrap();
        let linked_sel = chinwag_cli::execution_binding::select_repository(
            chinwag_cli::execution_binding::RepoSelectors {
                explicit_repo: Some(&linked),
                environment_repo: None,
                cwd: &linked,
            },
        )
        .unwrap();

        // 1. Clean offline primary repo permits standalone local-jsonl fallback (`daemon: None`),
        //    whereas a linked worktree with zero live daemons fails closed (`PublicationRejected`)
        //    so it never writes an orphaned split-brain `linked/.chinwag/bus/messages.jsonl`.
        let offline_primary =
            resolve_release_publish_daemon_route_with_env(&primary_sel, None, None).unwrap();
        assert!(offline_primary.daemon.is_none());
        assert!(!offline_primary.explicit_route);
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&linked_sel, None, None),
            Err(InstanceError::PublicationRejected)
        ));

        // 2. Start active primary daemon (including ordinary wildcard `0.0.0.0` / `[::]` bind
        //    entries as emitted by `endpoint.bound_sockets()`) -> linked worktree discovers it
        //    without mutating `linked`.
        let valid_endpoint = SecretKey::from_bytes(&[7; 32]).public().to_string();
        let common_state = DaemonState {
            ok: true,
            pid: std::process::id(),
            endpoint_id: valid_endpoint.clone(),
            bound_sockets: vec![
                "0.0.0.0:44330".to_owned(),
                "[::]:44330".to_owned(),
                "127.0.0.1:44330".to_owned(),
            ],
            alpns: vec!["chinwag/bus/1".to_owned()],
            repo_root: primary.to_string_lossy().into_owned(),
            tasks_md: primary.join("TASKS.md").to_string_lossy().into_owned(),
            messages_jsonl: messages_jsonl_path(&primary).to_string_lossy().into_owned(),
            started_at: 1,
            last_heartbeat: 1,
            total_messages: 42,
            product_governor: "DISABLED_CONTROLLED_INSTANCE".to_owned(),
            delivery_router: "QUALIFIED_ADMISSION_REQUIRED".to_owned(),
        };
        write_daemon_state(&primary, &common_state).unwrap();

        let primary_route =
            resolve_release_publish_daemon_route_with_env(&primary_sel, None, None).unwrap();
        assert_eq!(
            primary_route.daemon.unwrap().endpoint_id,
            common_state.endpoint_id
        );

        let discovered = resolve_release_publish_daemon_route_with_env(&linked_sel, None, None)
            .expect("linked worktree without local daemon must discover primary repo daemon");
        let discovered_daemon = discovered.daemon.unwrap();
        assert_eq!(discovered_daemon.endpoint_id, common_state.endpoint_id);
        assert_eq!(discovered_daemon.bound_sockets, common_state.bound_sockets);
        assert!(!discovered.explicit_route);
        assert!(!linked.join(".chinwag").exists());

        // 3. Malformed / partial / non-UTF-8 explicit env route MUST fail closed (`PublicationRejected`)
        //    and NEVER fall through to common-daemon discovery.
        let invalid_utf8 = OsStr::from_bytes(b"127.0.0.1:44330\xff");
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&linked_sel, Some(invalid_utf8), None),
            Err(InstanceError::PublicationRejected)
        ));
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(
                &linked_sel,
                Some(invalid_utf8),
                Some(OsStr::new(&valid_endpoint)),
            ),
            Err(InstanceError::PublicationRejected)
        ));
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(
                &linked_sel,
                Some(OsStr::new("127.0.0.1:44330")),
                None,
            ),
            Err(InstanceError::PublicationRejected)
        ));
        let explicit_ok = resolve_release_publish_daemon_route_with_env(
            &linked_sel,
            Some(OsStr::new("127.0.0.1:49999")),
            Some(OsStr::new(&valid_endpoint)),
        )
        .unwrap();
        assert!(explicit_ok.explicit_route);
        assert_eq!(
            explicit_ok.daemon.unwrap().bound_sockets,
            vec!["127.0.0.1:49999".to_owned()]
        );

        // 4. Dead local daemon PID (`pid == 0`) falls back cleanly to primary daemon.
        let mut zero_pid_state = common_state.clone();
        zero_pid_state.pid = 0;
        write_daemon_state(&linked, &zero_pid_state).unwrap();
        assert!(!is_live_positive_daemon_pid(0));
        let after_dead_local =
            resolve_release_publish_daemon_route_with_env(&linked_sel, None, None).unwrap();
        assert_eq!(
            after_dead_local.daemon.unwrap().bound_sockets,
            common_state.bound_sockets
        );

        // 5. Active local daemon in linked worktree takes precedence over primary daemon.
        let mut local_state = common_state.clone();
        local_state.bound_sockets = vec!["127.0.0.1:45441".to_owned()];
        write_daemon_state(&linked, &local_state).unwrap();
        let local_preferred =
            resolve_release_publish_daemon_route_with_env(&linked_sel, None, None).unwrap();
        assert_eq!(
            local_preferred.daemon.unwrap().bound_sockets,
            vec!["127.0.0.1:45441".to_owned()]
        );

        // 5b. Harmless `include` substrings in comments or remote URLs on the primary
        //     checkout `.git/config` remain accepted, whereas actual `[include]` /
        //     `[includeIf "..."]` directives fail closed (`PublicationRejected`).
        fs::remove_file(daemon_json_path(&linked)).unwrap();
        let primary_cfg_path = primary.join(".git/config");
        let baseline_primary_cfg = fs::read(&primary_cfg_path).unwrap();
        let mut harmless_cfg = baseline_primary_cfg.clone();
        harmless_cfg.extend_from_slice(
            b"\n# This clone includes generated files\n[remote \"origin\"]\n\turl = https://example.com/include-chinwag.git\n",
        );
        fs::write(&primary_cfg_path, &harmless_cfg).unwrap();
        let harmless_ok =
            resolve_release_publish_daemon_route_with_env(&linked_sel, None, None).unwrap();
        assert_eq!(
            harmless_ok.daemon.unwrap().bound_sockets,
            common_state.bound_sockets
        );

        let mut includeif_cfg = baseline_primary_cfg.clone();
        includeif_cfg
            .extend_from_slice(b"\n[includeIf \"gitdir:**\"]\n\tpath = /never-read-config\n");
        fs::write(&primary_cfg_path, &includeif_cfg).unwrap();
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&linked_sel, None, None),
            Err(InstanceError::PublicationRejected)
        ));
        fs::write(&primary_cfg_path, &baseline_primary_cfg).unwrap();

        // 6. Real daemon startup state (`run_daemon_loop_inner` writing `endpoint.bound_sockets()`)
        //    is accepted by `read_daemon_state_strict` and discovered from `linked_sel`.
        fs::remove_file(daemon_json_path(&primary)).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let mut out = Vec::new();
            let daemon_fut = run_daemon_loop(
                primary.clone(),
                0,
                None,
                true,
                &mut out,
                async move {
                    let _ = stop_rx.await;
                },
            );
            let probe_fut = async {
                let deadline = Instant::now() + Duration::from_secs(5);
                let live_discovered = loop {
                    if let Ok(route) =
                        resolve_release_publish_daemon_route_with_env(&linked_sel, None, None)
                        && let Some(d) = route.daemon
                    {
                        break d;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for real daemon startup state to validate from linked worktree"
                    );
                    tokio::time::sleep(Duration::from_millis(25)).await;
                };
                assert!(
                    live_discovered.bound_sockets.iter().any(|s| {
                        s.parse::<std::net::SocketAddr>()
                            .is_ok_and(|a| a.ip().is_unspecified())
                    }),
                    "expected real daemon bound_sockets to contain wildcard bind entry: {:?}",
                    live_discovered.bound_sockets
                );
                assert!(
                    read_daemon_state_strict_with_env(&primary, None, None)
                        .unwrap()
                        .is_some()
                );
                let _ = stop_tx.send(());
            };
            let (exit_code, ()) = tokio::join!(daemon_fut, probe_fut);
            assert_eq!(exit_code, 0);
        });

        // 7. Linked worktrees backed by a bare repo (`bare.git`) or `--separate-git-dir`
        //    (including a `.git`-named external holder directory) fail closed (`PublicationRejected`)
        //    when no local daemon is running rather than falling through to orphan `daemon: None`.
        let bare_repo = base.join("bare.git");
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "clone",
                    "-q",
                    "--bare",
                    primary.to_str().unwrap(),
                    bare_repo.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );
        let bare_linked = base.join("bare-linked");
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "bare-wt",
                    bare_linked.to_str().unwrap(),
                ])
                .current_dir(&bare_repo)
                .status()
                .unwrap()
                .success()
        );
        let bare_linked_sel = chinwag_cli::execution_binding::select_repository(
            chinwag_cli::execution_binding::RepoSelectors {
                explicit_repo: Some(&bare_linked),
                environment_repo: None,
                cwd: &bare_linked,
            },
        )
        .unwrap();
        assert!(bare_linked_sel.is_linked_worktree());
        assert!(bare_linked_sel.common_worktree_root().is_none());
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&bare_linked_sel, None, None),
            Err(InstanceError::PublicationRejected)
        ));

        let sep_holder = base.join("sep-holder");
        fs::create_dir_all(&sep_holder).unwrap();
        let sep_gitdir = sep_holder.join("repo.git");
        let sep_primary = base.join("sep-primary");
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "init",
                    "-q",
                    "--separate-git-dir",
                    sep_gitdir.to_str().unwrap(),
                    sep_primary.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );
        fs::write(sep_primary.join("README.md"), "seed\n").unwrap();
        assert!(
            Command::new("/usr/bin/git")
                .args(["add", "README.md"])
                .current_dir(&sep_primary)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "seed",
                ])
                .current_dir(&sep_primary)
                .status()
                .unwrap()
                .success()
        );
        write_daemon_state(&sep_holder, &common_state).unwrap();
        let sep_linked = base.join("sep-linked");
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "sep-wt",
                    sep_linked.to_str().unwrap(),
                ])
                .current_dir(&sep_primary)
                .status()
                .unwrap()
                .success()
        );
        let sep_linked_sel = chinwag_cli::execution_binding::select_repository(
            chinwag_cli::execution_binding::RepoSelectors {
                explicit_repo: Some(&sep_linked),
                environment_repo: None,
                cwd: &sep_linked,
            },
        )
        .unwrap();
        assert!(sep_linked_sel.is_linked_worktree());
        assert_eq!(sep_linked_sel.common_worktree_root(), None);
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&sep_linked_sel, None, None),
            Err(InstanceError::PublicationRejected)
        ));

        // 7c. Even when an external holder directory uses a `.git` basename, redirecting
        //     `core.worktree` away from the holder causes `verify_effective_toplevel()` to
        //     reject a planted `daemon.json` inside the holder directory.
        let dotgit_holder = base.join("dotgit-holder");
        fs::create_dir_all(&dotgit_holder).unwrap();
        let dotgit_dir = dotgit_holder.join(".git");
        let dotgit_primary = base.join("dotgit-primary");
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "init",
                    "-q",
                    "--separate-git-dir",
                    dotgit_dir.to_str().unwrap(),
                    dotgit_primary.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/git")
                .args(["config", "core.worktree", dotgit_primary.to_str().unwrap(),])
                .current_dir(&dotgit_holder)
                .status()
                .unwrap()
                .success()
        );
        fs::write(dotgit_primary.join("README.md"), "seed\n").unwrap();
        assert!(
            Command::new("/usr/bin/git")
                .args(["add", "README.md"])
                .current_dir(&dotgit_primary)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "seed",
                ])
                .current_dir(&dotgit_primary)
                .status()
                .unwrap()
                .success()
        );
        write_daemon_state(&dotgit_holder, &common_state).unwrap();
        let dotgit_linked = base.join("dotgit-linked");
        assert!(
            Command::new("/usr/bin/git")
                .args([
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    "dotgit-wt",
                    dotgit_linked.to_str().unwrap(),
                ])
                .current_dir(&dotgit_primary)
                .status()
                .unwrap()
                .success()
        );
        let dotgit_linked_sel = chinwag_cli::execution_binding::select_repository(
            chinwag_cli::execution_binding::RepoSelectors {
                explicit_repo: Some(&dotgit_linked),
                environment_repo: None,
                cwd: &dotgit_linked,
            },
        )
        .unwrap();
        assert!(dotgit_linked_sel.is_linked_worktree());
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&dotgit_linked_sel, None, None),
            Err(InstanceError::PublicationRejected)
        ));

        // 8. Symlinked local `daemon.json` fails closed (`Err(PublicationRejected)`) in BOTH
        //    `resolve_release_publish_daemon_route` AND `read_daemon_state_strict` — never
        //    followed via `fs::read_to_string` and never masked by local-jsonl split-brain!
        write_daemon_state(&primary, &common_state).unwrap();
        let outside = base.join("outside-daemon.json");
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&outside)
            .unwrap();
        f.write_all(serde_json::to_vec(&local_state).unwrap().as_slice())
            .unwrap();
        drop(f);
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::create_dir_all(linked.join(".chinwag/bus")).unwrap();
        fs::set_permissions(linked.join(".chinwag"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            linked.join(".chinwag/bus"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        symlink(&outside, daemon_json_path(&linked)).unwrap();
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&linked_sel, None, None),
            Err(InstanceError::PublicationRejected)
        ));
        assert!(read_daemon_state_strict_with_env(&linked, None, None).is_err());

        // 9. Symlinked primary `daemon.json` also fails closed (`Err(PublicationRejected)`).
        fs::remove_file(daemon_json_path(&linked)).unwrap();
        fs::remove_file(daemon_json_path(&primary)).unwrap();
        symlink(&outside, daemon_json_path(&primary)).unwrap();
        assert!(matches!(
            resolve_release_publish_daemon_route_with_env(&linked_sel, None, None),
            Err(InstanceError::PublicationRejected)
        ));
    }

    #[test]
    fn live_positive_daemon_pid_rejects_unreaped_zombie_process() {
        assert!(is_live_positive_daemon_pid(std::process::id()));
        assert!(!is_live_positive_daemon_pid(0));
        assert!(!is_live_positive_daemon_pid(u32::MAX));

        let true_bin = if Path::new("/usr/bin/true").exists() {
            "/usr/bin/true"
        } else {
            "/bin/true"
        };
        let mut child = Command::new(true_bin).spawn().unwrap();
        let child_pid = child.id();
        // Wait briefly without calling `wait()` so the exited child sits in kernel zombie (`Z`)
        // state while POSIX `kill(pid, 0)` still reports `Ok(())`.
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if is_zombie_or_gone_process(child_pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !is_live_positive_daemon_pid(child_pid),
            "un-reaped zombie PID {child_pid} must not be treated as a live daemon"
        );
        let _ = child.wait();
    }
}

#[cfg(test)]
#[path = "bus_network_tests.rs"]
mod network_tests;
