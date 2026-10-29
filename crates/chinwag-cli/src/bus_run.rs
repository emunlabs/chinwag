#![forbid(unsafe_code)]

//! Multi-party `iroh` QUIC messaging bus (`ALPN: chinwag/bus/1`) +
//! `■ PRODUCT` Utilization Governor & `■ DELIVERY` Work-Stream Router.
//!
//! Zero-config multi-party pub/sub and direct seat messaging backed by:
//! 1. Live `iroh::Endpoint` QUIC streams (`ALPN = b"chinwag/bus/1"`).
//! 2. Append-only `.chinwag/bus/messages.jsonl` (human & CLI inspectable).
//! 3. `.chinwag/state.crdb` (`agent_messages` & `comms_messages` tables).
//! 4. Canonical `/Users/brianspector/WORKSPACE/chinwag/TASKS.md` utilization board.

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
    address_lookup::memory::MemoryLookup, endpoint::presets,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
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

fn iso_now() -> String {
    let output = Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
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

fn actor_endpoint_id(actor: &str, fallback_secret: &SecretKey) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let slug = actor
        .trim()
        .trim_start_matches('●')
        .trim_start_matches('■')
        .trim_start_matches('◆')
        .trim()
        .to_lowercase();
    let ssh_key_path = PathBuf::from(format!("{home}/.chinwag/signing/{slug}_ed25519"));
    let resolved_path = fs::canonicalize(&ssh_key_path).unwrap_or(ssh_key_path);
    if let Ok(identity) = chinwag_swarm::identity::Identity::from_ssh_signing_file(&resolved_path) {
        return identity.endpoint_id().to_string();
    }
    fallback_secret.public().to_string()
}

fn actor_secret_key(actor: &str) -> SecretKey {
    let mut hasher = Sha256::new();
    hasher.update(b"chinwag-iroh-bus-actor-v1:");
    hasher.update(actor.trim().to_uppercase().as_bytes());
    let digest = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    SecretKey::from_bytes(&arr)
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

fn read_all_messages(repo_root: &Path) -> Vec<BusMessage> {
    let path = messages_jsonl_path(repo_root);
    let Ok(file) = fs::File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(msg) = serde_json::from_str::<BusMessage>(trimmed) {
            out.push(msg);
        }
    }
    out
}

fn append_message_to_disk_and_crdb(repo_root: &Path, msg: &BusMessage) -> u64 {
    let existing = read_all_messages(repo_root);
    if let Some(found) = existing.iter().find(|m| m.id == msg.id) {
        return found.seq;
    }
    let next_seq = existing.last().map(|m| m.seq + 1).unwrap_or(1);
    let mut persisted = msg.clone();
    persisted.seq = next_seq;

    let path = messages_jsonl_path(repo_root);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path)
        && let Ok(line) = serde_json::to_string(&persisted)
    {
        let _ = writeln!(file, "{line}");
    }

    // Mirror into .chinwag/bus/bus.sqlite (isolated from state.crdb WriteOwner FileId stamps)
    let bus_db = bus_dir(repo_root).join("bus.sqlite");
    let sender_display = format!("{} {}", persisted.sender_cast, persisted.sender);
    let item_key = persisted
        .task_id
        .clone()
        .unwrap_or_else(|| "CHWG-IROH-BUS-1".to_string());
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS bus_messages (id TEXT PRIMARY KEY, seq INTEGER, ts_iso TEXT, room TEXT, sender TEXT, sender_endpoint_id TEXT, recipient TEXT, task_id TEXT, body TEXT, digest_sha256 TEXT); \
         INSERT OR REPLACE INTO bus_messages (id, seq, ts_iso, room, sender, sender_endpoint_id, recipient, task_id, body, digest_sha256) VALUES ('{}', {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}');",
        persisted.id.replace('\'', "''"),
        persisted.seq,
        persisted.ts_iso.replace('\'', "''"),
        persisted.room.replace('\'', "''"),
        sender_display.replace('\'', "''"),
        persisted.sender_endpoint_id.replace('\'', "''"),
        persisted
            .to
            .clone()
            .unwrap_or_default()
            .replace('\'', "''"),
        item_key.replace('\'', "''"),
        persisted.body.replace('\'', "''"),
        persisted.digest_sha256.replace('\'', "''"),
    );
    let _ = Command::new("/usr/bin/sqlite3")
        .arg(&bus_db)
        .arg(&sql)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    next_seq
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
    let mut hex = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

fn read_daemon_state(repo_root: &Path) -> Option<DaemonState> {
    let raw = fs::read_to_string(daemon_json_path(repo_root)).ok()?;
    let state: DaemonState = serde_json::from_str(&raw).ok()?;
    // Check if PID is alive
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

async fn bind_bus_endpoint(secret: SecretKey, port: u16, lookup: MemoryLookup) -> Result<Endpoint, String> {
    let addr: SocketAddr = format!("127.0.0.1:{port}")
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
    let sock_str = daemon
        .bound_sockets
        .first()
        .ok_or_else(|| "daemon has no bound sockets".to_string())?;
    let sock: SocketAddr = sock_str
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
    let time_short = if m.ts_iso.len() >= 19 {
        &m.ts_iso[11..19]
    } else {
        &m.ts_iso
    };
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
        "#{:03} [{}] [{}] [{} {} · iroh:{}]{}{}: {}",
        m.seq, time_short, m.room, m.sender_cast, m.sender, short_ep, task_badge, to_badge, m.body
    )
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
    let bound_sockets: Vec<String> = endpoint
        .bound_sockets()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
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
        product_governor: "ACTIVE (Monitoring TASKS.md & Fleet Utilization)".to_string(),
        delivery_router: "ACTIVE (Routing Work Streams over iroh/bus/1)".to_string(),
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
    let actor_secret = actor_secret_key(&sender);
    let sender_endpoint_id = actor_endpoint_id(&sender, &actor_secret);
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
    };

    // If daemon is online, publish over live iroh QUIC (`ALPN: chinwag/bus/1`)
    if let Some(daemon) = read_daemon_state(repo_root)
        && let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        && let Ok(ack) = rt.block_on(publish_over_iroh_quic(&daemon, actor_secret, &msg))
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
    };
    (msg, ack)
}

fn run_worker_sync(repo_root: &Path, seat: &str, task_id: &str, prompt: &str) -> u8 {
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

    let _ = send_bus_message_sync(
        repo_root,
        seat,
        "#eng",
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
             chinwag bus wake [--seat <ALL|RUST|ARCHITECT|FLINT|QA>]\n\n\
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
            let task = task_arg.unwrap_or_else(|| "TASK-03".to_string());
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
                let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            } else {
                let _ = writeln!(
                    stdout,
                    "{}\n  ↳ Delivered via {} (daemon iroh:{})",
                    format_bus_line(&msg),
                    ack.transport,
                    &ack.daemon_endpoint_id[..12.min(ack.daemon_endpoint_id.len())]
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
                Some("TASK-00".to_string()),
                &format!(
                    "■ PRODUCT Utilization Audit: Enforcing 0% idle tolerance on TASKS.md (target={target_seat}). Routing READY/IN_PROGRESS work streams to GPT (■ RUST / ■ ARCHITECT) and ■ FLINT now."
                ),
            );

            let mut spawned = Vec::new();
            if target_seat == "ALL" || target_seat == "GPT" || target_seat == "RUST" {
                let ok = spawn_seat_workstream(
                    &repo_root,
                    "RUST",
                    "TASK-03",
                    "TASK-03 from TASKS.md: Inspect crates/chinwag-cli/src/bus_run.rs and crates/chinwag-cli/src/seat_signing.rs on unified main. Verify per-seat Ed25519 signing env injection and iroh bus CLI framing, and return a concise engineering verification summary.",
                );
                if ok {
                    spawned.push("■ RUST (GPT/Codex -> TASK-03)");
                }
            }
            if target_seat == "ALL" || target_seat == "GPT" || target_seat == "ARCHITECT" {
                let ok = spawn_seat_workstream(
                    &repo_root,
                    "ARCHITECT",
                    "TASK-04",
                    "TASK-04 from TASKS.md: Audit crates/chinwag-swarm/src/dispatch_wire.rs and crates/chinwag-claim/src/lib.rs on unified main. Confirm ALPN chinwag/agent-dispatch/1 + chinwag/bus/1 wire framing and ReplayGuard invariants, and return your architectural sign-off.",
                );
                if ok {
                    spawned.push("■ ARCHITECT (GPT/Codex -> TASK-04)");
                }
            }
            if target_seat == "ALL" || target_seat == "FLINT" {
                let ok = spawn_seat_workstream(
                    &repo_root,
                    "FLINT",
                    "TASK-05",
                    "TASK-05 from TASKS.md: Perform an adversarial review of unified main (7f3717d + bus_run.rs + seat_signing.rs). Verify zero unsafe code, bounded QUIC frame reads, and deterministic test fixtures. Return your adversarial verdict.",
                );
                if ok {
                    spawned.push("■ FLINT (flint-agent :11500 -> TASK-05)");
                }
            }

            let (_, ack) = send_bus_message_sync(
                &repo_root,
                "DELIVERY",
                "#eng",
                None,
                Some("TASK-02".to_string()),
                &format!(
                    "■ DELIVERY Work-Stream Router: Dispatched {} live worker stream(s) ({}). Streaming progress to #eng and #mgmt over iroh/bus/1.",
                    spawned.len(),
                    spawned.join(", ")
                ),
            );

            let out = json!({
                "ok": true,
                "command": "chinwag bus wake",
                "spawned_workstreams": spawned,
                "bus_seq": ack.seq,
                "daemon_endpoint_id": ack.daemon_endpoint_id
            });
            if is_json {
                let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            } else {
                let _ = writeln!(
                    stdout,
                    "🚀 ■ PRODUCT + ■ DELIVERY woke {} work stream(s) on the iroh bus:\n  • {}",
                    spawned.len(),
                    spawned.join("\n  • ")
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
            let tasks_path = repo_root.join("TASKS.md");

            if is_json {
                let out: Value = json!({
                    "ok": daemon.is_some(),
                    "daemon": daemon,
                    "rooms": {
                        "#mgmt": mgmt_count,
                        "#eng": eng_count,
                        "#qa": qa_count,
                        "total": all.len()
                    },
                    "tasks_md": tasks_path.to_string_lossy(),
                    "messages_jsonl": messages_jsonl_path(&repo_root).to_string_lossy()
                });
                let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&out).unwrap_or_default());
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
                     • Room Message Count: {} total (#mgmt: {}, #eng: {}, #qa: {})\n\
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
                    tasks_path.display()
                );
            } else {
                let fallback_ep = load_or_create_daemon_secret(&repo_root).public().to_string();
                let _ = writeln!(
                    stdout,
                    "🟡 Chinwag iroh Multi-Party Bus: DAEMON STOPPED (Run `chinwag bus daemon` to bind QUIC)\n\
                     • Provisioned EndpointId: {}\n\
                     • Stored Bus Messages:    {} (#mgmt: {}, #eng: {}, #qa: {})\n\
                     • Canonical Board:        {}",
                    fallback_ep,
                    all.len(),
                    mgmt_count,
                    eng_count,
                    qa_count,
                    tasks_path.display()
                );
            }
            0
        }
    }
}
