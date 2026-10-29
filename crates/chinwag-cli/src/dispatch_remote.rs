//! Explicitly configured, room-only dispatch runtime. No key or room defaults.
use crate::{
    DispatchNetworkRequest,
    dispatch_listen::{Listener, LocalDispatcher},
};
use chinwag_swarm::{
    DiscoveryScope, bind_sovereign_endpoint,
    dispatch_wire::{self as wire, Payload, Refused, Request, Response},
    identity::Identity,
    lan::LanInterfaces,
    relay_policy::RelayPolicy,
    room::{RoomClient, RoomSession},
};
use iroh::{Endpoint, EndpointId, address_lookup::memory::MemoryLookup};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) fn now() -> Result<u64, Refused> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| Refused)
}

// Normalize the local stdin contract before signing. A remote CRDB path is
// accepted for input compatibility but never selects a Studio filesystem path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StdinPayload {
    agent: String,
    sender: Option<String>,
    body: Option<String>,
    message: Option<String>,
    #[serde(rename = "itemKey")]
    item_key: Option<String>,
    item: Option<String>,
    crdb: Option<String>,
    #[serde(default)]
    history: Vec<wire::HistoryEntry>,
    #[serde(rename = "customAgent")]
    custom_agent: Option<wire::CustomAgent>,
}
fn read_payload(input: &mut dyn Read) -> Result<Payload, Refused> {
    let mut bytes = Vec::new();
    input
        .take(wire::MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Refused)?;
    if bytes.len() > wire::MAX_REQUEST_BYTES {
        return Err(Refused);
    }
    let mut raw: StdinPayload = serde_json::from_slice(&bytes).map_err(|_| Refused)?;
    if raw
        .crdb
        .as_ref()
        .is_some_and(|path| path.len() > 4096 || path.contains('\0'))
    {
        return Err(Refused);
    }
    if raw.history.len() > 10 {
        raw.history.drain(..raw.history.len() - 10);
    }
    let payload = Payload {
        agent: raw.agent,
        sender: raw.sender.unwrap_or_else(|| "Brian".into()),
        body: raw.body.or(raw.message).ok_or(Refused)?,
        item_key: raw
            .item_key
            .or(raw.item)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "chinwag-v0.1.1-sprint".into()),
        history: raw.history,
        custom_agent: raw.custom_agent,
    };
    payload.validate()?;
    Ok(payload)
}

struct Network {
    identity: Arc<Identity>,
    endpoint: Endpoint,
    room: Arc<Mutex<RoomSession>>,
    peer: EndpointId,
}
impl Network {
    async fn open(config: &DispatchNetworkRequest) -> Result<Self, Refused> {
        let peer: EndpointId = config.peer.parse().map_err(|_| Refused)?;
        let coordinator: EndpointId = config.coordinator.parse().map_err(|_| Refused)?;
        let local: Ipv4Addr = config.local_ipv4.parse().map_err(|_| Refused)?;
        let identity = Arc::new(Identity::from_ssh_signing_file(&config.key).map_err(|_| Refused)?);
        let policy = Arc::new(RelayPolicy::Disabled);
        let client =
            RoomClient::new(&config.room, coordinator, policy.clone()).map_err(|_| Refused)?;
        let book = MemoryLookup::new();
        let endpoint = bind_sovereign_endpoint(
            &identity,
            book.clone(),
            peer,
            LanInterfaces::new(vec![local]).map_err(|_| Refused)?,
            DiscoveryScope::RoomOnly,
            vec![wire::ALPN.to_vec()],
            &policy,
        )
        .await
        .map_err(|_| Refused)?;
        let opened = async {
            let addresses = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let addresses = endpoint
                        .addr()
                        .ip_addrs()
                        .copied()
                        .filter(|addr| addr.ip() == std::net::IpAddr::V4(local))
                        .collect::<Vec<_>>();
                    if !addresses.is_empty() {
                        break addresses;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| Refused)?;
            let mut room = client
                .open(&identity, peer, addresses, book)
                .await
                .map_err(|_| Refused)?;
            if room.receive_peer().await.is_err() || room.require_fresh_peer().is_err() {
                room.close().await;
                return Err(Refused);
            }
            Ok::<_, Refused>(room)
        }
        .await;
        match opened {
            Ok(room) => Ok(Self {
                identity,
                endpoint,
                room: Arc::new(Mutex::new(room)),
                peer,
            }),
            Err(error) => {
                endpoint.close().await;
                Err(error)
            }
        }
    }
    async fn close(self) {
        if let Ok(mutex) = Arc::try_unwrap(self.room)
            && let Ok(mut room) = mutex.into_inner()
        {
            room.close().await;
        }
        self.endpoint.close().await;
    }
}

/// One request/connection, EOF framing, no retry. Caller has checked its room
/// lease immediately before dialing; response identity and binding are rechecked.
pub(crate) async fn exchange(
    endpoint: &Endpoint,
    peer: EndpointId,
    request: &Request,
    admit_until: tokio::time::Instant,
) -> Result<Response, Refused> {
    tokio::time::timeout(Duration::from_secs(600), async {
        let connection = tokio::time::timeout_at(admit_until, endpoint.connect(peer, wire::ALPN))
            .await
            .map_err(|_| Refused)?
            .map_err(|_| Refused)?;
        let result = async {
            if tokio::time::Instant::now() >= admit_until
                || connection.remote_id() != peer
                || connection.alpn() != wire::ALPN
            {
                return Err(Refused);
            }
            let (mut send, mut recv) = connection.open_bi().await.map_err(|_| Refused)?;
            tokio::time::timeout_at(admit_until, send.write_all(&request.to_bytes()?))
                .await
                .map_err(|_| Refused)?
                .map_err(|_| Refused)?;
            send.finish().map_err(|_| Refused)?;
            let bytes = recv
                .read_to_end(wire::MAX_RESPONSE_BYTES)
                .await
                .map_err(|_| Refused)?;
            let response = Response::from_bytes(&bytes)?;
            response.verify(peer, request, now()?)?;
            Ok(response)
        }
        .await;
        if result.is_ok() {
            // Let the server observe FIN acknowledgments before its close.
            let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
        }
        connection.close(0u32.into(), b"dispatch_finished");
        result
    })
    .await
    .map_err(|_| Refused)?
}

async fn run(
    config: DispatchNetworkRequest,
    payload: Option<Payload>,
) -> Result<Option<Response>, Refused> {
    let started = now()?;
    let status = if config.listen {
        Some(Arc::new(super::dispatch_status::StatusStore::start(
            &config.repo,
            started,
        )?))
    } else {
        None
    };
    let network = Network::open(&config).await?;
    let result = async {
        if config.listen {
            let lease = network
                .room
                .lock()
                .map_err(|_| Refused)?
                .remaining_peer_validity()
                .map_err(|_| Refused)?;
            let status = status.as_ref().ok_or(Refused)?.clone();
            status.ready(now()?, now()?.checked_add(lease.as_secs()).ok_or(Refused)?)?;
            let listener = Arc::new(Listener::new(
                network.identity.clone(),
                network.peer,
                network.room.clone(),
                LocalDispatcher { repo: config.repo },
                started,
                status.clone(),
            ));
            listener.serve(&network.endpoint, lease).await?;
            Ok(None)
        } else {
            let validity = network
                .room
                .lock()
                .map_err(|_| Refused)?
                .remaining_peer_validity()
                .map_err(|_| Refused)?;
            let admit_until = tokio::time::Instant::now() + validity;
            // The verified Studio advertisement was created after its process
            // started. Cross one clock second before signing so a first client
            // does not collide with the listener's startup replay watermark.
            tokio::time::timeout_at(admit_until, tokio::time::sleep(Duration::from_secs(1)))
                .await
                .map_err(|_| Refused)?;
            let request = Request::sign(
                &network.identity,
                network.peer,
                payload.ok_or(Refused)?,
                rand::random(),
                now()?,
            )?;
            exchange(&network.endpoint, network.peer, &request, admit_until)
                .await
                .map(Some)
        }
    }
    .await;
    network.close().await;
    if let Some(status) = status {
        status.record(super::dispatch_status::Event::Stopped, now()?)?;
    }
    result
}

pub fn run_agent_dispatch_network(
    config: DispatchNetworkRequest,
    input: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let payload = if config.listen {
        None
    } else {
        match read_payload(input) {
            Ok(payload) => Some(payload),
            Err(_) => {
                let _ = writeln!(err, "chinwag: dispatch_refused");
                return 2;
            }
        }
    };
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| Refused)
        .and_then(|runtime| runtime.block_on(run(config, payload)));
    match result {
        Ok(Some(response)) => {
            if out.write_all(response.reply.as_bytes()).is_err() || out.flush().is_err() {
                return 1;
            }
            if !response.ok {
                let _ = writeln!(err, "chinwag: dispatch_failed");
            }
            response.exit_code
        }
        Ok(None) => 0,
        Err(_) => {
            let _ = writeln!(err, "chinwag: dispatch_refused");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdin_preserves_signed_context_and_last_ten_history_entries() {
        let history = (0..12).map(|i|serde_json::json!({"sender":"Brian", "role":"user", "body":format!("fixture {i}")})).collect::<Vec<_>>();
        let input = serde_json::json!({"agent":"RUST","body":"hello","history":history,"customAgent":{"role":"engineer","dept":"engineering","engine":"codex","system_prompt":"inert fixture"}});
        let payload = read_payload(&mut serde_json::to_vec(&input).unwrap().as_slice()).unwrap();
        assert_eq!(payload.history.len(), 10);
        assert_eq!(payload.history[0].body.as_deref(), Some("fixture 2"));
        assert_eq!(
            payload.custom_agent.unwrap().engine.as_deref(),
            Some("codex")
        );
    }

    #[test]
    fn stdin_matches_local_core_fields_defaults_and_aliases() {
        let payload =
            read_payload(&mut br#"{"agent":"RUST","message":"hello","item":"task"}"#.as_slice())
                .unwrap();
        assert_eq!(payload.sender, "Brian");
        assert_eq!(payload.item_key, "task");
        assert_eq!(payload.body, "hello");
        let payload=read_payload(&mut br#"{"agent":"RUST","body":"preferred","message":"other","itemKey":"preferred","item":"other","sender":"Nic"}"#.as_slice()).unwrap();
        assert_eq!(payload.sender, "Nic");
        assert_eq!(payload.body, "preferred");
        assert_eq!(payload.item_key, "preferred");
        assert!(
            read_payload(&mut br#"{"agent":"RUST","body":"hello","crdb":"/tmp/other"}"#.as_slice())
                .is_ok()
        );
        for input in [
            br#"{"agent":"RUST","body":"hello","extra":1}"#.as_slice(),
            br#"{"agent":"RUST","body":""}"#.as_slice(),
        ] {
            let mut reader: &[u8] = input;
            assert!(read_payload(&mut reader).is_err());
        }
    }
}
