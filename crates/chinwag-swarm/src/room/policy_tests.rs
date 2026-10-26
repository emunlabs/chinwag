//! Loopback receive_peer coverage. Not a physical pair and not room.open.

use super::{Error, RoomProof, RoomSession};
use crate::identity::Identity;
use crate::relay_policy::RelayPolicy;
use crate::room_wire::{self, Advertisement};
use futures_util::SinkExt;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::{EndpointAddr, EndpointId, TransportAddr};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_websockets::{ClientBuilder, MaybeTlsStream, Message, ServerBuilder};

const BOUND: Duration = Duration::from_millis(1000);
const SESSION_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SESSION_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NONCE_A: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const NONCE_B: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

async fn within<T>(work: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(BOUND, work).await {
        Ok(value) => value,
        Err(_) => panic!("loopback fixture exceeded 1000ms"),
    }
}

fn identity() -> Identity {
    Identity::test_identity([7; 32])
}

fn hex_id(id: EndpointId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id.as_bytes() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn proof() -> RoomProof {
    RoomProof {
        attach_challenge_ray: "fixture".into(),
        websocket_ray: "fixture".into(),
        advertise_challenge_ray: "fixture".into(),
        stored_ray: "fixture".into(),
        coordinator_receipt_verified: true,
    }
}

fn own_policy() -> Arc<RelayPolicy> {
    Arc::new(
        RelayPolicy::from_local_manifest(
            Some("https://pair-relay.invalid"),
            Some("https://pair-relay.invalid:443"),
        )
        .unwrap(),
    )
}

fn disabled_policy() -> Arc<RelayPolicy> {
    Arc::new(RelayPolicy::from_local_manifest(None, None).unwrap())
}

fn signed(
    id: &Identity,
    session: &str,
    nonce: &str,
    revision: u64,
    port: u16,
    expiry: u64,
    now: u64,
) -> Advertisement {
    let challenge = room_wire::Challenge {
        room: "genesis".into(),
        actor_id: hex_id(id.endpoint_id()),
        operation: "advertise".into(),
        session_id: session.into(),
        nonce: nonce.into(),
        expiry_unix: expiry,
    };
    let addresses = vec![SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), port))];
    room_wire::sign_advertisement(id, &challenge, revision, addresses, now).unwrap()
}

fn frame(advert: &Advertisement) -> String {
    let body = serde_json::to_string(advert).unwrap();
    format!(r#"{{"kind":"peer_advertisement","advertisement":{body}}}"#)
}

struct Sender(Option<tokio::task::JoinHandle<()>>);

impl Sender {
    async fn finish(mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
            let result = within(handle).await;
            assert!(result.is_ok() || result.is_err_and(|error| error.is_cancelled()));
        }
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

async fn session_with(policy: Arc<RelayPolicy>) -> (RoomSession, mpsc::Sender<String>, Sender) {
    let listener = within(TcpListener::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0,
    ))))
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let client_tcp = within(TcpStream::connect(address)).await.unwrap();
    let (server_tcp, _) = within(listener.accept()).await.unwrap();
    let client = ClientBuilder::new().take_over(MaybeTlsStream::Plain(client_tcp));
    let mut server = ServerBuilder::new().serve(MaybeTlsStream::Plain(server_tcp));
    let (tx, mut rx) = mpsc::channel(4);
    let handle = tokio::spawn(async move {
        while let Ok(Some(text)) = tokio::time::timeout(BOUND, rx.recv()).await {
            if tokio::time::timeout(BOUND, server.send(Message::text(text)))
                .await
                .ok()
                .and_then(Result::ok)
                .is_none()
            {
                break;
            }
        }
    });
    let id = identity();
    let session = RoomSession {
        socket: client,
        other: id.endpoint_id(),
        book: MemoryLookup::new(),
        revisions: Default::default(),
        peer_expiry: None,
        proof: Some(proof()),
        attached_session_id: None,
        policy,
    };
    (session, tx, Sender(Some(handle)))
}

async fn push(tx: &mpsc::Sender<String>, advert: &Advertisement) {
    within(tx.send(frame(advert))).await.unwrap();
}

fn published(session: &RoomSession) -> Option<EndpointAddr> {
    session
        .book
        .get_endpoint_info(session.other)
        .map(|info| info.to_endpoint_addr())
}

#[tokio::test]
async fn own_signed_record_publishes_direct_sockets_and_the_policy_url() {
    let id = identity();
    let policy = own_policy();
    let now = super::now_unix().unwrap();
    let advert = signed(&id, SESSION_A, NONCE_A, 1, 9, now + 60, now);
    let (mut session, tx, sender) = session_with(Arc::clone(&policy)).await;
    push(&tx, &advert).await;
    within(session.receive_peer()).await.unwrap();
    let addr = published(&session).unwrap();
    assert!(
        addr.ip_addrs()
            .any(|socket| *socket == "192.0.2.10:9".parse().unwrap())
    );
    assert!(
        addr.addrs
            .contains(&TransportAddr::Relay(policy.relay_url().unwrap().clone()))
    );
    assert_eq!(session.peer_expiry, Some(now + 60));
    drop(tx);
    sender.finish().await;
}

#[tokio::test]
async fn disabled_signed_record_publishes_ip_only() {
    let id = identity();
    let now = super::now_unix().unwrap();
    let advert = signed(&id, SESSION_A, NONCE_A, 1, 9, now + 60, now);
    let (mut session, tx, sender) = session_with(disabled_policy()).await;
    push(&tx, &advert).await;
    within(session.receive_peer()).await.unwrap();
    let addr = published(&session).unwrap();
    assert!(
        addr.ip_addrs()
            .any(|socket| *socket == "192.0.2.10:9".parse().unwrap())
    );
    assert!(
        addr.addrs
            .iter()
            .all(|item| matches!(item, TransportAddr::Ip(_)))
    );
    assert_eq!(session.peer_expiry, Some(now + 60));
    drop(tx);
    sender.finish().await;
}

#[tokio::test]
async fn tamper_and_expiry_do_not_publish() {
    let id = identity();
    let now = super::now_unix().unwrap();
    let mut tampered = signed(&id, SESSION_A, NONCE_A, 1, 9, now + 60, now);
    tampered.signature = "0".repeat(128);
    let (mut session, tx, sender) = session_with(own_policy()).await;
    push(&tx, &tampered).await;
    let error = within(session.receive_peer()).await.unwrap_err();
    assert!(matches!(error, Error::Wire(room_wire::Error::Signature)));
    assert!(published(&session).is_none());
    assert!(session.peer_expiry.is_none());
    let expired = signed(&id, SESSION_A, NONCE_A, 1, 9, 1_600_000_030, 1_600_000_000);
    push(&tx, &expired).await;
    let error = within(session.receive_peer()).await.unwrap_err();
    assert!(matches!(error, Error::Wire(room_wire::Error::Expired)));
    assert!(published(&session).is_none());
    assert!(session.peer_expiry.is_none());
    drop(tx);
    sender.finish().await;
}

#[tokio::test]
async fn replay_and_retired_revision_leave_the_published_record() {
    let id = identity();
    let now = super::now_unix().unwrap();
    let first = signed(&id, SESSION_A, NONCE_A, 1, 9, now + 40, now);
    let second = signed(&id, SESSION_B, NONCE_B, 1, 10, now + 80, now);
    let retired = signed(&id, SESSION_A, NONCE_A, 2, 11, now + 40, now);
    let (mut session, tx, sender) = session_with(own_policy()).await;
    push(&tx, &first).await;
    within(session.receive_peer()).await.unwrap();
    let after_first = published(&session);
    let expiry = session.peer_expiry;
    push(&tx, &first).await;
    let error = within(session.receive_peer()).await.unwrap_err();
    assert!(matches!(error, Error::Replay));
    assert_eq!(published(&session), after_first);
    assert_eq!(session.peer_expiry, expiry);
    push(&tx, &second).await;
    within(session.receive_peer()).await.unwrap();
    let after_second = published(&session);
    let second_expiry = session.peer_expiry;
    assert_ne!(after_second, after_first);
    push(&tx, &retired).await;
    let error = within(session.receive_peer()).await.unwrap_err();
    assert!(matches!(error, Error::Replay));
    assert_eq!(published(&session), after_second);
    assert_eq!(session.peer_expiry, second_expiry);
    drop(tx);
    sender.finish().await;
}
