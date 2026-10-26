//! Synthetic identity and real loopback HTTPS checks. No real keys or trust changes.
use super::*;
use crate::room::clean_origin;
use chinwag_claim::{ClaimReceiptUnsigned, SignedClaimRequest};
use ed25519_dalek::SigningKey;
use futures_util::{FutureExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

const ROOT: &[u8] = include_bytes!("fixtures/test-root.der");
const LEAF: &[u8] = include_bytes!("fixtures/test-server.der");
const KEY: &[u8] = include_bytes!("fixtures/test-server.pkcs8.der");
const SESSION: &str = "2222222222222222222222222222222222222222222222222222222222222222";
fn coordinator() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
#[derive(Clone, Copy)]
enum Response {
    Refuse,
    Hang,
    Signed(&'static str),
    Forged,
}
struct CapturedRequest {
    phase: String,
    body: Vec<u8>,
}
struct Fixture {
    origin: String,
    count: Arc<AtomicUsize>,
    seen: Arc<StdMutex<Vec<CapturedRequest>>>,
    task: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(dir: &Path, response: Response) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}/", listener.local_addr().unwrap());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(LEAF.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
        )
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let captured = seen.clone();
        let path = dir.join("attempt.json");
        let task = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let captured = captured.clone();
                let path = path.clone();
                handlers.spawn(async move {
                    let phase=serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap()["state"].as_str().unwrap().to_owned();
                    let mut tls=timeout(Duration::from_secs(4),acceptor.accept(tcp)).await.unwrap().unwrap();
                    let mut raw=Vec::new();let split;
                    loop {
                        let mut buffer=[0u8;1024];let n=timeout(Duration::from_secs(4),tls.read(&mut buffer)).await.unwrap().unwrap();assert!(n>0);raw.extend_from_slice(&buffer[..n]);assert!(raw.len()<=8192);
                        if let Some(index)=raw.windows(4).position(|b|b==b"\r\n\r\n") { split=index+4;break; }
                    }
                    let headers=String::from_utf8(raw[..split].to_vec()).unwrap();assert!(headers.starts_with("POST /room/genesis/claim HTTP/1.1\r\n"));
                    let length=headers.lines().find_map(|line|line.split_once(':').filter(|(key,_)|key.eq_ignore_ascii_case("content-length")).map(|(_,v)|v.trim().parse::<usize>().unwrap())).unwrap();assert!(length<=4096);
                    while raw.len()<split+length {
                        let mut buffer=[0u8;1024];let n=timeout(Duration::from_secs(4),tls.read(&mut buffer)).await.unwrap().unwrap();assert!(n>0);raw.extend_from_slice(&buffer[..n]);assert!(raw.len()<=8192);
                    }
                    let body=raw[split..split+length].to_vec();captured.lock().unwrap().push(CapturedRequest { phase, body: body.clone() });
                    if matches!(response,Response::Hang) { std::future::pending::<()>().await; }
                    let (status,body)=match response {
                        Response::Refuse | Response::Hang => (403,b"{\"error\":\"claim_policy\"}".to_vec()),
                        Response::Signed(disposition) => (200,signed_reply(&body,disposition,false)),
                        Response::Forged => (200,signed_reply(&body,"freshly_stored",true)),
                    };
                    let header=format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\ncf-ray: claim-slot-TEST\r\n\r\n",body.len());
                    tls.write_all(header.as_bytes()).await.unwrap();tls.write_all(&body).await.unwrap();let _=tls.shutdown().await;
                });
            }
        });
        Self {
            origin,
            count,
            seen,
            task,
        }
    }
    fn service(&self, dir: &Path) -> ClaimService {
        let identity = Identity::test_identity([7; 32]);
        let coordinator = EndpointId::from_bytes(coordinator().verifying_key().as_bytes()).unwrap();
        let pinned_coordinator = *coordinator.as_bytes();
        let binding = AttemptBinding::new(
            &self.origin,
            identity.ssh_public_bytes(),
            *coordinator.as_bytes(),
        )
        .unwrap();
        let journal = AttemptJournal::open(dir, binding).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ROOT.to_vec())).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        ClaimService {
            journal,
            identity,
            client: RoomClient::from_tls(
                clean_origin(&self.origin).unwrap(),
                coordinator,
                tls,
                Arc::new(RelayPolicy::Disabled),
            )
            .unwrap(),
            peer: Identity::test_identity([8; 32]).endpoint_id(),
            lan: "192.0.2.1".parse().unwrap(),
            coordinator: pinned_coordinator,
            endpoint: None,
            room: None,
            room_start_attempted: false,
            peer_plane: None,
            peer_recv_once: false,
            peer_start_once: false,
            lease: None,
            test_observed: None,
            closed: false,
        }
    }
    async fn request_seen(&self) {
        timeout(Duration::from_secs(3), async {
            while self.seen.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    fn assert_one(&self, dir: &Path) {
        assert_eq!(self.count.load(Ordering::SeqCst), 1);
        let seen = self.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].phase, "unknown");
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("attempt.json")).unwrap()).unwrap();
        assert_eq!(
            seen[0].body,
            record["request_json"].as_str().unwrap().as_bytes()
        );
    }
}
fn signed_reply(raw: &[u8], disposition: &str, forged: bool) -> Vec<u8> {
    let signed: SignedClaimRequest = serde_json::from_slice(raw).unwrap();
    let request = &signed.request;
    let mut receipt = ClaimReceiptUnsigned {
        claim_id: request.claim_id.clone(),
        actor: request.actor.clone(),
        session: request.session.clone(),
        pr: request.pr,
        files: request.files.clone(),
        revision: 1,
        issued: request.issued,
        expiry: request.expiry,
        request_sha256: signed.request_sha256_hex().unwrap(),
        coordinator: encode_hex(coordinator().verifying_key().as_bytes()),
    }
    .sign(&coordinator())
    .unwrap();
    if forged {
        receipt.signature = "00".repeat(64);
    }
    serde_json::to_vec(&serde_json::json!({"disposition":disposition,"receipt_json":serde_json::to_string(&receipt).unwrap()})).unwrap()
}

#[tokio::test]
async fn claim_slot_real_refusal_second_call_and_reopen_make_one_post_total() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Refuse).await;
    let mut service = fixture.service(dir.path());
    let first = service.submit_empty(Some(SESSION)).await.unwrap();
    assert_eq!(
        first,
        ClaimTaskReport::Refused {
            status: 403,
            code: "claim_policy".into(),
            cf_ray: "claim-slot-TEST".into()
        }
    );
    let before = std::fs::read(dir.path().join("attempt.json")).unwrap();
    assert_eq!(service.claim_task().await.unwrap(), first);
    assert!(service.endpoint.is_none() && service.room.is_none());
    drop(service);
    let mut reopened = fixture.service(dir.path());
    assert_eq!(reopened.claim_task().await.unwrap(), first);
    assert_eq!(
        std::fs::read(dir.path().join("attempt.json")).unwrap(),
        before
    );
    fixture.assert_one(dir.path());
}

#[tokio::test]
async fn claim_slot_cancel_after_unknown_never_reposts_or_replaces_original() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Hang).await;
    let shared = Arc::new(tokio::sync::Mutex::new(fixture.service(dir.path())));
    let owner = shared.clone();
    let call = tokio::spawn(async move { owner.lock().await.submit_empty(Some(SESSION)).await });
    fixture.request_seen().await;
    let original = std::fs::read(dir.path().join("attempt.json")).unwrap();
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    let report = timeout(Duration::from_secs(1), async {
        shared.lock().await.claim_task().await
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(report, ClaimTaskReport::OriginalUnresolved);
    assert_eq!(
        std::fs::read(dir.path().join("attempt.json")).unwrap(),
        original
    );
    drop(shared);
    let mut reopened = fixture.service(dir.path());
    assert_eq!(
        reopened.claim_task().await.unwrap(),
        ClaimTaskReport::OriginalUnresolved
    );
    assert_eq!(
        std::fs::read(dir.path().join("attempt.json")).unwrap(),
        original
    );
    fixture.assert_one(dir.path());
}

#[tokio::test]
async fn claim_slot_concurrent_calls_share_one_original() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Refuse).await;
    let shared = Arc::new(tokio::sync::Mutex::new(fixture.service(dir.path())));
    let a = shared.clone();
    let b = shared.clone();
    let (a, b) = tokio::join!(
        async move { a.lock().await.submit_empty(Some(SESSION)).await },
        async move { b.lock().await.submit_empty(Some(SESSION)).await }
    );
    assert_eq!(a.unwrap(), b.unwrap());
    fixture.assert_one(dir.path());
}

#[tokio::test]
async fn claim_slot_signed_outcomes_are_metadata_only_and_forgery_is_unresolved() {
    for response in [
        Response::Signed("outcome_resolution"),
        Response::Signed("freshly_stored"),
        Response::Forged,
    ] {
        let dir = private_dir();
        let fixture = Fixture::new(dir.path(), response).await;
        let mut service = fixture.service(dir.path());
        let report = service.submit_empty(Some(SESSION)).await.unwrap();
        if matches!(response, Response::Forged) {
            assert_eq!(report, ClaimTaskReport::OriginalUnresolved);
        } else {
            assert_eq!(
                report,
                ClaimTaskReport::Reported {
                    disposition: "stored_authenticated_outcome",
                    cf_ray: "claim-slot-TEST".into()
                }
            );
            assert_eq!(
                serde_json::to_value(&report).unwrap(),
                serde_json::json!({"outcome":"reported","disposition":"stored_authenticated_outcome","cf_ray":"claim-slot-TEST"})
            );
        }
        assert_eq!(service.claim_task().await.unwrap(), report);
        fixture.assert_one(dir.path());
    }
}

#[tokio::test]
async fn claim_slot_missing_session_armed_corruption_and_shutdown_open_zero_sockets() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Refuse).await;
    let mut service = fixture.service(dir.path());
    let actor_bytes = Identity::test_identity([7; 32]).ssh_public_bytes();
    let peer = Identity::test_identity([8; 32]).endpoint_id();
    assert!(service.matches_bundle_pins(actor_bytes, peer));
    assert!(!service.matches_bundle_pins([0; 32], peer));
    assert!(
        !service.matches_bundle_pins(actor_bytes, Identity::test_identity([9; 32]).endpoint_id())
    );
    assert!(matches!(
        service.submit_empty(None).await,
        Err(ClaimTaskError::SessionUnavailable)
    ));
    assert!(service.journal.load().unwrap().is_none());
    let identity = Identity::test_identity([7; 32]);
    let signed = identity
        .sign_claim(ClaimRequestUnsigned {
            claim_id: "11".repeat(32),
            actor: encode_hex(&identity.ssh_public_bytes()),
            session: SESSION.into(),
            nonce: "33".repeat(32),
            pr: Pr::Pr01,
            files: vec![FILE.into()],
            expected_revision: 0,
            issued: 1700000000,
            expiry: 1700000060,
        })
        .unwrap();
    service
        .journal
        .arm(&PreparedClaim::from_signed(signed).unwrap())
        .unwrap();
    assert_eq!(
        service.claim_task().await.unwrap(),
        ClaimTaskReport::OriginalUnresolved
    );
    drop(service);
    let mut reopened = fixture.service(dir.path());
    assert_eq!(
        reopened.claim_task().await.unwrap(),
        ClaimTaskReport::OriginalUnresolved
    );
    std::fs::write(dir.path().join("attempt.json"), b"corrupt").unwrap();
    assert!(matches!(
        reopened.claim_task().await,
        Err(ClaimTaskError::Journal(AttemptError::Corrupt))
    ));
    reopened.shutdown().await;
    assert!(!reopened.matches_bundle_pins(actor_bytes, peer));
    assert!(matches!(
        reopened.claim_task().await,
        Err(ClaimTaskError::Closed)
    ));
    assert_eq!(fixture.count.load(Ordering::SeqCst), 0);
    assert!(reopened.endpoint.is_none() && reopened.room.is_none());
    println!(
        "host_pin_preflight actual_fixture_identity=true wrong_actor_peer_refused=true closed_refused=true zero_room_sockets=true metadata_only=true"
    );
}

#[tokio::test]
async fn fresh_acceptance_leases_this_process_and_a_second_authorize_does_not_post() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Signed("freshly_stored")).await;
    let mut service = fixture.service(dir.path());
    let report = service.submit_empty(Some(SESSION)).await.unwrap();
    assert_eq!(
        report,
        ClaimTaskReport::Reported {
            disposition: "stored_authenticated_outcome",
            cf_ray: "claim-slot-TEST".into(),
        }
    );
    assert!(service.lease.is_some());
    let path = Path::new(CLAIM_FILE);
    service
        .authorize_local_write(path)
        .unwrap()
        .validate(path)
        .unwrap();
    assert_eq!(service.claim_task().await.unwrap(), report);
    service
        .authorize_local_write(path)
        .unwrap()
        .validate(path)
        .unwrap();
    assert!(matches!(
        service.authorize_local_write(Path::new("./crates/chinwag-seed/src/main.rs")),
        Err(LeaseError::Path)
    ));
    assert!(matches!(
        service.authorize_local_write(Path::new("crates/chinwag-seed/src/lib.rs")),
        Err(LeaseError::Path)
    ));
    service.test_observed = None;
    assert!(matches!(
        service.authorize_local_write(path),
        Err(LeaseError::Session)
    ));
    assert!(service.lease.is_some());
    service.test_observed = Some(SESSION.to_owned());
    service.authorize_local_write(path).unwrap();
    fixture.assert_one(dir.path());
}

#[tokio::test]
async fn fresh_lease_rejects_wall_before_issue_exact_expiry_and_past_deadline() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Signed("freshly_stored")).await;
    let mut service = fixture.service(dir.path());
    service.submit_empty(Some(SESSION)).await.unwrap();
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("attempt.json")).unwrap()).unwrap();
    let signed: SignedClaimRequest =
        serde_json::from_str(record["request_json"].as_str().unwrap()).unwrap();
    let issued = signed.request.issued;
    let expiry = signed.request.expiry;
    let path = Path::new(CLAIM_FILE);
    let witness = service.authorize_local_write(path).unwrap();
    let now = std::time::Instant::now();
    assert_eq!(
        witness.validate_at(path, issued - 1, now),
        Err(LeaseError::Expired)
    );
    assert_eq!(
        witness.validate_at(path, expiry, now),
        Err(LeaseError::Expired)
    );
    assert_eq!(
        witness.validate_at(path, issued, now + std::time::Duration::from_secs(120)),
        Err(LeaseError::Expired)
    );
    witness.validate_at(path, issued, now).unwrap();
    fixture.assert_one(dir.path());
}

#[tokio::test]
async fn refused_historical_and_unknown_do_not_install_a_lease() {
    for response in [
        Response::Refuse,
        Response::Signed("outcome_resolution"),
        Response::Forged,
    ] {
        let dir = private_dir();
        let fixture = Fixture::new(dir.path(), response).await;
        let mut service = fixture.service(dir.path());
        service.submit_empty(Some(SESSION)).await.unwrap();
        assert!(service.lease.is_none());
        assert!(matches!(
            service.authorize_local_write(Path::new(CLAIM_FILE)),
            Err(LeaseError::Unavailable)
        ));
        fixture.assert_one(dir.path());
    }
}

#[tokio::test]
async fn reopened_verified_journal_has_no_lease() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Signed("freshly_stored")).await;
    let mut service = fixture.service(dir.path());
    let report = service.submit_empty(Some(SESSION)).await.unwrap();
    let before = std::fs::read(dir.path().join("attempt.json")).unwrap();
    drop(service);
    let mut reopened = fixture.service(dir.path());
    assert_eq!(reopened.claim_task().await.unwrap(), report);
    assert!(reopened.lease.is_none());
    assert!(matches!(
        reopened.authorize_local_write(Path::new(CLAIM_FILE)),
        Err(LeaseError::Unavailable)
    ));
    assert_eq!(
        std::fs::read(dir.path().join("attempt.json")).unwrap(),
        before
    );
    fixture.assert_one(dir.path());
}

#[tokio::test]
async fn shutdown_clears_the_live_lease() {
    let dir = private_dir();
    let fixture = Fixture::new(dir.path(), Response::Signed("freshly_stored")).await;
    let mut service = fixture.service(dir.path());
    service.submit_empty(Some(SESSION)).await.unwrap();
    assert!(service.lease.is_some());
    service.shutdown().await;
    assert!(service.lease.is_none());
    assert!(service.test_observed.is_none());
    assert!(matches!(
        service.authorize_local_write(Path::new(CLAIM_FILE)),
        Err(LeaseError::Unavailable)
    ));
    assert!(matches!(
        service.claim_task().await,
        Err(ClaimTaskError::Closed)
    ));
    fixture.assert_one(dir.path());
}

fn arm_peer_fixture(service: &mut ClaimService) -> crate::attempt_journal::ArmedAttempt {
    let issued = now_unix().unwrap();
    let signed = service
        .identity
        .sign_claim(ClaimRequestUnsigned {
            claim_id: "11".repeat(32),
            actor: encode_hex(&service.identity.ssh_public_bytes()),
            session: SESSION.into(),
            nonce: "33".repeat(32),
            pr: Pr::Pr01,
            files: vec![FILE.into()],
            expected_revision: 0,
            issued,
            expiry: issued + 60,
        })
        .unwrap();
    service
        .journal
        .arm(&PreparedClaim::from_signed(signed).unwrap())
        .unwrap()
}

#[tokio::test]
async fn peer_transport_refuses_nonlive_outcomes_without_start_read_or_mutation() {
    for state in [
        "empty",
        "armed",
        "unknown",
        "refused",
        "corrupt",
        "closed",
        "verified_cached",
    ] {
        let dir = private_dir();
        let fixture = Fixture::new(dir.path(), Response::Signed("freshly_stored")).await;
        let mut service = fixture.service(dir.path());
        if state == "verified_cached" {
            service.submit_empty(Some(SESSION)).await.unwrap();
        } else if !matches!(state, "empty" | "closed") {
            let mut attempt = arm_peer_fixture(&mut service);
            if matches!(state, "unknown" | "refused") {
                service.journal.note_unknown(&mut attempt).unwrap();
            }
            if state == "refused" {
                service
                    .journal
                    .note_refused(&mut attempt, 403, "claim_policy", "fixture")
                    .unwrap();
            }
            if state == "corrupt" {
                std::fs::write(dir.path().join("attempt.json"), b"corrupt").unwrap();
            }
        }
        if state == "closed" {
            service.shutdown().await;
        }
        let before = std::fs::read(dir.path().join("attempt.json")).ok();
        for _ in 0..2 {
            assert!(
                matches!(
                    service.prepare_peer_transport().now_or_never(),
                    Some(Err(_))
                ),
                "{state}"
            );
            assert!(service.peer_plane().is_err(), "{state}");
        }
        assert!(!service.peer_recv_once && !service.peer_start_once);
        assert!(
            service.peer_plane.is_none() && service.endpoint.is_none() && service.room.is_none()
        );
        assert_eq!(std::fs::read(dir.path().join("attempt.json")).ok(), before);
        assert_eq!(
            fixture.count.load(Ordering::SeqCst),
            usize::from(state == "verified_cached")
        );
    }
    println!(
        "shared_peer_refusals states7=true immediate=true no_start_read=true original_unchanged=true"
    );
}

async fn attach_peer_fixture(service: &mut ClaimService) -> (Endpoint, tokio::net::TcpStream) {
    let book = MemoryLookup::new();
    let endpoint = crate::base_builder(
        &service.identity,
        vec![b"chinwag-seed-claim/v1".to_vec()],
        service.client.relay_policy(),
    )
    .unwrap()
    .hooks(crate::transport::PinnedEndpoint(service.peer))
    .address_lookup(book.clone())
    .clear_ip_transports()
    .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
    .unwrap()
    .bind()
    .await
    .unwrap();
    let peer_identity = Identity::test_identity([8; 32]);
    let peer_book = MemoryLookup::new();
    peer_book.set_endpoint_info(endpoint.addr());
    let peer_endpoint = crate::base_builder(&peer_identity, vec![], &RelayPolicy::Disabled)
        .unwrap()
        .hooks(crate::transport::PinnedEndpoint(
            service.identity.endpoint_id(),
        ))
        .address_lookup(peer_book)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (peer, _) = listener.accept().await.unwrap();
    let socket = tokio_websockets::ClientBuilder::new()
        .take_over(tokio_websockets::MaybeTlsStream::Plain(client));
    service.endpoint = Some(endpoint);
    service.room = Some(RoomSession {
        socket,
        other: service.peer,
        book,
        revisions: super::super::Revisions::default(),
        policy: Arc::new(RelayPolicy::Disabled),
        peer_expiry: None,
        attached_session_id: Some(SESSION.into()),
        proof: Some(super::super::RoomProof {
            attach_challenge_ray: "fixture-TEST".into(),
            websocket_ray: "fixture-TEST".into(),
            advertise_challenge_ray: "fixture-TEST".into(),
            stored_ray: "fixture-TEST".into(),
            coordinator_receipt_verified: true,
        }),
    });
    service.lease = None; // A transport borrow is not a file-write lease.
    (peer_endpoint, peer)
}

async fn send_peer_frame(stream: &mut tokio::net::TcpStream, text: &str) {
    // Existing fixture uses ClientBuilder::take_over, so send a bounded raw
    // unmasked server text frame. No server feature or production parser added.
    assert!(text.len() <= 2048);
    let mut header = vec![0x81];
    if text.len() < 126 {
        header.push(text.len() as u8);
    } else {
        header.push(126);
        header.extend_from_slice(&(text.len() as u16).to_be_bytes());
    }
    stream.write_all(&header).await.unwrap();
    stream.write_all(text.as_bytes()).await.unwrap();
}

fn peer_frame(endpoint: &Endpoint, revision: u64) -> String {
    let identity = Identity::test_identity([8; 32]);
    let now = now_unix().unwrap();
    let challenge = crate::room_wire::Challenge {
        room: "genesis".into(),
        actor_id: encode_hex(&identity.ssh_public_bytes()),
        operation: "advertise".into(),
        session_id: "44".repeat(32),
        nonce: "55".repeat(32),
        expiry_unix: now + 60,
    };
    let advertisement = crate::room_wire::sign_advertisement(
        &identity,
        &challenge,
        revision,
        endpoint.addr().ip_addrs().copied().collect(),
        now,
    )
    .unwrap();
    serde_json::to_string(
        &serde_json::json!({"kind":"peer_advertisement","advertisement":advertisement}),
    )
    .unwrap()
}

#[tokio::test]
async fn peer_transport_reuses_original_socket_reads_once_and_accepts_real_blob() {
    timeout(Duration::from_secs(20), async {
        let dir = private_dir();
        let fixture = Fixture::new(dir.path(), Response::Signed("freshly_stored")).await;
        let mut service = fixture.service(dir.path());
        service.submit_empty(Some(SESSION)).await.unwrap();
        let before = std::fs::read(dir.path().join("attempt.json")).unwrap();
        let (other, mut peer_socket) = attach_peer_fixture(&mut service).await;
        let own = service.endpoint.as_ref().unwrap().clone();
        let addresses = own.addr().ip_addrs().copied().collect::<Vec<_>>();
        let original_session = service.room.as_mut().unwrap().attached_session_id.replace("mismatched".into());
        assert_eq!(service.prepare_peer_transport().await.unwrap_err(), PeerError::Unavailable);
        service.room.as_mut().unwrap().attached_session_id = original_session;
        assert!(!service.peer_recv_once && !service.peer_start_once);
        send_peer_frame(&mut peer_socket, &(peer_frame(&other, 1))).await;
        service.prepare_peer_transport().await.unwrap();
        assert!(service.peer_recv_once && service.peer_start_once);
        assert!(service.lease.is_none());
        let bytes = b"one original socket, one retained store".to_vec();
        let tag = service.peer_plane().unwrap().publish_blob(bytes.clone()).await.unwrap();
        let second = peer_frame(&other, 2);
        send_peer_frame(&mut peer_socket, &(second.clone())).await;
        service.prepare_peer_transport().await.unwrap();
        // The second frame remains unread by prepare, despite being available.
        let frame = service.room.as_mut().unwrap().socket.next().await.unwrap().unwrap();
        assert_eq!(frame.as_text(), Some(second.as_str()));
        assert_eq!(service.peer_plane().unwrap().endpoint_addr().id, own.id());
        assert_eq!(service.peer_plane().unwrap().endpoint_addr().ip_addrs().copied().collect::<Vec<_>>(), addresses);
        let remote = crate::transport::DataPlane::start(other, own.id()).unwrap();
        let received = remote.fetch_blob(tag.hash(), bytes.len() as u64).await.unwrap();
        assert_eq!(received, bytes);
        assert_eq!(std::fs::read(dir.path().join("attempt.json")).unwrap(), before);
        fixture.assert_one(dir.path());
        drop(tag);
        drop(peer_socket);
        service.shutdown().await;
        assert!(own.is_closed());
        assert!(matches!(service.peer_plane(), Err(PeerError::Closed)));
        assert!(matches!(service.prepare_peer_transport().await, Err(PeerError::Closed)));
        assert!(service.endpoint.is_none() && service.room.is_none() && service.peer_plane.is_none());
        remote.shutdown().await.unwrap();
        println!("shared_peer_live same_id_port=true read_once=true start_once=true actual_blob=true shutdown_closed=true no_write_lease=true");
    }).await.unwrap();
}

#[tokio::test]
async fn peer_transport_expired_record_and_cancelled_initial_read_never_refresh() {
    timeout(Duration::from_secs(20), async {
        for expired in [true, false] {
            let dir = private_dir();
            let fixture = Fixture::new(dir.path(), Response::Signed("freshly_stored")).await;
            let mut service = fixture.service(dir.path());
            service.submit_empty(Some(SESSION)).await.unwrap();
            let before = std::fs::read(dir.path().join("attempt.json")).unwrap();
            let (other, mut peer_socket) = attach_peer_fixture(&mut service).await;
            if expired {
                service.room.as_mut().unwrap().peer_expiry = Some(now_unix().unwrap() - 1);
                assert!(matches!(service.prepare_peer_transport().now_or_never(), Some(Err(PeerError::PeerRecord))));
            } else {
                assert!(timeout(Duration::from_millis(10), service.prepare_peer_transport()).await.is_err());
            }
            assert!(service.peer_recv_once && !service.peer_start_once && service.peer_plane.is_none());
            let frame = peer_frame(&other, 1);
            send_peer_frame(&mut peer_socket, &(frame.clone())).await;
            assert!(matches!(service.prepare_peer_transport().now_or_never(), Some(Err(PeerError::PeerRecord))));
            let untouched = service.room.as_mut().unwrap().socket.next().await.unwrap().unwrap();
            assert_eq!(untouched.as_text(), Some(frame.as_str()));
            assert!(service.peer_plane().is_err());
            assert_eq!(std::fs::read(dir.path().join("attempt.json")).unwrap(), before);
            fixture.assert_one(dir.path());
            drop(peer_socket);
            service.shutdown().await;
            assert!(service.endpoint.is_none() && service.room.is_none());
            other.close().await;
        }
        println!("shared_peer_no_refresh expired_some=true cancelled_initial=true queued_frame_unread=true original_unchanged=true");
    }).await.unwrap();
}

#[test]
fn genesis_roles_have_only_the_exact_opposite_pin() {
    assert_eq!(
        genesis_opposite(A).unwrap(),
        B.parse::<EndpointId>().unwrap()
    );
    assert_eq!(
        genesis_opposite(B).unwrap(),
        A.parse::<EndpointId>().unwrap()
    );
    for unknown in ["", "other", COORDINATOR] {
        assert!(matches!(
            genesis_opposite(unknown),
            Err(ClaimTaskError::Identity)
        ));
    }
}
