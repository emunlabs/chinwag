//! Real loopback HTTPS boundary tests. All TLS material is synthetic and is
//! trusted only by the clients built in this test module.

use super::*;
use crate::attempt_journal::AttemptBinding;
use chinwag_claim::reply::PreparedClaim;
use chinwag_claim::{ClaimReceiptUnsigned, ClaimRequestUnsigned, Pr, encode_hex};
use ed25519_dalek::SigningKey;
use futures_util::FutureExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

const ROOT: &[u8] = include_bytes!("fixtures/test-root.der");
const LEAF: &[u8] = include_bytes!("fixtures/test-server.der");
const KEY: &[u8] = include_bytes!("fixtures/test-server.pkcs8.der");

fn actor() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn coordinator() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}
fn coordinator_id() -> EndpointId {
    EndpointId::from_bytes(coordinator().verifying_key().as_bytes()).unwrap()
}
fn binding(origin: &str) -> AttemptBinding {
    AttemptBinding::new(
        origin,
        actor().verifying_key().to_bytes(),
        coordinator().verifying_key().to_bytes(),
    )
    .unwrap()
}
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

struct Fixture {
    journal: AttemptJournal,
    attempt: ArmedAttempt,
    prepared: PreparedClaim,
}
impl Fixture {
    fn new(origin: &str, dir: &Path) -> Self {
        let signed = ClaimRequestUnsigned {
            claim_id: encode_hex(&[0x11; 32]),
            actor: encode_hex(actor().verifying_key().as_bytes()),
            session: encode_hex(&[0x22; 32]),
            nonce: encode_hex(&[0x33; 32]),
            pr: Pr::Pr01,
            files: vec!["crates/chinwag-seed/src/main.rs".into()],
            expected_revision: 0,
            issued: 1_700_000_000,
            expiry: 1_700_000_060,
        }
        .sign(&actor())
        .unwrap();
        let wire = format!("\n{}\n", serde_json::to_string_pretty(&signed).unwrap());
        let prepared = PreparedClaim::from_request_json_exact(wire.as_bytes()).unwrap();
        let mut journal = AttemptJournal::open(dir, binding(origin)).unwrap();
        let attempt = journal.arm(&prepared).unwrap();
        Self {
            journal,
            attempt,
            prepared,
        }
    }
    fn signed_reply(&self, disposition: &str) -> Vec<u8> {
        let request = &self.prepared.signed().request;
        let receipt = ClaimReceiptUnsigned {
            claim_id: request.claim_id.clone(),
            actor: request.actor.clone(),
            session: request.session.clone(),
            pr: request.pr,
            files: request.files.clone(),
            revision: 1,
            issued: request.issued,
            expiry: request.expiry,
            request_sha256: self.prepared.signed().request_sha256_hex().unwrap(),
            coordinator: encode_hex(coordinator().verifying_key().as_bytes()),
        }
        .sign(&coordinator())
        .unwrap();
        let inner = format!("\n{}\n", serde_json::to_string_pretty(&receipt).unwrap());
        serde_json::to_vec(&serde_json::json!({"disposition":disposition,"receipt_json":inner}))
            .unwrap()
    }
}

#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    chunked: bool,
    hang: bool,
    deny_journal_writes: bool,
}
impl Reply {
    fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("cf-ray", "abc123-TEST".into())],
            body: body.into(),
            chunked: false,
            hang: false,
            deny_journal_writes: false,
        }
    }
}
#[derive(Debug)]
struct Seen {
    headers: String,
    body: Vec<u8>,
    phase_at_accept: Option<String>,
}
struct Server {
    origin: String,
    accepted: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: Option<JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Server {
    async fn start(replies: Vec<Reply>, record: PathBuf) -> Self {
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
        let accepted = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let count = accepted.clone();
        let captured = seen.clone();
        let task = tokio::spawn(async move {
            for reply in replies {
                let (tcp, _) = timeout(Duration::from_secs(8), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let state = std::fs::read(&record)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| v.get("state").and_then(|s| s.as_str()).map(str::to_owned));
                let mut tls = timeout(Duration::from_secs(4), acceptor.accept(tcp))
                    .await
                    .unwrap()
                    .unwrap();
                let mut request = Vec::new();
                let split;
                loop {
                    let mut bytes = [0u8; 1024];
                    let n = timeout(Duration::from_secs(4), tls.read(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(n > 0 && request.len() + n <= 8192);
                    request.extend_from_slice(&bytes[..n]);
                    if let Some(i) = request.windows(4).position(|b| b == b"\r\n\r\n") {
                        split = i + 4;
                        break;
                    }
                }
                let headers = String::from_utf8(request[..split].to_vec()).unwrap();
                let len: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse().unwrap())
                    })
                    .unwrap();
                assert!(len <= MAX_JSON_BYTES);
                while request.len() < split + len {
                    let mut bytes = [0u8; 1024];
                    let n = timeout(Duration::from_secs(4), tls.read(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&bytes[..n]);
                    assert!(request.len() <= 8192);
                }
                captured.lock().unwrap().push(Seen {
                    headers,
                    body: request[split..split + len].to_vec(),
                    phase_at_accept: state,
                });
                if reply.deny_journal_writes {
                    std::fs::set_permissions(
                        record.parent().unwrap(),
                        std::fs::Permissions::from_mode(0o500),
                    )
                    .unwrap();
                }
                if reply.hang {
                    std::future::pending::<()>().await;
                }
                let mut head =
                    format!("HTTP/1.1 {} Fixture\r\nConnection: close\r\n", reply.status);
                for (key, value) in reply.headers {
                    head += &format!("{key}: {value}\r\n");
                }
                let wire = if reply.chunked {
                    head += "Transfer-Encoding: chunked\r\n\r\n";
                    [
                        head.into_bytes(),
                        format!("{:x}\r\n", reply.body.len()).into_bytes(),
                        reply.body,
                        b"\r\n0\r\n\r\n".to_vec(),
                    ]
                    .concat()
                } else {
                    head += &format!("Content-Length: {}\r\n\r\n", reply.body.len());
                    [head.into_bytes(), reply.body].concat()
                };
                // Oversize clients may close before the fixture finishes writing.
                let _ = tls.write_all(&wire).await;
                let _ = tls.shutdown().await;
            }
        });
        Self {
            origin,
            accepted,
            seen,
            task: Some(task),
        }
    }
    fn client(&self, origin: &str, pin: EndpointId) -> RoomClient {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ROOT.to_vec())).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        RoomClient::from_tls(
            clean_origin(origin).unwrap(),
            pin,
            config,
            Arc::new(RelayPolicy::Disabled),
        )
        .unwrap()
    }
    async fn finish(&mut self) {
        timeout(Duration::from_secs(2), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
    fn assert_one_original(&self, prepared: &PreparedClaim) {
        assert_eq!(self.accepted.load(Ordering::SeqCst), 1);
        let seen = self.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, prepared.request_json().as_bytes());
        assert_eq!(seen[0].phase_at_accept.as_deref(), Some("unknown"));
        assert!(
            seen[0]
                .headers
                .starts_with("POST /room/genesis/claim HTTP/1.1\r\n")
        );
        assert!(
            seen[0]
                .headers
                .to_ascii_lowercase()
                .contains(&format!("user-agent: {USER_AGENT}\r\n"))
        );
    }
}

#[tokio::test]
async fn mismatched_origin_pin_or_poison_performs_zero_connections() {
    let dir = private_dir();
    let server = Server::start(
        vec![Reply::new(403, br#"{"error":"claim_policy"}"#.to_vec())],
        dir.path().join("attempt.json"),
    )
    .await;
    let mut f = Fixture::new(&server.origin, dir.path());
    let other_origin = server.origin.replace("127.0.0.1", "localhost");
    let wrong_pin =
        EndpointId::from_bytes(SigningKey::from_bytes(&[10; 32]).verifying_key().as_bytes())
            .unwrap();
    for client in [
        server.client(&other_origin, coordinator_id()),
        server.client(&server.origin, wrong_pin),
    ] {
        assert!(matches!(
            client.submit_original(&mut f.journal, &mut f.attempt).await,
            Err(Error::Url)
        ));
        assert_eq!(f.attempt.phase(), AttemptPhase::Armed);
    }
    std::fs::rename(
        dir.path().join("journal.lock"),
        dir.path().join("moved.lock"),
    )
    .unwrap();
    let _replacement = AttemptJournal::open(dir.path(), binding(&server.origin)).unwrap();
    let client = server.client(&server.origin, coordinator_id());
    assert!(matches!(
        client.submit_original(&mut f.journal, &mut f.attempt).await,
        Err(Error::Attempt(AttemptError::Lock))
    ));
    assert_eq!(server.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn strict_refusals_persist_only_after_one_exact_https_post() {
    for (status, code) in [(403, "claim_policy"), (409, "claim_session")] {
        let dir = private_dir();
        let body = format!("{{\"error\":\"{code}\"}}");
        let mut server = Server::start(
            vec![Reply::new(status, body.into_bytes())],
            dir.path().join("attempt.json"),
        )
        .await;
        let mut f = Fixture::new(&server.origin, dir.path());
        let client = server.client(&server.origin, coordinator_id());
        let result = client
            .submit_original(&mut f.journal, &mut f.attempt)
            .await
            .unwrap();
        assert!(
            matches!(result,ClaimSubmission::Refused{status:s,code:c,..} if s==status && c==code)
        );
        assert_eq!(f.attempt.phase(), AttemptPhase::Refused);
        server.finish().await;
        server.assert_one_original(&f.prepared);
        drop(f.journal);
        let journal = AttemptJournal::open(dir.path(), binding(&server.origin)).unwrap();
        assert_eq!(
            journal.load().unwrap().unwrap().phase(),
            AttemptPhase::Refused
        );
    }
}

#[tokio::test]
async fn malformed_refusals_rays_statuses_and_caps_remain_unknown() {
    let mut no_ray = Reply::new(403, br#"{"error":"claim_policy"}"#.to_vec());
    no_ray.headers.clear();
    let mut duplicate_ray = Reply::new(403, br#"{"error":"claim_policy"}"#.to_vec());
    duplicate_ray.headers.push(("cf-ray", "other-TEST".into()));
    let mut big = Reply::new(200, vec![b'x'; MAX_REPLY_BODY_BYTES + 1]);
    big.chunked = true;
    for reply in [
        no_ray,
        duplicate_ray,
        big,
        Reply::new(503, b"unavailable".to_vec()),
        Reply::new(403, br#"{"error":"claim_session"}"#.to_vec()),
        Reply::new(403, br#"{"error":"claim_policy","extra":1}"#.to_vec()),
        Reply::new(
            403,
            br#"{"error":"claim_policy","error":"claim_policy"}"#.to_vec(),
        ),
        Reply::new(403, vec![b'x'; 1025]),
        Reply::new(200, b"{}".to_vec()),
    ] {
        let dir = private_dir();
        let mut server = Server::start(vec![reply], dir.path().join("attempt.json")).await;
        let mut f = Fixture::new(&server.origin, dir.path());
        let client = server.client(&server.origin, coordinator_id());
        assert!(matches!(
            client
                .submit_original(&mut f.journal, &mut f.attempt)
                .await
                .unwrap(),
            ClaimSubmission::Unknown { .. }
        ));
        assert_eq!(f.attempt.phase(), AttemptPhase::Unknown);
        server.finish().await;
        server.assert_one_original(&f.prepared);
        assert_eq!(
            f.journal.load().unwrap().unwrap().prepared().request_json(),
            f.prepared.request_json()
        );
    }
}

#[tokio::test]
async fn valid_signed_replies_keep_historical_and_reported_fresh_distinct() {
    for disposition in ["outcome_resolution", "freshly_stored"] {
        let dir = private_dir();
        // Bind a listener first; the signed response does not depend on its origin.
        let signing_dir = private_dir();
        let signed =
            Fixture::new("https://example.invalid/", signing_dir.path()).signed_reply(disposition);
        let mut server = Server::start(
            vec![Reply::new(200, signed.clone())],
            dir.path().join("attempt.json"),
        )
        .await;
        let mut f = Fixture::new(&server.origin, dir.path());
        let client = server.client(&server.origin, coordinator_id());
        let result = client
            .submit_original(&mut f.journal, &mut f.attempt)
            .await
            .unwrap();
        assert!(matches!(
            (&result, disposition),
            (ClaimSubmission::Historical { .. }, "outcome_resolution")
                | (ClaimSubmission::ReportedFresh { .. }, "freshly_stored")
        ));
        assert_eq!(f.attempt.phase(), AttemptPhase::Verified);
        server.finish().await;
        server.assert_one_original(&f.prepared);
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("attempt.json")).unwrap())
                .unwrap();
        assert_eq!(stored["reply_body"].as_str().unwrap().as_bytes(), signed);
        drop(f.journal);
        let journal = AttemptJournal::open(dir.path(), binding(&server.origin)).unwrap();
        assert_eq!(
            journal.load().unwrap().unwrap().phase(),
            AttemptPhase::Verified
        );
    }
}

#[tokio::test]
async fn forged_signed_response_is_unknown_and_explicit_retry_keeps_exact_packet() {
    let dir = private_dir();
    let temporary = private_dir();
    let fixture = Fixture::new("https://example.invalid/", temporary.path());
    let signed = fixture.signed_reply("outcome_resolution");
    let mut outer: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    let mut inner: serde_json::Value =
        serde_json::from_str(outer["receipt_json"].as_str().unwrap()).unwrap();
    let mut signature = inner["signature"].as_str().unwrap().to_owned();
    let last = signature.pop().unwrap();
    signature.push(if last == 'a' { 'b' } else { 'a' });
    inner["signature"] = signature.into();
    outer["receipt_json"] = serde_json::to_string(&inner).unwrap().into();
    let mut server = Server::start(
        vec![
            Reply::new(200, serde_json::to_vec(&outer).unwrap()),
            Reply::new(403, br#"{"error":"claim_policy"}"#.to_vec()),
        ],
        dir.path().join("attempt.json"),
    )
    .await;
    let mut f = Fixture::new(&server.origin, dir.path());
    let client = server.client(&server.origin, coordinator_id());
    assert!(matches!(
        client
            .submit_original(&mut f.journal, &mut f.attempt)
            .await
            .unwrap(),
        ClaimSubmission::Unknown {
            reason: ClaimUnknownReason::Body,
            ..
        }
    ));
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(f.attempt.phase(), AttemptPhase::Unknown);
    assert!(matches!(
        client
            .submit_original(&mut f.journal, &mut f.attempt)
            .await
            .unwrap(),
        ClaimSubmission::Refused { .. }
    ));
    server.finish().await;
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for seen in seen.iter() {
        assert_eq!(seen.body, f.prepared.request_json().as_bytes());
        assert_eq!(seen.phase_at_accept.as_deref(), Some("unknown"));
    }
}

#[tokio::test]
async fn real_five_second_timeout_does_not_retry_or_replace_original() {
    let dir = private_dir();
    let mut reply = Reply::new(200, Vec::new());
    reply.hang = true;
    let server = Server::start(vec![reply], dir.path().join("attempt.json")).await;
    let mut f = Fixture::new(&server.origin, dir.path());
    let client = server.client(&server.origin, coordinator_id());
    let started = std::time::Instant::now();
    assert!(matches!(
        client
            .submit_original(&mut f.journal, &mut f.attempt)
            .await
            .unwrap(),
        ClaimSubmission::Unknown {
            reason: ClaimUnknownReason::Network,
            ..
        }
    ));
    assert!(started.elapsed() >= Duration::from_secs(4));
    assert!(started.elapsed() < Duration::from_secs(8));
    assert_eq!(f.attempt.phase(), AttemptPhase::Unknown);
    server.assert_one_original(&f.prepared);
    assert_eq!(
        f.journal.load().unwrap().unwrap().prepared().request_json(),
        f.prepared.request_json()
    );
}

#[tokio::test]
async fn cancellation_recovers_the_same_unknown_packet_after_reopen() {
    let dir = private_dir();
    let mut response = Reply::new(200, Vec::new());
    response.hang = true;
    let server = Server::start(vec![response], dir.path().join("attempt.json")).await;
    let mut f = Fixture::new(&server.origin, dir.path());
    let client = server.client(&server.origin, coordinator_id());
    assert!(
        timeout(
            Duration::from_secs(1),
            client.submit_original(&mut f.journal, &mut f.attempt)
        )
        .await
        .is_err()
    );
    assert_eq!(f.attempt.phase(), AttemptPhase::Unknown);
    server.assert_one_original(&f.prepared);
    drop(f.journal);
    let journal = AttemptJournal::open(dir.path(), binding(&server.origin)).unwrap();
    let recovered = journal.load().unwrap().unwrap();
    assert_eq!(recovered.phase(), AttemptPhase::Unknown);
    assert_eq!(
        recovered.prepared().request_json(),
        f.prepared.request_json()
    );
    assert_eq!(recovered.prepared().wire_sha256(), f.prepared.wire_sha256());
}

#[tokio::test]
async fn valid_reply_with_failed_terminal_persistence_is_not_reported_terminal() {
    for verified in [false, true] {
        let dir = private_dir();
        let signing_dir = private_dir();
        let signing = Fixture::new("https://example.invalid/", signing_dir.path());
        let mut response = if verified {
            Reply::new(200, signing.signed_reply("outcome_resolution"))
        } else {
            Reply::new(403, br#"{"error":"claim_policy"}"#.to_vec())
        };
        response.deny_journal_writes = true;
        let mut server = Server::start(vec![response], dir.path().join("attempt.json")).await;
        let mut f = Fixture::new(&server.origin, dir.path());
        let client = server.client(&server.origin, coordinator_id());
        let result = client.submit_original(&mut f.journal, &mut f.attempt).await;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            result,
            Err(Error::Attempt(AttemptError::Poisoned))
        ));
        assert_eq!(f.attempt.phase(), AttemptPhase::Unknown);
        server.finish().await;
        server.assert_one_original(&f.prepared);
        drop(f.journal);
        let journal = AttemptJournal::open(dir.path(), binding(&server.origin)).unwrap();
        let recovered = journal.load().unwrap().unwrap();
        assert_eq!(recovered.phase(), AttemptPhase::Unknown);
        assert_eq!(
            recovered.prepared().request_json(),
            f.prepared.request_json()
        );
    }
}

#[tokio::test]
async fn stale_and_terminal_attempts_cannot_post() {
    for terminal in [false, true] {
        let dir = private_dir();
        let server = Server::start(
            vec![Reply::new(403, Vec::new())],
            dir.path().join("attempt.json"),
        )
        .await;
        let mut f = Fixture::new(&server.origin, dir.path());
        let client = server.client(&server.origin, coordinator_id());
        let mut stale = f.journal.load().unwrap().unwrap();
        f.journal.note_unknown(&mut f.attempt).unwrap();
        if terminal {
            f.journal
                .note_refused(&mut f.attempt, 403, "claim_policy", "fixture-ray")
                .unwrap();
            assert!(matches!(
                client.submit_original(&mut f.journal, &mut f.attempt).await,
                Err(Error::Attempt(AttemptError::Phase))
            ));
        } else {
            assert!(matches!(
                client.submit_original(&mut f.journal, &mut stale).await,
                Err(Error::Attempt(AttemptError::Stale))
            ));
        }
        assert_eq!(server.accepted.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn session_id_needs_a_proof_and_close_clears_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    let socket = ClientBuilder::new().take_over(MaybeTlsStream::Plain(client));
    let mut session = RoomSession {
        socket,
        other: coordinator_id(),
        book: MemoryLookup::new(),
        revisions: Revisions::default(),
        policy: Arc::new(RelayPolicy::Disabled),
        peer_expiry: None,
        proof: None,
        attached_session_id: Some("fixture-session".into()),
    };
    assert_eq!(session.pinned_peer_id(), coordinator_id());
    assert!(session.attached_session_id().is_err());
    assert!(session.remaining_peer_validity().is_err());
    session.peer_expiry = Some(now_unix().unwrap() + 60);
    assert!(matches!(
        session.require_fresh_peer(),
        Err(Error::Malformed)
    ));
    session.proof = Some(RoomProof {
        attach_challenge_ray: "fixture".into(),
        websocket_ray: "fixture".into(),
        advertise_challenge_ray: "fixture".into(),
        stored_ray: "fixture".into(),
        coordinator_receipt_verified: true,
    });
    assert_eq!(session.attached_session_id().unwrap(), "fixture-session");
    session.book.set_endpoint_info(
        EndpointAddr::new(coordinator_id()).with_ip_addr(listener.local_addr().unwrap()),
    );
    assert!(session.require_fresh_peer().is_ok());
    let remaining = session.remaining_peer_validity().unwrap();
    assert!(!remaining.is_zero() && remaining <= Duration::from_secs(60));
    session.peer_expiry = Some(now_unix().unwrap());
    assert!(matches!(
        session.remaining_peer_validity(),
        Err(Error::Expired)
    ));
    session.peer_expiry = Some(now_unix().unwrap() + 60);
    assert!(session.book.get_endpoint_info(coordinator_id()).is_some());
    session.close().await;
    // The fixed pin remains metadata; freshness and proof still refuse below.
    assert_eq!(session.pinned_peer_id(), coordinator_id());
    assert!(session.attached_session_id().is_err());
    assert!(session.proof().is_err());
    assert!(session.peer_expiry.is_none());
    assert!(session.remaining_peer_validity().is_err());
    assert!(matches!(
        session.require_fresh_peer(),
        Err(Error::Malformed)
    ));
    // Must be ready without waiting for a frame or advancing virtual time.
    assert!(matches!(
        session.receive_peer().now_or_never(),
        Some(Err(Error::Malformed))
    ));
    assert!(session.book.get_endpoint_info(coordinator_id()).is_none());
    assert!(session.peer_expiry.is_none());
    println!(
        "room_close_fixture future_expiry_before_close=true closed_freshness_refused=true closed_receive_ready_refusal=true lookup_empty=true no_physical_peer=true"
    );
    println!(
        "driver_ttl internal_clock=true future_snapshot_bounded=true expired_refused=true closed_refused=true loopback_fixture_only=true"
    );
}
