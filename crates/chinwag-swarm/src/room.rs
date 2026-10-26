//! Bounded Cloudflare control-plane client. Only verified peer advertisements
//! enter the memory lookup. A stored receipt is not a QUIC or source review.

use crate::{
    attempt_journal::{ArmedAttempt, AttemptError, AttemptJournal, AttemptPhase},
    identity::Identity,
    relay_policy::RelayPolicy,
    room_wire::{self, Advertisement, Challenge, Receipt},
};
use chinwag_claim::{
    MAX_JSON_BYTES,
    reply::{
        FreshReply, HistoricalReply, MAX_REPLY_BODY_BYTES, ParsedClaimReply, parse_claim_reply,
    },
};
use ed25519_dalek::VerifyingKey;
use futures_util::{SinkExt, StreamExt};
use iroh::{EndpointAddr, EndpointId, address_lookup::memory::MemoryLookup};
use reqwest::{Client, Url};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, time::timeout};
use tokio_websockets::{ClientBuilder, Connector, Limits, MaybeTlsStream, WebSocketStream};

const LIMIT: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = "chinwag-seed/0.0.1 (+https://github.com/emunlabs/chinwag)";
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Attempt(#[from] AttemptError),
    #[error("the room endpoint must be a clean HTTPS origin")]
    Url,
    #[error("the bounded room request failed")]
    Network,
    #[error("the room HTTP request failed ({0})")]
    Http(&'static str),
    #[error("the room WebSocket operation failed ({0})")]
    WebSocket(&'static str),
    #[error("the room WebSocket upgrade returned HTTP {0}")]
    Upgrade(u16),
    #[error("the room TLS configuration could not be initialized")]
    Tls,
    #[error("the room operation exceeded its deadline")]
    Timeout,
    #[error("the room {0} operation exceeded its deadline")]
    PhaseTimeout(&'static str),
    #[error("the room refused this operation with HTTP {0}")]
    Refused(u16),
    #[error("room input exceeds its size limit")]
    Size,
    #[error("the room response is malformed")]
    Malformed,
    #[error("the room response lacks a valid Cloudflare request receipt")]
    MissingRay,
    #[error("the room advertisement replays a revision or retired session")]
    Replay,
    #[error("the peer advertisement has expired")]
    Expired,
    #[error(transparent)]
    Wire(#[from] room_wire::Error),
    #[error(transparent)]
    Policy(#[from] crate::relay_policy::PolicyError),
}

/// A bounded network report. No variant is a file-write permit.
#[derive(Debug)]
pub enum ClaimSubmission {
    Unknown {
        reason: ClaimUnknownReason,
        status: Option<u16>,
        cf_ray: Option<String>,
    },
    Refused {
        status: u16,
        code: String,
        cf_ray: String,
    },
    Historical {
        reply: HistoricalReply,
        cf_ray: String,
    },
    ReportedFresh {
        reply: FreshReply,
        cf_ray: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimUnknownReason {
    Network,
    Ray,
    Size,
    Status,
    Body,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRefusalBody {
    error: String,
}

pub fn now_unix() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|x| x.as_secs())
        .map_err(|_| Error::Malformed)
}

fn clean_origin(value: &str) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|_| Error::Url)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::Url);
    }
    Ok(url)
}

fn ray(headers: &http::HeaderMap) -> Result<String, Error> {
    let mut values = headers.get_all("cf-ray").iter();
    let value = values
        .next()
        .and_then(|h| h.to_str().ok())
        .ok_or(Error::MissingRay)?;
    if values.next().is_some()
        || value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(Error::MissingRay);
    }
    Ok(value.to_owned())
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > LIMIT {
        return Err(Error::Size);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Malformed)
}

// Retain diagnostic categories without serializing request headers, signed
// challenges, response bodies, URLs, or an upstream error's arbitrary text.
fn http_error(error: reqwest::Error) -> Error {
    Error::Http(if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else {
        "request"
    })
}

fn websocket_error(error: tokio_websockets::Error) -> Error {
    use tokio_websockets::{Error as Ws, upgrade::Error as Upgrade};
    match error {
        Ws::Upgrade(Upgrade::DidNotSwitchProtocols(code)) => Error::Upgrade(code),
        Ws::CannotResolveHost => Error::WebSocket("dns"),
        Ws::Io(error) => Error::WebSocket(match error.kind() {
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::TimedOut => "io_timeout",
            std::io::ErrorKind::ConnectionRefused => "connection_refused",
            std::io::ErrorKind::ConnectionReset => "connection_reset",
            std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
            _ => "io",
        }),
        Ws::Rustls(_) => Error::WebSocket("tls"),
        Ws::InvalidDNSName(_) => Error::WebSocket("tls_dns_name"),
        Ws::Upgrade(_) => Error::WebSocket("upgrade_protocol"),
        Ws::Protocol(_) => Error::WebSocket("frame_protocol"),
        _ => Error::WebSocket("protocol"),
    }
}

#[derive(Clone, Serialize)]
pub struct RoomProof {
    pub attach_challenge_ray: String,
    pub websocket_ray: String,
    pub advertise_challenge_ray: String,
    pub stored_ray: String,
    pub coordinator_receipt_verified: bool,
}

pub struct RoomClient {
    base: Url,
    http: Client,
    websocket_tls: Connector,
    coordinator: EndpointId,
    policy: Arc<RelayPolicy>,
}

impl RoomClient {
    pub fn new(
        base: &str,
        coordinator: EndpointId,
        policy: Arc<RelayPolicy>,
    ) -> Result<Self, Error> {
        let base = clean_origin(base)?;
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Tls)?
        .with_platform_verifier()
        .map_err(|_| Error::Tls)?
        .with_no_client_auth();
        Self::from_tls(base, coordinator, tls, policy)
    }

    fn from_tls(
        base: Url,
        coordinator: EndpointId,
        mut tls: rustls::ClientConfig,
        policy: Arc<RelayPolicy>,
    ) -> Result<Self, Error> {
        // Both this HTTP client and the WebSocket upgrade use HTTP/1.1.
        // The provider is local to these clients, with normal platform trust.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let websocket_tls = Connector::Rustls(Arc::new(tls.clone()).into());
        let http = Client::builder()
            .tls_backend_preconfigured(tls)
            .http1_only()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .user_agent(USER_AGENT)
            .connect_timeout(REQUEST_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| Error::Network)?;
        Ok(Self {
            base,
            http,
            websocket_tls,
            coordinator,
            policy,
        })
    }

    pub fn relay_policy(&self) -> &RelayPolicy {
        &self.policy
    }

    /// Submit one durably armed original. No session opening, restamping, or retry.
    pub async fn submit_original(
        &self,
        journal: &mut AttemptJournal,
        attempt: &mut ArmedAttempt,
    ) -> Result<ClaimSubmission, Error> {
        if attempt.binding().origin() != self.base.as_str()
            || attempt.binding().coordinator() != self.coordinator.as_bytes()
        {
            return Err(Error::Url);
        }
        if !matches!(attempt.phase(), AttemptPhase::Armed | AttemptPhase::Unknown) {
            return Err(AttemptError::Phase.into());
        }
        let original = attempt.prepared().request_json().as_bytes();
        if original.len() > MAX_JSON_BYTES {
            return Err(Error::Size);
        }
        let body = original.to_vec();
        let url = self
            .base
            .join("/room/genesis/claim")
            .map_err(|_| Error::Url)?;
        journal.note_unknown(attempt)?;
        // Cancellation from this point leaves the on-disk original Unknown.
        let response = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(_) => {
                return Ok(ClaimSubmission::Unknown {
                    reason: ClaimUnknownReason::Network,
                    status: None,
                    cf_ray: None,
                });
            }
        };
        let status = response.status().as_u16();
        let cf_ray = match ray(response.headers()) {
            Ok(ray) => ray,
            Err(_) => {
                return Ok(ClaimSubmission::Unknown {
                    reason: ClaimUnknownReason::Ray,
                    status: Some(status),
                    cf_ray: None,
                });
            }
        };
        tracing::info!(room_phase = "claim_response", status, cf_ray = %cf_ray);
        let unknown = |reason| ClaimSubmission::Unknown {
            reason,
            status: Some(status),
            cf_ray: Some(cf_ray.clone()),
        };
        if status != 200 && !matches!(status, 400 | 401 | 403 | 409) {
            return Ok(unknown(ClaimUnknownReason::Status));
        }
        let cap = if status == 200 {
            MAX_REPLY_BODY_BYTES
        } else {
            1024
        };
        if response.content_length().is_some_and(|n| n > cap as u64) {
            return Ok(unknown(ClaimUnknownReason::Size));
        }
        let mut bytes = Vec::new();
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => return Ok(unknown(ClaimUnknownReason::Network)),
            };
            if chunk.len() > cap.saturating_sub(bytes.len()) {
                return Ok(unknown(ClaimUnknownReason::Size));
            }
            bytes.extend_from_slice(&chunk);
        }
        if status != 200 {
            let body: ClaimRefusalBody = match serde_json::from_slice(&bytes) {
                Ok(body) => body,
                Err(_) => return Ok(unknown(ClaimUnknownReason::Body)),
            };
            return match journal.note_refused(attempt, status, &body.error, &cf_ray) {
                Ok(()) => Ok(ClaimSubmission::Refused {
                    status,
                    code: body.error,
                    cf_ray,
                }),
                Err(AttemptError::Refusal) => Ok(unknown(ClaimUnknownReason::Body)),
                Err(error) => Err(error.into()),
            };
        }
        let actor =
            VerifyingKey::from_bytes(attempt.binding().actor()).map_err(|_| Error::Malformed)?;
        let coordinator = VerifyingKey::from_bytes(attempt.binding().coordinator())
            .map_err(|_| Error::Malformed)?;
        let parsed =
            match parse_claim_reply(&bytes, attempt.prepared().signed(), &actor, &coordinator) {
                Ok(parsed) => parsed,
                Err(_) => return Ok(unknown(ClaimUnknownReason::Body)),
            };
        journal.note_verified(attempt, &bytes, &cf_ray)?;
        Ok(match parsed {
            ParsedClaimReply::Historical(reply) => ClaimSubmission::Historical { reply, cf_ray },
            ParsedClaimReply::FreshlyStored(reply) => {
                ClaimSubmission::ReportedFresh { reply, cf_ray }
            }
        })
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Vec<u8>,
        headers: Vec<(&'static str, String)>,
    ) -> Result<(T, String), Error> {
        if body.len() > LIMIT {
            return Err(Error::Size);
        }
        let url = self.base.join(path).map_err(|_| Error::Url)?;
        let mut request = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .body(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let mut response = request.send().await.map_err(http_error)?;
        tracing::info!(
            room_phase = "http_response",
            operation = path,
            status = response.status().as_u16()
        );
        if !response.status().is_success() {
            return Err(Error::Refused(response.status().as_u16()));
        }
        let cf_ray = ray(response.headers())?;
        if response.content_length().is_some_and(|n| n > LIMIT as u64) {
            return Err(Error::Size);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(http_error)? {
            if chunk.len() > LIMIT.saturating_sub(bytes.len()) {
                return Err(Error::Size);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((parse(&bytes)?, cf_ray))
    }

    async fn challenge(
        &self,
        actor: EndpointId,
        operation: &str,
        session: Option<&str>,
    ) -> Result<(Challenge, String), Error> {
        let mut body = serde_json::json!({"actor_id":actor.to_string(),"operation":operation});
        if let Some(session) = session {
            body["session_id"] = session.into();
        }
        let (challenge, cf_ray): (Challenge, String) = self
            .post(
                "/room/genesis/challenge",
                serde_json::to_vec(&body).map_err(|_| Error::Malformed)?,
                vec![],
            )
            .await?;
        room_wire::validate_challenge(&challenge, actor, operation, session, now_unix()?)?;
        Ok((challenge, cf_ray))
    }

    pub async fn open(
        &self,
        identity: &Identity,
        other: EndpointId,
        addresses: Vec<SocketAddr>,
        book: MemoryLookup,
    ) -> Result<RoomSession, Error> {
        if other == identity.endpoint_id()
            || self.coordinator == identity.endpoint_id()
            || self.coordinator == other
        {
            return Err(Error::Malformed);
        }
        let (attach, attach_ray) = self
            .challenge(identity.endpoint_id(), "attach", None)
            .await?;
        tracing::info!(room_phase = "attach_challenge_verified");
        let mut ws_url = self.base.join("/room/genesis/ws").map_err(|_| Error::Url)?;
        ws_url.set_scheme("wss").map_err(|_| Error::Url)?;
        let mut builder = ClientBuilder::new()
            .connector(&self.websocket_tls)
            .uri(ws_url.as_str())
            .map_err(|_| Error::Url)?
            .limits(Limits::default().max_payload_len(Some(LIMIT)))
            .add_header(
                http::header::USER_AGENT,
                http::HeaderValue::from_static(USER_AGENT),
            )
            .map_err(|_| Error::Malformed)?;
        for (name, value) in room_wire::auth_headers(identity, &attach)? {
            builder = builder
                .add_header(
                    http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::Malformed)?,
                    http::HeaderValue::from_str(&value).map_err(|_| Error::Malformed)?,
                )
                .map_err(|_| Error::Malformed)?;
        }
        let (socket, response) = timeout(REQUEST_TIMEOUT, builder.connect())
            .await
            .map_err(|_| Error::PhaseTimeout("websocket_upgrade"))?
            .map_err(websocket_error)?;
        let websocket_ray = ray(response.headers())?;
        tracing::info!(room_phase = "websocket_open");
        let policy = Arc::clone(&self.policy);
        let mut session = RoomSession {
            socket,
            other,
            book,
            revisions: Revisions::default(),
            peer_expiry: None,
            proof: None,
            attached_session_id: None,
            policy,
        };
        let store = async {
            let (challenge, challenge_ray) = self
                .challenge(
                    identity.endpoint_id(),
                    "advertise",
                    Some(&attach.session_id),
                )
                .await?;
            let wire =
                room_wire::sign_advertisement(identity, &challenge, 1, addresses, now_unix()?)?;
            let (stored, stored_ray): (Stored, String) = self
                .post(
                    "/room/genesis/peer",
                    serde_json::to_vec(&wire).map_err(|_| Error::Malformed)?,
                    room_wire::auth_headers(identity, &challenge)?,
                )
                .await?;
            if !stored.stored {
                return Err(Error::Malformed);
            }
            room_wire::verify_receipt(&stored.receipt, self.coordinator, &wire)?;
            tracing::info!(room_phase = "own_advertisement_receipt_verified");
            Ok(RoomProof {
                attach_challenge_ray: attach_ray,
                websocket_ray,
                advertise_challenge_ray: challenge_ray,
                stored_ray,
                coordinator_receipt_verified: true,
            })
        }
        .await;
        match store {
            Ok(proof) => {
                session.proof = Some(proof);
                session.attached_session_id = Some(attach.session_id);
                Ok(session)
            }
            Err(error) => {
                session.close().await;
                Err(error)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    stored: bool,
    receipt: Receipt,
}

#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum ServerMessage {
    #[serde(rename = "peer_advertisement")]
    PeerAdvertisement { advertisement: Advertisement },
}

#[derive(Default)]
struct Revisions {
    active: Option<String>,
    seen: BTreeMap<String, u64>,
}
impl Revisions {
    fn accept(&mut self, session: &str, revision: u64) -> Result<(), Error> {
        if let Some(previous) = self.seen.get(session) {
            if self.active.as_deref() != Some(session) || revision <= *previous {
                return Err(Error::Replay);
            }
        } else if self.seen.len() >= 8 {
            return Err(Error::Replay);
        }
        self.active = Some(session.to_owned());
        self.seen.insert(session.to_owned(), revision);
        Ok(())
    }
}

pub struct RoomSession {
    socket: Socket,
    other: EndpointId,
    book: MemoryLookup,
    revisions: Revisions,
    peer_expiry: Option<u64>,
    proof: Option<RoomProof>,
    attached_session_id: Option<String>,
    policy: Arc<RelayPolicy>,
}
impl RoomSession {
    /// The configured other identity. This metadata is not freshness or authority.
    pub fn pinned_peer_id(&self) -> EndpointId {
        self.other
    }

    /// Last successful own attach; this does not assert that the socket is alive.
    pub fn attached_session_id(&self) -> Result<&str, Error> {
        self.proof()?;
        self.attached_session_id.as_deref().ok_or(Error::Malformed)
    }
    pub fn proof(&self) -> Result<&RoomProof, Error> {
        self.proof.as_ref().ok_or(Error::Malformed)
    }

    /// Receives one fresh, pinned peer record. No implicit refresh or retry.
    /// The diagnostic caller keeps this socket alive while using the record,
    /// and closes the session before the advertisement expires.
    pub async fn receive_peer(&mut self) -> Result<(), Error> {
        self.proof()?;
        let next = timeout(Duration::from_secs(12), self.socket.next())
            .await
            .map_err(|_| Error::PhaseTimeout("peer_advertisement"))?;
        let message = next.ok_or(Error::Network)?.map_err(websocket_error)?;
        let text = message.as_text().ok_or(Error::Malformed)?;
        let ServerMessage::PeerAdvertisement { advertisement } = parse(text.as_bytes())?;
        let addresses = room_wire::verify_advertisement(&advertisement, self.other, now_unix()?)?;
        self.revisions
            .accept(&advertisement.session_id, advertisement.revision)?;
        let info = addresses
            .into_iter()
            .fold(EndpointAddr::new(self.other), |addr, ip| {
                addr.with_ip_addr(ip)
            });
        let info = self.policy.attach_verified_peer(info, self.other)?;
        self.book.set_endpoint_info(info);
        self.peer_expiry = Some(advertisement.expiry_unix);
        Ok(())
    }
    pub fn require_fresh_peer(&self) -> Result<(), Error> {
        self.proof()?;
        match self.peer_expiry {
            Some(expiry) if expiry > now_unix()? => Ok(()),
            _ => Err(Error::Expired),
        }
    }
    /// Snapshot from the accepted peer record and the internal wall clock.
    /// This cannot renew the record or prove socket liveness. Callers still
    /// check freshness before acting and own their monotonic phase cutoff.
    pub fn remaining_peer_validity(&self) -> Result<Duration, Error> {
        self.proof()?;
        let now = now_unix()?;
        match self.peer_expiry {
            Some(expiry) if expiry > now => Ok(Duration::from_secs(expiry - now)),
            _ => Err(Error::Expired),
        }
    }
    pub async fn close(&mut self) {
        self.proof = None;
        self.attached_session_id = None;
        self.peer_expiry = None;
        self.book.remove_endpoint_info(self.other);
        let _ = timeout(Duration::from_secs(2), self.socket.close()).await;
    }
}

#[cfg(test)]
#[path = "room/claim_tests.rs"]
mod claim_tests;
#[cfg(test)]
#[path = "room/policy_tests.rs"]
mod policy_tests;
impl Drop for RoomSession {
    fn drop(&mut self) {
        self.book.remove_endpoint_info(self.other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_policy::RelayPolicy;
    use std::sync::Arc;
    #[test]
    fn room_clients_initialize_with_explicit_tls_without_a_global_provider() {
        let coordinator: EndpointId =
            "366eb665b85888a6b5f265d340b29d0623c6c92c96e6c0746c7b4554b5949919"
                .parse()
                .unwrap();
        let policy = Arc::new(RelayPolicy::from_local_manifest(None, None).unwrap());
        let _client = RoomClient::new("https://bootstrap.chinwag.sh", coordinator, policy).unwrap();
    }

    #[test]
    fn endpoint_requires_https_and_no_credentials_or_extra_url_components() {
        assert!(clean_origin("https://bootstrap.chinwag.sh/").is_ok());
        for value in [
            "http://bootstrap.chinwag.sh",
            "https://user:password@bootstrap.chinwag.sh",
            "https://bootstrap.chinwag.sh/?x=1",
            "https://bootstrap.chinwag.sh/#secret",
            "https://bootstrap.chinwag.sh/room/genesis",
        ] {
            assert!(clean_origin(value).is_err());
        }
    }
    #[test]
    fn revisions_increase_and_retired_sessions_cannot_return() {
        let mut r = Revisions::default();
        r.accept("a", 1).unwrap();
        assert!(r.accept("a", 1).is_err());
        assert!(r.accept("a", 0).is_err());
        r.accept("a", 2).unwrap();
        r.accept("b", 1).unwrap();
        assert!(r.accept("a", 3).is_err());
    }
    #[test]
    fn oversized_and_unknown_control_messages_are_refused() {
        assert!(matches!(
            parse::<ServerMessage>(&vec![0; LIMIT + 1]),
            Err(Error::Size)
        ));
        assert!(
            parse::<ServerMessage>(
                br#"{"kind":"peer_advertisement","advertisement":{},"extra":1}"#
            )
            .is_err()
        );
        assert!(parse::<ServerMessage>(br#"{"kind":"ping","payload":""}"#).is_err());
    }
}

mod claim_slot;
pub use claim_slot::{
    CLAIM_FILE, ClaimOperatorConfig, ClaimService, ClaimTaskError, ClaimTaskReport, LeaseError,
    PeerError, WriteWitness,
};

fn cached_peer_ips_from_book(
    book: &MemoryLookup,
    peer: EndpointId,
) -> Option<crate::transport::BoundedIps> {
    let info = book.get_endpoint_info(peer)?;
    let addr = info.to_endpoint_addr();
    Some(crate::transport::BoundedIps::from_ips(
        addr.ip_addrs().copied(),
    ))
}

impl RoomSession {
    /// Passive cached IPs only; no refresh, dial, freshness, or liveness proof.
    pub fn cached_peer_ips(&self) -> Option<crate::transport::BoundedIps> {
        cached_peer_ips_from_book(&self.book, self.other)
    }
}

#[cfg(test)]
mod cached_ip_metadata_tests {
    use super::cached_peer_ips_from_book;
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::{EndpointAddr, EndpointId};
    use std::cell::Cell;
    use std::net::{Ipv4Addr, SocketAddr};

    fn peer() -> EndpointId {
        "df7676a8680f06f1cddb51a793be9a07a0d022638cb25ebe681dd42328867931"
            .parse()
            .unwrap()
    }
    fn at(n: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, n), 1000 + u16::from(n)))
    }

    #[test]
    fn book_cache_is_bounded_ip_metadata_only() {
        let book = MemoryLookup::new();
        let peer = peer();
        assert!(cached_peer_ips_from_book(&book, peer).is_none());

        book.set_endpoint_info(EndpointAddr::new(peer));
        let empty = cached_peer_ips_from_book(&book, peer).unwrap();
        assert!(empty.addrs().is_empty());
        assert!(!empty.truncated());

        let relay = "https://relay.invalid./".parse::<iroh::RelayUrl>().unwrap();
        book.set_endpoint_info(
            EndpointAddr::new(peer)
                .with_ip_addr(at(1))
                .with_relay_url(relay),
        );
        let filtered = cached_peer_ips_from_book(&book, peer).unwrap();
        assert_eq!(filtered.addrs(), &[at(1)]);
        assert!(!filtered.truncated());

        let mut many = EndpointAddr::new(peer);
        for n in 1..=5 {
            many = many.with_ip_addr(at(n));
        }
        book.set_endpoint_info(many);
        let bounded = cached_peer_ips_from_book(&book, peer).unwrap();
        assert_eq!(bounded.addrs(), &[at(1), at(2), at(3), at(4)]);
        assert!(bounded.truncated());

        book.remove_endpoint_info(peer);
        assert!(cached_peer_ips_from_book(&book, peer).is_none());
    }

    #[test]
    fn from_ips_keeps_encounter_order_and_stops_at_five() {
        let pulls = Cell::new(0u8);
        let ips = std::iter::from_fn(|| {
            let n = pulls.get();
            pulls.set(n + 1);
            Some(at(10 - n))
        });
        let got = crate::transport::BoundedIps::from_ips(ips);
        assert_eq!(pulls.get(), 5);
        assert_eq!(got.addrs(), &[at(10), at(9), at(8), at(7)]);
        assert!(got.truncated());
    }
}
