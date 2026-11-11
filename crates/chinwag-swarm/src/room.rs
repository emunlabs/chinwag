//! Bounded Cloudflare control-plane client. Only verified peer advertisements
//! enter the memory lookup. A stored receipt is not a QUIC or source review.

use crate::{
    attempt_journal::{ArmedAttempt, AttemptError, AttemptJournal, AttemptPhase},
    identity::Identity,
    relay_policy::RelayPolicy,
    room_binding::{
        BindingError, DaemonPeerGate, DaemonRoomIdentity, DaemonRoomOwner, RoomSigner,
        VerifiedDaemonPeer,
    },
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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpStream, time::timeout};
use tokio_websockets::{ClientBuilder, Connector, Limits, MaybeTlsStream, WebSocketStream};

const LIMIT: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = "chinwag-seed/0.0.1 (+https://github.com/emunlabs/chinwag)";
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

// Dropping a renewal future after the coordinator may have stored its new
// revision must not leave the old gate usable with an unknown successor.
struct PresenceRenewalGuard {
    gate: DaemonPeerGate,
    committed: bool,
}
impl Drop for PresenceRenewalGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.gate.revoke();
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DaemonBinding(#[from] BindingError),
    #[error(transparent)]
    Attempt(#[from] AttemptError),
    #[error("the room endpoint must be a clean HTTPS origin")]
    Url,
    #[error("the bounded room request failed")]
    Network,
    #[error("the room HTTP request failed ({0})")]
    Http(&'static str),
    #[error("the room HTTP {phase} failed ({category}, elapsed_ms={elapsed_ms})")]
    HttpResponse {
        phase: &'static str,
        category: &'static str,
        elapsed_ms: u128,
    },
    #[error("the room WebSocket operation failed ({0})")]
    WebSocket(&'static str),
    #[error("the room WebSocket closed with code {0}")]
    WebSocketClosed(u16),
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

fn peer_message_text(message: &tokio_websockets::Message) -> Result<&str, Error> {
    if let Some(text) = message.as_text() {
        return Ok(text);
    }
    if message.is_close() {
        return Err(match message.as_close() {
            Some((code, _)) if code != tokio_websockets::CloseCode::NO_STATUS_RECEIVED => {
                Error::WebSocketClosed(code.into())
            }
            _ => Error::WebSocket("peer_close_without_status"),
        });
    }
    Err(Error::WebSocket(if message.is_ping() {
        "peer_ping_frame"
    } else if message.is_pong() {
        "peer_pong_frame"
    } else {
        "peer_non_text_frame"
    }))
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
fn http_category(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() {
        "body"
    } else {
        "request"
    }
}

fn http_response_error(
    path: &str,
    reading_body: bool,
    started: Instant,
    error: reqwest::Error,
) -> Error {
    // Map only known operations to fixed labels. Never format the path or the
    // upstream error, which can carry URLs, headers or response contents.
    let phase = match (path, reading_body) {
        ("/room/genesis/challenge", false) => "challenge_response_headers",
        ("/room/genesis/challenge", true) => "challenge_response_body",
        ("/room/genesis/peer", false) => "peer_store_response_headers",
        ("/room/genesis/peer", true) => "peer_store_response_body",
        (_, false) => "other_response_headers",
        (_, true) => "other_response_body",
    };
    Error::HttpResponse {
        phase,
        category: http_category(&error),
        elapsed_ms: started.elapsed().as_millis(),
    }
}

pub const ATTACH_CHALLENGE_MAX_RETRIES: usize = 2;
const ATTACH_WARMUP_BACKOFF_MS: [u64; ATTACH_CHALLENGE_MAX_RETRIES] = [500, 1500];
pub const RECONNECT_BACKOFF_MIN_MS: u64 = 250;
pub const RECONNECT_BACKOFF_MAX_MS: u64 = 30_000;

fn startup_http_phase(phase: &'static str, error: Error) -> Error {
    match error {
        Error::Http("timeout")
        | Error::HttpResponse {
            category: "timeout",
            ..
        } => Error::PhaseTimeout(phase),
        other => other,
    }
}

/// True only for cold-start coordinator timeouts or transient pre-session TCP
/// connect failures on `attach_challenge_http`. Explicit HTTP status refusals
/// (401/403/etc.), signature/wire failures, TLS errors, and malformed payloads
/// always fail closed immediately with zero retries.
pub fn is_retryable_attach_challenge_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Timeout
            | Error::PhaseTimeout(_)
            | Error::Http("timeout" | "connect")
            | Error::HttpResponse {
                category: "timeout" | "connect",
                ..
            }
    )
}

/// True when an established or reconnecting room WebSocket closed cleanly/idly
/// (`code 1000` / Durable Object hibernation / transient network reset) rather
/// than an authentication, signature, replay, or coordinator pin violation.
pub fn is_reconnectable_room_error(error: &Error) -> bool {
    matches!(
        error,
        Error::WebSocketClosed(1000 | 1001 | 1006)
            | Error::WebSocket(
                "peer_close_without_status"
                    | "connection_reset"
                    | "unexpected_eof"
                    | "io_timeout"
                    | "io"
                    | "connection_refused"
                    | "dns"
            )
            | Error::Network
            | Error::Timeout
            | Error::PhaseTimeout(
                "peer_advertisement"
                    | "attach_challenge_http"
                    | "websocket_upgrade"
                    | "advertise_challenge_http"
                    | "advertisement_store_http"
            )
            | Error::Http("timeout" | "connect")
            | Error::HttpResponse {
                category: "timeout" | "connect",
                ..
            }
    )
}

/// Pure bounded jittered exponential backoff (`250ms` -> `30s` max).
/// `jitter_per_mille` in `0..=250` adds up to +25% jitter before clamping to `30s`.
pub fn reconnect_backoff_duration(attempt: u32, jitter_per_mille: u16) -> Duration {
    let shift = attempt.min(8);
    let base_ms = RECONNECT_BACKOFF_MIN_MS
        .saturating_mul(1u64 << shift)
        .min(RECONNECT_BACKOFF_MAX_MS);
    let capped_jitter = u64::from(jitter_per_mille.min(250));
    let jitter_ms = base_ms.saturating_mul(capped_jitter) / 1000;
    Duration::from_millis(
        base_ms
            .saturating_add(jitter_ms)
            .clamp(RECONNECT_BACKOFF_MIN_MS, RECONNECT_BACKOFF_MAX_MS),
    )
}

/// Computes the next bounded reconnect delay using OS CSPRNG jitter.
pub fn next_reconnect_backoff(attempt: u32) -> Duration {
    use rand::{TryRngCore, rngs::OsRng};
    let mut raw = [0u8; 2];
    let jitter_per_mille = if OsRng.try_fill_bytes(&mut raw).is_ok() {
        u16::from_le_bytes(raw) % 251
    } else {
        0
    };
    reconnect_backoff_duration(attempt, jitter_per_mille)
}

fn csprng_warmup_jitter_ms() -> u64 {
    use rand::{TryRngCore, rngs::OsRng};
    let mut raw = [0u8; 2];
    if OsRng.try_fill_bytes(&mut raw).is_ok() {
        u64::from(u16::from_le_bytes(raw) % 200)
    } else {
        0
    }
}

pub async fn retry_cold_attach_challenge<T, Op, OpFut, Sleep, SleepFut>(
    max_retries: usize,
    mut op: Op,
    mut sleep_fn: Sleep,
) -> Result<T, Error>
where
    Op: FnMut(usize) -> OpFut,
    OpFut: std::future::Future<Output = Result<T, Error>>,
    Sleep: FnMut(Duration) -> SleepFut,
    SleepFut: std::future::Future<Output = ()>,
{
    let bounded_retries = max_retries.min(ATTACH_CHALLENGE_MAX_RETRIES);
    let mut attempt = 0usize;
    loop {
        match op(attempt).await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if attempt >= bounded_retries || !is_retryable_attach_challenge_error(&error) {
                    return Err(error);
                }
                let base_ms = ATTACH_WARMUP_BACKOFF_MS
                    .get(attempt)
                    .copied()
                    .unwrap_or(1500);
                let delay =
                    Duration::from_millis(base_ms.saturating_add(csprng_warmup_jitter_ms()));
                tracing::info!(
                    room_phase = "attach_challenge_cold_retry",
                    attempt = attempt + 1,
                    backoff_ms = delay.as_millis() as u64
                );
                sleep_fn(delay).await;
                attempt += 1;
            }
        }
    }
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
        let headers_started = Instant::now();
        let mut response = request
            .send()
            .await
            .map_err(|error| http_response_error(path, false, headers_started, error))?;
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
        let body_started = Instant::now();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| http_response_error(path, true, body_started, error))?
        {
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
        self.open_inner(identity, other, addresses, book, None, false)
            .await
    }

    /// Explicit ordinary-daemon entrypoint. The pending gate and selected pins
    /// alone grant nothing; genuine own and peer stored-record joins are needed.
    pub async fn open_daemon(
        &self,
        identity: &DaemonRoomIdentity,
        endpoint: &iroh::Endpoint,
        gate: DaemonPeerGate,
        addresses: Vec<SocketAddr>,
        book: MemoryLookup,
    ) -> Result<RoomSession, Error> {
        if !bool::from(
            identity
                .endpoint_id()
                .as_bytes()
                .ct_eq(endpoint.id().as_bytes()),
        ) {
            return Err(BindingError::Endpoint.into());
        }
        let owner = gate.begin_owner(
            endpoint.id(),
            self.coordinator,
            &self.policy,
            self.base.as_str(),
        )?;
        let other = gate.configuration().peer_endpoint_id();
        self.open_inner(identity, other, addresses, book, Some(owner), false)
            .await
    }

    /// Reconnect an already-started ordinary-daemon gate after a clean room
    /// WebSocket closure (`code 1000` / DO hibernation / transient EOF) without
    /// permanently revoking the gate if a reconnect attempt itself hits a
    /// transient timeout/network error. Explicit coordinator/auth/signature
    /// refusals fail closed and revoke the gate immediately.
    pub async fn reconnect_daemon(
        &self,
        identity: &DaemonRoomIdentity,
        endpoint: &iroh::Endpoint,
        gate: DaemonPeerGate,
        addresses: Vec<SocketAddr>,
        book: MemoryLookup,
    ) -> Result<RoomSession, Error> {
        if !bool::from(
            identity
                .endpoint_id()
                .as_bytes()
                .ct_eq(endpoint.id().as_bytes()),
        ) {
            return Err(BindingError::Endpoint.into());
        }
        let owner = gate.reopen_owner(
            endpoint.id(),
            self.coordinator,
            &self.policy,
            self.base.as_str(),
        )?;
        let other = gate.configuration().peer_endpoint_id();
        self.open_inner(identity, other, addresses, book, Some(owner), true)
            .await
    }

    /// Refresh only this live daemon's transport presence on its existing
    /// WebSocket. No reconnect, original-message retry or task lease renewal.
    /// The caller must cancel its pending receive before invoking this method.
    pub async fn renew_daemon_presence(
        &self,
        identity: &DaemonRoomIdentity,
        session: &mut RoomSession,
    ) -> Result<(), Error> {
        let result = self.renew_daemon_presence_inner(identity, session).await;
        if let Err(ref error) = result {
            if matches!(error, Error::DaemonBinding(BindingError::Expired)) {
                session.close_for_reconnect().await;
            } else {
                // Unknown storage/receipt outcomes fail closed, with no nonce replay.
                session.close().await;
            }
        }
        result
    }

    async fn renew_daemon_presence_inner(
        &self,
        identity: &DaemonRoomIdentity,
        session: &mut RoomSession,
    ) -> Result<(), Error> {
        let owner = session
            .daemon_owner
            .as_ref()
            .ok_or(BindingError::Unavailable)?;
        let config = owner.gate().configuration();
        if !bool::from(
            identity
                .endpoint_id()
                .as_bytes()
                .ct_eq(config.local_endpoint_id().as_bytes()),
        ) || !bool::from(
            self.coordinator
                .as_bytes()
                .ct_eq(config.coordinator_endpoint_id().as_bytes()),
        ) || self.policy.as_ref() != config.relay_policy()
            || self.base.as_str() != owner.origin()
        {
            return Err(BindingError::Configuration.into());
        }
        let wait = owner.remaining_validity()?.min(REQUEST_TIMEOUT * 2);
        let ticket = owner.prepare_renewal()?;
        let mut cancellation = PresenceRenewalGuard {
            gate: owner.gate().clone(),
            committed: false,
        };
        let old = ticket.advertisement();
        let addresses = old
            .direct_addresses
            .iter()
            .map(|address| address.parse::<SocketAddr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Malformed)?;
        let revision = ticket.next_revision()?;
        let attached_session = session.attached_session_id()?;
        if attached_session != old.session_id {
            return Err(BindingError::Receipt.into());
        }
        let result = timeout(wait, async {
            let (challenge, _) = self
                .challenge(identity.endpoint_id(), "advertise", Some(attached_session))
                .await?;
            let wire = room_wire::sign_daemon_advertisement(
                identity,
                &challenge,
                revision,
                addresses,
                now_unix()?,
                &self.policy,
            )?;
            let (stored, _): (Stored, String) = self
                .post(
                    "/room/genesis/peer",
                    serde_json::to_vec(&wire).map_err(|_| Error::Malformed)?,
                    room_wire::auth_headers(identity, &challenge)?,
                )
                .await?;
            if !stored.stored {
                return Err(Error::Malformed);
            }
            Ok((wire, stored.receipt))
        })
        .await
        .map_err(|_| Error::PhaseTimeout("transport_presence_renewal"))??;
        session
            .daemon_owner
            .as_mut()
            .ok_or(BindingError::Unavailable)?
            .commit_renewal(ticket, result.0, result.1)?;
        cancellation.committed = true;
        tracing::info!(room_phase = "own_transport_presence_renewed");
        Ok(())
    }

    async fn open_inner<S: RoomSigner + ?Sized>(
        &self,
        identity: &S,
        other: EndpointId,
        addresses: Vec<SocketAddr>,
        book: MemoryLookup,
        mut daemon_owner: Option<DaemonRoomOwner>,
        preserve_gate_on_transient_failure: bool,
    ) -> Result<RoomSession, Error> {
        if other == identity.endpoint_id()
            || self.coordinator == identity.endpoint_id()
            || self.coordinator == other
        {
            return Err(Error::Malformed);
        }
        let pre_session = async {
            let (attach, attach_ray) = retry_cold_attach_challenge(
                ATTACH_CHALLENGE_MAX_RETRIES,
                |_| self.challenge(identity.endpoint_id(), "attach", None),
                tokio::time::sleep,
            )
            .await
            .map_err(|error| startup_http_phase("attach_challenge_http", error))?;
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
                        http::HeaderName::from_bytes(name.as_bytes())
                            .map_err(|_| Error::Malformed)?,
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
            Ok::<_, Error>((attach, attach_ray, socket, websocket_ray))
        }
        .await;
        let (attach, attach_ray, socket, websocket_ray) = match pre_session {
            Ok(tuple) => tuple,
            Err(error) => {
                if preserve_gate_on_transient_failure
                    && is_reconnectable_room_error(&error)
                    && let Some(owner) = daemon_owner.as_mut()
                {
                    let _ = owner.suspend_for_reconnect();
                }
                return Err(error);
            }
        };
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
            daemon_owner,
        };
        let store = async {
            let (challenge, challenge_ray) = self
                .challenge(
                    identity.endpoint_id(),
                    "advertise",
                    Some(&attach.session_id),
                )
                .await
                .map_err(|error| startup_http_phase("advertise_challenge_http", error))?;
            let wire = if session.daemon_owner.is_some() {
                room_wire::sign_daemon_advertisement(
                    identity,
                    &challenge,
                    1,
                    addresses,
                    now_unix()?,
                    &self.policy,
                )?
            } else {
                room_wire::sign_advertisement(identity, &challenge, 1, addresses, now_unix()?)?
            };
            let (stored, stored_ray): (Stored, String) = self
                .post(
                    "/room/genesis/peer",
                    serde_json::to_vec(&wire).map_err(|_| Error::Malformed)?,
                    room_wire::auth_headers(identity, &challenge)?,
                )
                .await
                .map_err(|error| startup_http_phase("advertisement_store_http", error))?;
            if !stored.stored {
                return Err(Error::Malformed);
            }
            room_wire::verify_receipt(&stored.receipt, self.coordinator, &wire)?;
            tracing::info!(room_phase = "own_advertisement_receipt_verified");
            Ok((
                RoomProof {
                    attach_challenge_ray: attach_ray,
                    websocket_ray,
                    advertise_challenge_ray: challenge_ray,
                    stored_ray,
                    coordinator_receipt_verified: true,
                },
                wire,
                stored.receipt,
            ))
        }
        .await;
        match store {
            Ok((proof, wire, receipt)) => {
                if let Some(owner) = session.daemon_owner.as_mut()
                    && let Err(error) = owner.bind_own(wire, receipt, &attach.session_id)
                {
                    session.close().await;
                    return Err(error.into());
                }
                session.proof = Some(proof);
                session.attached_session_id = Some(attach.session_id);
                Ok(session)
            }
            Err(error) => {
                if preserve_gate_on_transient_failure && is_reconnectable_room_error(&error) {
                    session.close_for_reconnect().await;
                } else {
                    session.close().await;
                }
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
    PeerAdvertisement {
        advertisement: Advertisement,
        #[serde(default)]
        receipt: Option<Receipt>,
    },
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
    daemon_owner: Option<DaemonRoomOwner>,
}
impl RoomSession {
    /// Fixed once per verified own advertisement, using the original clock.
    /// Observing this duration does not extend it or assert socket liveness.
    pub fn daemon_renewal_wait(&self) -> Result<Duration, Error> {
        self.daemon_owner
            .as_ref()
            .ok_or(BindingError::Unavailable)?
            .renewal_wait()
            .map_err(Error::from)
    }
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
        let result = self.receive_peer_inner(Duration::from_secs(12)).await;
        if result.is_err() {
            drop(self.daemon_owner.take());
        }
        result
    }

    async fn receive_peer_inner(&mut self, wait: Duration) -> Result<(), Error> {
        self.proof()?;
        let next = timeout(wait, self.socket.next())
            .await
            .map_err(|_| Error::PhaseTimeout("peer_advertisement"))?;
        let message = next.ok_or(Error::Network)?.map_err(websocket_error)?;
        let text = peer_message_text(&message)?;
        let ServerMessage::PeerAdvertisement {
            advertisement,
            receipt,
        } = parse(text.as_bytes())?;
        let addresses = if self.daemon_owner.is_some() {
            room_wire::verify_daemon_advertisement(
                &advertisement,
                self.other,
                now_unix()?,
                &self.policy,
            )?
        } else {
            room_wire::verify_advertisement(&advertisement, self.other, now_unix()?)?
        };
        self.revisions
            .accept(&advertisement.session_id, advertisement.revision)?;
        let info = addresses
            .into_iter()
            .fold(EndpointAddr::new(self.other), |addr, ip| {
                addr.with_ip_addr(ip)
            });
        let info = self.policy.attach_verified_peer(info, self.other)?;
        if let Some(owner) = self.daemon_owner.as_mut() {
            match receipt {
                Some(receipt) => owner.bind_peer(&advertisement, &receipt)?,
                None => owner.clear_peer()?,
            }
        }
        self.book.set_endpoint_info(info);
        self.peer_expiry = Some(advertisement.expiry_unix);
        Ok(())
    }
    pub async fn receive_daemon_peer(&mut self) -> Result<VerifiedDaemonPeer, Error> {
        let wait = match self
            .daemon_owner
            .as_ref()
            .ok_or(BindingError::Unavailable)
            .and_then(DaemonRoomOwner::remaining_validity)
        {
            Ok(wait) => wait,
            Err(error) => {
                if error == BindingError::Expired
                    && let Some(owner) = self.daemon_owner.as_mut()
                {
                    let _ = owner.suspend_for_reconnect();
                }
                drop(self.daemon_owner.take());
                return Err(error.into());
            }
        };
        let result = match self.receive_peer_inner(wait).await {
            Ok(()) => self.verified_daemon_peer(),
            Err(error) => Err(error),
        };
        if let Err(ref error) = result {
            if (is_reconnectable_room_error(error)
                || matches!(error, Error::DaemonBinding(BindingError::Expired)))
                && let Some(owner) = self.daemon_owner.as_mut()
            {
                let _ = owner.suspend_for_reconnect();
            }
            drop(self.daemon_owner.take());
        }
        result
    }
    pub fn verified_daemon_peer(&self) -> Result<VerifiedDaemonPeer, Error> {
        self.daemon_owner
            .as_ref()
            .ok_or(BindingError::Unavailable)?
            .gate()
            .current_peer()
            .map_err(Error::from)
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
        drop(self.daemon_owner.take());
        self.proof = None;
        self.attached_session_id = None;
        self.peer_expiry = None;
        self.book.remove_endpoint_info(self.other);
        let _ = timeout(Duration::from_secs(2), self.socket.close()).await;
    }
    pub async fn close_for_reconnect(&mut self) {
        if let Some(mut owner) = self.daemon_owner.take() {
            let _ = owner.suspend_for_reconnect();
        }
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
        drop(self.daemon_owner.take());
        self.book.remove_endpoint_info(self.other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_policy::RelayPolicy;
    use std::sync::Arc;

    #[test]
    fn http_response_diagnostics_distinguish_stages_without_upstream_text() {
        let coordinator = Identity::test_identity(rand::random()).endpoint_id();
        let policy = Arc::new(RelayPolicy::from_local_manifest(None, None).unwrap());
        let client = RoomClient::new("https://room.invalid", coordinator, policy).unwrap();
        for (path, body, phase) in [
            (
                "/room/genesis/challenge",
                false,
                "challenge_response_headers",
            ),
            ("/room/genesis/challenge", true, "challenge_response_body"),
            ("/room/genesis/peer", false, "peer_store_response_headers"),
            ("/room/genesis/peer", true, "peer_store_response_body"),
            ("PRIVATE_PATH_MARKER", false, "other_response_headers"),
            ("PRIVATE_PATH_MARKER", true, "other_response_body"),
        ] {
            let error = client
                .http
                .get("https://room.invalid/PRIVATE_URL_MARKER")
                .header("invalid\nheader", "PRIVATE_HEADER_MARKER")
                .build()
                .unwrap_err();
            let diagnostic = http_response_error(path, body, Instant::now(), error).to_string();
            assert!(diagnostic.starts_with(&format!(
                "the room HTTP {phase} failed (request, elapsed_ms="
            )));
            assert!(!diagnostic.contains("PRIVATE_"));
            assert!(!diagnostic.contains("room.invalid"));
        }
        assert!(matches!(
            startup_http_phase(
                "attach_challenge",
                Error::HttpResponse {
                    phase: "challenge_response_body",
                    category: "timeout",
                    elapsed_ms: 5000,
                }
            ),
            Error::PhaseTimeout("attach_challenge")
        ));
    }

    #[test]
    fn peer_frame_diagnostics_exclude_payload_and_close_reason() {
        use tokio_websockets::{CloseCode, Message};
        let private = "PRIVATE_FRAME_TEST_MARKER";
        for (message, expected) in [
            (
                Message::close(Some(CloseCode::NORMAL_CLOSURE), private),
                "the room WebSocket closed with code 1000",
            ),
            (
                Message::close(None, ""),
                "the room WebSocket operation failed (peer_close_without_status)",
            ),
            (
                Message::ping(private.as_bytes().to_vec()),
                "the room WebSocket operation failed (peer_ping_frame)",
            ),
            (
                Message::pong(private.as_bytes().to_vec()),
                "the room WebSocket operation failed (peer_pong_frame)",
            ),
            (
                Message::binary(private.as_bytes().to_vec()),
                "the room WebSocket operation failed (peer_non_text_frame)",
            ),
        ] {
            let diagnostic = peer_message_text(&message).unwrap_err().to_string();
            assert_eq!(diagnostic, expected);
            assert!(!diagnostic.contains(private));
        }
        let text = Message::text(private);
        assert_eq!(peer_message_text(&text).unwrap(), private);
    }

    #[test]
    fn cancelled_presence_renewal_revokes_gate_but_committed_guard_does_not() {
        use futures_util::FutureExt;
        for committed in [false, true] {
            let local = Identity::test_identity(rand::random()).endpoint_id();
            let peer = Identity::test_identity(rand::random()).endpoint_id();
            let coordinator = Identity::test_identity(rand::random()).endpoint_id();
            let policy = Arc::new(RelayPolicy::from_local_manifest(None, None).unwrap());
            let config = crate::room_binding::DaemonPairConfig::try_new(
                "cancel-test".into(),
                1,
                local,
                peer,
                coordinator,
                policy.clone(),
            )
            .unwrap();
            let gate = DaemonPeerGate::pending(config);
            let owner = gate
                .begin_owner(local, coordinator, &policy, "https://room.invalid/")
                .unwrap();
            let future = async {
                let _guard = PresenceRenewalGuard {
                    gate: gate.clone(),
                    committed,
                };
                std::future::pending::<()>().await;
            };
            assert!(future.now_or_never().is_none());
            let expected = if committed {
                BindingError::Unavailable
            } else {
                BindingError::Revoked
            };
            assert!(matches!(owner.prepare_renewal(), Err(error) if error == expected));
        }
    }
    #[test]
    fn peer_receipt_is_optional_observational_wire_data_until_verified() {
        let advertisement = serde_json::json!({"v":1,"room":"genesis","actor_id":"11".repeat(32),"session_id":"22".repeat(32),
            "challenge_nonce":"33".repeat(32),"revision":1,"expiry_unix":1060,"node_id":"11".repeat(32),"direct_addresses":["127.0.0.1:1234"],"signature":"00".repeat(64)});
        let body = serde_json::to_vec(
            &serde_json::json!({"kind":"peer_advertisement","advertisement":advertisement}),
        )
        .unwrap();
        let ServerMessage::PeerAdvertisement { receipt, .. } = parse(&body).unwrap();
        assert!(receipt.is_none());
    }
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

    #[test]
    fn reconnect_classification_distinguishes_clean_ws_closure_from_auth_and_pin_refusals() {
        for transient in [
            Error::WebSocketClosed(1000),
            Error::WebSocketClosed(1001),
            Error::WebSocketClosed(1006),
            Error::WebSocket("peer_close_without_status"),
            Error::WebSocket("connection_reset"),
            Error::WebSocket("unexpected_eof"),
            Error::Network,
            Error::PhaseTimeout("attach_challenge_http"),
            Error::PhaseTimeout("peer_advertisement"),
        ] {
            assert!(
                is_reconnectable_room_error(&transient),
                "expected transient reconnect classification for {transient}"
            );
        }
        for terminal in [
            Error::Refused(401),
            Error::Refused(403),
            Error::Upgrade(401),
            Error::Upgrade(403),
            Error::WebSocketClosed(4003),
            Error::WebSocket("tls"),
            Error::WebSocket("frame_protocol"),
            Error::Replay,
            Error::Malformed,
            Error::MissingRay,
            Error::DaemonBinding(BindingError::Revoked),
            Error::DaemonBinding(BindingError::Replay),
        ] {
            assert!(
                !is_reconnectable_room_error(&terminal),
                "expected fail-closed non-reconnectable classification for {terminal}"
            );
        }
    }

    #[test]
    fn reconnect_backoff_scales_from_250ms_and_caps_at_30s() {
        assert_eq!(reconnect_backoff_duration(0, 0), Duration::from_millis(250));
        assert_eq!(
            reconnect_backoff_duration(0, 200),
            Duration::from_millis(300)
        );
        assert_eq!(reconnect_backoff_duration(1, 0), Duration::from_millis(500));
        assert_eq!(
            reconnect_backoff_duration(2, 0),
            Duration::from_millis(1000)
        );
        assert_eq!(reconnect_backoff_duration(7, 250), Duration::from_secs(30));
        assert_eq!(
            reconnect_backoff_duration(u32::MAX, u16::MAX),
            Duration::from_secs(30)
        );
        let live = next_reconnect_backoff(0);
        assert!(live >= Duration::from_millis(250) && live <= Duration::from_millis(313));
    }

    #[tokio::test]
    async fn cold_attach_challenge_retries_timeouts_with_warmup_but_never_retries_refusals() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // 2 cold timeouts followed by warm success on attempt 2 (total 3 calls).
        let calls = AtomicUsize::new(0);
        let sleeps = AtomicUsize::new(0);
        let ok = retry_cold_attach_challenge(
            ATTACH_CHALLENGE_MAX_RETRIES,
            |_| {
                let idx = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if idx < 2 {
                        Err(Error::HttpResponse {
                            phase: "challenge_response_headers",
                            category: "timeout",
                            elapsed_ms: 5002,
                        })
                    } else {
                        Ok(42u8)
                    }
                }
            },
            |_| {
                sleeps.fetch_add(1, Ordering::SeqCst);
                async {}
            },
        )
        .await
        .unwrap();
        assert_eq!(ok, 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(sleeps.load(Ordering::SeqCst), 2);

        // Exhausting all retries returns the timeout error cleanly.
        let exhausted_calls = AtomicUsize::new(0);
        let exhausted = retry_cold_attach_challenge(
            ATTACH_CHALLENGE_MAX_RETRIES,
            |_| {
                exhausted_calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<u8, _>(Error::PhaseTimeout("attach_challenge_http")) }
            },
            |_| async {},
        )
        .await;
        assert!(matches!(
            exhausted,
            Err(Error::PhaseTimeout("attach_challenge_http"))
        ));
        assert_eq!(exhausted_calls.load(Ordering::SeqCst), 3);

        // Explicit 403 coordinator refusal fails closed on first attempt with zero retries.
        let refusal_calls = AtomicUsize::new(0);
        let refusal_sleeps = AtomicUsize::new(0);
        let refused = retry_cold_attach_challenge(
            ATTACH_CHALLENGE_MAX_RETRIES,
            |_| {
                refusal_calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<u8, _>(Error::Refused(403)) }
            },
            |_| {
                refusal_sleeps.fetch_add(1, Ordering::SeqCst);
                async {}
            },
        )
        .await;
        assert!(matches!(refused, Err(Error::Refused(403))));
        assert_eq!(refusal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(refusal_sleeps.load(Ordering::SeqCst), 0);
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
