//! Owner-held, fixed-room Streamable HTTP inbox. This creates no admission
//! registry and authenticates possession of a local capability, never an app,
//! account or model. No stdio process is attached or retroactively observed.

mod session;
#[cfg(test)]
mod tests;
mod transport;

use super::*;
use axum::{
    body::{Body, Bytes, HttpBody, to_bytes},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use chinwag_connector_registry::AuthorityKind;
use http_body::Frame;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use session::SingleSessionManager;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use transport::TransportOwner;

pub const MOUNT_PATH: &str = "/api/mcp";
const BODY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HTTP_LEASE: Duration = Duration::from_secs(900);
const VERSIONS: [&str; 2] = ["2025-06-18", "2025-11-25"];

/// Fresh owner-created transport secret. It is never a registry identity and
/// deliberately has no Debug, Clone, Serialize or deserialization interface.
pub struct HttpCapability {
    token: String,
}
impl HttpCapability {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            token: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        }
    }
    /// Only the trusted launch owner uses this to write its new private file.
    /// Never include this value in status, receipts, logs or client identity.
    pub fn token(&self) -> &str {
        &self.token
    }
    fn accepts(&self, value: &str) -> bool {
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        if token.len() != self.token.len() {
            return false;
        }
        bool::from(token.as_bytes().ct_eq(self.token.as_bytes()))
    }
}

pub struct HttpInboxConfig {
    pub allowed_authority: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpInboxSnapshot {
    pub schema: &'static str,
    pub connection_observation: LifecycleSnapshot,
    pub session_started: bool,
    pub session_closed: bool,
    pub transport_worker_joined: bool,
    pub reader_worker_joined: bool,
    pub client_identity: &'static str,
}

struct CleanupJob {
    join: tokio::sync::Mutex<Option<JoinHandle<Result<(), InboxError>>>>,
}
struct Control {
    owner: InboxServer,
    deadline: Instant,
    closed: AtomicBool,
    started: AtomicBool,
    cancel: CancellationToken,
    transport: Arc<TransportOwner>,
    runtime: tokio::runtime::Handle,
    cleanup: Mutex<Option<Arc<CleanupJob>>>,
    gate: Mutex<()>,
}
impl Control {
    fn live(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && !self.owner.shared.closed.load(Ordering::Acquire)
    }
    fn retire(self: &Arc<Self>) {
        let _gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.closed.store(true, Ordering::Release);
        self.owner.shared.close_admission();
        self.cancel.cancel();
        self.transport.cancel();
        let mut slot = self
            .cleanup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return;
        }
        let control = self.clone();
        let handle = self.runtime.spawn(async move {
            let transport = if control.started.load(Ordering::Acquire) {
                control.transport.wait().await
            } else {
                Ok(())
            };
            let reader = control.owner.shutdown().await;
            transport.and(reader)
        });
        *slot = Some(Arc::new(CleanupJob {
            join: tokio::sync::Mutex::new(Some(handle)),
        }));
    }
    async fn shutdown(self: &Arc<Self>) -> Result<(), InboxError> {
        self.retire();
        let job = self
            .cleanup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(InboxError::Unavailable)?;
        let mut slot = job.join.lock().await;
        if let Some(handle) = slot.as_mut() {
            let outcome = handle.await;
            slot.take();
            outcome.map_err(|_| InboxError::Unavailable)??;
        }
        if self.owner.lifecycle_snapshot().worker_state != WorkerState::Drained {
            return Err(InboxError::Unavailable);
        }
        if self.started.load(Ordering::Acquire) && !self.transport.joined() {
            return Err(InboxError::Protocol);
        }
        Ok(())
    }
}

pub struct HttpInbox {
    sdk: StreamableHttpService<InboxServer, SingleSessionManager>,
    manager: Arc<SingleSessionManager>,
    control: Arc<Control>,
    capability: HttpCapability,
    authority: String,
    responses: Arc<Semaphore>,
    incoming: Arc<Semaphore>,
    timer: Mutex<Option<JoinHandle<()>>>,
}
impl HttpInbox {
    pub fn new(
        owner: InboxServer,
        capability: HttpCapability,
        config: HttpInboxConfig,
    ) -> Result<Self, InboxError> {
        if !canonical_authority(&config.allowed_authority) {
            return Err(InboxError::InvalidLaunch);
        }
        let binding = owner.current_binding()?;
        if binding.authority != AuthorityKind::OwnerLocalHttpCapabilityUnattributed {
            return Err(InboxError::InvalidLaunch);
        }
        let deadline = binding.lease_expires_at.min(binding.grant_expires_at);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > MAX_HTTP_LEASE {
            return Err(InboxError::InvalidLaunch);
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| InboxError::InvalidLaunch)?;
        let control = Arc::new(Control {
            owner: owner.clone(),
            deadline,
            closed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            cancel: CancellationToken::new(),
            transport: TransportOwner::new(runtime.clone()),
            runtime: runtime.clone(),
            cleanup: Mutex::new(None),
            gate: Mutex::new(()),
        });
        let manager = Arc::new(SingleSessionManager::new(control.clone()));
        let mut sdk_config = StreamableHttpServerConfig::default().enforce_origin_validation();
        sdk_config.legacy_session_mode = true;
        sdk_config.sse_keep_alive = None;
        sdk_config.sse_retry = None;
        sdk_config.session_store = None;
        sdk_config.max_request_body_bytes = wire::MAX_INPUT_BYTES;
        sdk_config.allowed_hosts = vec![config.allowed_authority.clone()];
        sdk_config.cancellation_token = control.cancel.clone();
        let sdk =
            StreamableHttpService::new(move || Ok(owner.clone()), manager.clone(), sdk_config);
        let weak = Arc::downgrade(&control);
        let timer = runtime.spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            if let Some(control) = weak.upgrade() {
                control.retire();
            }
        });
        Ok(Self {
            sdk,
            manager,
            control,
            capability,
            authority: config.allowed_authority,
            responses: Arc::new(Semaphore::new(1)),
            incoming: Arc::new(Semaphore::new(1)),
            timer: Mutex::new(Some(timer)),
        })
    }

    pub fn lifecycle_snapshot(&self) -> HttpInboxSnapshot {
        let observation = self.control.owner.lifecycle_snapshot();
        HttpInboxSnapshot {
            schema: "chinwag-owner-http-inbox/v1",
            session_started: self.control.started.load(Ordering::Acquire),
            session_closed: self.control.closed.load(Ordering::Acquire),
            transport_worker_joined: self.control.transport.joined(),
            reader_worker_joined: observation.worker_state == WorkerState::Drained,
            connection_observation: observation,
            client_identity: "unattributed_owner_http_capability",
        }
    }
    pub async fn shutdown(&self) -> Result<(), InboxError> {
        if let Some(timer) = self
            .timer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            timer.abort();
        }
        self.control.shutdown().await
    }

    /// Stops new admission and requests retained cleanup without blocking on
    /// the shared host writer. Use shutdown to observe actual worker joins.
    pub fn request_close(&self) {
        self.control.retire();
    }

    /// A busy cancellation cannot inspect the grant while the original read
    /// owns the writer. It may request closure of this exact admitted session,
    /// without entering SDK hooks or claiming that the read has drained.
    fn canonical_fence(
        &self,
        cancellation: bool,
        session: Option<&str>,
    ) -> Result<(), (StatusCode, &'static str)> {
        match self.control.owner.current_binding() {
            Ok(_) => Ok(()),
            Err(InboxError::Busy)
                if cancellation && session.is_some_and(|id| self.manager.owns_id(id)) =>
            {
                self.control.retire();
                Err((
                    StatusCode::ACCEPTED,
                    "Owner HTTP inbox closure requested; reader completion unconfirmed",
                ))
            }
            Err(InboxError::Busy) => {
                Err((StatusCode::CONFLICT, "Owner HTTP inbox request unavailable"))
            }
            Err(_) => {
                self.control.retire();
                Err((StatusCode::GONE, "Owner HTTP inbox request unavailable"))
            }
        }
    }

    pub async fn handle(&self, request: Request<Body>) -> Response {
        let headers = request.headers();
        if request.uri().path() != MOUNT_PATH || request.uri().query().is_some() {
            return failure(StatusCode::NOT_FOUND);
        }
        if one(headers, header::HOST.as_str()) != Some(self.authority.as_str())
            || headers.contains_key(header::ORIGIN)
            || headers.contains_key(header::COOKIE)
            || headers.contains_key(header::PROXY_AUTHORIZATION)
        {
            return failure(StatusCode::FORBIDDEN);
        }
        if !one(headers, header::AUTHORIZATION.as_str())
            .is_some_and(|value| self.capability.accepts(value))
        {
            return failure(StatusCode::UNAUTHORIZED);
        }
        if !self.control.live() {
            self.control.retire();
            return failure(StatusCode::GONE);
        }
        let method = request.method().clone();
        if method != axum::http::Method::POST && method != axum::http::Method::DELETE {
            let mut response = failure(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(
                header::ALLOW,
                header::HeaderValue::from_static("POST, DELETE"),
            );
            return response;
        }
        if headers.contains_key("last-event-id") {
            return failure(StatusCode::BAD_REQUEST);
        }
        let protocol = one(headers, "mcp-protocol-version").map(str::to_owned);
        if headers.get_all("mcp-protocol-version").iter().count() > 1
            || (headers.contains_key("mcp-protocol-version") && protocol.is_none())
            || protocol
                .as_deref()
                .is_some_and(|value| !VERSIONS.contains(&value))
        {
            return failure(StatusCode::BAD_REQUEST);
        }
        let session = one(headers, "mcp-session-id").map(str::to_owned);
        if headers.get_all("mcp-session-id").iter().count() > 1
            || (headers.contains_key("mcp-session-id") && session.is_none())
            || session.as_deref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return failure(StatusCode::BAD_REQUEST);
        }
        let _receiving = match self.incoming.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return failure(StatusCode::CONFLICT),
        };
        let (mut parts, body) = request.into_parts();
        // SDK extensions receive headers, so remove the secret before parsing or
        // handing any request to rmcp. Nothing stores it in peer observations.
        parts.headers.remove(header::AUTHORIZATION);
        let bytes =
            match tokio::time::timeout(BODY_TIMEOUT, to_bytes(body, wire::MAX_INPUT_BYTES)).await {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(_)) => return failure(StatusCode::PAYLOAD_TOO_LARGE),
                Err(_) => return failure(StatusCode::REQUEST_TIMEOUT),
            };
        if method == axum::http::Method::DELETE {
            if session.is_none() || protocol.is_none() || !bytes.is_empty() {
                return failure(StatusCode::BAD_REQUEST);
            }
            if let Err(response) = self.canonical_fence(false, session.as_deref()) {
                return response.into_response();
            }
            let response = self
                .sdk
                .handle(Request::from_parts(parts, Body::empty()))
                .await;
            return response.map(Body::new);
        }
        if one(&parts.headers, header::CONTENT_TYPE.as_str()) != Some("application/json")
            || one(&parts.headers, header::ACCEPT.as_str()).is_none_or(|value| !valid_accept(value))
        {
            return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => return failure(StatusCode::BAD_REQUEST),
        };
        let envelope = match classify(&value, session.is_some(), protocol.as_deref()) {
            Ok(envelope) => envelope,
            Err(()) => return failure(StatusCode::BAD_REQUEST),
        };
        let cancellation =
            value.get("method").and_then(Value::as_str) == Some("notifications/cancelled");
        if let Err(response) = self.canonical_fence(cancellation, session.as_deref()) {
            return response.into_response();
        }
        let permit = if envelope {
            match self.responses.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return failure(StatusCode::CONFLICT),
            }
        } else {
            None
        };
        let normalized = match serde_json::to_vec(&value) {
            Ok(bytes) => bytes,
            Err(_) => return failure(StatusCode::BAD_REQUEST),
        };
        let mut dispatch = DispatchGuard {
            control: self.control.clone(),
            armed: envelope,
        };
        let response = self
            .sdk
            .handle(Request::from_parts(parts, Body::from(normalized)))
            .await;
        dispatch.armed = false;
        if let Some(permit) = permit {
            let (parts, body) = response.into_parts();
            Response::from_parts(
                parts,
                Body::new(ResponseBody {
                    inner: Box::pin(body),
                    permit: Some(permit),
                    control: self.control.clone(),
                    finished: false,
                    bytes: 0,
                }),
            )
        } else {
            response.map(Body::new)
        }
    }
}

fn canonical_authority(value: &str) -> bool {
    if let Ok(address) = value.parse::<std::net::Ipv4Addr>() {
        // A canonical HTTP origin omits the default port 80. The exact Host
        // value still has to match this authority on every request.
        return address.is_loopback() && address.to_string() == value;
    }
    value
        .parse::<std::net::SocketAddrV4>()
        .is_ok_and(|address| {
            address.ip().is_loopback()
                && !matches!(address.port(), 0 | 80)
                && address.to_string() == value
        })
}
impl Drop for HttpInbox {
    fn drop(&mut self) {
        if let Some(timer) = self
            .timer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            timer.abort();
        }
        self.control.retire();
    }
}

fn one<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(first)
    }
}
fn valid_accept(value: &str) -> bool {
    let mut json = false;
    let mut sse = false;
    for item in value.split(',').map(str::trim) {
        match item {
            "application/json" if !json => json = true,
            "text/event-stream" if !sse => sse = true,
            _ => return false,
        }
    }
    json && sse
}
fn classify(value: &Value, session: bool, protocol: Option<&str>) -> Result<bool, ()> {
    let object = value.as_object().ok_or(())?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || object.contains_key("_meta")
    {
        return Err(());
    }
    let method = object.get("method").and_then(Value::as_str).ok_or(())?;
    let params = object.get("params");
    if params.is_some_and(|params| !params.is_object()) {
        return Err(());
    }
    if let Some(meta) = params.and_then(|params| params.get("_meta"))
        && (!matches!(method, "tools/list" | "tools/call" | "ping") || !legacy_progress_meta(meta))
    {
        return Err(());
    }
    if method == "initialize" {
        let version = params
            .and_then(|params| params.get("protocolVersion"))
            .and_then(Value::as_str)
            .ok_or(())?;
        if session
            || !VERSIONS.contains(&version)
            || protocol.is_some_and(|header| header != version)
            || !object.contains_key("id")
        {
            return Err(());
        }
        return Ok(true);
    }
    if !session || protocol.is_none() {
        return Err(());
    }
    match method {
        "tools/list" | "tools/call" | "ping" if object.contains_key("id") => Ok(true),
        "notifications/initialized" | "notifications/cancelled" if !object.contains_key("id") => {
            Ok(false)
        }
        _ => Err(()),
    }
}

fn legacy_progress_meta(meta: &Value) -> bool {
    let Some(object) = meta.as_object() else {
        return false;
    };
    if object.len() != 1 {
        return false;
    }
    // rmcp adds this correlation value even for legacy requests. No version,
    // client capability or other discovery-lifecycle metadata is accepted.
    match object.get("progressToken") {
        Some(Value::Number(number)) => number.is_i64(),
        Some(Value::String(token)) => {
            !token.is_empty() && token.len() <= 128 && !token.chars().any(char::is_control)
        }
        _ => false,
    }
}
fn failure(status: StatusCode) -> Response {
    (status, "Owner HTTP inbox request unavailable").into_response()
}

struct DispatchGuard {
    control: Arc<Control>,
    armed: bool,
}
impl Drop for DispatchGuard {
    fn drop(&mut self) {
        if self.armed {
            self.control.retire();
        }
    }
}

struct ResponseBody<B> {
    inner: Pin<Box<B>>,
    permit: Option<OwnedSemaphorePermit>,
    control: Arc<Control>,
    finished: bool,
    bytes: usize,
}
impl<B> HttpBody for ResponseBody<B>
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    this.bytes = this.bytes.saturating_add(bytes.len());
                }
                if this.bytes > wire::MAX_OUTPUT_BYTES {
                    this.control.retire();
                    this.finished = true;
                    this.permit.take();
                    return Poll::Ready(Some(Err(std::io::Error::other(
                        "HTTP MCP response limit",
                    ))));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.finished = true;
                this.permit.take();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(_))) => {
                this.control.retire();
                this.finished = true;
                this.permit.take();
                Poll::Ready(Some(Err(std::io::Error::other(
                    "HTTP MCP response unavailable",
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
impl<B> Drop for ResponseBody<B> {
    fn drop(&mut self) {
        if !self.finished {
            self.control.retire();
        }
    }
}
