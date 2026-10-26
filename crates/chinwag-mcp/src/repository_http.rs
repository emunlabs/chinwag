//! Root-private service-only HTTP/SSE ownership proof. No listener or CLI transport.
use crate::{
    http_lifetime::{Activity, HttpLifetime},
    owner::{ContextServer, Owner},
    wire,
};
use bytes::Bytes;
use http::{
    HeaderMap, Request, Response, StatusCode,
    header::{AUTHORIZATION, HOST},
};
use http_body::Body;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
};
use std::{
    convert::Infallible, error::Error, fmt::Display, marker::PhantomData, num::NonZeroU16,
    path::PathBuf, sync::Arc,
};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use tower_service::Service;
use zeroize::Zeroizing;

type ResponseBody = BoxBody<Bytes, Infallible>;

/// A rejection condition for this new endpoint, never a repository/cleanup owner.
pub struct AccessSecret(Zeroizing<[u8; 32]>);
impl AccessSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self(Zeroizing::new(secret))
    }
    /// Reads an explicitly supplied, memory-only secret; never a path, URL or environment value.
    pub fn read_exact_input(input: &mut dyn std::io::Read) -> Result<Self, &'static str> {
        let mut secret = Zeroizing::new([0u8; 32]);
        input
            .read_exact(secret.as_mut())
            .map_err(|_| "HTTP input requires exactly 32 secret bytes and EOF")?;
        let mut extra = Zeroizing::new([0u8; 1]);
        if input
            .read(extra.as_mut())
            .map_err(|_| "HTTP secret input read failed")?
            != 0
        {
            return Err("HTTP input requires exactly 32 secret bytes and EOF");
        }
        Ok(Self(secret))
    }
    fn matches(&self, header: &[u8]) -> bool {
        if header.len() != 71 || !header.starts_with(b"Bearer ") {
            return false;
        }
        let mut actual = Zeroizing::new([0u8; 32]);
        for (index, pair) in header[7..].chunks_exact(2).enumerate() {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
                return false;
            };
            actual[index] = high * 16 + low;
        }
        bool::from(self.0.as_slice().ct_eq(actual.as_slice()))
    }
}
impl std::fmt::Debug for AccessSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessSecret(<redacted>)")
    }
}

/// This service proof never binds this authority to a socket.
pub struct LoopbackAuthority(String);
impl LoopbackAuthority {
    pub fn new(port: NonZeroU16) -> Self {
        Self(format!("127.0.0.1:{port}"))
    }
}

#[must_use = "Consume the same original HTTP owner through checked finish"]
pub struct RepositoryHttp {
    owner: Option<Owner>,
    service: StreamableHttpService<ContextServer, NeverSessionManager>,
    stop: CancellationToken,
    lifetime: Arc<HttpLifetime>,
    access: AccessSecret,
    authority: LoopbackAuthority,
}

/// Its borrow and activity guard both belong to the same original owner.
/// Forgetting this value leaks activity and cannot create a finish receipt.
#[must_use = "Read or drop this original response before finishing its HTTP owner"]
pub struct ScopedHttpResponse<'owner> {
    response: Option<Response<ResponseBody>>,
    bytes: usize,
    frames: usize,
    _activity: Activity,
    _original: PhantomData<&'owner mut RepositoryHttp>,
}
impl ScopedHttpResponse<'_> {
    pub fn status(&self) -> Option<StatusCode> {
        self.response.as_ref().map(Response::status)
    }
    pub fn headers(&self) -> Option<&HeaderMap> {
        self.response.as_ref().map(Response::headers)
    }
    pub async fn frame(&mut self) -> Result<Option<Bytes>, &'static str> {
        let Some(response) = self.response.as_mut() else {
            return Err("Original HTTP response is closed");
        };
        let next = response.body_mut().frame().await;
        let bytes = match next {
            None => return Ok(None),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.response.take();
                    return Err("Unexpected HTTP response trailer");
                }
            },
            Some(Err(never)) => match never {},
        };
        self.frames += 1;
        if self.frames > 4096 {
            self.response.take();
            return Err("HTTP response frame limit");
        }
        let Some(total) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= wire::MAX_OUTPUT_BYTES)
        else {
            // Drop the original SDK body now; it cancels this exact request.
            self.response.take();
            return Err("HTTP response limit");
        };
        self.bytes = total;
        Ok(Some(bytes))
    }
}

#[must_use = "Failure retains the original owner; do not start another"]
pub struct HttpFinishFailure {
    original: Box<RepositoryHttp>,
    reason: String,
}
impl HttpFinishFailure {
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub fn into_original(self) -> RepositoryHttp {
        *self.original
    }
}
impl std::fmt::Debug for HttpFinishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpFinishFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for HttpFinishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}
impl Error for HttpFinishFailure {}

/// Observation only; private fields prevent it from reminting an owner.
pub struct HttpFinished {
    worker_checked: bool,
}
impl HttpFinished {
    pub fn original_worker_checked(&self) -> bool {
        self.worker_checked
    }
}

impl RepositoryHttp {
    /// Synchronous startup prevents abandoning a future with a newly spawned worker.
    /// Call outside Tokio; drive request/response futures inside your own runtime.
    pub fn open_private_repository(
        repo: PathBuf,
        access: AccessSecret,
        authority: LoopbackAuthority,
    ) -> Result<Self, Box<dyn Error>> {
        Self::open_with_lifetime(repo, access, authority, Arc::new(HttpLifetime::default()))
    }
    #[cfg(test)]
    pub(crate) fn open_with_probe(
        repo: PathBuf,
        access: AccessSecret,
        authority: LoopbackAuthority,
        probe: Arc<crate::http_probe::Probe>,
    ) -> Result<Self, Box<dyn Error>> {
        Self::open_with_lifetime(
            repo,
            access,
            authority,
            Arc::new(HttpLifetime::with_probe(probe)),
        )
    }
    fn open_with_lifetime(
        repo: PathBuf,
        access: AccessSecret,
        authority: LoopbackAuthority,
        lifetime: Arc<HttpLifetime>,
    ) -> Result<Self, Box<dyn Error>> {
        let stop = CancellationToken::new();
        let config = StreamableHttpServerConfig::default()
            .with_allowed_hosts([authority.0.clone()])
            .enforce_origin_validation()
            .with_legacy_session_mode(false)
            .with_json_response(false)
            .with_sse_keep_alive(None)
            .with_sse_retry(None)
            .with_max_request_body_bytes(wire::MAX_INPUT_BYTES)
            .with_stateless_protocol_metadata_required(true)
            .with_cancellation_token(stop.clone());
        let (server, owner) = Owner::start_blocking(repo)?;
        let server = server.require_modern_http(lifetime.clone());
        let service = StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(NeverSessionManager::default()),
            config,
        );
        Ok(Self {
            owner: Some(owner),
            service,
            stop,
            lifetime,
            access,
            authority,
        })
    }
    pub fn active_observations(&self) -> (usize, usize) {
        self.lifetime.counts()
    }
    pub async fn request<B>(
        &mut self,
        request: Request<B>,
    ) -> Result<ScopedHttpResponse<'_>, &'static str>
    where
        B: Body + Send + 'static,
        B::Error: Display,
        B::Data: Send + 'static,
    {
        let activity = self.lifetime.frontend()?;
        let mut authorization = request.headers().get_all(AUTHORIZATION).iter();
        let authorized = authorization
            .next()
            .is_some_and(|value| self.access.matches(value.as_bytes()))
            && authorization.next().is_none();
        let mut host = request.headers().get_all(HOST).iter();
        let host_matches = host
            .next()
            .is_some_and(|value| value.as_bytes() == self.authority.0.as_bytes())
            && host.next().is_none()
            && request
                .uri()
                .authority()
                .is_none_or(|value| value.as_str() == self.authority.0)
            && request
                .uri()
                .scheme_str()
                .is_none_or(|scheme| scheme == "http");
        let path_matches = request.uri().path() == "/mcp" && request.uri().query().is_none();
        let metadata_unique = request.headers().keys().all(|name| {
            let text = name.as_str();
            !(text == "mcp-protocol-version"
                || text == "mcp-method"
                || text == "mcp-name"
                || text.starts_with("mcp-param-"))
                || request.headers().get_all(name).iter().nth(1).is_none()
        });
        let modern_protocol = request
            .headers()
            .get("mcp-protocol-version")
            .is_some_and(|value| value.as_bytes() == b"2026-07-28");
        let response = if !authorized {
            refusal(StatusCode::UNAUTHORIZED)
        } else if !host_matches {
            refusal(StatusCode::FORBIDDEN)
        } else if !path_matches {
            refusal(StatusCode::NOT_FOUND)
        } else if request.method() != http::Method::POST {
            refusal(StatusCode::METHOD_NOT_ALLOWED)
        } else if !metadata_unique || !modern_protocol {
            refusal(StatusCode::BAD_REQUEST)
        } else {
            match self.service.call(request).await {
                Ok(response) => response,
                Err(never) => match never {},
            }
        };
        Ok(ScopedHttpResponse {
            response: Some(response),
            bytes: 0,
            frames: 0,
            _activity: activity,
            _original: PhantomData,
        })
    }
    fn failure(self, reason: impl ToString) -> HttpFinishFailure {
        HttpFinishFailure {
            original: Box::new(self),
            reason: reason.to_string(),
        }
    }
    pub(crate) fn close_http(&self) {
        self.lifetime.close();
        self.stop.cancel();
    }
    /// Stop new work and consume the original worker only after real activity ends.
    /// A busy original is retained. Quiescence never proves a tool completed.
    pub fn finish(mut self) -> Result<HttpFinished, HttpFinishFailure> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(self.failure("HTTP checked finish must run outside a Tokio runtime"));
        }
        self.close_http();
        if self.lifetime.counts() != (0, 0) {
            return Err(self.failure("Original HTTP activity still retained"));
        }
        let Some(owner) = self.owner.take() else {
            return Err(self.failure("Original HTTP shutdown already attempted"));
        };
        match owner.shutdown_blocking() {
            Ok(()) => Ok(HttpFinished {
                worker_checked: true,
            }),
            Err(error) => Err(self.failure(format!("Original HTTP worker unconfirmed: {error}"))),
        }
    }
}
impl Drop for RepositoryHttp {
    fn drop(&mut self) {
        self.lifetime.close();
        self.stop.cancel();
        // Drop is neither a worker join nor an HTTP completion receipt.
    }
}
fn refusal(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(Full::new(Bytes::new()).boxed());
    *response.status_mut() = status;
    response
}
