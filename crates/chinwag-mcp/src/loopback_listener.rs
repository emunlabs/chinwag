//! A serial, bounded HTTP/1 loopback endpoint for the original repository owner.
//! Complete finite SSE bodies are buffered before socket output. Output loss
//! never turns a committed database write into an acknowledged client result.
use crate::repository_http::{AccessSecret, HttpFinished, LoopbackAuthority, RepositoryHttp};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible, error::Error, net::Ipv4Addr, net::SocketAddr, net::TcpListener,
    num::NonZeroU16, path::PathBuf, time::Duration,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[must_use = "Stop this listener and explicitly finish its original repository owner"]
pub struct LoopbackListener {
    socket: Option<TcpListener>,
    address: SocketAddr,
    original: Option<RepositoryHttp>,
}

/// Socket observations; these cannot construct a repository completion receipt.
pub struct ListenerStopped {
    connections: u64,
    transport_failures: u64,
}
impl ListenerStopped {
    pub fn connections(&self) -> u64 {
        self.connections
    }
    pub fn transport_failures(&self) -> u64 {
        self.transport_failures
    }
}

#[must_use = "Failure retains the same original; it does not authorize another listener"]
pub struct ListenerFinishFailure {
    original: Box<LoopbackListener>,
    reason: String,
}
impl ListenerFinishFailure {
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub fn into_original(self) -> LoopbackListener {
        *self.original
    }
}
impl std::fmt::Debug for ListenerFinishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerFinishFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl LoopbackListener {
    /// No bind-address input: the OS chooses a fresh port on IPv4 loopback only.
    /// The secret stays in memory; no environment, URL, log or token file is made.
    pub fn bind_private_repository(
        repo: PathBuf,
        access: AccessSecret,
    ) -> Result<Self, Box<dyn Error>> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err("Loopback startup must run outside a Tokio runtime".into());
        }
        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let port = NonZeroU16::new(address.port()).ok_or("Unassigned loopback port")?;
        let original =
            RepositoryHttp::open_private_repository(repo, access, LoopbackAuthority::new(port))?;
        Ok(Self {
            socket: Some(socket),
            address,
            original: Some(original),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Synchronous orchestration owns the runtime and every connection future.
    /// Cancellation closes the listening socket and drops the exact connection
    /// before waiting for the SDK handlers. There are no detached socket tasks.
    pub fn serve_until(&mut self, stop: CancellationToken) -> Result<ListenerStopped, String> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err("Loopback serving must run outside a Tokio runtime".into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let socket = self
            .socket
            .take()
            .ok_or("Original listener already consumed")?;
        let original = self
            .original
            .as_mut()
            .ok_or("Original repository already consumed")?;
        runtime.block_on(serve(socket, original, stop))
    }
    /// Install the original SIGINT receiver before announcing CLI readiness.
    /// The callback runs once; an output failure still drops this original socket
    /// and leaves the original HTTP owner available for checked finish.
    #[cfg(unix)]
    pub fn serve_until_interrupt_and_ready(
        &mut self,
        ready: impl FnOnce(SocketAddr) -> Result<(), String>,
    ) -> Result<ListenerStopped, String> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err("Loopback serving must run outside a Tokio runtime".into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let address = self.address;
        let socket = self
            .socket
            .take()
            .ok_or("Original listener already consumed")?;
        let original = self
            .original
            .as_mut()
            .ok_or("Original repository already consumed")?;
        runtime.block_on(async {
            // Registration is synchronous here, inside this original runtime.
            // A client that sees readiness can immediately send SIGINT safely.
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .map_err(|e| e.to_string())?;
            ready(address)?;
            let stop = CancellationToken::new();
            let mut serving = Box::pin(serve(socket, original, stop.clone()));
            tokio::select! {
                biased;
                signal = interrupt.recv() => {
                    stop.cancel();
                    let ended = serving.await;
                    if signal.is_none() { return Err("CLI interrupt receiver closed".into()); }
                    ended
                }
                ended = &mut serving => ended,
            }
        })
    }
    /// Explicitly stop an original socket that has never entered serving, then
    /// check its original worker. This handles failed endpoint-output/startup.
    pub fn cancel_before_serve(mut self) -> Result<HttpFinished, ListenerFinishFailure> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(self.failure("Loopback cancellation must run outside a Tokio runtime"));
        }
        if self.socket.is_none() {
            return Err(self.failure("Original listener already entered serving"));
        }
        drop(self.socket.take());
        self.finish()
    }
    fn failure(self, reason: impl ToString) -> ListenerFinishFailure {
        ListenerFinishFailure {
            original: Box::new(self),
            reason: reason.to_string(),
        }
    }
    /// Only after serve returns can this consume the original worker's join and
    /// directory admission. A transport observation alone never closes the owner.
    pub fn finish(mut self) -> Result<HttpFinished, ListenerFinishFailure> {
        if self.socket.is_some() {
            return Err(self.failure("Original listener has not been stopped"));
        }
        let Some(original) = self.original.take() else {
            return Err(self.failure("Original repository already consumed"));
        };
        match original.finish() {
            Ok(receipt) => Ok(receipt),
            Err(failure) => {
                let reason = failure.reason().to_owned();
                self.original = Some(failure.into_original());
                Err(self.failure(reason))
            }
        }
    }
}

async fn serve(
    socket: TcpListener,
    original: &mut RepositoryHttp,
    stop: CancellationToken,
) -> Result<ListenerStopped, String> {
    let listener = tokio::net::TcpListener::from_std(socket).map_err(|e| e.to_string())?;
    let owner = Mutex::new(original);
    let mut result = Ok(ListenerStopped {
        connections: 0,
        transport_failures: 0,
    });
    loop {
        let accepted = tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = match accepted {
            Ok(value) => value,
            Err(error) => {
                result = Err(error.to_string());
                break;
            }
        };
        let counts = result
            .as_mut()
            .expect("only loop exit records accept failure");
        counts.connections = counts.connections.saturating_add(1);
        let service = service_fn(|request| respond(&owner, request));
        let mut builder = http1::Builder::new();
        builder
            .keep_alive(false)
            .max_headers(32)
            .max_buf_size(16 * 1024);
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        let failed = tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            ended = tokio::time::timeout(Duration::from_secs(10), connection) => !matches!(ended, Ok(Ok(()))),
        };
        if failed {
            counts.transport_failures = counts.transport_failures.saturating_add(1);
        }
    }
    drop(listener);
    let original = owner.into_inner();
    original.close_http();
    // Retained activity refuses checked finish if it cannot quiesce in this
    // bounded wait. Counts never stand in for the worker's actual checked join.
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while original.active_observations() != (0, 0) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    result
}

async fn respond(
    owner: &Mutex<&mut RepositoryHttp>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut original = owner.lock().await;
    let mut response = match original.request(request).await {
        Ok(response) => response,
        Err(_) => return Ok(unavailable()),
    };
    let Some(status) = response.status() else {
        return Ok(unavailable());
    };
    let Some(headers) = response.headers().cloned() else {
        return Ok(unavailable());
    };
    let mut body = Vec::new();
    loop {
        match response.frame().await {
            Ok(Some(frame)) => body.extend_from_slice(&frame),
            Ok(None) => break,
            Err(_) => return Ok(unavailable()),
        }
    }
    let mut output = Response::new(Full::new(Bytes::from(body)));
    *output.status_mut() = status;
    *output.headers_mut() = headers;
    Ok(output)
}
fn unavailable() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
    response
}
