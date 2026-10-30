//! One consumed SDK session slot for one owner capability; no restoration.

use super::*;
use futures::Stream;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::streamable_http_server::session::{
        ServerSseMessage, SessionId, SessionManager, local::LocalSessionManager,
    },
};
use transport::OwnedSessionTransport;

#[derive(Debug)]
pub(super) struct SessionError;
impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("owner HTTP MCP session unavailable")
    }
}
impl std::error::Error for SessionError {}

pub(super) struct SingleSessionManager {
    inner: LocalSessionManager,
    claimed: AtomicBool,
    id: Mutex<Option<SessionId>>,
    control: Arc<Control>,
}
impl SingleSessionManager {
    pub fn new(control: Arc<Control>) -> Self {
        let mut inner = LocalSessionManager::default();
        inner.session_config.channel_capacity = 1;
        inner.session_config.init_timeout = Some(Duration::from_secs(2));
        inner.session_config.keep_alive = Some(Duration::from_secs(60));
        inner.session_config.sse_retry = None;
        inner.session_config.completed_cache_ttl = Duration::ZERO;
        Self {
            inner,
            claimed: AtomicBool::new(false),
            id: Mutex::new(None),
            control,
        }
    }
    fn owns(&self, id: &SessionId) -> bool {
        self.owns_id(id)
    }
    pub(super) fn owns_id(&self, id: &str) -> bool {
        self.id
            .lock()
            .is_ok_and(|current| current.as_deref() == Some(id))
    }
    fn live(&self, id: &SessionId) -> Result<(), SessionError> {
        if self.control.live() && self.owns(id) {
            Ok(())
        } else {
            Err(SessionError)
        }
    }
}
struct CreationGuard {
    control: Arc<Control>,
    completed: bool,
}
impl Drop for CreationGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.control.transport.creation_failed();
            self.control.retire();
        }
    }
}
impl SessionManager for SingleSessionManager {
    type Error = SessionError;
    type Transport = OwnedSessionTransport;
    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        {
            let _gate = self.control.gate.lock().map_err(|_| SessionError)?;
            // SDK parsing and factory creation occur after the HTTP fence.
            // Recheck the canonical writer immediately before reserving the
            // one session slot; no host lock crosses the following await.
            self.control
                .owner
                .current_binding()
                .map_err(|_| SessionError)?;
            if !self.control.live()
                || self
                    .claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                return Err(SessionError);
            }
            self.control.started.store(true, Ordering::Release);
            self.control.transport.creating();
        }
        let mut guard = CreationGuard {
            control: self.control.clone(),
            completed: false,
        };
        let (id, inner) = self
            .inner
            .create_session()
            .await
            .map_err(|_| SessionError)?;
        *self.id.lock().map_err(|_| SessionError)? = Some(id.clone());
        let transport = OwnedSessionTransport::new(inner, self.control.transport.clone());
        guard.completed = true;
        if !self.control.live() {
            self.control.transport.cancel();
        }
        Ok((id, transport))
    }
    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.live(id)?;
        self.inner
            .initialize_session(id, message)
            .await
            .map_err(|_| SessionError)
    }
    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        if !self.control.live() || !self.owns(id) {
            return Ok(false);
        }
        self.inner.has_session(id).await.map_err(|_| SessionError)
    }
    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        if !self.owns(id) {
            return Err(SessionError);
        }
        self.control.retire();
        self.inner
            .close_session(id)
            .await
            .map_err(|_| SessionError)?;
        self.control.shutdown().await.map_err(|_| SessionError)
    }
    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.live(id)?;
        self.inner
            .create_stream(id, message)
            .await
            .map_err(|_| SessionError)
    }
    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.live(id)?;
        self.inner
            .accept_message(id, message)
            .await
            .map_err(|_| SessionError)
    }
    async fn create_standalone_stream(
        &self,
        _id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Err::<futures::stream::Empty<ServerSseMessage>, _>(SessionError)
    }
    async fn resume(
        &self,
        _id: &SessionId,
        _last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Err::<futures::stream::Empty<ServerSseMessage>, _>(SessionError)
    }
}
