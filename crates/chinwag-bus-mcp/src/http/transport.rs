//! Retain the original SDK transport close job across owner cancellation.

use super::*;
use rmcp::{
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{
        Transport, WorkerTransport,
        streamable_http_server::session::local::{LocalSessionWorker, LocalSessionWorkerError},
    },
};
use tokio::sync::watch;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    NotCreated,
    AwaitingClose,
    Closing,
    Joined,
    Failed,
}

type CloseResult = Result<(), InboxError>;
struct Job {
    join: tokio::sync::Mutex<Option<JoinHandle<CloseResult>>>,
}

pub(super) struct TransportOwner {
    runtime: tokio::runtime::Handle,
    phase: watch::Sender<Phase>,
    job: Mutex<Option<Arc<Job>>>,
    cancel: Mutex<Option<CancellationToken>>,
}

impl TransportOwner {
    pub fn new(runtime: tokio::runtime::Handle) -> Arc<Self> {
        let (phase, _) = watch::channel(Phase::NotCreated);
        Arc::new(Self {
            runtime,
            phase,
            job: Mutex::new(None),
            cancel: Mutex::new(None),
        })
    }
    pub fn creating(&self) {
        self.phase.send_replace(Phase::AwaitingClose);
    }
    pub fn creation_failed(&self) {
        self.phase.send_replace(Phase::Failed);
    }
    pub fn cancel(&self) {
        if let Ok(token) = self.cancel.lock()
            && let Some(token) = token.as_ref()
        {
            token.cancel();
        }
    }
    pub fn joined(&self) -> bool {
        *self.phase.borrow() == Phase::Joined
    }
    fn start(self: &Arc<Self>, mut inner: WorkerTransport<LocalSessionWorker>) {
        inner.cancel_token().cancel();
        let mut slot = self
            .job
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return;
        }
        self.phase.send_replace(Phase::Closing);
        let owner = self.clone();
        let handle = self.runtime.spawn(async move {
            let result = inner.close().await.map_err(|_| InboxError::Protocol);
            owner.phase.send_replace(if result.is_ok() {
                Phase::Joined
            } else {
                Phase::Failed
            });
            result
        });
        *slot = Some(Arc::new(Job {
            join: tokio::sync::Mutex::new(Some(handle)),
        }));
    }
    pub async fn wait(&self) -> Result<(), InboxError> {
        let mut phase = self.phase.subscribe();
        loop {
            let state = *phase.borrow_and_update();
            if state == Phase::NotCreated {
                return Ok(());
            }
            if matches!(state, Phase::Closing | Phase::Joined | Phase::Failed) {
                let job = self
                    .job
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                if let Some(job) = job {
                    let mut slot = job.join.lock().await;
                    if let Some(handle) = slot.as_mut() {
                        let outcome = handle.await;
                        slot.take();
                        return outcome.map_err(|_| InboxError::Protocol)?;
                    }
                    return if self.joined() {
                        Ok(())
                    } else {
                        Err(InboxError::Protocol)
                    };
                }
                if state == Phase::Failed {
                    return Err(InboxError::Protocol);
                }
            }
            phase.changed().await.map_err(|_| InboxError::Protocol)?;
        }
    }
}

pub(super) struct OwnedSessionTransport {
    inner: Option<WorkerTransport<LocalSessionWorker>>,
    owner: Arc<TransportOwner>,
}

impl OwnedSessionTransport {
    pub fn new(inner: WorkerTransport<LocalSessionWorker>, owner: Arc<TransportOwner>) -> Self {
        *owner
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(inner.cancel_token());
        Self {
            inner: Some(inner),
            owner,
        }
    }
}
impl Transport<RoleServer> for OwnedSessionTransport {
    type Error = LocalSessionWorkerError;
    fn send(
        &mut self,
        message: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let send = self.inner.as_mut().map(|inner| inner.send(message));
        async move {
            match send {
                Some(send) => send.await,
                None => Err(LocalSessionWorkerError::TransportClosed),
            }
        }
    }
    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        match self.inner.as_mut() {
            Some(inner) => inner.receive().await,
            None => None,
        }
    }
    async fn close(&mut self) -> Result<(), Self::Error> {
        if let Some(inner) = self.inner.take() {
            self.owner.start(inner);
        }
        self.owner
            .wait()
            .await
            .map_err(|_| LocalSessionWorkerError::TransportClosed)
    }
}
impl Drop for OwnedSessionTransport {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            self.owner.start(inner);
        }
    }
}
