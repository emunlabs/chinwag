//! Durability-before-effect bridge. The IO peer and all grants are supplied by
//! the trusted protocol owner; no frontend or bus message can create them.

use crate::{
    CodexSteerConnection, ConnectionOwner, Evidence, HumanSteerGrant, ObservedActiveTurn,
    OwnerControlScope, Receipt, Result, SteerError,
    connection::CommittedSteerAttempt,
    journal::{Consume, SteerJournal},
    record::{valid_operation_id, valid_text},
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
};

#[derive(Clone)]
pub struct SteerController {
    inner: Arc<Inner>,
}

struct Inner {
    connection: CodexSteerConnection,
    journal: Arc<Mutex<SteerJournal>>,
    evidence_worker: tokio::sync::Mutex<Option<JoinHandle<Result<()>>>>,
    #[cfg(test)]
    before_dispatch: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

#[cfg(test)]
mod tests;

impl Drop for Inner {
    fn drop(&mut self) {
        self.connection.request_close();
    }
}

impl SteerController {
    /// Accepts an exclusively owner-delegated, already initialized stream.
    /// The owner must arrange delivery of the real turn/started notification
    /// for its permitted thread. This never discovers/resumes/starts a thread.
    pub async fn from_established_io<R, W>(
        scope: OwnerControlScope,
        journal_path: &Path,
        reader: R,
        writer: W,
    ) -> Result<(Self, ConnectionOwner)>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        tokio::runtime::Handle::try_current().map_err(|_| SteerError::Unavailable)?;
        let path = journal_path.to_owned();
        // A failed journal opens no transport and performs no protocol write.
        let journal = tokio::task::spawn_blocking(move || SteerJournal::open(&path))
            .await
            .map_err(|_| SteerError::Storage)??;
        let journal = Arc::new(Mutex::new(journal));
        let (connection, owner) = CodexSteerConnection::from_established_io(scope, reader, writer)?;
        let mut events = connection.take_events().ok_or(SteerError::Unavailable)?;
        let store = journal.clone();
        let evidence_worker = tokio::spawn(async move {
            let mut failed = false;
            while let Some(event) = events.recv().await {
                let store = store.clone();
                // Blocking persistence cannot stop the independent wire reader.
                // Transport event capacity is fixed; overflow fences dispatch.
                let result = tokio::task::spawn_blocking(move || {
                    let mut store = store.lock().map_err(|_| SteerError::Storage)?;
                    if store.apply(&event.id, event.evidence).is_err() {
                        let _ = store.mark_persistence_failure(&event.id);
                        return Err(SteerError::Storage);
                    }
                    Ok(())
                })
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    failed = true;
                }
            }
            if failed {
                Err(SteerError::Storage)
            } else {
                Ok(())
            }
        });
        Ok((
            Self {
                inner: Arc::new(Inner {
                    connection,
                    journal,
                    evidence_worker: tokio::sync::Mutex::new(Some(evidence_worker)),
                    #[cfg(test)]
                    before_dispatch: None,
                }),
            },
            owner,
        ))
    }

    pub fn active_turn(&self) -> Option<ObservedActiveTurn> {
        self.inner.connection.active_turn()
    }

    /// The embedding's trusted human-action handler supplies the separate grant
    /// and opaque captured target. No read grant or caller thread string enters.
    pub async fn submit_human_text(
        &self,
        grant: &HumanSteerGrant,
        target: &ObservedActiveTurn,
        operation_id: &str,
        text: &str,
    ) -> Result<Receipt> {
        if !valid_operation_id(operation_id) || !valid_text(text) {
            return Err(SteerError::InvalidInput);
        }
        if let Some(receipt) = self.receipt(operation_id).await? {
            if receipt.operation.text == text
                && self.inner.connection.owns_target(target)
                && target.matches_record(&receipt.operation)
            {
                return Ok(receipt);
            }
            return Err(SteerError::Conflict);
        }
        let prepared = self
            .inner
            .connection
            .prepare(grant, target, operation_id, text)?;
        let record = prepared.record().clone();
        let store = self.inner.journal.clone();
        let consumed = tokio::task::spawn_blocking(move || {
            store
                .lock()
                .map_err(|_| SteerError::Storage)?
                .consume(record)
        })
        .await
        .map_err(|_| SteerError::Storage)??;
        match consumed {
            Consume::Existing(receipt) => Ok(receipt),
            Consume::Created(receipt) => {
                let id = receipt.operation.id;
                #[cfg(test)]
                if let Some((reached, resume)) = &self.inner.before_dispatch {
                    reached.notify_one();
                    resume.notified().await;
                }
                // This non-public capsule can only be created after durable
                // consumption. Cancellation before here cannot dispatch later.
                let committed = CommittedSteerAttempt::new(prepared);
                let evidence = self.inner.connection.dispatch_committed(committed).await;
                self.save_evidence(&id, evidence).await
            }
        }
    }

    /// Original operation lookup. It never writes, queues or replays a steer.
    pub async fn receipt(&self, operation_id: &str) -> Result<Option<Receipt>> {
        if !valid_operation_id(operation_id) {
            return Err(SteerError::InvalidInput);
        }
        let store = self.inner.journal.clone();
        let id = operation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            store.lock().map_err(|_| SteerError::Storage)?.lookup(&id)
        })
        .await
        .map_err(|_| SteerError::Storage)?
    }

    async fn save_evidence(&self, operation_id: &str, evidence: Evidence) -> Result<Receipt> {
        let store = self.inner.journal.clone();
        let id = operation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut store = store.lock().map_err(|_| SteerError::Storage)?;
            match store.apply(&id, evidence) {
                Ok(receipt) => Ok(receipt),
                Err(_) => store.mark_persistence_failure(&id),
            }
        })
        .await
        .map_err(|_| SteerError::Storage)?
    }

    /// Joins this owner's reader/writer and drains retained evidence work. This
    /// sends no interrupt/shutdown/approval RPC and makes no model-stop claim.
    pub async fn shutdown(&self) -> Result<()> {
        let transport_result = self.inner.connection.shutdown().await;
        let mut worker = self.inner.evidence_worker.lock().await;
        if let Some(handle) = worker.as_mut() {
            let result = handle.await;
            worker.take();
            result.map_err(|_| SteerError::Unavailable)??;
        }
        transport_result
    }
}
