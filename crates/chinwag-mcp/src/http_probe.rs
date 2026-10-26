//! Test-only pause belongs to one request on one original service.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    BeforeEnqueue,
    BeforeCommit,
    DuringPrepare,
}
pub(crate) struct Probe {
    phase: Phase,
    prepare_checks: AtomicUsize,
    reached: Mutex<Option<oneshot::Sender<()>>>,
    resume: Mutex<Option<oneshot::Receiver<()>>>,
}
pub(crate) struct Control {
    pub(crate) reached: oneshot::Receiver<()>,
    pub(crate) resume: oneshot::Sender<()>,
}
impl Probe {
    pub(crate) fn new(phase: Phase) -> (Arc<Self>, Control) {
        let (reached_tx, reached) = oneshot::channel();
        let (resume, resume_rx) = oneshot::channel();
        (
            Arc::new(Self {
                phase,
                prepare_checks: AtomicUsize::new(0),
                reached: Mutex::new(Some(reached_tx)),
                resume: Mutex::new(Some(resume_rx)),
            }),
            Control { reached, resume },
        )
    }
    fn take(&self, phase: Phase) -> Option<oneshot::Receiver<()>> {
        if self.phase != phase {
            return None;
        }
        let receiver = self.resume.lock().expect("owned probe mutex").take()?;
        let reached = self.reached.lock().expect("owned probe mutex").take();
        reached
            .expect("one reached observation")
            .send(())
            .expect("original probe observer");
        Some(receiver)
    }
    pub(crate) async fn before_enqueue(&self) {
        if let Some(receiver) = self.take(Phase::BeforeEnqueue) {
            receiver.await.expect("original enqueue probe release");
        }
    }
    // The first cancellation callback is before BEGIN; the second follows the
    // in-memory SQL operation and precedes COMMIT in run_transaction.
    pub(crate) fn during_prepare_cancel_check(&self) {
        if self.phase == Phase::DuringPrepare
            && self.prepare_checks.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(receiver) = self.take(Phase::DuringPrepare)
        {
            receiver
                .blocking_recv()
                .expect("original prepare callback release");
        }
    }
    pub(crate) fn prepare_checks(&self) -> usize {
        self.prepare_checks.load(Ordering::SeqCst)
    }
    pub(crate) fn before_commit(&self) {
        if let Some(receiver) = self.take(Phase::BeforeCommit) {
            receiver
                .blocking_recv()
                .expect("original commit probe release");
        }
    }
}
