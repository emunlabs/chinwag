//! One cold export job and its observers, with an explicit existing-peer handoff.
//! The peer constructor uses the shared live claim session; it opens no room or
//! new claim. The operator must drain this owner before claim shutdown and
//! runtime drop. Dropping an observer never aborts the worker; dropping the
//! owner detaches a running Tokio task. No automatic retry or MCP registration.

pub mod mcp;
pub(crate) mod peer;

use crate::bundle_export::{BundleExporter, ExportOperatorConfig, PreparedBundle};
use std::{future::Future, pin::Pin, sync::Mutex, time::Duration};
use tokio::{runtime::Handle, sync::watch, task::JoinHandle};

/// What the local worker reported, never independent delivery or review proof.
///
/// ```compile_fail
/// use chinwag_seed::send_owner::LocalNote;
/// use chinwag_swarm::review::VerifiedReview;
/// let review: VerifiedReview = LocalNote::PublishedLocal;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNote {
    PublishedLocal,
    FailedLocal,
}

/// The operator callback reports only local publication or an unresolved
/// handoff. It cannot report FailedLocal after prepare has succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackOutcome {
    PublishedLocal,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("send owner scope or runtime is unavailable")]
    Unavailable,
    #[error("local send outcome is unknown; do not restart or replay")]
    Unknown,
}

// This budget begins after prepare. It is a cooperative async deadline, not
// preemption of blocking Rust code or a bound on the whole Git export.
const CALLBACK_DEADLINE: Duration = Duration::from_secs(30);
type Outcome = Result<LocalNote, Error>;
type Job = Pin<Box<dyn Future<Output = Outcome> + Send + 'static>>;

enum State {
    Ready(Job),
    Running {
        observer: watch::Receiver<Option<Outcome>>,
        task: JoinHandle<()>,
    },
    Lost,
}

/// A single service instance, retained independently of MCP request futures.
/// The model must never choose `config` or supply the callback.
///
/// ```compile_fail
/// use chinwag_seed::send_owner::SendOwner;
/// fn duplicate(owner: SendOwner) { let second = owner.clone(); }
/// ```
pub struct SendOwner {
    state: Mutex<State>,
}

impl SendOwner {
    /// Validate one fixed, empty operator scope without starting a job.
    /// An occupied/invalid scope refuses here; there is no cached-byte recovery.
    /// The callback is consumed once, only after successful `prepare`, and must
    /// retain any temporary blob tag until its operation finishes. The callback
    /// gets a fixed cooperative 30-second budget after prepare. Expiry drops
    /// that future and caches Unknown; it never proves a peer-side failure or
    /// permits retry. Blocking code and detached tasks are not preempted.
    /// Explicit callback Unknown is cached immediately, without waiting for
    /// the deadline. A local publication report is never peer, Cargo, or model acceptance.
    pub fn open<F, T>(config: ExportOperatorConfig, send: F) -> Result<Self, Error>
    where
        F: FnOnce(PreparedBundle) -> T + Send + 'static,
        T: Future<Output = CallbackOutcome> + Send + 'static,
    {
        let exporter = BundleExporter::open(config).map_err(|_| Error::Unavailable)?;
        Ok(Self::from_outcome(async move {
            match exporter.prepare().await {
                Ok(bundle) => {
                    match tokio::time::timeout(CALLBACK_DEADLINE, async move { send(bundle).await })
                        .await
                    {
                        Ok(CallbackOutcome::PublishedLocal) => Ok(LocalNote::PublishedLocal),
                        Ok(CallbackOutcome::Unknown) | Err(_) => Err(Error::Unknown),
                    }
                }
                Err(_) => Ok(LocalNote::FailedLocal),
            }
        }))
    }

    #[cfg(test)]
    pub(crate) fn from_job(job: impl Future<Output = LocalNote> + Send + 'static) -> Self {
        Self::from_outcome(async move { Ok(job.await) })
    }

    fn from_outcome(job: impl Future<Output = Outcome> + Send + 'static) -> Self {
        Self {
            state: Mutex::new(State::Ready(Box::pin(job))),
        }
    }

    /// The first observer starts the one owned job before it can await prepare.
    /// Subsequent observers attach to that same job or its cached local note.
    /// There is no await between taking the job, spawning it, and recording it.
    pub fn attach(&self) -> Result<Waiter, Error> {
        let mut state = self.state.lock().map_err(|_| Error::Unknown)?;
        match &*state {
            State::Running { observer, .. } => {
                return Ok(Waiter {
                    observer: observer.clone(),
                });
            }
            State::Lost => return Err(Error::Unknown),
            State::Ready(_) => {}
        }
        let runtime = Handle::try_current().map_err(|_| Error::Unavailable)?;
        let State::Ready(job) = std::mem::replace(&mut *state, State::Lost) else {
            return Err(Error::Unknown);
        };
        let (result, observer) = watch::channel(None);
        let task = runtime.spawn(async move {
            let outcome = job.await;
            result.send_replace(Some(outcome));
        });
        *state = State::Running {
            observer: observer.clone(),
            task,
        };
        Ok(Waiter { observer })
    }

    /// Normal service shutdown waits for the existing worker; it never starts
    /// a pending job. The callback has its fixed cooperative budget; prepare
    /// retains its existing per-command bounds, not one whole-job deadline.
    pub async fn finish(self) -> Result<Option<LocalNote>, Error> {
        match self.state.into_inner().map_err(|_| Error::Unknown)? {
            State::Ready(_) => Ok(None),
            State::Lost => Err(Error::Unknown),
            State::Running { observer, task } => {
                task.await.map_err(|_| Error::Unknown)?;
                let outcome = (*observer.borrow()).ok_or(Error::Unknown)?;
                outcome.map(Some)
            }
        }
    }
}

/// An observation handle. It owns no exporter, task handle, or temporary tag.
pub struct Waiter {
    observer: watch::Receiver<Option<Outcome>>,
}

impl Waiter {
    pub async fn wait(mut self) -> Result<LocalNote, Error> {
        loop {
            if let Some(outcome) = *self.observer.borrow_and_update() {
                return outcome;
            }
            if self.observer.changed().await.is_err() {
                return (*self.observer.borrow()).unwrap_or(Err(Error::Unknown));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::GitCandidate;
    use ssh_key::{PrivateKey, private::Ed25519Keypair};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::sync::oneshot;

    struct TagGuard(Arc<AtomicUsize>);
    impl Drop for TagGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn concurrent_attaches_start_one_job_and_cache_the_same_note() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (started, observed) = oneshot::channel();
        let (release, gate) = oneshot::channel();
        let owner = Arc::new(SendOwner::from_job(async move {
            count.fetch_add(1, Ordering::SeqCst);
            started.send(()).unwrap();
            gate.await.unwrap();
            LocalNote::PublishedLocal
        }));
        let runtime = Handle::current();
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let owner = owner.clone();
                let runtime = runtime.clone();
                std::thread::spawn(move || {
                    let _entered = runtime.enter();
                    owner.attach().unwrap()
                })
            })
            .collect();
        let mut observers = threads.into_iter().map(|t| t.join().unwrap());
        let first = observers.next().unwrap();
        let second = observers.next().unwrap();
        observed.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert_eq!(first.wait().await.unwrap(), LocalNote::PublishedLocal);
        assert_eq!(second.wait().await.unwrap(), LocalNote::PublishedLocal);
        assert_eq!(
            owner.attach().unwrap().wait().await.unwrap(),
            LocalNote::PublishedLocal
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let owner = Arc::try_unwrap(owner).ok().unwrap();
        assert_eq!(
            owner.finish().await.unwrap(),
            Some(LocalNote::PublishedLocal)
        );
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_drop_the_worker_resource_or_start_another_job() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let drops = Arc::new(AtomicUsize::new(0));
        let resource = drops.clone();
        let (started, observed) = oneshot::channel();
        let (release, gate) = oneshot::channel();
        let owner = SendOwner::from_job(async move {
            count.fetch_add(1, Ordering::SeqCst);
            let _tag = TagGuard(resource);
            started.send(()).unwrap();
            gate.await.unwrap();
            LocalNote::PublishedLocal
        });
        let waiter = owner.attach().unwrap();
        let waiting = tokio::spawn(waiter.wait());
        observed.await.unwrap();
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let next = owner.attach().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert_eq!(next.wait().await.unwrap(), LocalNote::PublishedLocal);
        owner.finish().await.unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_returned_local_failure_is_cached_without_reexecution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let owner = SendOwner::from_job(async move {
            count.fetch_add(1, Ordering::SeqCst);
            LocalNote::FailedLocal
        });
        for _ in 0..2 {
            assert_eq!(
                owner.attach().unwrap().wait().await.unwrap(),
                LocalNote::FailedLocal
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.finish().await.unwrap(), Some(LocalNote::FailedLocal));
    }

    #[tokio::test]
    async fn a_panicked_worker_is_unknown_and_never_restarted() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let owner = SendOwner::from_job(async move {
            let prior = count.fetch_add(1, Ordering::SeqCst);
            if prior == 0 {
                panic!("intentional send-owner test fault");
            }
            LocalNote::FailedLocal
        });
        assert_eq!(owner.attach().unwrap().wait().await, Err(Error::Unknown));
        assert_eq!(owner.attach().unwrap().wait().await, Err(Error::Unknown));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(owner.finish().await, Err(Error::Unknown));
    }

    #[tokio::test]
    async fn shutdown_before_any_attach_does_not_start_a_job() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let owner = SendOwner::from_job(async move {
            count.fetch_add(1, Ordering::SeqCst);
            LocalNote::FailedLocal
        });
        assert_eq!(owner.finish().await.unwrap(), None);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn occupied_export_scope_refuses_reopening_without_a_worker_or_recovery_read() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        for n in [
            "source",
            "source/.git",
            "source/.git/objects",
            "export",
            "staging",
            "templates",
        ] {
            let path = root.join(n);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let synthetic = PrivateKey::from(Ed25519Keypair::from_seed(&[0x51; 32]));
        let builder = synthetic.public_key().key_data().ed25519().unwrap().0;
        let signers = root.join("signers");
        fs::write(
            &signers,
            format!("fixture {}\n", synthetic.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        fs::set_permissions(&signers, fs::Permissions::from_mode(0o600)).unwrap();
        let config = || ExportOperatorConfig {
            source: root.join("source"),
            export: root.join("export"),
            staging: root.join("staging"),
            empty_templates: root.join("templates"),
            builder_signers: signers.clone(),
            candidate: GitCandidate::new(&"1".repeat(40), &"2".repeat(40), builder).unwrap(),
        };
        let publishes = Arc::new(AtomicUsize::new(0));
        let callback = || {
            let publishes = publishes.clone();
            move |_: PreparedBundle| async move {
                publishes.fetch_add(1, Ordering::SeqCst);
                CallbackOutcome::PublishedLocal
            }
        };
        // This fixture only exercises open/preflight, never prepare or Git.
        let cold = SendOwner::open(config(), callback()).unwrap();
        assert_eq!(cold.finish().await.unwrap(), None);
        assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
        assert!(fs::read_dir(root.join("export")).unwrap().next().is_none());
        let marker = root.join("staging/synthetic-prior-attempt");
        fs::write(&marker, b"preserve unknown outcome").unwrap();
        assert!(matches!(
            SendOwner::open(config(), callback()),
            Err(Error::Unavailable)
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"preserve unknown outcome");
        assert_eq!(fs::read_dir(root.join("staging")).unwrap().count(), 1);
        assert!(fs::read_dir(root.join("export")).unwrap().next().is_none());
        assert_eq!(publishes.load(Ordering::SeqCst), 0);
    }
}
