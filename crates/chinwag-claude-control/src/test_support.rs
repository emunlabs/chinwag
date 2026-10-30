//! Synthetic fixtures using the production actor, wire observer and private journal.
//! This feature is never needed by the native product constructor.
use crate::{
    service::{self, ChildIo, Spawner},
    *,
};
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Instant,
};
use tokio::{io::DuplexStream, sync::oneshot};
struct FixtureSpawner(Mutex<Option<ChildIo>>);
impl Spawner for FixtureSpawner {
    fn spawn(
        &self,
        _config: WorkConfig,
        _session: String,
        _deadline: Instant,
        _ended: Arc<AtomicBool>,
        _admission: Arc<Mutex<()>>,
    ) -> Pin<Box<dyn Future<Output = Result<ChildIo>> + Send>> {
        let io = self.0.lock().ok().and_then(|mut slot| slot.take());
        Box::pin(async move { io.ok_or(ClaudeError::Unavailable) })
    }
}
pub struct FixturePeer {
    pub io: DuplexStream,
    pub workdir: PathBuf,
    stderr: DuplexStream,
    exit: Option<oneshot::Sender<Option<i32>>>,
}
impl FixturePeer {
    /// Reports fake child wait completion and then drops both synthetic output pipes.
    pub fn finish(mut self, exit_code: i32) {
        if let Some(exit) = self.exit.take() {
            let _ = exit.send(Some(exit_code));
        }
        drop(self.stderr);
        drop(self.io);
    }
}
pub fn open_fixture_service(journal: &Path) -> Result<(Arc<dyn HumanWorkPort>, FixturePeer)> {
    let workdir = journal
        .parent()
        .ok_or(ClaudeError::InvalidInput)?
        .canonicalize()
        .map_err(|_| ClaudeError::InvalidInput)?;
    let config = WorkConfig::new(
        &workdir.join("synthetic-claude"),
        &"0".repeat(64),
        &workdir,
        journal,
        StartupPolicyDeclaration::ManagedPolicyProseOnly,
    )?;
    let (host, peer) = tokio::io::duplex(65536);
    let (reader, writer) = tokio::io::split(host);
    let (stderr_read, stderr) = tokio::io::duplex(8192);
    let (exit, wait) = oneshot::channel();
    let child = ChildIo {
        reader: Box::new(reader),
        writer: Box::new(writer),
        stderr: Box::new(stderr_read),
        wait: Box::pin(async move { wait.await.map_err(|_| ClaudeError::Unavailable) }),
        valid: true,
        verify: Arc::new(|| Ok(())),
    };
    let port = service::open_with(config, Arc::new(FixtureSpawner(Mutex::new(Some(child)))))?;
    Ok((
        port,
        FixturePeer {
            io: peer,
            workdir,
            stderr,
            exit: Some(exit),
        },
    ))
}
/// Mints an opaque target by feeding strict synthetic initialization messages
/// through the production observer. It cannot select a native child/session.
pub fn observed_session() -> Result<ObservedSession> {
    service::observed_fixture_session()
}
