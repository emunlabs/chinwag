//! Feature-gated synthetic child boundary; the production actor/wire/journal are retained.
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
        _: WorkConfig,
        _: Instant,
        _: Arc<AtomicBool>,
        _: Arc<Mutex<()>>,
    ) -> Pin<Box<dyn Future<Output = Result<ChildIo>> + Send>> {
        let io = self.0.lock().ok().and_then(|mut s| s.take());
        Box::pin(async move { io.ok_or(GeminiError::Unavailable) })
    }
}
pub struct FixturePeer {
    pub io: DuplexStream,
    pub workdir: PathBuf,
    stderr: DuplexStream,
    exit: Option<oneshot::Sender<Option<i32>>>,
}
impl FixturePeer {
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
        .ok_or(GeminiError::InvalidInput)?
        .canonicalize()
        .map_err(|_| GeminiError::InvalidInput)?;
    let config = WorkConfig::new(
        &workdir.join("synthetic-gemini"),
        &"0".repeat(64),
        &workdir,
        journal,
        StartupPolicyDeclaration::ConfiguredRuntimeEffectsManualModeExtensionsDisabled,
    )?;
    let (host, peer) = tokio::io::duplex(65536);
    let (reader, writer) = tokio::io::split(host);
    let (er, ew) = tokio::io::duplex(8192);
    let (exit, wait) = oneshot::channel();
    let io = ChildIo {
        reader: Box::new(reader),
        writer: Box::new(writer),
        stderr: Box::new(er),
        wait: Box::pin(async move { wait.await.map_err(|_| GeminiError::Unavailable) }),
        valid: true,
        verify: Arc::new(|| Ok(())),
    };
    let port = service::open_with(config, Arc::new(FixtureSpawner(Mutex::new(Some(io)))))?;
    Ok((
        port,
        FixturePeer {
            io: peer,
            workdir,
            stderr: ew,
            exit: Some(exit),
        },
    ))
}
pub fn observed_targets() -> Result<(ObservedSession, ObservedActivePrompt)> {
    service::fixture_targets()
}
pub fn observed_session() -> Result<ObservedSession> {
    observed_targets().map(|(session, _)| session)
}
