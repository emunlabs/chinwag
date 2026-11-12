// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! One local tool read of an already native-delivered, ACU-qualified capture.
//! These pipes are finite and owner scoped; it is not a remote message bridge.
//! Complete client read/pipe write is distinct from a model's internal context.
use crate::{acu, capture_read, runtime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};
use zeroize::Zeroizing;

/// Never leave an uncancellable Tokio blocking-stdio write behind on timeout.
/// Descriptors use cancellable nonblocking writes and restore their flags.
struct NonblockingOutput {
    fd: std::os::fd::OwnedFd,
    original_flags: rustix::fs::OFlags,
    wait: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}
impl NonblockingOutput {
    fn new(fd: std::os::fd::OwnedFd) -> std::io::Result<Self> {
        let flags = rustix::fs::fcntl_getfl(&fd)?;
        rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self {
            fd,
            original_flags: flags,
            wait: None,
        })
    }
    fn stdout() -> std::io::Result<Self> {
        Self::new(rustix::io::dup(std::io::stdout())?)
    }
}
impl Drop for NonblockingOutput {
    fn drop(&mut self) {
        let _ = rustix::fs::fcntl_setfl(&self.fd, self.original_flags);
    }
}
impl AsyncWrite for NonblockingOutput {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Some(wait) = &mut this.wait {
            std::task::ready!(std::future::Future::poll(wait.as_mut(), cx));
            this.wait = None;
        }
        match rustix::io::write(&this.fd, bytes) {
            Ok(n) => std::task::Poll::Ready(Ok(n)),
            Err(rustix::io::Errno::AGAIN) => {
                let wait = this
                    .wait
                    .insert(Box::pin(tokio::time::sleep(Duration::from_millis(1))));
                let _ = std::future::Future::poll(wait.as_mut(), cx);
                std::task::Poll::Pending
            }
            Err(e) => std::task::Poll::Ready(Err(e.into())),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncRead for NonblockingOutput {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(wait) = &mut this.wait {
            std::task::ready!(std::future::Future::poll(wait.as_mut(), cx));
            this.wait = None;
        }
        match rustix::io::read(&this.fd, buffer.initialize_unfilled()) {
            Ok(n) => {
                buffer.advance(n);
                std::task::Poll::Ready(Ok(()))
            }
            Err(rustix::io::Errno::AGAIN) => {
                let wait = this
                    .wait
                    .insert(Box::pin(tokio::time::sleep(Duration::from_millis(1))));
                let _ = std::future::Future::poll(wait.as_mut(), cx);
                std::task::Poll::Pending
            }
            Err(e) => std::task::Poll::Ready(Err(e.into())),
        }
    }
}
struct PipePair {
    input: NonblockingOutput,
    output: NonblockingOutput,
}
impl AsyncRead for PipePair {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().input).poll_read(cx, buffer)
    }
}
impl AsyncWrite for PipePair {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().output).poll_write(cx, b)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().output).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().output).poll_shutdown(cx)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("scoped capture read held; preserve the original wake")]
pub struct ReadError;
fn checked<T, E>(r: Result<T, E>) -> Result<T, ReadError> {
    r.map_err(|_| ReadError)
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
const MAX_CAPTURE: usize = 32 * 1024 * 1024;

/// Constructed only following a verified current grant and full capture check.
pub(crate) struct ReadAuthorization {
    grant_until: u64,
    policy_until: u64,
    policy: [u8; 32],
    epoch: u64,
    signer: [u8; 32],
    revocation_gate: Option<(runtime::Plan, Option<PathBuf>)>,
}
impl ReadAuthorization {
    #[cfg(test)]
    pub(crate) fn qualified(grant_until: u64, p: &acu::CurrentPolicy) -> Self {
        Self {
            grant_until,
            policy_until: p.expires_unix(),
            policy: p.digest(),
            epoch: p.epoch(),
            signer: p.signer(),
            revocation_gate: None,
        }
    }
    pub(crate) fn qualified_for_plan(
        grant_until: u64,
        p: &acu::CurrentPolicy,
        plan: runtime::Plan,
        recipient_revocations: Option<PathBuf>,
    ) -> Self {
        Self {
            grant_until,
            policy_until: p.expires_unix(),
            policy: p.digest(),
            epoch: p.epoch(),
            signer: p.signer(),
            revocation_gate: Some((plan, recipient_revocations)),
        }
    }
    pub(crate) fn until(&self) -> u64 {
        self.grant_until.min(self.policy_until)
    }
    pub(crate) fn verify_current(&self, raw: &[u8], now: u64) -> Result<(), ReadError> {
        let p = checked(acu::verify_current_policy(raw, self.signer, now))?;
        if now >= self.until() || p.digest() != self.policy || p.epoch() != self.epoch {
            return Err(ReadError);
        }
        Ok(())
    }
    pub(crate) fn current_until(
        &self,
        raw: &[u8],
        sample: crate::agent_deadline::Sample,
    ) -> Result<Instant, ReadError> {
        self.verify_current(raw, sample.unix())?;
        if let Some((plan, revocations_path)) = &self.revocation_gate {
            let revocations =
                checked(runtime::load_revocations(revocations_path.as_deref(), plan))?;
            let _ = checked(plan.delivery_with_revocations(&revocations))?;
        }
        checked(sample.until(self.until()))
    }
    pub(crate) async fn current(&self, origin: &str) -> Result<Instant, ReadError> {
        let client = checked(crate::github::normal_https_client())?;
        let raw = checked(
            runtime::request_bytes(
                &client,
                reqwest::Method::GET,
                &format!("{origin}v1/policy"),
                None,
                128 * 1024,
            )
            .await,
        )?;
        let sample = checked(crate::agent_deadline::Sample::now())?;
        self.current_until(&raw, sample)
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadScope {
    pub configuration_sha256: [u8; 32],
    pub session_id: String,
    pub generation: u64,
    pub envelope_sha256: [u8; 32],
    pub object_sha256: [u8; 32],
    pub plaintext_sha256: [u8; 32],
    pub plaintext_bytes: u64,
    pub expires_unix: u64,
}
impl ReadScope {
    pub(crate) fn digest(&self) -> Result<[u8; 32], ReadError> {
        Ok(hash(&checked(serde_json::to_vec(self))?))
    }
}

#[derive(Serialize)]
pub(crate) struct ReadObservation {
    classification: &'static str,
    scope: ReadScope,
    scope_sha256: [u8; 32],
    owner_only_pipe_uid: u32,
    complete_capture_validated: bool,
    complete_stdout_write_acknowledged: bool,
}

/// FIFO descriptors never enter a blocking pool. Their paths grant no authority
/// beyond the original once-only scope and current ACU check held by the owner.
struct PipeName {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl PipeName {
    fn check(&self) -> bool {
        std::fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.dev() == self.dev && m.ino() == self.ino && m.nlink() == 1 && m.file_type().is_fifo()
        })
    }
}
impl Drop for PipeName {
    fn drop(&mut self) {
        if self.check() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
fn open_pipe(path: &Path, flags: rustix::fs::OFlags) -> Result<std::os::fd::OwnedFd, ReadError> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    let fd = checked(fs::open(
        path,
        flags | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ))?;
    let m = checked(fs::fstat(&fd))?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;
        checked(crate::macos_acl::require_absent(fd.as_fd()))?;
    }
    let named = checked(fs::stat(path))?;
    if FileType::from_raw_mode(m.st_mode) != FileType::Fifo
        || m.st_uid != rustix::process::geteuid().as_raw()
        || m.st_mode & 0o7777 != 0o600
        || m.st_nlink != 1
        || m.st_dev != named.st_dev
        || m.st_ino != named.st_ino
    {
        return Err(ReadError);
    }
    Ok(fd)
}
pub(crate) struct ScopedPipes {
    directory: crate::storage::CiphertextStore,
    path: PathBuf,
    names: Vec<PipeName>,
    peer: Option<PipePair>,
}
impl ScopedPipes {
    pub(crate) fn bind(directory: &Path, workspace: &Path) -> Result<Self, ReadError> {
        if checked(directory.canonicalize())? != directory
            || !directory.starts_with(workspace.join("target"))
        {
            return Err(ReadError);
        }
        let directory_handle = checked(crate::storage::CiphertextStore::open(directory))?;
        let mut endpoint = Self {
            directory: directory_handle,
            path: directory.to_owned(),
            names: vec![],
            peer: None,
        };
        let mut fds = vec![];
        for name in [c"capture.fifo", c"read-ack.fifo"] {
            #[cfg(not(target_os = "macos"))]
            checked(rustix::fs::mkfifoat(
                endpoint.directory.directory(),
                name,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            ))?;
            #[cfg(target_os = "macos")]
            checked(crate::macos_acl::create_fifo_at(
                endpoint.directory.directory(),
                name,
            ))?;
            let path = directory.join(checked(name.to_str())?);
            let fd = open_pipe(&path, rustix::fs::OFlags::RDWR)?;
            let m = checked(rustix::fs::fstat(&fd))?;
            endpoint.names.push(PipeName {
                path,
                dev: m.st_dev as u64,
                ino: m.st_ino as u64,
            });
            fds.push(fd);
        }
        let input = checked(NonblockingOutput::new(fds.pop().ok_or(ReadError)?))?;
        let output = checked(NonblockingOutput::new(fds.pop().ok_or(ReadError)?))?;
        endpoint.peer = Some(PipePair { input, output });
        Ok(endpoint)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    fn check(&self) -> Result<(), ReadError> {
        checked(self.directory.check())?;
        if !self.names.iter().all(PipeName::check) {
            return Err(ReadError);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn serve(
        mut self,
        scope: ReadScope,
        bytes: &[u8],
        authorization: &ReadAuthorization,
        origin: &str,
        started: Arc<AtomicBool>,
        until: Instant,
        receipt: &Path,
    ) -> Result<ReadObservation, ReadError> {
        timeout_at(until,async {
            let mut peer=self.peer.take().ok_or(ReadError)?;
            let digest=scope.digest()?;
            let mut request=[0;32];checked(peer.read_exact(&mut request).await)?;
            self.check()?;
            if !started.load(Ordering::Acquire)||request!=digest||hash(bytes)!=scope.plaintext_sha256||bytes.len() as u64!=scope.plaintext_bytes||scope.expires_unix!=authorization.until(){return Err(ReadError)}
            authorization.current(origin).await?;
            checked(capture_read::inspect_complete(bytes))?;
            checked(peer.write_u64(bytes.len() as u64).await)?;checked(peer.write_all(&scope.plaintext_sha256).await)?;checked(peer.write_all(bytes).await)?;checked(peer.flush().await)?;
            let mut ack=[0;32];checked(peer.read_exact(&mut ack).await)?;if ack!=scope.plaintext_sha256{return Err(ReadError)}
            self.check()?;authorization.current(origin).await?;
            let observed=ReadObservation{classification:"SCOPED_HELPER_COMPLETE_READ_AND_STDOUT_WRITE_NOT_MODEL_CONTEXT_OR_REPAIR",scope,scope_sha256:digest,owner_only_pipe_uid:rustix::process::geteuid().as_raw(),complete_capture_validated:true,complete_stdout_write_acknowledged:true};
            checked(runtime::write_new(receipt,&checked(serde_json::to_vec(&observed))?))?;
            checked(peer.write_all(b"FINAL_ACK").await)?;checked(peer.flush().await)?;
            // Drop ALL parent write descriptors now; client requires physical
            // FIFO EOF after the final ACK. The endpoint is never reopened.
            drop(peer);Ok(observed)
        }).await.map_err(|_|ReadError)?
    }
}

async fn read_to_output<S: AsyncRead + AsyncWrite + Unpin, W: AsyncWrite + Unpin>(
    s: &mut S,
    digest: [u8; 32],
    out: &mut W,
) -> Result<(), ReadError> {
    checked(s.write_all(&digest).await)?;
    let n = checked(s.read_u64().await)?;
    if n == 0 || n > MAX_CAPTURE as u64 {
        return Err(ReadError);
    }
    let mut expected = [0; 32];
    checked(s.read_exact(&mut expected).await)?;
    let mut bytes = Zeroizing::new(vec![0; n as usize]);
    checked(s.read_exact(&mut bytes).await)?;
    if hash(&bytes) != expected {
        return Err(ReadError);
    }
    checked(capture_read::inspect_complete(&bytes))?;
    // Full framed data precedes ACK. Physical EOF follows the final durable ACK.
    checked(out.write_all(&bytes).await)?;
    checked(out.flush().await)?;
    checked(s.write_all(&expected).await)?;
    checked(s.flush().await)?;
    let mut ack = [0; 9];
    checked(s.read_exact(&mut ack).await)?;
    if &ack != b"FINAL_ACK" {
        return Err(ReadError);
    }
    let mut tail = [0; 1];
    if checked(s.read(&mut tail).await)? != 0 {
        return Err(ReadError);
    }
    Ok(())
}

/// Fixed owner-issued tool command. No key, grant file, global journal or agent
/// history is read. The active parent independently checks scope and policy.
pub async fn read_capture(directory: &Path, scope: &str) -> Result<(), ReadError> {
    if !crate::intent::canonical_hex(scope, 32) || checked(directory.canonicalize())? != directory {
        return Err(ReadError);
    }
    let _private_directory = checked(crate::storage::CiphertextStore::open(directory))?;
    let digest: [u8; 32] = checked(checked(hex::decode(scope))?.try_into())?;
    timeout_at(Instant::now() + Duration::from_secs(35), async {
        let input = checked(NonblockingOutput::new(open_pipe(
            &directory.join("capture.fifo"),
            rustix::fs::OFlags::RDONLY,
        )?))?;
        let output = checked(NonblockingOutput::new(open_pipe(
            &directory.join("read-ack.fifo"),
            rustix::fs::OFlags::WRONLY,
        )?))?;
        let mut stream = PipePair { input, output };
        let mut out = checked(NonblockingOutput::stdout())?;
        read_to_output(&mut stream, digest, &mut out).await
    })
    .await
    .map_err(|_| ReadError)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn actual_fifo_complete_read_ack_final_ack_and_physical_eof_have_no_retained_writer() {
        let d = tempfile::tempdir().unwrap();
        let workspace = d.path().canonicalize().unwrap();
        let directory = workspace.join("target/r");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut endpoint = ScopedPipes::bind(&directory, &workspace).unwrap();
        let mut parent = endpoint.peer.take().unwrap();
        let mut client = PipePair {
            input: NonblockingOutput::new(
                open_pipe(&directory.join("capture.fifo"), rustix::fs::OFlags::RDONLY).unwrap(),
            )
            .unwrap(),
            output: NonblockingOutput::new(
                open_pipe(&directory.join("read-ack.fifo"), rustix::fs::OFlags::WRONLY).unwrap(),
            )
            .unwrap(),
        };
        let payload = capture_read::reader_fixture(&vec![b'o'; 90000], &vec![b'e'; 90000]);
        let digest = hash(&payload);
        let mut out = Vec::new();
        let server = async {
            let mut request = [0; 32];
            parent.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [7; 32]);
            endpoint.check().unwrap();
            parent.write_u64(payload.len() as u64).await.unwrap();
            parent.write_all(&digest).await.unwrap();
            parent.write_all(&payload).await.unwrap();
            let mut ack = [0; 32];
            parent.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, digest);
            parent.write_all(b"FINAL_ACK").await.unwrap();
            parent.flush().await.unwrap();
            drop(parent);
            drop(endpoint);
        };
        let (r, _) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(read_to_output(&mut client, [7; 32], &mut out), server)
        })
        .await
        .unwrap();
        r.unwrap();
        assert_eq!(out, payload);
        assert!(!directory.join("capture.fifo").exists());
        assert!(!directory.join("read-ack.fifo").exists());
    }
    #[tokio::test]
    async fn a_stalled_tool_output_descriptor_cancels_without_a_blocking_runtime_job() {
        let (writer, _unread_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut output = NonblockingOutput::new(writer.into()).unwrap();
        let started = Instant::now();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                output.write_all(&vec![b'x'; 4 * 1024 * 1024])
            )
            .await
            .is_err()
        );
        drop(output);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    #[tokio::test]
    async fn framed_complete_capture_acknowledges_only_after_full_output_and_final_ack_eof() {
        let payload =
            capture_read::reader_fixture(&vec![b'x'; 60000], b"genuine assertion failed\n");
        let expected = hash(&payload);
        let scope = [3; 32];
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut out = Vec::new();
        let server = async {
            let mut r = [0; 32];
            server.read_exact(&mut r).await.unwrap();
            assert_eq!(r, scope);
            server.write_u64(payload.len() as u64).await.unwrap();
            server.write_all(&expected).await.unwrap();
            for chunk in payload.chunks(137) {
                server.write_all(chunk).await.unwrap();
            }
            let mut ack = [0; 32];
            server.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, expected);
            server.write_all(b"FINAL_ACK").await.unwrap();
            server.shutdown().await.unwrap();
        };
        let (r, _) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(read_to_output(&mut client, scope, &mut out), server)
        })
        .await
        .unwrap();
        r.unwrap();
        assert_eq!(out, payload);
    }
    #[tokio::test]
    async fn truncated_or_altered_frame_and_missing_final_ack_never_qualify() {
        for broken in 0..4 {
            let payload = capture_read::reader_fixture(b"stdout", b"stderr");
            let expected = hash(&payload);
            let (mut c, mut s) = tokio::io::duplex(4096);
            let mut out = Vec::new();
            let server = async {
                let mut q = [0; 32];
                s.read_exact(&mut q).await.unwrap();
                s.write_u64(payload.len() as u64).await.unwrap();
                s.write_all(&if broken == 0 { [9; 32] } else { expected })
                    .await
                    .unwrap();
                s.write_all(if broken == 1 {
                    &payload[..100]
                } else {
                    &payload
                })
                .await
                .unwrap();
                if broken >= 2 {
                    let mut a = [0; 32];
                    s.read_exact(&mut a).await.unwrap();
                    if broken == 3 {
                        s.write_all(b"FINAL_ACKx").await.unwrap();
                    }
                }
                s.shutdown().await.unwrap();
            };
            let (r, _) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(read_to_output(&mut c, [3; 32], &mut out), server)
            })
            .await
            .unwrap();
            assert!(r.is_err());
        }
    }
    #[tokio::test]
    async fn pipes_are_exclusive_private_and_cleanup_preserves_a_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let parent = root.join("target/r");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = ScopedPipes::bind(&parent, &root).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(listener.path().join("capture.fifo"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert!(ScopedPipes::bind(&parent, &root).is_err());
        let path = listener.path().join("capture.fifo");
        let old = parent.join("old.fifo");
        std::fs::rename(&path, &old).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        drop(listener);
        assert_eq!(std::fs::read(path).unwrap(), b"replacement");
    }
}
