use super::*;
use crate::binary::{self, BinaryPin};
use std::{future::Future, pin::Pin, process::Stdio};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
pub(crate) type ReadIo = Box<dyn AsyncRead + Send + Unpin>;
pub(crate) type WriteIo = Box<dyn AsyncWrite + Send + Unpin>;
type Wait = Pin<Box<dyn Future<Output = Result<Option<i32>>> + Send>>;
pub(crate) struct ChildIo {
    pub(crate) reader: ReadIo,
    pub(crate) writer: WriteIo,
    pub(crate) stderr: ReadIo,
    pub(crate) wait: Wait,
    pub(crate) valid: bool,
    pub(crate) verify: Arc<dyn Fn() -> Result<()> + Send + Sync>,
}
pub(crate) trait Spawner: Send + Sync {
    fn spawn(
        &self,
        config: WorkConfig,
        deadline: Instant,
        ended: Arc<AtomicBool>,
        admission: Arc<Mutex<()>>,
    ) -> Pin<Box<dyn Future<Output = Result<ChildIo>> + Send>>;
}
pub(crate) struct NativeSpawner;
pub(super) fn argv() -> Vec<String> {
    [
        "--acp",
        "--approval-mode",
        "default",
        "--extensions",
        "none",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
impl Spawner for NativeSpawner {
    fn spawn(
        &self,
        config: WorkConfig,
        deadline: Instant,
        ended: Arc<AtomicBool>,
        admission: Arc<Mutex<()>>,
    ) -> Pin<Box<dyn Future<Output = Result<ChildIo>> + Send>> {
        Box::pin(async move {
            let pin_config = config.clone();
            let (pin, directory) = tokio::task::spawn_blocking(move || {
                let p = BinaryPin::open(&pin_config)?;
                let d = binary::work_directory(&pin_config.workdir)?;
                p.verify()?;
                binary::verify_directory(&pin_config.workdir, &d)?;
                Ok::<_, GeminiError>((Arc::new(p), Arc::new(d)))
            })
            .await
            .map_err(|_| GeminiError::Unavailable)??;
            // Fixed shell-free argv. Inherited process environment is not inspected,
            // logged, rewritten or interpreted by Chinwag.
            let mut child = {
                let _linearize = admission.lock().map_err(|_| GeminiError::Unavailable)?;
                if ended.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err(GeminiError::PermissionDenied);
                }
                tokio::process::Command::new(&config.binary)
                    .args(argv())
                    .current_dir(&config.workdir)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(false)
                    .spawn()
                    .map_err(|_| GeminiError::Unavailable)?
            };
            let writer = child.stdin.take().ok_or(GeminiError::Unavailable)?;
            let reader = child.stdout.take().ok_or(GeminiError::Unavailable)?;
            let stderr = child.stderr.take().ok_or(GeminiError::Unavailable)?;
            let verify: Arc<dyn Fn() -> Result<()> + Send + Sync> = Arc::new(move || {
                pin.verify()?;
                binary::verify_directory(&config.workdir, &directory)
            });
            let checking = verify.clone();
            let valid = tokio::task::spawn_blocking(move || checking())
                .await
                .is_ok_and(|r| r.is_ok());
            let wait: Wait = Box::pin(async move {
                child
                    .wait()
                    .await
                    .map(|s| s.code())
                    .map_err(|_| GeminiError::Unavailable)
            });
            Ok(ChildIo {
                reader: Box::new(reader),
                writer: Box::new(writer),
                stderr: Box::new(stderr),
                wait,
                valid,
                verify,
            })
        })
    }
}
#[derive(PartialEq, Eq)]
pub(super) enum PermissionWrite {
    Written,
    NoDispatch,
    Uncertain,
}
enum WriteResult {
    Written,
    NoDispatch,
    Uncertain,
}
async fn write_frame(
    shared: &Arc<Shared>,
    frame: Vec<u8>,
    deadline: Instant,
    admit: impl FnOnce(&mut State) -> Result<()>,
) -> WriteResult {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let permit = tokio::time::timeout(
        remaining.min(Duration::from_secs(2)),
        shared.write_gate.clone().acquire_owned(),
    )
    .await;
    let Ok(Ok(_permit)) = permit else {
        return WriteResult::NoDispatch;
    };
    let mut ended = shared.end.subscribe();
    let attempted = AtomicBool::new(false);
    let write = async {
        let mut writer = shared.writer.lock().await;
        let writer = writer.as_mut().ok_or(GeminiError::Unavailable)?;
        #[cfg(test)]
        {
            let pause = shared.before_write.lock().ok().and_then(|p| p.clone());
            if let Some((entered, resume)) = pause {
                entered.notify_one();
                resume.notified().await;
            }
        }
        {
            let _effect = shared
                .admission
                .lock()
                .map_err(|_| GeminiError::Unavailable)?;
            let mut s = shared.state.lock().map_err(|_| GeminiError::Unavailable)?;
            shared.control(&s, deadline)?;
            admit(&mut s)?;
            attempted.store(true, Ordering::Release);
        }
        writer
            .write_all(&frame)
            .await
            .map_err(|_| GeminiError::Uncertain)?;
        writer.flush().await.map_err(|_| GeminiError::Uncertain)
    };
    let result = tokio::select! {biased;_=ended.changed()=>Err(GeminiError::Unavailable),r=tokio::time::timeout(deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(2)),write)=>r.unwrap_or(Err(GeminiError::Uncertain))};
    match result {
        Ok(()) => WriteResult::Written,
        Err(_) if !attempted.load(Ordering::Acquire) => WriteResult::NoDispatch,
        Err(_) => {
            shared.fence();
            WriteResult::Uncertain
        }
    }
}
fn evidence(result: WriteResult) -> Evidence {
    match result {
        WriteResult::Written => Evidence {
            frame_written: true,
            ..Default::default()
        },
        WriteResult::NoDispatch => Evidence {
            not_dispatched: true,
            ..Default::default()
        },
        WriteResult::Uncertain => Evidence {
            write_uncertain: true,
            ..Default::default()
        },
    }
}
pub(super) async fn write_bootstrap(
    shared: &Arc<Shared>,
    frame: Vec<u8>,
    deadline: Instant,
) -> Result<()> {
    match write_frame(shared, frame, deadline, |s| {
        if !s
            .records
            .values()
            .any(|p| p.saved.kind == ActionKind::Start && p.ticket.permits(&p.saved.id))
        {
            return Err(GeminiError::PermissionDenied);
        }
        Ok(())
    })
    .await
    {
        WriteResult::Written => Ok(()),
        WriteResult::NoDispatch => Err(GeminiError::Unavailable),
        WriteResult::Uncertain => Err(GeminiError::Uncertain),
    }
}
pub(super) async fn write_prompt(
    shared: &Arc<Shared>,
    saved: &SavedOperation,
    deadline: Instant,
) -> Evidence {
    let sid = shared.state.lock().ok().and_then(|s| s.session.clone());
    let Some(sid) = sid else {
        return Evidence {
            not_dispatched: true,
            ..Default::default()
        };
    };
    let frame = match wire::prompt(saved, &sid) {
        Ok(f) => f,
        Err(_) => {
            return Evidence {
                not_dispatched: true,
                ..Default::default()
            };
        }
    };
    let result = write_frame(shared, frame, deadline, |s| {
        if !s
            .records
            .get(&saved.id)
            .is_some_and(|p| p.ticket.permits(&saved.id))
            || !s.initialized
            || s.session.as_ref() != Some(&sid)
            || s.epoch != saved.session_epoch
            || s.active.is_some()
            || s.cancel.is_some()
            || s.policy_blocked
            || !s.permissions.is_empty()
        {
            return Err(GeminiError::StaleTarget);
        }
        s.records
            .get_mut(&saved.id)
            .ok_or(GeminiError::Unavailable)?
            .may_written = true;
        s.active = Some(Active {
            operation_id: saved.id.clone(),
            rpc_id: saved.prompt_rpc_id.clone(),
            generation: saved.prompt_generation,
            may_written: true,
        });
        s.snapshot.agent_text = None;
        Ok(())
    })
    .await;
    let e = evidence(result);
    shared.emit(&saved.id, e.clone());
    shared.publish();
    e
}
pub(super) async fn write_cancel(
    shared: &Arc<Shared>,
    saved: &SavedOperation,
    deadline: Instant,
) -> Evidence {
    let Some(sid) = saved.session_id.as_deref() else {
        return Evidence {
            not_dispatched: true,
            ..Default::default()
        };
    };
    let frame = match wire::cancel(sid) {
        Ok(f) => f,
        Err(_) => {
            return Evidence {
                not_dispatched: true,
                ..Default::default()
            };
        }
    };
    let result = write_frame(shared, frame, deadline, |s| {
        if !s
            .records
            .get(&saved.id)
            .is_some_and(|p| p.ticket.permits(&saved.id))
            || s.epoch != saved.session_epoch
            || s.session.as_deref() != Some(sid)
            || !s.active.as_ref().is_some_and(|a| {
                a.rpc_id == saved.prompt_rpc_id && a.generation == saved.prompt_generation
            })
            || !s
                .cancel
                .as_ref()
                .is_some_and(|c| c.saved == *saved && c.committed && !c.writer_retired)
        {
            return Err(GeminiError::StaleTarget);
        }
        s.records
            .get_mut(&saved.id)
            .ok_or(GeminiError::Unavailable)?
            .may_written = true;
        Ok(())
    })
    .await;
    let e = evidence(result);
    shared.emit(&saved.id, e.clone());
    e
}
pub(super) async fn write_permission_cancel(
    shared: &Arc<Shared>,
    saved: &SavedOperation,
    request: &RpcId,
    deadline: Instant,
) -> PermissionWrite {
    let frame = match wire::permission_cancel(request) {
        Ok(f) => f,
        Err(_) => return PermissionWrite::NoDispatch,
    };
    let result = write_frame(shared, frame, deadline, |s| {
        let valid = s
            .cancel
            .as_ref()
            .is_some_and(|c| c.saved == *saved && c.committed)
            && s.permissions.get(request).is_some_and(|p| {
                p.rpc_id == saved.prompt_rpc_id && p.generation == saved.prompt_generation
            })
            && s.active.as_ref().is_some_and(|a| {
                a.rpc_id == saved.prompt_rpc_id && a.generation == saved.prompt_generation
            });
        if !valid {
            return Err(GeminiError::StaleTarget);
        }
        Ok(())
    })
    .await;
    match result {
        WriteResult::Written => PermissionWrite::Written,
        WriteResult::NoDispatch => PermissionWrite::NoDispatch,
        WriteResult::Uncertain => PermissionWrite::Uncertain,
    }
}
pub(super) async fn install(shared: Arc<Shared>, io: ChildIo) {
    *shared.writer.lock().await = Some(io.writer);
    let closing = shared.clone();
    let mut end = shared.end.subscribe();
    tokio::spawn(async move {
        if !closing.ended.load(Ordering::Acquire) {
            let _ = end.changed().await;
        }
        let writer = closing.writer.lock().await.take();
        let confirmed = if let Some(mut writer) = writer {
            let closed = tokio::time::timeout(Duration::from_secs(2), writer.shutdown()).await;
            drop(writer);
            matches!(closed, Ok(Ok(())))
        } else {
            true
        };
        if let Ok(mut s) = closing.state.lock() {
            s.snapshot.lifecycle.stdin_ended = confirmed;
            if !confirmed {
                s.hard_fenced = true;
            }
        }
        if confirmed {
            closing.publish();
        } else {
            closing.fence();
        }
    });
    let reading = shared.clone();
    let reader = tokio::spawn(async move { read_loop(reading, io.reader).await });
    let joining = shared.clone();
    tokio::spawn(async move {
        let _ = reader.await;
        if let Ok(mut s) = joining.state.lock() {
            s.snapshot.lifecycle.reader_joined = true;
        }
        joining.publish();
    });
    let draining = shared.clone();
    let stderr = tokio::spawn(async move {
        let mut stream = io.stderr;
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    if let Ok(mut s) = draining.state.lock() {
                        s.snapshot.lifecycle.stderr_eof = true;
                    }
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        draining.publish();
    });
    let joining = shared.clone();
    tokio::spawn(async move {
        let _ = stderr.await;
        if let Ok(mut s) = joining.state.lock() {
            s.snapshot.lifecycle.stderr_joined = true;
        }
        joining.publish();
    });
    let waiting = shared.clone();
    let child = tokio::spawn(async move {
        let result = io.wait.await;
        if let Ok(mut s) = waiting.state.lock() {
            if let Ok(code) = result {
                s.snapshot.lifecycle.child_exited = true;
                s.snapshot.lifecycle.exit_code = code;
            }
            s.hard_fenced = true;
        }
        waiting.fence();
    });
    tokio::spawn(async move {
        let joined = child.await.is_ok();
        if let Ok(mut s) = shared.state.lock() {
            s.snapshot.lifecycle.child_wait_joined = joined;
        }
        shared.publish();
    });
}
async fn read_loop(shared: Arc<Shared>, reader: ReadIo) {
    let mut reader = BufReader::new(reader);
    loop {
        let mut bytes = Vec::new();
        let read = (&mut reader)
            .take((wire::MAX_FRAME + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .await;
        match read {
            Ok(0) => {
                if let Ok(mut s) = shared.state.lock() {
                    s.snapshot.lifecycle.stdout_eof = true;
                    s.hard_fenced = true;
                }
                shared.fence();
                break;
            }
            Ok(_) if bytes.len() <= wire::MAX_FRAME && bytes.ends_with(b"\n") => {
                match wire::parse(&bytes) {
                    Ok(event) => observe(&shared, event),
                    Err(_) => shared.fence(),
                }
            }
            _ => {
                shared.fence();
                break;
            }
        }
    }
}
