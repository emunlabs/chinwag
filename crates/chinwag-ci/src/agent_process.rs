// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Finite direct ownership of a fixed Codex CLI child. This is a host adapter,
//! not a grant to invoke another seat. Enrollment and wake admission live above
//! it. Input stays off argv; reasoning/output is drained, not persisted or logged.
use crate::agent_events::{AgentTurnObservation, CodexEvents, session_uuid};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    fs::File,
    future::Future,
    io::Read,
    os::unix::{fs::MetadataExt, process::ExitStatusExt},
    path::PathBuf,
    process::{ExitStatus, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::{Instant, sleep_until},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_LINE: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingAgentRoute {
    pub executable: PathBuf,
    pub executable_sha256: [u8; 32],
    pub workspace: PathBuf,
    pub turn_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("owned coding-agent route refused before launch")]
pub struct AgentRouteError;

#[derive(Clone, Serialize)]
pub struct AgentProcessObservation {
    pub classification: &'static str,
    pub original_child_pid: Option<u32>,
    pub started_unix_ms: Option<u64>,
    pub input_sha256: [u8; 32],
    pub input_bytes: u64,
    pub stdin_complete: bool,
    pub streams_eof: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub os_exit_observed: bool,
    pub deadline_exceeded: bool,
    pub forced: bool,
    pub stop_requested: bool,
    pub forced_kill_failed: bool,
    pub reap_unconfirmed: bool,
    pub turn: Option<AgentTurnObservation>,
}
impl AgentProcessObservation {
    pub fn clean(&self) -> bool {
        self.os_exit_observed
            && self.exit_code == Some(0)
            && self.signal.is_none()
            && self.stdin_complete
            && self.streams_eof
            && !self.deadline_exceeded
            && !self.forced
            && !self.stop_requested
            && !self.forced_kill_failed
            && !self.reap_unconfirmed
            && self.turn.is_some()
    }
}
/// Custody of an ORIGINAL whose terminal wait is unconfirmed. This is not a
/// closed process or permission to retry/signal a numeric PID. Keep it with the
/// held operation for operator reconciliation. Drop must not issue an implicit
/// kill after a failed wait/start_kill (PID ownership may be uncertain).
pub struct OriginalChildCustody {
    child: Option<tokio::process::Child>,
}
impl Drop for OriginalChildCustody {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            std::mem::forget(child);
        }
    }
}

pub struct AgentRun {
    pub observation: AgentProcessObservation,
    /// Initial build request only. Never serialize an agent's free text.
    pub(crate) last_message: Zeroizing<Vec<u8>>,
    pub original_custody: Option<OriginalChildCustody>,
}
impl AgentRun {
    pub fn initial_build_request(&self) -> &[u8] {
        &self.last_message
    }
}

impl CodingAgentRoute {
    pub fn verify(&self) -> Result<(), AgentRouteError> {
        if self.executable_sha256 == [0; 32]
            || !(15..=1800).contains(&self.turn_seconds)
            || !self.executable.is_absolute()
            || !self.workspace.is_absolute()
            || self
                .executable
                .canonicalize()
                .map_err(|_| AgentRouteError)?
                != self.executable
            || self.workspace.canonicalize().map_err(|_| AgentRouteError)? != self.workspace
            || self.executable.file_name().is_none_or(|n| n != "codex")
        {
            return Err(AgentRouteError);
        }
        let mut f = File::open(&self.executable).map_err(|_| AgentRouteError)?;
        let before = f.metadata().map_err(|_| AgentRouteError)?;
        if !before.is_file()
            || before.nlink() != 1
            || before.mode() & 0o022 != 0
            || before.mode() & 0o111 == 0
            || before.len() > 512 * 1024 * 1024
            || (before.uid() != 0 && before.uid() != rustix::process::geteuid().as_raw())
        {
            return Err(AgentRouteError);
        }
        let mut h = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let n = f.read(&mut buffer).map_err(|_| AgentRouteError)?;
            if n == 0 {
                break;
            }
            h.update(&buffer[..n]);
        }
        let after = f.metadata().map_err(|_| AgentRouteError)?;
        let named = std::fs::symlink_metadata(&self.executable).map_err(|_| AgentRouteError)?;
        if <[u8; 32]>::from(h.finalize()) != self.executable_sha256
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || named.dev() != after.dev()
            || named.ino() != after.ino()
            || named.len() != after.len()
        {
            return Err(AgentRouteError);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct ThreadStart<'a> {
    r#type: &'a str,
    thread_id: Option<&'a str>,
}
#[derive(Deserialize)]
struct MessageEvent<'a> {
    r#type: &'a str,
    #[serde(borrow)]
    item: Option<Message<'a>>,
}
#[derive(Deserialize)]
struct Message<'a> {
    r#type: &'a str,
    #[serde(borrow)]
    text: Option<Cow<'a, str>>,
}
struct Output {
    turn: Option<AgentTurnObservation>,
    message: Zeroizing<Vec<u8>>,
    bytes: u64,
    eof: bool,
}

async fn read_events<R: AsyncRead + Unpin>(
    mut reader: R,
    expected: Option<String>,
    workspace: Option<PathBuf>,
) -> Output {
    let initial = expected.is_none();
    let mut parser = expected.as_deref().and_then(|id| CodexEvents::new(id).ok());
    if let (Some(parser), Some(workspace)) = (&mut parser, &workspace) {
        parser.allow_workspace_fixture(workspace);
    }
    let mut invalid = false;
    let mut count = 0u64;
    let mut eof = false;
    let mut message = Zeroizing::new(Vec::new());
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    let mut buffer = Zeroizing::new([0u8; 16384]);
    loop {
        let n = match reader.read(&mut buffer[..]).await {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => n,
            Err(_) => {
                invalid = true;
                break;
            }
        };
        count = count.saturating_add(n as u64);
        for &b in &buffer[..n] {
            if invalid {
                continue;
            }
            if b == b'\n' {
                if !line.iter().all(u8::is_ascii_whitespace) {
                    if parser.is_none() && initial {
                        parser = serde_json::from_slice::<ThreadStart<'_>>(&line)
                            .ok()
                            .filter(|e| e.r#type == "thread.started")
                            .and_then(|e| e.thread_id)
                            .and_then(|id| CodexEvents::new(id).ok());
                    }
                    if let Some(p) = parser.as_mut() {
                        if let Some(workspace) = &workspace {
                            p.allow_workspace_fixture(workspace);
                        }
                        if p.push(&line).is_err() || p.push(b"\n").is_err() {
                            invalid = true;
                        }
                    } else {
                        invalid = true;
                    }
                    if initial
                        && !invalid
                        && let Ok(e) = serde_json::from_slice::<MessageEvent<'_>>(&line)
                        && e.r#type == "item.completed"
                        && let Some(item) = e.item.filter(|i| i.r#type == "agent_message")
                        && let Some(text) = item.text
                    {
                        message.as_mut_slice().zeroize();
                        message.clear();
                        message.extend_from_slice(text.as_bytes());
                    }
                }
                line.as_mut_slice().zeroize();
                line.clear();
            } else if line.len() < MAX_LINE {
                line.push(b);
            } else {
                invalid = true;
                line.as_mut_slice().zeroize();
                line.clear();
            }
        }
        buffer[..n].zeroize();
    }
    // JSONL requires a completed final record. No truncated tail is promoted.
    if !line.iter().all(u8::is_ascii_whitespace) {
        invalid = true;
    }
    let turn = if invalid {
        None
    } else {
        parser.and_then(|p| p.finish().ok())
    };
    Output {
        turn,
        message,
        bytes: count,
        eof,
    }
}
async fn drain<R: AsyncRead + Unpin>(mut reader: R) -> (u64, bool) {
    let mut b = Zeroizing::new([0u8; 8192]);
    let mut count = 0u64;
    loop {
        match reader.read(&mut b[..]).await {
            Ok(0) => return (count, true),
            Ok(n) => {
                count = count.saturating_add(n as u64);
                b[..n].zeroize();
            }
            Err(_) => return (count, false),
        }
    }
}
fn signal_owned(pid: u32) {
    if let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::INT);
    }
}

struct CancelOnDrop(Option<tokio::sync::oneshot::Sender<()>>);
impl CancelOnDrop {
    fn request(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.request();
    }
}

async fn owned<F, S, C>(
    mut command: Command,
    expected: Option<String>,
    prompt: Zeroizing<Vec<u8>>,
    bounds: [Instant; 2],
    on_spawn: F,
    stop: S,
    completed: C,
) -> AgentRun
where
    F: FnOnce(u32) -> Result<(), ()>,
    S: Future<Output = ()>,
    C: FnOnce(&AgentProcessObservation) + Send + 'static,
{
    let [work, close] = bounds;
    let mut observation = AgentProcessObservation {
        classification: "OWNED_AGENT_PROCESS_OBSERVATION_NOT_VERIFIED_REPAIR",
        original_child_pid: None,
        started_unix_ms: None,
        input_sha256: Sha256::digest(&prompt).into(),
        input_bytes: prompt.len() as u64,
        stdin_complete: false,
        streams_eof: false,
        stdout_bytes: 0,
        stderr_bytes: 0,
        exit_code: None,
        signal: None,
        os_exit_observed: false,
        deadline_exceeded: false,
        forced: false,
        stop_requested: false,
        forced_kill_failed: false,
        reap_unconfirmed: false,
        turn: None,
    };
    tokio::pin!(stop);
    if Instant::now() >= work {
        observation.deadline_exceeded = true;
        return AgentRun {
            observation,
            last_message: Zeroizing::new(Vec::new()),
            original_custody: None,
        };
    }
    tokio::select! {
        biased;
        _ = &mut stop => {
            observation.stop_requested = true;
            return AgentRun { observation, last_message: Zeroizing::new(Vec::new()), original_custody:None };
        },
        _ = std::future::ready(()) => {},
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let workspace = command.as_std().get_current_dir().map(PathBuf::from);
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(_) => {
            return AgentRun {
                observation,
                last_message: Zeroizing::new(Vec::new()),
                original_custody: None,
            };
        }
    };
    let pid = child.id().unwrap_or(0);
    observation.original_child_pid = Some(pid);
    observation.started_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|t| u64::try_from(t.as_millis()).ok());
    let mut deliver = true;
    if pid == 0 || on_spawn(pid).is_err() {
        let _ = child.start_kill();
        observation.forced = true;
        deliver = false;
    }
    let mut close_at = close;
    tokio::select! {
        biased;
        _ = &mut stop => {
            observation.stop_requested = true;
            deliver = false;
            close_at = close_at.min(Instant::now() + Duration::from_secs(10));
            signal_owned(pid);
        },
        _ = std::future::ready(()) => {},
    }
    if Instant::now() >= work {
        observation.deadline_exceeded = true;
        deliver = false;
        signal_owned(pid);
    }
    let fallback = observation.clone();
    let already_stopped = observation.stop_requested;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut cancellation = CancelOnDrop(Some(tx));
    // This task retains the ORIGINAL child, streams and deadline if its caller
    // stops awaiting. Dropping the awaiter requests stop; it never drops the
    // supervisor. Runtime destruction is still UNKNOWN, not clean closure.
    let mut monitor = tokio::spawn(async move {
        let result = supervise(
            child,
            (expected, workspace),
            prompt,
            observation,
            [work, close_at],
            deliver,
            rx,
        )
        .await;
        completed(&result.observation);
        result
    });
    let result = if already_stopped {
        monitor.await
    } else {
        tokio::select! {
            r=&mut monitor=>r,
            _=&mut stop=>{cancellation.request();monitor.await},
        }
    };
    cancellation.0 = None;
    result.unwrap_or_else(|_| AgentRun {
        observation: AgentProcessObservation {
            classification: "OWNED_AGENT_SUPERVISOR_LOST_UNKNOWN_NO_RETRY",
            os_exit_observed: false,
            turn: None,
            ..fallback
        },
        last_message: Zeroizing::new(Vec::new()),
        original_custody: None,
    })
}

struct Retirement<T> {
    kill_failed: bool,
    status: Option<T>,
}
async fn bounded_retirement<T>(
    kill: std::io::Result<()>,
    wait: impl Future<Output = std::io::Result<T>>,
    close_at: Instant,
) -> Retirement<T> {
    let status = if Instant::now() >= close_at {
        None
    } else {
        match tokio::time::timeout_at(close_at, wait).await {
            Ok(Ok(status)) if Instant::now() < close_at => Some(status),
            _ => None,
        }
    };
    Retirement {
        kill_failed: kill.is_err(),
        status,
    }
}
fn retirement_start(grace_start: Instant, close_at: Instant) -> Instant {
    let reserved =
        (close_at.saturating_duration_since(grace_start) / 2).min(Duration::from_secs(1));
    close_at - reserved
}

async fn supervise(
    mut child: tokio::process::Child,
    scope: (Option<String>, Option<PathBuf>),
    prompt: Zeroizing<Vec<u8>>,
    mut observation: AgentProcessObservation,
    bounds: [Instant; 2],
    deliver: bool,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> AgentRun {
    let (expected, workspace) = scope;
    let [work, mut close_at] = bounds;
    let pid = observation.original_child_pid.unwrap_or(0);
    let mut force_at = retirement_start(work, close_at);
    let mut kill_attempted = false;
    let mut stdin = child.stdin.take().expect("owned piped stdin");
    let stdout = child.stdout.take().expect("owned piped stdout");
    let stderr = child.stderr.take().expect("owned piped stderr");
    let io = async {
        tokio::join!(
            async {
                let r = if deliver && Instant::now() < work {
                    tokio::select! {biased;
                        _=sleep_until(work)=>false,
                        r=stdin.write_all(&prompt)=>r.is_ok()&&Instant::now()<work,
                    }
                } else {
                    false
                };
                drop(stdin);
                r
            },
            read_events(stdout, expected, workspace),
            drain(stderr)
        )
    };
    tokio::pin!(io);
    let mut io_result = None;
    let mut status: Option<ExitStatus> = None;
    loop {
        if status.is_some() && io_result.is_some() {
            break;
        }
        tokio::select! {
            s=child.wait(),if status.is_none()=>{ match s {
                Ok(s)=>status=Some(s),
                Err(_)=>{
                    // A failed wait does not establish an unreaped PID. Do not
                    // send another signal or let kill_on_drop target a reused
                    // numeric PID. Preserve UNKNOWN for original reconciliation.
                    observation.reap_unconfirmed=true;
                    observation.classification="ORIGINAL_AGENT_WAIT_UNCONFIRMED_HELD_NO_RETRY";
                    return AgentRun {observation,last_message:Zeroizing::new(Vec::new()),original_custody:Some(OriginalChildCustody{child:Some(child)})};
                }
            } },
            r=&mut io,if io_result.is_none()=>io_result=Some(r),
            _=sleep_until(work),if !observation.deadline_exceeded=>{
                observation.deadline_exceeded=true;
                if status.is_none() {signal_owned(pid);}
            },
            _=&mut stop,if !observation.stop_requested=>{
                observation.stop_requested=true;
                close_at=close_at.min(Instant::now()+Duration::from_secs(10));
                force_at=force_at.min(retirement_start(Instant::now(),close_at));
                if status.is_none() {signal_owned(pid);}
            },
            _=sleep_until(force_at),if status.is_none()&&!kill_attempted=>{
                kill_attempted=true;observation.forced=true;
                let retired=bounded_retirement(child.start_kill(),child.wait(),close_at).await;
                observation.forced_kill_failed=retired.kill_failed;
                status=retired.status;
                if status.is_none(){observation.reap_unconfirmed=true;break;}
            },
            _=sleep_until(close_at)=>{
                observation.deadline_exceeded=true;
                if status.is_none(){
                    if !kill_attempted{observation.forced=true;observation.forced_kill_failed=child.start_kill().is_err();}
                    observation.reap_unconfirmed=true;
                }
                break;
            },
        }
    }
    observation.deadline_exceeded |= Instant::now() >= work;
    if let Some(s) = status {
        observation.os_exit_observed = true;
        observation.exit_code = s.code();
        observation.signal = s.signal();
    }
    if let Some((input, out, (err_bytes, err_eof))) = io_result {
        observation.stdin_complete = input;
        observation.streams_eof = out.eof && err_eof;
        observation.stdout_bytes = out.bytes;
        observation.stderr_bytes = err_bytes;
        observation.turn = out.turn;
        return AgentRun {
            observation,
            last_message: out.message,
            original_custody: if status.is_none() {
                Some(OriginalChildCustody { child: Some(child) })
            } else {
                None
            },
        };
    }
    AgentRun {
        observation,
        last_message: Zeroizing::new(Vec::new()),
        original_custody: if status.is_none() {
            Some(OriginalChildCustody { child: Some(child) })
        } else {
            None
        },
    }
}

/// Only the exact UUID may be resumed. Caller must already hold its owner wake
/// reservation; an actual spawned child is recorded before any prompt is sent.
pub async fn run<F: FnOnce(u32) -> Result<(), ()>, S: Future<Output = ()>>(
    route: &CodingAgentRoute,
    session: Option<&str>,
    prompt: Zeroizing<Vec<u8>>,
    original_work_deadline: Instant,
    on_spawn: F,
    stop: S,
) -> Result<AgentRun, AgentRouteError> {
    route.verify()?;
    if session.is_some_and(|s| !session_uuid(s))
        || prompt.is_empty()
        || prompt.len() > 16 * 1024 * 1024
    {
        return Err(AgentRouteError);
    }
    let mut command = Command::new(&route.executable);
    command.current_dir(&route.workspace).env_clear();
    for name in ["HOME", "PATH", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(v) = std::env::var_os(name) {
            command.env(name, v);
        }
    }
    command.args([
        "exec",
        "--model",
        "gpt-6.1-sol",
        "--sandbox",
        "workspace-write",
        "-c",
        "approval_policy=\"never\"",
    ]);
    if let Some(id) = session {
        command.args(["resume", "--json", "--ignore-user-config", id, "-"]);
    } else {
        command.args(["--json", "--ignore-user-config", "-"]);
    }
    let work = original_work_deadline.min(Instant::now() + Duration::from_secs(route.turn_seconds));
    if work <= Instant::now() {
        return Err(AgentRouteError);
    }
    Ok(owned(
        command,
        session.map(str::to_owned),
        prompt,
        [work, work + Duration::from_secs(10)],
        on_spawn,
        stop,
        |_| {},
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn failed_termination_and_unresolved_reap_return_by_original_close_with_custody() {
        // Inject failure/pending wait to exercise the production bound; this is
        // not a claim that an actual OS child was made unkillable.
        let mut command = Command::new("/bin/sleep");
        command.arg("30").kill_on_drop(true);
        let child = command.spawn().unwrap();
        let pid = child.id().unwrap();
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let close = Instant::now() + Duration::from_millis(25);
        let r = bounded_retirement::<ExitStatus>(
            Err(std::io::ErrorKind::PermissionDenied.into()),
            std::future::pending(),
            close,
        )
        .await;
        assert!(r.kill_failed && r.status.is_none());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(Instant::now() < close + Duration::from_millis(500));
        let mut custody = OriginalChildCustody { child: Some(child) };
        assert_eq!(custody.child.as_ref().unwrap().id(), Some(pid));
        // Separate test cleanup of the retained ORIGINAL, not a replacement or
        // an observation falsely attributed to the injected pending wait.
        let mut original = custody.child.take().unwrap();
        original.start_kill().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), original.wait())
                .await
                .unwrap()
                .is_ok()
        );
    }
    #[tokio::test]
    async fn wait_error_and_late_or_past_deadline_zero_cannot_qualify_a_reap() {
        let bound = Instant::now() + Duration::from_millis(20);
        let error = bounded_retirement::<u8>(
            Ok(()),
            async { Err(std::io::ErrorKind::Interrupted.into()) },
            bound,
        )
        .await;
        assert!(error.status.is_none());
        let late = bounded_retirement(
            Ok(()),
            async {
                tokio::time::sleep_until(bound + Duration::from_millis(20)).await;
                Ok(0u8)
            },
            bound,
        )
        .await;
        assert!(late.status.is_none());
        let past = bounded_retirement(Ok(()), std::future::ready(Ok(0u8)), Instant::now()).await;
        assert!(past.status.is_none());
        let ready = bounded_retirement(
            Ok(()),
            std::future::ready(Ok(0u8)),
            Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert_eq!(ready.status, Some(0));
    }
    const ID: &str = "0199a213-81c0-7800-8aa1-bbab2a035a53";
    #[tokio::test]
    async fn actual_owned_child_receives_complete_stdin_and_closes_before_clean_observation() {
        let wire = format!(
            "{{\"type\":\"thread.started\",\"thread_id\":\"{ID}\"}}\n{{\"type\":\"turn.started\"}}\n{{\"type\":\"turn.completed\",\"usage\":{{\"input_tokens\":1,\"output_tokens\":1}}}}\n"
        );
        // This is an explicit process fixture, never a live agent proof.
        let work = Instant::now() + Duration::from_secs(2);
        let r = owned(
            Command::new("/bin/cat"),
            Some(ID.into()),
            Zeroizing::new(wire.into_bytes()),
            [work, work + Duration::from_secs(1)],
            |pid| {
                assert!(pid > 0);
                Ok(())
            },
            std::future::pending(),
            |_| {},
        )
        .await;
        assert!(r.observation.clean());
        assert_eq!(r.observation.turn.unwrap().input_tokens, Some(1));
    }
    #[tokio::test]
    async fn failed_start_record_sends_no_input_and_observes_owned_child_retirement() {
        let work = Instant::now() + Duration::from_secs(1);
        let r = owned(
            Command::new("/bin/cat"),
            Some(ID.into()),
            Zeroizing::new(b"never-send".to_vec()),
            [work, work + Duration::from_secs(1)],
            |_| Err(()),
            std::future::pending(),
            |_| {},
        )
        .await;
        assert!(!r.observation.clean());
        assert!(!r.observation.stdin_complete);
        assert!(r.observation.forced);
        assert!(r.observation.os_exit_observed);
    }
    #[tokio::test]
    async fn deadline_is_held_even_when_exact_owned_child_is_reaped() {
        let mut c = Command::new("/bin/sleep");
        c.arg("30");
        let work = Instant::now() + Duration::from_millis(30);
        let r = owned(
            c,
            Some(ID.into()),
            Zeroizing::new(b"unused".to_vec()),
            [work, work + Duration::from_millis(100)],
            |_| Ok(()),
            std::future::pending(),
            |_| {},
        )
        .await;
        assert!(!r.observation.clean());
        assert!(r.observation.deadline_exceeded);
        assert!(r.observation.os_exit_observed);
    }

    #[tokio::test]
    async fn owner_stop_closes_the_same_child_without_becoming_success_or_extending_deadline() {
        let mut c = Command::new("/bin/sleep");
        c.arg("30");
        let work = Instant::now() + Duration::from_secs(2);
        let stop = tokio::time::sleep(Duration::from_millis(20));
        let r = owned(
            c,
            Some(ID.into()),
            Zeroizing::new(b"unused".to_vec()),
            [work, work + Duration::from_secs(1)],
            |_| Ok(()),
            stop,
            |_| {},
        )
        .await;
        assert!(r.observation.stop_requested);
        assert!(r.observation.os_exit_observed);
        assert!(!r.observation.clean());
        assert!(!r.observation.forced);
    }

    #[tokio::test]
    async fn refused_event_record_still_drains_full_owned_child_instead_of_killing_its_turn() {
        let mut bytes = vec![b'x'; MAX_LINE + 1];
        bytes.push(b'\n');
        let work = Instant::now() + Duration::from_secs(2);
        let r = owned(
            Command::new("/bin/cat"),
            Some(ID.into()),
            Zeroizing::new(bytes),
            [work, work + Duration::from_secs(1)],
            |_| Ok(()),
            std::future::pending(),
            |_| {},
        )
        .await;
        assert!(r.observation.os_exit_observed);
        assert_eq!(r.observation.exit_code, Some(0));
        assert!(r.observation.stdin_complete);
        assert!(r.observation.streams_eof);
        assert!(r.observation.stdout_bytes > MAX_LINE as u64);
        assert!(!r.observation.forced);
        assert!(!r.observation.deadline_exceeded);
        assert!(!r.observation.clean());
    }

    #[tokio::test]
    async fn cancelled_or_expired_before_launch_has_no_child_or_start_effect() {
        for cancelled in [true, false] {
            let start_count = std::sync::atomic::AtomicUsize::new(0);
            let work = if cancelled {
                Instant::now() + Duration::from_secs(1)
            } else {
                Instant::now() - Duration::from_millis(1)
            };
            let r = owned(
                Command::new("/bin/cat"),
                Some(ID.into()),
                Zeroizing::new(b"never-send".to_vec()),
                [work, work + Duration::from_secs(1)],
                |_| {
                    start_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
                std::future::ready(()),
                |_| {},
            )
            .await;
            assert_eq!(start_count.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(r.observation.original_child_pid.is_none());
            assert!(!r.observation.stdin_complete);
            assert!(!r.observation.clean());
        }
    }

    #[tokio::test]
    async fn expiry_during_start_record_sends_no_prompt_and_late_zero_never_becomes_clean() {
        let work = Instant::now() + Duration::from_millis(10);
        let r = owned(
            Command::new("/bin/cat"),
            Some(ID.into()),
            Zeroizing::new(b"never-send".to_vec()),
            [work, work + Duration::from_millis(200)],
            |_| {
                std::thread::sleep(Duration::from_millis(25));
                Ok(())
            },
            std::future::pending(),
            |_| {},
        )
        .await;
        assert!(r.observation.deadline_exceeded);
        assert!(!r.observation.stdin_complete);
        assert!(!r.observation.clean());
        assert!(r.observation.os_exit_observed);
    }

    #[tokio::test]
    async fn cancelling_the_awaiter_keeps_original_supervision_through_actual_child_reap() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let mut c = Command::new("/bin/sleep");
        c.arg("30");
        let work = Instant::now() + Duration::from_secs(2);
        let awaiter = tokio::spawn(owned(
            c,
            Some(ID.into()),
            Zeroizing::new(b"unused".to_vec()),
            [work, work + Duration::from_secs(1)],
            move |pid| {
                let _ = started_tx.send(pid);
                Ok(())
            },
            std::future::pending(),
            move |o| {
                let _ = closed_tx.send(o.clone());
            },
        ));
        let original_pid = started_rx.await.unwrap();
        awaiter.abort();
        let cancelled = match awaiter.await {
            Err(e) => e.is_cancelled(),
            Ok(_) => false,
        };
        assert!(cancelled);
        let closed = tokio::time::timeout(Duration::from_secs(1), closed_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(closed.original_child_pid, Some(original_pid));
        assert!(closed.stop_requested);
        assert!(closed.os_exit_observed);
        assert!(!closed.clean());
    }

    #[tokio::test]
    async fn new_session_build_request_decodes_escaped_json_without_loading_session_history() {
        let mut wire = format!(
            "{{\"type\":\"thread.started\",\"thread_id\":\"{ID}\"}}\n{{\"type\":\"turn.started\"}}\n"
        );
        wire.push_str(&serde_json::json!({"type":"item.completed","item":{"id":"reply","type":"agent_message","text":"{\"request_build\":true}"}}).to_string());
        wire.push_str("\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":10}}\n");
        let r = read_events(wire.as_bytes(), None, None).await;
        assert!(r.eof);
        assert_eq!(r.turn.unwrap().session_id, ID);
        assert_eq!(&*r.message, b"{\"request_build\":true}");
    }
}
