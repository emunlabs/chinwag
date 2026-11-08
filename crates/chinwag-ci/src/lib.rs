// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_code)]

//! CI evidence capture. A captured process result is data, not workload identity,
//! execution authority, delivery, a K2 attestation, or permission to remediate.
//! Raw output stays in memory and must be encrypted before durable delivery.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{
    io,
    process::Stdio,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};
use zeroize::Zeroizing;

#[cfg(unix)]
pub mod acu;
#[cfg(unix)]
pub mod admission;
#[cfg(unix)]
mod agent_deadline;
pub mod agent_events;
#[cfg(unix)]
pub mod agent_process;
#[cfg(unix)]
pub mod authorization;
#[cfg(unix)]
mod capture_read;
#[cfg(unix)]
pub mod custody;
pub mod envelope;
#[cfg(unix)]
pub mod execution;
pub mod github;
#[cfg(unix)]
mod http_diagnostics;
pub mod intent;
pub mod oidc;
#[cfg(unix)]
pub mod owner_cli;
#[cfg(unix)]
mod owner_http;
#[cfg(unix)]
mod owner_lifecycle;
#[cfg(unix)]
pub mod owner_supervisor;
#[cfg(unix)]
pub mod preparation;
#[cfg(unix)]
pub mod profile;
#[cfg(unix)]
pub mod receipt;
#[cfg(unix)]
pub mod runner;
pub mod runner_binding;
pub mod runner_identity;
#[cfg(unix)]
pub mod runtime;
pub mod transport;
// Only the descriptor-bound Darwin ACL adapter needs FFI. Crypto paths deny it.
#[cfg(unix)]
pub mod agent_read;
#[cfg(unix)]
pub mod delivery_barrier;
#[cfg(unix)]
pub mod idle_agent;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos_acl;
#[cfg(unix)]
pub mod storage;
#[cfg(unix)]
pub mod wake_store;

pub const MAX_STREAM_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMMAND_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;

/// Owned command-builder observations, never a scan of another process's argv
/// or environment. These bytes can contain credentials: seal them with the full
/// failure payload, never echo them. Cwd is recorded separately from argv hash.
#[derive(Serialize)]
pub struct CommandEvidence {
    os_string_encoding: &'static str,
    #[serde(serialize_with = "serialize_bytes")]
    program_base64: Zeroizing<Vec<u8>>,
    #[serde(serialize_with = "serialize_byte_arrays")]
    arguments_base64: Vec<Zeroizing<Vec<u8>>>,
    #[serde(serialize_with = "serialize_optional_bytes")]
    requested_working_directory_base64: Option<Zeroizing<Vec<u8>>>,
    #[serde(serialize_with = "serialize_optional_bytes")]
    observed_parent_working_directory_base64: Option<Zeroizing<Vec<u8>>>,
    argv_sha256: String,
}

impl CommandEvidence {
    /// Snapshot executable argv as represented by the owned command builder.
    /// NUL is not valid in an OS argument; structured-input callers must reject
    /// it before constructing Command, which may replace invalid NUL strings.
    pub fn snapshot(command: &Command) -> Result<Self, CaptureError> {
        let source = command.as_std();
        let parent = std::env::current_dir().ok();
        let requested = source
            .get_current_dir()
            .map(|path| path.as_os_str().as_encoded_bytes());
        let observed_parent = parent
            .as_ref()
            .map(|path| path.as_os_str().as_encoded_bytes());
        let program = source.get_program().as_encoded_bytes();
        let mut total = 0_usize;
        for value in std::iter::once(program)
            .chain(source.get_args().map(|value| value.as_encoded_bytes()))
            .chain(requested)
            .chain(observed_parent)
        {
            total = total
                .checked_add(8)
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(CaptureError::InvalidInput)?;
            if total > MAX_COMMAND_EVIDENCE_BYTES {
                return Err(CaptureError::InvalidInput);
            }
        }
        let encoding = if cfg!(unix) {
            "unix-os-bytes"
        } else {
            "rust-os-encoded-bytes-same-platform"
        };
        let mut digest = Sha256::new();
        digest.update(b"chinwag-ci-command-argv-v1\0");
        for value in std::iter::once(encoding.as_bytes())
            .chain(std::iter::once(program))
            .chain(source.get_args().map(|value| value.as_encoded_bytes()))
        {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        Ok(Self {
            os_string_encoding: encoding,
            program_base64: Zeroizing::new(program.to_vec()),
            arguments_base64: source
                .get_args()
                .map(|value| Zeroizing::new(value.as_encoded_bytes().to_vec()))
                .collect(),
            requested_working_directory_base64: requested
                .map(|value| Zeroizing::new(value.to_vec())),
            observed_parent_working_directory_base64: observed_parent
                .map(|value| Zeroizing::new(value.to_vec())),
            argv_sha256: hex::encode(digest.finalize()),
        })
    }
    /// Commits to program+argument boundaries and encoding, not cwd/environment
    /// or permission to execute. Verify checkout/cwd policy independently.
    pub fn argv_sha256(&self) -> &str {
        &self.argv_sha256
    }
}

#[derive(Serialize)]
struct HostTiming {
    classification: &'static str,
    started_unix_ms: Option<u64>,
    finished_unix_ms: Option<u64>,
    elapsed_monotonic_ms: u64,
}

fn host_unix_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

/// These fields are supplied claims. A separate admission verifier must bind
/// them to a signed initiating-agent intent and the actual workflow identity.
#[derive(Clone, Serialize)]
pub struct UnverifiedRunContext {
    pub repository: String,
    pub source_commit: String,
    pub workflow_ref: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub job: String,
    pub initiating_intent_sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("invalid CI run context or capture limits")]
    InvalidInput,
    #[error("could not start the requested process")]
    Spawn(#[source] io::Error),
}

#[derive(Clone, Copy)]
pub struct CaptureLimits {
    pub bytes_per_stream: usize,
    pub deadline: Duration,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            bytes_per_stream: MAX_STREAM_BYTES,
            deadline: Duration::from_secs(300),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessOutcome {
    Exited {
        code: i32,
    },
    Signaled {
        signal: Option<i32>,
    },
    DeadlineExceeded {
        child_reaped: bool,
    },
    CaptureIoFailed {
        child_reaped: bool,
        operation: CaptureOperation,
        io_error_kind: String,
    },
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOperation {
    Stdout,
    Stderr,
    WaitForChild,
}

/// The child status and the pipe capture result are independent observations.
#[derive(Serialize)]
pub struct ObservedChildExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub observed_before_capture_failure: bool,
}

impl ObservedChildExit {
    fn new(status: std::process::ExitStatus, before_failure: bool) -> Self {
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            status.signal()
        };
        #[cfg(not(unix))]
        let signal = None;
        Self {
            code: status.code(),
            signal,
            observed_before_capture_failure: before_failure,
        }
    }
}

struct CaptureIoError {
    operation: CaptureOperation,
    kind: io::ErrorKind,
}

fn classify_io(operation: CaptureOperation, error: io::Error) -> CaptureIoError {
    CaptureIoError {
        operation,
        kind: error.kind(),
    }
}

/// No Debug implementation: accidentally logging this value must not print
/// captured compiler output, source fragments, or command credentials.
#[derive(Serialize)]
pub struct CapturedRun {
    schema: &'static str,
    content_disposition: &'static str,
    provenance: &'static str,
    context: UnverifiedRunContext,
    command: CommandEvidence,
    timing: HostTiming,
    outcome: ProcessOutcome,
    observed_child_exit: Option<ObservedChildExit>,
    stdout: StreamEvidence,
    stderr: StreamEvidence,
}

#[derive(Serialize)]
pub struct StreamEvidence {
    #[serde(serialize_with = "serialize_bytes")]
    bytes_base64: Zeroizing<Vec<u8>>,
    observed_bytes: u64,
    reached_eof: bool,
    output_limit_exceeded: bool,
    /// Hashes every observed byte, including bytes beyond the retained prefix.
    observed_sha256: String,
    #[serde(skip)]
    digest: Sha256,
}

fn serialize_bytes<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    let encoded = Zeroizing::new(STANDARD.encode(value));
    serializer.serialize_str(&encoded)
}

fn serialize_byte_arrays<S: Serializer>(
    values: &[Zeroizing<Vec<u8>>],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut sequence = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        let encoded = Zeroizing::new(STANDARD.encode(value));
        sequence.serialize_element(encoded.as_str())?;
    }
    sequence.end()
}

fn serialize_optional_bytes<S: Serializer>(
    value: &Option<Zeroizing<Vec<u8>>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => {
            let encoded = Zeroizing::new(STANDARD.encode(value));
            serializer.serialize_some(encoded.as_str())
        }
        None => serializer.serialize_none(),
    }
}

impl StreamEvidence {
    fn new() -> Self {
        Self {
            bytes_base64: Zeroizing::new(Vec::new()),
            observed_bytes: 0,
            reached_eof: false,
            output_limit_exceeded: false,
            observed_sha256: String::new(),
            digest: Sha256::new(),
        }
    }

    async fn drain<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        mut reader: R,
        limit: usize,
    ) -> io::Result<()> {
        let mut scratch = Zeroizing::new([0_u8; 8192]);
        loop {
            let size = reader.read(&mut scratch[..]).await?;
            if size == 0 {
                self.reached_eof = true;
                return Ok(());
            }
            self.observed_bytes += size as u64;
            self.digest.update(&scratch[..size]);
            let retained = size.min(limit.saturating_sub(self.bytes_base64.len()));
            self.bytes_base64.extend_from_slice(&scratch[..retained]);
            self.output_limit_exceeded |= retained != size;
        }
    }

    fn finish(&mut self) {
        self.observed_sha256 = format!("{:x}", self.digest.clone().finalize());
    }

    pub fn is_complete(&self) -> bool {
        self.reached_eof && !self.output_limit_exceeded
    }
}

impl CapturedRun {
    pub fn outcome(&self) -> &ProcessOutcome {
        &self.outcome
    }

    pub fn output_is_complete(&self) -> bool {
        self.stdout.is_complete() && self.stderr.is_complete()
    }

    pub fn observed_child_exit(&self) -> Option<&ObservedChildExit> {
        self.observed_child_exit.as_ref()
    }

    /// Sensitive plaintext serialization, intended only as input to sealing.
    /// It must not be written to stdout, an inbox, or a GitHub Actions artifact.
    pub fn plaintext_for_sealing(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        serde_json::to_vec(self).map(Zeroizing::new)
    }
}

fn valid_context(context: &UnverifiedRunContext) -> bool {
    fn hex256(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
    fn repository_part(value: &str) -> bool {
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    }
    let commit = &context.source_commit;
    let bounded = [&context.repository, &context.workflow_ref, &context.job]
        .iter()
        .all(|value| !value.is_empty() && value.len() <= 1024 && !value.contains('\0'));
    bounded
        && context
            .repository
            .split_once('/')
            .is_some_and(|(owner, repo)| repository_part(owner) && repository_part(repo))
        && [40, 64].contains(&commit.len())
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        && hex256(&context.initiating_intent_sha256)
        && context.run_id > 0
        && context.run_attempt > 0
}

/// Runs the explicitly supplied argv with no shell interpolation and no output
/// echo. Both pipes are drained concurrently, even after a retention limit is
/// exceeded, so a full stderr pipe cannot deadlock a verbose stdout producer.
///
/// The deadline covers child exit AND pipe EOF. On cancellation or deadline the
/// directly owned child is killed; this is not a process-tree supervisor. A
/// runner must additionally contain descendants in its owned job sandbox.
pub async fn capture(
    command: &mut Command,
    context: UnverifiedRunContext,
    limits: CaptureLimits,
) -> Result<CapturedRun, CaptureError> {
    if !valid_context(&context)
        || limits.bytes_per_stream == 0
        || limits.bytes_per_stream > MAX_STREAM_BYTES
        || limits.deadline.is_zero()
        || limits.deadline > Duration::from_secs(3600)
    {
        return Err(CaptureError::InvalidInput);
    }
    let started = Instant::now();
    let started_unix_ms = host_unix_ms();
    let command_evidence = CommandEvidence::snapshot(command)?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(CaptureError::Spawn)?;
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let mut stdout = StreamEvidence::new();
    let mut stderr = StreamEvidence::new();
    let mut observed_child_exit = None;
    let result = timeout(limits.deadline, async {
        tokio::try_join!(
            async {
                stdout
                    .drain(stdout_pipe, limits.bytes_per_stream)
                    .await
                    .map_err(|e| classify_io(CaptureOperation::Stdout, e))
            },
            async {
                stderr
                    .drain(stderr_pipe, limits.bytes_per_stream)
                    .await
                    .map_err(|e| classify_io(CaptureOperation::Stderr, e))
            },
            async {
                let status = child
                    .wait()
                    .await
                    .map_err(|e| classify_io(CaptureOperation::WaitForChild, e))?;
                observed_child_exit = Some(ObservedChildExit::new(status, true));
                Ok::<_, CaptureIoError>(status)
            }
        )
    })
    .await;
    let outcome = match result {
        Ok(Ok(((), (), status))) => match status.code() {
            Some(code) => ProcessOutcome::Exited { code },
            None => {
                #[cfg(unix)]
                let signal = {
                    use std::os::unix::process::ExitStatusExt;
                    status.signal()
                };
                #[cfg(not(unix))]
                let signal = None;
                ProcessOutcome::Signaled { signal }
            }
        },
        failure => {
            // start_kill is safe even when wait already reaped the child but a
            // descendant retained a pipe. Never extend the process deadline.
            let _ = child.start_kill();
            let child_reaped = if observed_child_exit.is_some() {
                true
            } else {
                match timeout(Duration::from_secs(2), child.wait()).await {
                    Ok(Ok(status)) => {
                        observed_child_exit = Some(ObservedChildExit::new(status, false));
                        true
                    }
                    _ => false,
                }
            };
            match failure {
                Err(_) => ProcessOutcome::DeadlineExceeded { child_reaped },
                Ok(Err(error)) => ProcessOutcome::CaptureIoFailed {
                    child_reaped,
                    operation: error.operation,
                    // Only the stdlib enum name; never raw OS/upstream text.
                    io_error_kind: format!("{:?}", error.kind),
                },
                Ok(Ok(_)) => unreachable!(),
            }
        }
    };
    stdout.finish();
    stderr.finish();
    Ok(CapturedRun {
        schema: "chinwag.ci-captured-run.v1",
        content_disposition: "UNTRUSTED_PROCESS_OUTPUT_DATA_ONLY",
        provenance: "UNVERIFIED_REQUIRES_SIGNED_INTENT_AND_WORKLOAD_ADMISSION",
        context,
        command: command_evidence,
        timing: HostTiming {
            classification: "LOCAL_HOST_OBSERVATION_NOT_K2_TRUSTED_TIME",
            started_unix_ms,
            finished_unix_ms: host_unix_ms(),
            elapsed_monotonic_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        },
        outcome,
        observed_child_exit,
        stdout,
        stderr,
    })
}
