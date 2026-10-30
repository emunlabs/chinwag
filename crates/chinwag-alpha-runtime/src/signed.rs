//! The explicit human UI boundary into the existing Rust bus signer.
//! This adapter never reads key material, wakes an agent, or retries a child.
//! The server journals request IDs before calling this once-per-attempt adapter;
//! an uncertain attempt does not disable unrelated human messages.

use std::{
    fs,
    io::Read,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::{fs::PermissionsExt, process::CommandExt};

use chinwag_bus_client::{BusAck, BusMessage, SendReceipt, SendRequest};
use serde::Deserialize;

use crate::{Result, RuntimeError, SignedSender};

const CHILD_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_STDOUT: usize = 256 * 1024;
const MAX_STDERR: usize = 64 * 1024;
const MAX_BODY: usize = 16000;

pub struct CliSignedSender {
    cli: PathBuf,
    repo: PathBuf,
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
    active: Mutex<()>,
}

impl CliSignedSender {
    /// Configure an existing executable. Construction never invokes the signer.
    pub fn new(cli: PathBuf, repo: PathBuf) -> Result<Self> {
        if !cli.is_absolute() || !repo.is_absolute() {
            return Err(RuntimeError::Invalid(
                "signed CLI and repository paths must be absolute".into(),
            ));
        }
        let cli = fs::canonicalize(cli)?;
        let repo = fs::canonicalize(repo)?;
        let metadata = fs::metadata(&cli)?;
        if !metadata.is_file() || !repo.is_dir() {
            return Err(RuntimeError::Invalid(
                "signed CLI must be a regular executable and repository must be a directory".into(),
            ));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(RuntimeError::Invalid("signed CLI is not executable".into()));
        }
        Ok(Self {
            cli,
            repo,
            timeout: CHILD_TIMEOUT,
            max_stdout: MAX_STDOUT,
            max_stderr: MAX_STDERR,
            active: Mutex::new(()),
        })
    }

    fn command(&self, request: &SendRequest) -> Command {
        let mut command = Command::new(&self.cli);
        command
            .arg("bus")
            .arg("send")
            .arg("--repo")
            .arg(&self.repo)
            .arg("--from")
            .arg("Brian")
            .arg("--room")
            .arg(&request.room)
            .arg("--json")
            .arg("--message")
            .arg(&request.body)
            .current_dir(&self.repo)
            .env_remove("CHINWAG_BUS_ADDR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(to) = &request.to {
            command.arg("--to").arg(to);
        }
        if let Some(task) = &request.task_id {
            command.arg("--task").arg(task);
        }
        #[cfg(unix)]
        command.process_group(0);
        command
    }

    fn invoke(&self, request: &SendRequest) -> Result<SendReceipt> {
        let mut child = self.command(request).spawn().map_err(|error| {
            RuntimeError::Unavailable(format!("could not start existing signed CLI: {error}"))
        })?;
        let outcome = capture_child(&mut child, self.timeout, self.max_stdout, self.max_stderr)
            .and_then(|(status, stdout)| {
                if !status.success() {
                    return Err(format!(
                        "existing signed CLI exited with {status}; no validated receipt"
                    ));
                }
                validate_receipt(&stdout, request)
            });
        outcome.map_err(RuntimeError::SendUncertain)
    }
}

impl SignedSender for CliSignedSender {
    fn send(&self, request: &SendRequest) -> Result<SendReceipt> {
        validate_request(request)?;
        let _active = self.active.try_lock().map_err(|_| {
            RuntimeError::Unavailable(
                "a signed send is already active; no additional child started".into(),
            )
        })?;
        self.invoke(request)
    }
}

fn validate_request(request: &SendRequest) -> Result<()> {
    if request.sender != "Brian" {
        return Err(RuntimeError::Rejected("signed UI sends require the explicit human sender Brian; other or automated identities are not accepted".into()));
    }
    if !matches!(request.room.as_str(), "#alpha" | "#mgmt" | "#eng" | "#qa") {
        return Err(RuntimeError::Rejected(
            "signed UI room is not one of the four supported rooms".into(),
        ));
    }
    if request.body.trim().is_empty()
        || request.body.len() > MAX_BODY
        || request.body.contains('\0')
    {
        return Err(RuntimeError::Rejected(
            "signed message must contain text, fit 16000 bytes, and contain no NUL".into(),
        ));
    }
    for value in [&request.to, &request.task_id].into_iter().flatten() {
        if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(RuntimeError::Rejected(
                "optional recipient/task must be nonempty, bounded text without control characters"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct CliReceipt {
    ok: bool,
    message: BusMessage,
    ack: BusAck,
}

fn validate_receipt(
    stdout: &[u8],
    request: &SendRequest,
) -> std::result::Result<SendReceipt, String> {
    let wire: CliReceipt = serde_json::from_slice(stdout)
        .map_err(|_| "existing signed CLI did not return one complete JSON receipt".to_owned())?;
    let message = &wire.message;
    let ack = &wire.ack;
    if !wire.ok
        || !ack.ok
        || message.sender != "Brian"
        || message.room != request.room
        || ack.room != request.room
        || message.id.trim().is_empty()
        || message.seq == 0
        || message.ts_iso.trim().is_empty()
        || ack.message_id != message.id
        || ack.seq != message.seq
        || ack.transport.trim().is_empty()
        || message.to != request.to
        || message.task_id != request.task_id
        || message.sig_verified != ack.sig_verified
        || (message.body != request.body && message.body != request.body.trim())
    {
        return Err("existing signed CLI receipt does not confirm the requested Brian message, room, body, metadata, ID, sequence and signature outcome".into());
    }
    Ok(SendReceipt {
        message: wire.message,
        ack: wire.ack,
    })
}

type Capture = mpsc::Receiver<std::io::Result<Vec<u8>>>;

fn reader(mut stream: impl Read + Send + 'static, maximum: usize) -> std::io::Result<Capture> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("signed-cli-capture".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = stream
                .by_ref()
                .take((maximum + 1) as u64)
                .read_to_end(&mut bytes)
                .and_then(|_| {
                    if bytes.len() > maximum {
                        Err(std::io::Error::other(
                            "signed CLI output exceeded its byte bound",
                        ))
                    } else {
                        Ok(bytes)
                    }
                });
            let _ = sender.send(result);
        })?;
    Ok(receiver)
}

fn capture_child(
    child: &mut Child,
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
) -> std::result::Result<(ExitStatus, Vec<u8>), String> {
    let deadline = Instant::now() + timeout;
    let capture = (|| {
        let stdout = child
            .stdout
            .take()
            .ok_or("signed CLI stdout was unavailable")?;
        let stderr = child
            .stderr
            .take()
            .ok_or("signed CLI stderr was unavailable")?;
        let stdout =
            reader(stdout, max_stdout).map_err(|_| "could not capture signed CLI stdout")?;
        let stderr =
            reader(stderr, max_stderr).map_err(|_| "could not capture signed CLI stderr")?;
        let mut out = None;
        let mut err = None;
        let mut status = None;
        loop {
            for (receiver, result) in [(&stdout, &mut out), (&stderr, &mut err)] {
                if result.is_none() {
                    match receiver.try_recv() {
                        Ok(Ok(bytes)) => *result = Some(bytes),
                        Ok(Err(_)) => {
                            return Err(
                                "signed CLI output exceeded a bound or could not be captured"
                                    .to_string(),
                            );
                        }
                        Err(mpsc::TryRecvError::Disconnected) => {
                            return Err("signed CLI capture ended without a result".to_string());
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                }
            }
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|_| "could not observe signed CLI completion")?;
            }
            if let (Some(status), Some(_), Some(_)) = (status, &out, &err) {
                return Ok((status, out.take().unwrap_or_default()));
            }
            if Instant::now() >= deadline {
                return Err("existing signed CLI exceeded its finite deadline".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    })();
    if capture.is_err() {
        terminate_owned_child(child);
    }
    capture
}

fn terminate_owned_child(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(raw) = i32::try_from(child.id())
        && raw > 1
        && let Some(pid) = rustix::process::Pid::from_raw(raw)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        if child.try_wait().is_ok_and(|status| status.is_some()) {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests;
