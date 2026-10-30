//! One opt-in owned forward for the existing Studio preview route.
use super::*;
use std::{
    io::{Seek, SeekFrom},
    os::unix::fs::MetadataExt,
};

pub(super) const URL: &str = "http://127.0.0.1:44345";
const MAX_ATTEMPTS: usize = 32;
const RECORD: &str = "studio-forward-process.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessIdentity {
    pub command: String,
    pub started: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    SpawnPending,
    Spawned,
    Identified,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    started_unix_ms: u64,
    phase: Phase,
    pid: Option<u32>,
    identity: Option<ProcessIdentity>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    url: String,
    command: Vec<String>,
    attempts: Vec<Attempt>,
}

struct Journal {
    file: File,
    path: PathBuf,
    value: Record,
    preimage: Vec<u8>,
}

pub(super) fn command() -> Vec<String> {
    [
        "/usr/bin/ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=6",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "RemoteCommand=none",
        "-o",
        "RequestTTY=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-N",
        "-L",
        "127.0.0.1:44345:127.0.0.1:44345",
        "studio",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn private_regular(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_RECEIPT
    {
        return unavailable(
            "Studio forward receipt/log is not a bounded private owned regular file; retained",
        );
    }
    Ok(())
}

pub(super) fn log(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    private_regular(&file)?;
    Ok(file)
}

impl Journal {
    fn existing(path: PathBuf) -> Result<Option<Self>> {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        private_regular(&file)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            RuntimeError::Unavailable(
                "another launcher owns this Studio forward receipt; no duplicate attempted".into(),
            )
        })?;
        let mut preimage = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_RECEIPT + 1)
            .read_to_end(&mut preimage)?;
        if preimage.len() as u64 > MAX_RECEIPT {
            return unavailable("Studio forward receipt exceeds its bound; retained");
        }
        let value: Record = serde_json::from_slice(&preimage).map_err(|_| {
            RuntimeError::Unavailable(
                "Studio forward receipt is incomplete or invalid; no retry or duplicate attempted"
                    .into(),
            )
        })?;
        if value.schema != "chinwag-owned-studio-forward/v1"
            || value.url != URL
            || value.command != command()
            || value.attempts.is_empty()
            || value.attempts.len() > MAX_ATTEMPTS
            || value.attempts.iter().any(|attempt| match attempt.phase {
                Phase::SpawnPending => attempt.pid.is_some() || attempt.identity.is_some(),
                Phase::Spawned => {
                    attempt.pid.is_none_or(|pid| pid == 0) || attempt.identity.is_some()
                }
                Phase::Identified => {
                    attempt.pid.is_none_or(|pid| pid == 0)
                        || attempt.identity.as_ref().is_none_or(|identity| {
                            identity.command != value.command.join(" ")
                                || identity.started.is_empty()
                                || identity.started.len() > 64
                                || identity.started.chars().any(char::is_control)
                        })
                }
            })
        {
            return unavailable(
                "Studio forward receipt does not match this fixed owned route; no duplicate attempted",
            );
        }
        Ok(Some(Self {
            file,
            path,
            value,
            preimage,
        }))
    }

    fn create(path: PathBuf) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
            .open(&path)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            RuntimeError::Unavailable(
                "Studio forward receipt became busy; no forward started".into(),
            )
        })?;
        Ok(Self {
            file,
            path,
            value: Record {
                schema: "chinwag-owned-studio-forward/v1".into(),
                url: URL.into(),
                command: command(),
                attempts: Vec::new(),
            },
            preimage: Vec::new(),
        })
    }

    fn save(&mut self) -> Result<()> {
        private_regular(&self.file)?;
        let named = fs::symlink_metadata(&self.path)?;
        let held = self.file.metadata()?;
        if !named.is_file()
            || named.file_type().is_symlink()
            || named.dev() != held.dev()
            || named.ino() != held.ino()
        {
            return unavailable("Studio forward receipt changed; original retained without retry");
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut actual = Vec::new();
        Read::by_ref(&mut self.file)
            .take(MAX_RECEIPT + 1)
            .read_to_end(&mut actual)?;
        if actual != self.preimage {
            return unavailable(
                "Studio forward receipt bytes changed; original retained without retry",
            );
        }
        let bytes = serde_json::to_vec_pretty(&self.value)
            .map_err(|error| RuntimeError::Invalid(error.to_string()))?;
        if bytes.len() as u64 > MAX_RECEIPT {
            return unavailable("Studio forward history capacity reached; retained");
        }
        // A crash can leave an invalid/partial record. Loading refuses it rather
        // than interpreting it as permission to start another SSH process.
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&bytes)?;
        self.file.set_len(bytes.len() as u64)?;
        self.file.sync_all()?;
        File::open(
            self.path
                .parent()
                .ok_or_else(|| RuntimeError::Invalid("forward receipt has no parent".into()))?,
        )?
        .sync_all()?;
        self.preimage = bytes;
        Ok(())
    }
}

pub(super) fn ensure(state: &Path, platform: &mut impl Platform) -> Result<Value> {
    let path = state.join(RECORD);
    let mut journal = Journal::existing(path.clone())?;
    if let Some(journal) = &journal {
        let attempt = journal.value.attempts.last().expect("validated history");
        let pid = attempt.pid.ok_or_else(|| {
            RuntimeError::Unavailable(
                "Original Studio forward start is uncertain; retained without retry or duplicate"
                    .into(),
            )
        })?;
        if let Some(actual) = platform.forward_identity(pid)? {
            if attempt.identity.as_ref() != Some(&actual) {
                return unavailable(
                    "Original Studio forward PID/command/start-time proof is uncertain or changed; retained without duplicate",
                );
            }
            if platform.forward_port_free()? {
                return unavailable(
                    "Original Studio forward is still active but its local listener is unavailable; retained without duplicate",
                );
            }
            if !platform.forward_listens(pid)? {
                return unavailable(
                    "Preview port 44345 is not proven to be owned by the original Studio forward; retained without duplicate",
                );
            }
            return Ok(
                json!({"action":"reused","pid":pid,"url":URL,"route":"saved-studio-loopback44345","identity_proof":"exact-owned-pid-command-start-time"}),
            );
        }
    }
    if !platform.forward_port_free()? {
        return unavailable(
            "Local preview port 44345 is occupied without a matching live owned forward; original listener retained, no duplicate started",
        );
    }
    let mut journal = match journal.take() {
        Some(journal) => journal,
        None => Journal::create(path)?,
    };
    if journal.value.attempts.len() >= MAX_ATTEMPTS {
        return unavailable("Studio forward attempt history is full; no new forward started");
    }
    journal.value.attempts.push(Attempt {
        started_unix_ms: now_ms()?,
        phase: Phase::SpawnPending,
        pid: None,
        identity: None,
    });
    journal.save()?; // Durable consumed intent precedes possible process creation.
    let pid = platform.spawn_forward(&command(), &state.join("studio-forward.log")).map_err(|error| {
        RuntimeError::Unavailable(format!("Studio forward start outcome is unconfirmed; consumed intent retained without retry: {error}"))
    })?;
    let attempt = journal.value.attempts.last_mut().expect("new attempt");
    attempt.phase = Phase::Spawned;
    attempt.pid = Some(pid);
    journal.save().map_err(|error|RuntimeError::Unavailable(format!("Original Studio forward PID {pid} may be active; receipt update failed; retain it without retry: {error}")))?;
    let identity=platform.forward_identity(pid)?.filter(|identity|identity.command==command().join(" "))
        .ok_or_else(||RuntimeError::Unavailable(format!("Original Studio forward PID {pid} did not establish exact process proof; receipt retained without retry")))?;
    let attempt = journal.value.attempts.last_mut().expect("new attempt");
    attempt.phase = Phase::Identified;
    attempt.identity = Some(identity.clone());
    journal.save()?;
    // Wait only for this new child's local bind, never restart SSH or retry an
    // uncertain HTTP result. The launcher performs one HTTP preflight afterward.
    for _ in 0..60 {
        if let Some(code) = platform.poll_forward(pid)? {
            return unavailable(&format!(
                "Owned Studio forward PID {pid} exited {code}; inspect studio-forward.log; no retry"
            ));
        }
        if !platform.forward_port_free()? {
            if !platform.forward_listens(pid)? {
                return unavailable(
                    "Preview port 44345 was occupied before the owned Studio forward bound it; retained without retry",
                );
            }
            if platform.forward_identity(pid)?.as_ref() != Some(&identity) {
                return unavailable(
                    "Studio forward process proof changed during startup; retained without retry",
                );
            }
            return Ok(
                json!({"action":"started","pid":pid,"url":URL,"route":"saved-studio-loopback44345","identity_proof":"exact-owned-pid-command-start-time"}),
            );
        }
        platform.pause();
    }
    unavailable(&format!(
        "Owned Studio forward PID {pid} did not bind port 44345; retained without retry"
    ))
}

/// Recheck continuity after the one HTTP preflight, without permission to spawn.
pub(super) fn verify_after_preflight(state: &Path, platform: &mut impl Platform) -> Result<()> {
    let journal = Journal::existing(state.join(RECORD))?.ok_or_else(|| {
        RuntimeError::Unavailable("Owned Studio forward receipt disappeared; no app opened".into())
    })?;
    let attempt = journal.value.attempts.last().expect("validated history");
    let pid = attempt.pid.ok_or_else(|| {
        RuntimeError::Unavailable(
            "Owned Studio forward identity is uncertain; no app opened".into(),
        )
    })?;
    if attempt.identity.is_none()
        || platform.forward_identity(pid)?.as_ref() != attempt.identity.as_ref()
        || platform.forward_port_free()?
        || !platform.forward_listens(pid)?
    {
        return unavailable(
            "Owned Studio connection changed during preflight; no app opened, no retry attempted",
        );
    }
    Ok(())
}

pub(super) fn parse_listener_proof(text: &str, pid: u32) -> Result<bool> {
    let mut owner_seen = false;
    let mut listener_seen = false;
    for line in text.lines() {
        if let Some(owner) = line.strip_prefix('p') {
            if owner_seen || owner.parse::<u32>().ok() != Some(pid) {
                return unavailable("listener proof does not match the owned Studio PID");
            }
            owner_seen = true;
        } else if line == "n127.0.0.1:44345" && owner_seen {
            listener_seen = true;
        } else {
            return unavailable("listener proof contains an unexpected route or field");
        }
    }
    Ok(owner_seen && listener_seen)
}
