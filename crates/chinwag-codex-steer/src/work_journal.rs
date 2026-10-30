//! One human work intent, consumed before its first connection or protocol effect.

use crate::{
    Evidence, Result, SteerError, WorkConfig, WorkStartReceipt,
    connection::CommittedInitialTurn,
    journal::{JournalLock, named_file, open_root, owned_file, read_bounded, same_file},
    record::{valid_operation_id, valid_target_id, valid_text},
};
use rustix::fs::{Dir, FlockOperation, Mode, OFlags, flock, openat};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

const LOCK: &str = "work.lock";
const MARKER: &str = "work-domain.json";
const MARKER_BYTES: &[u8] = b"{\"schema\":\"chinwag-codex-owned-work/v1\"}\n";
const RECORD: &str = "work.jsonl";
const MAX_BYTES: usize = 256 * 1024;
const MAX_LINES: usize = 32;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WorkIntent {
    id: String,
    text: String,
    socket: PathBuf,
    cwd: PathBuf,
    dedicated_explicit_login_consent: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Line {
    Intent {
        intent: WorkIntent,
    },
    Receipt {
        receipt: WorkStartReceipt,
        epoch: Option<String>,
    },
}

/// No public/serialized constructor. Only successful durable consumption mints it.
pub(crate) struct CommittedWork {
    intent: WorkIntent,
    deadline: Instant,
}
impl CommittedWork {
    pub(crate) fn id(&self) -> &str {
        &self.intent.id
    }
    pub(crate) fn text(&self) -> &str {
        &self.intent.text
    }
    pub(crate) fn cwd(&self) -> &Path {
        &self.intent.cwd
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn dedicated_explicit_login_consent(&self) -> bool {
        self.intent.dedicated_explicit_login_consent
    }
}

pub(crate) enum ConsumedWork {
    Created(CommittedWork),
    Existing(WorkStartReceipt),
}

pub(crate) struct WorkJournal {
    root: PathBuf,
    directory: File,
    parent: File,
    name: OsString,
    lock: JournalLock,
    marker: File,
    config: WorkConfig,
    file: Option<File>,
    bytes: Vec<u8>,
    lines: usize,
    intent: Option<WorkIntent>,
    receipt: Option<WorkStartReceipt>,
    epoch: Option<String>,
    failed: bool,
}

impl WorkJournal {
    pub(crate) fn open(config: WorkConfig) -> Result<Self> {
        let (directory, parent, name) = open_root(&config.journal, true)?;
        let lock: File = openat(
            &directory,
            LOCK,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(storage)?
        .into();
        owned_file(&lock)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| SteerError::Unavailable)?;
        let lock = JournalLock(lock);
        named_file(&directory, LOCK, &lock.0)?;
        let marker = marker(&directory)?;
        let file: Option<File> = match openat(
            &directory,
            RECORD,
            OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => Some(fd.into()),
            Err(error) if error == rustix::io::Errno::NOENT => None,
            Err(_) => return Err(SteerError::Storage),
        };
        let mut result = Self {
            root: config.journal.clone(),
            directory,
            parent,
            name,
            lock,
            marker,
            config,
            file,
            bytes: Vec::new(),
            lines: 0,
            intent: None,
            receipt: None,
            epoch: None,
            failed: false,
        };
        result.check_root()?;
        if let Some(file) = &result.file {
            named_file(&result.directory, RECORD, file)?;
            result.bytes = read_bounded(file, MAX_BYTES)?;
            if !result.bytes.ends_with(b"\n") {
                return Err(SteerError::Storage);
            }
            let mut lines = result.bytes.split(|byte| *byte == b'\n');
            let first: Line = serde_json::from_slice(lines.next().ok_or(SteerError::Storage)?)
                .map_err(storage)?;
            let Line::Intent { intent } = first else {
                return Err(SteerError::Storage);
            };
            validate_intent(&intent, &result.config)?;
            result.receipt = Some(initial_receipt(&intent));
            result.intent = Some(intent);
            result.lines = 1;
            for line in lines {
                if line.is_empty() {
                    continue;
                }
                result.lines += 1;
                if result.lines > MAX_LINES {
                    return Err(SteerError::Storage);
                }
                let Line::Receipt { receipt, epoch } =
                    serde_json::from_slice(line).map_err(storage)?
                else {
                    return Err(SteerError::Storage);
                };
                validate_next(
                    result.receipt.as_ref().unwrap(),
                    &receipt,
                    result.epoch.as_deref(),
                    epoch.as_deref(),
                )?;
                result.receipt = Some(receipt);
                result.epoch = epoch;
            }
            // A complete line may have survived a failed previous sync.
            result.verify_record()?;
            file.sync_all().map_err(storage)?;
            result.directory.sync_all().map_err(storage)?;
            result.verify_record()?;
            if let Some(receipt) = &mut result.receipt {
                receipt.recovered_after_restart = true;
            }
        }
        Ok(result)
    }

    /// Historical cache for snapshot projection, never a fresh lookup proof.
    pub(crate) fn receipt(&self) -> Option<WorkStartReceipt> {
        self.receipt.clone()
    }

    pub(crate) fn lookup(&self) -> Result<Option<WorkStartReceipt>> {
        self.check_root()?;
        if self.failed {
            return Err(SteerError::Storage);
        }
        if self.intent.is_some() {
            self.verify_record()?;
        }
        Ok(self.receipt.clone())
    }

    pub(crate) fn consume(
        &mut self,
        id: &str,
        text: &str,
        deadline: Instant,
    ) -> Result<ConsumedWork> {
        if !valid_operation_id(id) || !valid_text(text) {
            return Err(SteerError::InvalidInput);
        }
        self.check_root()?;
        if let Some(intent) = &self.intent {
            return if intent.id == id && intent.text == text {
                self.verify_record()?;
                Ok(ConsumedWork::Existing(
                    self.receipt.clone().ok_or(SteerError::Storage)?,
                ))
            } else {
                Err(SteerError::Conflict)
            };
        }
        if self.failed {
            return Err(SteerError::Storage);
        }
        if Instant::now() >= deadline {
            return Err(SteerError::PermissionDenied);
        }
        let intent = WorkIntent {
            id: id.into(),
            text: text.into(),
            socket: self.config.socket.clone(),
            cwd: self.config.workdir.clone(),
            dedicated_explicit_login_consent: true,
        };
        validate_intent(&intent, &self.config)?;
        let file: File = openat(
            &self.directory,
            RECORD,
            OFlags::RDWR
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(storage)?
        .into();
        self.failed = true; // Failure after creation reserves this one Start permanently.
        owned_file(&file)?;
        let bytes = encode(&Line::Intent {
            intent: intent.clone(),
        })?;
        (&file).write_all(&bytes).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        named_file(&self.directory, RECORD, &file)?;
        if read_bounded(&file, MAX_BYTES)? != bytes {
            return Err(SteerError::Storage);
        }
        self.directory.sync_all().map_err(storage)?;
        self.check_root()?;
        self.file = Some(file);
        self.bytes = bytes;
        self.lines = 1;
        self.receipt = Some(initial_receipt(&intent));
        self.intent = Some(intent.clone());
        self.failed = false;
        Ok(ConsumedWork::Created(CommittedWork { intent, deadline }))
    }

    pub(crate) fn update(&mut self, receipt: WorkStartReceipt) -> Result<WorkStartReceipt> {
        self.append(receipt, self.epoch.clone())
    }

    pub(crate) fn commit_initial(
        &mut self,
        work: &CommittedWork,
        thread: &str,
        epoch: &str,
    ) -> Result<CommittedInitialTurn> {
        if self.intent.as_ref() != Some(&work.intent)
            || !valid_target_id(thread)
            || epoch.len() != 32
            || !epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SteerError::Conflict);
        }
        let mut receipt = self.receipt.clone().ok_or(SteerError::Storage)?;
        receipt.connected = true;
        receipt.initialized = true;
        receipt.thread_id = Some(thread.into());
        self.append(receipt, Some(epoch.into()))?;
        CommittedInitialTurn::new(
            work.id().into(),
            work.text().into(),
            epoch.into(),
            thread.into(),
            work.deadline(),
        )
    }

    fn append(
        &mut self,
        receipt: WorkStartReceipt,
        epoch: Option<String>,
    ) -> Result<WorkStartReceipt> {
        if self.failed {
            return Err(SteerError::Storage);
        }
        self.verify_record()?;
        let previous = self.receipt.as_ref().ok_or(SteerError::Storage)?;
        validate_next(previous, &receipt, self.epoch.as_deref(), epoch.as_deref())?;
        if previous == &receipt && self.epoch == epoch {
            return Ok(receipt);
        }
        let next = encode(&Line::Receipt {
            receipt: receipt.clone(),
            epoch: epoch.clone(),
        })?;
        if self.lines >= MAX_LINES || self.bytes.len() + next.len() > MAX_BYTES {
            return Err(SteerError::Capacity);
        }
        let result = (|| {
            let file = self.file.as_ref().ok_or(SteerError::Storage)?;
            (&*file).write_all(&next).map_err(storage)?;
            file.sync_all().map_err(storage)?;
            self.directory.sync_all().map_err(storage)?;
            named_file(&self.directory, RECORD, file)?;
            let mut expected = self.bytes.clone();
            expected.extend_from_slice(&next);
            if read_bounded(file, MAX_BYTES)? != expected {
                return Err(SteerError::Storage);
            }
            self.check_root()?;
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
            if let Some(last) = &mut self.receipt {
                last.persistence_failed = true;
            }
            return Err(SteerError::Storage);
        }
        self.bytes.extend_from_slice(&next);
        self.lines += 1;
        self.epoch = epoch;
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    fn verify_record(&self) -> Result<()> {
        self.check_root()?;
        let file = self.file.as_ref().ok_or(SteerError::Storage)?;
        named_file(&self.directory, RECORD, file)?;
        if read_bounded(file, MAX_BYTES)? != self.bytes {
            return Err(SteerError::Storage);
        }
        Ok(())
    }

    fn check_root(&self) -> Result<()> {
        let (directory, parent, name) = open_root(&self.root, false)?;
        if name != self.name {
            return Err(SteerError::Storage);
        }
        same_file(&directory, &self.directory)?;
        same_file(&parent, &self.parent)?;
        named_file(&self.directory, LOCK, &self.lock.0)?;
        named_file(&self.directory, MARKER, &self.marker)?;
        if read_bounded(&self.marker, MARKER_BYTES.len())? != MARKER_BYTES {
            return Err(SteerError::Storage);
        }
        Ok(())
    }
}

fn initial_receipt(intent: &WorkIntent) -> WorkStartReceipt {
    WorkStartReceipt {
        id: intent.id.clone(),
        text: intent.text.clone(),
        connected: false,
        initialized: false,
        bootstrap_uncertain: false,
        thread_id: None,
        accepted_turn_id: None,
        evidence: Evidence::default(),
        recovered_after_restart: false,
        persistence_failed: false,
    }
}

fn validate_intent(intent: &WorkIntent, config: &WorkConfig) -> Result<()> {
    if valid_operation_id(&intent.id)
        && valid_text(&intent.text)
        && intent.socket == config.socket
        && intent.cwd == config.workdir
        && intent.dedicated_explicit_login_consent
    {
        Ok(())
    } else {
        Err(SteerError::Storage)
    }
}

fn validate_next(
    old: &WorkStartReceipt,
    next: &WorkStartReceipt,
    old_epoch: Option<&str>,
    next_epoch: Option<&str>,
) -> Result<()> {
    if old.id != next.id
        || old.text != next.text
        || old.evidence.merged(next.evidence)? != next.evidence
        || (old.connected && !next.connected)
        || (old.initialized && !next.initialized)
        || (old.bootstrap_uncertain && !next.bootstrap_uncertain)
        || old
            .thread_id
            .as_ref()
            .is_some_and(|id| next.thread_id.as_ref() != Some(id))
        || old
            .accepted_turn_id
            .as_ref()
            .is_some_and(|id| next.accepted_turn_id.as_ref() != Some(id))
        || old_epoch.is_some_and(|epoch| next_epoch != Some(epoch))
        || next
            .thread_id
            .as_deref()
            .is_some_and(|id| !valid_target_id(id))
        || next
            .accepted_turn_id
            .as_deref()
            .is_some_and(|id| !valid_target_id(id))
        || next_epoch.is_some_and(|epoch| {
            epoch.len() != 32
                || !epoch
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || (next.initialized && !next.connected)
        || (next.thread_id.is_some() && !next.initialized)
        || (next.accepted_turn_id.is_some() != next.evidence.core_accepted)
        || (next_epoch.is_some() && next.thread_id.is_none())
        || (next.thread_id.is_none()
            && (next.evidence.frame_written
                || next.evidence.write_uncertain
                || next.evidence.core_accepted
                || next.evidence.harness_recorded
                || next.evidence.peer_error_observed))
    {
        Err(SteerError::Storage)
    } else {
        Ok(())
    }
}

fn marker(directory: &File) -> Result<File> {
    match openat(
        directory,
        MARKER,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let file: File = fd.into();
            named_file(directory, MARKER, &file)?;
            if read_bounded(&file, MARKER_BYTES.len())? != MARKER_BYTES {
                return Err(SteerError::Storage);
            }
            Ok(file)
        }
        Err(error) if error == rustix::io::Errno::NOENT => {
            let mut count = 0;
            for entry in Dir::read_from(directory).map_err(storage)? {
                let entry = entry.map_err(storage)?;
                count += 1;
                if count > 4 || !matches!(entry.file_name().to_bytes(), b"." | b".." | b"work.lock")
                {
                    return Err(SteerError::Storage);
                }
            }
            let file: File = openat(
                directory,
                MARKER,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(storage)?
            .into();
            (&file).write_all(MARKER_BYTES).map_err(storage)?;
            file.sync_all().map_err(storage)?;
            directory.sync_all().map_err(storage)?;
            named_file(directory, MARKER, &file)?;
            if read_bounded(&file, MARKER_BYTES.len())? != MARKER_BYTES {
                return Err(SteerError::Storage);
            }
            Ok(file)
        }
        Err(_) => Err(SteerError::Storage),
    }
}

fn encode(line: &Line) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(line).map_err(storage)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_BYTES {
        Err(SteerError::Capacity)
    } else {
        Ok(bytes)
    }
}
fn storage(_: impl std::fmt::Display) -> SteerError {
    SteerError::Storage
}

#[cfg(test)]
mod tests;
