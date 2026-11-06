#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Descriptor-pinned, bounded operation evidence for the Phase 0 writer.
//!
//! Every line is a complete state snapshot. A successful append means both the
//! bytes and the containing directory have been synced. An uncertain append
//! poisons this handle; reopening must inspect the evidence rather than invent
//! an empty journal. One authoritative filename and the retained directory lock
//! fence cooperating writers across every reopen of the store.
//! Authorization and projection semantics remain the writer's responsibility.

use crate::task_ref::{MAX_REV_COUNTER, validate_task_source_id, validate_workspace_id};
use crate::task_source_path::{MAX_SOURCE_FILE_BYTES, validate_enrolled_relative_path};
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, openat, statat,
};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};

/// Inclusive bounds. The record bound includes its terminating newline.
pub const MAX_JOURNAL_RECORD_UTF8_BYTES: usize = 65_536;
pub const MAX_JOURNAL_RECORD_BYTES: usize = MAX_JOURNAL_RECORD_UTF8_BYTES;
pub const MAX_JOURNAL_FILE_BYTES: u64 = 16_777_216;
pub const MAX_JOURNAL_RECORDS: usize = 4_096;
pub const AUTHORITATIVE_JOURNAL_FILE_NAME: &str = "task-write-journal-v1.ndjson";
pub const RESERVED_COMPLETION_RECORDS_AFTER_RECEIVED: usize = 6;
pub const RESERVED_COMPLETION_RECORDS_AFTER_PREPARED: usize = 4;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_JSON_OBJECT_KEYS: usize = 4_096;

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    InvalidName,
    UnsafeMetadata,
    LockUnavailable,
    RecordTooLarge,
    JournalSizeLimitExceeded,
    JournalRecordLimitExceeded,
    InvalidJson,
    DuplicateJsonKey,
    CorruptJournal,
    OperationReplayConflict,
    InvalidTransition,
    IdentityChanged,
    SymlinkRejected,
    HardlinkRejected,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "journal I/O failed: {error}"),
            other => write!(formatter, "journal held: {other:?}"),
        }
    }
}

impl std::error::Error for JournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn fs_error(error: rustix::io::Errno) -> JournalError {
    if error == rustix::io::Errno::LOOP {
        JournalError::SymlinkRejected
    } else {
        JournalError::Io(error.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteOperationState {
    Received,
    Validated,
    Prepared,
    FileCommitted,
    Reconciling,
    Recorded,
    Acknowledged,
    Rejected,
    Held,
}

impl WriteOperationState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Acknowledged | Self::Rejected | Self::Held)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Received,
                Self::Validated | Self::Rejected | Self::Held
            ) | (
                Self::Validated,
                Self::Prepared | Self::Rejected | Self::Held
            ) | (
                Self::Prepared,
                Self::FileCommitted | Self::Reconciling | Self::Rejected | Self::Held
            ) | (
                Self::FileCommitted,
                Self::Reconciling | Self::Recorded | Self::Held
            ) | (
                Self::Reconciling,
                Self::Recorded | Self::Rejected | Self::Held
            ) | (Self::Recorded, Self::Acknowledged | Self::Held)
        )
    }

    pub const fn may_transition_to(self, next: Self) -> bool {
        self.can_transition_to(next)
    }

    pub fn transition_to(&mut self, next: Self) -> Result<(), JournalError> {
        if !self.can_transition_to(next) {
            return Err(JournalError::InvalidTransition);
        }
        *self = next;
        Ok(())
    }
}

/// Opaque metadata is the writer's complete typed binding, serialized once.
/// Equality covers every field, including original signed TaskRef bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRequestV1 {
    pub workspace_id: String,
    pub task_source_id: String,
    pub operation_id: String,
    pub signer_principal: String,
    pub request_id: String,
    pub request_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub writer_epoch: u64,
    pub signed_task_ref: Vec<u8>,
    pub metadata: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedWriteV1 {
    pub canonical_relative_path: String,
    pub target_name: String,
    pub temp_name: String,
    pub parent_dev: u64,
    pub parent_ino: u64,
    pub previous_dev: u64,
    pub previous_ino: u64,
    pub staged_dev: u64,
    pub staged_ino: u64,
    pub predecessor_hash: [u8; 32],
    pub successor_hash: [u8; 32],
    pub predecessor_revision: u64,
    pub successor_revision: u64,
    /// The signed proposal snapshot remains distinct from a rebased predecessor.
    pub proposal_expected_file_cas_rev: u64,
    pub expected_file_cas_rev: u64,
    pub rebases_used: u8,
    pub expected_preimage_bytes: u64,
    pub committed_postimage_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecordV1 {
    pub schema_version: u32,
    pub request: JournalRequestV1,
    pub state: WriteOperationState,
    pub prepared: Option<PreparedWriteV1>,
    pub result: Option<Value>,
    pub unrelated_file_rebases: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayDispositionV1 {
    Fresh(JournalRecordV1),
    Existing(JournalRecordV1),
    DuplicateRecorded(JournalRecordV1),
}

pub type JournalReplayDisposition = ReplayDispositionV1;
type OperationKey = (String, String, String);
type RequestKey = (String, String, String);

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn component(value: &str) -> Result<(), JournalError> {
    if value.is_empty()
        || value.len() > 255
        || value == "."
        || value == ".."
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
    {
        return Err(JournalError::InvalidName);
    }
    Ok(())
}

fn operation_key(request: &JournalRequestV1) -> OperationKey {
    (
        request.workspace_id.clone(),
        request.task_source_id.clone(),
        request.operation_id.clone(),
    )
}

fn request_key(request: &JournalRequestV1) -> RequestKey {
    (
        request.workspace_id.clone(),
        request.signer_principal.clone(),
        request.request_id.clone(),
    )
}

impl JournalRequestV1 {
    pub fn validate(&self) -> Result<(), JournalError> {
        validate_workspace_id(&self.workspace_id).map_err(|_| JournalError::CorruptJournal)?;
        validate_task_source_id(&self.task_source_id).map_err(|_| JournalError::CorruptJournal)?;
        if !identifier(&self.operation_id)
            || !identifier(&self.signer_principal)
            || !identifier(&self.request_id)
            || self.writer_epoch > MAX_REV_COUNTER
            || self.signed_task_ref.is_empty()
            || self.signed_task_ref.len() > MAX_JOURNAL_RECORD_BYTES
            || !self.metadata.is_object()
        {
            return Err(JournalError::CorruptJournal);
        }
        Ok(())
    }
}

impl PreparedWriteV1 {
    pub fn validate(&self) -> Result<(), JournalError> {
        let components = validate_enrolled_relative_path(&self.canonical_relative_path)
            .map_err(|_| JournalError::CorruptJournal)?;
        component(&self.target_name)?;
        component(&self.temp_name)?;
        if components.last().copied() != Some(self.target_name.as_str())
            || self.target_name == self.temp_name
            || self.previous_dev != self.parent_dev
            || self.staged_dev != self.parent_dev
            || (self.previous_dev, self.previous_ino) == (self.staged_dev, self.staged_ino)
            || self.predecessor_hash == self.successor_hash
            || self.predecessor_revision >= MAX_REV_COUNTER
            || self.successor_revision != self.predecessor_revision + 1
            || self.expected_file_cas_rev != self.predecessor_revision
            || self.proposal_expected_file_cas_rev > self.expected_file_cas_rev
            || self.rebases_used > 2
            || self.expected_file_cas_rev - self.proposal_expected_file_cas_rev
                != u64::from(self.rebases_used)
            || self.expected_preimage_bytes == 0
            || self.expected_preimage_bytes > MAX_SOURCE_FILE_BYTES
            || self.committed_postimage_bytes == 0
            || self.committed_postimage_bytes > MAX_SOURCE_FILE_BYTES
        {
            return Err(JournalError::CorruptJournal);
        }
        Ok(())
    }
}

impl JournalRecordV1 {
    pub fn received(request: JournalRequestV1) -> Self {
        Self {
            schema_version: 1,
            request,
            state: WriteOperationState::Received,
            prepared: None,
            result: None,
            unrelated_file_rebases: 0,
        }
    }

    pub fn validate(&self) -> Result<(), JournalError> {
        self.request.validate()?;
        if self.schema_version != 1 || self.unrelated_file_rebases > 2 {
            return Err(JournalError::CorruptJournal);
        }
        if let Some(prepared) = &self.prepared {
            prepared.validate()?;
            if self.unrelated_file_rebases != prepared.rebases_used {
                return Err(JournalError::CorruptJournal);
            }
        }
        let expects_prepared = matches!(
            self.state,
            WriteOperationState::Prepared
                | WriteOperationState::FileCommitted
                | WriteOperationState::Reconciling
                | WriteOperationState::Recorded
                | WriteOperationState::Acknowledged
        );
        let expects_result = matches!(
            self.state,
            WriteOperationState::Recorded
                | WriteOperationState::Acknowledged
                | WriteOperationState::Rejected
                | WriteOperationState::Held
        );
        if (expects_prepared && self.prepared.is_none())
            || (matches!(
                self.state,
                WriteOperationState::Received | WriteOperationState::Validated
            ) && self.prepared.is_some())
            || self.result.is_some() != expects_result
            || self.result.as_ref().is_some_and(Value::is_null)
        {
            return Err(JournalError::CorruptJournal);
        }
        Ok(())
    }
}

fn validate_transition(
    previous: Option<&JournalRecordV1>,
    next: &JournalRecordV1,
) -> Result<(), JournalError> {
    next.validate()?;
    let Some(previous) = previous else {
        if next.state != WriteOperationState::Received
            || next.unrelated_file_rebases != 0
            || next.prepared.is_some()
            || next.result.is_some()
        {
            return Err(JournalError::InvalidTransition);
        }
        return Ok(());
    };
    if previous.request != next.request {
        return Err(JournalError::OperationReplayConflict);
    }
    if !previous.state.can_transition_to(next.state)
        || next.unrelated_file_rebases < previous.unrelated_file_rebases
        || previous
            .prepared
            .as_ref()
            .is_some_and(|prepared| next.prepared.as_ref() != Some(prepared))
        || previous
            .result
            .as_ref()
            .is_some_and(|result| next.result.as_ref() != Some(result))
    {
        return Err(JournalError::InvalidTransition);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileSnapshot {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileSnapshot {
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &Stat) -> Result<Self, JournalError> {
        Ok(Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            uid: stat.st_uid,
            mode: stat.st_mode as u32,
            nlink: stat.st_nlink as u64,
            size: u64::try_from(stat.st_size).map_err(|_| JournalError::UnsafeMetadata)?,
            mtime: stat.st_mtime as i64,
            mtime_nsec: stat.st_mtime_nsec as i64,
            ctime: stat.st_ctime as i64,
            ctime_nsec: stat.st_ctime_nsec as i64,
        })
    }
}

fn check_directory(file: &File, uid: u32, private: bool) -> Result<FileSnapshot, JournalError> {
    let stat = fstat(file).map_err(fs_error)?;
    let snapshot = FileSnapshot::of(&stat)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || snapshot.uid != uid
        || (private && snapshot.mode & 0o7777 != 0o700)
    {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(snapshot)
}

fn check_regular(stat: &Stat, uid: u32, private: bool) -> Result<FileSnapshot, JournalError> {
    let kind = FileType::from_raw_mode(stat.st_mode);
    if kind == FileType::Symlink {
        return Err(JournalError::SymlinkRejected);
    }
    let snapshot = FileSnapshot::of(stat)?;
    if kind != FileType::RegularFile || snapshot.uid != uid {
        return Err(JournalError::UnsafeMetadata);
    }
    if snapshot.nlink != 1 {
        return Err(JournalError::HardlinkRejected);
    }
    if private && snapshot.mode & 0o7777 != 0o600 {
        return Err(JournalError::UnsafeMetadata);
    }
    Ok(snapshot)
}

/// The lock descriptor is independently opened, never `try_clone`d from a
/// caller's open description. Dropping another caller descriptor cannot unlock
/// this journal, and a second open in the same process must contend normally.
#[derive(Debug)]
pub struct Journal {
    directory: File,
    file: File,
    name: String,
    uid: u32,
    directory_identity: (u64, u64),
    file_identity: (u64, u64),
    file_snapshot: FileSnapshot,
    file_bytes: u64,
    records: Vec<JournalRecordV1>,
    operations: BTreeMap<OperationKey, usize>,
    requests: BTreeMap<RequestKey, OperationKey>,
    poisoned: bool,
}

impl Journal {
    pub fn open(directory: &File, name: &str, expected_uid: u32) -> Result<Self, JournalError> {
        component(name)?;
        if name != AUTHORITATIVE_JOURNAL_FILE_NAME {
            return Err(JournalError::InvalidName);
        }
        if expected_uid != rustix::process::geteuid().as_raw() {
            return Err(JournalError::UnsafeMetadata);
        }
        let caller_directory = check_directory(directory, expected_uid, true)?;
        let retained = File::from(
            openat(
                directory,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(fs_error)?,
        );
        let parent = check_directory(&retained, expected_uid, true)?;
        if (parent.dev, parent.ino) != (caller_directory.dev, caller_directory.ino) {
            return Err(JournalError::IdentityChanged);
        }
        flock(&retained, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| JournalError::LockUnavailable)?;
        let file = File::from(
            openat(
                &retained,
                name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::APPEND
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(fs_error)?,
        );
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| JournalError::LockUnavailable)?;
        let snapshot = check_regular(&fstat(&file).map_err(fs_error)?, expected_uid, true)?;
        if snapshot.size > MAX_JOURNAL_FILE_BYTES {
            return Err(JournalError::JournalSizeLimitExceeded);
        }
        let bound = check_regular(
            &statat(&retained, name, AtFlags::SYMLINK_NOFOLLOW).map_err(fs_error)?,
            expected_uid,
            true,
        )?;
        if snapshot != bound {
            return Err(JournalError::IdentityChanged);
        }
        let mut journal = Self {
            directory: retained,
            file,
            name: name.to_owned(),
            uid: expected_uid,
            directory_identity: (parent.dev, parent.ino),
            file_identity: (snapshot.dev, snapshot.ino),
            file_snapshot: snapshot,
            file_bytes: snapshot.size,
            records: Vec::new(),
            operations: BTreeMap::new(),
            requests: BTreeMap::new(),
            poisoned: false,
        };
        journal.load()?;
        journal.verify_binding(snapshot.size)?;
        // This also makes creation of an empty journal durable before reserve.
        journal.file.sync_all()?;
        journal.directory.sync_all()?;
        Ok(journal)
    }

    fn load(&mut self) -> Result<(), JournalError> {
        let mut buffer = [0_u8; 8192];
        let mut line = Vec::new();
        let mut total = 0_u64;
        loop {
            let remaining = (MAX_JOURNAL_FILE_BYTES + 1 - total).min(buffer.len() as u64) as usize;
            let count = self.file.read(&mut buffer[..remaining])?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > MAX_JOURNAL_FILE_BYTES {
                return Err(JournalError::JournalSizeLimitExceeded);
            }
            for byte in &buffer[..count] {
                // Refuse another record before allocating any of its body.
                if self.records.len() >= MAX_JOURNAL_RECORDS {
                    return Err(JournalError::JournalRecordLimitExceeded);
                }
                if *byte == b'\n' {
                    strict_json_object(&line, MAX_JOURNAL_RECORD_BYTES - 1)?;
                    let record: JournalRecordV1 =
                        serde_json::from_slice(&line).map_err(|_| JournalError::CorruptJournal)?;
                    self.check_next(&record)?;
                    self.index(record);
                    line.clear();
                } else {
                    // Reserve the last admitted byte for the NDJSON newline.
                    // A hostile line is never copied into an aggregate buffer.
                    if line.len() >= MAX_JOURNAL_RECORD_BYTES - 1 {
                        return Err(JournalError::RecordTooLarge);
                    }
                    line.push(*byte);
                }
            }
        }
        if !line.is_empty() {
            return Err(JournalError::CorruptJournal);
        }
        if total != self.file_bytes {
            return Err(JournalError::IdentityChanged);
        }
        Ok(())
    }

    fn verify_binding(&self, expected_size: u64) -> Result<FileSnapshot, JournalError> {
        if self.poisoned {
            return Err(JournalError::CorruptJournal);
        }
        let parent = check_directory(&self.directory, self.uid, true)?;
        let open = check_regular(&fstat(&self.file).map_err(fs_error)?, self.uid, true)?;
        let bound = check_regular(
            &statat(
                &self.directory,
                self.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(fs_error)?,
            self.uid,
            true,
        )?;
        if (parent.dev, parent.ino) != self.directory_identity
            || (open.dev, open.ino) != self.file_identity
            || open != bound
            || open.size != expected_size
            || (expected_size == self.file_bytes && open != self.file_snapshot)
        {
            return Err(JournalError::IdentityChanged);
        }
        Ok(open)
    }

    fn check_next(&self, record: &JournalRecordV1) -> Result<(), JournalError> {
        let key = operation_key(&record.request);
        if self
            .requests
            .get(&request_key(&record.request))
            .is_some_and(|existing| *existing != key)
        {
            return Err(JournalError::OperationReplayConflict);
        }
        let previous = self.operations.get(&key).map(|index| &self.records[*index]);
        validate_transition(previous, record)
    }

    fn index(&mut self, record: JournalRecordV1) {
        let key = operation_key(&record.request);
        self.requests
            .insert(request_key(&record.request), key.clone());
        self.operations.insert(key, self.records.len());
        self.records.push(record);
    }

    pub fn latest(
        &self,
        workspace: &str,
        source: &str,
        operation: &str,
    ) -> Option<&JournalRecordV1> {
        self.operations
            .get(&(
                workspace.to_owned(),
                source.to_owned(),
                operation.to_owned(),
            ))
            .map(|index| &self.records[*index])
    }

    /// A committed phase cannot be forgotten when the latest snapshot is Reconciling.
    /// The full qualified operation key is required; this scan is bounded by 4096 records.
    pub(crate) fn had_durable_file_commit(&self, request: &JournalRequestV1) -> bool {
        let key = operation_key(request);
        self.records().any(|record| {
            operation_key(&record.request) == key
                && record.state == WriteOperationState::FileCommitted
        })
    }

    /// All durable snapshots, in append order. Use latest_records for fencing.
    pub fn records(&self) -> impl Iterator<Item = &JournalRecordV1> {
        self.records.iter()
    }

    pub fn latest_records(&self) -> impl Iterator<Item = &JournalRecordV1> {
        self.operations.values().map(|index| &self.records[*index])
    }

    pub fn lookup_request(
        &self,
        request: &JournalRequestV1,
    ) -> Result<Option<&JournalRecordV1>, JournalError> {
        self.verify_binding(self.file_bytes)?;
        request.validate()?;
        let key = operation_key(request);
        let by_request = self
            .requests
            .get(&request_key(request))
            .and_then(|existing_key| self.operations.get(existing_key))
            .copied();
        let by_operation = self.operations.get(&key).copied();
        for index in [by_request, by_operation].into_iter().flatten() {
            if !same_replay_binding(&self.records[index].request, request) {
                return Err(JournalError::OperationReplayConflict);
            }
        }
        Ok(by_request
            .or(by_operation)
            .map(|index| &self.records[index]))
    }

    pub fn reserve(
        &mut self,
        request: JournalRequestV1,
    ) -> Result<ReplayDispositionV1, JournalError> {
        self.verify_binding(self.file_bytes)?;
        if let Some(existing) = self.lookup_request(&request)? {
            if matches!(
                existing.state,
                WriteOperationState::Acknowledged
                    | WriteOperationState::Recorded
                    | WriteOperationState::FileCommitted
                    | WriteOperationState::Rejected
                    | WriteOperationState::Held
            ) {
                return Ok(ReplayDispositionV1::DuplicateRecorded(existing.clone()));
            }
            return Ok(ReplayDispositionV1::Existing(existing.clone()));
        }
        let record = JournalRecordV1::received(request);
        self.append(record.clone())?;
        Ok(ReplayDispositionV1::Fresh(record))
    }

    /// The durable phase itself is the reservation receipt. Reopening derives
    /// the same remaining budget from latest snapshots, so a crash cannot lose
    /// an in-memory reservation or let another operation consume it.
    fn remaining_completion_records(state: WriteOperationState) -> usize {
        match state {
            WriteOperationState::Received => RESERVED_COMPLETION_RECORDS_AFTER_RECEIVED,
            WriteOperationState::Validated => 5,
            WriteOperationState::Prepared => RESERVED_COMPLETION_RECORDS_AFTER_PREPARED,
            WriteOperationState::Reconciling => 2,
            WriteOperationState::FileCommitted => 3,
            WriteOperationState::Recorded => 1,
            WriteOperationState::Acknowledged
            | WriteOperationState::Rejected
            | WriteOperationState::Held => 0,
        }
    }

    fn check_completion_capacity(
        &self,
        record: &JournalRecordV1,
        encoded_bytes: usize,
        appending: bool,
    ) -> Result<(), JournalError> {
        let key = operation_key(&record.request);
        let remaining = self
            .latest_records()
            .filter(|prior| operation_key(&prior.request) != key)
            .map(|prior| Self::remaining_completion_records(prior.state))
            .sum::<usize>()
            .checked_add(Self::remaining_completion_records(record.state))
            .ok_or(JournalError::JournalRecordLimitExceeded)?;
        let appended_records = usize::from(appending);
        let required_records = self
            .records
            .len()
            .checked_add(appended_records)
            .and_then(|count| count.checked_add(remaining))
            .ok_or(JournalError::JournalRecordLimitExceeded)?;
        if required_records > MAX_JOURNAL_RECORDS {
            return Err(JournalError::JournalRecordLimitExceeded);
        }
        let appended_bytes = if appending { encoded_bytes as u64 } else { 0 };
        let required_bytes = (remaining as u64)
            .checked_mul(MAX_JOURNAL_RECORD_BYTES as u64)
            .and_then(|reserved| self.file_bytes.checked_add(reserved))
            .and_then(|size| size.checked_add(appended_bytes))
            .ok_or(JournalError::JournalSizeLimitExceeded)?;
        if required_bytes > MAX_JOURNAL_FILE_BYTES {
            return Err(JournalError::JournalSizeLimitExceeded);
        }
        Ok(())
    }

    /// Call before staging/replacement and before projection. A caller may also
    /// preflight a complete next-phase placeholder before creating its inode.
    /// Every reserved future line is charged at the full inclusive 64 KiB bound.
    pub fn preflight_completion(&self, record: &JournalRecordV1) -> Result<(), JournalError> {
        self.verify_binding(self.file_bytes)?;
        record.validate()?;
        let bytes = encode_record(record)?;
        let key = operation_key(&record.request);
        let is_current = self
            .operations
            .get(&key)
            .is_some_and(|index| self.records[*index] == *record);
        if !is_current {
            self.check_next(record)?;
        }
        self.check_completion_capacity(record, bytes.len(), !is_current)
    }

    /// Preflight the largest complete future snapshot before any staging side
    /// effect. This is separate from aggregate capacity and transition checks.
    pub fn preflight_record_size(&self, record: &JournalRecordV1) -> Result<(), JournalError> {
        self.verify_binding(self.file_bytes)?;
        record.validate()?;
        encode_record(record).map(|_| ())
    }

    pub fn append(&mut self, record: JournalRecordV1) -> Result<(), JournalError> {
        self.verify_binding(self.file_bytes)?;
        self.check_next(&record)?;
        if self.records.len() >= MAX_JOURNAL_RECORDS {
            return Err(JournalError::JournalRecordLimitExceeded);
        }
        let bytes = encode_record(&record)?;
        self.check_completion_capacity(&record, bytes.len(), true)?;
        let new_size = self
            .file_bytes
            .checked_add(bytes.len() as u64)
            .filter(|size| *size <= MAX_JOURNAL_FILE_BYTES)
            .ok_or(JournalError::JournalSizeLimitExceeded)?;
        let write_result = (|| {
            self.file.write_all(&bytes)?;
            self.file.sync_all()?;
            self.directory.sync_all()?;
            self.verify_binding(new_size)
        })();
        let snapshot = match write_result {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.file_bytes = new_size;
        self.file_snapshot = snapshot;
        self.index(record);
        Ok(())
    }

    pub fn append_record(&mut self, record: JournalRecordV1) -> Result<(), JournalError> {
        self.append(record)
    }
}

fn same_replay_binding(previous: &JournalRequestV1, next: &JournalRequestV1) -> bool {
    previous.workspace_id == next.workspace_id
        && previous.task_source_id == next.task_source_id
        && previous.signer_principal == next.signer_principal
        && previous.request_id == next.request_id
        && previous.request_digest == next.request_digest
        && previous.nonce == next.nonce
        && previous.signed_task_ref == next.signed_task_ref
}

struct BoundedRecordBytes {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl Write for BoundedRecordBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > (MAX_JOURNAL_RECORD_BYTES - 1).saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("journal record byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_record(record: &JournalRecordV1) -> Result<Vec<u8>, JournalError> {
    let mut output = BoundedRecordBytes {
        bytes: Vec::new(),
        exceeded: false,
    };
    if serde_json::to_writer(&mut output, record).is_err() {
        return Err(if output.exceeded {
            JournalError::RecordTooLarge
        } else {
            JournalError::InvalidJson
        });
    }
    // Apply the same depth, object-count and key rules on both sides of disk.
    strict_json_object(&output.bytes, MAX_JOURNAL_RECORD_BYTES - 1)?;
    output.bytes.push(b'\n');
    Ok(output.bytes)
}

/// Checks every nested object before deserialization can erase duplicate keys.
/// The caller supplies its independently admitted document bound (for example
/// 1 MiB for a source document, or 64 KiB minus newline for a journal record).
pub(crate) fn strict_json_object(raw: &[u8], max_bytes: usize) -> Result<(), JournalError> {
    if raw.len() > max_bytes {
        return Err(JournalError::RecordTooLarge);
    }
    if raw.contains(&0) || raw.contains(&b'\r') {
        return Err(JournalError::InvalidJson);
    }
    if raw.iter().copied().find(|byte| !byte.is_ascii_whitespace()) != Some(b'{') {
        return Err(JournalError::InvalidJson);
    }
    let mut duplicate = false;
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    if JsonCheck(&mut duplicate).deserialize(&mut decoder).is_err() {
        return Err(if duplicate {
            JournalError::DuplicateJsonKey
        } else {
            JournalError::InvalidJson
        });
    }
    decoder.end().map_err(|_| JournalError::InvalidJson)
}

struct JsonCheck<'a>(&'a mut bool);

impl<'de> DeserializeSeed<'de> for JsonCheck<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonCheck<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON object without duplicate keys")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence
            .next_element_seed(JsonCheck(&mut *self.0))?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                *self.0 = true;
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            if keys.len() > MAX_JSON_OBJECT_KEYS {
                return Err(serde::de::Error::custom("JSON object key limit"));
            }
            map.next_value_seed(JsonCheck(&mut *self.0))?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryFileState {
    Predecessor,
    Successor,
    Other,
}

fn inspect_file(
    parent: &File,
    name: &str,
    uid: u32,
) -> Result<(FileSnapshot, [u8; 32]), JournalError> {
    component(name)?;
    let before = check_regular(
        &statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(fs_error)?,
        uid,
        false,
    )?;
    if !matches!(before.mode & 0o7777, 0o400 | 0o600) {
        return Err(JournalError::UnsafeMetadata);
    }
    if before.size > MAX_SOURCE_FILE_BYTES {
        return Err(JournalError::RecordTooLarge);
    }
    let mut file = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(fs_error)?,
    );
    if before != check_regular(&fstat(&file).map_err(fs_error)?, uid, false)? {
        return Err(JournalError::IdentityChanged);
    }
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = (MAX_SOURCE_FILE_BYTES + 1 - total).min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..remaining])?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_SOURCE_FILE_BYTES {
            return Err(JournalError::RecordTooLarge);
        }
        hash.update(&buffer[..read]);
    }
    let bound = check_regular(
        &statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(fs_error)?,
        uid,
        false,
    )?;
    if total != before.size
        || before != bound
        || before != check_regular(&fstat(&file).map_err(fs_error)?, uid, false)?
    {
        return Err(JournalError::IdentityChanged);
    }
    Ok((before, hash.finalize().into()))
}

fn check_prepared_parent(
    parent: &File,
    prepared: &PreparedWriteV1,
    uid: u32,
) -> Result<(), JournalError> {
    prepared.validate()?;
    let snapshot = check_directory(parent, uid, false)?;
    if (snapshot.dev, snapshot.ino) != (prepared.parent_dev, prepared.parent_ino) {
        return Err(JournalError::IdentityChanged);
    }
    Ok(())
}

/// Classifies both bytes and pinned inode identity. A third file containing
/// matching bytes is still external namespace drift, not a committed proposal.
pub fn inspect_prepared(
    parent: &File,
    prepared: &PreparedWriteV1,
    uid: u32,
) -> Result<RecoveryFileState, JournalError> {
    check_prepared_parent(parent, prepared, uid)?;
    let (file, hash) = inspect_file(parent, &prepared.target_name, uid)?;
    check_prepared_parent(parent, prepared, uid)?;
    if (file.dev, file.ino) == (prepared.previous_dev, prepared.previous_ino)
        && file.size == prepared.expected_preimage_bytes
        && hash == prepared.predecessor_hash
    {
        Ok(RecoveryFileState::Predecessor)
    } else if (file.dev, file.ino) == (prepared.staged_dev, prepared.staged_ino)
        && file.size == prepared.committed_postimage_bytes
        && hash == prepared.successor_hash
    {
        Ok(RecoveryFileState::Successor)
    } else {
        Ok(RecoveryFileState::Other)
    }
}

/// Required before resuming F0: a durable Prepared line alone cannot establish
/// that the staged successor survived, is complete, or retains its identity.
pub fn verify_prepared_stage(
    parent: &File,
    prepared: &PreparedWriteV1,
    uid: u32,
) -> Result<(), JournalError> {
    check_prepared_parent(parent, prepared, uid)?;
    let (file, hash) = inspect_file(parent, &prepared.temp_name, uid)?;
    if (file.dev, file.ino) != (prepared.staged_dev, prepared.staged_ino)
        || file.size != prepared.committed_postimage_bytes
        || hash != prepared.successor_hash
    {
        return Err(JournalError::IdentityChanged);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedRecoveryDisposition {
    Predecessor(JournalRecordV1),
    Recorded(JournalRecordV1),
    Held(JournalRecordV1),
}

/// F0 is preserved for the original writer operation to resume only after
/// complete revalidation and staged-file verification. F1 is never replaced a
/// second time: directory sync and the projection callback precede Recorded.
/// Fx is preserved and held. Callback failure leaves the last durable phase
/// intact and cannot emit a success acknowledgment. The callback durably records
/// projection evidence and returns no journal payload. A fixed Recorded receipt
/// is fully preflighted before the callback; projection-specific evidence stays
/// in the durable projection store.
pub fn classify_and_recover_prepared_operation(
    journal: &mut Journal,
    parent: &File,
    workspace: &str,
    source: &str,
    operation: &str,
    mut revalidate: impl FnMut(&JournalRecordV1) -> Result<(), JournalError>,
    mut record_projection: impl FnMut(&JournalRecordV1) -> Result<(), JournalError>,
) -> Result<PreparedRecoveryDisposition, JournalError> {
    let mut record = journal
        .latest(workspace, source, operation)
        .cloned()
        .ok_or(JournalError::InvalidTransition)?;
    if !matches!(
        record.state,
        WriteOperationState::Prepared
            | WriteOperationState::FileCommitted
            | WriteOperationState::Reconciling
    ) {
        return Err(JournalError::InvalidTransition);
    }
    let prepared = record
        .prepared
        .clone()
        .ok_or(JournalError::CorruptJournal)?;
    let had_file_commit = journal.had_durable_file_commit(&record.request);
    journal.preflight_completion(&record)?;
    if matches!(
        record.state,
        WriteOperationState::Prepared | WriteOperationState::FileCommitted
    ) {
        record.state = WriteOperationState::Reconciling;
        journal.append(record.clone())?;
    }
    let uid = journal.uid;
    check_prepared_parent(parent, &prepared, uid)?;
    match inspect_prepared(parent, &prepared, uid).unwrap_or(RecoveryFileState::Other) {
        RecoveryFileState::Predecessor => {
            if had_file_commit {
                record.state = WriteOperationState::Held;
                record.result = Some(serde_json::json!({
                    "disposition": "held", "reason": "durable_file_commit_has_predecessor_bytes"
                }));
                journal.append(record.clone())?;
                return Ok(PreparedRecoveryDisposition::Held(record));
            }
            revalidate(&record)?;
            verify_prepared_stage(parent, &prepared, uid)?;
            Ok(PreparedRecoveryDisposition::Predecessor(record))
        }
        RecoveryFileState::Successor => {
            revalidate(&record)?;
            journal.preflight_completion(&record)?;
            parent.sync_all()?;
            let mut recorded = record.clone();
            recorded.state = WriteOperationState::Recorded;
            recorded.result = Some(serde_json::json!({"disposition": "Recorded"}));
            // Check the complete next line and ACK reservation before projection.
            journal.preflight_completion(&recorded)?;
            record_projection(&record)?;
            // Do not record a projection if canonical bytes drifted during it.
            if inspect_prepared(parent, &prepared, uid)? != RecoveryFileState::Successor {
                return Err(JournalError::IdentityChanged);
            }
            journal.append(recorded.clone())?;
            Ok(PreparedRecoveryDisposition::Recorded(recorded))
        }
        RecoveryFileState::Other => {
            record.state = WriteOperationState::Held;
            record.result = Some(serde_json::json!({
                "disposition": "held", "reason": "canonical_file_differs_from_prepared_states"
            }));
            journal.append(record.clone())?;
            Ok(PreparedRecoveryDisposition::Held(record))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use tempfile::TempDir;

    fn store() -> (TempDir, File, u32) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(directory.path()).unwrap();
        let uid = file.metadata().unwrap().uid();
        (directory, file, uid)
    }

    fn request(operation: &str) -> JournalRequestV1 {
        JournalRequestV1 {
            workspace_id: "workspace".to_owned(),
            task_source_id: "0123456789abcdef0123456789abcdef".to_owned(),
            operation_id: operation.to_owned(),
            signer_principal: "signer".to_owned(),
            request_id: format!("request-{operation}"),
            request_digest: [1; 32],
            nonce: [2; 32],
            writer_epoch: 1,
            signed_task_ref: vec![1, 2, 3],
            metadata: serde_json::json!({"lease": "original"}),
        }
    }

    fn reserve(journal: &mut Journal, operation: &str) -> JournalRecordV1 {
        match journal.reserve(request(operation)).unwrap() {
            ReplayDispositionV1::Fresh(record) => record,
            ReplayDispositionV1::Existing(_) | ReplayDispositionV1::DuplicateRecorded(_) => {
                panic!("expected fresh operation")
            }
        }
    }

    fn prepared_fixture(directory: &TempDir, parent: &File) -> PreparedWriteV1 {
        fs::write(directory.path().join("TASKS.md"), b"predecessor").unwrap();
        fs::write(directory.path().join("stage.tmp"), b"successor").unwrap();
        for name in ["TASKS.md", "stage.tmp"] {
            fs::set_permissions(
                directory.path().join(name),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let previous = fs::metadata(directory.path().join("TASKS.md")).unwrap();
        let staged = fs::metadata(directory.path().join("stage.tmp")).unwrap();
        let parent = parent.metadata().unwrap();
        PreparedWriteV1 {
            canonical_relative_path: "TASKS.md".to_owned(),
            target_name: "TASKS.md".to_owned(),
            temp_name: "stage.tmp".to_owned(),
            parent_dev: parent.dev(),
            parent_ino: parent.ino(),
            previous_dev: previous.dev(),
            previous_ino: previous.ino(),
            staged_dev: staged.dev(),
            staged_ino: staged.ino(),
            predecessor_hash: Sha256::digest(b"predecessor").into(),
            successor_hash: Sha256::digest(b"successor").into(),
            predecessor_revision: 7,
            successor_revision: 8,
            proposal_expected_file_cas_rev: 7,
            expected_file_cas_rev: 7,
            rebases_used: 0,
            expected_preimage_bytes: b"predecessor".len() as u64,
            committed_postimage_bytes: b"successor".len() as u64,
        }
    }

    fn prepare(journal: &mut Journal, prepared: PreparedWriteV1) -> JournalRecordV1 {
        let mut record = reserve(journal, "op");
        record.state = WriteOperationState::Validated;
        journal.append(record.clone()).unwrap();
        record.state = WriteOperationState::Prepared;
        record.unrelated_file_rebases = prepared.rebases_used;
        record.prepared = Some(prepared);
        journal.append(record.clone()).unwrap();
        record
    }

    fn terminal_history(count: usize) -> Vec<JournalRecordV1> {
        assert!(count != 1);
        let mut history = Vec::new();
        while history.len() < count {
            let mut record = JournalRecordV1::received(request(&format!("past-{}", history.len())));
            history.push(record.clone());
            if count - history.len() == 2 {
                record.state = WriteOperationState::Validated;
                history.push(record.clone());
            }
            record.state = WriteOperationState::Rejected;
            record.result = Some(serde_json::json!({"disposition": "rejected"}));
            history.push(record);
        }
        assert_eq!(history.len(), count);
        history
    }

    fn write_history(directory: &TempDir, bytes: &[u8]) {
        let path = directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn padded_record(record: &JournalRecordV1, length: usize) -> Vec<u8> {
        let mut bytes = encode_record(record).unwrap();
        assert!(bytes.len() <= length && length <= MAX_JOURNAL_RECORD_BYTES);
        bytes.pop();
        bytes.resize(length - 1, b' ');
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn p0_writer_journal_received_and_rejected_survive_restart_and_replay() {
        let (_directory, parent, uid) = store();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut record = reserve(&mut journal, "op");
        record.state = WriteOperationState::Rejected;
        record.result = Some(serde_json::json!({"receipt": "stable-rejection"}));
        journal.append(record.clone()).unwrap();
        drop(journal);
        let mut reopened = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert_eq!(
            reopened.reserve(request("op")).unwrap(),
            ReplayDispositionV1::DuplicateRecorded(record)
        );
        assert_eq!(reopened.records().count(), 2);
    }

    #[test]
    fn p0_writer_journal_operation_and_request_keys_both_reject_changed_replay() {
        let (_directory, parent, uid) = store();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        reserve(&mut journal, "op");
        for changed in 0..4 {
            let mut proposal = request("op");
            match changed {
                0 => proposal.request_digest[0] ^= 1,
                1 => proposal.nonce[0] ^= 1,
                2 => proposal.signed_task_ref.push(4),
                _ => proposal.task_source_id = "fedcba9876543210fedcba9876543210".to_owned(),
            }
            assert!(matches!(
                journal.reserve(proposal),
                Err(JournalError::OperationReplayConflict)
            ));
        }
        let mut identical = request("op");
        identical.operation_id = "operation-alias".to_owned();
        identical.writer_epoch = 2;
        identical.metadata = serde_json::json!({"lease": "refreshed"});
        assert!(matches!(
            journal.reserve(identical).unwrap(),
            ReplayDispositionV1::Existing(_)
        ));
        assert_eq!(journal.records().count(), 1);
    }

    #[test]
    fn p0_writer_journal_authoritative_name_and_namespace_lock_survive_reopen() {
        let (directory, parent, uid) = store();
        let first = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert!(matches!(
            Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid),
            Err(JournalError::LockUnavailable)
        ));
        assert!(matches!(
            Journal::open(&parent, "second.ndjson", uid),
            Err(JournalError::InvalidName)
        ));
        assert!(!directory.path().join("second.ndjson").exists());
        drop(first);
        assert!(matches!(
            Journal::open(&parent, "second.ndjson", uid),
            Err(JournalError::InvalidName)
        ));
        assert!(Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).is_ok());
    }

    #[test]
    fn p0_writer_journal_strict_json_rejects_nested_and_escaped_duplicate_keys() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":{"b":1,"\u0062":2}}"#.as_slice(),
        ] {
            assert!(matches!(
                strict_json_object(bytes, 1024),
                Err(JournalError::DuplicateJsonKey)
            ));
        }
        assert!(strict_json_object(br#"{"a":[{"b":1},{"b":2}]}"#, 1024).is_ok());
        assert!(strict_json_object(br#"{"a":1} {}"#, 1024).is_err());
        assert!(strict_json_object(b"[]", 1024).is_err());
    }

    #[test]
    fn p0_writer_journal_truncation_unknown_state_and_unknown_field_hold_evidence() {
        for mutation in 0..3 {
            let (directory, parent, uid) = store();
            let mut bytes = encode_record(&JournalRecordV1::received(request("op"))).unwrap();
            match mutation {
                0 => {
                    bytes.pop();
                }
                1 => {
                    bytes = String::from_utf8(bytes)
                        .unwrap()
                        .replace("\"received\"", "\"invented\"")
                        .into_bytes();
                }
                _ => {
                    bytes = String::from_utf8(bytes)
                        .unwrap()
                        .replacen('{', "{\"unknown\":0,", 1)
                        .into_bytes();
                }
            }
            let path = directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME);
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).is_err());
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn p0_writer_journal_symlink_hardlink_private_permissions_and_owner_refuse() {
        let (directory, parent, uid) = store();
        let real = directory.path().join("real");
        let authoritative = directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME);
        fs::write(&real, b"").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        symlink("real", &authoritative).unwrap();
        assert!(matches!(
            Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid),
            Err(JournalError::SymlinkRejected)
        ));
        fs::remove_file(&authoritative).unwrap();
        fs::hard_link(&real, &authoritative).unwrap();
        assert!(matches!(
            Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid),
            Err(JournalError::HardlinkRejected)
        ));
        fs::remove_file(&authoritative).unwrap();
        fs::rename(&real, &authoritative).unwrap();
        fs::set_permissions(&authoritative, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid),
            Err(JournalError::UnsafeMetadata)
        ));
        assert!(matches!(
            Journal::open(
                &parent,
                AUTHORITATIVE_JOURNAL_FILE_NAME,
                uid.wrapping_add(1)
            ),
            Err(JournalError::UnsafeMetadata)
        ));
    }

    #[test]
    fn p0_writer_journal_closed_transitions_and_immutable_prepared_metadata() {
        let mut state = WriteOperationState::Prepared;
        assert!(state.can_transition_to(WriteOperationState::Rejected));
        state.transition_to(WriteOperationState::Rejected).unwrap();
        assert!(state.transition_to(WriteOperationState::Validated).is_err());
        assert_eq!(state, WriteOperationState::Rejected);
        assert!(
            WriteOperationState::FileCommitted.can_transition_to(WriteOperationState::Reconciling)
        );
        assert!(WriteOperationState::Reconciling.can_transition_to(WriteOperationState::Recorded));
        assert!(
            !WriteOperationState::Reconciling.can_transition_to(WriteOperationState::FileCommitted)
        );
        assert!(WriteOperationState::Recorded.can_transition_to(WriteOperationState::Held));
        let (directory, parent, uid) = store();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut record = reserve(&mut journal, "op");
        record.state = WriteOperationState::Acknowledged;
        record.result = Some(serde_json::json!({"receipt": "forged"}));
        assert!(journal.append(record).is_err());
        let mut record = journal
            .latest("workspace", &request("op").task_source_id, "op")
            .unwrap()
            .clone();
        record.state = WriteOperationState::Validated;
        journal.append(record.clone()).unwrap();
        record.state = WriteOperationState::Prepared;
        record.prepared = Some(prepared_fixture(&directory, &parent));
        journal.append(record.clone()).unwrap();
        record.state = WriteOperationState::Reconciling;
        record.prepared.as_mut().unwrap().successor_hash[0] ^= 1;
        assert!(matches!(
            journal.append(record),
            Err(JournalError::InvalidTransition)
        ));
    }

    #[test]
    fn p0_writer_journal_record_exact_bound_and_overflow_precede_disk_append() {
        let (directory, parent, uid) = store();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut proposal = request("op");
        let base = encode_record(&JournalRecordV1::received(proposal.clone()))
            .unwrap()
            .len();
        proposal.metadata["padding"] = Value::String(String::new());
        let with_empty = encode_record(&JournalRecordV1::received(proposal.clone()))
            .unwrap()
            .len();
        assert!(with_empty > base);
        proposal.metadata["padding"] =
            Value::String("x".repeat(MAX_JOURNAL_RECORD_BYTES - with_empty));
        assert_eq!(
            encode_record(&JournalRecordV1::received(proposal.clone()))
                .unwrap()
                .len(),
            MAX_JOURNAL_RECORD_BYTES
        );
        journal.reserve(proposal.clone()).unwrap();
        proposal.operation_id = "oq".to_owned();
        proposal.request_id = "request-oq".to_owned();
        proposal.metadata["padding"] =
            Value::String("x".repeat(MAX_JOURNAL_RECORD_BYTES - with_empty + 1));
        assert!(matches!(
            journal.reserve(proposal),
            Err(JournalError::RecordTooLarge)
        ));
        assert_eq!(journal.records().count(), 1);
        drop(journal);
        let reopened = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert_eq!(reopened.records().count(), 1);
        drop(reopened);
        let path = directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME);
        let mut overlong = vec![b'x'; MAX_JOURNAL_RECORD_BYTES];
        overlong.push(b'\n');
        fs::write(&path, &overlong).unwrap();
        assert!(matches!(
            Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid),
            Err(JournalError::RecordTooLarge)
        ));
        assert_eq!(fs::read(path).unwrap(), overlong);
    }

    #[test]
    fn p0_writer_journal_aggregate_and_record_count_bounds_are_inclusive() {
        let (directory, parent, uid) = store();
        let path = directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME);
        let mut bytes = Vec::new();
        for index in 0..MAX_JOURNAL_RECORDS {
            bytes.extend(
                encode_record(&JournalRecordV1::received(request(&format!("op-{index}")))).unwrap(),
            );
        }
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert_eq!(journal.records().count(), MAX_JOURNAL_RECORDS);
        assert!(matches!(
            journal.reserve(request("extra")),
            Err(JournalError::JournalRecordLimitExceeded)
        ));
        drop(journal);
        bytes.extend(encode_record(&JournalRecordV1::received(request("extra"))).unwrap());
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid),
            Err(JournalError::JournalRecordLimitExceeded)
        ));

        bytes.clear();
        for index in 0..(MAX_JOURNAL_FILE_BYTES as usize / MAX_JOURNAL_RECORD_BYTES) {
            let mut record = JournalRecordV1::received(request(&format!("large-{index}")));
            record.request.metadata["padding"] = Value::String(String::new());
            let base = encode_record(&record).unwrap().len();
            record.request.metadata["padding"] =
                Value::String("x".repeat(MAX_JOURNAL_RECORD_BYTES - base));
            bytes.extend(encode_record(&record).unwrap());
        }
        assert_eq!(bytes.len() as u64, MAX_JOURNAL_FILE_BYTES);
        fs::write(&path, &bytes).unwrap();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert!(matches!(
            journal.reserve(request("extra")),
            Err(JournalError::JournalSizeLimitExceeded)
        ));
        drop(journal);
        let mut raw = OpenOptions::new().append(true).open(&path).unwrap();
        raw.write_all(b"x").unwrap();
        assert!(matches!(
            Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid),
            Err(JournalError::JournalSizeLimitExceeded)
        ));
    }

    #[test]
    fn p0_writer_journal_record_completion_reservation_refuses_before_admission() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        let history: Vec<u8> = terminal_history(MAX_JOURNAL_RECORDS - 6)
            .iter()
            .flat_map(|record| encode_record(record).unwrap())
            .collect();
        write_history(&directory, &history);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert!(matches!(
            journal.reserve(request("op")),
            Err(JournalError::JournalRecordLimitExceeded)
        ));
        assert_eq!(journal.records().count(), MAX_JOURNAL_RECORDS - 6);
        assert_eq!(
            fs::read(directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME)).unwrap(),
            history
        );
        assert_eq!(
            inspect_prepared(&parent, &prepared, uid).unwrap(),
            RecoveryFileState::Predecessor
        );
    }

    #[test]
    fn p0_writer_journal_record_reservation_survives_prepared_crash_at_exact_limit() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        let history: Vec<u8> = terminal_history(MAX_JOURNAL_RECORDS - 7)
            .iter()
            .flat_map(|record| encode_record(record).unwrap())
            .collect();
        write_history(&directory, &history);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut record = prepare(&mut journal, prepared.clone());
        assert_eq!(journal.records().count(), MAX_JOURNAL_RECORDS - 4);
        assert!(matches!(
            journal.reserve(request("interloper")),
            Err(JournalError::JournalRecordLimitExceeded)
        ));
        fs::rename(
            directory.path().join("stage.tmp"),
            directory.path().join("TASKS.md"),
        )
        .unwrap();
        record.state = WriteOperationState::FileCommitted;
        journal.append(record).unwrap();
        drop(journal);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let recovered = classify_and_recover_prepared_operation(
            &mut journal,
            &parent,
            "workspace",
            &request("op").task_source_id,
            "op",
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        let PreparedRecoveryDisposition::Recorded(mut record) = recovered else {
            panic!("F1 must recover");
        };
        record.state = WriteOperationState::Acknowledged;
        journal.append(record).unwrap();
        assert_eq!(journal.records().count(), MAX_JOURNAL_RECORDS);
        assert_eq!(
            inspect_prepared(&parent, &prepared, uid).unwrap(),
            RecoveryFileState::Successor
        );
        drop(journal);
        let journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert_eq!(journal.records().count(), MAX_JOURNAL_RECORDS);
    }

    #[test]
    fn p0_writer_journal_byte_reservation_boundary_and_recovery_after_crash() {
        for excess in [0_u64, 1] {
            let (directory, parent, uid) = store();
            let prepared = prepared_fixture(&directory, &parent);
            let received_bytes = encode_record(&JournalRecordV1::received(request("op")))
                .unwrap()
                .len() as u64;
            let history_bytes =
                MAX_JOURNAL_FILE_BYTES - 6 * MAX_JOURNAL_RECORD_BYTES as u64 - received_bytes
                    + excess;
            let history = terminal_history(250);
            let mut bytes = Vec::new();
            for record in &history[..249] {
                bytes.extend(padded_record(record, MAX_JOURNAL_RECORD_BYTES));
            }
            let final_length = history_bytes as usize - bytes.len();
            bytes.extend(padded_record(&history[249], final_length));
            assert_eq!(bytes.len() as u64, history_bytes);
            write_history(&directory, &bytes);
            let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
            if excess == 1 {
                assert!(matches!(
                    journal.reserve(request("op")),
                    Err(JournalError::JournalSizeLimitExceeded)
                ));
                assert_eq!(
                    fs::read(directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME)).unwrap(),
                    bytes
                );
                assert_eq!(
                    inspect_prepared(&parent, &prepared, uid).unwrap(),
                    RecoveryFileState::Predecessor
                );
                continue;
            }
            prepare(&mut journal, prepared.clone());
            fs::rename(
                directory.path().join("stage.tmp"),
                directory.path().join("TASKS.md"),
            )
            .unwrap();
            drop(journal);
            let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
            let recovered = classify_and_recover_prepared_operation(
                &mut journal,
                &parent,
                "workspace",
                &request("op").task_source_id,
                "op",
                |_| Ok(()),
                |_| Ok(()),
            )
            .unwrap();
            let PreparedRecoveryDisposition::Recorded(mut record) = recovered else {
                panic!("F1 must recover");
            };
            record.state = WriteOperationState::Acknowledged;
            journal.append(record).unwrap();
            assert!(
                fs::metadata(directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME))
                    .unwrap()
                    .len()
                    <= MAX_JOURNAL_FILE_BYTES
            );
        }
    }

    #[test]
    fn p0_writer_journal_rebase_allowance_survives_restart_and_cannot_reset() {
        let (directory, parent, uid) = store();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut record = reserve(&mut journal, "op");
        record.state = WriteOperationState::Validated;
        record.unrelated_file_rebases = 1;
        journal.append(record.clone()).unwrap();
        let mut invalid_self_transition = record.clone();
        invalid_self_transition.unrelated_file_rebases = 2;
        assert!(matches!(
            journal.append(invalid_self_transition),
            Err(JournalError::InvalidTransition)
        ));
        record.state = WriteOperationState::Prepared;
        record.unrelated_file_rebases = 2;
        record.prepared = Some(prepared_fixture(&directory, &parent));
        record
            .prepared
            .as_mut()
            .unwrap()
            .proposal_expected_file_cas_rev = 5;
        record.prepared.as_mut().unwrap().rebases_used = 2;
        journal.append(record.clone()).unwrap();
        drop(journal);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let replay = journal.lookup_request(&request("op")).unwrap().unwrap();
        assert_eq!(replay.unrelated_file_rebases, 2);
        let journal_path = directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME);
        let before_invalid = fs::read(&journal_path).unwrap();
        record.state = WriteOperationState::Reconciling;
        record.unrelated_file_rebases = 0;
        // The typed consistency check may reject before the phase validator.
        // The required contract is no reset and no durable append.
        assert!(journal.append(record.clone()).is_err());
        assert_eq!(fs::read(&journal_path).unwrap(), before_invalid);
        let retained = journal.lookup_request(&request("op")).unwrap().unwrap();
        assert_eq!(retained.unrelated_file_rebases, 2);
        record.unrelated_file_rebases = 3;
        assert!(journal.append(record).is_err());
        assert_eq!(fs::read(&journal_path).unwrap(), before_invalid);
        drop(journal);
        let reopened = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let retained = reopened.lookup_request(&request("op")).unwrap().unwrap();
        assert_eq!(retained.unrelated_file_rebases, 2);
        assert_eq!(fs::read(&journal_path).unwrap(), before_invalid);
    }

    #[test]
    fn p0_writer_journal_recovery_f0_preserves_original_and_checks_stage() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        prepare(&mut journal, prepared.clone());
        drop(journal);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut projections = 0;
        let outcome = classify_and_recover_prepared_operation(
            &mut journal,
            &parent,
            "workspace",
            &request("op").task_source_id,
            "op",
            |_| Ok(()),
            |_| {
                projections += 1;
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            outcome,
            PreparedRecoveryDisposition::Predecessor(_)
        ));
        assert_eq!(projections, 0);
        assert_eq!(
            fs::read(directory.path().join("TASKS.md")).unwrap(),
            b"predecessor"
        );
        fs::write(directory.path().join("stage.tmp"), b"partial").unwrap();
        assert!(verify_prepared_stage(&parent, &prepared, uid).is_err());
    }

    #[test]
    fn p0_writer_journal_recovery_f1_records_projection_once_without_replacement() {
        let (directory, parent, uid) = store();
        let mut prepared = prepared_fixture(&directory, &parent);
        prepared.proposal_expected_file_cas_rev = 5;
        prepared.rebases_used = 2;
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        prepare(&mut journal, prepared.clone());
        fs::rename(
            directory.path().join("stage.tmp"),
            directory.path().join("TASKS.md"),
        )
        .unwrap();
        drop(journal);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut projections = 0;
        let outcome = classify_and_recover_prepared_operation(
            &mut journal,
            &parent,
            "workspace",
            &request("op").task_source_id,
            "op",
            |_| Ok(()),
            |_| {
                projections += 1;
                Ok(())
            },
        )
        .unwrap();
        let PreparedRecoveryDisposition::Recorded(recovered) = outcome else {
            panic!("F1 must recover");
        };
        assert_eq!(
            recovered.result,
            Some(serde_json::json!({"disposition": "Recorded"}))
        );
        let recovered_prepared = recovered.prepared.unwrap();
        assert_eq!(recovered_prepared.proposal_expected_file_cas_rev, 5);
        assert_eq!(recovered_prepared.expected_file_cas_rev, 7);
        assert_eq!(recovered_prepared.rebases_used, 2);
        assert_eq!(
            recovered_prepared.expected_preimage_bytes,
            b"predecessor".len() as u64
        );
        assert_eq!(
            recovered_prepared.committed_postimage_bytes,
            b"successor".len() as u64
        );
        assert_eq!(projections, 1);
        assert_eq!(
            fs::metadata(directory.path().join("TASKS.md"))
                .unwrap()
                .ino(),
            prepared.staged_ino
        );
        let mut record = journal
            .latest("workspace", &request("op").task_source_id, "op")
            .unwrap()
            .clone();
        record.state = WriteOperationState::Acknowledged;
        journal.append(record.clone()).unwrap();
        drop(journal);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert_eq!(
            journal.reserve(request("op")).unwrap(),
            ReplayDispositionV1::DuplicateRecorded(record)
        );
    }

    #[test]
    fn p0_writer_journal_recovery_fx_holds_and_preserves_external_bytes() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        prepare(&mut journal, prepared);
        fs::write(directory.path().join("TASKS.md"), b"external-third-state").unwrap();
        let outcome = classify_and_recover_prepared_operation(
            &mut journal,
            &parent,
            "workspace",
            &request("op").task_source_id,
            "op",
            |_| panic!("Fx must not revalidate to commit"),
            |_| panic!("Fx must not project"),
        )
        .unwrap();
        assert!(matches!(outcome, PreparedRecoveryDisposition::Held(_)));
        assert_eq!(
            fs::read(directory.path().join("TASKS.md")).unwrap(),
            b"external-third-state"
        );
        assert_eq!(
            journal.latest_records().next().unwrap().state,
            WriteOperationState::Held
        );
    }

    #[test]
    fn p0_writer_journal_recovery_preflights_recorded_line_before_projection() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        let mut largest_before_projection = JournalRecordV1::received(request("op"));
        largest_before_projection.request.metadata["padding"] = Value::String(String::new());
        largest_before_projection.state = WriteOperationState::Reconciling;
        largest_before_projection.prepared = Some(prepared.clone());
        let base = encode_record(&largest_before_projection).unwrap().len();
        largest_before_projection.request.metadata["padding"] =
            Value::String("x".repeat(MAX_JOURNAL_RECORD_BYTES - base));
        assert_eq!(
            encode_record(&largest_before_projection).unwrap().len(),
            MAX_JOURNAL_RECORD_BYTES
        );
        let mut would_be_recorded = largest_before_projection.clone();
        would_be_recorded.state = WriteOperationState::Recorded;
        would_be_recorded.result = Some(serde_json::json!({"disposition": "Recorded"}));
        assert!(matches!(
            encode_record(&would_be_recorded),
            Err(JournalError::RecordTooLarge)
        ));
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let ReplayDispositionV1::Fresh(mut record) = journal
            .reserve(largest_before_projection.request.clone())
            .unwrap()
        else {
            panic!("expected fresh operation");
        };
        record.state = WriteOperationState::Validated;
        journal.append(record.clone()).unwrap();
        record.state = WriteOperationState::Prepared;
        record.prepared = Some(prepared.clone());
        journal.append(record).unwrap();
        fs::rename(
            directory.path().join("stage.tmp"),
            directory.path().join("TASKS.md"),
        )
        .unwrap();
        let canonical = fs::read(directory.path().join("TASKS.md")).unwrap();
        drop(journal);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        let mut projections = 0;
        let outcome = classify_and_recover_prepared_operation(
            &mut journal,
            &parent,
            "workspace",
            &request("op").task_source_id,
            "op",
            |_| Ok(()),
            |_| {
                projections += 1;
                Ok(())
            },
        );
        assert!(matches!(outcome, Err(JournalError::RecordTooLarge)));
        assert_eq!(projections, 0);
        assert_eq!(
            journal.latest_records().next().unwrap().state,
            WriteOperationState::Reconciling
        );
        assert_eq!(
            fs::read(directory.path().join("TASKS.md")).unwrap(),
            canonical
        );
        assert_eq!(
            fs::metadata(directory.path().join("TASKS.md"))
                .unwrap()
                .ino(),
            prepared.staged_ino
        );
        drop(journal);
        let journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        assert_eq!(
            journal.latest_records().next().unwrap().state,
            WriteOperationState::Reconciling
        );
    }
    #[test]
    fn p0_writer_journal_recovery_projection_failure_and_wrong_parent_do_not_record() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        prepare(&mut journal, prepared.clone());
        let (_wrong_directory, wrong_parent, _) = store();
        assert!(matches!(
            inspect_prepared(&wrong_parent, &prepared, uid),
            Err(JournalError::IdentityChanged)
        ));
        fs::rename(
            directory.path().join("stage.tmp"),
            directory.path().join("TASKS.md"),
        )
        .unwrap();
        assert!(
            classify_and_recover_prepared_operation(
                &mut journal,
                &parent,
                "workspace",
                &request("op").task_source_id,
                "op",
                |_| Ok(()),
                |_| Err(JournalError::Io(io::Error::other("projection failed")))
            )
            .is_err()
        );
        assert_eq!(
            journal.latest_records().next().unwrap().state,
            WriteOperationState::Reconciling
        );
        assert_eq!(
            fs::read(directory.path().join("TASKS.md")).unwrap(),
            b"successor"
        );
    }

    #[test]
    fn p0_writer_journal_replaced_namespace_and_appended_corruption_are_detected() {
        let (directory, parent, uid) = store();
        let mut journal = Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).unwrap();
        reserve(&mut journal, "op");
        fs::rename(
            directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME),
            directory.path().join("old.ndjson"),
        )
        .unwrap();
        let replacement = directory.path().join(AUTHORITATIVE_JOURNAL_FILE_NAME);
        fs::write(&replacement, b"").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            journal.reserve(request("other")),
            Err(JournalError::IdentityChanged)
        ));
        drop(journal);
        fs::remove_file(&replacement).unwrap();
        fs::rename(directory.path().join("old.ndjson"), &replacement).unwrap();
        let mut raw = OpenOptions::new().append(true).open(&replacement).unwrap();
        raw.write_all(b"{bad}\n").unwrap();
        assert!(Journal::open(&parent, AUTHORITATIVE_JOURNAL_FILE_NAME, uid).is_err());
    }

    #[test]
    fn p0_writer_journal_source_bound_and_identical_bytes_on_wrong_inode_hold() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        fs::write(directory.path().join("third.tmp"), b"predecessor").unwrap();
        fs::set_permissions(
            directory.path().join("third.tmp"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::rename(
            directory.path().join("third.tmp"),
            directory.path().join("TASKS.md"),
        )
        .unwrap();
        assert_eq!(
            inspect_prepared(&parent, &prepared, uid).unwrap(),
            RecoveryFileState::Other
        );
        let mut file = OpenOptions::new()
            .write(true)
            .open(directory.path().join("TASKS.md"))
            .unwrap();
        file.set_len(MAX_SOURCE_FILE_BYTES + 1).unwrap();
        file.seek(SeekFrom::Start(MAX_SOURCE_FILE_BYTES)).unwrap();
        file.write_all(b"x").unwrap();
        assert!(matches!(
            inspect_prepared(&parent, &prepared, uid),
            Err(JournalError::RecordTooLarge)
        ));
    }

    #[test]
    fn p0_writer_journal_recovery_requires_both_persisted_byte_lengths() {
        let (directory, parent, uid) = store();
        let prepared = prepared_fixture(&directory, &parent);
        let mut incorrect = prepared.clone();
        incorrect.expected_preimage_bytes += 1;
        assert_eq!(
            inspect_prepared(&parent, &incorrect, uid).unwrap(),
            RecoveryFileState::Other
        );
        incorrect = prepared.clone();
        incorrect.committed_postimage_bytes += 1;
        assert!(matches!(
            verify_prepared_stage(&parent, &incorrect, uid),
            Err(JournalError::IdentityChanged)
        ));
        fs::rename(
            directory.path().join("stage.tmp"),
            directory.path().join("TASKS.md"),
        )
        .unwrap();
        assert_eq!(
            inspect_prepared(&parent, &incorrect, uid).unwrap(),
            RecoveryFileState::Other
        );
        assert_eq!(
            inspect_prepared(&parent, &prepared, uid).unwrap(),
            RecoveryFileState::Successor
        );
    }
}
