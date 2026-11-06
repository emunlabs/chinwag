#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Fenced canonical task transitions. The journal lock serializes cooperating
//! writers; retained descriptors pin the namespace through atomic replacement.
//! A same-UID process ignoring that lock can still race the final rename. This
//! module detects observed drift and never treats a parseable external edit as
//! authority. Projection persistence is an explicit, fallible commit boundary.

use crate::agent_instance::ActorAddress;
use crate::task_dependency::{
    DependencyCommitment, DependencySourceBinding, ResolvedDependency, canonicalize_dependencies,
    validate_dependency_satisfaction,
};
use crate::task_ref::{
    CasEligibility, GitOid, MAX_LIST_ITEMS, MAX_TASKS_PER_SOURCE, MAX_UNRELATED_FILE_REBASES,
    Sha256Digest, TaskContractError, TaskKey, TaskRefV1, advance_task_revision,
    check_cas_eligibility, checked_next_revision, encode_checked_rev, validate_id,
    validate_task_source_id, validate_workspace_id,
};
use crate::task_source::{
    HeldReason, SourceFilesystemIdentity, TaskSourceRecord, TaskSourceState, WorkspaceTaskPolicy,
};
use crate::task_source_path::{
    MAX_DIRECTORY_ENTRIES, MAX_SOURCE_FILE_BYTES, SourcePathHoldReason, WorkspaceRootPin,
    validate_enrolled_relative_path,
};
use crate::task_wire::{HostClockState, VerifiedTaskMessage};
use crate::task_write_journal::{
    Journal, JournalError, JournalRecordV1, JournalRequestV1, PreparedWriteV1, RecoveryFileState,
    ReplayDispositionV1, WriteOperationState, inspect_prepared, strict_json_object,
    verify_prepared_stage,
};
use rustix::fs::{
    AtFlags, CWD, Dir, FileType, Mode, OFlags, Stat, fstat, openat, renameat, statat, unlinkat,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum WriterError {
    Io(std::io::Error),
    Journal(JournalError),
    Contract(TaskContractError),
    Source(SourcePathHoldReason),
    ClockFenceHeld,
    StaleWriterEpoch,
    WriterPrincipalMismatch,
    PolicyBindingMismatch,
    SourceNotEnrolled,
    SourceHeld,
    InvalidDocument,
    DocumentParseError,
    InvalidActor,
    InvalidTransition,
    AuthorityMismatch,
    UnreviewedDoneForbidden,
    DoneRequiresP006ReviewAttestation,
    SelfReviewForbidden,
    AcceptanceInvalidated,
    DependencyUnsatisfied,
    TargetTaskConflict,
    RebaseLimitExceeded,
    FileCasConflict,
    SourceIdentityChanged,
    SymlinkRejected,
    HardlinkRejected,
    FileTooLarge,
    OperationInProgress,
    RecordedRejection,
    InjectedCrash,
}

impl fmt::Display for WriterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task writer refused: {self:?}")
    }
}
impl std::error::Error for WriterError {}
impl From<std::io::Error> for WriterError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rustix::io::Errno> for WriterError {
    fn from(error: rustix::io::Errno) -> Self {
        if error == rustix::io::Errno::LOOP {
            Self::SymlinkRejected
        } else {
            Self::Io(error.into())
        }
    }
}
impl From<JournalError> for WriterError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}
impl From<TaskContractError> for WriterError {
    fn from(error: TaskContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<SourcePathHoldReason> for WriterError {
    fn from(error: SourcePathHoldReason) -> Self {
        Self::Source(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterLeaseV1 {
    pub workspace_id: String,
    pub repo_id: String,
    pub source_worktree_id: String,
    pub task_source_id: String,
    pub canonical_relative_path: String,
    pub source_generation: u64,
    pub writer_principal: String,
    pub writer_epoch: u64,
    pub config_revision: u64,
    pub authority_epoch: u64,
    pub config_digest: [u8; 32],
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl WriterLeaseV1 {
    pub fn verify(&self, authority: &WriterAuthoritySnapshot) -> Result<(), WriterError> {
        let WriterAuthoritySnapshot {
            policy,
            record,
            writer_principal,
            writer_epoch,
            clock,
            ..
        } = authority;
        record
            .validate(policy)
            .map_err(|_| WriterError::PolicyBindingMismatch)?;
        if record.state != TaskSourceState::Enrolled {
            return Err(WriterError::SourceNotEnrolled);
        }
        if self.writer_principal != *writer_principal
            || self.writer_principal != record.writer_principal
        {
            return Err(WriterError::WriterPrincipalMismatch);
        }
        if self.writer_epoch != *writer_epoch || self.writer_epoch != record.writer_epoch {
            return Err(WriterError::StaleWriterEpoch);
        }
        if self.workspace_id != policy.workspace_id
            || self.repo_id != policy.repo_id
            || self.workspace_id != record.workspace_id
            || self.repo_id != record.repo_id
            || self.source_worktree_id != record.source_worktree_id
            || self.task_source_id != record.task_source_id
            || self.canonical_relative_path != record.canonical_relative_path
            || self.source_generation != record.source_generation
            || self.config_revision != policy.config_revision
            || self.authority_epoch != policy.authority_epoch
            || self.config_digest != policy.config_digest
            || self.config_digest != record.config_digest
        {
            return Err(WriterError::PolicyBindingMismatch);
        }
        match clock {
            HostClockState::Verified { now_unix }
                if self.issued_at_unix <= *now_unix
                    && *now_unix <= self.expires_at_unix
                    && self.expires_at_unix >= self.issued_at_unix =>
            {
                Ok(())
            }
            _ => Err(WriterError::ClockFenceHeld),
        }
    }
}

/// Must be refreshed from the current authority immediately before each effect.
/// Lease expiration alone never authorizes replacement of an unknown writer.
#[derive(Clone, Debug)]
pub struct WriterAuthoritySnapshot {
    pub policy: WorkspaceTaskPolicy,
    pub record: TaskSourceRecord,
    pub writer_principal: String,
    pub writer_epoch: u64,
    pub clock: HostClockState,
    pub reviewer_role_grants: Vec<ReviewerRoleGrantV1>,
    /// Current confirmed admissions, refreshed by the trusted authority provider.
    /// Historical reservations and unknown commitments must not appear here.
    pub execution_admissions: Vec<ExecutionAdmissionV1>,
}

/// A current authority claim for one qualified transition. The provider retains
/// the original assignment/operation and verifies its recorded transition chain
/// before binding the claim to this proposal's immutable TaskRef.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAdmissionV1 {
    pub actor: String,
    pub authenticated_signer_principal: String,
    pub executor_actor: String,
    pub task_ref: TaskRefV1,
    pub task_control_digest: Sha256Digest,
    pub admission_id: String,
    pub assignment_id: String,
    pub original_operation_id: String,
    pub action: String,
    pub grant_id: String,
    pub capacity_claim_id: String,
    pub write_scope_claim_id: String,
}

/// Supplied by the current workspace grant authority, never by review prose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewerRoleGrantV1 {
    pub reviewer_actor: String,
    pub authenticated_signer_principal: String,
    pub reviewer_role: String,
    pub completion_policy_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalTaskStatus {
    Todo,
    InProgress,
    DonePendingReview,
    Done,
    Blocked,
}

impl CanonicalTaskStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Todo => "todo",
            Self::InProgress => "in-progress",
            Self::DonePendingReview => "done-pending-review",
            Self::Done => "done",
            Self::Blocked => "blocked",
        }
    }
}

mod digest_json {
    use super::*;
    pub fn serialize<S: Serializer>(
        value: &Sha256Digest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(decoder: D) -> Result<Sha256Digest, D::Error> {
        Sha256Digest::from_hex(&String::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}
mod oid_json {
    use super::*;
    pub fn serialize<S: Serializer>(value: &GitOid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(decoder: D) -> Result<GitOid, D::Error> {
        GitOid::from_hex(&String::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}
mod optional_oid_json {
    use super::*;
    pub fn serialize<S: Serializer>(
        value: &Option<GitOid>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|oid| oid.to_string()).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(decoder: D) -> Result<Option<GitOid>, D::Error> {
        Option::<String>::deserialize(decoder)?
            .map(|s| GitOid::from_hex(&s))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}
mod optional_digest_json {
    use super::*;
    pub fn serialize<S: Serializer>(
        value: &Option<Sha256Digest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|digest| digest.to_string()).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        decoder: D,
    ) -> Result<Option<Sha256Digest>, D::Error> {
        Option::<String>::deserialize(decoder)?
            .map(|s| Sha256Digest::from_hex(&s))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}
mod dependencies_json {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireDependency {
        workspace_id: String,
        task_source_id: String,
        task_id: String,
        #[serde(with = "digest_json")]
        target_spec_digest: Sha256Digest,
        #[serde(with = "digest_json")]
        completion_policy_digest: Sha256Digest,
    }
    pub fn serialize<S: Serializer>(
        values: &[DependencyCommitment],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        values
            .iter()
            .map(|value| WireDependency {
                workspace_id: value.target_key.workspace_id.clone(),
                task_source_id: value.target_key.task_source_id.clone(),
                task_id: value.target_key.task_id.clone(),
                target_spec_digest: value.target_spec_digest,
                completion_policy_digest: value.completion_policy_digest,
            })
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        decoder: D,
    ) -> Result<Vec<DependencyCommitment>, D::Error> {
        Vec::<WireDependency>::deserialize(decoder)?
            .into_iter()
            .map(|value| {
                Ok(DependencyCommitment {
                    target_key: TaskKey::new(
                        value.workspace_id,
                        value.task_source_id,
                        value.task_id,
                    )
                    .map_err(serde::de::Error::custom)?,
                    target_spec_digest: value.target_spec_digest,
                    completion_policy_digest: value.completion_policy_digest,
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEntrySnapshotV1 {
    pub task_id: String,
    pub status: CanonicalTaskStatus,
    pub task_status_rev: u64,
    #[serde(with = "digest_json")]
    pub task_spec_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub completion_policy_digest: Sha256Digest,
    pub owner_actor: Option<String>,
    pub reviewer_role: String,
    #[serde(with = "oid_json")]
    pub baseline_commit: GitOid,
    #[serde(with = "optional_oid_json")]
    pub candidate_commit: Option<GitOid>,
    #[serde(with = "optional_digest_json")]
    pub overlay_digest: Option<Sha256Digest>,
    pub execution_flags: Vec<String>,
    #[serde(with = "dependencies_json")]
    pub dependencies: Vec<DependencyCommitment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTaskDocumentV1 {
    pub workspace_id: String,
    pub repo_id: String,
    pub task_source_id: String,
    pub source_generation: u64,
    pub file_cas_rev: u64,
    pub last_operation_id: Option<String>,
    pub tasks: Vec<TaskEntrySnapshotV1>,
    #[serde(skip)]
    markdown: Option<PreservedTaskMarkdownV1>,
}

// Formatting is provenance for a later surgical rewrite, not task identity.
impl PartialEq for CanonicalTaskDocumentV1 {
    fn eq(&self, other: &Self) -> bool {
        self.workspace_id == other.workspace_id
            && self.repo_id == other.repo_id
            && self.task_source_id == other.task_source_id
            && self.source_generation == other.source_generation
            && self.file_cas_rev == other.file_cas_rev
            && self.last_operation_id == other.last_operation_id
            && self.tasks == other.tasks
    }
}
impl Eq for CanonicalTaskDocumentV1 {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskSourceMarkdownMetadataV1 {
    workspace_id: String,
    repo_id: String,
    task_source_id: String,
    source_generation: u64,
    file_cas_rev: u64,
    last_operation_id: Option<String>,
}

impl TaskSourceMarkdownMetadataV1 {
    fn from_document(document: &CanonicalTaskDocumentV1) -> Self {
        Self {
            workspace_id: document.workspace_id.clone(),
            repo_id: document.repo_id.clone(),
            task_source_id: document.task_source_id.clone(),
            source_generation: document.source_generation,
            file_cas_rev: document.file_cas_rev,
            last_operation_id: document.last_operation_id.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct PreservedTaskMarkdownV1 {
    original: String,
    metadata_range: std::ops::Range<usize>,
    metadata: TaskSourceMarkdownMetadataV1,
    blocks: Vec<PreservedTaskBlockV1>,
}

#[derive(Clone, Debug)]
struct PreservedTaskBlockV1 {
    snapshot: TaskEntrySnapshotV1,
    entry_range: std::ops::Range<usize>,
    bullet_range: std::ops::Range<usize>,
    summary: String,
}

struct OpenTaskMarkdownBlockV1 {
    task_id: String,
    entry: Option<(TaskEntrySnapshotV1, std::ops::Range<usize>)>,
    bullet: Option<(bool, String, String, std::ops::Range<usize>)>,
}

fn full_actor(value: &str) -> Result<ActorAddress, WriterError> {
    let actor = ActorAddress::parse(value)
        .and_then(ActorAddress::require_instance)
        .map_err(|_| WriterError::InvalidActor)?;
    if actor.instance().is_none() || actor.to_string() != value {
        return Err(WriterError::InvalidActor);
    }
    Ok(actor)
}

impl CanonicalTaskDocumentV1 {
    pub fn validate(&self) -> Result<(), WriterError> {
        validate_workspace_id(&self.workspace_id)?;
        validate_task_source_id(&self.task_source_id)?;
        validate_id(&self.repo_id, "repo_id")?;
        encode_checked_rev(self.source_generation)?;
        encode_checked_rev(self.file_cas_rev)?;
        if let Some(id) = &self.last_operation_id {
            validate_task_source_id(id)?;
        }
        if self.tasks.is_empty()
            || self.tasks.len() > MAX_TASKS_PER_SOURCE
            || self
                .tasks
                .windows(2)
                .any(|pair| pair[0].task_id >= pair[1].task_id)
        {
            return Err(WriterError::InvalidDocument);
        }
        for task in &self.tasks {
            validate_id(&task.task_id, "task_id")?;
            validate_id(&task.reviewer_role, "reviewer_role")?;
            encode_checked_rev(task.task_status_rev)?;
            if let Some(owner) = &task.owner_actor {
                full_actor(owner)?;
            }
            if task.execution_flags.len() > MAX_LIST_ITEMS
                || task
                    .execution_flags
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(WriterError::InvalidDocument);
            }
            for flag in &task.execution_flags {
                validate_id(flag, "execution_flag")?;
            }
            let key = TaskKey::new(&self.workspace_id, &self.task_source_id, &task.task_id)?;
            if canonicalize_dependencies(&key, task.dependencies.clone())? != task.dependencies {
                return Err(WriterError::InvalidDocument);
            }
        }
        Ok(())
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WriterError> {
        if bytes.len() as u64 > MAX_SOURCE_FILE_BYTES {
            return Err(WriterError::FileTooLarge);
        }
        Self::parse_strict(std::str::from_utf8(bytes).map_err(|_| WriterError::DocumentParseError)?)
    }
    pub fn parse_strict(markdown: &str) -> Result<Self, WriterError> {
        parse_canonical_markdown(markdown)
    }
    pub fn to_canonical_string(&self) -> Result<String, WriterError> {
        render_canonical_markdown(self)
    }
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, WriterError> {
        Ok(self.to_canonical_string()?.into_bytes())
    }
    pub fn task_ref(&self, task: &TaskEntrySnapshotV1, path: &str) -> TaskRefV1 {
        TaskRefV1 {
            workspace_id: self.workspace_id.clone(),
            repo_id: self.repo_id.clone(),
            task_source_id: self.task_source_id.clone(),
            source_generation: self.source_generation,
            canonical_task_path: path.into(),
            task_id: task.task_id.clone(),
            task_spec_digest: task.task_spec_digest,
            task_status_rev: task.task_status_rev,
            file_cas_rev: self.file_cas_rev,
            baseline_commit: task.baseline_commit,
        }
    }
}

const SOURCE_META_PREFIX: &str = "<!-- chinwag-task-source-meta-v1 ";
const TASK_ENTRY_PREFIX: &str = "<!-- chinwag-task-entry-v1 ";
const MARKER_SUFFIX: &str = " -->";

fn markdown_json<T: serde::de::DeserializeOwned>(
    line: &str,
    prefix: &str,
) -> Result<T, WriterError> {
    let json = line
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(MARKER_SUFFIX))
        .ok_or(WriterError::DocumentParseError)?;
    strict_json_object(json.as_bytes(), MAX_SOURCE_FILE_BYTES as usize)
        .map_err(|_| WriterError::DocumentParseError)?;
    serde_json::from_str(json).map_err(|_| WriterError::DocumentParseError)
}

fn markdown_task_marker<'a>(line: &'a str, prefix: &str) -> Result<&'a str, WriterError> {
    let id = line
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix("\" -->"))
        .ok_or(WriterError::DocumentParseError)?;
    validate_id(id, "task_id").map_err(|_| WriterError::DocumentParseError)?;
    Ok(id)
}

fn markdown_task_bullet(line: &str) -> Result<(bool, &str, &str, &str), WriterError> {
    let (checked, rest) = if let Some(rest) = line.strip_prefix("- [ ] **") {
        (false, rest)
    } else if let Some(rest) = line.strip_prefix("- [x] **") {
        (true, rest)
    } else {
        return Err(WriterError::DocumentParseError);
    };
    let (id, rest) = rest
        .split_once("** (`")
        .ok_or(WriterError::DocumentParseError)?;
    validate_id(id, "task_id").map_err(|_| WriterError::DocumentParseError)?;
    let (status, summary) = rest
        .split_once("`) — ")
        .ok_or(WriterError::DocumentParseError)?;
    if summary.trim().is_empty() {
        return Err(WriterError::DocumentParseError);
    }
    Ok((checked, id, status, summary))
}

fn task_bullet_line(task: &TaskEntrySnapshotV1, summary: &str) -> String {
    format!(
        "- [{}] **{}** (`{}`) — {}\n",
        if task.status == CanonicalTaskStatus::Done {
            "x"
        } else {
            " "
        },
        task.task_id,
        task.status.as_str(),
        summary
    )
}

fn markdown_json_line<T: Serialize>(prefix: &str, value: &T) -> Result<String, WriterError> {
    let mut sink = BoundedSource(Vec::new());
    sink.write_all(prefix.as_bytes())
        .map_err(|_| WriterError::FileTooLarge)?;
    serde_json::to_writer(&mut sink, value).map_err(|_| WriterError::FileTooLarge)?;
    sink.write_all(b" -->\n")
        .map_err(|_| WriterError::FileTooLarge)?;
    String::from_utf8(sink.0).map_err(|_| WriterError::InvalidDocument)
}

/// Parses the enrolled Markdown profile while retaining every original byte for
/// later writes. Reserved markers are authoritative only as exact, unfenced lines.
pub fn parse_canonical_markdown(markdown: &str) -> Result<CanonicalTaskDocumentV1, WriterError> {
    if markdown.len() as u64 > MAX_SOURCE_FILE_BYTES {
        return Err(WriterError::FileTooLarge);
    }
    if !markdown.ends_with('\n') || markdown.contains('\r') || markdown.contains('\0') {
        return Err(WriterError::DocumentParseError);
    }
    let mut metadata = None;
    let mut metadata_range = None;
    let mut blocks = Vec::new();
    let mut open: Option<OpenTaskMarkdownBlockV1> = None;
    let mut heading_seen = false;
    let mut fence: Option<(u8, usize)> = None;
    let mut offset = 0;
    for raw in markdown.split_inclusive('\n') {
        let line = raw
            .strip_suffix('\n')
            .ok_or(WriterError::DocumentParseError)?;
        let range = offset..offset + raw.len();
        offset += raw.len();
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        let first = trimmed.as_bytes().first().copied();
        let fence_length = if matches!(first, Some(b'`' | b'~')) {
            trimmed
                .bytes()
                .take_while(|byte| Some(*byte) == first)
                .count()
        } else {
            0
        };
        if let Some((character, length)) = fence {
            if line.contains("<!--") && line.contains("chinwag-task-") {
                return Err(WriterError::DocumentParseError);
            }
            if indent <= 3
                && first == Some(character)
                && fence_length >= length
                && trimmed[fence_length..].trim().is_empty()
            {
                fence = None;
            }
            continue;
        }
        if indent <= 3 && fence_length >= 3 {
            if line.contains("<!--") && line.contains("chinwag-task-") {
                return Err(WriterError::DocumentParseError);
            }
            fence = Some((first.ok_or(WriterError::DocumentParseError)?, fence_length));
            continue;
        }
        let heading_length = line.bytes().take_while(|byte| *byte == b'#').count();
        if (1..=6).contains(&heading_length)
            && line[heading_length..].starts_with(' ')
            && !line[heading_length + 1..].trim().is_empty()
        {
            heading_seen = true;
        }
        if line.starts_with(SOURCE_META_PREFIX) {
            if metadata.is_some() || open.is_some() {
                return Err(WriterError::DocumentParseError);
            }
            let value: TaskSourceMarkdownMetadataV1 = markdown_json(line, SOURCE_META_PREFIX)?;
            // Option fields still have to be explicit in this six-field wire schema.
            let object: serde_json::Value = markdown_json(line, SOURCE_META_PREFIX)?;
            if object
                .as_object()
                .is_none_or(|object| object.len() != 6 || !object.contains_key("last_operation_id"))
            {
                return Err(WriterError::DocumentParseError);
            }
            metadata = Some(value);
            metadata_range = Some(range);
        } else if line.starts_with("<!-- chinwag-task-begin-v1 task_id=\"") {
            if open.is_some() {
                return Err(WriterError::DocumentParseError);
            }
            let id = markdown_task_marker(line, "<!-- chinwag-task-begin-v1 task_id=\"")?;
            open = Some(OpenTaskMarkdownBlockV1 {
                task_id: id.into(),
                entry: None,
                bullet: None,
            });
        } else if line.starts_with(TASK_ENTRY_PREFIX) {
            let block = open.as_mut().ok_or(WriterError::DocumentParseError)?;
            if block.entry.is_some() {
                return Err(WriterError::DocumentParseError);
            }
            let entry: TaskEntrySnapshotV1 = markdown_json(line, TASK_ENTRY_PREFIX)?;
            let object: serde_json::Value = markdown_json(line, TASK_ENTRY_PREFIX)?;
            if object.as_object().is_none_or(|object| object.len() != 13) {
                return Err(WriterError::DocumentParseError);
            }
            if entry.task_id != block.task_id {
                return Err(WriterError::DocumentParseError);
            }
            block.entry = Some((entry, range));
        } else if line.starts_with("<!-- chinwag-task-end-v1 task_id=\"") {
            let id = markdown_task_marker(line, "<!-- chinwag-task-end-v1 task_id=\"")?;
            let block = open.take().ok_or(WriterError::DocumentParseError)?;
            let (snapshot, entry_range) = block.entry.ok_or(WriterError::DocumentParseError)?;
            let (checked, status, summary, bullet_range) =
                block.bullet.ok_or(WriterError::DocumentParseError)?;
            if id != block.task_id
                || status != snapshot.status.as_str()
                || checked != (snapshot.status == CanonicalTaskStatus::Done)
            {
                return Err(WriterError::DocumentParseError);
            }
            blocks.push(PreservedTaskBlockV1 {
                snapshot,
                entry_range,
                bullet_range,
                summary,
            });
            if blocks.len() > MAX_TASKS_PER_SOURCE {
                return Err(WriterError::InvalidDocument);
            }
        } else if line.contains("<!--") && line.contains("chinwag-task-") {
            return Err(WriterError::DocumentParseError);
        } else if trimmed.starts_with("- [") && trimmed.contains("** (`") {
            // Ordinary body checklists are prose. A bold task-id bullet is part
            // of this controlled grammar and must be exact and unambiguous.
            let block = open.as_mut().ok_or(WriterError::DocumentParseError)?;
            let (checked, id, status, summary) = markdown_task_bullet(line)?;
            if block.bullet.is_some() || id != block.task_id {
                return Err(WriterError::DocumentParseError);
            }
            block.bullet = Some((checked, status.into(), summary.into(), range));
        }
    }
    if open.is_some() || fence.is_some() || !heading_seen || blocks.is_empty() {
        return Err(WriterError::DocumentParseError);
    }
    let metadata = metadata.ok_or(WriterError::DocumentParseError)?;
    let mut tasks: Vec<_> = blocks.iter().map(|block| block.snapshot.clone()).collect();
    tasks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
    let document = CanonicalTaskDocumentV1 {
        workspace_id: metadata.workspace_id.clone(),
        repo_id: metadata.repo_id.clone(),
        task_source_id: metadata.task_source_id.clone(),
        source_generation: metadata.source_generation,
        file_cas_rev: metadata.file_cas_rev,
        last_operation_id: metadata.last_operation_id.clone(),
        tasks,
        markdown: Some(PreservedTaskMarkdownV1 {
            original: markdown.into(),
            metadata,
            metadata_range: metadata_range.ok_or(WriterError::DocumentParseError)?,
            blocks,
        }),
    };
    document.validate()?;
    Ok(document)
}

/// Renders a new document deterministically, or edits only metadata and changed
/// task entry/bullet lines in a parsed document. The task body remains untouched.
pub fn render_canonical_markdown(
    document: &CanonicalTaskDocumentV1,
) -> Result<String, WriterError> {
    let mut ordered = document.clone();
    ordered
        .tasks
        .sort_by(|left, right| left.task_id.cmp(&right.task_id));
    ordered.validate()?;
    let metadata = TaskSourceMarkdownMetadataV1::from_document(&ordered);
    let mut sink = BoundedSource(Vec::new());
    if let Some(preserved) = &ordered.markdown {
        if preserved.blocks.len() != ordered.tasks.len() {
            return Err(WriterError::InvalidDocument);
        }
        let mut changes: Vec<(std::ops::Range<usize>, String)> = Vec::new();
        if metadata != preserved.metadata {
            changes.push((
                preserved.metadata_range.clone(),
                markdown_json_line(SOURCE_META_PREFIX, &metadata)?,
            ));
        }
        for block in &preserved.blocks {
            let task = ordered
                .tasks
                .iter()
                .find(|task| task.task_id == block.snapshot.task_id)
                .ok_or(WriterError::InvalidDocument)?;
            if task != &block.snapshot {
                changes.push((
                    block.entry_range.clone(),
                    markdown_json_line(TASK_ENTRY_PREFIX, task)?,
                ));
                if task.status != block.snapshot.status {
                    changes.push((
                        block.bullet_range.clone(),
                        task_bullet_line(task, &block.summary),
                    ));
                }
            }
        }
        changes.sort_by_key(|(range, _)| range.start);
        let mut position = 0;
        for (range, replacement) in changes {
            if range.start < position {
                return Err(WriterError::InvalidDocument);
            }
            sink.write_all(&preserved.original.as_bytes()[position..range.start])
                .map_err(|_| WriterError::FileTooLarge)?;
            sink.write_all(replacement.as_bytes())
                .map_err(|_| WriterError::FileTooLarge)?;
            position = range.end;
        }
        sink.write_all(&preserved.original.as_bytes()[position..])
            .map_err(|_| WriterError::FileTooLarge)?;
    } else {
        sink.write_all(format!("# Canonical Tasks ({})\n\n", ordered.task_source_id).as_bytes())
            .map_err(|_| WriterError::FileTooLarge)?;
        sink.write_all(markdown_json_line(SOURCE_META_PREFIX, &metadata)?.as_bytes())
            .map_err(|_| WriterError::FileTooLarge)?;
        for task in &ordered.tasks {
            sink.write_all(
                format!(
                    "\n<!-- chinwag-task-begin-v1 task_id=\"{}\" -->\n",
                    task.task_id
                )
                .as_bytes(),
            )
            .map_err(|_| WriterError::FileTooLarge)?;
            sink.write_all(task_bullet_line(task, &task.task_id).as_bytes())
                .map_err(|_| WriterError::FileTooLarge)?;
            sink.write_all(markdown_json_line(TASK_ENTRY_PREFIX, task)?.as_bytes())
                .map_err(|_| WriterError::FileTooLarge)?;
            sink.write_all(
                format!(
                    "<!-- chinwag-task-end-v1 task_id=\"{}\" -->\n",
                    task.task_id
                )
                .as_bytes(),
            )
            .map_err(|_| WriterError::FileTooLarge)?;
        }
    }
    String::from_utf8(sink.0).map_err(|_| WriterError::InvalidDocument)
}

struct BoundedSource(Vec<u8>);
impl Write for BoundedSource {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_SOURCE_FILE_BYTES as usize - self.0.len() {
            return Err(std::io::Error::other("source size limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Typed evidence is inert until its digest matches the signed proposal digest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransitionEvidenceV1 {
    pub admission_id: Option<String>,
    pub assignment_id: Option<String>,
    pub original_operation_id: Option<String>,
    pub grant_id: Option<String>,
    pub capacity_claim_id: Option<String>,
    pub write_scope_claim_id: Option<String>,
    pub executor_actor: Option<String>,
    pub blocker: Option<String>,
    pub resolution: Option<String>,
}

fn validate_transition_reason(reason: &str) -> Result<(), WriterError> {
    if reason.is_empty()
        || reason.len() > 4096
        || reason.trim() != reason
        || reason.chars().any(char::is_control)
    {
        return Err(WriterError::AuthorityMismatch);
    }
    Ok(())
}

impl TransitionEvidenceV1 {
    fn validate(&self) -> Result<(), WriterError> {
        for id in [
            &self.admission_id,
            &self.assignment_id,
            &self.original_operation_id,
            &self.grant_id,
            &self.capacity_claim_id,
            &self.write_scope_claim_id,
        ]
        .into_iter()
        .flatten()
        {
            validate_id(id, "transition_evidence_id")?;
        }
        for reason in [&self.blocker, &self.resolution].into_iter().flatten() {
            validate_transition_reason(reason)?;
        }
        if let Some(executor) = &self.executor_actor {
            full_actor(executor)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32], WriterError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"chinwag-transition-evidence-v1\0");
        for value in [
            &self.admission_id,
            &self.assignment_id,
            &self.original_operation_id,
            &self.grant_id,
            &self.capacity_claim_id,
            &self.write_scope_claim_id,
            &self.executor_actor,
            &self.blocker,
            &self.resolution,
        ] {
            match value {
                Some(value) => {
                    hash.update([1u8]);
                    hash.update((value.len() as u64).to_be_bytes());
                    hash.update(value.as_bytes());
                }
                None => hash.update([0u8]),
            }
        }
        Ok(hash.finalize().into())
    }
}

/// Constructible only from a message that passed the current wire verifier.
#[derive(Clone, Debug)]
pub struct TransitionAuthorityV1 {
    actor: String,
    signer: String,
    message_id: String,
    operation_id: String,
    task_ref: TaskRefV1,
    control_digest: Sha256Digest,
    proposal_digest: Sha256Digest,
    nonce: [u8; 32],
    config_digest: Sha256Digest,
    issued_at_unix: u64,
    expires_at_unix: u64,
    evidence: TransitionEvidenceV1,
}
impl TransitionAuthorityV1 {
    pub fn from_verified(message: &VerifiedTaskMessage) -> Result<Self, WriterError> {
        let authenticated = message.authenticated();
        let transcript = authenticated.transcript();
        full_actor(&transcript.sender_full_actor_address)?;
        if transcript.message_kind != crate::task_wire::TaskMessageKind::TaskProposal {
            return Err(WriterError::AuthorityMismatch);
        }
        let body: serde_json::Value = serde_json::from_str(&transcript.body_utf8)
            .map_err(|_| WriterError::AuthorityMismatch)?;
        if body
            .get("payload_profile")
            .and_then(serde_json::Value::as_str)
            != Some("chinwag-writer-request-v1")
        {
            return Err(WriterError::AuthorityMismatch);
        }
        let proposal_digest = Sha256Digest::from_hex(
            body.get("canonical_payload_hex")
                .and_then(serde_json::Value::as_str)
                .ok_or(WriterError::AuthorityMismatch)?,
        )?;
        Ok(Self {
            actor: transcript.sender_full_actor_address.clone(),
            signer: authenticated.signer_principal().into(),
            message_id: transcript.message_id.clone(),
            operation_id: transcript
                .operation_id
                .clone()
                .ok_or(WriterError::AuthorityMismatch)?,
            task_ref: transcript.task_ref.clone(),
            control_digest: transcript.task_control_digest,
            proposal_digest,
            nonce: transcript.nonce,
            config_digest: transcript.config_digest,
            issued_at_unix: transcript.issued_at_unix,
            expires_at_unix: transcript.expires_at_unix,
            evidence: TransitionEvidenceV1::default(),
        })
    }
    /// The commit boundary verifies this evidence's digest as part of the exact
    /// authenticated request; attaching evidence alone confers no authority.
    pub fn with_evidence(mut self, evidence: TransitionEvidenceV1) -> Self {
        self.evidence = evidence;
        self
    }
    pub fn evidence_digest(&self) -> Result<[u8; 32], WriterError> {
        self.evidence.digest()
    }
}

#[derive(Clone, Debug)]
pub struct ReviewedAcceptanceProofV1 {
    pub reviewer_actor: String,
    pub implementer_actor: String,
    pub reviewed_task_ref: TaskRefV1,
    pub reviewed_task_control_digest: Sha256Digest,
    pub completion_policy_digest: Sha256Digest,
    pub candidate_commit: GitOid,
    pub reviewer_role: String,
    pub verification_checks_passed: Vec<String>,
    pub authority: TransitionAuthorityV1,
}
#[derive(Clone, Debug)]
pub enum TransitionAuthorization {
    Standard(Box<TransitionAuthorityV1>),
    ReviewedAcceptance(Box<ReviewedAcceptanceProofV1>),
    ProseClaim(String),
}

pub struct DependencySnapshotV1 {
    pub resolved: ResolvedDependency,
    pub current_source: DependencySourceBinding,
    pub source_record: TaskSourceRecord,
    pub policy: WorkspaceTaskPolicy,
}

fn valid_edge(old: CanonicalTaskStatus, next: CanonicalTaskStatus) -> bool {
    use CanonicalTaskStatus::*;
    matches!(
        (old, next),
        (Todo, InProgress)
            | (InProgress, DonePendingReview)
            | (DonePendingReview, Done)
            | (Blocked, Todo)
            | (Todo | InProgress | DonePendingReview, Blocked)
    )
}

fn verify_current_review_grant(
    authorization: &TransitionAuthorization,
    current: &WriterAuthoritySnapshot,
) -> Result<(), WriterError> {
    if let TransitionAuthorization::ReviewedAcceptance(proof) = authorization
        && !current.reviewer_role_grants.iter().any(|grant| {
            grant.reviewer_actor == proof.reviewer_actor
                && grant.authenticated_signer_principal == proof.authority.signer
                && grant.reviewer_role == proof.reviewer_role
                && grant.completion_policy_digest == proof.completion_policy_digest
        })
    {
        return Err(WriterError::AuthorityMismatch);
    }
    Ok(())
}

/// Rechecked from fresh authority immediately before every protected effect.
/// The claims are current confirmed authority records, never proposal booleans.
fn verify_current_transition_grant(
    authorization: &TransitionAuthorization,
    next: CanonicalTaskStatus,
    current: &WriterAuthoritySnapshot,
) -> Result<(), WriterError> {
    verify_current_review_grant(authorization, current)?;
    let authority = match authorization {
        TransitionAuthorization::Standard(authority) => authority.as_ref(),
        TransitionAuthorization::ReviewedAcceptance(_) => return Ok(()),
        TransitionAuthorization::ProseClaim(_) => return Err(WriterError::AuthorityMismatch),
    };
    authority.evidence.validate()?;
    if next == CanonicalTaskStatus::Blocked && authority.signer == current.record.writer_principal {
        return Ok(());
    }
    if current.execution_admissions.len() > MAX_LIST_ITEMS {
        return Err(WriterError::AuthorityMismatch);
    }
    let evidence = &authority.evidence;
    let mut matching = current.execution_admissions.iter().filter(|admission| {
        admission.actor == authority.actor
            && admission.authenticated_signer_principal == authority.signer
            && admission.task_ref == authority.task_ref
            && admission.task_control_digest == authority.control_digest
            && evidence.admission_id.as_deref() == Some(admission.admission_id.as_str())
            && evidence.assignment_id.as_deref() == Some(admission.assignment_id.as_str())
            && evidence.original_operation_id.as_deref()
                == Some(admission.original_operation_id.as_str())
            && evidence.grant_id.as_deref() == Some(admission.grant_id.as_str())
            && evidence.capacity_claim_id.as_deref() == Some(admission.capacity_claim_id.as_str())
            && evidence.write_scope_claim_id.as_deref()
                == Some(admission.write_scope_claim_id.as_str())
            && evidence.executor_actor.as_deref() == Some(admission.executor_actor.as_str())
    });
    let admission = matching.next().ok_or(WriterError::AuthorityMismatch)?;
    if matching.next().is_some() {
        return Err(WriterError::AuthorityMismatch);
    }
    full_actor(&admission.actor)?;
    full_actor(&admission.executor_actor)?;
    admission.task_ref.encode()?;
    for id in [
        &admission.admission_id,
        &admission.assignment_id,
        &admission.original_operation_id,
        &admission.action,
        &admission.grant_id,
        &admission.capacity_claim_id,
        &admission.write_scope_claim_id,
    ] {
        validate_id(id, "execution_admission_id")?;
    }
    current
        .record
        .controls
        .check_dispatch_admission(&admission.action)
        .map_err(|_| WriterError::AuthorityMismatch)?;
    if matches!(
        next,
        CanonicalTaskStatus::Todo | CanonicalTaskStatus::InProgress
    ) && admission.original_operation_id != authority.operation_id
    {
        return Err(WriterError::AuthorityMismatch);
    }
    if next == CanonicalTaskStatus::DonePendingReview && admission.executor_actor != authority.actor
    {
        return Err(WriterError::AuthorityMismatch);
    }
    Ok(())
}

fn verify_proposal_fence(
    authority: &TransitionAuthorityV1,
    current: &WriterAuthoritySnapshot,
) -> Result<(), WriterError> {
    if authority.config_digest.0 != current.policy.config_digest {
        return Err(WriterError::PolicyBindingMismatch);
    }
    match current.clock {
        HostClockState::Verified { now_unix }
            if authority.issued_at_unix <= now_unix && now_unix <= authority.expires_at_unix =>
        {
            Ok(())
        }
        _ => Err(WriterError::ClockFenceHeld),
    }
}

fn verify_transition_dependencies(
    document: &CanonicalTaskDocumentV1,
    task: &TaskEntrySnapshotV1,
    dependencies: &[DependencySnapshotV1],
) -> Result<(), WriterError> {
    if dependencies.len() != task.dependencies.len() {
        return Err(WriterError::DependencyUnsatisfied);
    }
    for required in &task.dependencies {
        let mut matching = dependencies
            .iter()
            .filter(|entry| entry.resolved.task_ref.task_key() == required.target_key);
        let entry = matching.next().ok_or(WriterError::DependencyUnsatisfied)?;
        if matching.next().is_some() {
            return Err(WriterError::DependencyUnsatisfied);
        }
        entry
            .source_record
            .validate(&entry.policy)
            .map_err(|_| WriterError::DependencyUnsatisfied)?;
        entry
            .source_record
            .state
            .check_new_admission()
            .map_err(|_| WriterError::DependencyUnsatisfied)?;
        let binding = &entry.current_source;
        let source = &entry.source_record;
        if binding.workspace_id != source.workspace_id
            || binding.repo_id != source.repo_id
            || binding.repo_id != document.repo_id
            || binding.task_source_id != source.task_source_id
            || binding.source_generation != source.source_generation
            || binding.canonical_task_path != source.canonical_relative_path
        {
            return Err(WriterError::DependencyUnsatisfied);
        }
        validate_dependency_satisfaction(required, &entry.resolved, binding)
            .map_err(|_| WriterError::DependencyUnsatisfied)?;
    }
    Ok(())
}

pub fn authorize_transition(
    document: &CanonicalTaskDocumentV1,
    task: &TaskEntrySnapshotV1,
    path: &str,
    next: CanonicalTaskStatus,
    authorization: &TransitionAuthorization,
    dependencies: &[DependencySnapshotV1],
) -> Result<(), WriterError> {
    if next == CanonicalTaskStatus::Done
        && !matches!(
            authorization,
            TransitionAuthorization::ReviewedAcceptance(_)
        )
    {
        return Err(WriterError::UnreviewedDoneForbidden);
    }
    if !valid_edge(task.status, next) {
        return Err(WriterError::InvalidTransition);
    }
    let authority: &TransitionAuthorityV1 = match authorization {
        TransitionAuthorization::Standard(authority) => authority,
        TransitionAuthorization::ReviewedAcceptance(proof) => &proof.authority,
        TransitionAuthorization::ProseClaim(_) => return Err(WriterError::AuthorityMismatch),
    };
    let current = document.task_ref(task, path);
    // Whole-file revisions may advance independently of this immutable proposal.
    check_cas_eligibility(&authority.task_ref, &current, 0)
        .map_err(|_| WriterError::AcceptanceInvalidated)?;
    if authority.control_digest != task.task_control_digest {
        return Err(WriterError::AcceptanceInvalidated);
    }
    full_actor(&authority.actor)?;
    authority.evidence.validate()?;
    if matches!(
        next,
        CanonicalTaskStatus::Todo
            | CanonicalTaskStatus::InProgress
            | CanonicalTaskStatus::DonePendingReview
    ) {
        let evidence = &authority.evidence;
        if evidence.admission_id.is_none()
            || evidence.assignment_id.is_none()
            || evidence.original_operation_id.is_none()
            || evidence.grant_id.is_none()
            || evidence.capacity_claim_id.is_none()
            || evidence.write_scope_claim_id.is_none()
            || evidence.executor_actor.is_none()
        {
            return Err(WriterError::AuthorityMismatch);
        }
        if task.owner_actor.as_deref() != evidence.executor_actor.as_deref() {
            return Err(WriterError::AuthorityMismatch);
        }
    }
    if matches!(
        next,
        CanonicalTaskStatus::Todo | CanonicalTaskStatus::InProgress
    ) {
        if authority.evidence.original_operation_id.as_deref()
            != Some(authority.operation_id.as_str())
        {
            return Err(WriterError::AuthorityMismatch);
        }
        verify_transition_dependencies(document, task, dependencies)?;
    }
    if next == CanonicalTaskStatus::DonePendingReview
        && (task.owner_actor.as_deref() != Some(authority.actor.as_str())
            || task.candidate_commit.is_none())
    {
        return Err(WriterError::AcceptanceInvalidated);
    }
    if next == CanonicalTaskStatus::Blocked && authority.evidence.blocker.is_none() {
        return Err(WriterError::AuthorityMismatch);
    }
    if task.status == CanonicalTaskStatus::Blocked && authority.evidence.resolution.is_none() {
        return Err(WriterError::AuthorityMismatch);
    }
    if let TransitionAuthorization::ReviewedAcceptance(proof) = authorization {
        if next != CanonicalTaskStatus::Done {
            return Err(WriterError::InvalidTransition);
        }
        let reviewer = full_actor(&proof.reviewer_actor)?;
        let implementer = full_actor(&proof.implementer_actor)?;
        if reviewer == implementer || reviewer.seat() == implementer.seat() {
            return Err(WriterError::SelfReviewForbidden);
        }
        if authority.actor != proof.reviewer_actor
            || task.owner_actor.as_deref() != Some(&proof.implementer_actor)
            || proof.reviewed_task_ref != authority.task_ref
            || proof.reviewed_task_control_digest != task.task_control_digest
            || proof.completion_policy_digest != task.completion_policy_digest
            || task.candidate_commit != Some(proof.candidate_commit)
            || proof.reviewer_role != task.reviewer_role
            || proof.verification_checks_passed.is_empty()
            || proof.verification_checks_passed.len() > MAX_LIST_ITEMS
        {
            return Err(WriterError::AcceptanceInvalidated);
        }
        for check in &proof.verification_checks_passed {
            validate_id(check, "verification_check")?;
        }
        verify_transition_dependencies(document, task, dependencies)?;
        // P0-05 preserves negative review checks, but cannot mint acceptance
        // without P0-06's exact candidate and independently signed attestation.
        return Err(WriterError::DoneRequiresP006ReviewAttestation);
    }
    Ok(())
}

pub struct TaskWriteRequestV1 {
    pub operation_id: String,
    pub authenticated_signer_principal: String,
    pub request_message_id: String,
    pub nonce: [u8; 32],
    pub request_digest_sha256: [u8; 32],
    pub admitted_task_ref: TaskRefV1,
    pub expected_preimage_sha256: [u8; 32],
    pub admitted_document: CanonicalTaskDocumentV1,
    pub next_status: CanonicalTaskStatus,
    pub authorization: TransitionAuthorization,
}
impl TaskWriteRequestV1 {
    fn authority(&self) -> Result<&TransitionAuthorityV1, WriterError> {
        match &self.authorization {
            TransitionAuthorization::Standard(authority) => Ok(authority),
            TransitionAuthorization::ReviewedAcceptance(proof) => Ok(&proof.authority),
            TransitionAuthorization::ProseClaim(_) => Err(WriterError::UnreviewedDoneForbidden),
        }
    }
    /// Digest binds the immutable proposal, original file bytes and typed review
    /// evidence. Display text is deliberately absent from this authority format.
    pub fn canonical_request_digest(&self) -> Result<[u8; 32], WriterError> {
        let mut hash = Sha256::new();
        hash.update(b"chinwag-writer-request-v1\0");
        for value in [
            &self.operation_id,
            &self.authenticated_signer_principal,
            &self.request_message_id,
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(self.nonce);
        hash.update(self.admitted_task_ref.encode()?);
        hash.update(self.expected_preimage_sha256);
        hash.update(self.admitted_document.to_canonical_bytes()?);
        hash.update(
            serde_json::to_vec(&self.next_status).map_err(|_| WriterError::InvalidDocument)?,
        );
        hash.update(self.authority()?.evidence_digest()?);
        if let TransitionAuthorization::ReviewedAcceptance(proof) = &self.authorization {
            for value in [
                &proof.reviewer_actor,
                &proof.implementer_actor,
                &proof.reviewer_role,
            ] {
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value.as_bytes());
            }
            hash.update(proof.reviewed_task_ref.encode()?);
            hash.update(proof.reviewed_task_control_digest.0);
            hash.update(proof.completion_policy_digest.0);
            hash.update(proof.candidate_commit.encode_typed());
            for value in &proof.verification_checks_passed {
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value.as_bytes());
            }
        }
        Ok(hash.finalize().into())
    }
}

pub fn rebase_task_mutation(
    request: &TaskWriteRequestV1,
    live: &CanonicalTaskDocumentV1,
    live_hash: [u8; 32],
    rebases_used: usize,
) -> Result<(CanonicalTaskDocumentV1, usize), WriterError> {
    request.admitted_document.validate()?;
    live.validate()?;
    let admitted = &request.admitted_task_ref;
    let base_task = request
        .admitted_document
        .tasks
        .iter()
        .find(|task| task.task_id == admitted.task_id)
        .ok_or(WriterError::TargetTaskConflict)?;
    if request
        .admitted_document
        .task_ref(base_task, &admitted.canonical_task_path)
        != *admitted
    {
        return Err(WriterError::AcceptanceInvalidated);
    }
    let target = live
        .tasks
        .iter()
        .find(|task| task.task_id == admitted.task_id)
        .ok_or(WriterError::TargetTaskConflict)?;
    if target != base_task {
        return Err(WriterError::TargetTaskConflict);
    }
    let current = live.task_ref(target, &admitted.canonical_task_path);
    let delta = live
        .file_cas_rev
        .checked_sub(admitted.file_cas_rev)
        .ok_or(WriterError::FileCasConflict)?;
    if delta > MAX_UNRELATED_FILE_REBASES as u64
        || (delta > 0 && rebases_used >= MAX_UNRELATED_FILE_REBASES)
    {
        return Err(WriterError::RebaseLimitExceeded);
    }
    let eligible =
        check_cas_eligibility(admitted, &current, rebases_used).map_err(|error| match error {
            TaskContractError::RebaseLimitExceeded => WriterError::RebaseLimitExceeded,
            _ => WriterError::AcceptanceInvalidated,
        })?;
    let used = match eligible {
        CasEligibility::Exact => {
            if live_hash != request.expected_preimage_sha256 || live != &request.admitted_document {
                return Err(WriterError::FileCasConflict);
            }
            rebases_used
        }
        CasEligibility::UnrelatedFileRebase => {
            let base_others: Vec<_> = request
                .admitted_document
                .tasks
                .iter()
                .filter(|task| task.task_id != admitted.task_id)
                .collect();
            let live_others: Vec<_> = live
                .tasks
                .iter()
                .filter(|task| task.task_id != admitted.task_id)
                .collect();
            if base_others == live_others {
                return Err(WriterError::FileCasConflict);
            }
            rebases_used.max(delta as usize)
        }
    };
    let advanced = advance_task_revision(&current, target.status != request.next_status)?;
    let mut next = live.clone();
    next.file_cas_rev = advanced.file_cas_rev;
    next.last_operation_id = Some(request.operation_id.clone());
    let task = next
        .tasks
        .iter_mut()
        .find(|task| task.task_id == admitted.task_id)
        .ok_or(WriterError::TargetTaskConflict)?;
    task.status = request.next_status;
    task.task_status_rev = advanced.task_status_rev;
    Ok((next, used))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    identity: SourceFilesystemIdentity,
    uid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl FileStamp {
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &Stat, uid: u32, directory: bool) -> Result<Self, WriterError> {
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind == FileType::Symlink {
            return Err(WriterError::SymlinkRejected);
        }
        if stat.st_uid != uid
            || (directory && kind != FileType::Directory)
            || (!directory && kind != FileType::RegularFile)
        {
            return Err(WriterError::SourceIdentityChanged);
        }
        if !directory && stat.st_nlink != 1 {
            return Err(WriterError::HardlinkRejected);
        }
        if !directory && !matches!((stat.st_mode as u32) & 0o7777, 0o400 | 0o600) {
            return Err(WriterError::SourceIdentityChanged);
        }
        let size = u64::try_from(stat.st_size).map_err(|_| WriterError::SourceIdentityChanged)?;
        if !directory && size > MAX_SOURCE_FILE_BYTES {
            return Err(WriterError::FileTooLarge);
        }
        Ok(Self {
            identity: SourceFilesystemIdentity {
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
            },
            uid: stat.st_uid,
            mode: stat.st_mode as u32,
            nlink: stat.st_nlink as u64,
            size,
            mtime: stat.st_mtime as i64,
            mtime_nsec: stat.st_mtime_nsec as i64,
            ctime: stat.st_ctime as i64,
            ctime_nsec: stat.st_ctime_nsec as i64,
        })
    }
}
struct PinnedDirectory {
    file: File,
    identity: SourceFilesystemIdentity,
}
struct PinnedTarget {
    root: WorkspaceRootPin,
    components: Vec<String>,
    directories: Vec<PinnedDirectory>,
}
fn exact_entry(parent: &File, name: &str) -> Result<(), WriterError> {
    if !name.is_ascii() {
        return Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch.into());
    }
    let mut found = false;
    let mut count = 0;
    for entry in Dir::read_from(parent)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        count += 1;
        if count > MAX_DIRECTORY_ENTRIES {
            return Err(SourcePathHoldReason::HeldSourceDirectoryEnumerationLimit.into());
        }
        if !bytes.is_ascii()
            || (bytes != name.as_bytes() && bytes.eq_ignore_ascii_case(name.as_bytes()))
        {
            return Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch.into());
        }
        found |= bytes == name.as_bytes();
    }
    if !found {
        return Err(SourcePathHoldReason::HeldSourceMissing.into());
    }
    Ok(())
}
impl PinnedTarget {
    fn open(root: &WorkspaceRootPin, path: &str) -> Result<Self, WriterError> {
        root.verify()?;
        let components: Vec<String> = validate_enrolled_relative_path(path)?
            .into_iter()
            .map(str::to_owned)
            .collect();
        let file = File::from(openat(
            CWD,
            root.path.as_path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let identity = FileStamp::of(&fstat(&file)?, root.uid, true)?.identity;
        if identity
            != (SourceFilesystemIdentity {
                dev: root.dev,
                ino: root.ino,
            })
        {
            return Err(WriterError::SourceIdentityChanged);
        }
        let mut directories = vec![PinnedDirectory { file, identity }];
        for component in &components[..components.len() - 1] {
            let parent = &directories[directories.len() - 1].file;
            exact_entry(parent, component)?;
            let before = FileStamp::of(
                &statat(parent, component.as_str(), AtFlags::SYMLINK_NOFOLLOW)?,
                root.uid,
                true,
            )?;
            let file = File::from(openat(
                parent,
                component.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            if FileStamp::of(&fstat(&file)?, root.uid, true)? != before {
                return Err(WriterError::SourceIdentityChanged);
            }
            directories.push(PinnedDirectory {
                file,
                identity: before.identity,
            });
        }
        let target = Self {
            root: root.clone(),
            components,
            directories,
        };
        target.recheck()?;
        Ok(target)
    }
    fn parent(&self) -> &File {
        &self.directories[self.directories.len() - 1].file
    }
    fn leaf(&self) -> &str {
        &self.components[self.components.len() - 1]
    }
    fn recheck(&self) -> Result<(), WriterError> {
        self.root.verify()?;
        for (index, directory) in self.directories.iter().enumerate() {
            let opened = FileStamp::of(&fstat(&directory.file)?, self.root.uid, true)?;
            let bound = if index == 0 {
                statat(CWD, self.root.path.as_path(), AtFlags::SYMLINK_NOFOLLOW)?
            } else {
                statat(
                    &self.directories[index - 1].file,
                    self.components[index - 1].as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?
            };
            if opened.identity != directory.identity
                || FileStamp::of(&bound, self.root.uid, true)?.identity != directory.identity
            {
                return Err(WriterError::SourceIdentityChanged);
            }
            exact_entry(&directory.file, &self.components[index])?;
        }
        Ok(())
    }
    fn read(&self) -> Result<(Vec<u8>, FileStamp), WriterError> {
        self.recheck()?;
        let parent = self.parent();
        let leaf = self.leaf();
        let before = FileStamp::of(
            &statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)?,
            self.root.uid,
            false,
        )?;
        let mut file = File::from(openat(
            parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        if FileStamp::of(&fstat(&file)?, self.root.uid, false)? != before {
            return Err(WriterError::SourceIdentityChanged);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_SOURCE_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SOURCE_FILE_BYTES {
            return Err(WriterError::FileTooLarge);
        }
        if FileStamp::of(&fstat(&file)?, self.root.uid, false)? != before
            || FileStamp::of(
                &statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)?,
                self.root.uid,
                false,
            )? != before
            || bytes.len() as u64 != before.size
        {
            return Err(WriterError::SourceIdentityChanged);
        }
        self.recheck()?;
        Ok((bytes, before))
    }
}

/// Immutable provenance survives every clone and cannot be selected by callers.
/// Fixture finalization must use a distinct private constructor; production
/// journal recovery continues to decode only the original production metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
enum WriterProofOriginV1 {
    Production,
    Fixture(crate::task_acceptance::FixtureProvenanceV1),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterCommitProof {
    pub(crate) operation_id: String,
    pub(crate) workspace_id: String,
    pub(crate) repo_id: String,
    pub(crate) source_worktree_id: String,
    pub(crate) task_source_id: String,
    pub(crate) canonical_relative_path: String,
    pub(crate) source_generation: u64,
    pub(crate) writer_principal: String,
    pub(crate) writer_epoch: u64,
    pub(crate) config_revision: u64,
    pub(crate) authority_epoch: u64,
    pub(crate) config_digest: [u8; 32],
    pub(crate) proposal_expected_file_cas_rev: u64,
    pub(crate) expected_file_cas_rev: u64,
    pub(crate) rebases_used: u8,
    pub(crate) committed_file_cas_rev: u64,
    pub(crate) expected_preimage_bytes: u64,
    pub(crate) committed_postimage_bytes: u64,
    pub(crate) expected_preimage_sha256: [u8; 32],
    pub(crate) committed_postimage_sha256: [u8; 32],
    pub(crate) previous_identity: SourceFilesystemIdentity,
    pub(crate) committed_identity: SourceFilesystemIdentity,
    origin: WriterProofOriginV1,
    _seal: (),
}
impl WriterCommitProof {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }
    pub fn source_worktree_id(&self) -> &str {
        &self.source_worktree_id
    }
    pub fn task_source_id(&self) -> &str {
        &self.task_source_id
    }
    pub fn canonical_relative_path(&self) -> &str {
        &self.canonical_relative_path
    }
    pub fn source_generation(&self) -> u64 {
        self.source_generation
    }
    pub fn writer_principal(&self) -> &str {
        &self.writer_principal
    }
    pub fn writer_epoch(&self) -> u64 {
        self.writer_epoch
    }
    pub fn config_revision(&self) -> u64 {
        self.config_revision
    }
    pub fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
    pub fn config_digest(&self) -> &[u8; 32] {
        &self.config_digest
    }
    pub fn proposal_expected_file_cas_rev(&self) -> u64 {
        self.proposal_expected_file_cas_rev
    }
    pub fn expected_file_cas_rev(&self) -> u64 {
        self.expected_file_cas_rev
    }
    pub fn actual_predecessor_file_cas_rev(&self) -> u64 {
        self.expected_file_cas_rev
    }
    pub fn rebases_used(&self) -> u8 {
        self.rebases_used
    }
    pub fn committed_file_cas_rev(&self) -> u64 {
        self.committed_file_cas_rev
    }
    pub fn expected_preimage_bytes(&self) -> u64 {
        self.expected_preimage_bytes
    }
    pub fn predecessor_byte_len(&self) -> u64 {
        self.expected_preimage_bytes
    }
    pub fn committed_postimage_bytes(&self) -> u64 {
        self.committed_postimage_bytes
    }
    pub fn committed_postimage_byte_len(&self) -> u64 {
        self.committed_postimage_bytes
    }
    pub fn expected_preimage_sha256(&self) -> &[u8; 32] {
        &self.expected_preimage_sha256
    }
    pub fn committed_postimage_sha256(&self) -> &[u8; 32] {
        &self.committed_postimage_sha256
    }
    pub fn previous_identity(&self) -> SourceFilesystemIdentity {
        self.previous_identity
    }
    pub fn committed_identity(&self) -> SourceFilesystemIdentity {
        self.committed_identity
    }
    pub fn verify_for_source_record(
        &self,
        policy: &WorkspaceTaskPolicy,
        record: &TaskSourceRecord,
        current_identity: Option<SourceFilesystemIdentity>,
    ) -> Result<SourceFilesystemIdentity, HeldReason> {
        // A controlled fixture result can never adopt a live source record,
        // even when every scalar and filesystem binding otherwise matches.
        if self.origin != WriterProofOriginV1::Production {
            return Err(HeldReason::PolicyBindingMismatch);
        }
        record.validate(policy)?;
        record.state.check_new_admission()?;
        if self.workspace_id != policy.workspace_id
            || self.repo_id != policy.repo_id
            || self.config_revision != policy.config_revision
            || self.authority_epoch != policy.authority_epoch
            || self.config_digest != policy.config_digest
            || self.workspace_id != record.workspace_id
            || self.repo_id != record.repo_id
            || self.source_worktree_id != record.source_worktree_id
            || self.task_source_id != record.task_source_id
            || self.canonical_relative_path != record.canonical_relative_path
            || self.source_generation != record.source_generation
            || self.writer_principal != record.writer_principal
            || self.writer_epoch != record.writer_epoch
            || self.config_digest != record.config_digest
            || self.previous_identity.dev != self.committed_identity.dev
            || self.previous_identity == self.committed_identity
            || current_identity.is_none_or(|identity| {
                identity != self.previous_identity && identity != self.committed_identity
            })
            || self.expected_file_cas_rev.checked_add(1) != Some(self.committed_file_cas_rev)
            || self
                .expected_file_cas_rev
                .checked_sub(self.proposal_expected_file_cas_rev)
                != Some(u64::from(self.rebases_used))
            || usize::from(self.rebases_used) > MAX_UNRELATED_FILE_REBASES
            || self.expected_preimage_bytes == 0
            || self.expected_preimage_bytes > MAX_SOURCE_FILE_BYTES
            || self.committed_postimage_bytes == 0
            || self.committed_postimage_bytes > MAX_SOURCE_FILE_BYTES
            || encode_checked_rev(self.committed_file_cas_rev).is_err()
        {
            return Err(HeldReason::PolicyBindingMismatch);
        }
        Ok(self.committed_identity)
    }
    fn from_record(record: &JournalRecordV1) -> Result<Self, WriterError> {
        let lease: WriterLeaseV1 = serde_json::from_value(record.request.metadata.clone())
            .map_err(|_| WriterError::PolicyBindingMismatch)?;
        let prepared = record
            .prepared
            .as_ref()
            .ok_or(WriterError::OperationInProgress)?;
        prepared.validate()?;
        let admitted = TaskRefV1::decode(&record.request.signed_task_ref)?;
        if record.request.workspace_id != lease.workspace_id
            || record.request.task_source_id != lease.task_source_id
            || prepared.canonical_relative_path != lease.canonical_relative_path
            || admitted.workspace_id != lease.workspace_id
            || admitted.task_source_id != lease.task_source_id
            || admitted.repo_id != lease.repo_id
            || admitted.source_generation != lease.source_generation
            || admitted.canonical_task_path != lease.canonical_relative_path
            || admitted.file_cas_rev != prepared.proposal_expected_file_cas_rev
            || prepared.rebases_used != record.unrelated_file_rebases
            || checked_next_revision(prepared.predecessor_revision)? != prepared.successor_revision
        {
            return Err(WriterError::PolicyBindingMismatch);
        }
        Ok(Self {
            operation_id: record.request.operation_id.clone(),
            workspace_id: lease.workspace_id,
            repo_id: lease.repo_id,
            source_worktree_id: lease.source_worktree_id,
            task_source_id: lease.task_source_id,
            canonical_relative_path: lease.canonical_relative_path,
            source_generation: lease.source_generation,
            writer_principal: lease.writer_principal,
            writer_epoch: lease.writer_epoch,
            config_revision: lease.config_revision,
            authority_epoch: lease.authority_epoch,
            config_digest: lease.config_digest,
            proposal_expected_file_cas_rev: prepared.proposal_expected_file_cas_rev,
            expected_file_cas_rev: prepared.expected_file_cas_rev,
            rebases_used: prepared.rebases_used,
            committed_file_cas_rev: prepared.successor_revision,
            expected_preimage_bytes: prepared.expected_preimage_bytes,
            committed_postimage_bytes: prepared.committed_postimage_bytes,
            expected_preimage_sha256: prepared.predecessor_hash,
            committed_postimage_sha256: prepared.successor_hash,
            previous_identity: SourceFilesystemIdentity {
                dev: prepared.previous_dev,
                ino: prepared.previous_ino,
            },
            committed_identity: SourceFilesystemIdentity {
                dev: prepared.staged_dev,
                ino: prepared.staged_ino,
            },
            origin: WriterProofOriginV1::Production,
            _seal: (),
        })
    }
}

pub struct WriterContextV1<'a> {
    pub root: &'a WorkspaceRootPin,
    pub lease: &'a WriterLeaseV1,
    /// Current registry identity, including any previously adopted writer commit.
    pub source_identity: SourceFilesystemIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterStep {
    Prepared,
    BeforeRename,
    AfterRename,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriterWriteOutcome {
    Committed(WriterCommitProof),
    DuplicateRecorded(WriterCommitProof),
    Rejected,
    Held,
}

fn journal_phase(
    journal: &mut Journal,
    entry: &mut JournalRecordV1,
    next: WriteOperationState,
) -> Result<(), WriterError> {
    entry.state.transition_to(next)?;
    if entry.result.is_none()
        && matches!(
            next,
            WriteOperationState::Recorded
                | WriteOperationState::Acknowledged
                | WriteOperationState::Rejected
                | WriteOperationState::Held
        )
    {
        entry.result = Some(serde_json::json!({"disposition": format!("{next:?}")}));
    }
    journal.append(entry.clone())?;
    Ok(())
}
fn cleanup_temp(parent: &File, prepared: &PreparedWriteV1, uid: u32) -> Result<(), WriterError> {
    match statat(
        parent,
        prepared.temp_name.as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(error.into()),
        Ok(stat) => {
            let stamp = FileStamp::of(&stat, uid, false)?;
            if stamp.identity
                != (SourceFilesystemIdentity {
                    dev: prepared.staged_dev,
                    ino: prepared.staged_ino,
                })
            {
                return Err(WriterError::SourceIdentityChanged);
            }
            unlinkat(parent, prepared.temp_name.as_str(), AtFlags::empty())?;
            parent.sync_all()?;
            Ok(())
        }
    }
}

/// Requires the retained journal namespace lock. `refresh_authority` must read
/// current policy, epoch and trusted host time; it is called at validation and
/// after the final pre-rename hook. The projection callback must durably record
/// the exact proof before this function can return a successful disposition.
pub fn commit_task_write(
    context: &WriterContextV1<'_>,
    journal: &mut Journal,
    request: &TaskWriteRequestV1,
    dependencies: &[DependencySnapshotV1],
    mut refresh_authority: impl FnMut() -> Result<WriterAuthoritySnapshot, WriterError>,
    mut hook: impl FnMut(WriterStep, &File, &str) -> Result<(), WriterError>,
    mut record_projection: impl FnMut(&WriterCommitProof) -> Result<(), WriterError>,
) -> Result<WriterWriteOutcome, WriterError> {
    validate_task_source_id(&request.operation_id)?;
    let authority = request.authority()?;
    if request.operation_id != authority.operation_id
        || request.request_message_id != authority.message_id
        || request.authenticated_signer_principal != authority.signer
        || request.admitted_task_ref != authority.task_ref
        || request.nonce != authority.nonce
        || request.request_digest_sha256 != authority.proposal_digest.0
        || request.canonical_request_digest()? != request.request_digest_sha256
    {
        return Err(WriterError::AuthorityMismatch);
    }
    let journal_request = JournalRequestV1 {
        workspace_id: request.admitted_task_ref.workspace_id.clone(),
        task_source_id: request.admitted_task_ref.task_source_id.clone(),
        operation_id: request.operation_id.clone(),
        signer_principal: request.authenticated_signer_principal.clone(),
        request_id: request.request_message_id.clone(),
        request_digest: request.request_digest_sha256,
        nonce: request.nonce,
        writer_epoch: context.lease.writer_epoch,
        signed_task_ref: request.admitted_task_ref.encode()?,
        metadata: serde_json::to_value(context.lease).map_err(|_| WriterError::InvalidDocument)?,
    };
    let mut entry = match journal.reserve(journal_request)? {
        ReplayDispositionV1::Fresh(entry) => entry,
        ReplayDispositionV1::Existing(entry) | ReplayDispositionV1::DuplicateRecorded(entry) => {
            return match entry.state {
                WriteOperationState::Recorded | WriteOperationState::Acknowledged => Ok(
                    WriterWriteOutcome::DuplicateRecorded(WriterCommitProof::from_record(&entry)?),
                ),
                WriteOperationState::Rejected => Ok(WriterWriteOutcome::Rejected),
                WriteOperationState::Held => Ok(WriterWriteOutcome::Held),
                WriteOperationState::FileCommitted => {
                    match classify_and_recover_prepared_operation(
                        context,
                        journal,
                        &entry.request.operation_id,
                        &mut refresh_authority,
                        &mut record_projection,
                    )? {
                        RecoveredCommitOutcome::Committed(proof) => {
                            Ok(WriterWriteOutcome::DuplicateRecorded(*proof))
                        }
                        RecoveredCommitOutcome::RolledBack => Ok(WriterWriteOutcome::Rejected),
                        RecoveredCommitOutcome::Held(_) => Ok(WriterWriteOutcome::Held),
                    }
                }
                _ => Err(WriterError::OperationInProgress),
            };
        }
    };
    // Any unresolved predecessor, including a different operation, fences this
    // source. A new lease does not erase a durable unknown disposition.
    if journal.latest_records().any(|other| {
        other.request.workspace_id == entry.request.workspace_id
            && other.request.task_source_id == entry.request.task_source_id
            && other.request.operation_id != entry.request.operation_id
            && !matches!(
                other.state,
                WriteOperationState::Acknowledged | WriteOperationState::Rejected
            )
    }) {
        journal_phase(journal, &mut entry, WriteOperationState::Held)?;
        return Err(WriterError::SourceHeld);
    }
    let initial = match refresh_authority() {
        Ok(current) => current,
        Err(error) => {
            journal_phase(journal, &mut entry, WriteOperationState::Held)?;
            return Err(error);
        }
    };
    if let Err(error) = context.lease.verify(&initial) {
        journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
        return Err(error);
    }
    if let Err(error) = verify_proposal_fence(authority, &initial) {
        journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
        return Err(error);
    }
    let lease = context.lease;
    let admitted = &request.admitted_task_ref;
    if admitted.workspace_id != lease.workspace_id
        || admitted.repo_id != lease.repo_id
        || admitted.task_source_id != lease.task_source_id
        || admitted.source_generation != lease.source_generation
        || admitted.canonical_task_path != lease.canonical_relative_path
    {
        journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
        return Err(WriterError::PolicyBindingMismatch);
    }
    let validated = (|| {
        let target = PinnedTarget::open(context.root, &lease.canonical_relative_path)?;
        let (bytes, stamp) = target.read()?;
        if stamp.identity != context.source_identity {
            return Err(WriterError::SourceIdentityChanged);
        }
        let hash = Sha256Digest::of(&bytes).0;
        let live = CanonicalTaskDocumentV1::from_bytes(&bytes)?;
        let (postimage, used) = rebase_task_mutation(
            request,
            &live,
            hash,
            usize::from(entry.unrelated_file_rebases),
        )?;
        let task = live
            .tasks
            .iter()
            .find(|task| task.task_id == admitted.task_id)
            .ok_or(WriterError::TargetTaskConflict)?;
        authorize_transition(
            &live,
            task,
            &lease.canonical_relative_path,
            request.next_status,
            &request.authorization,
            dependencies,
        )?;
        verify_current_transition_grant(&request.authorization, request.next_status, &initial)?;
        Ok((target, stamp, hash, live, postimage, used))
    })();
    let (target, stamp, hash, live, postimage, used) = match validated {
        Ok(value) => value,
        Err(error) => {
            journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
            return Err(error);
        }
    };
    if used > 0
        && !journal.latest_records().any(|prior| {
            prior.request.workspace_id == lease.workspace_id
                && prior.request.task_source_id == lease.task_source_id
                && matches!(
                    prior.state,
                    WriteOperationState::Recorded | WriteOperationState::Acknowledged
                )
                && prior.prepared.as_ref().is_some_and(|prepared| {
                    prepared.successor_hash == hash
                        && prepared.successor_revision == live.file_cas_rev
                        && prepared.staged_dev == stamp.identity.dev
                        && prepared.staged_ino == stamp.identity.ino
                })
        })
    {
        journal_phase(journal, &mut entry, WriteOperationState::Held)?;
        return Err(WriterError::SourceHeld);
    }
    let mut authorization = ProductionCommitAuthorityV1 { context, request,
        refresh: &mut refresh_authority, projection: &mut record_projection };
    commit_planned_task_write(context, journal, entry, PlannedTaskMutationV1 {
        target, stamp, hash, live, postimage, used, admitted_ref: admitted.clone(),
        temp_name: format!(".chinwag-tmp-{}", request.operation_id),
    }, &mut authorization, &mut hook)
}

struct PlannedTaskMutationV1 {
    target: PinnedTarget,
    stamp: FileStamp,
    hash: [u8; 32],
    live: CanonicalTaskDocumentV1,
    postimage: CanonicalTaskDocumentV1,
    used: usize,
    admitted_ref: TaskRefV1,
    temp_name: String,
}

/// Private transaction hooks keep transition authority separate from the shared
/// descriptor-fenced staging/rename machinery. Only the authority-specific
/// implementations below may supply projection and post-Recorded finalization.
trait PreparedCommitAuthorityV1 {
    fn before_replace(&mut self) -> Result<(), WriterError>;
    fn expected_projection(&self) -> Option<serde_json::Value>;
    fn project(&mut self, record: &JournalRecordV1) -> Result<Option<serde_json::Value>, WriterError>;
    fn finalize_recorded(&mut self, journal: &mut Journal, record: &JournalRecordV1) -> Result<WriterCommitProof, WriterError>;
}

struct ProductionCommitAuthorityV1<'a, 'root, F, P> {
    context: &'a WriterContextV1<'root>,
    request: &'a TaskWriteRequestV1,
    refresh: &'a mut F,
    projection: &'a mut P,
}
impl<F, P> PreparedCommitAuthorityV1 for ProductionCommitAuthorityV1<'_, '_, F, P>
where F: FnMut() -> Result<WriterAuthoritySnapshot, WriterError>,
      P: FnMut(&WriterCommitProof) -> Result<(), WriterError> {
    fn before_replace(&mut self) -> Result<(), WriterError> {
        let current = (self.refresh)()?;
        self.context.lease.verify(&current)?;
        verify_proposal_fence(self.request.authority()?, &current)?;
        verify_current_review_grant(&self.request.authorization, &current)?;
        verify_current_transition_grant(&self.request.authorization, self.request.next_status, &current)
    }
    fn expected_projection(&self) -> Option<serde_json::Value> { None }
    fn project(&mut self, record: &JournalRecordV1) -> Result<Option<serde_json::Value>, WriterError> {
        let proof = WriterCommitProof::from_record(record)?;
        (self.projection)(&proof)?;
        Ok(None)
    }
    fn finalize_recorded(&mut self, _journal: &mut Journal, record: &JournalRecordV1) -> Result<WriterCommitProof, WriterError> {
        WriterCommitProof::from_record(record)
    }
}

fn commit_planned_task_write(
    context: &WriterContextV1<'_>,
    journal: &mut Journal,
    mut entry: JournalRecordV1,
    mutation: PlannedTaskMutationV1,
    authorization: &mut impl PreparedCommitAuthorityV1,
    hook: &mut impl FnMut(WriterStep, &File, &str) -> Result<(), WriterError>,
) -> Result<WriterWriteOutcome, WriterError> {
    let PlannedTaskMutationV1 { target, stamp, hash, live, postimage, used, admitted_ref, temp_name } = mutation;
    let lease = context.lease;
    let admitted = &admitted_ref;
    journal_phase(journal, &mut entry, WriteOperationState::Validated)?;
    let postimage = postimage.to_canonical_bytes()?;
    let parent = FileStamp::of(&fstat(target.parent())?, context.root.uid, true)?.identity;
    let mut prepared = PreparedWriteV1 {
        canonical_relative_path: lease.canonical_relative_path.clone(),
        target_name: target.leaf().into(),
        temp_name,
        parent_dev: parent.dev,
        parent_ino: parent.ino,
        previous_dev: stamp.identity.dev,
        previous_ino: stamp.identity.ino,
        staged_dev: parent.dev,
        staged_ino: u64::MAX,
        predecessor_hash: hash,
        successor_hash: Sha256Digest::of(&postimage).0,
        predecessor_revision: live.file_cas_rev,
        successor_revision: checked_next_revision(live.file_cas_rev)?,
        proposal_expected_file_cas_rev: admitted.file_cas_rev,
        expected_file_cas_rev: live.file_cas_rev,
        rebases_used: used as u8,
        expected_preimage_bytes: stamp.size,
        committed_postimage_bytes: postimage.len() as u64,
    };
    // The maximal inode encoding bounds the full Prepared snapshot before the
    // first staging effect. Its reservation survives a process restart.
    let mut preflight = entry.clone();
    preflight.state = WriteOperationState::Prepared;
    preflight.prepared = Some(prepared.clone());
    preflight.unrelated_file_rebases = used as u8;
    if let Err(error) = journal.preflight_completion(&preflight) {
        journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
        return Err(error.into());
    }
    let expected_projection = authorization.expected_projection();
    let mut terminal = preflight.clone();
    terminal.state = WriteOperationState::Acknowledged;
    terminal.result = Some(expected_projection.clone().unwrap_or_else(|| serde_json::json!({"disposition": "Acknowledged"})));
    if let Err(error) = journal.preflight_record_size(&terminal) {
        journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
        return Err(error.into());
    }
    let mut temp = File::from(openat(
        target.parent(),
        prepared.temp_name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    if let Err(error) = temp.write_all(&postimage).and_then(|()| temp.sync_all()) {
        unlinkat(
            target.parent(),
            prepared.temp_name.as_str(),
            AtFlags::empty(),
        )?;
        target.parent().sync_all()?;
        journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
        return Err(error.into());
    }
    let staged = FileStamp::of(&fstat(&temp)?, context.root.uid, false)?;
    if staged.identity.dev != stamp.identity.dev || staged.identity.ino == stamp.identity.ino {
        unlinkat(
            target.parent(),
            prepared.temp_name.as_str(),
            AtFlags::empty(),
        )?;
        return Err(WriterError::SourceIdentityChanged);
    }
    prepared.staged_dev = staged.identity.dev;
    prepared.staged_ino = staged.identity.ino;
    entry.prepared = Some(prepared.clone());
    entry.unrelated_file_rebases = used as u8;
    if let Err(error) = journal_phase(journal, &mut entry, WriteOperationState::Prepared) {
        cleanup_temp(target.parent(), &prepared, context.root.uid)?;
        return Err(error);
    }
    // Persist the directory entry of the synced staging file before allowing a
    // controlled crash/restart to inspect it.
    target.parent().sync_all()?;
    let before_rename = (|| {
        hook(WriterStep::Prepared, target.parent(), target.leaf())?;
        hook(WriterStep::BeforeRename, target.parent(), target.leaf())?;
        verify_prepared_stage(target.parent(), &prepared, context.root.uid)?;
        if FileStamp::of(&fstat(&temp)?, context.root.uid, false)? != staged {
            return Err(WriterError::SourceIdentityChanged);
        }
        let (current, current_stamp) = target.read()?;
        if current_stamp != stamp || Sha256Digest::of(&current).0 != hash {
            return Err(WriterError::SourceIdentityChanged);
        }
        authorization.before_replace()?;
        journal.preflight_completion(&entry)?;
        if FileStamp::of(
            &statat(target.parent(), target.leaf(), AtFlags::SYMLINK_NOFOLLOW)?,
            context.root.uid,
            false,
        )? != stamp
            || FileStamp::of(
                &statat(
                    target.parent(),
                    prepared.temp_name.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?,
                context.root.uid,
                false,
            )? != staged
        {
            return Err(WriterError::SourceIdentityChanged);
        }
        Ok(())
    })();
    if let Err(error) = before_rename {
        if matches!(error, WriterError::InjectedCrash) {
            return Err(error);
        }
        if let Err(cleanup_error) = cleanup_temp(target.parent(), &prepared, context.root.uid) {
            journal_phase(journal, &mut entry, WriteOperationState::Held)?;
            return Err(cleanup_error);
        }
        let disposition = if matches!(
            error,
            WriterError::SourceIdentityChanged | WriterError::Journal(_)
        ) {
            WriteOperationState::Held
        } else {
            WriteOperationState::Rejected
        };
        journal_phase(journal, &mut entry, disposition)?;
        return Err(error);
    }
    renameat(
        target.parent(),
        prepared.temp_name.as_str(),
        target.parent(),
        target.leaf(),
    )?;
    hook(WriterStep::AfterRename, target.parent(), target.leaf())?;
    target.parent().sync_all()?;
    target.recheck()?;
    if inspect_prepared(target.parent(), &prepared, context.root.uid)?
        != RecoveryFileState::Successor
    {
        journal_phase(journal, &mut entry, WriteOperationState::Held)?;
        return Err(WriterError::SourceIdentityChanged);
    }
    journal_phase(journal, &mut entry, WriteOperationState::FileCommitted)?;
    let actual_projection = authorization.project(&entry)?;
    if actual_projection != expected_projection {
        return Err(WriterError::PolicyBindingMismatch);
    }
    if let Some(projection) = actual_projection {
        entry.result = Some(projection);
    }
    target.recheck()?;
    if inspect_prepared(target.parent(), &prepared, context.root.uid)?
        != RecoveryFileState::Successor
    {
        journal_phase(journal, &mut entry, WriteOperationState::Held)?;
        return Err(WriterError::SourceIdentityChanged);
    }
    journal_phase(journal, &mut entry, WriteOperationState::Recorded)?;
    let proof = authorization.finalize_recorded(journal, &entry)?;
    journal_phase(journal, &mut entry, WriteOperationState::Acknowledged)?;
    Ok(WriterWriteOutcome::Committed(proof))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrashClassification {
    F0PreRename,
    F1Committed,
    FxExternalDrift,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveredCommitOutcome {
    RolledBack,
    Committed(Box<WriterCommitProof>),
    Held(CrashClassification),
}

/// Conservative F0 rollback is explicit; completion requires resubmission of
/// the original prepared proposal through an operator reconciliation path.
/// F1 needs current authority and durable projection reconciliation, never a
/// second rename or revision increment. Fx preserves external evidence.
fn require_production_recovery_request(
    context: &WriterContextV1<'_>,
    record: &JournalRecordV1,
) -> Result<(), WriterError> {
    // Reject fixture and unknown metadata before any recovery disposition,
    // cleanup, projection or journal append. Production decoding is strict.
    let lease: WriterLeaseV1 = serde_json::from_value(record.request.metadata.clone())
        .map_err(|_| WriterError::PolicyBindingMismatch)?;
    if lease != *context.lease
        || record.request.workspace_id != lease.workspace_id
        || record.request.task_source_id != lease.task_source_id
    {
        return Err(WriterError::PolicyBindingMismatch);
    }
    Ok(())
}

pub fn classify_and_recover_prepared_operation(
    context: &WriterContextV1<'_>,
    journal: &mut Journal,
    operation_id: &str,
    mut refresh_authority: impl FnMut() -> Result<WriterAuthoritySnapshot, WriterError>,
    mut record_projection: impl FnMut(&WriterCommitProof) -> Result<(), WriterError>,
) -> Result<RecoveredCommitOutcome, WriterError> {
    let lease = context.lease;
    let mut entry = journal
        .latest(&lease.workspace_id, &lease.task_source_id, operation_id)
        .cloned()
        .ok_or(WriterError::OperationInProgress)?;
    require_production_recovery_request(context, &entry)?;
    journal.lookup_request(&entry.request)?;
    let had_file_commit = journal.had_durable_file_commit(&entry.request);
    if matches!(
        entry.state,
        WriteOperationState::Recorded | WriteOperationState::Acknowledged
    ) {
        return Ok(RecoveredCommitOutcome::Committed(Box::new(
            WriterCommitProof::from_record(&entry)?,
        )));
    }
    if !matches!(
        entry.state,
        WriteOperationState::Prepared
            | WriteOperationState::Reconciling
            | WriteOperationState::FileCommitted
    ) {
        return Err(WriterError::OperationInProgress);
    }
    if matches!(
        entry.state,
        WriteOperationState::Prepared | WriteOperationState::FileCommitted
    ) {
        journal_phase(journal, &mut entry, WriteOperationState::Reconciling)?;
    }
    let prepared = entry.prepared.clone().ok_or(WriterError::InvalidDocument)?;
    journal.preflight_completion(&entry)?;
    let target = match PinnedTarget::open(context.root, &lease.canonical_relative_path) {
        Ok(target) => target,
        Err(_) => {
            journal_phase(journal, &mut entry, WriteOperationState::Held)?;
            return Ok(RecoveredCommitOutcome::Held(
                CrashClassification::FxExternalDrift,
            ));
        }
    };
    match inspect_prepared(target.parent(), &prepared, context.root.uid)
        .unwrap_or(RecoveryFileState::Other)
    {
        RecoveryFileState::Predecessor if !had_file_commit => {
            if cleanup_temp(target.parent(), &prepared, context.root.uid).is_err() {
                journal_phase(journal, &mut entry, WriteOperationState::Held)?;
                return Ok(RecoveredCommitOutcome::Held(
                    CrashClassification::FxExternalDrift,
                ));
            }
            journal_phase(journal, &mut entry, WriteOperationState::Rejected)?;
            Ok(RecoveredCommitOutcome::RolledBack)
        }
        RecoveryFileState::Successor => {
            let proof = WriterCommitProof::from_record(&entry)?;
            let current_authority = refresh_authority()?;
            proof
                .verify_for_source_record(
                    &current_authority.policy,
                    &current_authority.record,
                    Some(context.source_identity),
                )
                .map_err(|_| WriterError::PolicyBindingMismatch)?;
            lease.verify(&current_authority)?;
            target.parent().sync_all()?;
            record_projection(&proof)?;
            target.recheck()?;
            if inspect_prepared(target.parent(), &prepared, context.root.uid)
                .unwrap_or(RecoveryFileState::Other)
                != RecoveryFileState::Successor
            {
                journal_phase(journal, &mut entry, WriteOperationState::Held)?;
                return Ok(RecoveredCommitOutcome::Held(
                    CrashClassification::FxExternalDrift,
                ));
            }
            journal_phase(journal, &mut entry, WriteOperationState::Recorded)?;
            journal_phase(journal, &mut entry, WriteOperationState::Acknowledged)?;
            Ok(RecoveredCommitOutcome::Committed(Box::new(proof)))
        }
        _ => {
            journal_phase(journal, &mut entry, WriteOperationState::Held)?;
            Ok(RecoveredCommitOutcome::Held(
                CrashClassification::FxExternalDrift,
            ))
        }
    }
}

/// An operator may reject an interrupted operation that never acquired a
/// prepared replacement. This preserves its replay disposition and permits
/// later proposals without fabricating any committed phase.
pub fn reject_unprepared_operation(
    context: &WriterContextV1<'_>,
    journal: &mut Journal,
    operation_id: &str,
    current: &WriterAuthoritySnapshot,
) -> Result<(), WriterError> {
    context.lease.verify(current)?;
    let mut entry = journal
        .latest(
            &context.lease.workspace_id,
            &context.lease.task_source_id,
            operation_id,
        )
        .cloned()
        .ok_or(WriterError::OperationInProgress)?;
    require_production_recovery_request(context, &entry)?;
    journal.lookup_request(&entry.request)?;
    if !matches!(
        entry.state,
        WriteOperationState::Received | WriteOperationState::Validated
    ) {
        return Err(WriterError::OperationInProgress);
    }
    journal_phase(journal, &mut entry, WriteOperationState::Rejected)
}

/// Explicitly resume the original F0 intent under fresh authority. The full
/// original typed proposal is required; the staged bytes alone confer no
/// transition or review authority. This never substitutes a new operation ID.
pub fn complete_prepared_operation(
    context: &WriterContextV1<'_>,
    journal: &mut Journal,
    request: &TaskWriteRequestV1,
    dependencies: &[DependencySnapshotV1],
    mut refresh_authority: impl FnMut() -> Result<WriterAuthoritySnapshot, WriterError>,
    mut record_projection: impl FnMut(&WriterCommitProof) -> Result<(), WriterError>,
) -> Result<RecoveredCommitOutcome, WriterError> {
    let lease = context.lease;
    let mut entry = journal
        .latest(
            &lease.workspace_id,
            &lease.task_source_id,
            &request.operation_id,
        )
        .cloned()
        .ok_or(WriterError::OperationInProgress)?;
    require_production_recovery_request(context, &entry)?;
    journal.lookup_request(&entry.request)?;
    // An F0 operator resume cannot erase any historically durable file commit.
    if journal.had_durable_file_commit(&entry.request) {
        return Err(WriterError::SourceHeld);
    }
    if entry.state == WriteOperationState::Prepared {
        journal_phase(journal, &mut entry, WriteOperationState::Reconciling)?;
    }
    if entry.state != WriteOperationState::Reconciling {
        return Err(WriterError::OperationInProgress);
    }
    let authority = request.authority()?;
    if request.canonical_request_digest()? != entry.request.request_digest
        || request.request_digest_sha256 != entry.request.request_digest
        || request.admitted_task_ref.encode()? != entry.request.signed_task_ref
        || request.authenticated_signer_principal != entry.request.signer_principal
        || request.request_message_id != entry.request.request_id
        || request.nonce != entry.request.nonce
        || authority.proposal_digest.0 != entry.request.request_digest
        || authority.operation_id != request.operation_id
        || authority.signer != request.authenticated_signer_principal
        || authority.message_id != request.request_message_id
        || authority.task_ref != request.admitted_task_ref
        || authority.nonce != request.nonce
    {
        return Err(WriterError::AuthorityMismatch);
    }
    let prepared = entry
        .prepared
        .clone()
        .ok_or(WriterError::OperationInProgress)?;
    journal.preflight_completion(&entry)?;
    let target = PinnedTarget::open(context.root, &lease.canonical_relative_path)?;
    if inspect_prepared(target.parent(), &prepared, context.root.uid)?
        != RecoveryFileState::Predecessor
    {
        return Err(WriterError::SourceIdentityChanged);
    }
    let (bytes, stamp) = target.read()?;
    let current = refresh_authority()?;
    lease.verify(&current)?;
    verify_proposal_fence(request.authority()?, &current)?;
    let document = CanonicalTaskDocumentV1::from_bytes(&bytes)?;
    let (expected, used) = rebase_task_mutation(request, &document, Sha256Digest::of(&bytes).0, 0)?;
    if Sha256Digest::of(&expected.to_canonical_bytes()?).0 != prepared.successor_hash
        || used != usize::from(entry.unrelated_file_rebases)
        || stamp.identity != context.source_identity
    {
        return Err(WriterError::AcceptanceInvalidated);
    }
    let task = document
        .tasks
        .iter()
        .find(|task| task.task_id == request.admitted_task_ref.task_id)
        .ok_or(WriterError::TargetTaskConflict)?;
    authorize_transition(
        &document,
        task,
        &lease.canonical_relative_path,
        request.next_status,
        &request.authorization,
        dependencies,
    )?;
    verify_current_transition_grant(&request.authorization, request.next_status, &current)?;
    let proof = WriterCommitProof::from_record(&entry)?;
    proof
        .verify_for_source_record(
            &current.policy,
            &current.record,
            Some(context.source_identity),
        )
        .map_err(|_| WriterError::PolicyBindingMismatch)?;
    verify_prepared_stage(target.parent(), &prepared, context.root.uid)?;
    target.recheck()?;
    if target.read()?.1 != stamp {
        return Err(WriterError::SourceIdentityChanged);
    }
    let latest = refresh_authority()?;
    lease.verify(&latest)?;
    verify_proposal_fence(request.authority()?, &latest)?;
    verify_current_review_grant(&request.authorization, &latest)?;
    verify_current_transition_grant(&request.authorization, request.next_status, &latest)?;
    verify_prepared_stage(target.parent(), &prepared, context.root.uid)?;
    journal.preflight_completion(&entry)?;
    if FileStamp::of(
        &statat(target.parent(), target.leaf(), AtFlags::SYMLINK_NOFOLLOW)?,
        context.root.uid,
        false,
    )? != stamp
    {
        return Err(WriterError::SourceIdentityChanged);
    }
    renameat(
        target.parent(),
        prepared.temp_name.as_str(),
        target.parent(),
        target.leaf(),
    )?;
    target.parent().sync_all()?;
    if inspect_prepared(target.parent(), &prepared, context.root.uid)?
        != RecoveryFileState::Successor
    {
        journal_phase(journal, &mut entry, WriteOperationState::Held)?;
        return Err(WriterError::SourceIdentityChanged);
    }
    // The durable Reconciling intent covers this resumed rename and projection.
    // Recovery never returns to FileCommitted, so retries consume no phase cycle.
    record_projection(&proof)?;
    target.recheck()?;
    if inspect_prepared(target.parent(), &prepared, context.root.uid)?
        != RecoveryFileState::Successor
    {
        journal_phase(journal, &mut entry, WriteOperationState::Held)?;
        return Err(WriterError::SourceIdentityChanged);
    }
    journal_phase(journal, &mut entry, WriteOperationState::Recorded)?;
    journal_phase(journal, &mut entry, WriteOperationState::Acknowledged)?;
    Ok(RecoveredCommitOutcome::Committed(Box::new(proof)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_source::{SourceDispatchControls, SourceExecutionMode};
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use tempfile::TempDir;

    fn fixture_evidence() -> TransitionEvidenceV1 {
        TransitionEvidenceV1 {
            admission_id: Some("admission".into()),
            assignment_id: Some("assignment".into()),
            original_operation_id: Some("22222222222222222222222222222222".into()),
            grant_id: Some("grant".into()),
            capacity_claim_id: Some("capacity".into()),
            write_scope_claim_id: Some("scope".into()),
            executor_actor: Some("DEV#implementer".into()),
            blocker: None,
            resolution: None,
        }
    }
    fn fixture_admission(reference: TaskRefV1) -> ExecutionAdmissionV1 {
        ExecutionAdmissionV1 {
            actor: "WRITER#instance".into(),
            authenticated_signer_principal: "writer-key".into(),
            executor_actor: "DEV#implementer".into(),
            task_ref: reference,
            task_control_digest: Sha256Digest([2; 32]),
            admission_id: "admission".into(),
            assignment_id: "assignment".into(),
            original_operation_id: "22222222222222222222222222222222".into(),
            action: "task-write".into(),
            grant_id: "grant".into(),
            capacity_claim_id: "capacity".into(),
            write_scope_claim_id: "scope".into(),
        }
    }

    struct Fixture {
        _temp: TempDir,
        root: WorkspaceRootPin,
        lease: WriterLeaseV1,
        authority: WriterAuthoritySnapshot,
        document: CanonicalTaskDocumentV1,
        identity: SourceFilesystemIdentity,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let path = fs::canonicalize(temp.path()).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            let source_id = "11111111111111111111111111111111".to_string();
            let policy = WorkspaceTaskPolicy {
                workspace_id: "workspace".into(),
                repo_id: "repo".into(),
                config_revision: 1,
                authority_epoch: 1,
                scheduler_owner: "COORD#instance".into(),
                max_sources: 16,
                config_digest: [4; 32],
            };
            let record = TaskSourceRecord {
                workspace_id: policy.workspace_id.clone(),
                repo_id: policy.repo_id.clone(),
                source_worktree_id: "tree".into(),
                task_source_id: source_id.clone(),
                display_name: "tasks".into(),
                canonical_relative_path: "tasks.md".into(),
                source_generation: 0,
                normalization_version: 1,
                schema_version: 1,
                writer_principal: "writer-key".into(),
                writer_epoch: 1,
                config_digest: policy.config_digest,
                state: TaskSourceState::Enrolled,
                controls: SourceDispatchControls {
                    mode: SourceExecutionMode::Implementation,
                    implementation_authorized: true,
                    deployment_authorized: false,
                    automatic_dispatch: false,
                    allowed_actions: vec!["task-write".into()],
                },
            };
            let lease = WriterLeaseV1 {
                workspace_id: policy.workspace_id.clone(),
                repo_id: policy.repo_id.clone(),
                source_worktree_id: record.source_worktree_id.clone(),
                task_source_id: source_id.clone(),
                canonical_relative_path: record.canonical_relative_path.clone(),
                source_generation: 0,
                writer_principal: record.writer_principal.clone(),
                writer_epoch: 1,
                config_revision: 1,
                authority_epoch: 1,
                config_digest: policy.config_digest,
                issued_at_unix: 10,
                expires_at_unix: 20,
            };
            let task = |id: &str| TaskEntrySnapshotV1 {
                task_id: id.into(),
                status: CanonicalTaskStatus::Todo,
                task_status_rev: 0,
                task_spec_digest: Sha256Digest([1; 32]),
                task_control_digest: Sha256Digest([2; 32]),
                completion_policy_digest: Sha256Digest([3; 32]),
                owner_actor: Some("DEV#implementer".into()),
                reviewer_role: "independent-review".into(),
                baseline_commit: GitOid::Sha1([1; 20]),
                candidate_commit: Some(GitOid::Sha1([2; 20])),
                overlay_digest: None,
                execution_flags: vec!["implementation".into()],
                dependencies: Vec::new(),
            };
            let document = CanonicalTaskDocumentV1 {
                workspace_id: policy.workspace_id.clone(),
                repo_id: policy.repo_id.clone(),
                task_source_id: source_id,
                source_generation: 0,
                file_cas_rev: 0,
                last_operation_id: None,
                tasks: vec![task("A"), task("B")],
                markdown: None,
            };
            fs::write(
                path.join("tasks.md"),
                document.to_canonical_bytes().unwrap(),
            )
            .unwrap();
            fs::set_permissions(path.join("tasks.md"), fs::Permissions::from_mode(0o600)).unwrap();
            let file = fs::metadata(path.join("tasks.md")).unwrap();
            fs::create_dir(path.join("journal")).unwrap();
            fs::set_permissions(path.join("journal"), fs::Permissions::from_mode(0o700)).unwrap();
            let admission = fixture_admission(document.task_ref(&document.tasks[0], "tasks.md"));
            Self {
                _temp: temp,
                root: WorkspaceRootPin {
                    path,
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                    uid: metadata.uid(),
                    generation: 1,
                },
                lease,
                authority: WriterAuthoritySnapshot {
                    writer_principal: record.writer_principal.clone(),
                    writer_epoch: 1,
                    policy,
                    record,
                    clock: HostClockState::Verified { now_unix: 15 },
                    reviewer_role_grants: Vec::new(),
                    execution_admissions: vec![admission],
                },
                document,
                identity: SourceFilesystemIdentity {
                    dev: file.dev(),
                    ino: file.ino(),
                },
            }
        }
        fn journal(&self) -> Journal {
            let directory = File::open(self.root.path.join("journal")).unwrap();
            Journal::open(
                &directory,
                crate::task_write_journal::AUTHORITATIVE_JOURNAL_FILE_NAME,
                self.root.uid,
            )
            .unwrap()
        }
        fn context(&self) -> WriterContextV1<'_> {
            WriterContextV1 {
                root: &self.root,
                lease: &self.lease,
                source_identity: self.identity,
            }
        }
        fn request(&self) -> TaskWriteRequestV1 {
            let reference = self.document.task_ref(&self.document.tasks[0], "tasks.md");
            let operation_id = "22222222222222222222222222222222".to_string();
            let authority = TransitionAuthorityV1 {
                actor: "WRITER#instance".into(),
                signer: "writer-key".into(),
                message_id: "33333333333333333333333333333333".into(),
                operation_id: operation_id.clone(),
                task_ref: reference.clone(),
                control_digest: self.document.tasks[0].task_control_digest,
                proposal_digest: Sha256Digest([0; 32]),
                nonce: [9; 32],
                config_digest: Sha256Digest([4; 32]),
                issued_at_unix: 10,
                expires_at_unix: 20,
                evidence: fixture_evidence(),
            };
            let mut request = TaskWriteRequestV1 {
                operation_id,
                authenticated_signer_principal: "writer-key".into(),
                request_message_id: authority.message_id.clone(),
                nonce: [9; 32],
                request_digest_sha256: [0; 32],
                admitted_task_ref: reference,
                expected_preimage_sha256: Sha256Digest::of(&self.bytes()).0,
                admitted_document: self.document.clone(),
                next_status: CanonicalTaskStatus::InProgress,
                authorization: TransitionAuthorization::Standard(Box::new(authority)),
            };
            seal(&mut request);
            request
        }
        fn bytes(&self) -> Vec<u8> {
            fs::read(self.root.path.join("tasks.md")).unwrap()
        }
        fn commit(
            &self,
            journal: &mut Journal,
            request: &TaskWriteRequestV1,
        ) -> Result<WriterWriteOutcome, WriterError> {
            commit_task_write(
                &self.context(),
                journal,
                request,
                &[],
                || Ok(self.authority.clone()),
                |_, _, _| Ok(()),
                |_| Ok(()),
            )
        }
        fn request_for(
            &self,
            index: usize,
            next: CanonicalTaskStatus,
            operation: u8,
        ) -> TaskWriteRequestV1 {
            let mut request = self.request();
            request.operation_id = format!("{operation:032x}");
            request.request_message_id = format!("{:032x}", u64::from(operation) + 100);
            request.nonce = [operation; 32];
            request.admitted_task_ref = self
                .document
                .task_ref(&self.document.tasks[index], "tasks.md");
            request.next_status = next;
            if let TransitionAuthorization::Standard(authority) = &mut request.authorization {
                authority.operation_id = request.operation_id.clone();
                authority.message_id = request.request_message_id.clone();
                authority.nonce = request.nonce;
                authority.task_ref = request.admitted_task_ref.clone();
                authority.control_digest = self.document.tasks[index].task_control_digest;
                authority.evidence.original_operation_id = Some(request.operation_id.clone());
                if next == CanonicalTaskStatus::DonePendingReview {
                    authority.actor = "DEV#implementer".into();
                }
                if next == CanonicalTaskStatus::Blocked {
                    authority.evidence.blocker = Some("awaiting named dependency".into());
                }
                if self.document.tasks[index].status == CanonicalTaskStatus::Blocked {
                    authority.evidence.resolution =
                        Some("named dependency resolved and claims refreshed".into());
                }
            }
            seal(&mut request);
            request
        }
        fn admit_request(&mut self, request: &TaskWriteRequestV1) {
            let authority = request.authority().unwrap();
            let evidence = &authority.evidence;
            self.authority.execution_admissions = vec![ExecutionAdmissionV1 {
                actor: authority.actor.clone(),
                authenticated_signer_principal: authority.signer.clone(),
                executor_actor: evidence.executor_actor.clone().unwrap(),
                task_ref: authority.task_ref.clone(),
                task_control_digest: authority.control_digest,
                admission_id: evidence.admission_id.clone().unwrap(),
                assignment_id: evidence.assignment_id.clone().unwrap(),
                original_operation_id: evidence.original_operation_id.clone().unwrap(),
                action: "task-write".into(),
                grant_id: evidence.grant_id.clone().unwrap(),
                capacity_claim_id: evidence.capacity_claim_id.clone().unwrap(),
                write_scope_claim_id: evidence.write_scope_claim_id.clone().unwrap(),
            }];
        }
        fn review(&mut self) -> TaskWriteRequestV1 {
            self.document.tasks[0].status = CanonicalTaskStatus::DonePendingReview;
            fs::write(
                self.root.path.join("tasks.md"),
                self.document.to_canonical_bytes().unwrap(),
            )
            .unwrap();
            let mut request = self.request();
            let mut authority = request.authority().unwrap().clone();
            authority.actor = "QA#reviewer".into();
            let task = &self.document.tasks[0];
            request.next_status = CanonicalTaskStatus::Done;
            request.authorization =
                TransitionAuthorization::ReviewedAcceptance(Box::new(ReviewedAcceptanceProofV1 {
                    reviewer_actor: authority.actor.clone(),
                    implementer_actor: task.owner_actor.clone().unwrap(),
                    reviewed_task_ref: request.admitted_task_ref.clone(),
                    reviewed_task_control_digest: task.task_control_digest,
                    completion_policy_digest: task.completion_policy_digest,
                    candidate_commit: task.candidate_commit.unwrap(),
                    reviewer_role: task.reviewer_role.clone(),
                    verification_checks_passed: vec!["tests".into()],
                    authority,
                }));
            seal(&mut request);
            request
        }
    }
    fn seal(request: &mut TaskWriteRequestV1) {
        let digest = request.canonical_request_digest().unwrap();
        request.request_digest_sha256 = digest;
        match &mut request.authorization {
            TransitionAuthorization::Standard(authority) => {
                authority.proposal_digest = Sha256Digest(digest)
            }
            TransitionAuthorization::ReviewedAcceptance(proof) => {
                proof.authority.proposal_digest = Sha256Digest(digest)
            }
            TransitionAuthorization::ProseClaim(_) => {}
        }
    }
    fn proof(outcome: WriterWriteOutcome) -> WriterCommitProof {
        match outcome {
            WriterWriteOutcome::Committed(proof) | WriterWriteOutcome::DuplicateRecorded(proof) => {
                proof
            }
            _ => panic!("expected committed proof"),
        }
    }
    fn assert_preimage(fixture: &Fixture, request: &TaskWriteRequestV1) {
        assert_eq!(
            Sha256Digest::of(&fixture.bytes()).0,
            request.expected_preimage_sha256
        );
        assert!(
            !fixture
                .root
                .path
                .join(format!(".chinwag-tmp-{}", request.operation_id))
                .exists()
        );
    }

    #[test]
    fn p0_acceptance_fixture_proof_origin_cannot_be_adopted_as_production() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let committed = proof(fixture.commit(&mut journal, &request).unwrap());
        for identity in [fixture.identity, committed.committed_identity()] {
            assert!(committed.verify_for_source_record(
                &fixture.authority.policy, &fixture.authority.record, Some(identity)
            ).is_ok());
        }
        let metadata = fs::metadata(&fixture.root.path).unwrap();
        let provider = crate::task_acceptance::fixtures::Fixture::new(metadata.dev(), metadata.ino());
        // Negative classification fixture only: the underlying writer proof was
        // produced by a real commit above. This does not mint a qualified fixture
        // finalization or claim an Approved -> Done integration path exists yet.
        let mut tagged = committed.clone();
        tagged.origin = WriterProofOriginV1::Fixture(provider.provider.provenance().clone());
        let cloned = tagged.clone();
        assert_eq!(cloned.origin, tagged.origin);
        for identity in [fixture.identity, committed.committed_identity()] {
            assert!(cloned.verify_for_source_record(
                &fixture.authority.policy, &fixture.authority.record, Some(identity)
            ).is_err());
        }
    }

    #[test]
    fn p0_writer_valid_commit_has_sealed_registry_adoption_proof() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let committed = proof(fixture.commit(&mut journal, &request).unwrap());
        let document = CanonicalTaskDocumentV1::from_bytes(&fixture.bytes()).unwrap();
        assert_eq!(document.file_cas_rev, 1);
        assert_eq!(document.tasks[0].task_status_rev, 1);
        assert_eq!(document.tasks[0].status, CanonicalTaskStatus::InProgress);
        assert_eq!(
            committed.committed_postimage_sha256(),
            &Sha256Digest::of(&fixture.bytes()).0
        );
        assert_ne!(
            committed.previous_identity(),
            committed.committed_identity()
        );
        assert_eq!(
            committed
                .verify_for_source_record(
                    &fixture.authority.policy,
                    &fixture.authority.record,
                    Some(fixture.identity)
                )
                .unwrap(),
            committed.committed_identity()
        );
        let mut wrong = fixture.authority.policy.clone();
        wrong.authority_epoch += 1;
        assert!(
            committed
                .verify_for_source_record(&wrong, &fixture.authority.record, Some(fixture.identity))
                .is_err()
        );
        assert!(
            committed
                .verify_for_source_record(
                    &fixture.authority.policy,
                    &fixture.authority.record,
                    None
                )
                .is_err()
        );
    }
    #[test]
    fn p0_writer_lease_rejects_stale_principal_and_all_policy_bindings() {
        let fixture = Fixture::new();
        let mut lease = fixture.lease.clone();
        lease.writer_epoch = 0;
        assert!(matches!(
            lease.verify(&fixture.authority),
            Err(WriterError::StaleWriterEpoch)
        ));
        lease = fixture.lease.clone();
        lease.writer_principal = "other".into();
        assert!(matches!(
            lease.verify(&fixture.authority),
            Err(WriterError::WriterPrincipalMismatch)
        ));
        for field in 0..8 {
            let mut lease = fixture.lease.clone();
            match field {
                0 => lease.source_generation += 1,
                1 => lease.config_revision += 1,
                2 => lease.authority_epoch += 1,
                3 => lease.config_digest[0] ^= 1,
                4 => lease.workspace_id = "other".into(),
                5 => lease.repo_id = "other".into(),
                6 => lease.source_worktree_id = "other".into(),
                _ => lease.canonical_relative_path = "other.json".into(),
            }
            assert!(matches!(
                lease.verify(&fixture.authority),
                Err(WriterError::PolicyBindingMismatch)
            ));
        }
    }
    #[test]
    fn p0_writer_clock_and_inactive_sources_fail_closed() {
        let fixture = Fixture::new();
        for clock in [
            HostClockState::ClockRollback,
            HostClockState::TimeUnavailable,
            HostClockState::Verified { now_unix: 9 },
            HostClockState::Verified { now_unix: 21 },
        ] {
            let mut authority = fixture.authority.clone();
            authority.clock = clock;
            assert!(matches!(
                fixture.lease.verify(&authority),
                Err(WriterError::ClockFenceHeld)
            ));
        }
        for state in [
            TaskSourceState::Proposed,
            TaskSourceState::Held(HeldReason::InterruptedMigration),
            TaskSourceState::Suspended,
            TaskSourceState::Retired,
        ] {
            let mut authority = fixture.authority.clone();
            authority.record.state = state;
            assert!(matches!(
                fixture.lease.verify(&authority),
                Err(WriterError::SourceNotEnrolled)
            ));
        }
        for now_unix in [10, 20] {
            let mut authority = fixture.authority.clone();
            authority.clock = HostClockState::Verified { now_unix };
            fixture.lease.verify(&authority).unwrap();
        }
    }
    #[test]
    fn p0_writer_midoperation_lease_expiry_aborts_and_cleans_staging() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let calls = Cell::new(0);
        let result = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || {
                let mut authority = fixture.authority.clone();
                calls.set(calls.get() + 1);
                if calls.get() > 1 {
                    authority.clock = HostClockState::Verified { now_unix: 21 };
                }
                Ok(authority)
            },
            |_, _, _| Ok(()),
            |_| panic!("projection after expired lease"),
        );
        assert!(matches!(result, Err(WriterError::ClockFenceHeld)));
        assert_preimage(&fixture, &request);
        assert_eq!(
            journal
                .latest(
                    "workspace",
                    &fixture.lease.task_source_id,
                    &request.operation_id
                )
                .unwrap()
                .state,
            WriteOperationState::Rejected
        );
    }
    #[test]
    fn p0_writer_midoperation_epoch_bump_aborts_and_cleans_staging() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let calls = Cell::new(0);
        let result = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || {
                let mut authority = fixture.authority.clone();
                calls.set(calls.get() + 1);
                if calls.get() > 1 {
                    authority.record.writer_epoch += 1;
                    authority.writer_epoch += 1;
                }
                Ok(authority)
            },
            |_, _, _| Ok(()),
            |_| panic!("projection after epoch loss"),
        );
        assert!(matches!(result, Err(WriterError::StaleWriterEpoch)));
        assert_preimage(&fixture, &request);
    }
    #[test]
    fn p0_writer_duplicate_after_restart_reuses_exact_commit_without_effects() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let first = proof(fixture.commit(&mut journal, &request).unwrap());
        let bytes = fixture.bytes();
        drop(journal);
        let mut journal = fixture.journal();
        let second = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || panic!("duplicate authority callback"),
            |_, _, _| panic!("duplicate rename hook"),
            |_| panic!("duplicate projection"),
        )
        .unwrap();
        assert_eq!(second, WriterWriteOutcome::DuplicateRecorded(first));
        assert_eq!(fixture.bytes(), bytes);
    }
    #[test]
    fn p0_writer_one_and_two_unrelated_edits_preserve_target_and_original_ref() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let original = request.admitted_task_ref.encode().unwrap();
        for delta in [1, 2] {
            let mut live = fixture.document.clone();
            live.file_cas_rev += delta;
            live.tasks[1].task_status_rev += delta;
            let hash = Sha256Digest::of(&live.to_canonical_bytes().unwrap()).0;
            let (next, used) = rebase_task_mutation(&request, &live, hash, 0).unwrap();
            assert_eq!(next.file_cas_rev, delta + 1);
            assert_eq!(next.tasks[0].task_status_rev, 1);
            assert_eq!(next.tasks[1], live.tasks[1]);
            assert_eq!(used, delta as usize);
        }
        assert_eq!(request.admitted_task_ref.encode().unwrap(), original);
    }
    #[test]
    fn p0_writer_third_or_consumed_rebase_refuses() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut live = fixture.document.clone();
        live.file_cas_rev = 3;
        live.tasks[1].task_status_rev = 3;
        assert!(matches!(
            rebase_task_mutation(&request, &live, [0; 32], 0),
            Err(WriterError::RebaseLimitExceeded)
        ));
        live.file_cas_rev = 2;
        assert!(matches!(
            rebase_task_mutation(&request, &live, [0; 32], 2),
            Err(WriterError::RebaseLimitExceeded)
        ));
    }
    #[test]
    fn p0_writer_every_target_snapshot_field_invalidates_unrelated_rebase() {
        let fixture = Fixture::new();
        let request = fixture.request();
        for field in 0..14 {
            let mut live = fixture.document.clone();
            live.file_cas_rev = 1;
            live.tasks[1].task_status_rev = 1;
            let task = &mut live.tasks[0];
            match field {
                0 => task.status = CanonicalTaskStatus::InProgress,
                1 => task.task_status_rev += 1,
                2 => task.task_spec_digest.0[0] ^= 1,
                3 => task.task_control_digest.0[0] ^= 1,
                4 => task.completion_policy_digest.0[0] ^= 1,
                5 => task.owner_actor = Some("DEV#different".into()),
                6 => task.reviewer_role = "different".into(),
                7 => task.baseline_commit = GitOid::Sha1([9; 20]),
                8 => task.candidate_commit = None,
                9 => task.overlay_digest = Some(Sha256Digest([9; 32])),
                10 => task.execution_flags.push("z-extra".into()),
                11 => task.dependencies.push(DependencyCommitment {
                    target_key: TaskKey::new("workspace", &fixture.lease.task_source_id, "B")
                        .unwrap(),
                    target_spec_digest: Sha256Digest([1; 32]),
                    completion_policy_digest: Sha256Digest([3; 32]),
                }),
                12 => live.source_generation += 1,
                _ => live.repo_id = "different".into(),
            }
            assert!(
                rebase_task_mutation(&request, &live, [0; 32], 0).is_err(),
                "field {field}"
            );
        }
    }
    #[test]
    fn p0_writer_five_status_transition_matrix_and_p006_done_hold() {
        use CanonicalTaskStatus::*;
        let statuses = [Todo, InProgress, DonePendingReview, Done, Blocked];
        for old in statuses {
            for next in statuses {
                let expected = matches!(
                    (old, next),
                    (Todo, InProgress)
                        | (InProgress, DonePendingReview)
                        | (DonePendingReview, Done | Blocked)
                        | (Todo | InProgress, Blocked)
                        | (Blocked, Todo)
                );
                assert_eq!(
                    valid_edge(old, next),
                    expected,
                    "{} -> {}",
                    old.as_str(),
                    next.as_str()
                );
            }
        }
        for unsupported in [
            "open",
            "claimed",
            "in-review",
            "held",
            "cancelled",
            "Done",
            "review-only",
        ] {
            assert!(
                serde_json::from_value::<CanonicalTaskStatus>(serde_json::json!(unsupported))
                    .is_err()
            );
        }
        let mut fixture = Fixture::new();
        let mut journal = fixture.journal();
        for (operation, next) in [
            (40, InProgress),
            (41, DonePendingReview),
            (42, Blocked),
            (43, Todo),
        ] {
            let mut request = fixture.request_for(0, next, operation);
            if next == DonePendingReview {
                if let TransitionAuthorization::Standard(authority) = &mut request.authorization {
                    authority.evidence.original_operation_id = Some(format!("{:032x}", 40));
                }
                seal(&mut request);
            }
            fixture.admit_request(&request);
            let original_candidate = fixture.document.tasks[0].candidate_commit;
            let original_overlay = fixture.document.tasks[0].overlay_digest;
            let committed = proof(fixture.commit(&mut journal, &request).unwrap());
            fixture.identity = committed.committed_identity();
            fixture.document = CanonicalTaskDocumentV1::from_bytes(&fixture.bytes()).unwrap();
            assert_eq!(fixture.document.tasks[0].status, next);
            assert_eq!(
                fixture.document.tasks[0].candidate_commit,
                original_candidate
            );
            assert_eq!(fixture.document.tasks[0].overlay_digest, original_overlay);
        }
        drop(journal);

        let mut fixture = Fixture::new();
        let request = fixture.review();
        let task = &fixture.document.tasks[0];
        let authorize = |authorization: &TransitionAuthorization| {
            authorize_transition(
                &fixture.document,
                task,
                "tasks.md",
                Done,
                authorization,
                &[],
            )
        };
        assert!(matches!(
            authorize(&request.authorization),
            Err(WriterError::DoneRequiresP006ReviewAttestation)
        ));
        let standard =
            TransitionAuthorization::Standard(Box::new(request.authority().unwrap().clone()));
        assert!(matches!(
            authorize(&standard),
            Err(WriterError::UnreviewedDoneForbidden)
        ));
        assert!(matches!(
            authorize(&TransitionAuthorization::ProseClaim("accepted".into())),
            Err(WriterError::UnreviewedDoneForbidden)
        ));
        let mut invalid = request.authorization.clone();
        if let TransitionAuthorization::ReviewedAcceptance(proof) = &mut invalid {
            proof.reviewer_actor = "DEV#different-instance".into();
            proof.authority.actor = proof.reviewer_actor.clone();
        }
        assert!(matches!(
            authorize(&invalid),
            Err(WriterError::SelfReviewForbidden)
        ));
        if let TransitionAuthorization::ReviewedAcceptance(proof) = &mut invalid {
            proof.reviewer_actor = "QA#reviewer".into();
            proof.authority.actor = proof.reviewer_actor.clone();
            proof.verification_checks_passed.clear();
        }
        assert!(matches!(
            authorize(&invalid),
            Err(WriterError::AcceptanceInvalidated)
        ));
    }

    #[test]
    fn p0_writer_execution_claims_dependencies_and_candidate_correlation_fail_closed() {
        let mut fixture = Fixture::new();
        let request = fixture.request();
        let authorization = &request.authorization;
        verify_current_transition_grant(authorization, request.next_status, &fixture.authority)
            .unwrap();
        for field in 0..8 {
            let mut current = fixture.authority.clone();
            let admission = &mut current.execution_admissions[0];
            match field {
                0 => admission.authenticated_signer_principal = "ungranted-key".into(),
                1 => admission.grant_id = "revoked-grant".into(),
                2 => admission.capacity_claim_id = "consumed-capacity".into(),
                3 => admission.write_scope_claim_id = "other-scope".into(),
                4 => admission.task_ref.task_status_rev += 1,
                5 => admission.original_operation_id = "other-operation".into(),
                6 => current.record.controls.implementation_authorized = false,
                _ => current.execution_admissions.clear(),
            }
            assert!(
                verify_current_transition_grant(authorization, request.next_status, &current)
                    .is_err(),
                "claim {field}"
            );
        }
        fixture.document.tasks[0]
            .dependencies
            .push(DependencyCommitment {
                target_key: TaskKey::new("workspace", &fixture.lease.task_source_id, "B").unwrap(),
                target_spec_digest: Sha256Digest([1; 32]),
                completion_policy_digest: Sha256Digest([3; 32]),
            });
        assert!(matches!(
            authorize_transition(
                &fixture.document,
                &fixture.document.tasks[0],
                "tasks.md",
                CanonicalTaskStatus::InProgress,
                authorization,
                &[]
            ),
            Err(WriterError::DependencyUnsatisfied)
        ));
        fixture.document.tasks[0].dependencies.clear();
        fixture.document.tasks[0].status = CanonicalTaskStatus::InProgress;
        fixture.document.tasks[0].candidate_commit = None;
        let submission = fixture.request_for(0, CanonicalTaskStatus::DonePendingReview, 70);
        assert!(matches!(
            authorize_transition(
                &fixture.document,
                &fixture.document.tasks[0],
                "tasks.md",
                submission.next_status,
                &submission.authorization,
                &[]
            ),
            Err(WriterError::AcceptanceInvalidated)
        ));
    }

    #[test]
    fn p0_writer_done_requires_typed_review_and_refuses_prose() {
        let fixture = Fixture::new();
        let request = fixture.request();
        for authorization in [
            request.authorization.clone(),
            TransitionAuthorization::ProseClaim("APPROVED DONE exit0".into()),
        ] {
            assert!(matches!(
                authorize_transition(
                    &fixture.document,
                    &fixture.document.tasks[0],
                    "tasks.md",
                    CanonicalTaskStatus::Done,
                    &authorization,
                    &[]
                ),
                Err(WriterError::UnreviewedDoneForbidden)
            ));
        }
    }
    #[test]
    fn p0_writer_same_instance_or_same_canonical_seat_cannot_self_review() {
        let mut fixture = Fixture::new();
        let request = fixture.review();
        for reviewer in ["DEV#implementer", "DEV#other-instance"] {
            let mut auth = request.authorization.clone();
            if let TransitionAuthorization::ReviewedAcceptance(proof) = &mut auth {
                proof.reviewer_actor = reviewer.into();
                proof.authority.actor = reviewer.into();
            }
            assert!(matches!(
                authorize_transition(
                    &fixture.document,
                    &fixture.document.tasks[0],
                    "tasks.md",
                    CanonicalTaskStatus::Done,
                    &auth,
                    &[]
                ),
                Err(WriterError::SelfReviewForbidden)
            ));
        }
    }
    #[test]
    fn p0_writer_review_must_match_artifact_controls_policy_and_original_ref() {
        let mut fixture = Fixture::new();
        let request = fixture.review();
        for field in 0..8 {
            let mut auth = request.authorization.clone();
            if let TransitionAuthorization::ReviewedAcceptance(proof) = &mut auth {
                match field {
                    0 => proof.reviewed_task_ref.task_spec_digest.0[0] ^= 1,
                    1 => proof.reviewed_task_ref.baseline_commit = GitOid::Sha1([7; 20]),
                    2 => proof.candidate_commit = GitOid::Sha1([8; 20]),
                    3 => proof.reviewed_task_control_digest.0[0] ^= 1,
                    4 => proof.completion_policy_digest.0[0] ^= 1,
                    5 => proof.verification_checks_passed.clear(),
                    6 => proof.reviewer_role = "wrong".into(),
                    _ => proof.implementer_actor = "OTHER#instance".into(),
                }
            }
            assert!(matches!(
                authorize_transition(
                    &fixture.document,
                    &fixture.document.tasks[0],
                    "tasks.md",
                    CanonicalTaskStatus::Done,
                    &auth,
                    &[]
                ),
                Err(WriterError::AcceptanceInvalidated)
            ));
        }
    }
    #[test]
    fn p0_writer_valid_review_is_held_and_missing_dependency_refuses() {
        let mut fixture = Fixture::new();
        let mut request = fixture.review();
        assert!(matches!(
            authorize_transition(
                &fixture.document,
                &fixture.document.tasks[0],
                "tasks.md",
                CanonicalTaskStatus::Done,
                &request.authorization,
                &[]
            ),
            Err(WriterError::DoneRequiresP006ReviewAttestation)
        ));
        assert!(verify_current_review_grant(&request.authorization, &fixture.authority).is_err());
        fixture
            .authority
            .reviewer_role_grants
            .push(ReviewerRoleGrantV1 {
                reviewer_actor: "QA#reviewer".into(),
                authenticated_signer_principal: "writer-key".into(),
                reviewer_role: "independent-review".into(),
                completion_policy_digest: Sha256Digest([3; 32]),
            });
        verify_current_review_grant(&request.authorization, &fixture.authority).unwrap();
        let mut journal = fixture.journal();
        let before = fixture.bytes();
        assert!(matches!(
            fixture.commit(&mut journal, &request),
            Err(WriterError::DoneRequiresP006ReviewAttestation)
        ));
        assert_eq!(fixture.bytes(), before);
        assert_eq!(
            journal
                .latest(
                    "workspace",
                    &fixture.lease.task_source_id,
                    &request.operation_id
                )
                .unwrap()
                .state,
            WriteOperationState::Rejected
        );
        drop(journal);
        fixture.document.tasks[0]
            .dependencies
            .push(DependencyCommitment {
                target_key: TaskKey::new("workspace", &fixture.lease.task_source_id, "B").unwrap(),
                target_spec_digest: Sha256Digest([1; 32]),
                completion_policy_digest: Sha256Digest([3; 32]),
            });
        request.admitted_document = fixture.document.clone();
        assert!(matches!(
            authorize_transition(
                &fixture.document,
                &fixture.document.tasks[0],
                "tasks.md",
                CanonicalTaskStatus::Done,
                &request.authorization,
                &[]
            ),
            Err(WriterError::DependencyUnsatisfied)
        ));
        let mut dependency_ref = fixture
            .document
            .task_ref(&fixture.document.tasks[1], "tasks.md");
        dependency_ref.file_cas_rev = 1;
        let mut evidence = DependencySnapshotV1 {
            current_source: DependencySourceBinding::from_task_ref(&dependency_ref).unwrap(),
            resolved: ResolvedDependency {
                task_ref: dependency_ref,
                completion_policy_digest: Sha256Digest([3; 32]),
                status: crate::task_dependency::TaskStatus::Done,
            },
            source_record: fixture.authority.record.clone(),
            policy: fixture.authority.policy.clone(),
        };
        assert!(matches!(
            authorize_transition(
                &fixture.document,
                &fixture.document.tasks[0],
                "tasks.md",
                CanonicalTaskStatus::Done,
                &request.authorization,
                std::slice::from_ref(&evidence)
            ),
            Err(WriterError::DoneRequiresP006ReviewAttestation)
        ));
        evidence.resolved.status = crate::task_dependency::TaskStatus::DonePendingReview;
        assert!(matches!(
            authorize_transition(
                &fixture.document,
                &fixture.document.tasks[0],
                "tasks.md",
                CanonicalTaskStatus::Done,
                &request.authorization,
                std::slice::from_ref(&evidence)
            ),
            Err(WriterError::DependencyUnsatisfied)
        ));
        evidence.resolved.status = crate::task_dependency::TaskStatus::Done;
        evidence.resolved.task_ref.task_spec_digest.0[0] ^= 1;
        assert!(
            authorize_transition(
                &fixture.document,
                &fixture.document.tasks[0],
                "tasks.md",
                CanonicalTaskStatus::Done,
                &request.authorization,
                std::slice::from_ref(&evidence)
            )
            .is_err()
        );
    }
    #[test]
    fn p0_writer_f0_restart_rolls_back_exact_preimage_without_revision_advance() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let result = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |step, _, _| {
                if step == WriterStep::Prepared {
                    Err(WriterError::InjectedCrash)
                } else {
                    Ok(())
                }
            },
            |_| Ok(()),
        );
        assert!(matches!(result, Err(WriterError::InjectedCrash)));
        drop(journal);
        let mut journal = fixture.journal();
        assert_eq!(
            classify_and_recover_prepared_operation(
                &fixture.context(),
                &mut journal,
                &request.operation_id,
                || Ok(fixture.authority.clone()),
                |_| panic!("F0 projection")
            )
            .unwrap(),
            RecoveredCommitOutcome::RolledBack
        );
        assert_preimage(&fixture, &request);
        assert_eq!(
            CanonicalTaskDocumentV1::from_bytes(&fixture.bytes())
                .unwrap()
                .file_cas_rev,
            0
        );
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let _crash = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |step, _, _| {
                if step == WriterStep::Prepared {
                    Err(WriterError::InjectedCrash)
                } else {
                    Ok(())
                }
            },
            |_| Ok(()),
        );
        drop(journal);
        let mut journal = fixture.journal();
        let resumed = complete_prepared_operation(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |_| Ok(()),
        )
        .unwrap();
        assert!(matches!(resumed, RecoveredCommitOutcome::Committed(_)));
        assert_eq!(
            CanonicalTaskDocumentV1::from_bytes(&fixture.bytes())
                .unwrap()
                .file_cas_rev,
            1
        );
    }
    #[test]
    fn p0_writer_commit_proof_preserves_byte_lengths_and_rebased_predecessor_rev_across_f1_recovery()
     {
        for unrelated_commits in [1_u64, 2] {
            let mut fixture = Fixture::new();
            fixture.document.file_cas_rev = 1;
            fs::write(
                fixture.root.path.join("tasks.md"),
                fixture.document.to_canonical_bytes().unwrap(),
            )
            .unwrap();
            let original = fixture.request_for(0, CanonicalTaskStatus::InProgress, 20);
            fixture.admit_request(&original);
            let original_a = fixture.document.tasks[0].clone();
            let mut journal = fixture.journal();
            // The writer authenticates every intervening whole-file revision;
            // an external edit cannot supply the prior journal commitment.
            for index in 0..unrelated_commits {
                fixture.document = CanonicalTaskDocumentV1::from_bytes(&fixture.bytes()).unwrap();
                let next = if index == 0 {
                    CanonicalTaskStatus::InProgress
                } else {
                    CanonicalTaskStatus::Blocked
                };
                let b_request = fixture.request_for(1, next, 21 + index as u8);
                fixture.admit_request(&b_request);
                let before = fixture.bytes();
                let committed = proof(fixture.commit(&mut journal, &b_request).unwrap());
                let after = fixture.bytes();
                assert_eq!(committed.proposal_expected_file_cas_rev(), 1 + index);
                assert_eq!(committed.actual_predecessor_file_cas_rev(), 1 + index);
                assert_eq!(committed.predecessor_byte_len(), before.len() as u64);
                assert_eq!(committed.committed_postimage_byte_len(), after.len() as u64);
                assert_eq!(
                    committed.expected_preimage_sha256(),
                    &Sha256Digest::of(&before).0
                );
                assert_eq!(
                    committed.committed_postimage_sha256(),
                    &Sha256Digest::of(&after).0
                );
                fixture.identity = committed.committed_identity();
                assert_eq!(
                    CanonicalTaskDocumentV1::from_bytes(&after).unwrap().tasks[0],
                    original_a
                );
            }
            fixture.admit_request(&original);
            let predecessor = fixture.bytes();
            let predecessor_identity = fixture.identity;
            let predecessor_revision = 1 + unrelated_commits;
            let result = commit_task_write(
                &fixture.context(),
                &mut journal,
                &original,
                &[],
                || Ok(fixture.authority.clone()),
                |step, _, _| {
                    if step == WriterStep::AfterRename {
                        Err(WriterError::InjectedCrash)
                    } else {
                        Ok(())
                    }
                },
                |_| panic!("projection must follow the injected F1 crash"),
            );
            assert!(matches!(result, Err(WriterError::InjectedCrash)));
            let successor = fixture.bytes();
            let successor_metadata = fs::metadata(fixture.root.path.join("tasks.md")).unwrap();
            let successor_identity = SourceFilesystemIdentity {
                dev: successor_metadata.dev(),
                ino: successor_metadata.ino(),
            };
            assert_ne!(predecessor_identity, successor_identity);
            let record = journal
                .latest(
                    &fixture.lease.workspace_id,
                    &fixture.lease.task_source_id,
                    &original.operation_id,
                )
                .unwrap();
            assert_eq!(record.state, WriteOperationState::Prepared);
            let prepared = record.prepared.as_ref().unwrap();
            assert_eq!(prepared.proposal_expected_file_cas_rev, 1);
            assert_eq!(prepared.expected_file_cas_rev, predecessor_revision);
            assert_eq!(prepared.expected_preimage_bytes, predecessor.len() as u64);
            assert_eq!(prepared.committed_postimage_bytes, successor.len() as u64);
            let durable_proof = WriterCommitProof::from_record(record).unwrap();
            drop(journal);

            let mut journal = fixture.journal();
            let projections = Cell::new(0);
            let recovered = classify_and_recover_prepared_operation(
                &fixture.context(),
                &mut journal,
                &original.operation_id,
                || Ok(fixture.authority.clone()),
                |proof| {
                    projections.set(projections.get() + 1);
                    assert_eq!(proof, &durable_proof);
                    assert_eq!(proof.predecessor_byte_len(), predecessor.len() as u64);
                    assert_eq!(proof.committed_postimage_byte_len(), successor.len() as u64);
                    Ok(())
                },
            )
            .unwrap();
            let recovered = match recovered {
                RecoveredCommitOutcome::Committed(proof) => proof,
                other => panic!("expected F1 committed proof, got {other:?}"),
            };
            assert_eq!(*recovered, durable_proof);
            assert_eq!(recovered.proposal_expected_file_cas_rev(), 1);
            assert_eq!(
                recovered.actual_predecessor_file_cas_rev(),
                predecessor_revision
            );
            assert_eq!(recovered.expected_file_cas_rev(), predecessor_revision);
            assert_eq!(recovered.committed_file_cas_rev(), predecessor_revision + 1);
            assert_eq!(recovered.rebases_used(), unrelated_commits as u8);
            assert_eq!(
                recovered.expected_preimage_bytes(),
                predecessor.len() as u64
            );
            assert_eq!(
                recovered.committed_postimage_bytes(),
                successor.len() as u64
            );
            assert_eq!(
                recovered.expected_preimage_sha256(),
                &Sha256Digest::of(&predecessor).0
            );
            assert_eq!(
                recovered.committed_postimage_sha256(),
                &Sha256Digest::of(&successor).0
            );
            assert_eq!(recovered.previous_identity(), predecessor_identity);
            assert_eq!(recovered.committed_identity(), successor_identity);
            assert_eq!(projections.get(), 1);
            assert_eq!(fixture.bytes(), successor);
            assert_eq!(
                fs::metadata(fixture.root.path.join("tasks.md"))
                    .unwrap()
                    .ino(),
                successor_identity.ino
            );
            assert_eq!(
                CanonicalTaskDocumentV1::from_bytes(&successor)
                    .unwrap()
                    .file_cas_rev,
                predecessor_revision + 1
            );
            assert_eq!(
                journal
                    .latest(
                        &fixture.lease.workspace_id,
                        &fixture.lease.task_source_id,
                        &original.operation_id
                    )
                    .unwrap()
                    .state,
                WriteOperationState::Acknowledged
            );
        }
    }
    #[test]
    fn p0_writer_f0_resume_rejects_rebound_verified_authority() {
        for field in 0..5 {
            let fixture = Fixture::new();
            let mut request = fixture.request();
            let before = fixture.bytes();
            let mut journal = fixture.journal();
            let result = commit_task_write(
                &fixture.context(),
                &mut journal,
                &request,
                &[],
                || Ok(fixture.authority.clone()),
                |step, _, _| {
                    if step == WriterStep::Prepared {
                        Err(WriterError::InjectedCrash)
                    } else {
                        Ok(())
                    }
                },
                |_| panic!("pre-rename crash must not project"),
            );
            assert!(matches!(result, Err(WriterError::InjectedCrash)));
            if let TransitionAuthorization::Standard(authority) = &mut request.authorization {
                match field {
                    0 => authority.signer = "different-signer".into(),
                    1 => authority.message_id = "different-message".into(),
                    2 => authority.task_ref.file_cas_rev += 1,
                    3 => authority.nonce[0] ^= 1,
                    _ => authority.actor = "OTHER#instance".into(),
                }
            }
            // These envelope changes do not alter the proposal payload digest.
            // F0 must still require its original authenticated identity/binding.
            assert_eq!(
                request.canonical_request_digest().unwrap(),
                request.request_digest_sha256
            );
            let resumed = complete_prepared_operation(
                &fixture.context(),
                &mut journal,
                &request,
                &[],
                || Ok(fixture.authority.clone()),
                |_| panic!("rebound authority must not project"),
            );
            assert!(
                matches!(resumed, Err(WriterError::AuthorityMismatch)),
                "field {field}"
            );
            assert_eq!(fixture.bytes(), before);
            assert_eq!(
                journal
                    .latest(
                        "workspace",
                        &fixture.lease.task_source_id,
                        &request.operation_id
                    )
                    .unwrap()
                    .state,
                WriteOperationState::Reconciling
            );
        }
    }

    #[test]
    fn p0_writer_f0_final_refresh_stage_tamper_refuses_before_rename() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let before = fixture.bytes();
        let mut journal = fixture.journal();
        let interrupted = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |step, _, _| {
                if step == WriterStep::Prepared {
                    Err(WriterError::InjectedCrash)
                } else {
                    Ok(())
                }
            },
            |_| panic!("pre-rename crash must not project"),
        );
        assert!(matches!(interrupted, Err(WriterError::InjectedCrash)));
        let calls = Cell::new(0);
        let resumed = complete_prepared_operation(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    fs::write(
                        fixture
                            .root
                            .path
                            .join(format!(".chinwag-tmp-{}", request.operation_id)),
                        b"tampered stage",
                    )
                    .unwrap();
                }
                Ok(fixture.authority.clone())
            },
            |_| panic!("tampered stage must not project"),
        );
        assert!(matches!(
            resumed,
            Err(WriterError::Journal(JournalError::IdentityChanged))
        ));
        assert_eq!(calls.get(), 2);
        assert_eq!(fixture.bytes(), before);
        assert_eq!(
            journal
                .latest(
                    "workspace",
                    &fixture.lease.task_source_id,
                    &request.operation_id
                )
                .unwrap()
                .state,
            WriteOperationState::Reconciling
        );
    }

    #[test]
    fn p0_writer_f1_restart_recovers_original_proof_without_rewrite() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let result = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |step, _, _| {
                if step == WriterStep::AfterRename {
                    Err(WriterError::InjectedCrash)
                } else {
                    Ok(())
                }
            },
            |_| Ok(()),
        );
        assert!(matches!(result, Err(WriterError::InjectedCrash)));
        let bytes = fixture.bytes();
        let inode = fs::metadata(fixture.root.path.join("tasks.md"))
            .unwrap()
            .ino();
        drop(journal);
        let mut journal = fixture.journal();
        let projections = Cell::new(0);
        let result = classify_and_recover_prepared_operation(
            &fixture.context(),
            &mut journal,
            &request.operation_id,
            || Ok(fixture.authority.clone()),
            |_| {
                projections.set(projections.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(result, RecoveredCommitOutcome::Committed(_)));
        assert_eq!(projections.get(), 1);
        assert_eq!(fixture.bytes(), bytes);
        assert_eq!(
            fs::metadata(fixture.root.path.join("tasks.md"))
                .unwrap()
                .ino(),
            inode
        );
        assert_eq!(
            CanonicalTaskDocumentV1::from_bytes(&bytes)
                .unwrap()
                .file_cas_rev,
            1
        );
    }
    #[test]
    fn p0_writer_fx_external_or_missing_target_is_preserved_and_source_held() {
        for missing in [false, true] {
            let fixture = Fixture::new();
            let request = fixture.request();
            let mut journal = fixture.journal();
            let _result = commit_task_write(
                &fixture.context(),
                &mut journal,
                &request,
                &[],
                || Ok(fixture.authority.clone()),
                |step, _, _| {
                    if step == WriterStep::Prepared {
                        Err(WriterError::InjectedCrash)
                    } else {
                        Ok(())
                    }
                },
                |_| Ok(()),
            );
            if missing {
                fs::remove_file(fixture.root.path.join("tasks.md")).unwrap();
            } else {
                fs::write(fixture.root.path.join("tasks.md"), b"external evidence").unwrap();
            }
            drop(journal);
            let mut journal = fixture.journal();
            let result = classify_and_recover_prepared_operation(
                &fixture.context(),
                &mut journal,
                &request.operation_id,
                || Ok(fixture.authority.clone()),
                |_| panic!("Fx projection"),
            )
            .unwrap();
            assert_eq!(
                result,
                RecoveredCommitOutcome::Held(CrashClassification::FxExternalDrift)
            );
            if !missing {
                assert_eq!(fixture.bytes(), b"external evidence");
            }
        }
    }
    #[test]
    fn p0_writer_unadmitted_source_modes_refuse_without_file_effects() {
        for mode in [0o644, 0o640, 0o660, 0o700, 0o4600] {
            let fixture = Fixture::new();
            let request = fixture.request();
            let source = fixture.root.path.join("tasks.md");
            fs::set_permissions(&source, fs::Permissions::from_mode(mode)).unwrap();
            let before = fixture.bytes();
            let inode = fs::metadata(&source).unwrap().ino();
            let mut journal = fixture.journal();
            let effects = Cell::new(0);
            let result = commit_task_write(
                &fixture.context(),
                &mut journal,
                &request,
                &[],
                || Ok(fixture.authority.clone()),
                |_, _, _| {
                    effects.set(effects.get() + 1);
                    Ok(())
                },
                |_| {
                    effects.set(effects.get() + 1);
                    Ok(())
                },
            );
            assert!(matches!(result, Err(WriterError::SourceIdentityChanged)));
            assert_eq!(effects.get(), 0);
            assert_eq!(fixture.bytes(), before);
            assert_eq!(fs::metadata(&source).unwrap().ino(), inode);
            assert_eq!(
                fs::metadata(&source).unwrap().permissions().mode() & 0o7777,
                mode
            );
            assert_preimage(&fixture, &request);
        }
        for mode in [0o400, 0o600] {
            let fixture = Fixture::new();
            fs::set_permissions(
                fixture.root.path.join("tasks.md"),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            PinnedTarget::open(&fixture.root, "tasks.md")
                .unwrap()
                .read()
                .unwrap();
        }
    }
    #[test]
    fn p0_writer_target_symlink_hardlink_and_alias_are_rejected() {
        for kind in 0..3 {
            let fixture = Fixture::new();
            let source = fixture.root.path.join("tasks.md");
            let other = fixture.root.path.join("other");
            fs::rename(&source, &other).unwrap();
            match kind {
                0 => symlink(&other, &source).unwrap(),
                1 => {
                    fs::hard_link(&other, &source).unwrap();
                }
                _ => {
                    fs::rename(&other, fixture.root.path.join("TASKS.JSON")).unwrap();
                }
            }
            let result =
                PinnedTarget::open(&fixture.root, "tasks.md").and_then(|target| target.read());
            assert!(result.is_err());
        }
    }
    #[test]
    fn p0_writer_external_swap_before_rename_aborts_preserving_external_bytes() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let result = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |step, _, _| {
                if step == WriterStep::BeforeRename {
                    let swap = fixture.root.path.join("swap");
                    fs::write(&swap, b"external replacement").unwrap();
                    fs::rename(swap, fixture.root.path.join("tasks.md")).unwrap();
                }
                Ok(())
            },
            |_| panic!("drift projection"),
        );
        assert!(matches!(result, Err(WriterError::SourceIdentityChanged)));
        assert_eq!(fixture.bytes(), b"external replacement");
        assert!(
            !fixture
                .root
                .path
                .join(format!(".chinwag-tmp-{}", request.operation_id))
                .exists()
        );
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let result = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |step, _, _| {
                if step == WriterStep::BeforeRename {
                    fs::write(
                        fixture
                            .root
                            .path
                            .join(format!(".chinwag-tmp-{}", request.operation_id)),
                        b"tampered staging",
                    )
                    .unwrap();
                }
                Ok(())
            },
            |_| panic!("tampered staging projection"),
        );
        assert!(result.is_err());
        assert_preimage(&fixture, &request);
    }
    #[test]
    fn p0_writer_projection_failure_never_acknowledges_and_recovers_without_rewrite() {
        let fixture = Fixture::new();
        let request = fixture.request();
        let mut journal = fixture.journal();
        let result = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |_, _, _| Ok(()),
            |_| Err(WriterError::InjectedCrash),
        );
        assert!(matches!(result, Err(WriterError::InjectedCrash)));
        assert_eq!(
            journal
                .latest(
                    "workspace",
                    &fixture.lease.task_source_id,
                    &request.operation_id
                )
                .unwrap()
                .state,
            WriteOperationState::FileCommitted
        );
        let bytes = fixture.bytes();
        let inode = fs::metadata(fixture.root.path.join("tasks.md"))
            .unwrap()
            .ino();
        drop(journal);
        let mut journal = fixture.journal();
        let before_recovery = journal.records().count();
        let interrupted = classify_and_recover_prepared_operation(
            &fixture.context(),
            &mut journal,
            &request.operation_id,
            || Ok(fixture.authority.clone()),
            |_| Err(WriterError::InjectedCrash),
        );
        assert!(matches!(interrupted, Err(WriterError::InjectedCrash)));
        assert_eq!(
            journal
                .latest(
                    "workspace",
                    &fixture.lease.task_source_id,
                    &request.operation_id
                )
                .unwrap()
                .state,
            WriteOperationState::Reconciling
        );
        assert_eq!(journal.records().count(), before_recovery + 1);
        drop(journal);
        let mut journal = fixture.journal();
        let reconciling_records = journal.records().count();
        for _ in 0..2 {
            assert!(
                classify_and_recover_prepared_operation(
                    &fixture.context(),
                    &mut journal,
                    &request.operation_id,
                    || Ok(fixture.authority.clone()),
                    |_| Err(WriterError::InjectedCrash)
                )
                .is_err()
            );
            assert_eq!(journal.records().count(), reconciling_records);
        }
        let result = classify_and_recover_prepared_operation(
            &fixture.context(),
            &mut journal,
            &request.operation_id,
            || Ok(fixture.authority.clone()),
            |_| Ok(()),
        )
        .unwrap();
        assert!(matches!(result, RecoveredCommitOutcome::Committed(_)));
        assert_eq!(journal.records().count(), reconciling_records + 2);
        let phases: Vec<_> = journal
            .records()
            .filter(|record| record.request.operation_id == request.operation_id)
            .map(|record| record.state)
            .collect();
        assert_eq!(
            phases,
            [
                WriteOperationState::Received,
                WriteOperationState::Validated,
                WriteOperationState::Prepared,
                WriteOperationState::FileCommitted,
                WriteOperationState::Reconciling,
                WriteOperationState::Recorded,
                WriteOperationState::Acknowledged
            ]
        );
        assert_eq!(fixture.bytes(), bytes);
        assert_eq!(
            fs::metadata(fixture.root.path.join("tasks.md"))
                .unwrap()
                .ino(),
            inode
        );
        drop(journal);

        // Simulate a durable commit record whose exact predecessor later appears.
        // The FileCommitted history must survive a reopened Reconciling phase.
        let fixture = Fixture::new();
        let request = fixture.request();
        let before = fixture.bytes();
        let mut journal = fixture.journal();
        let _interrupted = commit_task_write(
            &fixture.context(),
            &mut journal,
            &request,
            &[],
            || Ok(fixture.authority.clone()),
            |step, _, _| {
                if step == WriterStep::Prepared {
                    Err(WriterError::InjectedCrash)
                } else {
                    Ok(())
                }
            },
            |_| panic!("uncommitted fixture must not project"),
        );
        let mut record = journal
            .latest(
                "workspace",
                &fixture.lease.task_source_id,
                &request.operation_id,
            )
            .unwrap()
            .clone();
        record.state = WriteOperationState::FileCommitted;
        journal.append(record.clone()).unwrap();
        record.state = WriteOperationState::Reconciling;
        journal.append(record).unwrap();
        drop(journal);
        let mut journal = fixture.journal();
        let snapshots = journal.records().count();
        assert!(matches!(
            complete_prepared_operation(
                &fixture.context(),
                &mut journal,
                &request,
                &[],
                || Ok(fixture.authority.clone()),
                |_| panic!("historical commit cannot resume F0")
            ),
            Err(WriterError::SourceHeld)
        ));
        assert_eq!(journal.records().count(), snapshots);
        let result = classify_and_recover_prepared_operation(
            &fixture.context(),
            &mut journal,
            &request.operation_id,
            || Ok(fixture.authority.clone()),
            |_| panic!("restored predecessor cannot project"),
        )
        .unwrap();
        assert_eq!(
            result,
            RecoveredCommitOutcome::Held(CrashClassification::FxExternalDrift)
        );
        assert_eq!(fixture.bytes(), before);
        assert_eq!(
            journal
                .latest(
                    "workspace",
                    &fixture.lease.task_source_id,
                    &request.operation_id
                )
                .unwrap()
                .state,
            WriteOperationState::Held
        );
    }
    #[test]
    fn p0_writer_markdown_preserves_unrelated_sections_verbatim_and_rejects_malformed_md() {
        let fixture = Fixture::new();
        let canonical = fixture.document.to_canonical_string().unwrap();
        assert!(canonical.starts_with(&format!(
            "# Canonical Tasks ({})\n",
            fixture.document.task_source_id
        )));
        let prose = "## Human context  \n\nKeep these spaces.  \nProfile chinwag-task-markdown-v1 is described here.\n\n| item | value |\n| --- | --- |\n| café | ✓ |\n\n- [ ] ordinary checklist\n\n";
        let body = "\nTask A body stays byte-for-byte.  \n- [ ] run a manual check\n  - [ ] **Important** body checklist\n```text\nraw body with  two spaces\n```\n";
        let source = canonical
            .replacen(
                "<!-- chinwag-task-begin-v1",
                &format!("{prose}<!-- chinwag-task-begin-v1"),
                1,
            )
            .replacen(
                "<!-- chinwag-task-end-v1 task_id=\"A\" -->",
                &format!("{body}<!-- chinwag-task-end-v1 task_id=\"A\" -->"),
                1,
            );
        let b_start = source
            .find("<!-- chinwag-task-begin-v1 task_id=\"B\" -->")
            .unwrap();
        let b_original = &source[b_start..];
        let mut document = CanonicalTaskDocumentV1::parse_strict(&source).unwrap();
        assert_eq!(document.to_canonical_string().unwrap(), source);
        document.file_cas_rev = 1;
        document.last_operation_id = Some("22222222222222222222222222222222".into());
        document.tasks[0].status = CanonicalTaskStatus::InProgress;
        document.tasks[0].task_status_rev = 1;
        let rendered = document.to_canonical_string().unwrap();
        assert!(rendered.contains(prose));
        assert!(rendered.contains(body));
        assert!(rendered.ends_with(b_original));
        assert!(rendered.contains("- [ ] **A** (`in-progress`) — A\n"));
        assert_eq!(
            CanonicalTaskDocumentV1::parse_strict(&rendered).unwrap(),
            document
        );
        // Parsed documents keep physical order while logical snapshots are sorted.
        let a_start = canonical
            .find("<!-- chinwag-task-begin-v1 task_id=\"A\" -->")
            .unwrap();
        let b_start = canonical
            .find("<!-- chinwag-task-begin-v1 task_id=\"B\" -->")
            .unwrap();
        let reversed = format!(
            "{}{}{}",
            &canonical[..a_start],
            &canonical[b_start..],
            &canonical[a_start..b_start]
        );
        let reversed_document = CanonicalTaskDocumentV1::parse_strict(&reversed).unwrap();
        assert_eq!(reversed_document.tasks[0].task_id, "A");
        assert_eq!(reversed_document.to_canonical_string().unwrap(), reversed);

        let metadata = canonical
            .lines()
            .find(|line| line.starts_with(SOURCE_META_PREFIX))
            .unwrap();
        let mut malformed = vec![
            "{\"workspace_id\":\"workspace\"}\n".to_owned(),
            canonical.replace(&format!("{metadata}\n"), ""),
            canonical.replacen(metadata, &format!("{metadata}\n{metadata}"), 1),
            canonical.replacen("\"workspace_id\":", "\"unknown\":true,\"workspace_id\":", 1),
            canonical.replacen(
                "\"workspace_id\":",
                "\"workspace_id\":\"evil\",\"workspace_id\":",
                1,
            ),
            canonical.replacen(
                "\"workspace_id\":",
                "\"sha256\":\"forbidden-self-hash\",\"workspace_id\":",
                1,
            ),
            canonical.replacen("\"task_id\":", "\"extra\":true,\"task_id\":", 1),
            canonical.replacen("\"task_id\":", "\"task_id\":\"A\",\"task_id\":", 1),
            canonical.replacen("- [ ] **A**", "- [x] **A**", 1),
            canonical.replacen("(`todo`) — A", "(`blocked`) — A", 1),
            canonical.replacen("- [ ] **A**", "- [ ] **C**", 1),
            canonical.replacen(
                "<!-- chinwag-task-entry-v1",
                "<!-- chinwag-task-begin-v1 task_id=\"C\" -->\n<!-- chinwag-task-entry-v1",
                1,
            ),
            canonical.replacen("<!-- chinwag-task-end-v1 task_id=\"A\" -->\n", "", 1),
            format!("{canonical}<!-- chinwag-task-end-v1 task_id=\"A\" -->\n"),
            canonical.replacen(
                "<!-- chinwag-task-begin-v1",
                " <!-- chinwag-task-begin-v1",
                1,
            ),
            canonical.replace('\n', "\r\n"),
            canonical.trim_end_matches('\n').to_owned(),
            format!("{canonical}\0\n"),
        ];
        malformed.push(canonical.replacen("- [ ] **A** (`todo`) — A\n", "", 1));
        malformed.push(canonical.replacen(
            "- [ ] **A** (`todo`) — A\n",
            "- [ ] **A** (`todo`) — A\n- [ ] **A** (`todo`) — duplicate\n",
            1,
        ));
        malformed.push(canonical.replacen(
            "<!-- chinwag-task-end-v1 task_id=\"A\" -->",
            "<!-- chinwag-task-end-v1 task_id=\"C\" -->",
            1,
        ));
        for (index, invalid) in malformed.iter().enumerate() {
            assert!(
                CanonicalTaskDocumentV1::parse_strict(invalid).is_err(),
                "accepted malformed case {index}"
            );
        }
    }
    #[test]
    fn p0_writer_preflights_full_journal_completion_capacity_before_prepared_and_rename() {
        use crate::task_write_journal::{
            AUTHORITATIVE_JOURNAL_FILE_NAME, MAX_JOURNAL_FILE_BYTES, MAX_JOURNAL_RECORD_BYTES,
            MAX_JOURNAL_RECORDS,
        };

        for byte_limit in [false, true] {
            let fixture = Fixture::new();
            let request = fixture.request();
            let canonical_before = fixture.bytes();
            let identity_before = fs::metadata(fixture.root.path.join("tasks.md"))
                .unwrap()
                .ino();
            let template = JournalRequestV1 {
                workspace_id: request.admitted_task_ref.workspace_id.clone(),
                task_source_id: request.admitted_task_ref.task_source_id.clone(),
                operation_id: request.operation_id.clone(),
                signer_principal: request.authenticated_signer_principal.clone(),
                request_id: request.request_message_id.clone(),
                request_digest: request.request_digest_sha256,
                nonce: request.nonce,
                writer_epoch: fixture.lease.writer_epoch,
                signed_task_ref: request.admitted_task_ref.encode().unwrap(),
                metadata: serde_json::to_value(&fixture.lease).unwrap(),
            };
            let received_bytes = serde_json::to_vec(&JournalRecordV1::received(template.clone()))
                .unwrap()
                .len()
                + 1;
            let terminal_records = if byte_limit {
                250
            } else {
                MAX_JOURNAL_RECORDS - 4
            };
            let target_history_bytes = MAX_JOURNAL_FILE_BYTES
                - 6 * MAX_JOURNAL_RECORD_BYTES as u64
                - received_bytes as u64
                + 1;
            let mut history = Vec::new();
            let mut snapshots = 0;
            for index in 0..terminal_records / 2 {
                let mut historical = template.clone();
                historical.operation_id = format!("{index:032x}");
                historical.request_id = format!("historical-request-{index}");
                let received = JournalRecordV1::received(historical);
                let mut rejected = received.clone();
                rejected.state = WriteOperationState::Rejected;
                rejected.result = Some(serde_json::json!({"disposition": "rejected"}));
                for record in [received, rejected] {
                    let mut bytes = serde_json::to_vec(&record).unwrap();
                    bytes.push(b'\n');
                    assert!(bytes.len() <= MAX_JOURNAL_RECORD_BYTES);
                    snapshots += 1;
                    if byte_limit {
                        let padded_length = if snapshots == terminal_records {
                            target_history_bytes as usize - history.len()
                        } else {
                            MAX_JOURNAL_RECORD_BYTES
                        };
                        assert!(
                            bytes.len() <= padded_length
                                && padded_length <= MAX_JOURNAL_RECORD_BYTES
                        );
                        bytes.pop();
                        bytes.resize(padded_length - 1, b' ');
                        bytes.push(b'\n');
                    }
                    history.extend(bytes);
                }
            }
            assert_eq!(snapshots, terminal_records);
            if byte_limit {
                assert_eq!(history.len() as u64, target_history_bytes);
            }
            let path = fixture
                .root
                .path
                .join("journal")
                .join(AUTHORITATIVE_JOURNAL_FILE_NAME);
            fs::write(&path, &history).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let mut journal = fixture.journal();
            let hooks = Cell::new(0);
            let projections = Cell::new(0);
            let outcome = commit_task_write(
                &fixture.context(),
                &mut journal,
                &request,
                &[],
                || Ok(fixture.authority.clone()),
                |_, _, _| {
                    hooks.set(hooks.get() + 1);
                    Ok(())
                },
                |_| {
                    projections.set(projections.get() + 1);
                    Ok(())
                },
            );
            if byte_limit {
                assert!(matches!(
                    outcome,
                    Err(WriterError::Journal(JournalError::JournalSizeLimitExceeded))
                ));
            } else {
                assert!(matches!(
                    outcome,
                    Err(WriterError::Journal(
                        JournalError::JournalRecordLimitExceeded
                    ))
                ));
            }
            assert_eq!(hooks.get(), 0);
            assert_eq!(projections.get(), 0);
            assert_eq!(journal.records().count(), terminal_records);
            assert!(
                journal
                    .latest(
                        &fixture.lease.workspace_id,
                        &fixture.lease.task_source_id,
                        &request.operation_id
                    )
                    .is_none()
            );
            assert!(journal.records().all(|record| record.prepared.is_none()));
            assert_eq!(fs::read(&path).unwrap(), history);
            assert_eq!(fixture.bytes(), canonical_before);
            assert_eq!(
                fs::metadata(fixture.root.path.join("tasks.md"))
                    .unwrap()
                    .ino(),
                identity_before
            );
            assert_preimage(&fixture, &request);
        }
    }
    #[test]
    fn p0_writer_canonical_document_is_strict_bounded_and_revisions_cannot_overflow() {
        let fixture = Fixture::new();
        let bytes = fixture.document.to_canonical_bytes().unwrap();
        assert_eq!(
            CanonicalTaskDocumentV1::from_bytes(&bytes).unwrap(),
            fixture.document
        );
        let duplicate = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"workspace_id\":",
            "\"workspace_id\":\"evil\",\"workspace_id\":",
            1,
        );
        assert!(CanonicalTaskDocumentV1::from_bytes(duplicate.as_bytes()).is_err());
        let mut duplicate_task = fixture.document.clone();
        duplicate_task.tasks.push(duplicate_task.tasks[0].clone());
        assert!(duplicate_task.to_canonical_bytes().is_err());
        let mut oversized = fixture.document.clone();
        oversized.tasks[0].reviewer_role = "x".repeat(MAX_SOURCE_FILE_BYTES as usize + 1);
        assert!(oversized.to_canonical_bytes().is_err());
        let mut request = fixture.request();
        request.admitted_document.file_cas_rev = i64::MAX as u64;
        request.admitted_task_ref.file_cas_rev = i64::MAX as u64;
        assert!(
            rebase_task_mutation(
                &request,
                &request.admitted_document,
                request.expected_preimage_sha256,
                0
            )
            .is_err()
        );
    }
}
