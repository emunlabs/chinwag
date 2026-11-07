#![forbid(unsafe_code)]

//! Qualified storage is observational. Only a current source and its original
//! writer journal can classify a projection; no replicated row grants an effect.

use crate::task_dependency::{DependencyCommitment, DependencyNode, validate_dependency_graph};
use crate::task_legacy::{
    LegacyMigrationPin, VerifiedLegacyRecord, associate_legacy_with_pinned_source,
    decode_legacy_record_json,
};
use crate::task_normalization::{NormalizedTaskSpecV1, TaskControlV1};
use crate::task_ref::{
    CanonicalDecoder, GitOid, MAX_ID_UTF8_BYTES, MAX_SCALAR_BYTES, Sha256Digest, TaskContractError,
    TaskRefV1, encode_bytes_field, encode_list, encode_opt, encode_str_field, encode_u64,
};
use crate::task_source::{
    TaskSourceRecord, TaskSourceState, WorkspaceSourceRegistry, WorkspaceTaskPolicy,
};
use crate::task_wire::{
    PublishTaskV1, SignerEnrollment, TASK_BUS_V2_ALPN, TaskVerificationContext,
};
use crate::task_write_journal::{Journal, WriteOperationState};
use crate::task_writer::{CanonicalTaskDocumentV1, CanonicalTaskStatus, TaskEntrySnapshotV1};
use chinwag_snapshot_session_private::qualified::{
    ImmutableOriginal, InferredLegacyAssociation, LogicalKey, ObservationBatch, QualifiedRecord,
    RecordFamily, StoredGitOid, TaskRefEnvelope, TaskRefIndexes,
};
use std::collections::BTreeMap;

const SOURCE_DOMAIN: &[u8] = b"chinwag-source-observation-payload-v1\0";
const PROJECTION_DOMAIN: &[u8] = b"chinwag-task-projection-payload-v1\0";
const DEPENDENCY_DOMAIN: &[u8] = b"chinwag-dependency-observation-v1\0";
const LEGACY_DOMAIN: &[u8] = b"chinwag-inferred-legacy-observation-v1\0";
const MAX_STAGED_RECORDS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    Contract(&'static str),
    Task(TaskContractError),
    Storage(String),
    Source(String),
    Journal(String),
    Wire(String),
    Legacy(String),
    Unsupported,
}
impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task projection refused: {self:?}")
    }
}
impl std::error::Error for ProjectionError {}
impl From<TaskContractError> for ProjectionError {
    fn from(error: TaskContractError) -> Self {
        Self::Task(error)
    }
}
pub type ProjectionResult<T> = Result<T, ProjectionError>;
fn storage(error: impl std::fmt::Display) -> ProjectionError {
    ProjectionError::Storage(error.to_string())
}

pub fn task_ref_indexes(reference: &TaskRefV1) -> ProjectionResult<TaskRefIndexes> {
    reference.validate()?;
    let baseline = match reference.baseline_commit {
        GitOid::Sha1(value) => StoredGitOid::Sha1(value),
        GitOid::Sha256(value) => StoredGitOid::Sha256(value),
    };
    TaskRefIndexes::try_new(
        reference.workspace_id.clone(),
        reference.repo_id.clone(),
        reference.task_source_id.clone(),
        reference.source_generation,
        reference.canonical_task_path.clone(),
        reference.task_id.clone(),
        reference.task_spec_digest.0,
        reference.task_status_rev,
        reference.file_cas_rev,
        baseline,
    )
    .map_err(storage)
}
pub fn task_ref_envelope(reference: &TaskRefV1) -> ProjectionResult<TaskRefEnvelope> {
    TaskRefEnvelope::try_new(
        reference.encode()?,
        reference.task_ref_digest()?.0,
        task_ref_indexes(reference)?,
    )
    .map_err(storage)
}
/// Repeat the CLI codec checks on reads; the native constructor is not authority.
pub fn decode_stored_reference(envelope: &TaskRefEnvelope) -> ProjectionResult<TaskRefV1> {
    let reference = TaskRefV1::decode(envelope.canonical())?;
    if reference.encode()? != envelope.canonical()
        || reference.task_ref_digest()?.0 != envelope.digest()
        || &task_ref_indexes(&reference)? != envelope.indexes()
    {
        return Err(ProjectionError::Contract(
            "TaskRef bytes/digest/index disagreement",
        ));
    }
    Ok(reference)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourcePayload {
    repo: String,
    worktree: String,
    path: String,
    normalization_version: u64,
    schema_version: u64,
    config_digest: Sha256Digest,
    writer: String,
    writer_epoch: u64,
    state: String,
    revision: u64,
    file_hash: Sha256Digest,
    enrollment_evidence: Vec<u8>,
}
impl SourcePayload {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = SOURCE_DOMAIN.to_vec();
        for value in [&self.repo, &self.worktree, &self.path] {
            bytes.extend(encode_str_field(value));
        }
        bytes.extend(encode_u64(self.normalization_version));
        bytes.extend(encode_u64(self.schema_version));
        bytes.extend(self.config_digest.encode_typed());
        bytes.extend(encode_str_field(&self.writer));
        bytes.extend(encode_u64(self.writer_epoch));
        bytes.extend(encode_str_field(&self.state));
        bytes.extend(encode_u64(self.revision));
        bytes.extend(self.file_hash.encode_typed());
        bytes.extend(encode_bytes_field(&self.enrollment_evidence));
        bytes
    }
    fn decode(bytes: &[u8]) -> ProjectionResult<Self> {
        let mut d = CanonicalDecoder::new(bytes);
        if d.take(SOURCE_DOMAIN.len())? != SOURCE_DOMAIN {
            return Err(ProjectionError::Contract("source payload domain"));
        }
        let value = Self {
            repo: d.string(MAX_ID_UTF8_BYTES)?,
            worktree: d.string(MAX_ID_UTF8_BYTES)?,
            path: d.string(crate::task_ref::MAX_CANONICAL_PATH_BYTES)?,
            normalization_version: d.u64()?,
            schema_version: d.u64()?,
            config_digest: d.sha256_digest()?,
            writer: d.string(MAX_ID_UTF8_BYTES)?,
            writer_epoch: d.revision()?,
            state: d.string(MAX_ID_UTF8_BYTES)?,
            revision: d.revision()?,
            file_hash: d.sha256_digest()?,
            enrollment_evidence: d.bytes(MAX_SCALAR_BYTES)?.to_vec(),
        };
        d.finish()?;
        if value.encode() != bytes {
            return Err(ProjectionError::Contract("noncanonical source payload"));
        }
        Ok(value)
    }
}

/// Records an observation of supplied source metadata, not an enrollment grant.
#[allow(clippy::too_many_arguments)]
pub fn source_observation(
    observation_id: String,
    record: &TaskSourceRecord,
    policy: &WorkspaceTaskPolicy,
    source_revision: u64,
    file_hash: Sha256Digest,
    enrollment_evidence: Vec<u8>,
) -> ProjectionResult<QualifiedRecord> {
    record
        .validate(policy)
        .map_err(|e| ProjectionError::Source(format!("{e:?}")))?;
    crate::task_ref::encode_checked_rev(source_revision)?;
    let state = match record.state {
        TaskSourceState::Proposed => "proposed",
        TaskSourceState::Enrolled => "enrolled",
        TaskSourceState::Held(_) => "held",
        TaskSourceState::Suspended => "suspended",
        TaskSourceState::Retired => "retired",
    };
    let payload = SourcePayload {
        repo: record.repo_id.clone(),
        worktree: record.source_worktree_id.clone(),
        path: record.canonical_relative_path.clone(),
        normalization_version: u64::from(record.normalization_version),
        schema_version: u64::from(record.schema_version),
        config_digest: Sha256Digest(record.config_digest),
        writer: record.writer_principal.clone(),
        writer_epoch: record.writer_epoch,
        state: state.into(),
        revision: source_revision,
        file_hash,
        enrollment_evidence,
    }
    .encode();
    let key = LogicalKey::source(
        record.workspace_id.clone(),
        record.task_source_id.clone(),
        record.source_generation,
    )
    .map_err(storage)?;
    QualifiedRecord::try_new(
        observation_id,
        key,
        vec![],
        None,
        payload.clone(),
        Sha256Digest::of(&payload).0,
    )
    .map_err(storage)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProjectionPayload {
    spec: Vec<u8>,
    control: Vec<u8>,
    source_hash: Sha256Digest,
    transition: Option<String>,
    status: String,
    owner: Option<String>,
    reviewer: String,
    completion: Sha256Digest,
    flags: Vec<String>,
}
fn status_text(status: CanonicalTaskStatus) -> &'static str {
    match status {
        CanonicalTaskStatus::Todo => "todo",
        CanonicalTaskStatus::InProgress => "in-progress",
        CanonicalTaskStatus::DonePendingReview => "done-pending-review",
        CanonicalTaskStatus::Done => "done",
        CanonicalTaskStatus::Blocked => "blocked",
    }
}
impl ProjectionPayload {
    fn encode(&self) -> ProjectionResult<Vec<u8>> {
        let mut bytes = PROJECTION_DOMAIN.to_vec();
        bytes.extend(encode_bytes_field(&self.spec));
        bytes.extend(encode_bytes_field(&self.control));
        bytes.extend(self.source_hash.encode_typed());
        bytes.extend(encode_opt(self.transition.as_deref(), encode_str_field));
        bytes.extend(encode_str_field(&self.status));
        bytes.extend(encode_opt(self.owner.as_deref(), encode_str_field));
        bytes.extend(encode_str_field(&self.reviewer));
        bytes.extend(self.completion.encode_typed());
        bytes.extend(encode_list(&self.flags, |s| encode_str_field(s))?);
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> ProjectionResult<Self> {
        let mut d = CanonicalDecoder::new(bytes);
        if d.take(PROJECTION_DOMAIN.len())? != PROJECTION_DOMAIN {
            return Err(ProjectionError::Contract("projection payload domain"));
        }
        let value = Self {
            spec: d.bytes(MAX_SCALAR_BYTES)?.to_vec(),
            control: d.bytes(MAX_SCALAR_BYTES)?.to_vec(),
            source_hash: d.sha256_digest()?,
            transition: d.optional(|d| d.string(MAX_ID_UTF8_BYTES))?,
            status: d.string(MAX_ID_UTF8_BYTES)?,
            owner: d.optional(|d| d.string(MAX_ID_UTF8_BYTES))?,
            reviewer: d.string(MAX_ID_UTF8_BYTES)?,
            completion: d.sha256_digest()?,
            flags: d.list(|d| d.string(MAX_ID_UTF8_BYTES))?,
        };
        d.finish()?;
        if value.encode()? != bytes {
            return Err(ProjectionError::Contract("noncanonical projection payload"));
        }
        Ok(value)
    }
}
fn check_projection_values(
    reference: &TaskRefV1,
    entry: &TaskEntrySnapshotV1,
    spec: &NormalizedTaskSpecV1,
    control: &TaskControlV1,
) -> ProjectionResult<()> {
    control.validate()?;
    if entry.task_id != reference.task_id
        || entry.task_status_rev != reference.task_status_rev
        || entry.baseline_commit != reference.baseline_commit
        || entry.task_spec_digest != reference.task_spec_digest
        || spec.task_id() != reference.task_id
        || spec.task_spec_digest() != reference.task_spec_digest
        || spec.reviewer_role() != entry.reviewer_role
        || control.reviewer_role != entry.reviewer_role
        || spec.dependencies() != entry.dependencies
        || control.task_key != reference.task_key()
        || control.task_control_digest()? != entry.task_control_digest
    {
        return Err(ProjectionError::Contract(
            "projection spec/control/current-entry mismatch",
        ));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn projection_observation(
    observation_id: String,
    reference: &TaskRefV1,
    entry: &TaskEntrySnapshotV1,
    spec: &NormalizedTaskSpecV1,
    control: &TaskControlV1,
    source_hash: Sha256Digest,
    transition: Option<String>,
) -> ProjectionResult<QualifiedRecord> {
    check_projection_values(reference, entry, spec, control)?;
    let payload = ProjectionPayload {
        spec: spec.encode(),
        control: control.encode()?,
        source_hash,
        transition,
        status: status_text(entry.status).into(),
        owner: entry.owner_actor.clone(),
        reviewer: entry.reviewer_role.clone(),
        completion: entry.completion_policy_digest,
        flags: entry.execution_flags.clone(),
    }
    .encode()?;
    let key = LogicalKey::projection(
        reference.workspace_id.clone(),
        reference.task_source_id.clone(),
        reference.task_id.clone(),
    )
    .map_err(storage)?;
    QualifiedRecord::try_new(
        observation_id,
        key,
        vec![task_ref_envelope(reference)?],
        None,
        payload.clone(),
        Sha256Digest::of(&payload).0,
    )
    .map_err(storage)
}

/// Signature verification and binary encoding occur on one owned, immutable frame.
/// The canonical binary signed frame appears only in the original binding.
pub fn message_observation(
    observation_id: String,
    frame: PublishTaskV1,
    roster: &[SignerEnrollment],
    context: &TaskVerificationContext<'_>,
    phase: Vec<u8>,
) -> ProjectionResult<QualifiedRecord> {
    let verified = frame
        .verify(TASK_BUS_V2_ALPN, roster, context)
        .map_err(|e| ProjectionError::Wire(e.to_string()))?;
    let principal = verified.authenticated().signer_principal().to_owned();
    let reference = verified.authenticated().transcript().task_ref.clone();
    let binding = frame
        .encode_binary(context.ratified_profiles)
        .map_err(|e| ProjectionError::Wire(e.to_string()))?;
    let key = LogicalKey::message(
        reference.workspace_id.clone(),
        principal,
        frame.transcript.message_id.clone(),
    )
    .map_err(storage)?;
    let original =
        ImmutableOriginal::try_new(key.clone(), binding.clone(), Sha256Digest::of(&binding).0)
            .map_err(storage)?;
    QualifiedRecord::try_new(
        observation_id,
        key,
        vec![task_ref_envelope(&reference)?],
        Some(original),
        phase.clone(),
        Sha256Digest::of(&phase).0,
    )
    .map_err(storage)
}

pub fn dependency_observation(
    observation_id: String,
    dependent: &TaskRefV1,
    prerequisite: &TaskRefV1,
    commitment: &DependencyCommitment,
    dag_revision: u64,
) -> ProjectionResult<QualifiedRecord> {
    crate::task_dependency::canonicalize_dependencies(
        &dependent.task_key(),
        vec![commitment.clone()],
    )?;
    crate::task_ref::encode_checked_rev(dag_revision)?;
    if dependent.repo_id != prerequisite.repo_id
        || commitment.target_key != prerequisite.task_key()
        || commitment.target_spec_digest != prerequisite.task_spec_digest
    {
        return Err(ProjectionError::Contract(
            "dependency repository/key/spec mismatch",
        ));
    }
    let mut payload = DEPENDENCY_DOMAIN.to_vec();
    payload.extend(encode_u64(dag_revision));
    payload.extend(commitment.encode());
    let key = LogicalKey::dependency(
        dependent.workspace_id.clone(),
        dependent.task_source_id.clone(),
        dependent.task_id.clone(),
        prerequisite.task_source_id.clone(),
        prerequisite.task_id.clone(),
    )
    .map_err(storage)?;
    QualifiedRecord::try_new(
        observation_id,
        key,
        vec![
            task_ref_envelope(dependent)?,
            task_ref_envelope(prerequisite)?,
        ],
        None,
        payload.clone(),
        Sha256Digest::of(&payload).0,
    )
    .map_err(storage)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionDisposition {
    LinkedObservation,
    DanglingObservation,
    LegacyUnqualified,
    HeldUnsupported,
    HistoricalObservation,
    FixtureCurrentObservation,
    Quarantined,
    MalformedHeld,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionObservation {
    id: String,
    disposition: ProjectionDisposition,
    reference: Option<TaskRefV1>,
}
impl ProjectionObservation {
    pub fn observation_id(&self) -> &str {
        &self.id
    }
    pub fn disposition(&self) -> ProjectionDisposition {
        self.disposition
    }
    pub fn task_ref(&self) -> Option<&TaskRefV1> {
        self.reference.as_ref()
    }
    /// No cache classifier or fixture result is an authority for live effects.
    pub fn require_production_current(&self) -> ProjectionResult<()> {
        Err(ProjectionError::Unsupported)
    }
}

/// Relationship consistency only. Staged source rows never enroll a source.
pub fn classify_staged_relationships(
    records: &[QualifiedRecord],
    existing: &[QualifiedRecord],
) -> ProjectionResult<Vec<ProjectionObservation>> {
    if records.len().saturating_add(existing.len()) > MAX_STAGED_RECORDS {
        return Err(ProjectionError::Contract("staged observation count"));
    }
    let all: Vec<_> = existing.iter().chain(records).collect();
    let source_conflict = |source_key: &LogicalKey| -> ProjectionResult<bool> {
        let sources = all
            .iter()
            .filter(|candidate| candidate.key() == source_key)
            .map(|candidate| SourcePayload::decode(candidate.payload()))
            .collect::<ProjectionResult<Vec<_>>>()?;
        Ok(sources.first().is_some_and(|first| {
            sources.iter().any(|other| {
                other.repo != first.repo
                    || other.worktree != first.worktree
                    || other.path != first.path
                    || other.normalization_version != first.normalization_version
                    || other.schema_version != first.schema_version
            })
        }))
    };
    let mut tasks = BTreeMap::new();
    for record in &all {
        if record.family() == RecordFamily::Projection {
            for envelope in record.references() {
                let reference = decode_stored_reference(envelope)?;
                tasks.insert(reference.task_ref_digest()?.0, reference);
            }
        }
    }
    records
        .iter()
        .map(|record| {
            let references = record
                .references()
                .iter()
                .map(decode_stored_reference)
                .collect::<ProjectionResult<Vec<_>>>()?;
            if references.windows(2).any(|pair| {
                pair[0].workspace_id != pair[1].workspace_id || pair[0].repo_id != pair[1].repo_id
            }) {
                return Err(ProjectionError::Contract(
                    "cross-workspace/repository relationship",
                ));
            }
            let mut linked = true;
            let mut conflicting_source =
                record.family() == RecordFamily::Source && source_conflict(record.key())?;
            for reference in &references {
                let source_key = LogicalKey::source(
                    reference.workspace_id.clone(),
                    reference.task_source_id.clone(),
                    reference.source_generation,
                )
                .map_err(storage)?;
                let sources = all
                    .iter()
                    .filter(|candidate| candidate.key() == &source_key)
                    .map(|candidate| SourcePayload::decode(candidate.payload()))
                    .collect::<ProjectionResult<Vec<_>>>()?;
                if let Some(first) = sources.first() {
                    conflicting_source |= sources.iter().any(|other| {
                        other.repo != first.repo
                            || other.worktree != first.worktree
                            || other.path != first.path
                            || other.normalization_version != first.normalization_version
                            || other.schema_version != first.schema_version
                    });
                    linked &= sources.iter().all(|source| {
                        source.repo == reference.repo_id
                            && source.path == reference.canonical_task_path
                    });
                } else {
                    linked = false;
                }
                linked &= tasks.get(&reference.task_ref_digest()?.0) == Some(reference);
            }
            let disposition = if conflicting_source {
                ProjectionDisposition::Quarantined
            } else if record.payload().starts_with(LEGACY_DOMAIN) {
                ProjectionDisposition::LegacyUnqualified
            } else if linked {
                ProjectionDisposition::LinkedObservation
            } else {
                ProjectionDisposition::DanglingObservation
            };
            Ok(ProjectionObservation {
                id: record.observation_id().into(),
                disposition,
                reference: references.first().cloned(),
            })
        })
        .collect()
}
pub fn prepare_replica_observations(
    records: Vec<QualifiedRecord>,
    existing: &[QualifiedRecord],
) -> ProjectionResult<ObservationBatch> {
    classify_staged_relationships(&records, existing)?;
    ObservationBatch::try_new(records).map_err(storage)
}
pub fn validate_projection_dependency_graph(nodes: &[DependencyNode]) -> ProjectionResult<()> {
    validate_dependency_graph(nodes).map_err(ProjectionError::Task)
}

struct ControlledProjection<'a> {
    registry: &'a WorkspaceSourceRegistry,
    journal: &'a Journal,
}
/// No public constructor supplies source, signature, custody or recovery trust.
pub struct ProjectionAuthority<'a> {
    controlled: Option<ControlledProjection<'a>>,
}
impl ProjectionAuthority<'_> {
    pub fn unsupported() -> Self {
        Self { controlled: None }
    }
}
#[cfg(test)]
impl<'a> ProjectionAuthority<'a> {
    pub(crate) fn fixture(registry: &'a WorkspaceSourceRegistry, journal: &'a Journal) -> Self {
        Self {
            controlled: Some(ControlledProjection { registry, journal }),
        }
    }
}

pub fn reconcile_current_projection(
    record: &QualifiedRecord,
    authority: &ProjectionAuthority<'_>,
    spec: &NormalizedTaskSpecV1,
    control: &TaskControlV1,
) -> ProjectionResult<ProjectionObservation> {
    reconcile_projection_inner(record, authority, spec, control, || {})
}

#[cfg(test)]
pub(crate) fn reconcile_projection_with_private_cut(
    record: &QualifiedRecord,
    authority: &ProjectionAuthority<'_>,
    spec: &NormalizedTaskSpecV1,
    control: &TaskControlV1,
    after_source_recheck: impl FnOnce(),
) -> ProjectionResult<ProjectionObservation> {
    reconcile_projection_inner(record, authority, spec, control, after_source_recheck)
}

fn reconcile_projection_inner(
    record: &QualifiedRecord,
    authority: &ProjectionAuthority<'_>,
    spec: &NormalizedTaskSpecV1,
    control: &TaskControlV1,
    after_source_recheck: impl FnOnce(),
) -> ProjectionResult<ProjectionObservation> {
    if record.family() != RecordFamily::Projection || record.references().len() != 1 {
        return Err(ProjectionError::Contract("not a task projection"));
    }
    let reference = decode_stored_reference(&record.references()[0])?;
    let payload = ProjectionPayload::decode(record.payload())?;
    let held = |disposition| ProjectionObservation {
        id: record.observation_id().into(),
        disposition,
        reference: Some(reference.clone()),
    };
    let Some(context) = &authority.controlled else {
        return Ok(held(ProjectionDisposition::HeldUnsupported));
    };
    context
        .journal
        .revalidate_snapshot()
        .map_err(|e| ProjectionError::Journal(e.to_string()))?;
    let result = (|| {
        let (source, file) = context
            .registry
            .read_for_scheduler(&reference.task_source_id)
            .map_err(|e| ProjectionError::Source(format!("{e:?}")))?;
        let document = CanonicalTaskDocumentV1::from_bytes(&file.bytes)
            .map_err(|e| ProjectionError::Source(format!("{e:?}")))?;
        if document.workspace_id != source.workspace_id
            || document.repo_id != source.repo_id
            || document.task_source_id != source.task_source_id
            || document.source_generation != source.source_generation
        {
            return Err(ProjectionError::Contract(
                "canonical source metadata disagreement",
            ));
        }
        let Some(entry) = document
            .tasks
            .iter()
            .find(|entry| entry.task_id == reference.task_id)
        else {
            return Ok(held(ProjectionDisposition::HistoricalObservation));
        };
        if document.task_ref(entry, &source.canonical_relative_path) != reference
            || file.sha256 != payload.source_hash.0
            || document.last_operation_id != payload.transition
        {
            return Ok(held(ProjectionDisposition::HistoricalObservation));
        }
        check_projection_values(&reference, entry, spec, control)?;
        let expected = ProjectionPayload {
            spec: spec.encode(),
            control: control.encode()?,
            source_hash: Sha256Digest(file.sha256),
            transition: document.last_operation_id.clone(),
            status: status_text(entry.status).into(),
            owner: entry.owner_actor.clone(),
            reviewer: entry.reviewer_role.clone(),
            completion: entry.completion_policy_digest,
            flags: entry.execution_flags.clone(),
        };
        if expected != payload {
            return Err(ProjectionError::Contract(
                "projection differs from current canonical commitments",
            ));
        }
        let mut current_record = None;
        for original in context.journal.latest_records().filter(|row| {
            row.request.workspace_id == reference.workspace_id
                && row.request.task_source_id == reference.task_source_id
        }) {
            let checked = context
                .journal
                .lookup_request(&original.request)
                .map_err(|e| ProjectionError::Journal(e.to_string()))?
                .ok_or(ProjectionError::Contract("original writer record missing"))?;
            if Some(checked.request.operation_id.as_str()) == document.last_operation_id.as_deref()
            {
                current_record = Some(checked);
            } else if !matches!(
                checked.state,
                WriteOperationState::Acknowledged | WriteOperationState::Rejected
            ) {
                return Ok(held(ProjectionDisposition::HistoricalObservation));
            }
        }
        match (document.last_operation_id.as_deref(), current_record) {
            (None, None) if document.file_cas_rev == 0 => {}
            (Some(_), Some(row))
                if matches!(
                    row.state,
                    WriteOperationState::Recorded | WriteOperationState::Acknowledged
                ) =>
            {
                let prepared = row.prepared.as_ref().ok_or(ProjectionError::Contract(
                    "writer successor evidence absent",
                ))?;
                if prepared.successor_hash != file.sha256
                    || prepared.successor_revision != document.file_cas_rev
                    || prepared.canonical_relative_path != source.canonical_relative_path
                    || row.request.writer_epoch != source.writer_epoch
                    || row.result.is_none()
                {
                    return Ok(held(ProjectionDisposition::HistoricalObservation));
                }
                let signed = TaskRefV1::decode(&row.request.signed_task_ref)?;
                if signed.workspace_id != reference.workspace_id
                    || signed.repo_id != reference.repo_id
                    || signed.task_source_id != reference.task_source_id
                    || signed.source_generation != reference.source_generation
                    || signed.canonical_task_path != reference.canonical_task_path
                {
                    return Ok(held(ProjectionDisposition::HistoricalObservation));
                }
            }
            _ => return Ok(held(ProjectionDisposition::HistoricalObservation)),
        }
        let (_, rechecked) = context
            .registry
            .read_for_scheduler(&reference.task_source_id)
            .map_err(|e| ProjectionError::Source(format!("{e:?}")))?;
        if rechecked.sha256 != file.sha256 || rechecked.dev != file.dev || rechecked.ino != file.ino
        {
            return Err(ProjectionError::Contract(
                "source changed during projection reconciliation",
            ));
        }
        after_source_recheck();
        Ok(held(ProjectionDisposition::FixtureCurrentObservation))
    })();
    context
        .journal
        .revalidate_snapshot()
        .map_err(|e| ProjectionError::Journal(e.to_string()))?;
    result
}

/// The inferred association remains a separate LegacyUnqualified observation.
#[allow(clippy::too_many_arguments)]
pub fn legacy_association_observation(
    observation_id: String,
    legacy_thread_id: String,
    migration_operation: String,
    original: &VerifiedLegacyRecord,
    raw_original: Vec<u8>,
    pin: &LegacyMigrationPin,
    pinned_preimage: &[u8],
    historical_candidates: &[TaskRefV1],
    authority: &ProjectionAuthority<'_>,
) -> ProjectionResult<InferredLegacyAssociation> {
    if authority.controlled.is_none() {
        return Err(ProjectionError::Unsupported);
    }
    if decode_legacy_record_json(&raw_original)
        .map_err(|e| ProjectionError::Legacy(e.to_string()))?
        != *original.record()
    {
        return Err(ProjectionError::Contract("legacy original record mismatch"));
    }
    let association = associate_legacy_with_pinned_source(
        original,
        true,
        pin,
        pinned_preimage,
        historical_candidates,
    )
    .map_err(|e| ProjectionError::Legacy(e.to_string()))?;
    let mut payload = LEGACY_DOMAIN.to_vec();
    payload.extend(encode_str_field(&pin.workspace_id));
    payload.extend(encode_str_field(&pin.repo_id));
    payload.extend(encode_str_field(&pin.canonical_task_path));
    payload.extend(encode_str_field(&pin.task_source_id));
    payload.extend(encode_u64(pin.source_generation));
    payload.extend(encode_u64(pin.file_cas_rev));
    payload.extend(pin.preimage_digest.encode_typed());
    payload.extend(association.legacy_canonical_payload_digest().encode_typed());
    payload.extend([1, 0]);
    InferredLegacyAssociation::try_new(
        observation_id,
        pin.workspace_id.clone(),
        legacy_thread_id,
        original.record().id.clone(),
        Sha256Digest::of(&raw_original).0,
        migration_operation,
        task_ref_envelope(association.task_ref())?,
        payload.clone(),
        Sha256Digest::of(&payload).0,
    )
    .map_err(storage)
}
