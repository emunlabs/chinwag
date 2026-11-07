#![forbid(unsafe_code)]

//! Typed storage joins. These APIs never turn a replicated observation or a
//! historical migration receipt into source, scheduler or execution authority.

use crate::task_projection::{
    ProjectionDisposition, ProjectionError, ProjectionResult, classify_staged_relationships,
    decode_stored_reference,
};
use crate::task_source_path::WorkspaceRootPin;
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    SessionReceipt, ThreadContext,
    qualified::{
        ImmutableOriginalKey, InferredLegacyAssociation, LegacyAssociationBatch,
        LocalJournalMirrorBatch, LogicalKey, ObservationBatch, QualifiedRecord, RecordFamily,
    },
    qualified_read::{
        MigrationReceipt, QualifiedSnapshotSession, RecordClassification, RecordView,
    },
    replacement::{
        Completion, MigrationRequest, QualifiedMigrationSession, QualifiedWriteSession, WriteOwner,
    },
};
use std::path::Path;

fn storage(error: impl std::fmt::Display) -> ProjectionError {
    ProjectionError::Storage(error.to_string())
}

/// Retain the original native read owner until checked close and file release.
#[must_use = "Finish the native snapshot and verify its original read owner"]
pub struct TaskStoreSnapshot {
    native: QualifiedSnapshotSession,
}
impl TaskStoreSnapshot {
    pub fn from_v2_owner(owner: ReadOwner) -> ProjectionResult<Self> {
        QualifiedSnapshotSession::from_v2_owner(owner)
            .map(|native| Self { native })
            .map_err(storage)
    }

    pub fn record(
        &self,
        family: RecordFamily,
        workspace: &str,
        observation_id: &str,
    ) -> ProjectionResult<StoredObservation> {
        let observed = checked_view(
            self.native
                .record(family, workspace, observation_id)
                .map_err(storage)?,
        )?;
        self.classify_relationships(observed)
    }

    pub fn original(&self, key: &ImmutableOriginalKey) -> ProjectionResult<StoredObservation> {
        let observed = checked_view(self.native.original(key).map_err(storage)?)?;
        self.classify_relationships(observed)
    }

    fn classify_relationships(
        &self,
        mut observed: StoredObservation,
    ) -> ProjectionResult<StoredObservation> {
        let Some(record) = observed.record.as_ref() else {
            return Ok(observed);
        };
        let mut keys = Vec::new();
        if record.family() == RecordFamily::Source {
            keys.push(record.key().clone());
        }
        for envelope in record.references() {
            let reference = decode_stored_reference(envelope)?;
            keys.push(
                LogicalKey::source(
                    reference.workspace_id.clone(),
                    reference.task_source_id.clone(),
                    reference.source_generation,
                )
                .map_err(storage)?,
            );
            keys.push(
                LogicalKey::projection(
                    reference.workspace_id,
                    reference.task_source_id,
                    reference.task_id,
                )
                .map_err(storage)?,
            );
        }
        keys.sort_by_cached_key(LogicalKey::canonical_bytes);
        keys.dedup();
        let mut context = Vec::new();
        for key in keys {
            let mut cursor = String::new();
            loop {
                let ids = self
                    .native
                    .observation_ids(&key, &cursor, 64)
                    .map_err(storage)?;
                if ids.is_empty() {
                    break;
                }
                for id in &ids {
                    if context.len() >= 4096 {
                        return Err(ProjectionError::Contract(
                            "relationship context count; held",
                        ));
                    }
                    let view = self
                        .native
                        .record(key.family(), key.workspace(), id)
                        .map_err(storage)?;
                    match view.classification() {
                        RecordClassification::Quarantined
                        | RecordClassification::MalformedHeld
                        | RecordClassification::Missing => {
                            observed.disposition =
                                if view.classification() == RecordClassification::Quarantined {
                                    ProjectionDisposition::Quarantined
                                } else {
                                    ProjectionDisposition::MalformedHeld
                                };
                            observed.record = None;
                            observed.reason = Some("related stored observation held");
                            return Ok(observed);
                        }
                        _ => {}
                    }
                    if let Some(record) = view.record() {
                        context.push(record.clone());
                    }
                }
                let next = ids.last().expect("nonempty page");
                if next <= &cursor {
                    return Err(ProjectionError::Contract(
                        "relationship cursor did not advance",
                    ));
                }
                cursor = next.clone();
            }
        }
        observed.disposition =
            classify_staged_relationships(std::slice::from_ref(record), &context)?[0].disposition();
        if observed.disposition == ProjectionDisposition::Quarantined {
            observed.record = None;
            observed.reason = Some("conflicting source binding observations");
        }
        Ok(observed)
    }

    pub fn observation_ids(
        &self,
        key: &LogicalKey,
        after_id: &str,
        limit: usize,
    ) -> ProjectionResult<Vec<String>> {
        self.native
            .observation_ids(key, after_id, limit)
            .map_err(storage)
    }

    pub fn legacy_context(&self, thread: &str) -> ProjectionResult<ThreadContext> {
        self.native.legacy_context(thread).map_err(storage)
    }

    pub fn legacy_associations(
        &self,
        workspace: &str,
        thread: &str,
        message: &str,
        after_id: &str,
        limit: usize,
    ) -> ProjectionResult<Vec<String>> {
        self.native
            .legacy_associations(workspace, thread, message, after_id, limit)
            .map_err(storage)
    }

    pub fn legacy_association(
        &self,
        workspace: &str,
        thread: &str,
        message: &str,
        association_id: &str,
    ) -> ProjectionResult<StoredLegacyAssociation> {
        let view = self
            .native
            .legacy_association(workspace, thread, message, association_id)
            .map_err(storage)?;
        if let Some(association) = view.association() {
            decode_stored_reference(association.reference())?;
        }
        Ok(StoredLegacyAssociation {
            classification: view.classification(),
            association: view.association().cloned(),
            reason: view.reason(),
        })
    }

    /// The request commits the original V1 preimage and complete batch. Replay
    /// reads that exact join in this already-held V2 snapshot; no write owner,
    /// migration transaction, fresh operation or repeated DDL is constructed.
    pub fn migration_replay(
        &self,
        original_request: &MigrationRequest,
    ) -> ProjectionResult<HistoricalMigration> {
        let receipt = self
            .native
            .migration_receipt(original_request.workspace(), original_request.operation())
            .map_err(storage)?
            .ok_or(ProjectionError::Contract("migration receipt missing; held"))?;
        check_migration_receipt(original_request, receipt)
    }

    pub fn finish(self) -> ProjectionResult<SessionReceipt> {
        self.native.finish().map_err(storage)
    }
}

#[derive(Debug)]
pub struct StoredLegacyAssociation {
    classification: RecordClassification,
    association: Option<InferredLegacyAssociation>,
    reason: Option<&'static str>,
}
impl StoredLegacyAssociation {
    pub fn classification(&self) -> RecordClassification {
        self.classification
    }
    pub fn association(&self) -> Option<&InferredLegacyAssociation> {
        self.association.as_ref()
    }
    pub fn reason(&self) -> Option<&'static str> {
        self.reason
    }
    pub fn require_production_authority(&self) -> ProjectionResult<()> {
        Err(ProjectionError::Unsupported)
    }
}

#[derive(Debug)]
pub struct StoredObservation {
    disposition: ProjectionDisposition,
    record: Option<QualifiedRecord>,
    reason: Option<&'static str>,
}
impl StoredObservation {
    pub fn disposition(&self) -> ProjectionDisposition {
        self.disposition
    }
    pub fn record(&self) -> Option<&QualifiedRecord> {
        self.record.as_ref()
    }
    pub fn reason(&self) -> Option<&'static str> {
        self.reason
    }
    pub fn require_production_authority(&self) -> ProjectionResult<()> {
        Err(ProjectionError::Unsupported)
    }
}
fn checked_view(view: RecordView) -> ProjectionResult<StoredObservation> {
    let disposition = match view.classification() {
        RecordClassification::Missing | RecordClassification::Dangling => {
            ProjectionDisposition::DanglingObservation
        }
        RecordClassification::LinkedObservation => ProjectionDisposition::LinkedObservation,
        RecordClassification::Quarantined => ProjectionDisposition::Quarantined,
        RecordClassification::MalformedHeld => ProjectionDisposition::MalformedHeld,
        RecordClassification::LegacyUnqualified => ProjectionDisposition::LegacyUnqualified,
    };
    if let Some(record) = view.record() {
        for reference in record.references() {
            decode_stored_reference(reference)?;
        }
    }
    Ok(StoredObservation {
        disposition,
        record: view.record().cloned(),
        reason: view.reason(),
    })
}

/// Successful historical storage evidence; it grants no repeated migration or
/// current task effect, even when its operation and digest match exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalMigration {
    workspace: String,
    operation: String,
    request_digest: [u8; 32],
}
impl HistoricalMigration {
    pub fn workspace(&self) -> &str {
        &self.workspace
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub fn require_production_authority(&self) -> ProjectionResult<()> {
        Err(ProjectionError::Unsupported)
    }
}
fn check_migration_receipt(
    request: &MigrationRequest,
    receipt: MigrationReceipt,
) -> ProjectionResult<HistoricalMigration> {
    if receipt.workspace() != request.workspace()
        || receipt.operation() != request.operation()
        || receipt.request_digest() != request.digest()
        || receipt.from_version() != 1
        || receipt.to_version() != 2
        || receipt.outcome() != "MIGRATED_OBSERVATIONS_ONLY"
    {
        return Err(ProjectionError::Contract(
            "migration receipt conflict; held",
        ));
    }
    Ok(HistoricalMigration {
        workspace: receipt.workspace().into(),
        operation: receipt.operation().into(),
        request_digest: receipt.request_digest(),
    })
}

/// No public constructor can approve a host path or infer a migration grant
/// from stored rows. The positive seam is confined to controlled unit fixtures.
pub struct StoreMutationAuthority {
    fixture_root: Option<WorkspaceRootPin>,
}
impl StoreMutationAuthority {
    pub fn unsupported() -> Self {
        Self { fixture_root: None }
    }
    fn revalidate(&self, root: &Path) -> ProjectionResult<()> {
        let expected = self
            .fixture_root
            .as_ref()
            .ok_or(ProjectionError::Unsupported)?;
        let actual = std::fs::canonicalize(root).map_err(storage)?;
        if actual != expected.path {
            return Err(ProjectionError::Contract("fixture store root changed"));
        }
        expected
            .verify()
            .map_err(|error| ProjectionError::Source(format!("{error:?}")))
    }
    #[cfg(test)]
    pub(crate) fn fixture(root: &Path) -> ProjectionResult<Self> {
        use std::os::unix::fs::MetadataExt;
        let path = std::fs::canonicalize(root).map_err(storage)?;
        let metadata = std::fs::metadata(&path).map_err(storage)?;
        let pin = WorkspaceRootPin {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            generation: 1,
        };
        pin.verify()
            .map_err(|error| ProjectionError::Source(format!("{error:?}")))?;
        Ok(Self {
            fixture_root: Some(pin),
        })
    }
}

/// One original explicitly controlled migration. Failures retain the native
/// owner's markers; there is no cleanup, adoption, new-ID or retry path here.
pub fn migrate_store(
    root: &Path,
    request: MigrationRequest,
    authority: &StoreMutationAuthority,
) -> ProjectionResult<Completion> {
    authority.revalidate(root)?;
    let owner = WriteOwner::acquire_existing_private_fixture(root).map_err(storage)?;
    let session = QualifiedMigrationSession::from_v1_owner(owner).map_err(storage)?;
    authority.revalidate(root)?;
    session
        .prepare(request, || false)
        .map_err(storage)?
        .commit(false)
        .map_err(storage)
}

pub fn append_observations(
    root: &Path,
    batch: ObservationBatch,
    authority: &StoreMutationAuthority,
) -> ProjectionResult<Completion> {
    authority.revalidate(root)?;
    let owner = WriteOwner::acquire_existing_private_fixture(root).map_err(storage)?;
    let session = QualifiedWriteSession::from_v2_owner(owner).map_err(storage)?;
    authority.revalidate(root)?;
    session
        .prepare_observations(batch, || false)
        .map_err(storage)?
        .commit(false)
        .map_err(storage)
}

/// Mirror DTOs have their own non-CRR API. This never reads or replaces the
/// authoritative NDJSON source-writer or scheduler journal.
pub fn append_local_journal_mirrors(
    root: &Path,
    batch: LocalJournalMirrorBatch,
    authority: &StoreMutationAuthority,
) -> ProjectionResult<Completion> {
    authority.revalidate(root)?;
    let owner = WriteOwner::acquire_existing_private_fixture(root).map_err(storage)?;
    let session = QualifiedWriteSession::from_v2_owner(owner).map_err(storage)?;
    authority.revalidate(root)?;
    session
        .prepare_local_journal_mirrors(batch, || false)
        .map_err(storage)?
        .commit(false)
        .map_err(storage)
}

pub fn append_legacy_associations(
    root: &Path,
    batch: LegacyAssociationBatch,
    authority: &StoreMutationAuthority,
) -> ProjectionResult<Completion> {
    authority.revalidate(root)?;
    let owner = WriteOwner::acquire_existing_private_fixture(root).map_err(storage)?;
    let session = QualifiedWriteSession::from_v2_owner(owner).map_err(storage)?;
    authority.revalidate(root)?;
    session
        .prepare_legacy_associations(batch, || false)
        .map_err(storage)?
        .commit(false)
        .map_err(storage)
}
