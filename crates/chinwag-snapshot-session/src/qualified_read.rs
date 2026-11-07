//! Fixed V2 snapshot reads. Stored observations never mint task authority.
#![forbid(unsafe_code)]

use crate::{
    Error, Result, Rows, SessionError, SessionReceipt, ThreadContext, Value,
    native::Connection,
    qualified::{
        ImmutableOriginalKey, InferredLegacyAssociation, LogicalKey, QualifiedRecord, RecordChunk,
        RecordFamily, RecordHeader, TaskRefEnvelope, assemble_record, chunk_key,
        decode_legacy_association, legacy_association_key, record_variant_key,
    },
    qualified_schema as schema,
};
use chinwag_snapshot_read_owner_private::ReadOwner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClassification {
    Missing,
    LinkedObservation,
    Dangling,
    Quarantined,
    MalformedHeld,
    LegacyUnqualified,
}

#[derive(Debug)]
pub struct RecordView {
    classification: RecordClassification,
    record: Option<QualifiedRecord>,
    reason: Option<&'static str>,
}
pub type OriginalView = RecordView;

#[derive(Debug)]
pub struct LegacyAssociationView {
    classification: RecordClassification,
    association: Option<InferredLegacyAssociation>,
    reason: Option<&'static str>,
}
impl LegacyAssociationView {
    pub fn classification(&self) -> RecordClassification {
        self.classification
    }
    pub fn association(&self) -> Option<&InferredLegacyAssociation> {
        self.association.as_ref()
    }
    pub fn reason(&self) -> Option<&'static str> {
        self.reason
    }
    fn held(classification: RecordClassification, reason: &'static str) -> Self {
        Self {
            classification,
            association: None,
            reason: Some(reason),
        }
    }
}
impl RecordView {
    pub fn classification(&self) -> RecordClassification {
        self.classification
    }
    pub fn record(&self) -> Option<&QualifiedRecord> {
        self.record.as_ref()
    }
    pub fn reason(&self) -> Option<&'static str> {
        self.reason
    }
    fn held(classification: RecordClassification, reason: &'static str) -> Self {
        Self {
            classification,
            record: None,
            reason: Some(reason),
        }
    }
}

/// A historical migration outcome, not permission to migrate or execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReceipt {
    workspace: String,
    operation: String,
    request_digest: [u8; 32],
    from_version: u32,
    to_version: u32,
    outcome: String,
}
impl MigrationReceipt {
    pub fn workspace(&self) -> &str {
        &self.workspace
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub fn from_version(&self) -> u32 {
        self.from_version
    }
    pub fn to_version(&self) -> u32 {
        self.to_version
    }
    pub fn outcome(&self) -> &str {
        &self.outcome
    }
}

#[must_use = "Finish this original native snapshot before releasing its original file owner"]
pub struct QualifiedSnapshotSession {
    native: Option<Connection>,
    owner: Option<ReadOwner>,
    bootstrap: crate::native::BootstrapReceipt,
}
impl QualifiedSnapshotSession {
    pub fn from_v2_owner(owner: ReadOwner) -> std::result::Result<Self, SessionError> {
        let (native, bootstrap) = schema::open_v2_image(owner.image())?;
        Ok(Self {
            native: Some(native),
            owner: Some(owner),
            bootstrap,
        })
    }
    fn connection(&self) -> std::result::Result<&Connection, SessionError> {
        self.native
            .as_ref()
            .ok_or(SessionError::Contract("Qualified native owner missing"))
    }
    pub fn site_id(&self) -> std::result::Result<[u8; 16], SessionError> {
        crate::site_id(self.connection()?).map_err(SessionError::Native)
    }
    pub fn callback_api_was_null(&self) -> bool {
        self.bootstrap.api_was_null
    }
    pub fn record(
        &self,
        family: RecordFamily,
        workspace: &str,
        observation_id: &str,
    ) -> std::result::Result<RecordView, SessionError> {
        load_record(self.connection()?, family, workspace, observation_id)
            .map_err(SessionError::Native)
    }
    pub fn observation_ids(
        &self,
        key: &LogicalKey,
        after_id: &str,
        limit: usize,
    ) -> std::result::Result<Vec<String>, SessionError> {
        observation_ids(self.connection()?, key, after_id, limit).map_err(SessionError::Native)
    }
    pub fn original(
        &self,
        key: &ImmutableOriginalKey,
    ) -> std::result::Result<OriginalView, SessionError> {
        load_original(self.connection()?, key).map_err(SessionError::Native)
    }
    /// Borrowing this already-held snapshot permits exact historical replay
    /// lookup without another writer owner, migration transaction or operation.
    pub fn migration_receipt(
        &self,
        workspace: &str,
        operation: &str,
    ) -> std::result::Result<Option<MigrationReceipt>, SessionError> {
        migration_receipt(self.connection()?, workspace, operation).map_err(SessionError::Native)
    }
    /// IDs only; a page cannot amplify 64 maximum-size association payloads.
    pub fn legacy_associations(
        &self,
        workspace: &str,
        thread: &str,
        message: &str,
        after_id: &str,
        limit: usize,
    ) -> std::result::Result<Vec<String>, SessionError> {
        legacy_association_ids(
            self.connection()?,
            workspace,
            thread,
            message,
            after_id,
            limit,
        )
        .map_err(SessionError::Native)
    }
    pub fn legacy_association(
        &self,
        workspace: &str,
        thread: &str,
        message: &str,
        association_id: &str,
    ) -> std::result::Result<LegacyAssociationView, SessionError> {
        load_legacy_association(
            self.connection()?,
            workspace,
            thread,
            message,
            association_id,
        )
        .map_err(SessionError::Native)
    }
    pub fn legacy_context(
        &self,
        thread_id: &str,
    ) -> std::result::Result<ThreadContext, SessionError> {
        let native = self.connection()?;
        let values = crate::texts(&[thread_id]).map_err(SessionError::Native)?;
        Ok(ThreadContext {
            thread: native.query(c"SELECT id,repo_id,branch_ref,title,created_at_ms,updated_at_ms FROM threads WHERE id=?1 ORDER BY id", &values).map_err(SessionError::Native)?,
            messages: native.query(c"SELECT id,thread_id,author_key_id,role,body,created_at_ms FROM messages WHERE thread_id=?1 ORDER BY id", &values).map_err(SessionError::Native)?,
            pins: native.query(c"SELECT id,thread_id,file_path,symbol_hash,source_commit,body,created_at_ms FROM context_pins WHERE thread_id=?1 ORDER BY id", &values).map_err(SessionError::Native)?,
        })
    }
    pub fn finish(mut self) -> std::result::Result<SessionReceipt, SessionError> {
        let mut native = self
            .native
            .take()
            .ok_or(SessionError::Contract("Qualified native owner missing"))?;
        native.close().map_err(SessionError::Native)?;
        let before_file_release = crate::native::counts();
        let mut owner = self
            .owner
            .take()
            .ok_or(SessionError::Contract("Qualified file owner missing"))?;
        owner.verify_unchanged().map_err(SessionError::Owner)?;
        let file = owner.finish_read().map_err(SessionError::Owner)?;
        Ok(SessionReceipt {
            file,
            before_file_release,
            owner_verified_after_native_close: true,
        })
    }
}

fn identifier(value: &str, allow_empty: bool) -> Result<()> {
    if value.len() > 256
        || (!allow_empty && value.is_empty())
        || value.trim() != value
        || value.contains(['\0', '\r', '\n'])
    {
        return Err(Error::Contract("Invalid qualified lookup identifier"));
    }
    Ok(())
}
fn contract(_: crate::qualified::QualifiedError) -> Error {
    Error::Contract("Malformed qualified record envelope")
}
fn digest(value: &Value) -> Result<[u8; 32]> {
    match value {
        Value::Blob(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Contract("Qualified digest length")),
        _ => Err(Error::Contract("Qualified digest type")),
    }
}
fn u64_blob(value: &Value) -> Result<u64> {
    match value {
        Value::Blob(bytes) => {
            Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(
                |_| Error::Contract("Qualified U64 blob length"),
            )?))
        }
        _ => Err(Error::Contract("Qualified U64 blob type")),
    }
}

fn parse_header(
    row: &[Value],
    expected_family: RecordFamily,
) -> Result<(String, RecordHeader, Vec<u8>)> {
    let [
        Value::Text(key),
        Value::Text(workspace),
        Value::Text(observation),
        sha,
        length,
        Value::Integer(parts),
        Value::Blob(logical),
        Value::Integer(family),
    ] = row
    else {
        return Err(Error::Contract("Incomplete qualified header"));
    };
    if *family != i64::from(expected_family.code()) {
        return Err(Error::Contract("Qualified header family differs"));
    }
    let header = RecordHeader::try_new(
        expected_family,
        workspace.clone(),
        observation.clone(),
        digest(sha)?,
        u64_blob(length)?,
        u16::try_from(*parts).map_err(|_| Error::Contract("Qualified part count"))?,
    )
    .map_err(contract)?;
    if record_variant_key(&header) != *key {
        return Err(Error::Contract("Qualified physical variant key differs"));
    }
    Ok((key.clone(), header, logical.clone()))
}

/// Strict reconstruction for immutable-original comparisons. This does not
/// consult public quarantine classification and never produces authority.
pub(crate) fn load_accepted_variant(
    native: &Connection,
    family: RecordFamily,
    record_key: &str,
) -> Result<QualifiedRecord> {
    let rows = native.query(
        schema::family_table(family).by_variant,
        &[Value::Text(record_key.into())],
    )?;
    let [row] = rows.as_slice() else {
        return Err(Error::Contract(
            "Missing/duplicate accepted qualified variant",
        ));
    };
    let (key, header, logical) = parse_header(row, family)?;
    let parts = native.query(
        if family.is_replicated() {
            schema::OBSERVATION_PARTS
        } else {
            schema::LOCAL_PARTS
        },
        &[Value::Text(key.clone())],
    )?;
    // LIMIT 5 detects an extra part instead of silently hiding it at LIMIT 4.
    if parts.len() > 4 {
        return Err(Error::Contract("Extra qualified chunk"));
    }
    let chunks: Vec<RecordChunk> = parts
        .iter()
        .map(|part| match part.as_slice() {
            [Value::Integer(ordinal), Value::Blob(bytes)] => RecordChunk::try_new(
                u16::try_from(*ordinal).map_err(|_| Error::Contract("Qualified chunk ordinal"))?,
                bytes.clone(),
            )
            .map_err(contract),
            _ => Err(Error::Contract("Incomplete qualified chunk")),
        })
        .collect::<Result<_>>()?;
    let record = assemble_record(&header, &chunks).map_err(contract)?;
    if record.key().canonical_bytes() != logical {
        return Err(Error::Contract("Qualified logical key index differs"));
    }
    if native.query(schema::REFS, &[Value::Text(key)])? != reference_rows(&record) {
        return Err(Error::Contract("Qualified TaskRef indexes differ"));
    }
    Ok(record)
}

fn reference_row(reference: &TaskRefEnvelope, ordinal: usize) -> Vec<Value> {
    let i = reference.indexes();
    let baseline = i.baseline_commit();
    vec![
        Value::Integer(ordinal as i64),
        Value::Blob(reference.canonical().to_vec()),
        Value::Blob(reference.digest().to_vec()),
        Value::Text(i.workspace_id().into()),
        Value::Text(i.repo_id().into()),
        Value::Text(i.task_source_id().into()),
        Value::Blob(i.source_generation().to_be_bytes().to_vec()),
        Value::Text(i.canonical_task_path().into()),
        Value::Text(i.task_id().into()),
        Value::Blob(i.task_spec_digest().to_vec()),
        Value::Blob(i.task_status_rev().to_be_bytes().to_vec()),
        Value::Blob(i.file_cas_rev().to_be_bytes().to_vec()),
        Value::Text(baseline.algorithm().into()),
        Value::Blob(baseline.raw().to_vec()),
    ]
}
pub(crate) fn reference_rows(record: &QualifiedRecord) -> Rows {
    record
        .references()
        .iter()
        .enumerate()
        .map(|(ordinal, reference)| reference_row(reference, ordinal))
        .collect()
}
pub(crate) fn stored_reference_rows(record_key: &str, record: &QualifiedRecord) -> Rows {
    reference_rows(record)
        .into_iter()
        .enumerate()
        .map(|(ordinal, row)| {
            let mut values = vec![
                Value::Text(chunk_key(record_key, ordinal as u16)),
                Value::Text(record_key.into()),
            ];
            values.extend(row);
            values
        })
        .collect()
}

fn quarantined(native: &Connection, record: &QualifiedRecord) -> Result<bool> {
    if quarantined_identity(
        native,
        record.family(),
        record.workspace(),
        record.observation_id(),
    )? {
        return Ok(true);
    }
    match record.original() {
        Some(original) => Ok(!native
            .query(
                c"SELECT 1 FROM qualified_quarantine WHERE original_key=?1 LIMIT 1",
                &[Value::Blob(original.key().canonical_bytes())],
            )?
            .is_empty()),
        None => Ok(false),
    }
}

fn quarantined_identity(
    native: &Connection,
    family: RecordFamily,
    workspace: &str,
    observation_id: &str,
) -> Result<bool> {
    Ok(!native.query(c"SELECT 1 FROM qualified_quarantine WHERE family=?1 AND workspace_id=?2 AND observation_id=?3 LIMIT 1", &[
        Value::Integer(i64::from(family.code())), Value::Text(workspace.into()), Value::Text(observation_id.into())
    ])?.is_empty())
}

pub(crate) fn load_record(
    native: &Connection,
    family: RecordFamily,
    workspace: &str,
    observation_id: &str,
) -> Result<RecordView> {
    identifier(workspace, false)?;
    identifier(observation_id, false)?;
    // A conflict-only batch deliberately creates no normal observation header.
    // Its retained quarantine identity must still be visible as held evidence.
    if quarantined_identity(native, family, workspace, observation_id)? {
        return Ok(RecordView::held(
            RecordClassification::Quarantined,
            "Immutable qualified identity is quarantined",
        ));
    }
    let rows = native.query(
        schema::family_table(family).by_identity,
        &[
            Value::Text(workspace.into()),
            Value::Text(observation_id.into()),
        ],
    )?;
    let [row] = rows.as_slice() else {
        return Ok(RecordView::held(
            if rows.is_empty() {
                RecordClassification::Missing
            } else {
                RecordClassification::Quarantined
            },
            if rows.is_empty() {
                "No qualified observation"
            } else {
                "Multiple immutable observation variants"
            },
        ));
    };
    let record = match parse_header(row, family)
        .and_then(|(key, _, _)| load_accepted_variant(native, family, &key))
    {
        Ok(record) => record,
        Err(Error::Contract(reason)) => {
            return Ok(RecordView::held(
                RecordClassification::MalformedHeld,
                reason,
            ));
        }
        Err(error) => return Err(error),
    };
    if record.workspace() != workspace || record.observation_id() != observation_id {
        return Ok(RecordView::held(
            RecordClassification::MalformedHeld,
            "Qualified lookup context differs",
        ));
    }
    if quarantined(native, &record)? {
        return Ok(RecordView::held(
            RecordClassification::Quarantined,
            "Immutable qualified identity is quarantined",
        ));
    }
    let classification = if references_present(native, &record)? {
        RecordClassification::LinkedObservation
    } else {
        RecordClassification::Dangling
    };
    Ok(RecordView {
        classification,
        record: Some(record),
        reason: None,
    })
}

fn observation_ids(
    native: &Connection,
    key: &LogicalKey,
    after_id: &str,
    limit: usize,
) -> Result<Vec<String>> {
    identifier(after_id, true)?;
    if !(1..=64).contains(&limit) {
        return Err(Error::Contract("Qualified observation page limit"));
    }
    native
        .query(
            schema::family_table(key.family()).by_logical_key,
            &[
                Value::Text(key.workspace().into()),
                Value::Blob(key.canonical_bytes()),
                Value::Text(after_id.into()),
                Value::Integer(limit as i64),
            ],
        )?
        .iter()
        .map(|row| match row.as_slice() {
            [Value::Text(value)] => {
                identifier(value, false)?;
                Ok(value.clone())
            }
            _ => Err(Error::Contract("Malformed qualified observation ID index")),
        })
        .collect()
}

fn has_reference(
    native: &Connection,
    key: &LogicalKey,
    reference: Option<&TaskRefEnvelope>,
) -> Result<bool> {
    for id in observation_ids(native, key, "", 64)? {
        let view = load_record(native, key.family(), key.workspace(), &id)?;
        if view.classification() == RecordClassification::LinkedObservation
            && let Some(record) = view.record()
            && reference.is_none_or(|expected| record.references().contains(expected))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn references_present(native: &Connection, record: &QualifiedRecord) -> Result<bool> {
    for reference in record.references() {
        let i = reference.indexes();
        let source = LogicalKey::source(
            i.workspace_id().into(),
            i.task_source_id().into(),
            i.source_generation(),
        )
        .map_err(contract)?;
        if !has_reference(native, &source, None)? {
            return Ok(false);
        }
        if record.family() != RecordFamily::Projection {
            let task = LogicalKey::projection(
                i.workspace_id().into(),
                i.task_source_id().into(),
                i.task_id().into(),
            )
            .map_err(contract)?;
            if !has_reference(native, &task, Some(reference))? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(crate) fn load_original(
    native: &Connection,
    key: &ImmutableOriginalKey,
) -> Result<OriginalView> {
    if !matches!(
        key.family(),
        RecordFamily::Event
            | RecordFamily::Message
            | RecordFamily::Assignment
            | RecordFamily::Acceptance
    ) {
        return Err(Error::Contract("Not an immutable-original family"));
    }
    let encoded = key.canonical_bytes();
    if !native
        .query(
            c"SELECT 1 FROM qualified_quarantine WHERE original_key=?1 LIMIT 1",
            &[Value::Blob(encoded.clone())],
        )?
        .is_empty()
    {
        return Ok(RecordView::held(
            RecordClassification::Quarantined,
            "Immutable original binding conflict",
        ));
    }
    let rows = native.query(c"SELECT original_key,family,workspace_id,record_key,record_sha256,binding_sha256 FROM qualified_originals WHERE original_key=?1 LIMIT 2", &[Value::Blob(encoded.clone())])?;
    let [row] = rows.as_slice() else {
        return Ok(RecordView::held(
            if rows.is_empty() {
                RecordClassification::Missing
            } else {
                RecordClassification::Quarantined
            },
            "Missing/ambiguous immutable original index",
        ));
    };
    let parsed = (|| -> Result<QualifiedRecord> {
        let [
            Value::Blob(stored_key),
            Value::Integer(family),
            Value::Text(workspace),
            Value::Text(record_key),
            record_sha,
            binding_sha,
        ] = row.as_slice()
        else {
            return Err(Error::Contract("Malformed immutable original index"));
        };
        if *stored_key != encoded
            || *family != i64::from(key.family().code())
            || workspace != key.workspace()
        {
            return Err(Error::Contract("Immutable original context differs"));
        }
        let record = load_accepted_variant(native, key.family(), record_key)?;
        let original = record
            .original()
            .ok_or(Error::Contract("Original binding absent"))?;
        if original.key() != key
            || original.binding_digest() != digest(binding_sha)?
            || record.canonical_digest() != digest(record_sha)?
        {
            return Err(Error::Contract("Immutable original pointer differs"));
        }
        Ok(record)
    })();
    match parsed {
        Ok(record) => load_record(
            native,
            record.family(),
            record.workspace(),
            record.observation_id(),
        ),
        Err(Error::Contract(reason)) => Ok(RecordView::held(
            RecordClassification::MalformedHeld,
            reason,
        )),
        Err(error) => Err(error),
    }
}

fn migration_receipt(
    native: &Connection,
    workspace: &str,
    operation: &str,
) -> Result<Option<MigrationReceipt>> {
    identifier(workspace, false)?;
    identifier(operation, false)?;
    let rows = native.query(c"SELECT workspace_id,operation_id,request_sha256,from_version,to_version,outcome FROM qualified_migrations WHERE workspace_id=?1 AND operation_id=?2 LIMIT 2", &[Value::Text(workspace.into()),Value::Text(operation.into())])?;
    if rows.is_empty() {
        return Ok(None);
    }
    let [row] = rows.as_slice() else {
        return Err(Error::Contract("Ambiguous migration receipt"));
    };
    let [
        Value::Text(stored_workspace),
        Value::Text(stored_operation),
        sha,
        Value::Integer(1),
        Value::Integer(2),
        Value::Text(outcome),
    ] = row.as_slice()
    else {
        return Err(Error::Contract("Malformed migration receipt"));
    };
    if stored_workspace != workspace
        || stored_operation != operation
        || outcome != "MIGRATED_OBSERVATIONS_ONLY"
    {
        return Err(Error::Contract("Migration receipt context/outcome differs"));
    }
    Ok(Some(MigrationReceipt {
        workspace: stored_workspace.clone(),
        operation: stored_operation.clone(),
        request_digest: digest(sha)?,
        from_version: 1,
        to_version: 2,
        outcome: outcome.clone(),
    }))
}

fn legacy_association_ids(
    native: &Connection,
    workspace: &str,
    thread: &str,
    message: &str,
    after_id: &str,
    limit: usize,
) -> Result<Vec<String>> {
    for value in [workspace, thread, message] {
        identifier(value, false)?;
    }
    identifier(after_id, true)?;
    if !(1..=64).contains(&limit) {
        return Err(Error::Contract("Legacy association page limit"));
    }
    native.query(c"SELECT DISTINCT association_id FROM qualified_legacy_associations WHERE workspace_id=?1 AND legacy_thread_id=?2 AND legacy_message_id=?3 AND association_id>?4 ORDER BY association_id LIMIT ?5", &[
        Value::Text(workspace.into()),Value::Text(thread.into()),Value::Text(message.into()),Value::Text(after_id.into()),Value::Integer(limit as i64)
    ])?.iter().map(|row| match row.as_slice() {
        [Value::Text(id)] => { identifier(id,false)?; Ok(id.clone()) },
        _ => Err(Error::Contract("Malformed legacy association ID"))
    }).collect()
}

pub(crate) fn load_legacy_association(
    native: &Connection,
    workspace: &str,
    thread: &str,
    message: &str,
    association_id: &str,
) -> Result<LegacyAssociationView> {
    for value in [workspace, thread, message, association_id] {
        identifier(value, false)?;
    }
    let rows=native.query(c"SELECT id,workspace_id,legacy_thread_id,legacy_message_id,association_id,legacy_sha256,migration_operation_id,association,association_sha256,inferred_legacy FROM qualified_legacy_associations WHERE workspace_id=?1 AND legacy_thread_id=?2 AND legacy_message_id=?3 AND association_id=?4 ORDER BY id LIMIT 2", &[
        Value::Text(workspace.into()),Value::Text(thread.into()),Value::Text(message.into()),Value::Text(association_id.into())
    ])?;
    let [row] = rows.as_slice() else {
        return Ok(LegacyAssociationView::held(
            if rows.is_empty() {
                RecordClassification::Missing
            } else {
                RecordClassification::Quarantined
            },
            "Missing or conflicting legacy association variants",
        ));
    };
    let parsed = (|| -> Result<InferredLegacyAssociation> {
        let [
            Value::Text(physical),
            Value::Text(stored_workspace),
            Value::Text(stored_thread),
            Value::Text(stored_message),
            Value::Text(stored_id),
            body_sha,
            Value::Text(operation),
            Value::Blob(raw),
            association_sha,
            Value::Integer(1),
        ] = row.as_slice()
        else {
            return Err(Error::Contract("Malformed legacy association columns"));
        };
        let association = decode_legacy_association(raw).map_err(contract)?;
        if stored_workspace != workspace
            || stored_thread != thread
            || stored_message != message
            || stored_id != association_id
            || association.workspace() != workspace
            || association.legacy_thread_id() != thread
            || association.legacy_message_id() != message
            || association.association_id() != association_id
            || association.migration_operation() != operation
            || association.legacy_body_sha256() != digest(body_sha)?
            || association.canonical_digest() != digest(association_sha)?
            || legacy_association_key(&association) != *physical
        {
            return Err(Error::Contract(
                "Legacy association canonical/index context differs",
            ));
        }
        // Inference remains tied to the original exact legacy body, rather than
        // silently attaching to a later row under the same display identity.
        let original = native.query(
            c"SELECT body FROM messages WHERE id=?1 AND thread_id=?2 LIMIT 2",
            &[Value::Text(message.into()), Value::Text(thread.into())],
        )?;
        let [original] = original.as_slice() else {
            return Err(Error::Contract("Legacy original message absent"));
        };
        let [Value::Text(body)] = original.as_slice() else {
            return Err(Error::Contract("Legacy original message type"));
        };
        if crate::qualified::digest(body.as_bytes()) != association.legacy_body_sha256()
            || native
                .query(
                    c"SELECT 1 FROM threads WHERE id=?1",
                    &[Value::Text(thread.into())],
                )?
                .len()
                != 1
        {
            return Err(Error::Contract("Legacy original context/preimage changed"));
        }
        Ok(association)
    })();
    match parsed {
        Ok(association) => Ok(LegacyAssociationView {
            classification: RecordClassification::LegacyUnqualified,
            association: Some(association),
            reason: Some(
                "Inferred association has no historical source signature or task authority",
            ),
        }),
        Err(Error::Contract(reason)) => Ok(LegacyAssociationView::held(
            RecordClassification::MalformedHeld,
            reason,
        )),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qualified::{StoredGitOid, TaskRefIndexes, digest, split_record};

    const WORKSPACE: &str = "read-fixture-workspace";
    const SOURCE: &str = "00000000000000000000000000000001";

    fn native_test(test: impl FnOnce(&Connection) -> Result<()>) {
        let native = Connection::open_template_memory().unwrap();
        let result = crate::initialize_schema(&native)
            .and_then(|()| crate::transaction(&native, || schema::upgrade_v1(&native)))
            .and_then(|()| test(&native));
        crate::finish(native, result).unwrap();
    }
    fn reference() -> TaskRefEnvelope {
        let indexes = TaskRefIndexes::try_new(
            WORKSPACE.into(),
            "read-repository".into(),
            SOURCE.into(),
            1,
            "source/tasks.md".into(),
            "same-task-label".into(),
            [1; 32],
            0,
            0,
            StoredGitOid::Sha1([2; 20]),
        )
        .unwrap();
        let raw = indexes.canonical_bytes();
        TaskRefEnvelope::try_new(raw.clone(), digest(&raw), indexes).unwrap()
    }
    fn source() -> QualifiedRecord {
        record(
            "source-observation",
            LogicalKey::source(WORKSPACE.into(), SOURCE.into(), 1).unwrap(),
            vec![],
            b"source-observation".to_vec(),
        )
    }
    fn projection(id: &str, payload: Vec<u8>) -> QualifiedRecord {
        record(
            id,
            LogicalKey::projection(WORKSPACE.into(), SOURCE.into(), "same-task-label".into())
                .unwrap(),
            vec![reference()],
            payload,
        )
    }
    fn record(
        id: &str,
        key: LogicalKey,
        references: Vec<TaskRefEnvelope>,
        payload: Vec<u8>,
    ) -> QualifiedRecord {
        QualifiedRecord::try_new(
            id.into(),
            key,
            references,
            None,
            payload.clone(),
            digest(&payload),
        )
        .unwrap()
    }
    // This seeds only fresh private in-memory reader fixtures. Migration/write
    // sessions have separate original-owner installation and replay tests.
    fn seed(native: &Connection, record: &QualifiedRecord) -> Result<String> {
        let (header, parts) = split_record(record);
        let key = record_variant_key(&header);
        native.query(
            schema::family_table(record.family()).insert,
            &[
                Value::Text(key.clone()),
                Value::Text(record.workspace().into()),
                Value::Text(record.observation_id().into()),
                Value::Blob(header.record_digest().to_vec()),
                Value::Blob(header.total_length().to_be_bytes().to_vec()),
                Value::Integer(i64::from(header.part_count())),
                Value::Blob(record.key().canonical_bytes()),
                Value::Integer(i64::from(record.family().code())),
            ],
        )?;
        for part in parts {
            native.query(
                if record.family().is_replicated() {
                    schema::INSERT_OBSERVATION_PART
                } else {
                    schema::INSERT_LOCAL_PART
                },
                &[
                    Value::Text(chunk_key(&key, part.ordinal())),
                    Value::Text(key.clone()),
                    Value::Integer(i64::from(part.ordinal())),
                    Value::Blob(part.bytes().to_vec()),
                ],
            )?;
        }
        for values in stored_reference_rows(&key, record) {
            native.query(schema::INSERT_REF, &values)?;
        }
        Ok(key)
    }
    fn reset_refs(native: &Connection, key: &str, record: &QualifiedRecord) -> Result<()> {
        native.query(
            c"DELETE FROM qualified_task_refs WHERE record_key=?1",
            &[Value::Text(key.into())],
        )?;
        for values in stored_reference_rows(key, record) {
            native.query(schema::INSERT_REF, &values)?;
        }
        Ok(())
    }

    #[test]
    fn p010_read_dangling_dependencies_arrive_without_selecting_a_current_authority() {
        native_test(|native| {
            let first = projection("projection-observation", b"observed-phase-one".to_vec());
            seed(native, &first)?;
            let missing = load_record(
                native,
                RecordFamily::Projection,
                WORKSPACE,
                first.observation_id(),
            )?;
            assert_eq!(missing.classification(), RecordClassification::Dangling);
            assert_eq!(missing.record(), Some(&first));
            seed(native, &source())?;
            assert_eq!(
                load_record(
                    native,
                    RecordFamily::Projection,
                    WORKSPACE,
                    first.observation_id()
                )?
                .classification(),
                RecordClassification::LinkedObservation
            );
            let second = projection(
                first.observation_id(),
                b"competing-same-observation-id".to_vec(),
            );
            seed(native, &second)?;
            let conflict = load_record(
                native,
                RecordFamily::Projection,
                WORKSPACE,
                first.observation_id(),
            )?;
            assert_eq!(conflict.classification(), RecordClassification::Quarantined);
            assert!(conflict.record().is_none());
            assert_eq!(
                load_record(
                    native,
                    RecordFamily::Projection,
                    "other-workspace",
                    first.observation_id()
                )?
                .classification(),
                RecordClassification::Missing
            );
            Ok(())
        });
    }

    #[test]
    fn p010_read_never_exposes_a_missing_extra_or_corrupt_chunk_prefix() {
        native_test(|native| {
            let record = record(
                "large-source",
                LogicalKey::source(WORKSPACE.into(), SOURCE.into(), 1).unwrap(),
                vec![],
                vec![b's'; 65536],
            );
            let key = seed(native, &record)?;
            assert_eq!(
                load_record(
                    native,
                    RecordFamily::Source,
                    WORKSPACE,
                    record.observation_id()
                )?
                .record(),
                Some(&record)
            );
            native.query(c"UPDATE qualified_observation_chunks SET bytes=?1 WHERE record_key=?2 AND ordinal=1",&[Value::Blob(vec![0]),Value::Text(key.clone())])?;
            let bad = load_record(
                native,
                RecordFamily::Source,
                WORKSPACE,
                record.observation_id(),
            )?;
            assert_eq!(bad.classification(), RecordClassification::MalformedHeld);
            assert!(bad.record().is_none());
            let (_, parts) = split_record(&record);
            native.query(c"UPDATE qualified_observation_chunks SET bytes=?1 WHERE record_key=?2 AND ordinal=1",&[Value::Blob(parts[1].bytes().to_vec()),Value::Text(key.clone())])?;
            for ordinal in 2..=4 {
                native.query(
                    schema::INSERT_OBSERVATION_PART,
                    &[
                        Value::Text(chunk_key(&key, ordinal)),
                        Value::Text(key.clone()),
                        Value::Integer(i64::from(ordinal)),
                        Value::Blob(vec![1]),
                    ],
                )?;
            }
            assert_eq!(
                load_record(
                    native,
                    RecordFamily::Source,
                    WORKSPACE,
                    record.observation_id()
                )?
                .classification(),
                RecordClassification::MalformedHeld
            );
            native.query(
                c"DELETE FROM qualified_observation_chunks WHERE record_key=?1 AND ordinal>=1",
                &[Value::Text(key)],
            )?;
            let missing = load_record(
                native,
                RecordFamily::Source,
                WORKSPACE,
                record.observation_id(),
            )?;
            assert_eq!(
                missing.classification(),
                RecordClassification::MalformedHeld
            );
            assert!(missing.record().is_none());
            Ok(())
        });
    }

    #[test]
    fn p010_read_checks_all_ten_sql_indexes_and_exact_reference_bytes_again() {
        native_test(|native| {
            seed(native, &source())?;
            let record = projection("indexed-projection", b"phase".to_vec());
            let key = seed(native, &record)?;
            let changes: Vec<(&std::ffi::CStr, Value)> = vec![
                (
                    c"UPDATE qualified_task_refs SET workspace_id=?1 WHERE record_key=?2",
                    Value::Text("other-workspace".into()),
                ),
                (
                    c"UPDATE qualified_task_refs SET repo_id=?1 WHERE record_key=?2",
                    Value::Text("other-repository".into()),
                ),
                (
                    c"UPDATE qualified_task_refs SET task_source_id=?1 WHERE record_key=?2",
                    Value::Text("00000000000000000000000000000002".into()),
                ),
                (
                    c"UPDATE qualified_task_refs SET source_generation=?1 WHERE record_key=?2",
                    Value::Blob(2u64.to_be_bytes().to_vec()),
                ),
                (
                    c"UPDATE qualified_task_refs SET canonical_task_path=?1 WHERE record_key=?2",
                    Value::Text("Source/tasks.md".into()),
                ),
                (
                    c"UPDATE qualified_task_refs SET task_id=?1 WHERE record_key=?2",
                    Value::Text("other-task".into()),
                ),
                (
                    c"UPDATE qualified_task_refs SET task_spec_sha256=?1 WHERE record_key=?2",
                    Value::Blob(vec![9; 32]),
                ),
                (
                    c"UPDATE qualified_task_refs SET task_status_rev=?1 WHERE record_key=?2",
                    Value::Blob(2u64.to_be_bytes().to_vec()),
                ),
                (
                    c"UPDATE qualified_task_refs SET file_cas_rev=?1 WHERE record_key=?2",
                    Value::Blob(2u64.to_be_bytes().to_vec()),
                ),
                (
                    c"UPDATE qualified_task_refs SET baseline_algorithm=?1 WHERE record_key=?2",
                    Value::Text("git-sha256".into()),
                ),
                (
                    c"UPDATE qualified_task_refs SET baseline_bytes=?1 WHERE record_key=?2",
                    Value::Blob(vec![9; 20]),
                ),
                (
                    c"UPDATE qualified_task_refs SET canonical=?1 WHERE record_key=?2",
                    Value::Blob(vec![9]),
                ),
                (
                    c"UPDATE qualified_task_refs SET task_ref_sha256=?1 WHERE record_key=?2",
                    Value::Blob(vec![9; 32]),
                ),
            ];
            for (sql, value) in changes {
                reset_refs(native, &key, &record)?;
                native.query(sql, &[value, Value::Text(key.clone())])?;
                let view = load_record(
                    native,
                    RecordFamily::Projection,
                    WORKSPACE,
                    record.observation_id(),
                )?;
                assert_eq!(
                    view.classification(),
                    RecordClassification::MalformedHeld,
                    "{sql:?}"
                );
                assert!(view.record().is_none());
            }
            reset_refs(native, &key, &record)?;
            assert_eq!(
                load_record(
                    native,
                    RecordFamily::Projection,
                    WORKSPACE,
                    record.observation_id()
                )?
                .record(),
                Some(&record)
            );
            Ok(())
        });
    }

    #[test]
    fn p010_read_conflict_only_quarantine_is_held_without_normal_header() {
        native_test(|native| {
            let record = projection("incoming-only-conflict", b"incoming".to_vec());
            let (header, _) = split_record(&record);
            let key = record_variant_key(&header);
            native.query(c"INSERT INTO qualified_quarantine(id,identity,record_key,record_sha256,family,workspace_id,observation_id,total_length,part_count,logical_key,original_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL)",&[
                Value::Text(key.clone()),Value::Blob(record.key().canonical_bytes()),Value::Text(key),Value::Blob(header.record_digest().to_vec()),Value::Integer(i64::from(record.family().code())),Value::Text(WORKSPACE.into()),Value::Text(record.observation_id().into()),Value::Blob(header.total_length().to_be_bytes().to_vec()),Value::Integer(i64::from(header.part_count())),Value::Blob(record.key().canonical_bytes())
            ])?;
            let view = load_record(native, record.family(), WORKSPACE, record.observation_id())?;
            assert_eq!(view.classification(), RecordClassification::Quarantined);
            assert!(view.record().is_none());
            Ok(())
        });
    }

    #[test]
    fn p010_read_migration_receipt_is_exact_context_and_not_an_authority_grant() {
        native_test(|native| {
            assert!(migration_receipt(native, WORKSPACE, "migration-op")?.is_none());
            native.query(c"INSERT INTO qualified_migrations(id,workspace_id,operation_id,request_sha256,from_version,to_version,outcome) VALUES(?1,?2,?3,?4,1,2,'MIGRATED_OBSERVATIONS_ONLY')",&[Value::Text("receipt-key".into()),Value::Text(WORKSPACE.into()),Value::Text("migration-op".into()),Value::Blob(vec![7;32])])?;
            let receipt = migration_receipt(native, WORKSPACE, "migration-op")?.unwrap();
            assert_eq!(receipt.workspace(), WORKSPACE);
            assert_eq!(receipt.operation(), "migration-op");
            assert_eq!(receipt.request_digest(), [7; 32]);
            assert_eq!((receipt.from_version(), receipt.to_version()), (1, 2));
            assert!(migration_receipt(native, "other-workspace", "migration-op")?.is_none());
            native.query(
                c"UPDATE qualified_migrations SET from_version=9 WHERE id='receipt-key'",
                &[],
            )?;
            assert!(migration_receipt(native, WORKSPACE, "migration-op").is_err());
            Ok(())
        });
    }

    #[test]
    fn p010_read_original_pointer_reconstructs_and_checks_accepted_complete_bytes() {
        native_test(|native| {
            use crate::qualified::ImmutableOriginal;
            seed(native, &source())?;
            seed(native, &projection("projection", b"phase".to_vec()))?;
            let key =
                LogicalKey::message(WORKSPACE.into(), "signer-one".into(), "message-one".into())
                    .unwrap();
            let binding = b"controlled immutable signed-binding bytes".to_vec();
            let original =
                ImmutableOriginal::try_new(key.clone(), binding.clone(), digest(&binding)).unwrap();
            let payload = b"separate observed phase".to_vec();
            let record = QualifiedRecord::try_new(
                "message-observation".into(),
                key.clone(),
                vec![reference()],
                Some(original),
                payload.clone(),
                digest(&payload),
            )
            .unwrap();
            let record_key = seed(native, &record)?;
            native.query(c"INSERT INTO qualified_originals(id,original_key,family,workspace_id,record_key,record_sha256,binding_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7)", &[
                Value::Text("original-index".into()),Value::Blob(key.canonical_bytes()),Value::Integer(i64::from(key.family().code())),Value::Text(WORKSPACE.into()),Value::Text(record_key.clone()),Value::Blob(record.canonical_digest().to_vec()),Value::Blob(digest(&binding).to_vec())
            ])?;
            assert_eq!(load_original(native, &key)?.record(), Some(&record));
            native.query(
                c"UPDATE qualified_originals SET binding_sha256=?1 WHERE id='original-index'",
                &[Value::Blob(vec![8; 32])],
            )?;
            assert_eq!(
                load_original(native, &key)?.classification(),
                RecordClassification::MalformedHeld
            );
            native.query(
                c"UPDATE qualified_originals SET binding_sha256=?1 WHERE id='original-index'",
                &[Value::Blob(digest(&binding).to_vec())],
            )?;
            native.query(c"UPDATE qualified_observation_chunks SET bytes=?1 WHERE record_key=?2 AND ordinal=0", &[Value::Blob(vec![0]),Value::Text(record_key)])?;
            let corrupted = load_original(native, &key)?;
            assert_eq!(
                corrupted.classification(),
                RecordClassification::MalformedHeld
            );
            assert!(corrupted.record().is_none());
            Ok(())
        });
    }

    #[test]
    fn p010_read_id_pages_are_context_bound_and_partial_headers_stay_held() {
        native_test(|native| {
            let a = projection("observation-a", b"a".to_vec());
            let b = projection("observation-b", b"b".to_vec());
            seed(native, &a)?;
            seed(native, &b)?;
            assert_eq!(
                observation_ids(native, a.key(), "", 1)?,
                vec!["observation-a"]
            );
            assert_eq!(
                observation_ids(native, a.key(), "observation-a", 1)?,
                vec!["observation-b"]
            );
            assert!(observation_ids(native, a.key(), "", 65).is_err());
            let other = LogicalKey::projection(
                "other-workspace".into(),
                SOURCE.into(),
                "same-task-label".into(),
            )
            .unwrap();
            assert!(observation_ids(native, &other, "", 64)?.is_empty());
            native.query(c"INSERT INTO task_projection(id,workspace_id,observation_id) VALUES('controlled-partial',?1,'partial')", &[Value::Text(WORKSPACE.into())])?;
            let partial = load_record(native, RecordFamily::Projection, WORKSPACE, "partial")?;
            assert_eq!(
                partial.classification(),
                RecordClassification::MalformedHeld
            );
            assert!(partial.record().is_none());
            Ok(())
        });
    }
}
