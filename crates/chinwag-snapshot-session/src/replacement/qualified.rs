//! One original fixture migration or bounded V2 observation write.
//! Authority journals remain external; every SQL operation here is fixed.
#![forbid(unsafe_code)]

use super::{
    Candidate, Decision, OriginalStoreOwner, Pending, PreparedOutcome, Result, WriteOwner,
    WriteSession, db_version, original_store_owner_seal, retained, run_transaction,
};
use crate::{
    Error, Rows, Value,
    native::Connection,
    qualified::{
        self, LegacyAssociationBatch, LocalJournalMirrorBatch, LogicalKey, ObservationBatch,
        QualifiedError, QualifiedRecord, RecordHeader, chunk_key, encode_record,
        record_variant_key, split_record,
    },
    qualified_read, qualified_schema,
};
use std::ffi::CStr;

const MIGRATION_DOMAIN: &[u8] = b"chinwag-qualified-migration-v1\0";
const WRITE_DOMAIN: &[u8] = b"chinwag-qualified-observation-write-v1\0";
const MIGRATION_OUTCOME: &str = "MIGRATED_OBSERVATIONS_ONLY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRequest {
    workspace: String,
    operation: String,
    expected_v1_sha: [u8; 32],
    observations: ObservationBatch,
    mirrors: LocalJournalMirrorBatch,
    legacy: LegacyAssociationBatch,
    digest: [u8; 32],
}
impl MigrationRequest {
    pub fn try_new(
        workspace: String,
        operation: String,
        expected_v1_sha: [u8; 32],
        observations: ObservationBatch,
        mirrors: LocalJournalMirrorBatch,
    ) -> std::result::Result<Self, QualifiedError> {
        Self::try_new_with_legacy(
            workspace,
            operation,
            expected_v1_sha,
            observations,
            mirrors,
            LegacyAssociationBatch::try_new(vec![])?,
        )
    }
    pub fn try_new_with_legacy(
        workspace: String,
        operation: String,
        expected_v1_sha: [u8; 32],
        observations: ObservationBatch,
        mirrors: LocalJournalMirrorBatch,
        legacy: LegacyAssociationBatch,
    ) -> std::result::Result<Self, QualifiedError> {
        // Uses the existing exact workspace/ID profile without inventing an
        // authority or exposing a caller-supplied SQL key/table name.
        LogicalKey::scheduler_admission(workspace.clone(), operation.clone())?;
        if observations.records().len() + mirrors.records().len() + legacy.associations().len()
            > qualified::MAX_QUALIFIED_BATCH_RECORDS
            || observations.encoded_bytes() + mirrors.encoded_bytes() + legacy.encoded_bytes()
                > qualified::MAX_QUALIFIED_BATCH_BYTES
        {
            return Err(QualifiedError::OversizeHeld);
        }
        if observations
            .records()
            .iter()
            .chain(mirrors.records())
            .any(|record| record.workspace() != workspace)
        {
            return Err(QualifiedError::Mismatch("migration workspace/record"));
        }
        if legacy
            .associations()
            .iter()
            .any(|a| a.workspace() != workspace || a.migration_operation() != operation)
        {
            return Err(QualifiedError::Mismatch(
                "legacy association migration context",
            ));
        }
        let mut encoded = MIGRATION_DOMAIN.to_vec();
        append(&mut encoded, workspace.as_bytes());
        append(&mut encoded, operation.as_bytes());
        encoded.extend_from_slice(&expected_v1_sha);
        encoded.extend_from_slice(&1_u64.to_be_bytes());
        encoded.extend_from_slice(&2_u64.to_be_bytes());
        append_records(&mut encoded, observations.records());
        append_records(&mut encoded, mirrors.records());
        append_legacy(&mut encoded, legacy.associations());
        let digest = qualified::digest(&encoded);
        Ok(Self {
            workspace,
            operation,
            expected_v1_sha,
            observations,
            mirrors,
            legacy,
            digest,
        })
    }
    pub fn workspace(&self) -> &str {
        &self.workspace
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn expected_v1_sha(&self) -> [u8; 32] {
        self.expected_v1_sha
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
fn append(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn append_records(out: &mut Vec<u8>, records: &[QualifiedRecord]) {
    out.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        append(out, &encode_record(record));
    }
}
fn append_legacy(out: &mut Vec<u8>, associations: &[qualified::InferredLegacyAssociation]) {
    out.extend_from_slice(&(associations.len() as u64).to_be_bytes());
    for association in associations {
        append(out, &qualified::encode_legacy_association(association));
    }
}

#[must_use = "Finish the original migration once; drop retains its lock and provides no receipt"]
pub struct QualifiedMigrationSession {
    inner: WriteSession,
}
impl QualifiedMigrationSession {
    pub fn from_v1_owner(owner: WriteOwner) -> Result<Self> {
        WriteSession::from_owner(owner).map(|inner| Self { inner })
    }
    pub fn prepare(
        mut self,
        request: MigrationRequest,
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        let original = self
            .inner
            .owner
            .as_ref()
            .ok_or_else(|| retained("migration_owner_missing", false, false))?;
        if qualified::digest(original.image()) != request.expected_v1_sha {
            return Err(retained(
                "migration_original_preimage_mismatch",
                false,
                false,
            ));
        }
        let native = self
            .inner
            .native
            .take()
            .ok_or_else(|| retained("migration_native_missing", false, false))?;
        let before = legacy_rows(&native);
        let outcome = (|| {
            let before = before?;
            let decision = run_transaction(
                &native,
                |native| {
                    qualified_schema::upgrade_v1(native)?;
                    let records: Vec<_> = request
                        .observations
                        .records()
                        .iter()
                        .chain(request.mirrors.records())
                        .collect();
                    let ingress = ingest(native, &records)?;
                    let legacy_count = ingest_legacy(native, request.legacy.associations())?;
                    native.query(c"INSERT INTO qualified_migrations(id,workspace_id,operation_id,request_sha256,from_version,to_version,outcome) VALUES(?1,?2,?3,?4,?5,?6,?7)",&[
                    Value::Text(migration_key(&request.workspace,&request.operation)),Value::Text(request.workspace.clone()),Value::Text(request.operation.clone()),
                    Value::Blob(request.digest.to_vec()),Value::Integer(1),Value::Integer(2),Value::Text(MIGRATION_OUTCOME.into()),
                ])?;
                    if legacy_rows(native)? != before {
                        return Err(Error::Contract("Migration changed original legacy rows"));
                    }
                    Ok(Decision {
                        dirty: true,
                        response: serde_json::json!({"classification":MIGRATION_OUTCOME,"observations":ingress.response,"authority":"NONE","legacy":"LegacyUnqualified","legacy_associations":legacy_count}),
                        outcome: MIGRATION_OUTCOME,
                        is_error: false,
                    })
                },
                cancelled,
            )?;
            finalize_native(
                &native,
                &decision,
                self.inner.site,
                self.inner.version,
                Some(&self.inner.schema),
            )
            .map(|(version, candidate)| (decision, version, candidate))
        })();
        let (decision, new_version, candidate) = crate::finish(native, outcome)
            .map_err(|_| retained("migration_operation_export_or_close", false, false))?;
        let mut owner = self
            .inner
            .owner
            .take()
            .ok_or_else(|| retained("migration_owner_missing", false, false))?;
        owner.verify_unchanged()?;
        Ok(prepared(
            owner,
            candidate,
            decision,
            self.inner.site,
            self.inner.version,
            new_version,
            request.digest,
            "qualified_v1_to_v2",
        ))
    }
}
impl original_store_owner_seal::Sealed for QualifiedMigrationSession {}
impl OriginalStoreOwner for QualifiedMigrationSession {
    fn verify_bound_source(
        &mut self,
        repository: (u64, u64),
        parent: (u64, u64),
        file: (u64, u64),
        sha256: [u8; 32],
    ) -> Result<()> {
        self.inner
            .verify_bound_source(repository, parent, file, sha256)
    }
}

#[must_use = "Finish this original V2 owner once; no retry or recovery authority is created"]
pub struct QualifiedWriteSession {
    native: Option<Connection>,
    owner: Option<WriteOwner>,
    site: [u8; 16],
    version: i64,
}
impl QualifiedWriteSession {
    pub fn from_v2_owner(mut owner: WriteOwner) -> Result<Self> {
        owner.verify_unchanged()?;
        let (native, _) = qualified_schema::open_v2_image(owner.image())
            .map_err(|_| retained("qualified_v2_import", false, false))?;
        let identity = (|| Ok((crate::site_id(&native)?, db_version(&native)?)))();
        match identity {
            Ok((site, version)) => Ok(Self {
                native: Some(native),
                owner: Some(owner),
                site,
                version,
            }),
            Err(error) => crate::finish(native, Err::<Self, _>(error))
                .map_err(|_| retained("qualified_v2_identity_or_close", false, false)),
        }
    }
    pub fn prepare_observations(
        self,
        batch: ObservationBatch,
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        self.prepare_records(batch.records(), cancelled)
    }
    pub fn prepare_local_journal_mirrors(
        self,
        batch: LocalJournalMirrorBatch,
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        self.prepare_records(batch.records(), cancelled)
    }
    pub fn prepare_legacy_associations(
        mut self,
        batch: LegacyAssociationBatch,
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        let mut encoded = WRITE_DOMAIN.to_vec();
        encoded.extend_from_slice(b"legacy\0");
        append_legacy(&mut encoded, batch.associations());
        let request_digest = qualified::digest(&encoded);
        let native = self
            .native
            .take()
            .ok_or_else(|| retained("qualified_native_missing", false, false))?;
        let outcome = (|| {
            let decision = run_transaction(
                &native,
                |native| {
                    let inserted = ingest_legacy(native, batch.associations())?;
                    Ok(Decision {
                        dirty: inserted > 0,
                        response: serde_json::json!({"classification":"LegacyUnqualified","inserted":inserted,"authority":"NONE"}),
                        outcome: "LEGACY_UNQUALIFIED_ASSOCIATIONS",
                        is_error: false,
                    })
                },
                cancelled,
            )?;
            finalize_native(&native, &decision, self.site, self.version, None)
                .map(|(version, candidate)| (decision, version, candidate))
        })();
        let (decision, new_version, candidate) = crate::finish(native, outcome)
            .map_err(|_| retained("qualified_legacy_export_or_close", false, false))?;
        let mut owner = self
            .owner
            .take()
            .ok_or_else(|| retained("qualified_owner_missing", false, false))?;
        owner.verify_unchanged()?;
        Ok(prepared(
            owner,
            candidate,
            decision,
            self.site,
            self.version,
            new_version,
            request_digest,
            "legacy_inferred_associations",
        ))
    }
    fn prepare_records(
        mut self,
        records: &[QualifiedRecord],
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        let mut encoded = WRITE_DOMAIN.to_vec();
        append_records(&mut encoded, records);
        let request_digest = qualified::digest(&encoded);
        let native = self
            .native
            .take()
            .ok_or_else(|| retained("qualified_native_missing", false, false))?;
        let outcome = (|| {
            let records: Vec<_> = records.iter().collect();
            let decision = run_transaction(&native, |native| ingest(native, &records), cancelled)?;
            finalize_native(&native, &decision, self.site, self.version, None)
                .map(|(version, candidate)| (decision, version, candidate))
        })();
        let (decision, new_version, candidate) = crate::finish(native, outcome)
            .map_err(|_| retained("qualified_write_export_or_close", false, false))?;
        let mut owner = self
            .owner
            .take()
            .ok_or_else(|| retained("qualified_owner_missing", false, false))?;
        owner.verify_unchanged()?;
        Ok(prepared(
            owner,
            candidate,
            decision,
            self.site,
            self.version,
            new_version,
            request_digest,
            "qualified_observation_batch",
        ))
    }
}
impl original_store_owner_seal::Sealed for QualifiedWriteSession {}
impl OriginalStoreOwner for QualifiedWriteSession {
    fn verify_bound_source(
        &mut self,
        repository: (u64, u64),
        parent: (u64, u64),
        file: (u64, u64),
        sha256: [u8; 32],
    ) -> Result<()> {
        self.owner
            .as_mut()
            .ok_or_else(|| retained("qualified_owner_missing", false, false))?
            .verify_bound_source(repository, parent, file, sha256)
    }
}
#[allow(clippy::too_many_arguments)]
fn prepared(
    owner: WriteOwner,
    candidate: Option<Candidate>,
    decision: Decision,
    site: [u8; 16],
    old_version: i64,
    new_version: i64,
    request_digest: [u8; 32],
    kind: &'static str,
) -> PreparedOutcome {
    PreparedOutcome {
        owner,
        candidate,
        pending: Pending {
            site,
            old_version,
            new_version,
            request_digest,
            kind,
            decision,
            native_closed: crate::native_counts_for_private_probe(),
        },
    }
}
fn finalize_native(
    native: &Connection,
    decision: &Decision,
    site: [u8; 16],
    old_version: i64,
    original_v1_schema: Option<&Rows>,
) -> crate::Result<(i64, Option<Candidate>)> {
    let version = db_version(native)?;
    if crate::site_id(native)? != site
        || crate::metadata_site(native)? != site
        || version < old_version
        || (!decision.dirty && version != old_version)
    {
        return Err(Error::Contract(
            "Qualified identity or DB version changed unexpectedly",
        ));
    }
    if !decision.dirty
        && let Some(schema) = original_v1_schema
    {
        if &crate::schema_objects(native)? != schema {
            return Err(Error::Contract("Cancelled migration changed V1 schema"));
        }
    } else {
        qualified_schema::validate_v2(native)?;
    }
    let candidate = if decision.dirty {
        let bytes = native.export_image_for_original_writer()?;
        // Validate the exported image through the exact V2 reader too, closing
        // that independent in-memory owner before file staging is permitted.
        let (probe, _) = qualified_schema::open_v2_image(&bytes)
            .map_err(|_| Error::Contract("Exported V2 image failed admission"))?;
        crate::finish(probe, Ok(()))?;
        Some(Candidate {
            sha256: qualified::digest(&bytes),
            bytes,
        })
    } else {
        None
    };
    Ok((version, candidate))
}

fn legacy_rows(native: &Connection) -> crate::Result<Vec<Rows>> {
    const READS: [&CStr; 8] = [
        c"SELECT * FROM threads ORDER BY id",
        c"SELECT * FROM messages ORDER BY id",
        c"SELECT * FROM context_pins ORDER BY id",
        c"SELECT * FROM agent_claims ORDER BY id",
        c"SELECT * FROM leases ORDER BY id",
        c"SELECT * FROM flight_checkpoints ORDER BY id",
        c"SELECT * FROM tombstones ORDER BY id",
        c"SELECT * FROM verified_invariants ORDER BY id",
    ];
    READS
        .into_iter()
        .map(|sql| native.query(sql, &[]))
        .collect()
}
fn migration_key(workspace: &str, operation: &str) -> String {
    let mut bytes = Vec::new();
    append(&mut bytes, workspace.as_bytes());
    append(&mut bytes, operation.as_bytes());
    qualified::hex(&bytes)
}
fn context(record: &QualifiedRecord) -> Vec<u8> {
    let mut bytes = vec![record.family().code()];
    append(&mut bytes, record.workspace().as_bytes());
    append(&mut bytes, record.observation_id().as_bytes());
    bytes
}
fn same_observation(one: &QualifiedRecord, two: &QualifiedRecord) -> bool {
    one.family() == two.family()
        && one.workspace() == two.workspace()
        && one.observation_id() == two.observation_id()
}
fn original_row(native: &Connection, key: &LogicalKey) -> crate::Result<Option<Vec<Value>>> {
    super::one_row(native.query(c"SELECT record_key,record_sha256,binding_sha256 FROM qualified_originals WHERE id=?1 AND original_key=?2 AND family=?3 AND workspace_id=?4",&[
        Value::Text(qualified::hex(&key.canonical_bytes())),Value::Blob(key.canonical_bytes()),Value::Integer(i64::from(key.family().code())),Value::Text(key.workspace().into()),
    ])?)
}
fn accepted_original(
    native: &Connection,
    key: &LogicalKey,
) -> crate::Result<Option<QualifiedRecord>> {
    let Some(row) = original_row(native, key)? else {
        return Ok(None);
    };
    let [
        Value::Text(record_key),
        Value::Blob(record_digest),
        Value::Blob(binding_digest),
    ] = row.as_slice()
    else {
        return Err(Error::Contract("Original index shape"));
    };
    let record = qualified_read::load_accepted_variant(native, key.family(), record_key)?;
    let original = record
        .original()
        .ok_or(Error::Contract("Original pointer has no immutable binding"))?;
    if original.key() != key
        || record.canonical_digest().as_slice() != record_digest
        || original.binding_digest().as_slice() != binding_digest
    {
        return Err(Error::Contract("Original index/accepted bytes mismatch"));
    }
    Ok(Some(record))
}

fn ingest(native: &Connection, records: &[&QualifiedRecord]) -> crate::Result<Decision> {
    let mut conflicts = vec![false; records.len()];
    let mut replay = vec![false; records.len()];
    for (i, record) in records.iter().enumerate() {
        let table = qualified_schema::family_table(record.family());
        let existing = native.query(
            table.by_identity,
            &[
                Value::Text(record.workspace().into()),
                Value::Text(record.observation_id().into()),
            ],
        )?;
        match existing.as_slice() {
            [] => {}
            [row] => {
                let Some(Value::Text(key)) = row.first() else {
                    return Err(Error::Contract("Existing observation header shape"));
                };
                let accepted = qualified_read::load_accepted_variant(native, record.family(), key)?;
                if encode_record(&accepted) == encode_record(record) {
                    replay[i] = true;
                } else {
                    conflicts[i] = true;
                }
            }
            _ => conflicts[i] = true,
        }
        if let Some(original) = record.original()
            && let Some(accepted) = accepted_original(native, original.key())?
            && accepted.original().map(|o| o.binding()) != Some(original.binding())
        {
            conflicts[i] = true;
        }
        for j in 0..i {
            if same_observation(records[j], record)
                && encode_record(records[j]) != encode_record(record)
            {
                conflicts[i] = true;
                conflicts[j] = true;
            }
            if let (Some(one), Some(two)) = (records[j].original(), record.original())
                && one.key() == two.key()
                && one.binding() != two.binding()
            {
                conflicts[i] = true;
                conflicts[j] = true;
            }
        }
        // A prior retained quarantine permanently prevents a new normal row
        // from selecting a winner, even if its first accepted pointer remains.
        let quarantined=native.query(c"SELECT id FROM qualified_quarantine WHERE identity=?1 OR (?2 IS NOT NULL AND original_key=?2) LIMIT 1",&[
            Value::Blob(context(record)),record.original().map_or(Value::Null,|o|Value::Blob(o.key().canonical_bytes())),
        ])?;
        if !quarantined.is_empty() {
            conflicts[i] = true;
        }
    }
    if conflicts.iter().any(|flag| *flag) {
        let mut dirty = false;
        let mut count = 0;
        for (record, conflict) in records.iter().zip(conflicts) {
            if conflict {
                dirty |= quarantine(native, record)?;
                count += 1;
            }
        }
        return Ok(Decision {
            dirty,
            response: serde_json::json!({"classification":"Quarantined","retained_conflicts":count,"normal_insertions":0,"authority":"NONE"}),
            outcome: "QUALIFIED_QUARANTINED",
            is_error: false,
        });
    }
    let mut inserted = 0;
    for (i, record) in records.iter().enumerate() {
        if replay[i]
            || records[..i]
                .iter()
                .any(|prior| encode_record(prior) == encode_record(record))
        {
            continue;
        }
        insert_record(native, record)?;
        inserted += 1;
    }
    Ok(Decision {
        dirty: inserted > 0,
        response: serde_json::json!({"classification":if inserted==0 {"ExactReplay"}else {"ObservationsStored"},"inserted":inserted,"authority":"NONE"}),
        outcome: if inserted == 0 {
            "QUALIFIED_EXACT_REPLAY"
        } else {
            "QUALIFIED_OBSERVATIONS_STORED"
        },
        is_error: false,
    })
}
fn header_values(record: &QualifiedRecord, header: &RecordHeader, key: &str) -> Vec<Value> {
    vec![
        Value::Text(key.into()),
        Value::Text(header.workspace().into()),
        Value::Text(header.observation_id().into()),
        Value::Blob(header.record_digest().to_vec()),
        Value::Blob(header.total_length().to_be_bytes().to_vec()),
        Value::Integer(i64::from(header.part_count())),
        Value::Blob(record.key().canonical_bytes()),
        Value::Integer(i64::from(header.family().code())),
    ]
}
fn insert_record(native: &Connection, record: &QualifiedRecord) -> crate::Result<()> {
    let (header, parts) = split_record(record);
    let key = record_variant_key(&header);
    let table = qualified_schema::family_table(record.family());
    native.query(table.insert, &header_values(record, &header, &key))?;
    for part in parts {
        native.query(
            if record.family().is_replicated() {
                qualified_schema::INSERT_OBSERVATION_PART
            } else {
                qualified_schema::INSERT_LOCAL_PART
            },
            &[
                Value::Text(chunk_key(&key, part.ordinal())),
                Value::Text(key.clone()),
                Value::Integer(i64::from(part.ordinal())),
                Value::Blob(part.bytes().to_vec()),
            ],
        )?;
    }
    for parameters in qualified_read::stored_reference_rows(&key, record) {
        native.query(qualified_schema::INSERT_REF, &parameters)?;
    }
    if let Some(original) = record.original()
        && original_row(native, original.key())?.is_none()
    {
        native.query(c"INSERT INTO qualified_originals(id,original_key,family,workspace_id,record_key,record_sha256,binding_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7)",&[
            Value::Text(qualified::hex(&original.key().canonical_bytes())),Value::Blob(original.key().canonical_bytes()),Value::Integer(i64::from(record.family().code())),Value::Text(record.workspace().into()),
            Value::Text(key),Value::Blob(record.canonical_digest().to_vec()),Value::Blob(original.binding_digest().to_vec()),
        ])?;
    }
    Ok(())
}
fn quarantine(native: &Connection, record: &QualifiedRecord) -> crate::Result<bool> {
    let (header, parts) = split_record(record);
    let key = record_variant_key(&header);
    let existing=native.query(c"SELECT identity,record_key,record_sha256,family,workspace_id,observation_id,original_key,total_length,part_count,logical_key FROM qualified_quarantine WHERE id=?1",&[Value::Text(key.clone())])?;
    if !existing.is_empty() {
        let expected = vec![
            Value::Blob(context(record)),
            Value::Text(key.clone()),
            Value::Blob(header.record_digest().to_vec()),
            Value::Integer(i64::from(record.family().code())),
            Value::Text(record.workspace().into()),
            Value::Text(record.observation_id().into()),
            record
                .original()
                .map_or(Value::Null, |o| Value::Blob(o.key().canonical_bytes())),
            Value::Blob(header.total_length().to_be_bytes().to_vec()),
            Value::Integer(i64::from(header.part_count())),
            Value::Blob(record.key().canonical_bytes()),
        ];
        if existing != vec![expected] {
            return Err(Error::Contract("Quarantine identity differs"));
        }
        verify_local_parts(native, &key, &parts)?;
        return Ok(false);
    }
    native.query(c"INSERT INTO qualified_quarantine(id,identity,record_key,record_sha256,family,workspace_id,observation_id,original_key,total_length,part_count,logical_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",&[
        Value::Text(key.clone()),Value::Blob(context(record)),Value::Text(key.clone()),Value::Blob(header.record_digest().to_vec()),Value::Integer(i64::from(record.family().code())),Value::Text(record.workspace().into()),Value::Text(record.observation_id().into()),
        record.original().map_or(Value::Null,|o|Value::Blob(o.key().canonical_bytes())),Value::Blob(header.total_length().to_be_bytes().to_vec()),Value::Integer(i64::from(header.part_count())),Value::Blob(record.key().canonical_bytes()),
    ])?;
    // A previously accepted local mirror can be quarantined later. Its exact
    // local parts may already exist; reuse only a complete byte-equal set.
    let existing_parts =
        native.query(qualified_schema::LOCAL_PARTS, &[Value::Text(key.clone())])?;
    if !existing_parts.is_empty() {
        verify_local_parts(native, &key, &parts)?;
        return Ok(true);
    }
    for part in parts {
        native.query(
            qualified_schema::INSERT_LOCAL_PART,
            &[
                Value::Text(chunk_key(&key, part.ordinal())),
                Value::Text(key.clone()),
                Value::Integer(i64::from(part.ordinal())),
                Value::Blob(part.bytes().to_vec()),
            ],
        )?;
    }
    Ok(true)
}
fn verify_local_parts(
    native: &Connection,
    key: &str,
    parts: &[qualified::RecordChunk],
) -> crate::Result<()> {
    let expected: Rows = parts
        .iter()
        .map(|part| {
            vec![
                Value::Integer(i64::from(part.ordinal())),
                Value::Blob(part.bytes().to_vec()),
            ]
        })
        .collect();
    if native.query(qualified_schema::LOCAL_PARTS, &[Value::Text(key.into())])? != expected {
        return Err(Error::Contract(
            "Quarantine chunks differ or are incomplete",
        ));
    }
    Ok(())
}

fn ingest_legacy(
    native: &Connection,
    associations: &[qualified::InferredLegacyAssociation],
) -> crate::Result<usize> {
    // This local, explicitly inferred view cannot alter the raw original row
    // or enter the replicated task message/signature family.
    for association in associations {
        let rows = native.query(
            c"SELECT body FROM messages WHERE id=?1 AND thread_id=?2",
            &[
                Value::Text(association.legacy_message_id().into()),
                Value::Text(association.legacy_thread_id().into()),
            ],
        )?;
        let [row] = rows.as_slice() else {
            return Err(Error::Contract(
                "Legacy association original context missing",
            ));
        };
        let [Value::Text(body)] = row.as_slice() else {
            return Err(Error::Contract("Legacy association body type"));
        };
        if qualified::digest(body.as_bytes()) != association.legacy_body_sha() {
            return Err(Error::Contract("Legacy association original bytes changed"));
        }
    }
    let mut inserted = 0;
    for association in associations {
        let key = qualified::legacy_association_key(association);
        let bytes = qualified::encode_legacy_association(association);
        let values = vec![
            Value::Text(association.workspace().into()),
            Value::Text(association.association_id().into()),
            Value::Blob(association.canonical_digest().to_vec()),
            Value::Text(association.legacy_thread_id().into()),
            Value::Text(association.legacy_message_id().into()),
            Value::Blob(association.legacy_body_sha().to_vec()),
            Value::Text(association.migration_operation().into()),
            Value::Blob(bytes),
            Value::Integer(1),
        ];
        let existing=native.query(c"SELECT workspace_id,association_id,association_sha256,legacy_thread_id,legacy_message_id,legacy_sha256,migration_operation_id,association,inferred_legacy FROM qualified_legacy_associations WHERE id=?1",&[Value::Text(key.clone())])?;
        if !existing.is_empty() {
            if existing != vec![values] {
                return Err(Error::Contract("Legacy association replay differs"));
            }
            continue;
        }
        let mut parameters = vec![Value::Text(key)];
        parameters.extend(values);
        native.query(c"INSERT INTO qualified_legacy_associations(id,workspace_id,association_id,association_sha256,legacy_thread_id,legacy_message_id,legacy_sha256,migration_operation_id,association,inferred_legacy) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",&parameters)?;
        inserted += 1;
    }
    Ok(inserted)
}

#[cfg(test)]
#[path = "qualified_tests.rs"]
mod tests;
