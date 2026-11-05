#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Historical v2 verification without source-qualified task authority.
//!
//! This module does not change the live bus protocol. The caller supplies an
//! authenticated historical signer binding and existing read permissions.
//! Migration associations are separate observations: a v2 sender never signed
//! a source binding, and no verified legacy record can admit a task effect.

use crate::task_ref::{
    Sha256Digest, TaskContractError, TaskKey, TaskRefV1, encode_checked_rev,
    validate_canonical_task_path, validate_id, validate_task_source_id, validate_workspace_id,
};
use crate::task_source::{HeldReason, MAX_ENROLLED_SOURCES, TaskSourceRecord, TaskSourceState};
use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The controlled profile's complete JSON record limit, before parsing.
pub const MAX_LEGACY_RECORD_BYTES: usize = 131_072;

/// The historical `BusMessage` shape. Unknown adjacent fields, including a
/// `task_ref` even when null, are rejected rather than silently discarded.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyBusRecord {
    pub id: String,
    pub seq: u64,
    pub ts_unix: u64,
    pub ts_iso: String,
    pub room: String,
    pub sender: String,
    pub sender_cast: String,
    pub sender_endpoint_id: String,
    pub to: Option<String>,
    pub task_id: Option<String>,
    pub body: String,
    pub digest_sha256: String,
    #[serde(default)]
    pub pubkey_ed25519: Option<String>,
    #[serde(default)]
    pub signature_ed25519: Option<String>,
    #[serde(default)]
    pub sig_verified: bool,
}

impl LegacyBusRecord {
    /// Even unverified historical input has no source-qualified task authority.
    pub const fn qualification(&self) -> LegacyQualification {
        LegacyQualification::LegacyUnqualified
    }
}

/// A caller-validated historical registration, not an enrollment minted here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacySignerBinding {
    pub sender: String,
    pub public_key: EndpointId,
}

/// Signature validity does not upgrade historical task qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyQualification {
    LegacyUnqualified,
}

/// An immutable, locally verified historical record. Transported verification
/// flags and digests remain historical metadata, not verification evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLegacyRecord {
    record: LegacyBusRecord,
    canonical_payload_digest: Sha256Digest,
    qualification: LegacyQualification,
}

impl VerifiedLegacyRecord {
    pub fn record(&self) -> &LegacyBusRecord {
        &self.record
    }

    pub const fn qualification(&self) -> LegacyQualification {
        self.qualification
    }

    pub const fn canonical_payload_digest(&self) -> Sha256Digest {
        self.canonical_payload_digest
    }
}

/// Visible holds at the legacy compatibility and selector boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegacyError {
    FrameTooLarge,
    MalformedLegacyRecord,
    MissingSignature,
    InvalidPublicKey,
    InvalidSignatureEncoding,
    InvalidSignature,
    SignerBindingMismatch,
    /// Retained for public API compatibility; opaque task IDs are preserved.
    PathQualifiedLegacyTaskId,
    HeldUpgradeRequired,
    LegacyUnqualifiedCannotMutateTaskState,
    PermissionDenied,
    MigrationNotAuthorized,
    MigrationBindingMismatch,
    AmbiguousHistoricalId,
    MissingLegacyTaskId,
    InvalidSourceInventory,
    SourceInventoryLimit,
    ExplicitSourceSelectionRequired,
    OwnerConfiguredSingleSourceRequired,
    SourceNotActiveOrAmbiguous,
    TaskContract(TaskContractError),
    SourceHeld(HeldReason),
}

/// Public hold terminology used by callers of the legacy admission boundary.
pub type LegacyHoldReason = LegacyError;

impl fmt::Display for LegacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeldUpgradeRequired | Self::LegacyUnqualifiedCannotMutateTaskState => {
                f.write_str("HELD_UPGRADE_REQUIRED")
            }
            _ => write!(f, "legacy task record held: {self:?}"),
        }
    }
}

impl std::error::Error for LegacyError {}

impl From<TaskContractError> for LegacyError {
    fn from(error: TaskContractError) -> Self {
        Self::TaskContract(error)
    }
}

/// Decode only the existing record shape, preserving exact signed strings.
pub fn decode_legacy_record_json(bytes: &[u8]) -> Result<LegacyBusRecord, LegacyError> {
    if bytes.len() > MAX_LEGACY_RECORD_BYTES {
        return Err(LegacyError::FrameTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| LegacyError::MalformedLegacyRecord)
}

/// Byte-for-byte compatibility with `bus_run::canonical_signing_payload`:
/// seven fields, UTF-8 byte lengths, decimal timestamp, and historical
/// absence-to-empty behavior. No source or path is inserted into this payload.
pub fn canonical_signing_payload(record: &LegacyBusRecord) -> String {
    let to = record.to.as_deref().unwrap_or("");
    let task = record.task_id.as_deref().unwrap_or("");
    let timestamp = record.ts_unix.to_string();
    format!(
        "chinwag-bus-sig-v2|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}|{}:{}",
        record.id.len(),
        record.id,
        timestamp.len(),
        timestamp,
        record.sender.len(),
        record.sender,
        to.len(),
        to,
        record.room.len(),
        record.room,
        task.len(),
        task,
        record.body.len(),
        record.body
    )
}

fn signature_bytes(value: &str) -> Result<[u8; 64], LegacyError> {
    if value.len() != 128 || !value.is_ascii() {
        return Err(LegacyError::InvalidSignatureEncoding);
    }
    let mut bytes = [0; 64];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| LegacyError::InvalidSignatureEncoding)?;
    }
    Ok(bytes)
}

fn check_legacy_field_budget(record: &LegacyBusRecord) -> Result<(), LegacyError> {
    let fields = [
        record.id.as_str(),
        record.ts_iso.as_str(),
        record.room.as_str(),
        record.sender.as_str(),
        record.sender_cast.as_str(),
        record.sender_endpoint_id.as_str(),
        record.to.as_deref().unwrap_or(""),
        record.task_id.as_deref().unwrap_or(""),
        record.body.as_str(),
        record.digest_sha256.as_str(),
        record.pubkey_ed25519.as_deref().unwrap_or(""),
        record.signature_ed25519.as_deref().unwrap_or(""),
    ];
    fields.iter().try_fold(0usize, |total, field| {
        total
            .checked_add(field.len())
            .filter(|total| *total <= MAX_LEGACY_RECORD_BYTES)
            .ok_or(LegacyError::FrameTooLarge)
    })?;
    Ok(())
}

/// Verify the original seven-field Ed25519 signature against the supplied
/// authorized historical sender/key binding. This grants historical identity
/// only; all task-effect admission gates below remain held.
pub fn verify_legacy_record(
    record: &LegacyBusRecord,
    authorized_signer: &LegacySignerBinding,
) -> Result<VerifiedLegacyRecord, LegacyError> {
    check_legacy_field_budget(record)?;
    let public_key = record
        .pubkey_ed25519
        .as_deref()
        .ok_or(LegacyError::MissingSignature)?
        .parse::<EndpointId>()
        .map_err(|_| LegacyError::InvalidPublicKey)?;
    if record.sender != authorized_signer.sender || public_key != authorized_signer.public_key {
        return Err(LegacyError::SignerBindingMismatch);
    }
    let signature = Signature::from_bytes(&signature_bytes(
        record
            .signature_ed25519
            .as_deref()
            .ok_or(LegacyError::MissingSignature)?,
    )?);
    let payload = canonical_signing_payload(record);
    if payload.len() > MAX_LEGACY_RECORD_BYTES {
        return Err(LegacyError::FrameTooLarge);
    }
    public_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| LegacyError::InvalidSignature)?;
    Ok(VerifiedLegacyRecord {
        record: record.clone(),
        canonical_payload_digest: Sha256Digest::of(payload.as_bytes()),
        qualification: LegacyQualification::LegacyUnqualified,
    })
}

/// Existing read permission remains necessary after cryptographic verification.
pub fn admit_legacy_for_historical_read(
    record: &VerifiedLegacyRecord,
    existing_permission: bool,
) -> Result<&LegacyBusRecord, LegacyError> {
    if !existing_permission {
        return Err(LegacyError::PermissionDenied);
    }
    Ok(record.record())
}

/// Ordinary document coordination carries no task-dispatch or mutation grant.
pub fn admit_legacy_for_document_coordination(
    record: &VerifiedLegacyRecord,
    existing_permission: bool,
) -> Result<&LegacyBusRecord, LegacyError> {
    admit_legacy_for_historical_read(record, existing_permission)
}

/// Historical reads and ordinary document coordination share the caller's
/// existing permission gate, without granting any task effect.
pub fn allow_historical_read_or_doc_coordination(
    record: &VerifiedLegacyRecord,
    existing_permission: bool,
) -> Result<&LegacyBusRecord, LegacyHoldReason> {
    admit_legacy_for_historical_read(record, existing_permission)
}

pub fn admit_legacy_for_task_dispatch(_: &VerifiedLegacyRecord) -> Result<(), LegacyError> {
    Err(LegacyError::HeldUpgradeRequired)
}

pub fn admit_legacy_for_task_lease(_: &VerifiedLegacyRecord) -> Result<(), LegacyError> {
    Err(LegacyError::HeldUpgradeRequired)
}

pub fn admit_legacy_for_canonical_status_commit(
    _: &VerifiedLegacyRecord,
) -> Result<(), LegacyError> {
    Err(LegacyError::HeldUpgradeRequired)
}

pub fn admit_legacy_mutation(_: &VerifiedLegacyRecord) -> Result<(), LegacyError> {
    Err(LegacyError::LegacyUnqualifiedCannotMutateTaskState)
}

/// An externally authorized migration's complete immutable source preimage pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyMigrationPin {
    pub workspace_id: String,
    pub repo_id: String,
    pub canonical_task_path: String,
    pub task_source_id: String,
    pub source_generation: u64,
    pub file_cas_rev: u64,
    pub preimage_digest: Sha256Digest,
}

impl LegacyMigrationPin {
    pub fn validate(&self) -> Result<(), LegacyError> {
        validate_workspace_id(&self.workspace_id)?;
        validate_id(&self.repo_id, "repo_id")?;
        validate_canonical_task_path(&self.canonical_task_path)?;
        validate_task_source_id(&self.task_source_id)?;
        encode_checked_rev(self.source_generation)?;
        encode_checked_rev(self.file_cas_rev)?;
        Ok(())
    }
}

/// A separate historical observation, never a replacement for the signed v2
/// record and never accepted by a task admission gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferredLegacyTaskProjection {
    legacy_message_id: String,
    legacy_canonical_payload_digest: Sha256Digest,
    task_ref: TaskRefV1,
    migration_pin: LegacyMigrationPin,
    inferred_legacy: bool,
    sender_signed_source_binding: bool,
}

impl InferredLegacyTaskProjection {
    pub fn legacy_message_id(&self) -> &str {
        &self.legacy_message_id
    }

    pub const fn legacy_canonical_payload_digest(&self) -> Sha256Digest {
        self.legacy_canonical_payload_digest
    }

    pub fn task_ref(&self) -> &TaskRefV1 {
        &self.task_ref
    }

    pub fn migration_pin(&self) -> &LegacyMigrationPin {
        &self.migration_pin
    }

    pub const fn inferred_legacy(&self) -> bool {
        self.inferred_legacy
    }

    pub const fn sender_signed_source_binding(&self) -> bool {
        self.sender_signed_source_binding
    }
}

/// Associate only a unique historical bare-ID match under an authorized exact
/// pin. `historical_candidates` must be the complete authorized historical
/// inventory, not a prefiltered first/newest match. This function performs no
/// search, persistence, source enrollment, or task mutation.
pub fn associate_legacy_with_pinned_source(
    record: &VerifiedLegacyRecord,
    migration_authorized: bool,
    pin: &LegacyMigrationPin,
    pinned_preimage: &[u8],
    historical_candidates: &[TaskRefV1],
) -> Result<InferredLegacyTaskProjection, LegacyError> {
    if !migration_authorized {
        return Err(LegacyError::MigrationNotAuthorized);
    }
    pin.validate()?;
    if Sha256Digest::of(pinned_preimage) != pin.preimage_digest {
        return Err(LegacyError::MigrationBindingMismatch);
    }
    let task_id = record
        .record()
        .task_id
        .as_deref()
        .filter(|task_id| !task_id.is_empty())
        .ok_or(LegacyError::MissingLegacyTaskId)?;
    let mut matches = historical_candidates
        .iter()
        .filter(|candidate| candidate.task_id == task_id);
    let matched = matches.next().ok_or(LegacyError::AmbiguousHistoricalId)?;
    if matches.next().is_some() {
        return Err(LegacyError::AmbiguousHistoricalId);
    }
    matched.validate()?;
    if matched.workspace_id != pin.workspace_id
        || matched.repo_id != pin.repo_id
        || matched.canonical_task_path != pin.canonical_task_path
        || matched.task_source_id != pin.task_source_id
        || matched.source_generation != pin.source_generation
        || matched.file_cas_rev != pin.file_cas_rev
    {
        return Err(LegacyError::MigrationBindingMismatch);
    }
    Ok(InferredLegacyTaskProjection {
        legacy_message_id: record.record().id.clone(),
        legacy_canonical_payload_digest: record.canonical_payload_digest(),
        task_ref: matched.clone(),
        migration_pin: pin.clone(),
        inferred_legacy: true,
        sender_signed_source_binding: false,
    })
}

/// Resolve a new interactive bare ID against the caller's complete source
/// inventory for one workspace/repository. Multiple entries require an explicit
/// source even when only one currently contains the task. The returned key is
/// only a selection: the client must capture and validate a complete TaskRef
/// and authority before signing an actionable envelope.
pub fn resolve_interactive_task_selector(
    enrolled_sources: &[TaskSourceRecord],
    explicit_source_id: Option<&str>,
    owner_configured_single_source_id: Option<&str>,
    bare_task_id: &str,
) -> Result<TaskKey, LegacyError> {
    validate_id(bare_task_id, "task_id")?;
    if enrolled_sources.len() > MAX_ENROLLED_SOURCES {
        return Err(LegacyError::SourceInventoryLimit);
    }
    let first = enrolled_sources
        .first()
        .ok_or(LegacyError::SourceNotActiveOrAmbiguous)?;
    if enrolled_sources
        .iter()
        .any(|source| source.workspace_id != first.workspace_id || source.repo_id != first.repo_id)
    {
        return Err(LegacyError::InvalidSourceInventory);
    }
    let selected_id = match explicit_source_id {
        Some(source_id) => source_id,
        None if enrolled_sources.len() > 1 => {
            return Err(LegacyError::ExplicitSourceSelectionRequired);
        }
        None => owner_configured_single_source_id
            .filter(|source_id| *source_id == first.task_source_id)
            .ok_or(LegacyError::OwnerConfiguredSingleSourceRequired)?,
    };
    validate_task_source_id(selected_id)?;
    let mut matches = enrolled_sources.iter().filter(|source| {
        source.task_source_id == selected_id && source.state == TaskSourceState::Enrolled
    });
    let selected = matches
        .next()
        .ok_or(LegacyError::SourceNotActiveOrAmbiguous)?;
    if matches.next().is_some() {
        return Err(LegacyError::SourceNotActiveOrAmbiguous);
    }
    selected
        .state
        .check_new_admission()
        .map_err(LegacyError::SourceHeld)?;
    validate_id(&selected.repo_id, "repo_id")?;
    validate_canonical_task_path(&selected.canonical_relative_path)?;
    encode_checked_rev(selected.source_generation)?;
    Ok(TaskKey::new(
        &selected.workspace_id,
        &selected.task_source_id,
        bare_task_id,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_ref::GitOid;
    use crate::task_source::{SourceDispatchControls, SourceExecutionMode};
    use iroh::SecretKey;
    use std::fmt::Write as _;

    const SOURCE_ID: &str = "00000000000000000000000000000001";
    const OTHER_SOURCE_ID: &str = "00000000000000000000000000000002";
    const PREIMAGE: &[u8] = b"# Tasks\n\nP0-FIXTURE-1\n";

    fn secret() -> SecretKey {
        static KEY: std::sync::OnceLock<SecretKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| SecretKey::from_bytes(&rand::random::<[u8; 32]>()))
            .clone()
    }

    fn alternate_secret() -> SecretKey {
        static KEY: std::sync::OnceLock<SecretKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            loop {
                let candidate = SecretKey::from_bytes(&rand::random::<[u8; 32]>());
                if candidate.public() != secret().public() {
                    return candidate;
                }
            }
        })
        .clone()
    }

    fn unsigned_record() -> LegacyBusRecord {
        LegacyBusRecord {
            id: "legacy-1".to_owned(),
            seq: 1,
            ts_unix: 7,
            ts_iso: "untrusted display time".to_owned(),
            room: "fixture".to_owned(),
            sender: "RUST@fixture".to_owned(),
            sender_cast: "untrusted display cast".to_owned(),
            sender_endpoint_id: "untrusted transport endpoint".to_owned(),
            to: None,
            task_id: Some("P0-FIXTURE-1".to_owned()),
            body: "historical evidence".to_owned(),
            digest_sha256: "untrusted transported digest".to_owned(),
            pubkey_ed25519: None,
            signature_ed25519: None,
            sig_verified: true,
        }
    }

    fn signed_record() -> (LegacyBusRecord, LegacySignerBinding) {
        sign_record(unsigned_record())
    }

    fn sign_record(mut record: LegacyBusRecord) -> (LegacyBusRecord, LegacySignerBinding) {
        let secret = secret();
        let signature = secret.sign(canonical_signing_payload(&record).as_bytes());
        let mut signature_hex = String::with_capacity(128);
        for byte in signature.to_bytes() {
            write!(&mut signature_hex, "{byte:02x}").expect("writing a String cannot fail");
        }
        record.pubkey_ed25519 = Some(secret.public().to_string());
        record.signature_ed25519 = Some(signature_hex);
        let signer = LegacySignerBinding {
            sender: record.sender.clone(),
            public_key: secret.public(),
        };
        (record, signer)
    }

    fn verified_record() -> VerifiedLegacyRecord {
        let (record, signer) = signed_record();
        verify_legacy_record(&record, &signer).expect("fixture signature verifies")
    }

    fn task_ref() -> TaskRefV1 {
        TaskRefV1 {
            workspace_id: "p0-fixture-workspace".to_owned(),
            repo_id: "p0-fixture-repo".to_owned(),
            task_source_id: SOURCE_ID.to_owned(),
            source_generation: 1,
            canonical_task_path: "TASKS.md".to_owned(),
            task_id: "P0-FIXTURE-1".to_owned(),
            task_spec_digest: Sha256Digest([0; 32]),
            task_status_rev: 0,
            file_cas_rev: 0,
            baseline_commit: GitOid::Sha1([0x11; 20]),
        }
    }

    fn migration_pin() -> LegacyMigrationPin {
        LegacyMigrationPin {
            workspace_id: "p0-fixture-workspace".to_owned(),
            repo_id: "p0-fixture-repo".to_owned(),
            canonical_task_path: "TASKS.md".to_owned(),
            task_source_id: SOURCE_ID.to_owned(),
            source_generation: 1,
            file_cas_rev: 0,
            preimage_digest: Sha256Digest::of(PREIMAGE),
        }
    }

    fn source(source_id: &str) -> TaskSourceRecord {
        TaskSourceRecord {
            workspace_id: "p0-fixture-workspace".to_owned(),
            repo_id: "p0-fixture-repo".to_owned(),
            source_worktree_id: "fixture-worktree".to_owned(),
            task_source_id: source_id.to_owned(),
            display_name: "Fixture".to_owned(),
            canonical_relative_path: "TASKS.md".to_owned(),
            source_generation: 1,
            normalization_version: 1,
            schema_version: 1,
            writer_principal: "fixture-writer".to_owned(),
            writer_epoch: 1,
            config_digest: [0; 32],
            state: TaskSourceState::Enrolled,
            controls: SourceDispatchControls {
                mode: SourceExecutionMode::ReviewOnly,
                implementation_authorized: false,
                deployment_authorized: false,
                automatic_dispatch: false,
                allowed_actions: vec!["document-review".to_owned()],
            },
        }
    }

    #[test]
    fn p0_wire_legacy_seven_field_utf8_golden_payload() {
        let mut record = unsigned_record();
        record.id = "é".to_owned();
        record.sender = "a".to_owned();
        record.to = Some("b|c".to_owned());
        record.room = "r".to_owned();
        record.task_id = Some("T-1".to_owned());
        record.body = "e\u{301}:|".to_owned();
        assert_eq!(
            canonical_signing_payload(&record),
            "chinwag-bus-sig-v2|2:é|1:7|1:a|3:b|c|1:r|3:T-1|5:e\u{301}:|"
        );
    }

    #[test]
    fn p0_wire_legacy_absence_to_empty_is_preserved() {
        let mut absent = unsigned_record();
        absent.to = None;
        absent.task_id = None;
        let mut empty = absent.clone();
        empty.to = Some(String::new());
        empty.task_id = Some(String::new());
        assert_eq!(
            canonical_signing_payload(&absent),
            canonical_signing_payload(&empty)
        );
    }

    #[test]
    fn p0_wire_legacy_verification_remains_unqualified_and_ignores_metadata() {
        let (mut record, signer) = signed_record();
        record.seq = u64::MAX;
        record.ts_iso = "different display".to_owned();
        record.sender_cast = "forged role".to_owned();
        record.sender_endpoint_id = "forged endpoint".to_owned();
        record.digest_sha256 = "forged digest".to_owned();
        record.sig_verified = false;
        let verified = verify_legacy_record(&record, &signer).expect("signed fields unchanged");
        assert_eq!(
            verified.qualification(),
            LegacyQualification::LegacyUnqualified
        );
        assert_eq!(
            verified.canonical_payload_digest(),
            Sha256Digest::of(canonical_signing_payload(&record).as_bytes())
        );
        assert_eq!(verified.record(), &record);
    }

    #[test]
    fn p0_wire_legacy_every_signed_field_tamper_is_rejected() {
        let (record, signer) = signed_record();
        for field in 0..7 {
            let mut tampered = record.clone();
            match field {
                0 => tampered.id.push('x'),
                1 => tampered.ts_unix += 1,
                2 => tampered.sender.push('x'),
                3 => tampered.to = Some("other-recipient".to_owned()),
                4 => tampered.room.push('x'),
                5 => tampered.task_id = Some("other-task".to_owned()),
                _ => tampered.body.push('x'),
            }
            assert!(
                verify_legacy_record(&tampered, &signer).is_err(),
                "field {field}"
            );
        }
    }

    #[test]
    fn p0_wire_legacy_flags_key_or_signature_cannot_replace_verification() {
        let (mut record, mut signer) = signed_record();
        assert_eq!(
            record.qualification(),
            LegacyQualification::LegacyUnqualified
        );
        let signature = record.signature_ed25519.take();
        record.sig_verified = true;
        assert_eq!(
            verify_legacy_record(&record, &signer),
            Err(LegacyError::MissingSignature)
        );
        record.signature_ed25519 = Some("zz".repeat(64));
        assert_eq!(
            verify_legacy_record(&record, &signer),
            Err(LegacyError::InvalidSignatureEncoding)
        );
        record.signature_ed25519 = signature;
        signer.public_key = alternate_secret().public();
        assert_eq!(
            verify_legacy_record(&record, &signer),
            Err(LegacyError::SignerBindingMismatch)
        );
        record.sender_cast = "x".repeat(MAX_LEGACY_RECORD_BYTES);
        assert_eq!(
            verify_legacy_record(&record, &signer),
            Err(LegacyError::FrameTooLarge)
        );
    }

    #[test]
    fn p0_wire_legacy_original_slash_and_backslash_task_ids_verify_and_hold_effects() {
        for task_id in ["TASKS.md/T-1", "T-1\\substep"] {
            let mut original = unsigned_record();
            original.task_id = Some(task_id.to_owned());
            let (record, signer) = sign_record(original);
            let verified = verify_legacy_record(&record, &signer)
                .expect("original opaque task ID was signed verbatim");
            assert_eq!(verified.record().task_id.as_deref(), Some(task_id));
            assert_eq!(
                verified.qualification(),
                LegacyQualification::LegacyUnqualified
            );
            assert_eq!(
                admit_legacy_for_historical_read(&verified, true),
                Ok(&record)
            );
            assert_eq!(
                admit_legacy_for_document_coordination(&verified, true),
                Ok(&record)
            );
            assert_eq!(
                admit_legacy_for_historical_read(&verified, false),
                Err(LegacyError::PermissionDenied)
            );
            assert_eq!(
                admit_legacy_for_document_coordination(&verified, false),
                Err(LegacyError::PermissionDenied)
            );
            for outcome in [
                admit_legacy_for_task_dispatch(&verified),
                admit_legacy_for_task_lease(&verified),
                admit_legacy_for_canonical_status_commit(&verified),
            ] {
                assert_eq!(outcome, Err(LegacyError::HeldUpgradeRequired));
            }
            assert_eq!(
                admit_legacy_mutation(&verified),
                Err(LegacyError::LegacyUnqualifiedCannotMutateTaskState)
            );
        }
    }

    #[test]
    fn p0_wire_legacy_adding_path_prefix_after_signing_fails_invalid_signature() {
        let mut original = unsigned_record();
        original.task_id = Some("T-1".to_owned());
        let (mut record, signer) = sign_record(original);
        record.task_id = Some("TASKS.md/T-1".to_owned());
        assert_eq!(
            verify_legacy_record(&record, &signer),
            Err(LegacyError::InvalidSignature)
        );
    }

    #[test]
    fn p0_wire_legacy_rejects_adjacent_task_ref_json_and_duplicate_keys() {
        let mut json = serde_json::to_value(unsigned_record()).expect("fixture JSON");
        for adjacent in [
            serde_json::Value::Null,
            serde_json::json!({"source": SOURCE_ID}),
        ] {
            json["task_ref"] = adjacent;
            let bytes = serde_json::to_vec(&json).expect("fixture JSON bytes");
            assert_eq!(
                decode_legacy_record_json(&bytes),
                Err(LegacyError::MalformedLegacyRecord)
            );
        }
        let json = serde_json::to_string(&unsigned_record()).expect("fixture JSON");
        let duplicate = format!("{{\"id\":\"duplicate\",{}", &json[1..]);
        assert_eq!(
            decode_legacy_record_json(duplicate.as_bytes()),
            Err(LegacyError::MalformedLegacyRecord)
        );
        assert_eq!(
            decode_legacy_record_json(&vec![b' '; MAX_LEGACY_RECORD_BYTES + 1]),
            Err(LegacyError::FrameTooLarge)
        );
    }

    #[test]
    fn p0_wire_legacy_all_task_effects_hold_upgrade_required() {
        let verified = verified_record();
        for outcome in [
            admit_legacy_for_task_dispatch(&verified),
            admit_legacy_for_task_lease(&verified),
            admit_legacy_for_canonical_status_commit(&verified),
            admit_legacy_mutation(&verified),
        ] {
            assert_eq!(
                outcome.expect_err("legacy task effect held").to_string(),
                "HELD_UPGRADE_REQUIRED"
            );
        }
    }

    #[test]
    fn p0_wire_legacy_historical_and_document_reads_need_existing_permission() {
        let verified = verified_record();
        assert_eq!(
            admit_legacy_for_historical_read(&verified, true),
            Ok(verified.record())
        );
        assert_eq!(
            admit_legacy_for_document_coordination(&verified, true),
            Ok(verified.record())
        );
        assert_eq!(
            admit_legacy_for_historical_read(&verified, false),
            Err(LegacyError::PermissionDenied)
        );
        assert_eq!(
            admit_legacy_for_document_coordination(&verified, false),
            Err(LegacyError::PermissionDenied)
        );
        assert_eq!(
            allow_historical_read_or_doc_coordination(&verified, true),
            Ok(verified.record())
        );
        assert_eq!(
            allow_historical_read_or_doc_coordination(&verified, false),
            Err(LegacyError::PermissionDenied)
        );
    }

    #[test]
    fn p0_wire_legacy_migration_binds_every_source_and_preimage_pin() {
        let verified = verified_record();
        let pin = migration_pin();
        let candidate = task_ref();
        let projection = associate_legacy_with_pinned_source(
            &verified,
            true,
            &pin,
            PREIMAGE,
            std::slice::from_ref(&candidate),
        )
        .expect("unique exact migration pin");
        assert!(projection.inferred_legacy());
        assert!(!projection.sender_signed_source_binding());
        assert_eq!(projection.task_ref(), &candidate);
        assert_eq!(projection.migration_pin(), &pin);
        assert_eq!(projection.legacy_message_id(), verified.record().id);
        assert_eq!(
            projection.legacy_canonical_payload_digest(),
            verified.canonical_payload_digest()
        );
        assert_eq!(
            verified.qualification(),
            LegacyQualification::LegacyUnqualified
        );
        for field in 0..7 {
            let mut changed = pin.clone();
            match field {
                0 => changed.workspace_id.push('x'),
                1 => changed.repo_id.push('x'),
                2 => changed.canonical_task_path = "tasks.md".to_owned(),
                3 => changed.task_source_id = OTHER_SOURCE_ID.to_owned(),
                4 => changed.source_generation += 1,
                5 => changed.file_cas_rev += 1,
                _ => changed.preimage_digest = Sha256Digest([0x22; 32]),
            }
            assert_eq!(
                associate_legacy_with_pinned_source(
                    &verified,
                    true,
                    &changed,
                    PREIMAGE,
                    std::slice::from_ref(&candidate),
                ),
                Err(LegacyError::MigrationBindingMismatch),
                "pin field {field}"
            );
        }
        assert_eq!(
            associate_legacy_with_pinned_source(&verified, true, &pin, b"changed", &[candidate],),
            Err(LegacyError::MigrationBindingMismatch)
        );
    }

    #[test]
    fn p0_wire_legacy_migration_never_guesses_missing_or_ambiguous_history() {
        let verified = verified_record();
        let pin = migration_pin();
        assert_eq!(
            associate_legacy_with_pinned_source(&verified, false, &pin, PREIMAGE, &[task_ref()]),
            Err(LegacyError::MigrationNotAuthorized)
        );
        assert_eq!(
            associate_legacy_with_pinned_source(&verified, true, &pin, PREIMAGE, &[]),
            Err(LegacyError::AmbiguousHistoricalId)
        );
        let mut other_source = task_ref();
        other_source.task_source_id = OTHER_SOURCE_ID.to_owned();
        assert_eq!(
            associate_legacy_with_pinned_source(
                &verified,
                true,
                &pin,
                PREIMAGE,
                &[task_ref(), other_source],
            ),
            Err(LegacyError::AmbiguousHistoricalId)
        );
    }

    #[test]
    fn p0_wire_interactive_selector_with_explicit_source_accepts_opaque_slash_task_id() {
        let sources = [source(SOURCE_ID), source(OTHER_SOURCE_ID)];
        let selected =
            resolve_interactive_task_selector(&sources, Some(SOURCE_ID), None, "T-1/substep")
                .expect("explicit source accepts an opaque task ID");
        assert_eq!(selected.workspace_id, "p0-fixture-workspace");
        assert_eq!(selected.task_source_id, SOURCE_ID);
        assert_eq!(selected.task_id, "T-1/substep");
        assert_eq!(
            resolve_interactive_task_selector(&sources, None, None, "T-1/substep"),
            Err(LegacyError::ExplicitSourceSelectionRequired)
        );
    }

    #[test]
    fn p0_wire_legacy_multi_source_always_needs_explicit_unique_active_selector() {
        let sources = [source(SOURCE_ID), source(OTHER_SOURCE_ID)];
        assert_eq!(
            resolve_interactive_task_selector(&sources, None, Some(SOURCE_ID), "unique-now"),
            Err(LegacyError::ExplicitSourceSelectionRequired)
        );
        let selected = resolve_interactive_task_selector(
            &sources,
            Some(OTHER_SOURCE_ID),
            None,
            "P0-FIXTURE-1",
        )
        .expect("explicit source");
        assert_eq!(selected.task_source_id, OTHER_SOURCE_ID);
        assert_eq!(selected.workspace_id, "p0-fixture-workspace");
        assert_eq!(
            resolve_interactive_task_selector(&sources[..1], Some(OTHER_SOURCE_ID), None, "T-1"),
            Err(LegacyError::SourceNotActiveOrAmbiguous)
        );
        assert_eq!(
            resolve_interactive_task_selector(
                &[source(SOURCE_ID), source(SOURCE_ID)],
                Some(SOURCE_ID),
                None,
                "T-1",
            ),
            Err(LegacyError::SourceNotActiveOrAmbiguous)
        );
    }

    #[test]
    fn p0_wire_legacy_single_source_requires_owner_configuration_and_active_state() {
        let mut sources = [source(SOURCE_ID)];
        assert_eq!(
            resolve_interactive_task_selector(&sources, None, None, "T-1"),
            Err(LegacyError::OwnerConfiguredSingleSourceRequired)
        );
        assert_eq!(
            resolve_interactive_task_selector(&sources, None, Some(OTHER_SOURCE_ID), "T-1"),
            Err(LegacyError::OwnerConfiguredSingleSourceRequired)
        );
        assert!(resolve_interactive_task_selector(&sources, None, Some(SOURCE_ID), "T-1").is_ok());
        for state in [
            TaskSourceState::Proposed,
            TaskSourceState::Suspended,
            TaskSourceState::Retired,
        ] {
            sources[0].state = state;
            assert_eq!(
                resolve_interactive_task_selector(&sources, Some(SOURCE_ID), None, "T-1"),
                Err(LegacyError::SourceNotActiveOrAmbiguous)
            );
        }
        sources[0].state = TaskSourceState::Enrolled;
        let selected =
            resolve_interactive_task_selector(&sources, Some(SOURCE_ID), None, "TASKS.md/T-1")
                .expect("explicit source preserves the opaque task ID");
        assert_eq!(selected.task_id, "TASKS.md/T-1");
        assert_eq!(
            resolve_interactive_task_selector(&sources, None, Some(SOURCE_ID), "T-1\\substep")
                .expect("owner-configured source preserves the opaque task ID")
                .task_id,
            "T-1\\substep"
        );
    }
}
