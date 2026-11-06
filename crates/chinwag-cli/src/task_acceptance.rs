#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Bounded, independently signed review proposals for the P0-06 source profile.
//!
//! Current policy keys, source snapshots and verified host time are trusted inputs
//! from the writer's authority provider. This module does not obtain grants,
//! approve K2 custody, persist consumption, or commit task bytes. Its sealed
//! result must be joined to the existing fenced writer and durable journal.
//! These explicitly versioned proposal schemas do not reinterpret historical
//! K1/K2 ReviewAttestation records as signing additional fields.

use crate::task_dependency::{
    DependencySourceBinding, ResolvedDependency, validate_dependency_satisfaction,
};
use crate::task_ref::{
    GitOid, Sha256Digest, TaskContractError, TaskRefV1, checked_next_revision,
    encode_bytes_field, encode_str_field, encode_u64, validate_id,
};
use crate::task_review_state::{
    MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES, MAX_DISPLAY_TEXT_UTF8_BYTES,
    MAX_EVIDENCE_DIGESTS_PER_CANDIDATE, MAX_FINDINGS_PER_ATTESTATION,
    MAX_REQUIRED_CHECKS_PER_ATTESTATION, MAX_VERIFICATION_CHECKS_PASSED,
    ReplayDisposition, ReplayEntryV1, ReviewReplayLedger, ReviewStateError,
    ReviewerRolePolicy, TaskReviewLifecycleState, TaskReviewStateRecord,
    verify_candidate_and_attestation_freshness, verify_separation_of_duties,
};
use crate::task_wire::HostClockState;
use crate::task_writer::{
    ReviewedAcceptanceProofV1, TaskEntrySnapshotV1, TransitionAuthorityV1,
    TransitionAuthorization,
};
use iroh::{EndpointId, Signature};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const TASK_CANDIDATE_SCHEMA_V1: &str = "chinwag.task.candidate.v1";
pub const REVIEW_ATTESTATION_SCHEMA_V1: &str = "chinwag.review.attestation.v1";
pub const TASK_ACCEPTANCE_SCHEMA_V1: &str = "chinwag.task.acceptance.v1";
pub const TASK_CANDIDATE_DOMAIN_V1: &[u8] = b"chinwag-task-candidate-v1\0";
pub const REVIEW_ATTESTATION_DOMAIN_V1: &[u8] = b"chinwag-review-attestation-v1\0";
pub const TASK_ACCEPTANCE_DOMAIN_V1: &[u8] = b"chinwag-task-acceptance-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptanceError {
    ProseCompletionForbidden,
    PayloadTooLarge,
    StructuralLimitExceeded,
    DuplicateJsonKey,
    InvalidJson,
    SchemaVersionMismatch,
    SignatureInvalid,
    SignerBindingMismatch,
    ReviewVerdictNotPass,
    ContradictoryPassAttestation,
    ClockFenceHeld,
    CandidateBindingMismatch,
    AttestationBindingMismatch,
    DependencyUnsatisfied,
    PolicyCommitmentMismatch,
    InvalidPolicy,
    ReviewState(ReviewStateError),
    Contract(TaskContractError),
}

impl fmt::Display for AcceptanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task acceptance refused: {self:?}")
    }
}
impl std::error::Error for AcceptanceError {}
impl From<TaskContractError> for AcceptanceError {
    fn from(error: TaskContractError) -> Self { Self::Contract(error) }
}
impl From<ReviewStateError> for AcceptanceError {
    fn from(error: ReviewStateError) -> Self { Self::ReviewState(error) }
}

mod digest_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &Sha256Digest, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Sha256Digest, D::Error> {
        Sha256Digest::from_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
mod oid_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &GitOid, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<GitOid, D::Error> {
        GitOid::from_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
mod optional_digest_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &Option<Sha256Digest>, s: S) -> Result<S::Ok, S::Error> {
        value.map(|digest| digest.to_string()).serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Sha256Digest>, D::Error> {
        Option::<String>::deserialize(d)?.map(|value| Sha256Digest::from_hex(&value))
            .transpose().map_err(serde::de::Error::custom)
    }
}
mod digest_list_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(values: &[Sha256Digest], s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = s.serialize_seq(Some(values.len()))?;
        for value in values { sequence.serialize_element(&value.to_string())?; }
        sequence.end()
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Sha256Digest>, D::Error> {
        struct Digests;
        impl<'de> Visitor<'de> for Digests {
            type Value = Vec<Sha256Digest>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("at most 64 digests") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<String>()? {
                    if values.len() == MAX_EVIDENCE_DIGESTS_PER_CANDIDATE {
                        return Err(serde::de::Error::custom("evidence digest limit"));
                    }
                    values.push(Sha256Digest::from_hex(&value).map_err(serde::de::Error::custom)?);
                }
                Ok(values)
            }
        }
        d.deserialize_seq(Digests)
    }
}
mod key_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        digest_json::serialize(&Sha256Digest(*value), s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        digest_json::deserialize(d).map(|digest| digest.0)
    }
}
mod signature_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let mut first = [0; 32];
        let mut second = [0; 32];
        first.copy_from_slice(&value[..32]);
        second.copy_from_slice(&value[32..]);
        s.serialize_str(&format!("{}{}", Sha256Digest(first), Sha256Digest(second)))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let value = String::deserialize(d)?;
        if value.len() != 128 || !value.is_ascii() {
            return Err(serde::de::Error::custom("invalid signature length"));
        }
        let mut raw = [0; 64];
        raw[..32].copy_from_slice(&Sha256Digest::from_hex(&value[..64]).map_err(serde::de::Error::custom)?.0);
        raw[32..].copy_from_slice(&Sha256Digest::from_hex(&value[64..]).map_err(serde::de::Error::custom)?.0);
        Ok(raw)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "TaskRefV1", deny_unknown_fields)]
struct TaskRefJson {
    workspace_id: String,
    repo_id: String,
    task_source_id: String,
    source_generation: u64,
    canonical_task_path: String,
    task_id: String,
    #[serde(with = "digest_json")]
    task_spec_digest: Sha256Digest,
    task_status_rev: u64,
    file_cas_rev: u64,
    #[serde(with = "oid_json")]
    baseline_commit: GitOid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCandidateV1 {
    pub schema_version: String,
    pub operation_id: String,
    pub message_id: String,
    #[serde(with = "TaskRefJson")]
    pub task_ref: TaskRefV1,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub completion_policy_digest: Sha256Digest,
    pub implementer_actor: String,
    pub reviewer_role: String,
    #[serde(with = "oid_json")]
    pub baseline_commit: GitOid,
    #[serde(with = "oid_json")]
    pub candidate_commit: GitOid,
    #[serde(with = "optional_digest_json")]
    pub overlay_digest: Option<Sha256Digest>,
    pub execution_flags: Vec<String>,
    #[serde(with = "digest_list_json")]
    pub evidence_digests: Vec<Sha256Digest>,
    pub verification_checks_passed: Vec<String>,
    pub submitted_at_unix: u64,
    pub display_text: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict { Pass, RequestChanges, Reject }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity { Blocker, Major, Minor, Info }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCheckResultV1 {
    pub check_id: String,
    pub passed: bool,
    #[serde(with = "digest_json")]
    pub artifact_digest: Sha256Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewFindingV1 {
    pub finding_id: String,
    pub severity: FindingSeverity,
    pub blocking: bool,
    pub summary: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAttestationV1 {
    pub schema_version: String,
    pub attestation_id: String,
    pub operation_id: String,
    pub message_id: String,
    pub candidate_operation_id: String,
    #[serde(with = "digest_json")]
    pub candidate_digest: Sha256Digest,
    #[serde(with = "TaskRefJson")]
    pub reviewed_task_ref: TaskRefV1,
    #[serde(with = "digest_json")]
    pub reviewed_task_control_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub completion_policy_digest: Sha256Digest,
    pub implementer_actor: String,
    pub reviewer_actor: String,
    pub reviewer_role: String,
    #[serde(with = "oid_json")]
    pub baseline_commit: GitOid,
    #[serde(with = "oid_json")]
    pub candidate_commit: GitOid,
    #[serde(with = "optional_digest_json")]
    pub overlay_digest: Option<Sha256Digest>,
    pub execution_flags: Vec<String>,
    #[serde(with = "digest_list_json")]
    pub evidence_digests: Vec<Sha256Digest>,
    pub required_checks: Vec<RequiredCheckResultV1>,
    pub verdict: ReviewVerdict,
    pub findings: Vec<ReviewFindingV1>,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub display_text: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAcceptanceV1 {
    pub schema_version: String,
    pub operation_id: String,
    pub message_id: String,
    pub candidate_operation_id: String,
    #[serde(with = "digest_json")]
    pub candidate_digest: Sha256Digest,
    pub attestation_id: String,
    #[serde(with = "digest_json")]
    pub attestation_digest: Sha256Digest,
    #[serde(with = "TaskRefJson")]
    pub task_ref: TaskRefV1,
    pub accepted_from_task_status_rev: u64,
    pub committed_task_status_rev: u64,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub completion_policy_digest: Sha256Digest,
    pub implementer_actor: String,
    pub reviewer_actor: String,
    pub reviewer_role: String,
    pub writer_actor: String,
    pub writer_epoch: u64,
    #[serde(with = "oid_json")]
    pub baseline_commit: GitOid,
    #[serde(with = "oid_json")]
    pub candidate_commit: GitOid,
    #[serde(with = "optional_digest_json")]
    pub overlay_digest: Option<Sha256Digest>,
    pub execution_flags: Vec<String>,
    #[serde(with = "digest_list_json")]
    pub evidence_digests: Vec<Sha256Digest>,
    pub verification_checks_passed: Vec<String>,
    pub accepted_at_unix: u64,
    pub display_text: Option<String>,
}

/// Keys/role grants and epoch must come from current authenticated authority.
/// The canonical policy digest commits to every field, including these keys.
#[derive(Clone, Debug)]
pub struct CompletionPolicyV1 {
    pub required_checks: Vec<String>,
    pub forbidden_execution_flags: Vec<String>,
    pub reviewer_role_policy: ReviewerRolePolicy,
    pub implementer_public_key: [u8; 32],
    pub reviewer_public_key: [u8; 32],
    pub writer_public_key: [u8; 32],
    pub writer_epoch: u64,
}

/// This adapter uses the accepted P0-05 dependency API, whose names differ from
/// the proposed `evaluate_dependencies` seam. Source enrollment remains a writer
/// responsibility, just as for `DependencySnapshotV1`.
#[derive(Clone, Debug)]
pub struct DependencyTargetSnapshot {
    pub resolved: ResolvedDependency,
    pub current_source: DependencySourceBinding,
}

struct Transcript(Vec<u8>);
impl Transcript {
    fn new(domain: &[u8]) -> Self { Self(domain.to_vec()) }
    fn string(&mut self, value: &str) { self.0.extend(encode_str_field(value)); }
    fn number(&mut self, value: u64) { self.0.extend(encode_u64(value)); }
    fn digest(&mut self, value: Sha256Digest) { self.0.extend(value.encode_typed()); }
    fn oid(&mut self, value: GitOid) { self.0.extend(value.encode_typed()); }
    fn overlay(&mut self, value: Option<Sha256Digest>) {
        self.0.push(u8::from(value.is_some()));
        if let Some(value) = value { self.digest(value); }
    }
    fn strings(&mut self, values: &[String]) {
        self.number(values.len() as u64);
        for value in values { self.string(value); }
    }
    fn digests(&mut self, values: &[Sha256Digest]) {
        self.number(values.len() as u64);
        for value in values { self.digest(*value); }
    }
    fn task_ref(&mut self, value: &TaskRefV1) {
        // Same typed field order as TaskRefV1::encode; validation precedes use
        // for authorization. Keeping this total permits a total digest method.
        let mut task = Self::new(crate::task_ref::TASK_REF_V1_DOMAIN);
        task.string(&value.workspace_id);
        task.string(&value.repo_id);
        task.string(&value.task_source_id);
        task.number(value.source_generation);
        task.string(&value.canonical_task_path);
        task.string(&value.task_id);
        task.digest(value.task_spec_digest);
        task.number(value.task_status_rev);
        task.number(value.file_cas_rev);
        task.oid(value.baseline_commit);
        self.0.extend(encode_bytes_field(&task.0));
    }
}

pub trait CanonicalReviewProposalV1 {
    fn canonical_bytes(&self) -> Vec<u8>;
    fn canonical_digest(&self) -> Sha256Digest { Sha256Digest::of(&self.canonical_bytes()) }
}
impl CanonicalReviewProposalV1 for TaskCandidateV1 {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut t = Transcript::new(TASK_CANDIDATE_DOMAIN_V1);
        t.string(&self.schema_version); t.string(&self.operation_id); t.string(&self.message_id);
        t.task_ref(&self.task_ref); t.digest(self.task_control_digest); t.digest(self.completion_policy_digest);
        t.string(&self.implementer_actor); t.string(&self.reviewer_role);
        t.oid(self.baseline_commit); t.oid(self.candidate_commit); t.overlay(self.overlay_digest);
        t.strings(&self.execution_flags); t.digests(&self.evidence_digests);
        t.strings(&self.verification_checks_passed); t.number(self.submitted_at_unix);
        t.0
    }
}
impl TaskCandidateV1 {
    pub fn canonical_digest(&self) -> Sha256Digest { CanonicalReviewProposalV1::canonical_digest(self) }
}
impl CanonicalReviewProposalV1 for ReviewAttestationV1 {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut t = Transcript::new(REVIEW_ATTESTATION_DOMAIN_V1);
        t.string(&self.schema_version); t.string(&self.attestation_id);
        t.string(&self.operation_id); t.string(&self.message_id); t.string(&self.candidate_operation_id);
        t.digest(self.candidate_digest); t.task_ref(&self.reviewed_task_ref);
        t.digest(self.reviewed_task_control_digest); t.digest(self.completion_policy_digest);
        t.string(&self.implementer_actor); t.string(&self.reviewer_actor); t.string(&self.reviewer_role);
        t.oid(self.baseline_commit); t.oid(self.candidate_commit); t.overlay(self.overlay_digest);
        t.strings(&self.execution_flags); t.digests(&self.evidence_digests);
        t.number(self.required_checks.len() as u64);
        for check in &self.required_checks {
            t.string(&check.check_id); t.0.push(u8::from(check.passed)); t.digest(check.artifact_digest);
        }
        t.string(match self.verdict { ReviewVerdict::Pass => "pass", ReviewVerdict::RequestChanges => "request_changes", ReviewVerdict::Reject => "reject" });
        t.number(self.findings.len() as u64);
        for finding in &self.findings {
            t.string(&finding.finding_id);
            t.string(match finding.severity { FindingSeverity::Blocker => "blocker", FindingSeverity::Major => "major", FindingSeverity::Minor => "minor", FindingSeverity::Info => "info" });
            t.0.push(u8::from(finding.blocking)); t.string(&finding.summary);
        }
        t.number(self.issued_at_unix); t.number(self.expires_at_unix);
        t.0
    }
}
impl ReviewAttestationV1 {
    pub fn canonical_digest(&self) -> Sha256Digest { CanonicalReviewProposalV1::canonical_digest(self) }
}
impl CanonicalReviewProposalV1 for TaskAcceptanceV1 {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut t = Transcript::new(TASK_ACCEPTANCE_DOMAIN_V1);
        t.string(&self.schema_version); t.string(&self.operation_id); t.string(&self.message_id);
        t.string(&self.candidate_operation_id); t.digest(self.candidate_digest);
        t.string(&self.attestation_id); t.digest(self.attestation_digest); t.task_ref(&self.task_ref);
        t.number(self.accepted_from_task_status_rev); t.number(self.committed_task_status_rev);
        t.digest(self.task_control_digest); t.digest(self.completion_policy_digest);
        t.string(&self.implementer_actor); t.string(&self.reviewer_actor); t.string(&self.reviewer_role);
        t.string(&self.writer_actor); t.number(self.writer_epoch);
        t.oid(self.baseline_commit); t.oid(self.candidate_commit); t.overlay(self.overlay_digest);
        t.strings(&self.execution_flags); t.digests(&self.evidence_digests);
        t.strings(&self.verification_checks_passed); t.number(self.accepted_at_unix);
        t.0
    }
}
impl TaskAcceptanceV1 {
    pub fn canonical_digest(&self) -> Sha256Digest { CanonicalReviewProposalV1::canonical_digest(self) }
}
impl CompletionPolicyV1 {
    pub fn canonical_digest(&self) -> Sha256Digest {
        let mut t = Transcript::new(b"chinwag-completion-policy-v1\0");
        t.strings(&self.required_checks); t.strings(&self.forbidden_execution_flags);
        t.strings(&self.reviewer_role_policy.authorized_reviewer_seats);
        t.string(&self.reviewer_role_policy.expected_writer_principal);
        t.0.extend(encode_bytes_field(&self.implementer_public_key));
        t.0.extend(encode_bytes_field(&self.reviewer_public_key));
        t.0.extend(encode_bytes_field(&self.writer_public_key)); t.number(self.writer_epoch);
        Sha256Digest::of(&t.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProposalEnvelopeV1<T> {
    pub payload_kind: String,
    pub signer_actor: String,
    #[serde(with = "key_json")]
    pub signer_public_key: [u8; 32],
    #[serde(with = "signature_json")]
    pub signature_ed25519: [u8; 64],
    pub payload: T,
}
pub type SignedCandidateV1 = SignedProposalEnvelopeV1<TaskCandidateV1>;
pub type SignedReviewAttestationV1 = SignedProposalEnvelopeV1<ReviewAttestationV1>;
pub type SignedTaskAcceptanceV1 = SignedProposalEnvelopeV1<TaskAcceptanceV1>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAcceptanceBundleV1 {
    pub candidate: SignedCandidateV1,
    pub attestation: SignedReviewAttestationV1,
    pub acceptance: SignedTaskAcceptanceV1,
}
#[derive(Serialize)]
struct BorrowedAcceptanceBundleV1<'a> {
    candidate: &'a SignedCandidateV1,
    attestation: &'a SignedReviewAttestationV1,
    acceptance: &'a SignedTaskAcceptanceV1,
}

fn verify_signature<T: CanonicalReviewProposalV1>(
    envelope: &SignedProposalEnvelopeV1<T>, kind: &str, actor: &str, expected_key: &[u8; 32],
) -> Result<(), AcceptanceError> {
    if envelope.payload_kind != kind { return Err(AcceptanceError::SchemaVersionMismatch); }
    if envelope.signer_actor != actor || &envelope.signer_public_key != expected_key {
        return Err(AcceptanceError::SignerBindingMismatch);
    }
    let key = EndpointId::from_bytes(expected_key).map_err(|_| AcceptanceError::SignatureInvalid)?;
    key.verify(&envelope.payload.canonical_bytes(), &Signature::from_bytes(&envelope.signature_ed25519))
        .map_err(|_| AcceptanceError::SignatureInvalid)
}

fn display_bound(value: &Option<String>) -> Result<(), AcceptanceError> {
    if value.as_ref().is_some_and(|value| value.len() > MAX_DISPLAY_TEXT_UTF8_BYTES) {
        return Err(AcceptanceError::StructuralLimitExceeded);
    }
    Ok(())
}
fn sorted_ids(values: &[String], required: bool) -> Result<(), AcceptanceError> {
    if values.len() > MAX_VERIFICATION_CHECKS_PASSED || (required && values.is_empty()) {
        return Err(AcceptanceError::StructuralLimitExceeded);
    }
    for value in values { validate_id(value, "review identifier")?; }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AcceptanceError::Contract(TaskContractError::InvalidSetOrder));
    }
    Ok(())
}
fn evidence_bound(values: &[Sha256Digest]) -> Result<(), AcceptanceError> {
    if values.is_empty() || values.len() > MAX_EVIDENCE_DIGESTS_PER_CANDIDATE {
        return Err(AcceptanceError::StructuralLimitExceeded);
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AcceptanceError::Contract(TaskContractError::InvalidSetOrder));
    }
    Ok(())
}
fn validate_structure(c: &TaskCandidateV1, r: &ReviewAttestationV1, a: &TaskAcceptanceV1) -> Result<(), AcceptanceError> {
    if c.schema_version != TASK_CANDIDATE_SCHEMA_V1 || r.schema_version != REVIEW_ATTESTATION_SCHEMA_V1
        || a.schema_version != TASK_ACCEPTANCE_SCHEMA_V1 {
        return Err(AcceptanceError::SchemaVersionMismatch);
    }
    for value in [&c.operation_id, &c.message_id, &r.attestation_id, &r.operation_id, &r.message_id,
        &r.candidate_operation_id, &a.operation_id, &a.message_id, &a.candidate_operation_id, &a.attestation_id,
        &c.implementer_actor, &c.reviewer_role, &r.implementer_actor, &r.reviewer_actor, &r.reviewer_role,
        &a.implementer_actor, &a.reviewer_actor, &a.reviewer_role, &a.writer_actor] {
        validate_id(value, "review identifier")?;
    }
    c.task_ref.validate()?; r.reviewed_task_ref.validate()?; a.task_ref.validate()?;
    if a.committed_task_status_rev != checked_next_revision(a.accepted_from_task_status_rev)? {
        return Err(ReviewStateError::TargetTaskRevisionConflict.into());
    }
    for values in [&c.execution_flags, &r.execution_flags, &a.execution_flags] { sorted_ids(values, false)?; }
    for values in [&c.evidence_digests, &r.evidence_digests, &a.evidence_digests] { evidence_bound(values)?; }
    sorted_ids(&c.verification_checks_passed, true)?; sorted_ids(&a.verification_checks_passed, true)?;
    if r.required_checks.is_empty() {
        return Err(if r.verdict == ReviewVerdict::Pass { AcceptanceError::ContradictoryPassAttestation }
            else { AcceptanceError::StructuralLimitExceeded });
    }
    if r.required_checks.len() > MAX_REQUIRED_CHECKS_PER_ATTESTATION
        || r.findings.len() > MAX_FINDINGS_PER_ATTESTATION {
        return Err(AcceptanceError::StructuralLimitExceeded);
    }
    let mut previous_check: Option<&str> = None;
    for check in &r.required_checks {
        validate_id(&check.check_id, "check_id")?;
        if previous_check.is_some_and(|previous| previous >= check.check_id.as_str()) {
            return Err(AcceptanceError::Contract(TaskContractError::InvalidSetOrder));
        }
        previous_check = Some(&check.check_id);
    }
    let mut previous_finding: Option<&str> = None;
    for finding in &r.findings {
        validate_id(&finding.finding_id, "finding_id")?;
        if finding.summary.len() > MAX_DISPLAY_TEXT_UTF8_BYTES {
            return Err(AcceptanceError::StructuralLimitExceeded);
        }
        if previous_finding.is_some_and(|previous| previous >= finding.finding_id.as_str()) {
            return Err(AcceptanceError::Contract(TaskContractError::InvalidSetOrder));
        }
        previous_finding = Some(&finding.finding_id);
    }
    display_bound(&c.display_text)?; display_bound(&r.display_text)?; display_bound(&a.display_text)?;
    Ok(())
}

pub fn reject_prose_completion_claim(_raw_input: &str) -> AcceptanceError {
    AcceptanceError::ProseCompletionForbidden
}

/// A streaming structural preflight runs before the typed parser allocates lists.
/// The raw frame is bounded first; object keys, strings and every array are finite.
fn preflight_json(raw: &str) -> Result<(), AcceptanceError> {
    if raw.len() > MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES { return Err(AcceptanceError::PayloadTooLarge); }
    if !raw.trim_start().starts_with('{') { return Err(reject_prose_completion_claim(raw)); }
    let mut failure = None;
    let mut decoder = serde_json::Deserializer::from_str(raw);
    if JsonGuard(&mut failure).deserialize(&mut decoder).is_err() {
        return Err(failure.unwrap_or(AcceptanceError::InvalidJson));
    }
    decoder.end().map_err(|_| AcceptanceError::InvalidJson)
}
struct JsonGuard<'a>(&'a mut Option<AcceptanceError>);
impl<'de> DeserializeSeed<'de> for JsonGuard<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> { d.deserialize_any(self) }
}
impl<'de> Visitor<'de> for JsonGuard<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("bounded strict proposal JSON") }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> { Ok(()) }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> { Ok(()) }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() > MAX_DISPLAY_TEXT_UTF8_BYTES {
            *self.0 = Some(AcceptanceError::StructuralLimitExceeded);
            return Err(E::custom("JSON string limit"));
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let mut count = 0;
        while sequence.next_element_seed(JsonGuard(&mut *self.0))?.is_some() {
            count += 1;
            if count > MAX_REQUIRED_CHECKS_PER_ATTESTATION {
                *self.0 = Some(AcceptanceError::StructuralLimitExceeded);
                return Err(serde::de::Error::custom("JSON array limit"));
            }
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 256 || keys.len() == 64 {
                *self.0 = Some(AcceptanceError::StructuralLimitExceeded);
                return Err(serde::de::Error::custom("JSON key limit"));
            }
            if !keys.insert(key) {
                *self.0 = Some(AcceptanceError::DuplicateJsonKey);
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            map.next_value_seed(JsonGuard(&mut *self.0))?;
        }
        Ok(())
    }
}

pub fn parse_signed_acceptance_bundle(raw: &str) -> Result<SignedAcceptanceBundleV1, AcceptanceError> {
    preflight_json(raw)?;
    let bundle: SignedAcceptanceBundleV1 = serde_json::from_str(raw).map_err(|_| AcceptanceError::InvalidJson)?;
    validate_structure(&bundle.candidate.payload, &bundle.attestation.payload, &bundle.acceptance.payload)?;
    Ok(bundle)
}

pub struct AcceptanceVerificationContextV1<'a> {
    pub task_snapshot: &'a TaskEntrySnapshotV1,
    pub current_target_task_ref: &'a TaskRefV1,
    pub rebases_used: u8,
    pub completion_policy: &'a CompletionPolicyV1,
    pub dependency_snapshots: &'a [DependencyTargetSnapshot],
    pub clock: HostClockState,
    pub review_state: &'a mut TaskReviewStateRecord,
    pub replay_ledger: &'a mut ReviewReplayLedger,
}
pub fn parse_and_verify_acceptance_bundle(
    raw: &str, context: AcceptanceVerificationContextV1<'_>,
) -> Result<AuthorizedAcceptanceOutcomeV1, AcceptanceError> {
    let bundle = parse_signed_acceptance_bundle(raw)?;
    authorize_reviewed_acceptance(context.task_snapshot, context.current_target_task_ref,
        context.rebases_used, context.completion_policy, context.dependency_snapshots, context.clock,
        &bundle.candidate, &bundle.attestation, &bundle.acceptance, context.review_state, context.replay_ledger)
}

/// Only this module can construct the token. Issuance means verified permission
/// to prepare a writer operation; it does not mean the task has committed Done.
#[derive(Debug)]
pub struct VerifiedReviewedAcceptanceV1 {
    bundle: SignedAcceptanceBundleV1,
}
#[derive(Debug)]
pub enum AuthorizedAcceptanceOutcomeV1 {
    Authorized(Box<VerifiedReviewedAcceptanceV1>),
    /// A pending retry receives a freshly revalidated token. A terminal or
    /// negative historical lookup carries no authority to perform an effect.
    IdempotentDuplicate { revalidated: Option<Box<VerifiedReviewedAcceptanceV1>> },
}
/// The old writer input stays paired with the sealed complete evidence. The
/// integrator must consume this pair, bind its digest in the journal and keep
/// the baseline Done hold until that protected boundary is wired.
#[derive(Debug)]
pub struct ReviewedAcceptanceBridgeV1 {
    authorization: TransitionAuthorization,
    verified_acceptance: VerifiedReviewedAcceptanceV1,
}
impl ReviewedAcceptanceBridgeV1 {
    pub fn authorization(&self) -> &TransitionAuthorization { &self.authorization }
    pub fn verified_acceptance(&self) -> &VerifiedReviewedAcceptanceV1 { &self.verified_acceptance }
}
impl VerifiedReviewedAcceptanceV1 {
    pub fn acceptance_digest(&self) -> Sha256Digest { self.bundle.acceptance.payload.canonical_digest() }
    pub fn candidate_digest(&self) -> Sha256Digest { self.bundle.candidate.payload.canonical_digest() }
    pub fn attestation_digest(&self) -> Sha256Digest { self.bundle.attestation.payload.canonical_digest() }
    pub fn acceptance(&self) -> &TaskAcceptanceV1 { &self.bundle.acceptance.payload }
    /// Retains original signatures and signer bindings for consumption/recovery
    /// revalidation; callers cannot mutate or manufacture the sealed token.
    pub fn signed_bundle(&self) -> &SignedAcceptanceBundleV1 { &self.bundle }
    /// WORKHORSE's writer integration must bind this sealed token to the exact
    /// authenticated request, revalidate current authority, and durably consume
    /// it with the journal outcome. The baseline writer deliberately holds Done.
    pub fn into_transition_authorization(self, authority: TransitionAuthorityV1) -> ReviewedAcceptanceBridgeV1 {
        let candidate = &self.bundle.candidate.payload;
        let attestation = &self.bundle.attestation.payload;
        let acceptance = &self.bundle.acceptance.payload;
        let authorization = TransitionAuthorization::ReviewedAcceptance(Box::new(ReviewedAcceptanceProofV1 {
            reviewer_actor: attestation.reviewer_actor.clone(),
            implementer_actor: candidate.implementer_actor.clone(),
            reviewed_task_ref: acceptance.task_ref.clone(),
            reviewed_task_control_digest: acceptance.task_control_digest,
            completion_policy_digest: acceptance.completion_policy_digest,
            candidate_commit: acceptance.candidate_commit,
            reviewer_role: acceptance.reviewer_role.clone(),
            verification_checks_passed: acceptance.verification_checks_passed.clone(),
            authority,
        }));
        ReviewedAcceptanceBridgeV1 { authorization, verified_acceptance: self }
    }
}

fn validate_policy(policy: &CompletionPolicyV1) -> Result<(), AcceptanceError> {
    sorted_ids(&policy.required_checks, true)?;
    sorted_ids(&policy.forbidden_execution_flags, false)?;
    sorted_ids(&policy.reviewer_role_policy.authorized_reviewer_seats, true)?;
    validate_id(&policy.reviewer_role_policy.expected_writer_principal, "writer principal")?;
    if policy.implementer_public_key == policy.reviewer_public_key {
        return Err(ReviewStateError::SelfReviewForbidden.into());
    }
    if policy.writer_public_key == policy.implementer_public_key || policy.writer_epoch == 0 {
        return Err(AcceptanceError::InvalidPolicy);
    }
    Ok(())
}
fn check_pass(review: &ReviewAttestationV1, policy: &CompletionPolicyV1, candidate: &TaskCandidateV1)
    -> Result<(), AcceptanceError> {
    if review.verdict != ReviewVerdict::Pass { return Err(AcceptanceError::ReviewVerdictNotPass); }
    if review.required_checks.iter().any(|check| !check.passed)
        || policy.required_checks.iter().any(|required| !review.required_checks.iter()
            .any(|check| &check.check_id == required && check.passed)
            || !candidate.verification_checks_passed.contains(required))
        || review.findings.iter().any(|finding| finding.blocking || finding.severity == FindingSeverity::Blocker) {
        return Err(AcceptanceError::ContradictoryPassAttestation);
    }
    Ok(())
}
fn evaluate_dependencies(snapshot: &TaskEntrySnapshotV1, targets: &[DependencyTargetSnapshot], current: &TaskRefV1)
    -> Result<(), AcceptanceError> {
    if targets.len() > crate::task_ref::MAX_DEPENDENCY_EDGES || snapshot.dependencies.len() > crate::task_ref::MAX_LIST_ITEMS {
        return Err(AcceptanceError::StructuralLimitExceeded);
    }
    let mut keys = BTreeSet::new();
    for target in targets {
        if !keys.insert(target.resolved.task_ref.task_key()) { return Err(AcceptanceError::DependencyUnsatisfied); }
    }
    let canonical = crate::task_dependency::canonicalize_dependencies(&current.task_key(), snapshot.dependencies.clone())
        .map_err(|_| AcceptanceError::DependencyUnsatisfied)?;
    if canonical != snapshot.dependencies { return Err(AcceptanceError::DependencyUnsatisfied); }
    for required in &snapshot.dependencies {
        let target = targets.iter().find(|target| target.resolved.task_ref.task_key() == required.target_key)
            .ok_or(AcceptanceError::DependencyUnsatisfied)?;
        if target.resolved.task_ref.repo_id != current.repo_id { return Err(AcceptanceError::DependencyUnsatisfied); }
        validate_dependency_satisfaction(required, &target.resolved, &target.current_source)
            .map_err(|_| AcceptanceError::DependencyUnsatisfied)?;
    }
    Ok(())
}
fn replay_entry(task_ref: &TaskRefV1, operation: &str, message: &str, signer: &[u8; 32], digest: Sha256Digest) -> ReplayEntryV1 {
    ReplayEntryV1 {
        workspace_id: task_ref.workspace_id.clone(), task_source_id: task_ref.task_source_id.clone(),
        operation_id: operation.into(), message_id: message.into(),
        signer_principal: Sha256Digest(*signer).to_string(), canonical_digest_sha256: digest,
    }
}

// This signature is the admitted integration seam; collecting it into an
// unreviewed context object would change the requested public API.
#[allow(clippy::too_many_arguments)]
pub fn authorize_reviewed_acceptance(
    task_snapshot: &TaskEntrySnapshotV1,
    current_target_task_ref: &TaskRefV1,
    rebases_used: u8,
    completion_policy: &CompletionPolicyV1,
    dependency_snapshots: &[DependencyTargetSnapshot],
    clock: HostClockState,
    signed_candidate: &SignedCandidateV1,
    signed_attestation: &SignedReviewAttestationV1,
    signed_acceptance: &SignedTaskAcceptanceV1,
    review_state: &mut TaskReviewStateRecord,
    replay_ledger: &mut ReviewReplayLedger,
) -> Result<AuthorizedAcceptanceOutcomeV1, AcceptanceError> {
    // Bound directly constructed inputs too, before cloning, hashing or staging.
    let c = &signed_candidate.payload;
    let r = &signed_attestation.payload;
    let a = &signed_acceptance.payload;
    for value in [&signed_candidate.payload_kind, &signed_candidate.signer_actor,
        &signed_attestation.payload_kind, &signed_attestation.signer_actor,
        &signed_acceptance.payload_kind, &signed_acceptance.signer_actor] {
        validate_id(value, "proposal envelope field")?;
    }
    validate_structure(c, r, a)?;
    let bundle = BorrowedAcceptanceBundleV1 {
        candidate: signed_candidate, attestation: signed_attestation, acceptance: signed_acceptance,
    };
    // Apply the same total wire bound to typed and parsed entrypoints.
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, &bundle).map_err(|_| AcceptanceError::PayloadTooLarge)?;
    validate_policy(completion_policy)?;
    verify_signature(signed_candidate, TASK_CANDIDATE_SCHEMA_V1, &c.implementer_actor, &completion_policy.implementer_public_key)?;
    verify_signature(signed_attestation, REVIEW_ATTESTATION_SCHEMA_V1, &r.reviewer_actor, &completion_policy.reviewer_public_key)?;
    verify_signature(signed_acceptance, TASK_ACCEPTANCE_SCHEMA_V1, &a.writer_actor, &completion_policy.writer_public_key)?;
    if let Err(error) = verify_separation_of_duties(task_snapshot, c, r, a, &completion_policy.reviewer_role_policy,
        &signed_candidate.signer_public_key, &signed_attestation.signer_public_key) {
        if review_state.active_candidate_digest.is_some() {
            invalidate_review_state(review_state);
        }
        return Err(error.into());
    }
    if c.operation_id != r.candidate_operation_id || c.operation_id != a.candidate_operation_id
        || c.canonical_digest() != r.candidate_digest || c.canonical_digest() != a.candidate_digest {
        return Err(AcceptanceError::CandidateBindingMismatch);
    }
    if r.attestation_id != a.attestation_id || r.canonical_digest() != a.attestation_digest {
        return Err(AcceptanceError::AttestationBindingMismatch);
    }
    let entries = [
        replay_entry(&c.task_ref, &c.operation_id, &c.message_id, &signed_candidate.signer_public_key, c.canonical_digest()),
        replay_entry(&r.reviewed_task_ref, &r.operation_id, &r.message_id, &signed_attestation.signer_public_key, r.canonical_digest()),
        replay_entry(&a.task_ref, &a.operation_id, &a.message_id, &signed_acceptance.signer_public_key, a.canonical_digest()),
    ];
    let mut staged_state = review_state.clone();
    let mut staged_ledger = replay_ledger.clone();
    let duplicate = match staged_ledger.record_batch(&entries, &mut staged_state) {
        Ok(ReplayDisposition::IdempotentDuplicate) => {
            if matches!(review_state.state, TaskReviewLifecycleState::AcceptedDone
                | TaskReviewLifecycleState::ChangesRequested | TaskReviewLifecycleState::RejectedByReviewer) {
                *replay_ledger = staged_ledger;
                return Ok(AuthorizedAcceptanceOutcomeV1::IdempotentDuplicate { revalidated: None });
            }
            true
        }
        Ok(ReplayDisposition::Fresh) => false,
        Err(error) => {
            if error == ReviewStateError::ReplayPayloadConflict { *review_state = staged_state; }
            return Err(error.into());
        }
    };
    if a.completion_policy_digest != completion_policy.canonical_digest() || a.writer_epoch != completion_policy.writer_epoch {
        invalidate_review_state(review_state);
        return Err(AcceptanceError::PolicyCommitmentMismatch);
    }
    let now = match clock {
        HostClockState::Verified { now_unix } => now_unix,
        HostClockState::ClockRollback | HostClockState::TimeUnavailable => {
            hold_review_state(review_state);
            return Err(AcceptanceError::ClockFenceHeld);
        }
    };
    if r.issued_at_unix > now || now > r.expires_at_unix || r.issued_at_unix > r.expires_at_unix
        || c.submitted_at_unix > r.issued_at_unix || a.accepted_at_unix < r.issued_at_unix
        || a.accepted_at_unix > now || a.accepted_at_unix > r.expires_at_unix {
        hold_review_state(review_state);
        return Err(AcceptanceError::ClockFenceHeld);
    }
    if let Err(error) = verify_candidate_and_attestation_freshness(task_snapshot, current_target_task_ref,
        rebases_used, c, r, a, &completion_policy.forbidden_execution_flags) {
        invalidate_review_state(review_state);
        return Err(error.into());
    }
    if staged_state.active_candidate_digest == Some(c.canonical_digest())
        && staged_state.snapshot.as_ref().is_some_and(|old| old != task_snapshot) {
        invalidate_review_state(review_state);
        return Err(ReviewStateError::TargetTaskMutated.into());
    }
    if let Err(error) = evaluate_dependencies(task_snapshot, dependency_snapshots, current_target_task_ref) {
        if review_state.active_candidate_digest.is_some() {
            invalidate_review_state(review_state);
        }
        return Err(error);
    }
    stage_candidate(&mut staged_state, c)?;
    if r.verdict != ReviewVerdict::Pass {
        let next = match r.verdict {
            ReviewVerdict::RequestChanges => TaskReviewLifecycleState::ChangesRequested,
            ReviewVerdict::Reject => TaskReviewLifecycleState::RejectedByReviewer,
            ReviewVerdict::Pass => return Err(AcceptanceError::ReviewVerdictNotPass),
        };
        staged_state.state.transition_to(next)?;
        staged_state.active_attestation_digest = Some(r.canonical_digest());
        staged_state.snapshot = Some(task_snapshot.clone());
        *review_state = staged_state;
        *replay_ledger = staged_ledger;
        return Err(AcceptanceError::ReviewVerdictNotPass);
    }
    check_pass(r, completion_policy, c)?;
    if staged_state.state == TaskReviewLifecycleState::ReviewAttestedPass {
        if staged_state.active_attestation_digest != Some(r.canonical_digest()) {
            hold_review_state(review_state);
            return Err(AcceptanceError::AttestationBindingMismatch);
        }
    } else {
        staged_state.state.transition_to(TaskReviewLifecycleState::ReviewAttestedPass)?;
    }
    staged_state.active_attestation_digest = Some(r.canonical_digest());
    staged_state.task_status_rev = Some(task_snapshot.task_status_rev);
    staged_state.snapshot = Some(task_snapshot.clone());
    // Authorization leaves the lifecycle at ReviewAttestedPass. Only the durable
    // writer outcome can advance it to AcceptedDone; no filesystem effect here.
    *review_state = staged_state;
    *replay_ledger = staged_ledger;
    let token = Box::new(VerifiedReviewedAcceptanceV1 {
        bundle: SignedAcceptanceBundleV1 {
            candidate: signed_candidate.clone(), attestation: signed_attestation.clone(), acceptance: signed_acceptance.clone(),
        },
    });
    if duplicate {
        Ok(AuthorizedAcceptanceOutcomeV1::IdempotentDuplicate { revalidated: Some(token) })
    } else {
        Ok(AuthorizedAcceptanceOutcomeV1::Authorized(token))
    }
}

fn stage_candidate(state: &mut TaskReviewStateRecord, candidate: &TaskCandidateV1) -> Result<(), AcceptanceError> {
    let digest = candidate.canonical_digest();
    if state.active_candidate_digest == Some(digest) {
        if matches!(state.state, TaskReviewLifecycleState::CandidateSubmitted | TaskReviewLifecycleState::ReviewAttestedPass) {
            return Ok(());
        }
        return Err(ReviewStateError::InvalidTransition.into());
    }
    if state.state == TaskReviewLifecycleState::ReviewAttestedPass {
        state.state.transition_to(TaskReviewLifecycleState::InvalidatedStale)?;
    }
    if state.state != TaskReviewLifecycleState::CandidateSubmitted {
        state.state.transition_to(TaskReviewLifecycleState::CandidateSubmitted)?;
    }
    state.active_candidate_digest = Some(digest);
    state.active_attestation_digest = None;
    state.task_status_rev = Some(candidate.task_ref.task_status_rev);
    Ok(())
}
fn hold_review_state(state: &mut TaskReviewStateRecord) {
    if state.state.can_transition_to(TaskReviewLifecycleState::HeldConflict) {
        state.state = TaskReviewLifecycleState::HeldConflict;
    }
}
fn invalidate_review_state(state: &mut TaskReviewStateRecord) {
    if state.state.can_transition_to(TaskReviewLifecycleState::InvalidatedStale) {
        state.state = TaskReviewLifecycleState::InvalidatedStale;
    }
}
struct ByteCounter(usize);
impl std::io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES - self.0 {
            return Err(std::io::Error::other("acceptance frame limit"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_dependency::{DependencyCommitment, TaskStatus};
    use crate::task_writer::CanonicalTaskStatus;
    use iroh::SecretKey;

    struct Fixture {
        bundle: SignedAcceptanceBundleV1,
        policy: CompletionPolicyV1,
        snapshot: TaskEntrySnapshotV1,
        current: TaskRefV1,
        dependencies: Vec<DependencyTargetSnapshot>,
        state: TaskReviewStateRecord,
        ledger: ReviewReplayLedger,
    }
    fn sign<T: CanonicalReviewProposalV1>(payload: T, kind: &str, actor: &str, seed: u8) -> SignedProposalEnvelopeV1<T> {
        let secret = SecretKey::from_bytes(&[seed; 32]);
        SignedProposalEnvelopeV1 {
            payload_kind: kind.into(), signer_actor: actor.into(),
            signer_public_key: *secret.public().as_bytes(),
            signature_ed25519: secret.sign(&payload.canonical_bytes()).to_bytes(), payload,
        }
    }
    impl Fixture {
        fn new() -> Self {
            let policy = CompletionPolicyV1 {
                required_checks: vec!["check".into()], forbidden_execution_flags: vec!["--no-verify".into(), "skip_tests".into()],
                reviewer_role_policy: ReviewerRolePolicy {
                    authorized_reviewer_seats: vec!["REVIEW".into()], expected_writer_principal: "WRITER".into(),
                },
                implementer_public_key: *SecretKey::from_bytes(&[1; 32]).public().as_bytes(),
                reviewer_public_key: *SecretKey::from_bytes(&[2; 32]).public().as_bytes(),
                writer_public_key: *SecretKey::from_bytes(&[3; 32]).public().as_bytes(), writer_epoch: 1,
            };
            let task_ref = TaskRefV1 {
                workspace_id: "workspace".into(), repo_id: "repo".into(),
                task_source_id: "11111111111111111111111111111111".into(), source_generation: 1,
                canonical_task_path: "TASKS.md".into(), task_id: "P0-06".into(),
                task_spec_digest: Sha256Digest([1; 32]), task_status_rev: 4, file_cas_rev: 8,
                baseline_commit: GitOid::Sha1([1; 20]),
            };
            let candidate = TaskCandidateV1 {
                schema_version: TASK_CANDIDATE_SCHEMA_V1.into(), operation_id: "candidate-op".into(), message_id: "candidate-msg".into(),
                task_ref: task_ref.clone(), task_control_digest: Sha256Digest([2; 32]), completion_policy_digest: policy.canonical_digest(),
                implementer_actor: "RUST#one".into(), reviewer_role: "independent".into(),
                baseline_commit: task_ref.baseline_commit, candidate_commit: GitOid::Sha1([2; 20]), overlay_digest: None,
                execution_flags: vec![], evidence_digests: vec![Sha256Digest([4; 32])],
                verification_checks_passed: vec!["check".into()], submitted_at_unix: 90, display_text: None,
            };
            let attestation = ReviewAttestationV1 {
                schema_version: REVIEW_ATTESTATION_SCHEMA_V1.into(), attestation_id: "review-id".into(),
                operation_id: "review-op".into(), message_id: "review-msg".into(), candidate_operation_id: candidate.operation_id.clone(),
                candidate_digest: candidate.canonical_digest(), reviewed_task_ref: task_ref.clone(),
                reviewed_task_control_digest: candidate.task_control_digest, completion_policy_digest: candidate.completion_policy_digest,
                implementer_actor: candidate.implementer_actor.clone(), reviewer_actor: "REVIEW#two".into(), reviewer_role: candidate.reviewer_role.clone(),
                baseline_commit: candidate.baseline_commit, candidate_commit: candidate.candidate_commit, overlay_digest: None,
                execution_flags: vec![], evidence_digests: candidate.evidence_digests.clone(),
                required_checks: vec![RequiredCheckResultV1 { check_id: "check".into(), passed: true, artifact_digest: Sha256Digest([5; 32]) }],
                verdict: ReviewVerdict::Pass, findings: vec![], issued_at_unix: 95, expires_at_unix: 105, display_text: None,
            };
            let acceptance = TaskAcceptanceV1 {
                schema_version: TASK_ACCEPTANCE_SCHEMA_V1.into(), operation_id: "accept-op".into(), message_id: "accept-msg".into(),
                candidate_operation_id: candidate.operation_id.clone(), candidate_digest: candidate.canonical_digest(),
                attestation_id: attestation.attestation_id.clone(), attestation_digest: attestation.canonical_digest(), task_ref: task_ref.clone(),
                accepted_from_task_status_rev: 4, committed_task_status_rev: 5,
                task_control_digest: candidate.task_control_digest, completion_policy_digest: candidate.completion_policy_digest,
                implementer_actor: candidate.implementer_actor.clone(), reviewer_actor: attestation.reviewer_actor.clone(),
                reviewer_role: candidate.reviewer_role.clone(), writer_actor: "WRITER#three".into(), writer_epoch: 1,
                baseline_commit: candidate.baseline_commit, candidate_commit: candidate.candidate_commit, overlay_digest: None,
                execution_flags: vec![], evidence_digests: candidate.evidence_digests.clone(),
                verification_checks_passed: candidate.verification_checks_passed.clone(), accepted_at_unix: 100, display_text: None,
            };
            let snapshot = TaskEntrySnapshotV1 {
                task_id: "P0-06".into(), status: CanonicalTaskStatus::DonePendingReview, task_status_rev: 4,
                task_spec_digest: task_ref.task_spec_digest, task_control_digest: candidate.task_control_digest,
                completion_policy_digest: candidate.completion_policy_digest, owner_actor: Some(candidate.implementer_actor.clone()),
                reviewer_role: candidate.reviewer_role.clone(), baseline_commit: candidate.baseline_commit,
                candidate_commit: Some(candidate.candidate_commit), overlay_digest: None, execution_flags: vec![], dependencies: vec![],
            };
            Self {
                bundle: SignedAcceptanceBundleV1 {
                    candidate: sign(candidate, TASK_CANDIDATE_SCHEMA_V1, "RUST#one", 1),
                    attestation: sign(attestation, REVIEW_ATTESTATION_SCHEMA_V1, "REVIEW#two", 2),
                    acceptance: sign(acceptance, TASK_ACCEPTANCE_SCHEMA_V1, "WRITER#three", 3),
                }, policy, snapshot, current: task_ref, dependencies: vec![], state: TaskReviewStateRecord::new(), ledger: ReviewReplayLedger::default(),
            }
        }
        fn resign(&mut self) {
            let c = &mut self.bundle.candidate;
            c.signer_actor = c.payload.implementer_actor.clone();
            c.signature_ed25519 = SecretKey::from_bytes(&[1; 32]).sign(&c.payload.canonical_bytes()).to_bytes();
            let r = &mut self.bundle.attestation;
            r.payload.candidate_digest = c.payload.canonical_digest();
            r.signer_actor = r.payload.reviewer_actor.clone();
            r.signature_ed25519 = SecretKey::from_bytes(&[2; 32]).sign(&r.payload.canonical_bytes()).to_bytes();
            let a = &mut self.bundle.acceptance;
            a.payload.candidate_digest = c.payload.canonical_digest();
            a.payload.attestation_digest = r.payload.canonical_digest();
            a.signer_actor = a.payload.writer_actor.clone();
            a.signature_ed25519 = SecretKey::from_bytes(&[3; 32]).sign(&a.payload.canonical_bytes()).to_bytes();
        }
        fn sync_policy(&mut self) {
            let digest = self.policy.canonical_digest();
            self.snapshot.completion_policy_digest = digest;
            self.bundle.candidate.payload.completion_policy_digest = digest;
            self.bundle.attestation.payload.completion_policy_digest = digest;
            self.bundle.acceptance.payload.completion_policy_digest = digest;
            self.resign();
        }
        fn authorize(&mut self) -> Result<AuthorizedAcceptanceOutcomeV1, AcceptanceError> {
            self.authorize_at(HostClockState::Verified { now_unix: 100 }, 0)
        }
        fn authorize_at(&mut self, clock: HostClockState, rebases: u8) -> Result<AuthorizedAcceptanceOutcomeV1, AcceptanceError> {
            authorize_reviewed_acceptance(&self.snapshot, &self.current, rebases, &self.policy, &self.dependencies,
                clock, &self.bundle.candidate, &self.bundle.attestation, &self.bundle.acceptance, &mut self.state, &mut self.ledger)
        }
        fn dependency(&mut self) {
            let mut task_ref = self.current.clone(); task_ref.task_id = "P0-05".into();
            self.snapshot.dependencies.push(DependencyCommitment { target_key: task_ref.task_key(),
                target_spec_digest: task_ref.task_spec_digest, completion_policy_digest: Sha256Digest([9; 32]) });
            self.dependencies.push(DependencyTargetSnapshot {
                current_source: DependencySourceBinding::from_task_ref(&task_ref).unwrap(),
                resolved: ResolvedDependency { task_ref, completion_policy_digest: Sha256Digest([9; 32]), status: TaskStatus::Done },
            });
        }
    }
    fn refused(result: Result<AuthorizedAcceptanceOutcomeV1, AcceptanceError>) -> AcceptanceError {
        result.expect_err("proposal must be refused")
    }
    fn authenticated_authority(f: &Fixture) -> TransitionAuthorityV1 {
        use crate::task_wire::{PublishTaskV1, RatifiedPayloadProfile, SignerEnrollment,
            TASK_BUS_V2_ALPN, TaskMessageKind, TaskTranscriptV3, TaskVerificationContext};
        // This fixture profile admits one literal digest. It does not ratify a
        // production request or bypass the writer's canonical request binding.
        let profiles = [RatifiedPayloadProfile {
            kind: TaskMessageKind::TaskProposal, name: "chinwag-writer-request-v1",
            validate_canonical_payload: |raw| raw.len() == 32,
        }];
        let digest = f.bundle.acceptance.payload.canonical_digest();
        let body = serde_json::json!({
            "payload_profile": "chinwag-writer-request-v1",
            "canonical_payload_hex": digest.to_string(),
            "payload_digest_sha256": Sha256Digest::of(&digest.0).to_string(),
            "display_text": null
        }).to_string();
        let secret = SecretKey::from_bytes(&[2; 32]);
        let transcript = TaskTranscriptV3 {
            message_id: "accept-msg".into(), issued_at_unix: 95, expires_at_unix: 105, nonce: [6; 32],
            sender_full_actor_address: "REVIEW#two".into(), parent_full_actor_address: None,
            recipient_full_actor_addresses: vec!["WRITER#three".into()], room: "#eng".into(),
            message_kind: TaskMessageKind::TaskProposal, receiver_authority_id: "writer-authority".into(),
            task_ref: f.current.clone(), assignment_id: None, operation_id: Some("accept-op".into()),
            request_id: None, in_reply_to_message_id: None, config_digest: f.policy.canonical_digest(),
            task_control_digest: f.snapshot.task_control_digest, body_utf8: body,
        };
        let roster = [SignerEnrollment {
            workspace_id: f.current.workspace_id.clone(), repo_id: f.current.repo_id.clone(), seat: "REVIEW".into(),
            authenticated_signer_principal: "reviewer-principal".into(), signer_pubkey: secret.public(),
            key_epoch: 1, config_digest: f.policy.canonical_digest(), allowed_actions: vec![TaskMessageKind::TaskProposal], active: true,
        }];
        let context = TaskVerificationContext {
            receiver_authority_id: "writer-authority", recipient_full_actor_address: "WRITER#three",
            current_task_ref: &f.current, config_digest: f.policy.canonical_digest(),
            task_control_digest: f.snapshot.task_control_digest, required_key_epoch: 1,
            current_granted_actions: &[TaskMessageKind::TaskProposal], ratified_profiles: &profiles,
            host_clock: HostClockState::Verified { now_unix: 100 },
        };
        let frame = PublishTaskV1::sign(transcript, &secret, &profiles).unwrap();
        let verified = frame.verify(TASK_BUS_V2_ALPN, &roster, &context).unwrap();
        TransitionAuthorityV1::from_verified(&verified).unwrap()
    }

    #[test]
    fn p0_acceptance_prose_has_no_authority_c01_c02() {
        for raw in ["COMPLETED P0-06", "TASK DONE", "LGTM", "VERDICT: APPROVE", "- [x] P0-06", "\"APPROVED\""] {
            assert_eq!(parse_signed_acceptance_bundle(raw).unwrap_err(), AcceptanceError::ProseCompletionForbidden);
        }
        assert!(parse_signed_acceptance_bundle("{\"sig_verified\":true,\"status\":\"COMPLETED\"}").is_err());
    }
    #[test]
    fn p0_acceptance_negative_verdict_overrides_display_c02_c03() {
        for verdict in [ReviewVerdict::RequestChanges, ReviewVerdict::Reject] {
            let mut f = Fixture::new();
            f.bundle.attestation.payload.verdict = verdict;
            f.bundle.attestation.payload.display_text = Some("COMPLETED DONE LGTM APPROVE".into());
            f.resign();
            assert_eq!(refused(f.authorize()), AcceptanceError::ReviewVerdictNotPass);
            assert_eq!(f.state.state, if verdict == ReviewVerdict::Reject { TaskReviewLifecycleState::RejectedByReviewer }
                else { TaskReviewLifecycleState::ChangesRequested });
            assert_eq!(f.ledger.len(), 3);
            assert!(matches!(f.authorize(), Ok(AuthorizedAcceptanceOutcomeV1::IdempotentDuplicate { revalidated: None })));
        }
    }
    #[test]
    fn p0_acceptance_contradictory_pass_c03() {
        for fault in 0..4 {
            let mut f = Fixture::new();
            match fault {
                0 => f.bundle.attestation.payload.required_checks[0].passed = false,
                1 => { f.policy.required_checks.push("missing".into()); f.sync_policy(); }
                _ => f.bundle.attestation.payload.findings.push(ReviewFindingV1 {
                    finding_id: "finding".into(), severity: if fault == 2 { FindingSeverity::Blocker } else { FindingSeverity::Minor },
                    blocking: fault == 3, summary: "requires rework".into(),
                }),
            }
            f.resign();
            assert_eq!(refused(f.authorize()), AcceptanceError::ContradictoryPassAttestation);
            assert_eq!(f.state.state, TaskReviewLifecycleState::NotSubmitted);
            assert!(f.ledger.is_empty());
        }
    }
    #[test]
    fn p0_acceptance_self_review_actor_seat_and_key_c04() {
        for fault in 0..3 {
            let mut f = Fixture::new();
            if fault == 2 { f.policy.reviewer_public_key = f.policy.implementer_public_key; f.sync_policy(); }
            else {
                let actor = if fault == 0 { "RUST#one" } else { "RUST#other" };
                f.bundle.attestation.payload.reviewer_actor = actor.into();
                f.bundle.acceptance.payload.reviewer_actor = actor.into(); f.resign();
            }
            assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(ReviewStateError::SelfReviewForbidden));
        }
    }
    #[test]
    fn p0_acceptance_role_and_writer_authority_c05() {
        for fault in 0..3 {
            let mut f = Fixture::new();
            match fault {
                0 => f.bundle.attestation.payload.reviewer_role = "unprivileged".into(),
                1 => { f.bundle.attestation.payload.reviewer_actor = "WORKER#two".into(); f.bundle.acceptance.payload.reviewer_actor = "WORKER#two".into(); }
                _ => f.bundle.acceptance.payload.writer_actor = "RUST#one".into(),
            }
            f.resign();
            let expected = if fault == 2 { ReviewStateError::UnauthorizedWriterPrincipal } else { ReviewStateError::UnauthorizedReviewerRole };
            assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(expected));
        }
    }
    #[test]
    fn p0_acceptance_spec_drift_invalidates_c06() {
        let mut f = Fixture::new(); f.snapshot.task_spec_digest = Sha256Digest([8; 32]);
        assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(ReviewStateError::StaleTaskSpecDigest));
        assert_eq!(f.state.state, TaskReviewLifecycleState::InvalidatedStale);
        assert!(f.ledger.is_empty());
    }
    #[test]
    fn p0_acceptance_artifact_drift_and_zero_commit_c07() {
        for fault in 0..5 {
            let mut f = Fixture::new();
            match fault {
                0 => f.snapshot.baseline_commit = GitOid::Sha1([8; 20]),
                1 => f.snapshot.candidate_commit = Some(GitOid::Sha1([8; 20])),
                2 => f.snapshot.overlay_digest = Some(Sha256Digest([8; 32])),
                3 => f.snapshot.execution_flags.push("changed".into()),
                _ => f.bundle.acceptance.payload.candidate_commit = GitOid::Sha1([0; 20]),
            }
            f.resign();
            assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(ReviewStateError::ArtifactCommitmentMismatch));
            assert!(f.ledger.is_empty());
        }
    }
    #[test]
    fn p0_acceptance_forbidden_execution_flag_c07() {
        let mut f = Fixture::new();
        for flags in [&mut f.bundle.candidate.payload.execution_flags, &mut f.bundle.attestation.payload.execution_flags,
            &mut f.bundle.acceptance.payload.execution_flags, &mut f.snapshot.execution_flags] { flags.push("--no-verify".into()); }
        f.resign();
        assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(ReviewStateError::ForbiddenExecutionFlag));
    }
    #[test]
    fn p0_acceptance_controls_and_policy_drift_c08() {
        for fault in 0..3 {
            let mut f = Fixture::new();
            match fault {
                0 => f.snapshot.task_control_digest = Sha256Digest([8; 32]),
                1 => f.snapshot.completion_policy_digest = Sha256Digest([8; 32]),
                _ => f.policy.writer_epoch += 1,
            }
            assert!(matches!(refused(f.authorize()), AcceptanceError::PolicyCommitmentMismatch
                | AcceptanceError::ReviewState(ReviewStateError::PolicyCommitmentMismatch)));
            assert_eq!(f.state.state, TaskReviewLifecycleState::InvalidatedStale);
        }
    }
    #[test]
    fn p0_acceptance_target_mutation_c09() {
        for fault in 0..3 {
            let mut f = Fixture::new();
            match fault { 0 => f.snapshot.task_status_rev += 1, 1 => f.snapshot.owner_actor = None,
                _ => f.snapshot.status = CanonicalTaskStatus::InProgress }
            assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(ReviewStateError::TargetTaskRevisionConflict));
        }
    }
    #[test]
    fn p0_acceptance_bounded_unrelated_cas_c10() {
        for count in 0..=3 {
            let mut f = Fixture::new(); f.current.file_cas_rev += u64::from(count);
            let result = f.authorize_at(HostClockState::Verified { now_unix: 100 }, count);
            if count <= 2 { assert!(matches!(result, Ok(AuthorizedAcceptanceOutcomeV1::Authorized(_)))); }
            else { assert_eq!(refused(result), AcceptanceError::ReviewState(ReviewStateError::RebaseLimitExceeded)); }
        }
        let mut f = Fixture::new(); f.current.file_cas_rev += 100;
        assert_eq!(refused(f.authorize_at(HostClockState::Verified { now_unix: 100 }, 1)),
            AcceptanceError::ReviewState(ReviewStateError::RebaseLimitExceeded));
        let mut f = Fixture::new(); f.current.file_cas_rev += 1;
        assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(ReviewStateError::RebaseLimitExceeded));
    }
    #[test]
    fn p0_acceptance_dependency_gate_c11() {
        for fault in 0..5 {
            let mut f = Fixture::new(); f.dependency();
            match fault {
                0 => f.dependencies.clear(), 1 => f.dependencies[0].resolved.status = TaskStatus::DonePendingReview,
                2 => f.dependencies[0].resolved.task_ref.task_spec_digest = Sha256Digest([8; 32]),
                3 => f.dependencies[0].resolved.completion_policy_digest = Sha256Digest([8; 32]),
                _ => f.dependencies[0].current_source.source_generation += 1,
            }
            assert_eq!(refused(f.authorize()), AcceptanceError::DependencyUnsatisfied);
            assert_eq!(f.state.state, TaskReviewLifecycleState::NotSubmitted);
            assert!(f.ledger.is_empty());
        }
        let mut f = Fixture::new(); f.dependency(); assert!(f.authorize().is_ok());
    }
    #[test]
    fn p0_acceptance_exact_replay_never_advances_twice_c12() {
        let mut f = Fixture::new(); assert!(f.authorize().is_ok());
        let before = f.state.clone(); let count = f.ledger.len();
        assert!(matches!(f.authorize(), Ok(AuthorizedAcceptanceOutcomeV1::IdempotentDuplicate { revalidated: Some(_) })));
        assert_eq!(f.state, before); assert_eq!(f.ledger.len(), count);
        assert_eq!(refused(f.authorize_at(HostClockState::Verified { now_unix: 106 }, 0)), AcceptanceError::ClockFenceHeld);
        assert_eq!(f.state.state, TaskReviewLifecycleState::HeldConflict);
        assert_eq!(f.ledger.len(), count);
    }
    #[test]
    fn p0_acceptance_conflicting_replay_holds_c12() {
        let mut f = Fixture::new(); assert!(f.authorize().is_ok()); let count = f.ledger.len();
        f.bundle.candidate.payload.submitted_at_unix -= 1; f.resign();
        assert_eq!(refused(f.authorize()), AcceptanceError::ReviewState(ReviewStateError::ReplayPayloadConflict));
        assert_eq!(f.state.state, TaskReviewLifecycleState::HeldConflict); assert_eq!(f.ledger.len(), count);
    }
    #[test]
    fn p0_acceptance_clock_fences_and_boundaries_c13() {
        for clock in [HostClockState::ClockRollback, HostClockState::TimeUnavailable,
            HostClockState::Verified { now_unix: 94 }, HostClockState::Verified { now_unix: 106 }] {
            let mut f = Fixture::new(); assert_eq!(refused(f.authorize_at(clock, 0)), AcceptanceError::ClockFenceHeld);
            assert_eq!(f.state.state, TaskReviewLifecycleState::HeldConflict); assert!(f.ledger.is_empty());
        }
        let mut f = Fixture::new(); f.bundle.acceptance.payload.accepted_at_unix = 95; f.resign();
        assert!(f.authorize_at(HostClockState::Verified { now_unix: 95 }, 0).is_ok());
        let mut f = Fixture::new(); assert!(f.authorize_at(HostClockState::Verified { now_unix: 105 }, 0).is_ok());
    }
    #[test]
    fn p0_acceptance_signature_schema_and_domain_c13() {
        for fault in 0..5 {
            let mut f = Fixture::new();
            match fault {
                0 => f.bundle.candidate.signature_ed25519[0] ^= 1,
                1 => f.bundle.attestation.signature_ed25519[0] ^= 1,
                2 => f.bundle.acceptance.signature_ed25519[0] ^= 1,
                3 => { f.bundle.candidate.payload.schema_version = "other".into(); f.resign(); }
                _ => f.bundle.attestation.payload_kind = TASK_ACCEPTANCE_SCHEMA_V1.into(),
            }
            assert!(matches!(refused(f.authorize()), AcceptanceError::SignatureInvalid | AcceptanceError::SchemaVersionMismatch));
            assert_eq!(f.state.state, TaskReviewLifecycleState::NotSubmitted); assert!(f.ledger.is_empty());
        }
        let mut f = Fixture::new();
        f.bundle.candidate.signature_ed25519 = SecretKey::from_bytes(&[1; 32]).sign(b"chinwag-task-acceptance-v1\0").to_bytes();
        assert_eq!(refused(f.authorize()), AcceptanceError::SignatureInvalid);
    }
    #[test]
    fn p0_acceptance_strict_json_rejects_ambiguity_c14() {
        assert_eq!(parse_signed_acceptance_bundle(&"x".repeat(MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES + 1)).unwrap_err(), AcceptanceError::PayloadTooLarge);
        assert_eq!(parse_signed_acceptance_bundle("{\"x\":1,\"\\u0078\":2}").unwrap_err(), AcceptanceError::DuplicateJsonKey);
        let f = Fixture::new(); let raw = serde_json::to_string(&f.bundle).unwrap();
        let unknown = raw.replacen('{', "{\"unknown\":true,", 1);
        assert_eq!(parse_signed_acceptance_bundle(&unknown).unwrap_err(), AcceptanceError::InvalidJson);
        let nested = raw.replacen("\"task_id\":\"P0-06\"", "\"task_id\":\"P0-06\",\"task_id\":\"P0-06\"", 1);
        assert_eq!(parse_signed_acceptance_bundle(&nested).unwrap_err(), AcceptanceError::DuplicateJsonKey);
        assert!(parse_signed_acceptance_bundle(&(raw + " false")).is_err());
    }
    #[test]
    fn p0_acceptance_structural_bounds_precede_mutation_c14() {
        for fault in 0..5 {
            let mut f = Fixture::new();
            match fault {
                0 => f.bundle.candidate.payload.evidence_digests = vec![Sha256Digest([4; 32]); 65],
                1 => f.bundle.attestation.payload.required_checks = vec![f.bundle.attestation.payload.required_checks[0].clone(); 65],
                2 => f.bundle.attestation.payload.findings = vec![ReviewFindingV1 { finding_id: "f".into(), severity: FindingSeverity::Info, blocking: false, summary: "info".into() }; 65],
                3 => f.bundle.candidate.payload.verification_checks_passed = vec!["check".into(); 65],
                _ => f.bundle.acceptance.payload.display_text = Some("x".repeat(4097)),
            }
            let before = f.state.clone();
            assert_eq!(refused(f.authorize()), AcceptanceError::StructuralLimitExceeded);
            assert_eq!(f.state, before); assert!(f.ledger.is_empty());
            let raw = serde_json::to_string(&f.bundle).unwrap(); assert!(parse_signed_acceptance_bundle(&raw).is_err());
        }
    }
    #[test]
    fn p0_acceptance_display_is_non_authoritative() {
        let mut f = Fixture::new(); let digests = (f.bundle.candidate.payload.canonical_digest(),
            f.bundle.attestation.payload.canonical_digest(), f.bundle.acceptance.payload.canonical_digest());
        f.bundle.candidate.payload.display_text = Some("DONE".into());
        f.bundle.attestation.payload.display_text = Some("LGTM".into());
        f.bundle.acceptance.payload.display_text = Some("COMPLETED".into());
        assert_eq!(digests, (f.bundle.candidate.payload.canonical_digest(), f.bundle.attestation.payload.canonical_digest(), f.bundle.acceptance.payload.canonical_digest()));
        assert!(f.authorize().is_ok());
    }
    #[test]
    fn p0_acceptance_complete_signed_bundle_golden_pipeline() {
        let mut f = Fixture::new(); let raw = serde_json::to_string(&f.bundle).unwrap();
        let result = parse_and_verify_acceptance_bundle(&raw, AcceptanceVerificationContextV1 {
            task_snapshot: &f.snapshot, current_target_task_ref: &f.current, rebases_used: 0,
            completion_policy: &f.policy, dependency_snapshots: &f.dependencies, clock: HostClockState::Verified { now_unix: 100 },
            review_state: &mut f.state, replay_ledger: &mut f.ledger,
        }).unwrap();
        let AuthorizedAcceptanceOutcomeV1::Authorized(token) = result else { panic!("fresh proposal expected") };
        assert_eq!(token.acceptance_digest(), f.bundle.acceptance.payload.canonical_digest());
        assert_eq!(token.attestation_digest(), f.bundle.attestation.payload.canonical_digest());
        assert_eq!(token.candidate_digest(), f.bundle.candidate.payload.canonical_digest());
        assert_eq!(token.acceptance().committed_task_status_rev, 5);
        assert_eq!(f.state.state, TaskReviewLifecycleState::ReviewAttestedPass); assert_eq!(f.ledger.len(), 3);
        let bridge = token.into_transition_authorization(authenticated_authority(&f));
        let TransitionAuthorization::ReviewedAcceptance(proof) = bridge.authorization() else {
            panic!("typed writer review authorization expected")
        };
        assert_eq!(proof.reviewed_task_ref, f.current);
        assert_eq!(proof.candidate_commit, f.bundle.candidate.payload.candidate_commit);
        assert_eq!(bridge.verified_acceptance().acceptance_digest(), f.bundle.acceptance.payload.canonical_digest());
        assert_eq!(bridge.verified_acceptance().signed_bundle().candidate.signature_ed25519,
            f.bundle.candidate.signature_ed25519);
    }
    #[test]
    fn p0_acceptance_candidate_canonical_golden_vector() {
        let mut f = Fixture::new(); f.bundle.candidate.payload.completion_policy_digest = Sha256Digest([3; 32]);
        let c = &f.bundle.candidate.payload;
        assert!(c.canonical_bytes().starts_with(TASK_CANDIDATE_DOMAIN_V1));
        assert_eq!(c.canonical_digest().to_string(), "7c54574741fbb907461b73d43c9efb5f528fd140e7f4ea6f0428e1ba841f51ea");
        assert_eq!(c.canonical_bytes().len(), 678);
        assert_ne!(Sha256Digest::of(&[REVIEW_ATTESTATION_DOMAIN_V1, &c.canonical_bytes()[TASK_CANDIDATE_DOMAIN_V1.len()..]].concat()), c.canonical_digest());
    }
    #[test]
    fn p0_acceptance_signed_chain_and_revision_substitutions() {
        for fault in 0..4 {
            let mut f = Fixture::new();
            match fault {
                0 => { f.bundle.attestation.payload.candidate_operation_id = "other".into(); f.resign(); }
                1 => { f.bundle.acceptance.payload.attestation_id = "other".into(); f.resign(); }
                2 => { f.bundle.acceptance.payload.committed_task_status_rev = 6; f.resign(); }
                _ => { f.bundle.acceptance.payload.evidence_digests = vec![Sha256Digest([7; 32])]; f.resign(); }
            }
            assert!(f.authorize().is_err()); assert!(f.ledger.is_empty());
        }
        let mut f = Fixture::new(); f.bundle.attestation.payload.verdict = ReviewVerdict::RequestChanges;
        f.resign(); assert_eq!(refused(f.authorize()), AcceptanceError::ReviewVerdictNotPass);
        // Rework needs a new candidate and a wholly new operation chain.
        f.bundle.candidate.payload.operation_id = "candidate-op-2".into();
        f.bundle.candidate.payload.message_id = "candidate-msg-2".into();
        f.bundle.candidate.payload.submitted_at_unix = 91;
        f.bundle.attestation.payload.operation_id = "review-op-2".into();
        f.bundle.attestation.payload.message_id = "review-msg-2".into();
        f.bundle.attestation.payload.attestation_id = "review-id-2".into();
        f.bundle.attestation.payload.candidate_operation_id = "candidate-op-2".into();
        f.bundle.attestation.payload.verdict = ReviewVerdict::Pass;
        f.bundle.acceptance.payload.operation_id = "accept-op-2".into();
        f.bundle.acceptance.payload.message_id = "accept-msg-2".into();
        f.bundle.acceptance.payload.candidate_operation_id = "candidate-op-2".into();
        f.bundle.acceptance.payload.attestation_id = "review-id-2".into();
        f.resign(); assert!(f.authorize().is_ok());
        assert_eq!(f.state.state, TaskReviewLifecycleState::ReviewAttestedPass);
        assert_eq!(f.ledger.len(), 6);
        assert_eq!(checked_next_revision(crate::task_ref::MAX_REV_COUNTER), Err(TaskContractError::RevisionExhausted));
    }
}
