#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Exact source-qualified transcripts and a sealed, finite **fixture-only** verifier.
//! Production legacy compatibility, custody, content and time profiles are unpinned:
//! ProductionHeld is unconditional. Fixture capabilities cannot be deserialized,
//! constructed by caller providers, or converted into production writer authority.
//! Supplemental fixture evidence uses a separate fixture domain and is never an
//! extension of the preserved PRD ReviewAttestationV1 signed schema.

use crate::task_dependency::{
    DependencySourceBinding, ResolvedDependency, validate_dependency_satisfaction,
};
use crate::task_ref::{
    GitOid, Sha256Digest, TaskContractError, TaskRefV1, checked_next_revision, encode_bytes_field,
    encode_str_field, encode_u64, validate_id,
};
use crate::task_writer::{CanonicalTaskStatus, TaskEntrySnapshotV1};
use iroh::{EndpointId, Signature};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES: usize = 65_536;
pub const MAX_DISPLAY_TEXT_UTF8_BYTES: usize = 4096;
pub const MAX_EVIDENCE_DIGESTS_PER_CANDIDATE: usize = 64;
pub const MAX_REQUIRED_CHECKS_PER_ATTESTATION: usize = 64;
pub const TASK_CANDIDATE_DOMAIN_V1: &[u8] = b"chinwag-task-candidate-v1\0";
pub const TASK_ACCEPTANCE_DOMAIN_V1: &[u8] = b"chinwag-task-acceptance-v1\0";
pub const REVIEW_ATTESTATION_DOMAIN_V1: &[u8] = b"chinwag-review-attestation-v1";
pub const REVIEW_HOST_DOMAIN_V1: &[u8] = b"chinwag-host-countersign-v1";
pub const ACCEPTANCE_HOST_DOMAIN_V1: &[u8] = b"chinwag-task-acceptance-host-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptanceError {
    UnsupportedLegacyReviewProfileHeld,
    UntrustedFixtureProviderHeld,
    FixtureProvenanceNotProduction,
    FixtureNamespaceMismatch,
    UnsupportedAuthorityProfileHeld,
    UnsupportedContainmentProfileHeld,
    UnsupportedCustodyProfileHeld,
    UnsupportedContentProfileHeld,
    UnsupportedRoughtimeProfileHeld,
    ClockFenceHeld,
    HighwaterRollback,
    ProseCompletionForbidden,
    PayloadTooLarge,
    StructuralLimitExceeded,
    DuplicateJsonKey,
    InvalidJson,
    SchemaVersionMismatch,
    SignatureInvalid,
    SignerBindingMismatch,
    CandidateBindingMismatch,
    AttestationBindingMismatch,
    AssignmentBindingMismatch,
    SubmissionHistoryMismatch,
    CurrentBindingMismatch,
    PolicyCommitmentMismatch,
    SelfReviewForbidden,
    UnauthorizedReviewerRole,
    QuorumNotSatisfied,
    DuplicateReviewer,
    DependencyUnsatisfied,
    RejectedReview,
    Contract(TaskContractError),
}
impl fmt::Display for AcceptanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "acceptance held: {self:?}")
    }
}
impl std::error::Error for AcceptanceError {}
impl From<TaskContractError> for AcceptanceError {
    fn from(e: TaskContractError) -> Self {
        Self::Contract(e)
    }
}

pub(crate) mod digest_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &Sha256Digest, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Sha256Digest, D::Error> {
        Sha256Digest::from_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
pub(crate) mod oid_json {
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
    pub fn serialize<S: serde::Serializer>(
        value: &Option<Sha256Digest>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|digest| digest.to_string()).serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Sha256Digest>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|value| Sha256Digest::from_hex(&value))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}
mod digest_list_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        values: &[Sha256Digest],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = s.serialize_seq(Some(values.len()))?;
        for value in values {
            sequence.serialize_element(&value.to_string())?;
        }
        sequence.end()
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<Sha256Digest>, D::Error> {
        struct Digests;
        impl<'de> Visitor<'de> for Digests {
            type Value = Vec<Sha256Digest>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("at most 64 digests")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
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
pub(crate) mod key_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        digest_json::serialize(&Sha256Digest(*value), s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        digest_json::deserialize(d).map(|digest| digest.0)
    }
}
pub(crate) mod signature_json {
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
        raw[..32].copy_from_slice(
            &Sha256Digest::from_hex(&value[..64])
                .map_err(serde::de::Error::custom)?
                .0,
        );
        raw[32..].copy_from_slice(
            &Sha256Digest::from_hex(&value[64..])
                .map_err(serde::de::Error::custom)?
                .0,
        );
        Ok(raw)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "TaskRefV1", deny_unknown_fields)]
pub(crate) struct TaskRefJson {
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
pub struct PublicationBindingV1 {
    pub publication_repo_id: String,
    #[serde(with = "oid_json")]
    pub publication_commit_oid: GitOid,
    #[serde(with = "digest_json")]
    pub publication_manifest_sha256: Sha256Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCandidateV1 {
    #[serde(with = "TaskRefJson")]
    pub original_assignment_task_ref: TaskRefV1,
    pub assignment_id: String,
    pub operation_id: String,
    pub author_principal: String,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    pub result_repo_id: String,
    #[serde(with = "oid_json")]
    pub result_code_commit_oid: GitOid,
    #[serde(with = "digest_json")]
    pub result_tree_sha256: Sha256Digest,
    pub publication: Option<PublicationBindingV1>,
    #[serde(with = "digest_list_json")]
    pub evidence_sha256: Vec<Sha256Digest>,
    #[serde(with = "digest_json")]
    pub policy_digest: Sha256Digest,
    pub review_round: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewVerdict {
    Approved,
    Rejected,
}
impl ReviewVerdict {
    fn text(self) -> &'static str {
        match self {
            Self::Approved => "Approved",
            Self::Rejected => "Rejected",
        }
    }
}

/// Exact PRD field list. OS containment and supplemental checks are external evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAttestationV1 {
    pub repo_id: String,
    pub task_id: String,
    #[serde(with = "digest_json")]
    pub task_spec_digest: Sha256Digest,
    pub assignment_id: String,
    pub operation_id: String,
    #[serde(with = "oid_json")]
    pub artifact_commit_oid: GitOid,
    pub jj_change_id: Option<String>,
    pub review_round: u64,
    pub author_id: String,
    pub reviewer_id: String,
    pub reviewer_role: String,
    pub verdict: ReviewVerdict,
    #[serde(with = "digest_json")]
    pub policy_digest: Sha256Digest,
    pub roughtime_midpoint_us: u64,
    pub roughtime_radius_us: u64,
    pub roughtime_server_ids: Vec<String>,
    #[serde(with = "key_json")]
    pub k1_pubkey: [u8; 32],
    #[serde(with = "signature_json")]
    pub k1_sig: [u8; 64],
    #[serde(with = "key_json")]
    pub k2_pubkey: [u8; 32],
    #[serde(with = "signature_json")]
    pub k2_sig: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAcceptanceV1 {
    #[serde(with = "TaskRefJson")]
    pub task_ref: TaskRefV1,
    pub expected_task_status_rev: u64,
    pub expected_file_cas_rev: u64,
    pub assignment_id: String,
    pub operation_id: String,
    #[serde(with = "digest_json")]
    pub candidate_digest: Sha256Digest,
    pub result_repo_id: String,
    #[serde(with = "oid_json")]
    pub result_code_commit_oid: GitOid,
    #[serde(with = "digest_json")]
    pub result_tree_sha256: Sha256Digest,
    pub publication: Option<PublicationBindingV1>,
    #[serde(with = "digest_list_json")]
    pub evidence_sha256: Vec<Sha256Digest>,
    #[serde(with = "digest_json")]
    pub verified_review_record_sha256: Sha256Digest,
    pub author_principal: String,
    pub reviewer_principal: String,
    pub reviewer_full_instance: String,
    pub reviewer_role: String,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub policy_digest: Sha256Digest,
    pub review_round: u64,
    pub verdict: ReviewVerdict,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(with = "key_json")]
    pub nonce: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEvidenceV1 {
    #[serde(with = "key_json")]
    pub public_key: [u8; 32],
    #[serde(with = "signature_json")]
    pub signature: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCandidateV1 {
    pub payload: TaskCandidateV1,
    pub author_k1: SignatureEvidenceV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTaskAcceptanceV1 {
    pub payload: TaskAcceptanceV1,
    pub reviewer_k1: SignatureEvidenceV1,
    pub host_k2: SignatureEvidenceV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAcceptanceBundleV1 {
    pub candidate: SignedCandidateV1,
    pub review: ReviewAttestationV1,
    pub acceptance: SignedTaskAcceptanceV1,
}

struct Transcript(Vec<u8>);
impl Transcript {
    fn new(domain: &[u8]) -> Self {
        Self(domain.to_vec())
    }
    fn b(&mut self, b: &[u8]) {
        self.0.extend(encode_bytes_field(b));
    }
    fn s(&mut self, s: &str) {
        self.0.extend(encode_str_field(s));
    }
    fn n(&mut self, n: u64) {
        self.0.extend(encode_u64(n));
    }
    fn wrapped_digest(&mut self, d: Sha256Digest) {
        self.b(&d.encode_typed());
    }
    fn publication(&mut self, p: &Option<PublicationBindingV1>) {
        self.0.push(u8::from(p.is_some()));
        if let Some(p) = p {
            self.s(&p.publication_repo_id);
            self.0.extend(p.publication_commit_oid.encode_typed());
            self.0.extend(p.publication_manifest_sha256.encode_typed());
        }
    }
    fn evidence(&mut self, ds: &[Sha256Digest]) -> Result<(), AcceptanceError> {
        if ds.len() > MAX_EVIDENCE_DIGESTS_PER_CANDIDATE {
            return Err(AcceptanceError::StructuralLimitExceeded);
        }
        let mut items: Vec<_> = ds.iter().map(Sha256Digest::encode_typed).collect();
        items.sort();
        if items.windows(2).any(|p| p[0] == p[1]) {
            return Err(TaskContractError::DuplicateSetItem.into());
        }
        self.n(items.len() as u64);
        for item in items {
            self.0.extend(item);
        }
        Ok(())
    }
}
impl TaskCandidateV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AcceptanceError> {
        self.validate()?;
        let mut t = Transcript::new(TASK_CANDIDATE_DOMAIN_V1);
        t.b(&self.original_assignment_task_ref.encode()?);
        t.s(&self.assignment_id);
        t.s(&self.operation_id);
        t.s(&self.author_principal);
        t.wrapped_digest(self.task_control_digest);
        t.s(&self.result_repo_id);
        t.b(&self.result_code_commit_oid.encode_typed());
        t.wrapped_digest(self.result_tree_sha256);
        t.publication(&self.publication);
        t.evidence(&self.evidence_sha256)?;
        t.wrapped_digest(self.policy_digest);
        t.n(self.review_round);
        Ok(t.0)
    }
    pub fn canonical_digest(&self) -> Result<Sha256Digest, AcceptanceError> {
        Ok(Sha256Digest::of(&self.canonical_bytes()?))
    }
    fn validate(&self) -> Result<(), AcceptanceError> {
        self.original_assignment_task_ref.validate()?;
        ids(&[
            &self.assignment_id,
            &self.operation_id,
            &self.author_principal,
            &self.result_repo_id,
        ])?;
        validate_publication(&self.publication)?;
        if self.review_round == 0 {
            return Err(AcceptanceError::CandidateBindingMismatch);
        }
        Ok(())
    }
}
impl ReviewAttestationV1 {
    /// Ratified finite FixtureProfileV1 only; NO production legacy codec claim.
    pub fn review_k1_transcript_bytes(&self) -> Result<Vec<u8>, AcceptanceError> {
        ids(&[
            &self.repo_id,
            &self.task_id,
            &self.assignment_id,
            &self.operation_id,
            &self.author_id,
            &self.reviewer_id,
            &self.reviewer_role,
        ])?;
        if let Some(id) = &self.jj_change_id {
            validate_id(id, "jj change id")?;
        }
        if self.review_round == 0
            || self.roughtime_server_ids.len() < 2
            || self.roughtime_server_ids.len() > 64
        {
            return Err(AcceptanceError::UnsupportedRoughtimeProfileHeld);
        }
        let mut t = Transcript::new(REVIEW_ATTESTATION_DOMAIN_V1);
        t.s(&self.repo_id);
        t.s(&self.task_id);
        t.0.extend(self.task_spec_digest.encode_typed());
        t.s(&self.assignment_id);
        t.s(&self.operation_id);
        t.0.extend(self.artifact_commit_oid.encode_typed());
        t.0.push(u8::from(self.jj_change_id.is_some()));
        if let Some(id) = &self.jj_change_id {
            t.s(id);
        }
        t.n(self.review_round);
        t.s(&self.author_id);
        t.s(&self.reviewer_id);
        t.s(&self.reviewer_role);
        t.s(self.verdict.text());
        t.0.extend(self.policy_digest.encode_typed());
        t.n(self.roughtime_midpoint_us);
        t.n(self.roughtime_radius_us);
        let mut servers = Vec::new();
        for id in &self.roughtime_server_ids {
            validate_id(id, "roughtime server")?;
            servers.push(encode_str_field(id));
        }
        servers.sort();
        if servers.windows(2).any(|p| p[0] == p[1]) {
            return Err(TaskContractError::DuplicateSetItem.into());
        }
        t.n(servers.len() as u64);
        for server in servers {
            t.0.extend(server);
        }
        Ok(t.0)
    }
    pub fn review_k2_transcript_bytes(&self) -> Result<Vec<u8>, AcceptanceError> {
        let mut t = REVIEW_HOST_DOMAIN_V1.to_vec();
        t.extend(Sha256Digest::of(&self.review_k1_transcript_bytes()?).0);
        Ok(t)
    }
    pub fn complete_record_bytes(&self) -> Result<Vec<u8>, AcceptanceError> {
        let mut t = Transcript(self.review_k1_transcript_bytes()?);
        t.b(&self.k1_pubkey);
        t.b(&self.k1_sig);
        t.b(&self.k2_pubkey);
        t.b(&self.k2_sig);
        Ok(t.0)
    }
    /// A digest is informational until both signatures and current evidence verify.
    pub fn complete_record_digest(&self) -> Result<Sha256Digest, AcceptanceError> {
        Ok(Sha256Digest::of(&self.complete_record_bytes()?))
    }
}
impl TaskAcceptanceV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AcceptanceError> {
        self.task_ref.validate()?;
        ids(&[
            &self.assignment_id,
            &self.operation_id,
            &self.result_repo_id,
            &self.author_principal,
            &self.reviewer_principal,
            &self.reviewer_full_instance,
            &self.reviewer_role,
        ])?;
        validate_publication(&self.publication)?;
        if self.expected_task_status_rev != self.task_ref.task_status_rev
            || self.expected_file_cas_rev != self.task_ref.file_cas_rev
        {
            return Err(AcceptanceError::CurrentBindingMismatch);
        }
        let mut t = Transcript::new(TASK_ACCEPTANCE_DOMAIN_V1);
        t.b(&self.task_ref.encode()?);
        t.n(self.expected_task_status_rev);
        t.n(self.expected_file_cas_rev);
        t.s(&self.assignment_id);
        t.s(&self.operation_id);
        t.wrapped_digest(self.candidate_digest);
        t.s(&self.result_repo_id);
        t.b(&self.result_code_commit_oid.encode_typed());
        t.wrapped_digest(self.result_tree_sha256);
        t.publication(&self.publication);
        t.evidence(&self.evidence_sha256)?;
        t.wrapped_digest(self.verified_review_record_sha256);
        t.s(&self.author_principal);
        t.s(&self.reviewer_principal);
        t.s(&self.reviewer_full_instance);
        t.s(&self.reviewer_role);
        t.wrapped_digest(self.task_control_digest);
        t.wrapped_digest(self.policy_digest);
        t.n(self.review_round);
        t.s(self.verdict.text());
        t.n(self.issued_at_unix);
        t.n(self.expires_at_unix);
        t.b(&self.nonce);
        Ok(t.0)
    }
    pub fn canonical_digest(&self) -> Result<Sha256Digest, AcceptanceError> {
        Ok(Sha256Digest::of(&self.canonical_bytes()?))
    }
}
impl SignedTaskAcceptanceV1 {
    pub fn acceptance_host_transcript_bytes(&self) -> Result<Vec<u8>, AcceptanceError> {
        let mut t = Transcript::new(ACCEPTANCE_HOST_DOMAIN_V1);
        t.0.extend(self.payload.canonical_digest()?.encode_typed());
        t.b(&self.reviewer_k1.public_key);
        t.b(&self.reviewer_k1.signature);
        Ok(t.0)
    }
}
fn ids(values: &[&str]) -> Result<(), AcceptanceError> {
    for id in values {
        validate_id(id, "review identity")?;
    }
    Ok(())
}
fn validate_publication(p: &Option<PublicationBindingV1>) -> Result<(), AcceptanceError> {
    if let Some(p) = p {
        validate_id(&p.publication_repo_id, "publication repository")?;
    }
    Ok(())
}
pub(crate) fn verify_strict(
    key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), AcceptanceError> {
    EndpointId::from_bytes(key)
        .map_err(|_| AcceptanceError::SignatureInvalid)?
        .verify(message, &Signature::from_bytes(signature))
        .map_err(|_| AcceptanceError::SignatureInvalid)
}
pub fn reject_prose_completion_claim(_: &str) -> AcceptanceError {
    AcceptanceError::ProseCompletionForbidden
}
/// A streaming structural preflight runs before the typed parser allocates lists.
/// The raw frame is bounded first; object keys, strings and every array are finite.
fn preflight_json(raw: &str) -> Result<(), AcceptanceError> {
    if raw.len() > MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES {
        return Err(AcceptanceError::PayloadTooLarge);
    }
    if !raw.trim_start().starts_with('{') {
        return Err(reject_prose_completion_claim(raw));
    }
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
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for JsonGuard<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded strict proposal JSON")
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
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() > MAX_DISPLAY_TEXT_UTF8_BYTES {
            *self.0 = Some(AcceptanceError::StructuralLimitExceeded);
            return Err(E::custom("JSON string limit"));
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let mut count = 0;
        while sequence
            .next_element_seed(JsonGuard(&mut *self.0))?
            .is_some()
        {
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

pub fn parse_signed_acceptance_bundle(
    raw: &str,
) -> Result<SignedAcceptanceBundleV1, AcceptanceError> {
    preflight_json(raw)?;
    serde_json::from_str(raw).map_err(|_| AcceptanceError::InvalidJson)
}

/// Public selection is a request, never admission or authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LegacyReviewProfileMode {
    #[default]
    ProductionHeld,
    FixtureProfileV1,
}
mod provider_seal {
    pub trait Sealed {}
}
/// Arbitrary callers cannot opt themselves into fixture admission.
/// ```compile_fail
/// use chinwag_cli::task_acceptance::{LegacyReviewVerifierProvider, TrustedFixtureVerifier};
/// struct Untrusted;
/// impl LegacyReviewVerifierProvider for Untrusted {
///     fn admitted_fixture(&self) -> Option<&TrustedFixtureVerifier> { None }
/// }
/// ```
pub trait LegacyReviewVerifierProvider: provider_seal::Sealed {
    #[doc(hidden)]
    fn admitted_fixture(&self) -> Option<&TrustedFixtureVerifier>;
}
#[derive(Default)]
pub struct ProductionHeldVerifier;
impl provider_seal::Sealed for ProductionHeldVerifier {}
impl LegacyReviewVerifierProvider for ProductionHeldVerifier {
    fn admitted_fixture(&self) -> Option<&TrustedFixtureVerifier> {
        None
    }
}
/// No public constructor, Deserialize, mode setter, or caller-implemented provider.
/// Only controlled in-module fixture admission constructs this provider. ROOT must
/// separately integrate an approved production trust boundary before any live use.
#[derive(Debug)]
pub struct TrustedFixtureVerifier {
    provenance: FixtureProvenanceV1,
    authority_root: [u8; 32],
    roughtime_servers: Vec<(String, [u8; 32])>,
    policy_digest: Sha256Digest,
}
impl provider_seal::Sealed for TrustedFixtureVerifier {}
impl LegacyReviewVerifierProvider for TrustedFixtureVerifier {
    fn admitted_fixture(&self) -> Option<&TrustedFixtureVerifier> {
        Some(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixtureProvenanceV1 {
    pub(crate) profile: String,
    pub(crate) context: String,
    pub(crate) workspace_id: String,
    pub(crate) task_source_id: String,
    pub(crate) canonical_task_path: String,
    pub(crate) namespace_dev: u64,
    pub(crate) namespace_ino: u64,
    #[serde(with = "digest_json")]
    pub(crate) admission_digest: Sha256Digest,
}
impl TrustedFixtureVerifier {
    pub(crate) fn provenance(&self) -> &FixtureProvenanceV1 {
        &self.provenance
    }
    fn check_mode<'a, P: LegacyReviewVerifierProvider>(
        p: &'a P,
        mode: LegacyReviewProfileMode,
    ) -> Result<&'a Self, AcceptanceError> {
        if mode == LegacyReviewProfileMode::ProductionHeld {
            return Err(AcceptanceError::UnsupportedLegacyReviewProfileHeld);
        }
        p.admitted_fixture()
            .ok_or(AcceptanceError::UntrustedFixtureProviderHeld)
    }
}

/// Fixture supplemental codecs are deliberately separate from normative transcripts.
/// They attest exact current bindings under the privately admitted fixture root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixturePrincipalV1 {
    pub principal: String,
    pub instance: String,
    pub role: String,
    #[serde(with = "key_json")]
    pub k1: [u8; 32],
    pub revoked: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCurrentAuthorityV1 {
    pub profile: String,
    pub context: String,
    pub authority_epoch: u64,
    pub writer_epoch: u64,
    pub writer_principal: String,
    pub owner_principal: String,
    pub principals: Vec<FixturePrincipalV1>,
    pub named_reviewers: Vec<String>,
    pub quorum: u64,
    #[serde(with = "digest_json")]
    pub policy_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    pub valid_from_us: u64,
    pub valid_until_us: u64,
    pub containment_profile: String,
    pub custody_profile: String,
    pub content_profile: String,
    pub fork_profile: String,
    pub publication_profile: String,
    #[serde(with = "key_json")]
    pub review_k2: [u8; 32],
    #[serde(with = "key_json")]
    pub acceptance_k2: [u8; 32],
    pub k2_purposes: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureScopeEvidenceV1 {
    pub context: String,
    pub reviewer_principal: String,
    pub reviewer_instance: String,
    pub containment_profile: String,
    pub os_user: String,
    pub seatbelt_profile: String,
    #[serde(with = "digest_json")]
    pub acceptance_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub review_transcript_digest: Sha256Digest,
    #[serde(with = "key_json")]
    pub nonce: [u8; 32],
    pub result_repo_id: String,
    #[serde(with = "oid_json")]
    pub result_commit: GitOid,
    #[serde(with = "digest_json")]
    pub result_tree_sha256: Sha256Digest,
    pub publication: Option<PublicationBindingV1>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFixtureEvidenceV1<T> {
    pub payload: T,
    pub signature: SignatureEvidenceV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureTimeResponseV1 {
    pub profile: String,
    pub context: String,
    pub server_id: String,
    #[serde(with = "key_json")]
    pub nonce: [u8; 32],
    pub midpoint_us: u64,
    pub radius_us: u64,
    pub response_elapsed_ms: u64,
    #[serde(with = "digest_json")]
    pub acceptance_digest: Sha256Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureVerificationEvidenceV1 {
    pub authority: SignedFixtureEvidenceV1<FixtureCurrentAuthorityV1>,
    pub scope: SignedFixtureEvidenceV1<FixtureScopeEvidenceV1>,
    pub time: Vec<SignedFixtureEvidenceV1<FixtureTimeResponseV1>>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewHighwaterV1 {
    pub authority_epoch: u64,
    pub writer_epoch: u64,
    pub roughtime_us: u64,
}
impl ReviewHighwaterV1 {
    pub fn permits(&self, next: Self) -> bool {
        next.authority_epoch >= self.authority_epoch
            && next.writer_epoch >= self.writer_epoch
            && next.roughtime_us >= self.roughtime_us
    }
}
pub(crate) fn fixture_statement<T: Serialize>(
    purpose: &str,
    value: &T,
) -> Result<Vec<u8>, AcceptanceError> {
    let mut out = Transcript::new(b"chinwag-controlled-fixture-evidence-v1\0");
    out.s(purpose);
    let mut writer = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| AcceptanceError::PayloadTooLarge)?;
    out.b(&writer.0);
    Ok(out.0)
}
fn verify_fixture_evidence<T: Serialize>(
    p: &TrustedFixtureVerifier,
    purpose: &str,
    e: &SignedFixtureEvidenceV1<T>,
) -> Result<(), AcceptanceError> {
    if e.signature.public_key != p.authority_root {
        return Err(AcceptanceError::SignerBindingMismatch);
    }
    verify_strict(
        &p.authority_root,
        &fixture_statement(purpose, &e.payload)?,
        &e.signature.signature,
    )
}
struct BoundedBytes(Vec<u8>);
impl std::io::Write for BoundedBytes {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("fixture record bound"));
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableAssignmentV1 {
    #[serde(with = "TaskRefJson")]
    pub original_task_ref: TaskRefV1,
    pub assignment_id: String,
    pub operation_id: String,
    pub author_principal: String,
    pub owner_principal: String,
    pub original_status: CanonicalTaskStatus,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub policy_digest: Sha256Digest,
    #[serde(with = "optional_digest_json")]
    pub overlay_commitment: Option<Sha256Digest>,
    pub review_round: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSubmissionTransitionV1 {
    #[serde(with = "TaskRefJson")]
    pub prior: TaskRefV1,
    #[serde(with = "TaskRefJson")]
    pub next: TaskRefV1,
    pub assignment_id: String,
    pub operation_id: String,
    #[serde(with = "digest_json")]
    pub assignment_record_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub candidate_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub task_control_digest: Sha256Digest,
    #[serde(with = "digest_json")]
    pub policy_digest: Sha256Digest,
    pub review_round: u64,
    pub status: CanonicalTaskStatus,
}
pub type SignedFixtureAssignmentV1 = SignedFixtureEvidenceV1<ImmutableAssignmentV1>;
pub type SignedFixtureSubmissionV1 = SignedFixtureEvidenceV1<QualifiedSubmissionTransitionV1>;
pub(crate) fn assignment_digest(
    a: &SignedFixtureAssignmentV1,
) -> Result<Sha256Digest, AcceptanceError> {
    Ok(Sha256Digest::of(&fixture_statement(
        "complete-assignment-record",
        a,
    )?))
}
pub(crate) fn verify_assignment(
    p: &TrustedFixtureVerifier,
    a: &SignedFixtureAssignmentV1,
) -> Result<(), AcceptanceError> {
    a.payload.original_task_ref.validate()?;
    ids(&[
        &a.payload.assignment_id,
        &a.payload.operation_id,
        &a.payload.author_principal,
        &a.payload.owner_principal,
    ])?;
    if a.payload.original_task_ref.workspace_id != p.provenance.workspace_id
        || a.payload.original_task_ref.task_source_id != p.provenance.task_source_id
        || a.payload.original_task_ref.canonical_task_path != p.provenance.canonical_task_path
        || p.provenance.profile != "FixtureProfileV1"
        || a.payload.policy_digest != p.policy_digest
        || a.payload.review_round == 0
    {
        return Err(AcceptanceError::PolicyCommitmentMismatch);
    }
    verify_fixture_evidence(p, "immutable-assignment", a)
}
fn stable_ref(a: &TaskRefV1, b: &TaskRefV1) -> bool {
    a.workspace_id == b.workspace_id
        && a.repo_id == b.repo_id
        && a.task_source_id == b.task_source_id
        && a.source_generation == b.source_generation
        && a.canonical_task_path == b.canonical_task_path
        && a.task_id == b.task_id
        && a.task_spec_digest == b.task_spec_digest
        && a.baseline_commit == b.baseline_commit
}
pub(crate) fn verify_history(
    p: &TrustedFixtureVerifier,
    a: &SignedFixtureAssignmentV1,
    c: &SignedCandidateV1,
    chain: &[SignedFixtureSubmissionV1],
    pending: &TaskRefV1,
) -> Result<(), AcceptanceError> {
    verify_history_prefix(p, a, c, chain)?;
    let last = chain
        .last()
        .ok_or(AcceptanceError::SubmissionHistoryMismatch)?;
    if &last.payload.next != pending
        || last.payload.status != CanonicalTaskStatus::DonePendingReview
    {
        return Err(AcceptanceError::SubmissionHistoryMismatch);
    }
    Ok(())
}
pub(crate) fn verify_history_prefix(
    p: &TrustedFixtureVerifier,
    a: &SignedFixtureAssignmentV1,
    c: &SignedCandidateV1,
    chain: &[SignedFixtureSubmissionV1],
) -> Result<(), AcceptanceError> {
    verify_assignment(p, a)?;
    let assignment = &a.payload;
    let candidate = &c.payload;
    if chain.is_empty()
        || chain.len() > 64
        || candidate.original_assignment_task_ref != assignment.original_task_ref
        || candidate.assignment_id != assignment.assignment_id
        || candidate.operation_id != assignment.operation_id
        || candidate.author_principal != assignment.author_principal
        || candidate.task_control_digest != assignment.task_control_digest
        || candidate.policy_digest != assignment.policy_digest
        || candidate.review_round != assignment.review_round
    {
        return Err(AcceptanceError::AssignmentBindingMismatch);
    }
    let ad = assignment_digest(a)?;
    let cd = candidate.canonical_digest()?;
    let mut previous = &assignment.original_task_ref;
    let mut status = assignment.original_status;
    for signed in chain {
        verify_fixture_evidence(p, "qualified-submission-transition", signed)?;
        let t = &signed.payload;
        t.prior.validate()?;
        t.next.validate()?;
        use CanonicalTaskStatus::*;
        let legitimate = matches!(
            (status, t.status),
            (Todo, InProgress)
                | (InProgress, DonePendingReview)
                | (Blocked, Todo)
                | (Todo | InProgress | DonePendingReview, Blocked)
        );
        if &t.prior != previous
            || !stable_ref(previous, &t.next)
            || !legitimate
            || t.next.task_status_rev != checked_next_revision(previous.task_status_rev)?
            || t.next.file_cas_rev <= previous.file_cas_rev
            || t.assignment_id != assignment.assignment_id
            || t.operation_id != assignment.operation_id
            || t.assignment_record_digest != ad
            || t.candidate_digest != cd
            || t.task_control_digest != assignment.task_control_digest
            || t.policy_digest != assignment.policy_digest
            || t.review_round != assignment.review_round
        {
            return Err(AcceptanceError::SubmissionHistoryMismatch);
        }
        previous = &t.next;
        status = t.status;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct DependencyTargetSnapshot {
    pub resolved: ResolvedDependency,
    pub current_source: DependencySourceBinding,
}
pub struct AcceptanceVerificationContextV1<'a> {
    pub snapshot: &'a TaskEntrySnapshotV1,
    pub current: &'a TaskRefV1,
    pub assignment: &'a SignedFixtureAssignmentV1,
    pub history: &'a [SignedFixtureSubmissionV1],
    pub dependencies: &'a [DependencyTargetSnapshot],
    pub rebases_used: u8,
    pub persisted_highwater: ReviewHighwaterV1,
}
/// Complete original evidence retained privately, including fixture provenance.
#[derive(Clone, Debug)]
pub struct VerifiedFixtureAcceptanceV1 {
    bundle: SignedAcceptanceBundleV1,
    evidence: FixtureVerificationEvidenceV1,
    assignment: SignedFixtureAssignmentV1,
    history: Vec<SignedFixtureSubmissionV1>,
    provenance: FixtureProvenanceV1,
    highwater: ReviewHighwaterV1,
    qualified_current: TaskRefV1,
    rebases_used: u8,
}
impl VerifiedFixtureAcceptanceV1 {
    pub fn signed_bundle(&self) -> &SignedAcceptanceBundleV1 {
        &self.bundle
    }
    pub fn acceptance_digest(&self) -> Result<Sha256Digest, AcceptanceError> {
        self.bundle.acceptance.payload.canonical_digest()
    }
    pub fn candidate_digest(&self) -> Result<Sha256Digest, AcceptanceError> {
        self.bundle.candidate.payload.canonical_digest()
    }
    pub fn highwater(&self) -> ReviewHighwaterV1 {
        self.highwater
    }
    pub(crate) fn qualified_current(&self) -> &TaskRefV1 {
        &self.qualified_current
    }
    pub(crate) fn rebases_used(&self) -> u8 {
        self.rebases_used
    }
    pub(crate) fn provenance(&self) -> &FixtureProvenanceV1 {
        &self.provenance
    }
    pub(crate) fn assignment(&self) -> &SignedFixtureAssignmentV1 {
        &self.assignment
    }
    pub(crate) fn history(&self) -> &[SignedFixtureSubmissionV1] {
        &self.history
    }
    pub(crate) fn evidence(&self) -> &FixtureVerificationEvidenceV1 {
        &self.evidence
    }
    pub fn into_fixture_bridge(self) -> FixtureAcceptanceBridgeV1 {
        FixtureAcceptanceBridgeV1 { verified: self }
    }
}
#[derive(Debug)]
pub struct FixtureAcceptanceBridgeV1 {
    verified: VerifiedFixtureAcceptanceV1,
}
impl FixtureAcceptanceBridgeV1 {
    pub fn verified_fixture(&self) -> &VerifiedFixtureAcceptanceV1 {
        &self.verified
    }
    pub fn require_production_authority(&self) -> Result<(), AcceptanceError> {
        Err(AcceptanceError::FixtureProvenanceNotProduction)
    }
}

pub fn authorize_reviewed_acceptance<P: LegacyReviewVerifierProvider>(
    provider: &P,
    mode: LegacyReviewProfileMode,
    bundle: &SignedAcceptanceBundleV1,
    evidence: &FixtureVerificationEvidenceV1,
    context: AcceptanceVerificationContextV1<'_>,
) -> Result<VerifiedFixtureAcceptanceV1, AcceptanceError> {
    let p = TrustedFixtureVerifier::check_mode(provider, mode)?;
    // Bound all directly constructed evidence before cloning, hashing, or staging.
    fixture_statement("bounded-bundle", bundle)?;
    fixture_statement("bounded-evidence", evidence)?;
    fixture_statement("bounded-history", &context.history)?;
    let c = &bundle.candidate.payload;
    let r = &bundle.review;
    let a = &bundle.acceptance.payload;
    let cb = c.canonical_bytes()?;
    let rb = r.review_k1_transcript_bytes()?;
    let ab = a.canonical_bytes()?;
    verify_history(
        p,
        context.assignment,
        &bundle.candidate,
        context.history,
        &a.task_ref,
    )?;
    let authority = &evidence.authority.payload;
    verify_fixture_evidence(p, "current-authority", &evidence.authority)?;
    if authority.profile != "fixture-current-authority-v1"
        || authority.context != p.provenance.context
        || authority.policy_digest != p.policy_digest
        || c.policy_digest != p.policy_digest
        || authority.authority_epoch == 0
        || authority.writer_epoch == 0
        || authority.task_control_digest != c.task_control_digest
        || authority.owner_principal != context.assignment.payload.owner_principal
    {
        return Err(AcceptanceError::UnsupportedAuthorityProfileHeld);
    }
    if authority.containment_profile != "fixture-os-seatbelt-v1" {
        return Err(AcceptanceError::UnsupportedContainmentProfileHeld);
    }
    if authority.custody_profile != "fixture-host-only-k2-v1"
        || authority.review_k2 != r.k2_pubkey
        || authority.acceptance_k2 != bundle.acceptance.host_k2.public_key
        || !authority.k2_purposes.iter().any(|x| x == "legacy-review")
        || !authority.k2_purposes.iter().any(|x| x == "task-acceptance")
    {
        return Err(AcceptanceError::UnsupportedCustodyProfileHeld);
    }
    if authority.content_profile != "fixture-exact-content-tree-sha256-v1"
        || authority.fork_profile != "fixture-explicit-result-repository-v1"
        || authority.publication_profile != "fixture-complete-publication-v1"
    {
        return Err(AcceptanceError::UnsupportedContentProfileHeld);
    }
    if authority.principals.len() > 64
        || authority.named_reviewers.is_empty()
        || authority.named_reviewers.len() > 64
        || authority.quorum == 0
        || authority.quorum as usize > authority.named_reviewers.len()
    {
        return Err(AcceptanceError::QuorumNotSatisfied);
    }
    let mut names = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for principal in &authority.principals {
        ids(&[&principal.principal, &principal.instance, &principal.role])?;
        if !names.insert(&principal.principal) || !keys.insert(principal.k1) {
            return Err(AcceptanceError::DuplicateReviewer);
        }
    }
    let mut roster = BTreeSet::new();
    for name in &authority.named_reviewers {
        if !roster.insert(name)
            || !authority
                .principals
                .iter()
                .any(|p| &p.principal == name && !p.revoked)
        {
            return Err(AcceptanceError::UnauthorizedReviewerRole);
        }
    }
    let lookup = |name: &str| {
        authority
            .principals
            .iter()
            .find(|p| p.principal == name && !p.revoked)
            .ok_or(AcceptanceError::SignerBindingMismatch)
    };
    let author = lookup(&c.author_principal)?;
    let reviewer = lookup(&a.reviewer_principal)?;
    let owner = lookup(&authority.owner_principal)?;
    if reviewer.k1 == author.k1
        || reviewer.k1 == owner.k1
        || reviewer.principal == author.principal
        || reviewer.principal == owner.principal
    {
        return Err(AcceptanceError::SelfReviewForbidden);
    }
    if reviewer.instance != a.reviewer_full_instance
        || reviewer.role != a.reviewer_role
        || !roster.contains(&a.reviewer_principal)
    {
        return Err(AcceptanceError::UnauthorizedReviewerRole);
    }
    crate::agent_instance::ActorAddress::parse(&a.reviewer_full_instance)
        .and_then(crate::agent_instance::ActorAddress::require_instance)
        .map_err(|_| AcceptanceError::SignerBindingMismatch)?;
    if bundle.candidate.author_k1.public_key != author.k1
        || r.k1_pubkey != reviewer.k1
        || bundle.acceptance.reviewer_k1.public_key != reviewer.k1
    {
        return Err(AcceptanceError::SignerBindingMismatch);
    }
    verify_strict(&author.k1, &cb, &bundle.candidate.author_k1.signature)?;
    verify_strict(&reviewer.k1, &rb, &r.k1_sig)?;
    verify_strict(&r.k2_pubkey, &r.review_k2_transcript_bytes()?, &r.k2_sig)?;
    verify_strict(&reviewer.k1, &ab, &bundle.acceptance.reviewer_k1.signature)?;
    verify_strict(
        &authority.acceptance_k2,
        &bundle.acceptance.acceptance_host_transcript_bytes()?,
        &bundle.acceptance.host_k2.signature,
    )?;
    if c.canonical_digest()? != a.candidate_digest
        || r.complete_record_digest()? != a.verified_review_record_sha256
        || c.assignment_id != a.assignment_id
        || c.operation_id != a.operation_id
        || r.assignment_id != c.assignment_id
        || r.operation_id != c.operation_id
        || r.repo_id != c.result_repo_id
        || a.result_repo_id != c.result_repo_id
        || r.task_id != a.task_ref.task_id
        || r.task_spec_digest != a.task_ref.task_spec_digest
        || r.artifact_commit_oid != c.result_code_commit_oid
        || a.result_code_commit_oid != c.result_code_commit_oid
        || a.result_tree_sha256 != c.result_tree_sha256
        || a.publication != c.publication
        || a.evidence_sha256 != c.evidence_sha256
        || a.author_principal != c.author_principal
        || r.author_id != c.author_principal
        || r.reviewer_id != a.reviewer_principal
        || r.reviewer_role != a.reviewer_role
        || r.policy_digest != c.policy_digest
        || a.policy_digest != c.policy_digest
        || a.task_control_digest != c.task_control_digest
        || r.review_round != c.review_round
        || a.review_round != c.review_round
        || r.verdict != a.verdict
    {
        return Err(AcceptanceError::AttestationBindingMismatch);
    }
    let scope = &evidence.scope.payload;
    verify_fixture_evidence(p, "review-scope-content", &evidence.scope)?;
    if scope.context != p.provenance.context
        || scope.reviewer_principal != a.reviewer_principal
        || scope.reviewer_instance != a.reviewer_full_instance
        || scope.containment_profile != authority.containment_profile
        || scope.os_user.is_empty()
        || scope.seatbelt_profile.is_empty()
        || scope.acceptance_digest != a.canonical_digest()?
        || scope.review_transcript_digest != Sha256Digest::of(&rb)
        || scope.nonce != a.nonce
        || scope.result_repo_id != c.result_repo_id
        || scope.result_commit != c.result_code_commit_oid
        || scope.result_tree_sha256 != c.result_tree_sha256
        || scope.publication != c.publication
    {
        return Err(AcceptanceError::UnsupportedContainmentProfileHeld);
    }
    let time = verify_time(p, evidence, a, r, context.persisted_highwater)?;
    let highwater = ReviewHighwaterV1 {
        authority_epoch: authority.authority_epoch,
        writer_epoch: authority.writer_epoch,
        roughtime_us: time,
    };
    if !context.persisted_highwater.permits(highwater) {
        return Err(AcceptanceError::HighwaterRollback);
    }
    if time < authority.valid_from_us || time > authority.valid_until_us {
        return Err(AcceptanceError::ClockFenceHeld);
    }
    let current = context.current;
    current.validate()?;
    crate::task_ref::check_cas_eligibility(&a.task_ref, current, context.rebases_used as usize)?;
    let s = context.snapshot;
    if !stable_ref(&a.task_ref, current)
        || current.task_status_rev != a.expected_task_status_rev
        || current.file_cas_rev < a.expected_file_cas_rev
        || s.status != CanonicalTaskStatus::DonePendingReview
        || s.task_status_rev != current.task_status_rev
        || s.task_spec_digest != current.task_spec_digest
        || s.task_control_digest != a.task_control_digest
        || s.completion_policy_digest != a.policy_digest
        || s.reviewer_role != a.reviewer_role
        || s.task_id != current.task_id
        || s.baseline_commit != current.baseline_commit
        || s.candidate_commit != Some(c.result_code_commit_oid)
        || s.overlay_digest != context.assignment.payload.overlay_commitment
        || s.owner_actor.as_deref() != Some(owner.instance.as_str())
    {
        return Err(AcceptanceError::CurrentBindingMismatch);
    }
    verify_dependencies(s, current, context.dependencies)?;
    Ok(VerifiedFixtureAcceptanceV1 {
        bundle: bundle.clone(),
        evidence: evidence.clone(),
        assignment: context.assignment.clone(),
        history: context.history.to_vec(),
        provenance: p.provenance.clone(),
        highwater,
        qualified_current: current.clone(),
        rebases_used: context.rebases_used,
    })
}
fn verify_time(
    p: &TrustedFixtureVerifier,
    e: &FixtureVerificationEvidenceV1,
    a: &TaskAcceptanceV1,
    r: &ReviewAttestationV1,
    last: ReviewHighwaterV1,
) -> Result<u64, AcceptanceError> {
    if e.time.len() < 2 || e.time.len() > 64 {
        return Err(AcceptanceError::UnsupportedRoughtimeProfileHeld);
    }
    let mut servers = BTreeSet::new();
    let mut server_keys = BTreeSet::new();
    let mut low = 0;
    let mut high = u64::MAX;
    let mut min = u64::MAX;
    let mut max = 0;
    for response in &e.time {
        let t = &response.payload;
        let key = p
            .roughtime_servers
            .iter()
            .find(|(id, _)| id == &t.server_id)
            .map(|(_, k)| k)
            .ok_or(AcceptanceError::UnsupportedRoughtimeProfileHeld)?;
        if t.profile != "fixture-signed-roughtime-v1"
            || t.context != p.provenance.context
            || t.nonce != a.nonce
            || t.acceptance_digest != a.canonical_digest()?
            || t.radius_us > 10_000_000
            || t.response_elapsed_ms > 3000
            || response.signature.public_key != *key
            || !servers.insert(t.server_id.clone())
            || !server_keys.insert(*key)
        {
            return Err(AcceptanceError::UnsupportedRoughtimeProfileHeld);
        }
        verify_strict(
            key,
            &fixture_statement("roughtime-response", t)?,
            &response.signature.signature,
        )?;
        low = low.max(t.midpoint_us.saturating_sub(t.radius_us));
        high = high.min(
            t.midpoint_us
                .checked_add(t.radius_us)
                .ok_or(AcceptanceError::ClockFenceHeld)?,
        );
        min = min.min(t.midpoint_us);
        max = max.max(t.midpoint_us);
    }
    let review_servers: BTreeSet<_> = r.roughtime_server_ids.iter().cloned().collect();
    if servers != review_servers
        || review_servers.len() != r.roughtime_server_ids.len()
        || (low > high && max - min > 30_000_000)
        || r.roughtime_midpoint_us < last.roughtime_us
    {
        return Err(AcceptanceError::ClockFenceHeld);
    }
    let (agreed, radius) = if low <= high {
        (low + (high - low) / 2, (high - low) / 2)
    } else {
        (min + (max - min) / 2, max - min)
    };
    if r.roughtime_midpoint_us != agreed || r.roughtime_radius_us != radius {
        return Err(AcceptanceError::ClockFenceHeld);
    }
    let now = r.roughtime_midpoint_us / 1_000_000;
    if a.issued_at_unix > now
        || now > a.expires_at_unix
        || a.issued_at_unix > a.expires_at_unix
        || a.nonce == [0; 32]
    {
        return Err(AcceptanceError::ClockFenceHeld);
    }
    Ok(r.roughtime_midpoint_us)
}
fn verify_dependencies(
    snapshot: &TaskEntrySnapshotV1,
    current: &TaskRefV1,
    targets: &[DependencyTargetSnapshot],
) -> Result<(), AcceptanceError> {
    if targets.len() > crate::task_ref::MAX_DEPENDENCY_EDGES {
        return Err(AcceptanceError::StructuralLimitExceeded);
    }
    let canonical = crate::task_dependency::canonicalize_dependencies(
        &current.task_key(),
        snapshot.dependencies.clone(),
    )
    .map_err(|_| AcceptanceError::DependencyUnsatisfied)?;
    if canonical != snapshot.dependencies {
        return Err(AcceptanceError::DependencyUnsatisfied);
    }
    let mut seen = BTreeSet::new();
    for target in targets {
        if !seen.insert(target.resolved.task_ref.task_key()) {
            return Err(AcceptanceError::DependencyUnsatisfied);
        }
    }
    for d in &snapshot.dependencies {
        let target = targets
            .iter()
            .find(|t| t.resolved.task_ref.task_key() == d.target_key)
            .ok_or(AcceptanceError::DependencyUnsatisfied)?;
        validate_dependency_satisfaction(d, &target.resolved, &target.current_source)
            .map_err(|_| AcceptanceError::DependencyUnsatisfied)?;
    }
    Ok(())
}
/// Quorum is exact-current and names distinct authenticated K1 principals.
/// It yields fixture-only authority; Rejected records remain durable separately.
pub fn verify_fixture_quorum(
    tokens: &[VerifiedFixtureAcceptanceV1],
) -> Result<(), AcceptanceError> {
    let first = tokens.first().ok_or(AcceptanceError::QuorumNotSatisfied)?;
    let authority = &first.evidence.authority.payload;
    let mut principals = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for t in tokens {
        let a = &t.bundle.acceptance.payload;
        let f = &first.bundle.acceptance.payload;
        if t.provenance != first.provenance
            || t.evidence.authority != first.evidence.authority
            || a.task_ref != f.task_ref
            || a.candidate_digest != f.candidate_digest
            || a.review_round != f.review_round
            || a.verdict != ReviewVerdict::Approved
            || t.bundle.review.verdict != ReviewVerdict::Approved
            || !principals.insert(&a.reviewer_principal)
            || !keys.insert(t.bundle.review.k1_pubkey)
        {
            return Err(AcceptanceError::DuplicateReviewer);
        }
    }
    if principals.len() < authority.quorum as usize {
        return Err(AcceptanceError::QuorumNotSatisfied);
    }
    Ok(())
}

/// Reopen checks complete original evidence under its immutable fixture profile.
/// This returns no approval and cannot refresh an expired or revoked authority.
pub(crate) fn verify_retained_fixture_record(
    p: &TrustedFixtureVerifier,
    b: &SignedAcceptanceBundleV1,
    e: &FixtureVerificationEvidenceV1,
    h: ReviewHighwaterV1,
) -> Result<(), AcceptanceError> {
    fixture_statement("retained-bundle", b)?;
    fixture_statement("retained-evidence", e)?;
    let c = &b.candidate.payload;
    let r = &b.review;
    let a = &b.acceptance.payload;
    verify_fixture_evidence(p, "current-authority", &e.authority)?;
    verify_fixture_evidence(p, "review-scope-content", &e.scope)?;
    let authority = &e.authority.payload;
    if authority.profile != "fixture-current-authority-v1"
        || authority.context != p.provenance.context
        || authority.policy_digest != p.policy_digest
        || a.policy_digest != p.policy_digest
        || h.authority_epoch != authority.authority_epoch
        || h.writer_epoch != authority.writer_epoch
        || h.roughtime_us != r.roughtime_midpoint_us
        || authority.task_control_digest != a.task_control_digest
        || authority.containment_profile != "fixture-os-seatbelt-v1"
        || authority.custody_profile != "fixture-host-only-k2-v1"
        || authority.content_profile != "fixture-exact-content-tree-sha256-v1"
        || authority.fork_profile != "fixture-explicit-result-repository-v1"
        || authority.publication_profile != "fixture-complete-publication-v1"
        || authority.review_k2 != r.k2_pubkey
        || authority.acceptance_k2 != b.acceptance.host_k2.public_key
        || !authority.k2_purposes.iter().any(|x| x == "legacy-review")
        || !authority.k2_purposes.iter().any(|x| x == "task-acceptance")
    {
        return Err(AcceptanceError::UnsupportedAuthorityProfileHeld);
    }
    let author = authority
        .principals
        .iter()
        .find(|x| x.principal == c.author_principal && !x.revoked)
        .ok_or(AcceptanceError::SignerBindingMismatch)?;
    let reviewer = authority
        .principals
        .iter()
        .find(|x| x.principal == a.reviewer_principal && !x.revoked)
        .ok_or(AcceptanceError::SignerBindingMismatch)?;
    let owner = authority
        .principals
        .iter()
        .find(|x| x.principal == authority.owner_principal && !x.revoked)
        .ok_or(AcceptanceError::SignerBindingMismatch)?;
    if author.k1 == reviewer.k1
        || owner.k1 == reviewer.k1
        || reviewer.instance != a.reviewer_full_instance
        || reviewer.role != a.reviewer_role
        || !authority.named_reviewers.contains(&reviewer.principal)
        || b.candidate.author_k1.public_key != author.k1
        || b.acceptance.reviewer_k1.public_key != reviewer.k1
        || r.k1_pubkey != reviewer.k1
    {
        return Err(AcceptanceError::SignerBindingMismatch);
    }
    verify_strict(
        &author.k1,
        &c.canonical_bytes()?,
        &b.candidate.author_k1.signature,
    )?;
    verify_strict(&reviewer.k1, &r.review_k1_transcript_bytes()?, &r.k1_sig)?;
    verify_strict(&r.k2_pubkey, &r.review_k2_transcript_bytes()?, &r.k2_sig)?;
    verify_strict(
        &reviewer.k1,
        &a.canonical_bytes()?,
        &b.acceptance.reviewer_k1.signature,
    )?;
    verify_strict(
        &authority.acceptance_k2,
        &b.acceptance.acceptance_host_transcript_bytes()?,
        &b.acceptance.host_k2.signature,
    )?;
    if c.canonical_digest()? != a.candidate_digest
        || r.complete_record_digest()? != a.verified_review_record_sha256
        || r.repo_id != c.result_repo_id
        || a.result_repo_id != c.result_repo_id
        || r.task_id != a.task_ref.task_id
        || r.task_spec_digest != a.task_ref.task_spec_digest
        || r.artifact_commit_oid != c.result_code_commit_oid
        || a.result_code_commit_oid != c.result_code_commit_oid
        || a.result_tree_sha256 != c.result_tree_sha256
        || a.publication != c.publication
        || a.evidence_sha256 != c.evidence_sha256
        || a.author_principal != c.author_principal
        || r.author_id != c.author_principal
        || r.reviewer_id != a.reviewer_principal
        || r.reviewer_role != a.reviewer_role
        || r.policy_digest != a.policy_digest
        || c.policy_digest != a.policy_digest
        || c.task_control_digest != a.task_control_digest
        || c.assignment_id != a.assignment_id
        || r.assignment_id != a.assignment_id
        || c.operation_id != a.operation_id
        || r.operation_id != a.operation_id
        || c.review_round != a.review_round
        || r.review_round != a.review_round
        || r.verdict != a.verdict
    {
        return Err(AcceptanceError::AttestationBindingMismatch);
    }
    let scope = &e.scope.payload;
    if scope.context != p.provenance.context
        || scope.reviewer_principal != reviewer.principal
        || scope.reviewer_instance != reviewer.instance
        || scope.containment_profile != authority.containment_profile
        || scope.os_user.is_empty()
        || scope.seatbelt_profile.is_empty()
        || scope.acceptance_digest != a.canonical_digest()?
        || scope.review_transcript_digest != Sha256Digest::of(&r.review_k1_transcript_bytes()?)
        || scope.nonce != a.nonce
        || scope.result_repo_id != c.result_repo_id
        || scope.result_commit != c.result_code_commit_oid
        || scope.result_tree_sha256 != c.result_tree_sha256
        || scope.publication != c.publication
    {
        return Err(AcceptanceError::UnsupportedContainmentProfileHeld);
    }
    verify_time(p, e, a, r, ReviewHighwaterV1::default())?;
    if h.roughtime_us < authority.valid_from_us || h.roughtime_us > authority.valid_until_us {
        return Err(AcceptanceError::ClockFenceHeld);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use iroh::SecretKey;
    pub(crate) fn key(seed: u8) -> [u8; 32] {
        *SecretKey::from_bytes(&[seed; 32]).public().as_bytes()
    }
    pub(crate) fn signature(seed: u8, bytes: &[u8]) -> SignatureEvidenceV1 {
        SignatureEvidenceV1 {
            public_key: key(seed),
            signature: SecretKey::from_bytes(&[seed; 32]).sign(bytes).to_bytes(),
        }
    }
    pub(crate) fn signed<T: Serialize>(
        purpose: &str,
        payload: T,
        seed: u8,
    ) -> SignedFixtureEvidenceV1<T> {
        let signature = signature(seed, &fixture_statement(purpose, &payload).unwrap());
        SignedFixtureEvidenceV1 { payload, signature }
    }
    pub(crate) struct Fixture {
        pub(crate) provider: TrustedFixtureVerifier,
        pub(crate) assignment: SignedFixtureAssignmentV1,
        pub(crate) history: Vec<SignedFixtureSubmissionV1>,
        pub(crate) bundle: SignedAcceptanceBundleV1,
        pub(crate) evidence: FixtureVerificationEvidenceV1,
        pub(crate) snapshot: TaskEntrySnapshotV1,
        pub(crate) current: TaskRefV1,
    }
    impl Fixture {
        pub(crate) fn new(dev: u64, ino: u64) -> Self {
            let policy = Sha256Digest([2; 32]);
            let control = Sha256Digest([3; 32]);
            let original = TaskRefV1 {
                workspace_id: "fixture-workspace".into(),
                repo_id: "task-repository".into(),
                task_source_id: "11111111111111111111111111111111".into(),
                source_generation: 1,
                canonical_task_path: "TASKS.md".into(),
                task_id: "P0-06".into(),
                task_spec_digest: Sha256Digest([1; 32]),
                task_status_rev: 3,
                file_cas_rev: 7,
                baseline_commit: GitOid::Sha1([1; 20]),
            };
            let mut current = original.clone();
            current.task_status_rev = 4;
            current.file_cas_rev = 8;
            let provider = TrustedFixtureVerifier {
                provenance: FixtureProvenanceV1 {
                    profile: "FixtureProfileV1".into(),
                    context: "controlled-p006-fixture".into(),
                    workspace_id: original.workspace_id.clone(),
                    task_source_id: original.task_source_id.clone(),
                    canonical_task_path: original.canonical_task_path.clone(),
                    namespace_dev: dev,
                    namespace_ino: ino,
                    admission_digest: Sha256Digest::of(b"finite-in-module-fixture-admission-v1"),
                },
                authority_root: key(40),
                roughtime_servers: vec![("server-a".into(), key(6)), ("server-b".into(), key(7))],
                policy_digest: policy,
            };
            let assignment = signed(
                "immutable-assignment",
                ImmutableAssignmentV1 {
                    original_task_ref: original.clone(),
                    assignment_id: "assignment".into(),
                    operation_id: "original-operation".into(),
                    author_principal: "author-principal".into(),
                    owner_principal: "author-principal".into(),
                    original_status: CanonicalTaskStatus::InProgress,
                    task_control_digest: control,
                    policy_digest: policy,
                    overlay_commitment: Some(Sha256Digest([9; 32])),
                    review_round: 1,
                },
                40,
            );
            let candidate = TaskCandidateV1 {
                original_assignment_task_ref: original,
                assignment_id: "assignment".into(),
                operation_id: "original-operation".into(),
                author_principal: "author-principal".into(),
                task_control_digest: control,
                result_repo_id: "result-repository".into(),
                result_code_commit_oid: GitOid::Sha1([4; 20]),
                result_tree_sha256: Sha256Digest::of(b"approved fixture exact content tree"),
                publication: None,
                evidence_sha256: vec![],
                policy_digest: policy,
                review_round: 1,
            };
            let candidate = SignedCandidateV1 {
                author_k1: signature(1, &candidate.canonical_bytes().unwrap()),
                payload: candidate,
            };
            let transition = signed(
                "qualified-submission-transition",
                QualifiedSubmissionTransitionV1 {
                    prior: assignment.payload.original_task_ref.clone(),
                    next: current.clone(),
                    assignment_id: "assignment".into(),
                    operation_id: "original-operation".into(),
                    assignment_record_digest: assignment_digest(&assignment).unwrap(),
                    candidate_digest: candidate.payload.canonical_digest().unwrap(),
                    task_control_digest: control,
                    policy_digest: policy,
                    review_round: 1,
                    status: CanonicalTaskStatus::DonePendingReview,
                },
                40,
            );
            let mut review = ReviewAttestationV1 {
                repo_id: "result-repository".into(),
                task_id: "P0-06".into(),
                task_spec_digest: current.task_spec_digest,
                assignment_id: "assignment".into(),
                operation_id: "original-operation".into(),
                artifact_commit_oid: candidate.payload.result_code_commit_oid,
                jj_change_id: None,
                review_round: 1,
                author_id: "author-principal".into(),
                reviewer_id: "reviewer-principal".into(),
                reviewer_role: "independent-review".into(),
                verdict: ReviewVerdict::Approved,
                policy_digest: policy,
                roughtime_midpoint_us: 100_000_000,
                roughtime_radius_us: 1_000_000,
                roughtime_server_ids: vec!["server-a".into(), "server-b".into()],
                k1_pubkey: key(2),
                k1_sig: [0; 64],
                k2_pubkey: key(4),
                k2_sig: [0; 64],
            };
            review.k1_sig = signature(2, &review.review_k1_transcript_bytes().unwrap()).signature;
            review.k2_sig = signature(4, &review.review_k2_transcript_bytes().unwrap()).signature;
            let a = TaskAcceptanceV1 {
                task_ref: current.clone(),
                expected_task_status_rev: 4,
                expected_file_cas_rev: 8,
                assignment_id: "assignment".into(),
                operation_id: "original-operation".into(),
                candidate_digest: candidate.payload.canonical_digest().unwrap(),
                result_repo_id: "result-repository".into(),
                result_code_commit_oid: candidate.payload.result_code_commit_oid,
                result_tree_sha256: candidate.payload.result_tree_sha256,
                publication: None,
                evidence_sha256: vec![],
                verified_review_record_sha256: review.complete_record_digest().unwrap(),
                author_principal: "author-principal".into(),
                reviewer_principal: "reviewer-principal".into(),
                reviewer_full_instance: "REVIEW#fixture".into(),
                reviewer_role: "independent-review".into(),
                task_control_digest: control,
                policy_digest: policy,
                review_round: 1,
                verdict: ReviewVerdict::Approved,
                issued_at_unix: 90,
                expires_at_unix: 110,
                nonce: [8; 32],
            };
            let reviewer_k1 = signature(2, &a.canonical_bytes().unwrap());
            let mut acceptance = SignedTaskAcceptanceV1 {
                payload: a,
                reviewer_k1,
                host_k2: signature(5, b"placeholder"),
            };
            acceptance.host_k2 =
                signature(5, &acceptance.acceptance_host_transcript_bytes().unwrap());
            let authority = FixtureCurrentAuthorityV1 {
                profile: "fixture-current-authority-v1".into(),
                context: provider.provenance.context.clone(),
                authority_epoch: 2,
                writer_epoch: 3,
                writer_principal: "fixture-writer".into(),
                owner_principal: "author-principal".into(),
                principals: vec![
                    FixturePrincipalV1 {
                        principal: "author-principal".into(),
                        instance: "RUST#fixture".into(),
                        role: "author".into(),
                        k1: key(1),
                        revoked: false,
                    },
                    FixturePrincipalV1 {
                        principal: "reviewer-principal".into(),
                        instance: "REVIEW#fixture".into(),
                        role: "independent-review".into(),
                        k1: key(2),
                        revoked: false,
                    },
                    FixturePrincipalV1 {
                        principal: "reviewer-two".into(),
                        instance: "REVIEW2#fixture".into(),
                        role: "independent-review".into(),
                        k1: key(3),
                        revoked: false,
                    },
                ],
                named_reviewers: vec!["reviewer-principal".into(), "reviewer-two".into()],
                quorum: 1,
                policy_digest: policy,
                task_control_digest: control,
                valid_from_us: 80_000_000,
                valid_until_us: 120_000_000,
                containment_profile: "fixture-os-seatbelt-v1".into(),
                custody_profile: "fixture-host-only-k2-v1".into(),
                content_profile: "fixture-exact-content-tree-sha256-v1".into(),
                fork_profile: "fixture-explicit-result-repository-v1".into(),
                publication_profile: "fixture-complete-publication-v1".into(),
                review_k2: key(4),
                acceptance_k2: key(5),
                k2_purposes: vec!["legacy-review".into(), "task-acceptance".into()],
            };
            let bundle = SignedAcceptanceBundleV1 {
                candidate,
                review,
                acceptance,
            };
            let scope = FixtureScopeEvidenceV1 {
                context: provider.provenance.context.clone(),
                reviewer_principal: "reviewer-principal".into(),
                reviewer_instance: "REVIEW#fixture".into(),
                containment_profile: "fixture-os-seatbelt-v1".into(),
                os_user: "fixture-review-user".into(),
                seatbelt_profile: "fixture-seatbelt".into(),
                acceptance_digest: bundle.acceptance.payload.canonical_digest().unwrap(),
                review_transcript_digest: Sha256Digest::of(
                    &bundle.review.review_k1_transcript_bytes().unwrap(),
                ),
                nonce: [8; 32],
                result_repo_id: "result-repository".into(),
                result_commit: bundle.candidate.payload.result_code_commit_oid,
                result_tree_sha256: bundle.candidate.payload.result_tree_sha256,
                publication: None,
            };
            let time = [6, 7]
                .into_iter()
                .enumerate()
                .map(|(i, seed)| {
                    signed(
                        "roughtime-response",
                        FixtureTimeResponseV1 {
                            profile: "fixture-signed-roughtime-v1".into(),
                            context: provider.provenance.context.clone(),
                            server_id: if i == 0 { "server-a" } else { "server-b" }.into(),
                            nonce: [8; 32],
                            midpoint_us: 100_000_000,
                            radius_us: 1_000_000,
                            response_elapsed_ms: 20,
                            acceptance_digest: bundle
                                .acceptance
                                .payload
                                .canonical_digest()
                                .unwrap(),
                        },
                        seed,
                    )
                })
                .collect();
            let evidence = FixtureVerificationEvidenceV1 {
                authority: signed("current-authority", authority, 40),
                scope: signed("review-scope-content", scope, 40),
                time,
            };
            let snapshot = TaskEntrySnapshotV1 {
                task_id: "P0-06".into(),
                status: CanonicalTaskStatus::DonePendingReview,
                task_status_rev: 4,
                task_spec_digest: current.task_spec_digest,
                task_control_digest: control,
                completion_policy_digest: policy,
                owner_actor: Some("RUST#fixture".into()),
                reviewer_role: "independent-review".into(),
                baseline_commit: current.baseline_commit,
                candidate_commit: Some(bundle.candidate.payload.result_code_commit_oid),
                overlay_digest: assignment.payload.overlay_commitment,
                execution_flags: vec![],
                dependencies: vec![],
            };
            Self {
                provider,
                assignment,
                history: vec![transition],
                bundle,
                evidence,
                snapshot,
                current,
            }
        }
        pub(crate) fn verify(
            &self,
            highwater: ReviewHighwaterV1,
        ) -> Result<VerifiedFixtureAcceptanceV1, AcceptanceError> {
            authorize_reviewed_acceptance(
                &self.provider,
                LegacyReviewProfileMode::FixtureProfileV1,
                &self.bundle,
                &self.evidence,
                AcceptanceVerificationContextV1 {
                    snapshot: &self.snapshot,
                    current: &self.current,
                    assignment: &self.assignment,
                    history: &self.history,
                    dependencies: &[],
                    rebases_used: 0,
                    persisted_highwater: highwater,
                },
            )
        }
        pub(crate) fn resign_authority(&mut self) {
            self.evidence.authority = signed(
                "current-authority",
                self.evidence.authority.payload.clone(),
                40,
            );
        }
        pub(crate) fn refresh_signed_records(&mut self) {
            self.refresh_reviewer(2);
        }
        pub(crate) fn refresh_reviewer(&mut self, reviewer_seed: u8) {
            self.bundle.review.k1_sig = signature(
                reviewer_seed,
                &self.bundle.review.review_k1_transcript_bytes().unwrap(),
            )
            .signature;
            self.bundle.review.k2_sig =
                signature(4, &self.bundle.review.review_k2_transcript_bytes().unwrap()).signature;
            self.bundle.acceptance.payload.verified_review_record_sha256 =
                self.bundle.review.complete_record_digest().unwrap();
            self.bundle.acceptance.reviewer_k1 = signature(
                reviewer_seed,
                &self.bundle.acceptance.payload.canonical_bytes().unwrap(),
            );
            self.bundle.acceptance.host_k2 = signature(
                5,
                &self
                    .bundle
                    .acceptance
                    .acceptance_host_transcript_bytes()
                    .unwrap(),
            );
            let digest = self.bundle.acceptance.payload.canonical_digest().unwrap();
            self.evidence.scope.payload.acceptance_digest = digest;
            self.evidence.scope.payload.review_transcript_digest =
                Sha256Digest::of(&self.bundle.review.review_k1_transcript_bytes().unwrap());
            self.evidence.scope = signed(
                "review-scope-content",
                self.evidence.scope.payload.clone(),
                40,
            );
            for (index, t) in self.evidence.time.iter_mut().enumerate() {
                t.payload.acceptance_digest = digest;
                *t = signed(
                    "roughtime-response",
                    t.payload.clone(),
                    if index == 0 { 6 } else { 7 },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    // Independent byte construction: no production encoder/helper calls.
    fn b(x: &[u8]) -> Vec<u8> {
        let mut out = (x.len() as u64).to_be_bytes().to_vec();
        out.extend(x);
        out
    }
    fn text(x: &str) -> Vec<u8> {
        b(x.as_bytes())
    }
    fn sha(x: Sha256Digest) -> Vec<u8> {
        [text("sha256"), b(&x.0)].concat()
    }
    fn oid(x: GitOid) -> Vec<u8> {
        match x {
            GitOid::Sha1(v) => [text("git-sha1"), b(&v)].concat(),
            GitOid::Sha256(v) => [text("git-sha256"), b(&v)].concat(),
        }
    }
    fn task(x: &TaskRefV1) -> Vec<u8> {
        [
            b"chinwag-taskref-v1\0".to_vec(),
            text(&x.workspace_id),
            text(&x.repo_id),
            text(&x.task_source_id),
            x.source_generation.to_be_bytes().to_vec(),
            text(&x.canonical_task_path),
            text(&x.task_id),
            sha(x.task_spec_digest),
            x.task_status_rev.to_be_bytes().to_vec(),
            x.file_cas_rev.to_be_bytes().to_vec(),
            oid(x.baseline_commit),
        ]
        .concat()
    }
    fn publication(x: &Option<PublicationBindingV1>) -> Vec<u8> {
        match x {
            None => vec![0],
            Some(x) => [
                vec![1],
                text(&x.publication_repo_id),
                oid(x.publication_commit_oid),
                sha(x.publication_manifest_sha256),
            ]
            .concat(),
        }
    }
    fn evidence(x: &[Sha256Digest]) -> Vec<u8> {
        let mut ds: Vec<_> = x.iter().copied().map(sha).collect();
        ds.sort();
        [(ds.len() as u64).to_be_bytes().to_vec(), ds.concat()].concat()
    }
    fn candidate_vector(c: &TaskCandidateV1) -> Vec<u8> {
        [
            b"chinwag-task-candidate-v1\0".to_vec(),
            b(&task(&c.original_assignment_task_ref)),
            text(&c.assignment_id),
            text(&c.operation_id),
            text(&c.author_principal),
            b(&sha(c.task_control_digest)),
            text(&c.result_repo_id),
            b(&oid(c.result_code_commit_oid)),
            b(&sha(c.result_tree_sha256)),
            publication(&c.publication),
            evidence(&c.evidence_sha256),
            b(&sha(c.policy_digest)),
            c.review_round.to_be_bytes().to_vec(),
        ]
        .concat()
    }
    fn acceptance_vector(a: &TaskAcceptanceV1) -> Vec<u8> {
        [
            b"chinwag-task-acceptance-v1\0".to_vec(),
            b(&task(&a.task_ref)),
            a.expected_task_status_rev.to_be_bytes().to_vec(),
            a.expected_file_cas_rev.to_be_bytes().to_vec(),
            text(&a.assignment_id),
            text(&a.operation_id),
            b(&sha(a.candidate_digest)),
            text(&a.result_repo_id),
            b(&oid(a.result_code_commit_oid)),
            b(&sha(a.result_tree_sha256)),
            publication(&a.publication),
            evidence(&a.evidence_sha256),
            b(&sha(a.verified_review_record_sha256)),
            text(&a.author_principal),
            text(&a.reviewer_principal),
            text(&a.reviewer_full_instance),
            text(&a.reviewer_role),
            b(&sha(a.task_control_digest)),
            b(&sha(a.policy_digest)),
            a.review_round.to_be_bytes().to_vec(),
            text(a.verdict.text()),
            a.issued_at_unix.to_be_bytes().to_vec(),
            a.expires_at_unix.to_be_bytes().to_vec(),
            b(&a.nonce),
        ]
        .concat()
    }
    #[test]
    fn p0_acceptance_exact_candidate_and_acceptance_vectors_empty_and_publication() {
        let mut f = Fixture::new(1, 2);
        assert_eq!(
            f.bundle.candidate.payload.canonical_bytes().unwrap().len(),
            640
        );
        assert_eq!(
            f.bundle
                .candidate
                .payload
                .canonical_digest()
                .unwrap()
                .to_string(),
            "b220a6fe0d8538749072e53c567f0b0177b39b24e538c3439446692303939658"
        );
        for with_publication in [false, true] {
            let publication = with_publication.then(|| PublicationBindingV1 {
                publication_repo_id: "publication".into(),
                publication_commit_oid: GitOid::Sha256([7; 32]),
                publication_manifest_sha256: Sha256Digest([8; 32]),
            });
            f.bundle.candidate.payload.publication = publication.clone();
            f.bundle.acceptance.payload.publication = publication;
            let ds = if with_publication {
                vec![Sha256Digest([8; 32]), Sha256Digest([1; 32])]
            } else {
                vec![]
            };
            f.bundle.candidate.payload.evidence_sha256 = ds.clone();
            f.bundle.acceptance.payload.evidence_sha256 = ds;
            assert_eq!(
                f.bundle.candidate.payload.canonical_bytes().unwrap(),
                candidate_vector(&f.bundle.candidate.payload)
            );
            assert_eq!(
                f.bundle.acceptance.payload.canonical_bytes().unwrap(),
                acceptance_vector(&f.bundle.acceptance.payload)
            );
        }
    }
    #[test]
    fn p0_acceptance_exact_legacy_k1_k2_complete_record_and_new_host_vectors() {
        let f = Fixture::new(1, 2);
        let r = &f.bundle.review;
        let mut servers: Vec<_> = r.roughtime_server_ids.iter().map(|x| text(x)).collect();
        servers.sort();
        let expected = [
            b"chinwag-review-attestation-v1".to_vec(),
            text(&r.repo_id),
            text(&r.task_id),
            sha(r.task_spec_digest),
            text(&r.assignment_id),
            text(&r.operation_id),
            oid(r.artifact_commit_oid),
            vec![0],
            r.review_round.to_be_bytes().to_vec(),
            text(&r.author_id),
            text(&r.reviewer_id),
            text(&r.reviewer_role),
            text("Approved"),
            sha(r.policy_digest),
            r.roughtime_midpoint_us.to_be_bytes().to_vec(),
            r.roughtime_radius_us.to_be_bytes().to_vec(),
            2_u64.to_be_bytes().to_vec(),
            servers.concat(),
        ]
        .concat();
        assert_eq!(r.review_k1_transcript_bytes().unwrap(), expected);
        assert_eq!(
            r.review_k2_transcript_bytes().unwrap(),
            [
                b"chinwag-host-countersign-v1".as_slice(),
                &Sha256Digest::of(&expected).0
            ]
            .concat()
        );
        let complete = [
            expected,
            b(&r.k1_pubkey),
            b(&r.k1_sig),
            b(&r.k2_pubkey),
            b(&r.k2_sig),
        ]
        .concat();
        assert_eq!(r.complete_record_bytes().unwrap(), complete);
        assert_ne!(
            Sha256Digest::of(&complete),
            Sha256Digest::of(&r.review_k1_transcript_bytes().unwrap())
        );
        let a = &f.bundle.acceptance;
        assert_eq!(
            a.acceptance_host_transcript_bytes().unwrap(),
            [
                b"chinwag-task-acceptance-host-v1\0".to_vec(),
                sha(Sha256Digest::of(&acceptance_vector(&a.payload))),
                b(&a.reviewer_k1.public_key),
                b(&a.reviewer_k1.signature)
            ]
            .concat()
        );
    }
    #[test]
    fn p0_acceptance_duplicate_evidence_and_roughtime_servers_refused() {
        let mut f = Fixture::new(1, 2);
        f.bundle.candidate.payload.evidence_sha256 = vec![Sha256Digest([1; 32]); 2];
        assert!(f.bundle.candidate.payload.canonical_bytes().is_err());
        f.bundle.review.roughtime_server_ids = vec!["same".into(); 2];
        assert!(f.bundle.review.review_k1_transcript_bytes().is_err());
    }
    #[test]
    fn p0_acceptance_fixture_positive_same_reviewer_both_hosts_production_held() {
        let f = Fixture::new(1, 2);
        let cap = f.verify(ReviewHighwaterV1::default()).unwrap();
        verify_fixture_quorum(&[cap.clone()]).unwrap();
        assert_eq!(
            cap.into_fixture_bridge().require_production_authority(),
            Err(AcceptanceError::FixtureProvenanceNotProduction)
        );
        for mode in [
            LegacyReviewProfileMode::ProductionHeld,
            LegacyReviewProfileMode::default(),
        ] {
            assert_eq!(
                TrustedFixtureVerifier::check_mode(&f.provider, mode).unwrap_err(),
                AcceptanceError::UnsupportedLegacyReviewProfileHeld
            );
        }
        assert_eq!(
            TrustedFixtureVerifier::check_mode(
                &ProductionHeldVerifier,
                LegacyReviewProfileMode::FixtureProfileV1
            )
            .unwrap_err(),
            AcceptanceError::UntrustedFixtureProviderHeld
        );
    }
    #[test]
    fn p0_acceptance_strict_ed25519_negative_vectors() {
        let message = b"strict-fixture-vector";
        let valid = signature(2, message);
        verify_strict(&valid.public_key, message, &valid.signature).unwrap();
        assert!(verify_strict(&valid.public_key, b"other-domain", &valid.signature).is_err());
        assert!(verify_strict(&key(3), message, &valid.signature).is_err());
        assert!(verify_strict(&valid.public_key, message, &[0; 64]).is_err());
        let mut high_s = valid.signature;
        high_s[32..].fill(255);
        assert!(verify_strict(&valid.public_key, message, &high_s).is_err());
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut forged = [0; 64];
        forged[0] = 1;
        assert!(verify_strict(&identity, message, &forged).is_err());
        assert!(verify_strict(&[0; 32], message, &forged).is_err());
    }
    #[test]
    fn p0_acceptance_original_three_pending_four_and_arbitrary_valid_history() {
        let mut f = Fixture::new(1, 2);
        f.verify(ReviewHighwaterV1::default()).unwrap();
        let original = f.assignment.clone();
        let mut prior = original.payload.original_task_ref.clone();
        let mut transitions = Vec::new();
        for status in [
            CanonicalTaskStatus::Blocked,
            CanonicalTaskStatus::Todo,
            CanonicalTaskStatus::InProgress,
            CanonicalTaskStatus::DonePendingReview,
        ] {
            let mut next = prior.clone();
            next.task_status_rev += 1;
            next.file_cas_rev += 1;
            let mut t = f.history[0].payload.clone();
            t.prior = prior;
            t.next = next.clone();
            t.status = status;
            transitions.push(signed("qualified-submission-transition", t, 40));
            prior = next;
        }
        verify_history(
            &f.provider,
            &original,
            &f.bundle.candidate,
            &transitions,
            &prior,
        )
        .unwrap();
        assert_eq!(f.assignment, original);
        transitions.remove(1);
        assert!(
            verify_history(
                &f.provider,
                &original,
                &f.bundle.candidate,
                &transitions,
                &prior
            )
            .is_err()
        );
        f.history[0].signature.signature[0] ^= 1;
        assert!(f.verify(ReviewHighwaterV1::default()).is_err());
        f.history.clear();
        assert!(f.verify(ReviewHighwaterV1::default()).is_err());
    }
    #[test]
    fn p0_acceptance_signed_binding_mutations_and_both_host_domains_refused() {
        for case in 0..14 {
            let mut f = Fixture::new(1, 2);
            match case {
                0 => f.bundle.review.k1_sig[0] ^= 1,
                1 => {
                    f.bundle.review.k2_sig =
                        signature(4, b"chinwag-host-countersign-v1\0").signature
                }
                2 => {
                    f.bundle.acceptance.host_k2.signature =
                        signature(5, b"chinwag-task-acceptance-host-v1").signature
                }
                3 => {
                    f.bundle.acceptance.reviewer_k1 =
                        signature(1, &f.bundle.acceptance.payload.canonical_bytes().unwrap())
                }
                4 => f.bundle.review.repo_id = "task-repository".into(),
                5 => f.bundle.acceptance.payload.result_tree_sha256 = Sha256Digest([0; 32]),
                6 => f.bundle.review.review_round += 1,
                7 => f.bundle.acceptance.payload.nonce = [9; 32],
                8 => f.bundle.acceptance.payload.policy_digest = Sha256Digest([4; 32]),
                9 => f.bundle.review.verdict = ReviewVerdict::Rejected,
                10 => f.bundle.review.operation_id = "substituted-operation".into(),
                11 => f.bundle.review.artifact_commit_oid = GitOid::Sha1([9; 20]),
                12 => f.bundle.review.k2_pubkey = key(7),
                _ => f.bundle.acceptance.payload.reviewer_role = "author".into(),
            }
            assert!(
                f.verify(ReviewHighwaterV1::default()).is_err(),
                "case {case}"
            );
        }
    }
    #[test]
    fn p0_acceptance_current_profiles_revocation_os_custody_and_time_refusals() {
        for case in 0..13 {
            let mut f = Fixture::new(1, 2);
            match case {
                0 => f.evidence.authority.payload.principals[1].revoked = true,
                1 => f.evidence.authority.payload.containment_profile.clear(),
                2 => f.evidence.authority.payload.custody_profile.clear(),
                3 => f
                    .evidence
                    .authority
                    .payload
                    .k2_purposes
                    .pop()
                    .map(|_| ())
                    .unwrap(),
                4 => f.evidence.authority.payload.content_profile.clear(),
                5 => f.evidence.authority.payload.fork_profile.clear(),
                6 => f.evidence.authority.payload.publication_profile.clear(),
                7 => f.evidence.authority.payload.principals[1].role = "author".into(),
                8 => f.evidence.time.clear(),
                9 => f.evidence.time[0].payload.nonce = [0; 32],
                10 => f.evidence.time[0].payload.radius_us = 10_000_001,
                11 => f.evidence.time[0].payload.response_elapsed_ms = 3001,
                _ => f.evidence.authority.payload.context = "outside-fixture".into(),
            }
            f.resign_authority();
            assert!(
                f.verify(ReviewHighwaterV1::default()).is_err(),
                "case {case}"
            );
        }
    }
    #[test]
    fn p0_acceptance_same_k1_alias_quorum_and_rejected_records() {
        let mut f = Fixture::new(1, 2);
        let cap = f.verify(ReviewHighwaterV1::default()).unwrap();
        assert_eq!(
            verify_fixture_quorum(&[cap.clone(), cap]),
            Err(AcceptanceError::DuplicateReviewer)
        );
        f.evidence.authority.payload.quorum = 2;
        f.resign_authority();
        let cap = f.verify(ReviewHighwaterV1::default()).unwrap();
        assert_eq!(
            verify_fixture_quorum(&[cap]),
            Err(AcceptanceError::QuorumNotSatisfied)
        );
        f.evidence.authority.payload.quorum = 1;
        f.evidence.authority.payload.principals[1].k1 = key(1);
        f.resign_authority();
        assert!(f.verify(ReviewHighwaterV1::default()).is_err());
        let mut f = Fixture::new(1, 2);
        f.bundle.review.verdict = ReviewVerdict::Rejected;
        f.bundle.acceptance.payload.verdict = ReviewVerdict::Rejected;
        f.refresh_signed_records();
        let rejected = f.verify(ReviewHighwaterV1::default()).unwrap();
        assert!(verify_fixture_quorum(&[rejected]).is_err());
    }
    #[test]
    fn p0_acceptance_highwater_exact_current_overlay_and_json_bounds() {
        let mut f = Fixture::new(1, 2);
        for highwater in [
            ReviewHighwaterV1 {
                authority_epoch: 3,
                ..Default::default()
            },
            ReviewHighwaterV1 {
                writer_epoch: 4,
                ..Default::default()
            },
            ReviewHighwaterV1 {
                roughtime_us: 100_000_001,
                ..Default::default()
            },
        ] {
            assert!(f.verify(highwater).is_err());
        }
        f.snapshot.overlay_digest = None;
        assert!(f.verify(Default::default()).is_err());
        assert_eq!(
            preflight_json("{\"a\":1,\"a\":2}"),
            Err(AcceptanceError::DuplicateJsonKey)
        );
        assert_eq!(
            preflight_json(&"x".repeat(65_537)),
            Err(AcceptanceError::PayloadTooLarge)
        );
        assert_eq!(
            preflight_json("DONE"),
            Err(AcceptanceError::ProseCompletionForbidden)
        );
        let raw = serde_json::to_string(&f.bundle).unwrap();
        assert!(parse_signed_acceptance_bundle(&raw).is_ok());
        let raw = raw.replacen(
            "\"candidate\":",
            "\"unknown_executable\":0,\"candidate\":",
            1,
        );
        assert!(parse_signed_acceptance_bundle(&raw).is_err());
    }
    #[test]
    fn p0_acceptance_named_two_of_two_distinct_authenticated_principals() {
        let mut first = Fixture::new(1, 2);
        first.evidence.authority.payload.quorum = 2;
        first.resign_authority();
        let mut second = Fixture::new(1, 2);
        second.evidence.authority = first.evidence.authority.clone();
        second.bundle.review.reviewer_id = "reviewer-two".into();
        second.bundle.review.k1_pubkey = key(3);
        second.bundle.acceptance.payload.reviewer_principal = "reviewer-two".into();
        second.bundle.acceptance.payload.reviewer_full_instance = "REVIEW2#fixture".into();
        second.bundle.acceptance.payload.nonce = [10; 32];
        second.evidence.scope.payload.reviewer_principal = "reviewer-two".into();
        second.evidence.scope.payload.reviewer_instance = "REVIEW2#fixture".into();
        second.evidence.scope.payload.nonce = [10; 32];
        for t in &mut second.evidence.time {
            t.payload.nonce = [10; 32];
        }
        second.refresh_reviewer(3);
        let a = first.verify(Default::default()).unwrap();
        let b = second.verify(Default::default()).unwrap();
        verify_fixture_quorum(&[a, b]).unwrap();
    }
    #[test]
    fn p0_acceptance_cas_rebase_time_disagreement_and_scope_nonce_refused() {
        let mut f = Fixture::new(1, 2);
        f.current.file_cas_rev += 20;
        // A whole-file revision jump is one bounded unrelated rebase, while the
        // target status/spec/control/candidate/overlay remain exactly pinned.
        assert!(
            authorize_reviewed_acceptance(
                &f.provider,
                LegacyReviewProfileMode::FixtureProfileV1,
                &f.bundle,
                &f.evidence,
                AcceptanceVerificationContextV1 {
                    snapshot: &f.snapshot,
                    current: &f.current,
                    assignment: &f.assignment,
                    history: &f.history,
                    dependencies: &[],
                    rebases_used: 1,
                    persisted_highwater: Default::default()
                }
            )
            .is_ok()
        );
        f.current.task_status_rev += 1;
        assert!(f.verify(Default::default()).is_err());
        let mut f = Fixture::new(1, 2);
        f.evidence.time[1].payload.midpoint_us += 30_000_001;
        f.evidence.time[1] = signed("roughtime-response", f.evidence.time[1].payload.clone(), 7);
        assert!(f.verify(Default::default()).is_err());
        let mut f = Fixture::new(1, 2);
        f.evidence.scope.payload.nonce = [11; 32];
        f.evidence.scope = signed("review-scope-content", f.evidence.scope.payload.clone(), 40);
        assert!(f.verify(Default::default()).is_err());
    }

    #[test]
    fn p0_acceptance_valid_signatures_do_not_repair_cross_record_substitution_or_dependencies() {
        let mut f = Fixture::new(1, 2);
        f.bundle.review.repo_id = "task-repository".into();
        f.refresh_signed_records();
        assert!(matches!(
            f.verify(Default::default()),
            Err(AcceptanceError::AttestationBindingMismatch)
        ));
        let mut f = Fixture::new(1, 2);
        f.bundle.review.verdict = ReviewVerdict::Rejected;
        f.refresh_signed_records();
        assert!(matches!(
            f.verify(Default::default()),
            Err(AcceptanceError::AttestationBindingMismatch)
        ));
        let mut f = Fixture::new(1, 2);
        f.snapshot
            .dependencies
            .push(crate::task_dependency::DependencyCommitment {
                target_key: crate::task_ref::TaskKey {
                    workspace_id: "fixture-workspace".into(),
                    task_source_id: "22222222222222222222222222222222".into(),
                    task_id: "prerequisite".into(),
                },
                target_spec_digest: Sha256Digest([11; 32]),
                completion_policy_digest: Sha256Digest([12; 32]),
            });
        assert!(matches!(
            f.verify(Default::default()),
            Err(AcceptanceError::DependencyUnsatisfied)
        ));
    }
}
