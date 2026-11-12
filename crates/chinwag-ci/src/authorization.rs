// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Signed owner admission certificates. Signature verification is distinct
//! from current validity. Historical inspection cannot create CurrentAdmission.
//! Local clocks are explicit observations, not K2 trusted-time attestations.

use crate::{
    admission::{AdmissionRecord, CommittedAdmission},
    envelope::{self, AuthenticatedEnvelope, ClaimedProvenance, KeyPins, SealedEnvelope},
    intent::VerifiedIntent,
    recipient_key::{SeatSignerDirectory, SignedRecipientKeyRevocation, VerifiedRevocationState},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const CERTIFICATE_DOMAIN: &[u8] = b"chinwag-ci-owner-admission-certificate-v1\0";
const REVOCATION_STATUS_DOMAIN: &[u8] = b"chinwag-ci-owner-revocation-status-v1\0";
pub(crate) const MAX_AUTH_BYTES: usize = 64 * 1024;
const MAX_REVOCATION_STATUS_BYTES: usize = 128 * 1024;
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationError {
    #[error("CI owner authorization is malformed, out of scope or unauthenticated")]
    Rejected,
    #[error("CI owner authorization is outside its finite validity")]
    Lifetime,
}
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, AuthorizationError> {
    serde_json::to_vec(value).map_err(|_| AuthorizationError::Rejected)
}
pub(crate) fn parse<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, AuthorizationError> {
    if bytes.is_empty() || bytes.len() > MAX_AUTH_BYTES {
        return Err(AuthorizationError::Rejected);
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| AuthorizationError::Rejected)?;
    if canonical(&value)? != bytes {
        return Err(AuthorizationError::Rejected);
    }
    Ok(value)
}
pub(crate) fn digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}
pub(crate) fn signing_bytes<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Vec<u8>, AuthorizationError> {
    let bytes = canonical(value)?;
    let mut output = domain.to_vec();
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(&bytes);
    Ok(output)
}
pub(crate) fn verify_signature<T: Serialize>(
    domain: &[u8],
    statement: &T,
    signature_hex: &str,
    pin: [u8; 32],
) -> Result<(), AuthorizationError> {
    let signature: [u8; 64] = decode_hex(signature_hex)?;
    VerifyingKey::from_bytes(&pin)
        .map_err(|_| AuthorizationError::Rejected)?
        .verify_strict(
            &signing_bytes(domain, statement)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| AuthorizationError::Rejected)
}
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], AuthorizationError> {
    if value.len() != 2 * N
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AuthorizationError::Rejected);
    }
    hex::decode(value)
        .map_err(|_| AuthorizationError::Rejected)?
        .try_into()
        .map_err(|_| AuthorizationError::Rejected)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionStatement {
    version: u16,
    signer: [u8; 32],
    admission_sha256: [u8; 32],
    record: AdmissionRecord,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Certificate {
    statement: AdmissionStatement,
    signature_hex: String,
}
pub struct HistoricalAdmission {
    statement: AdmissionStatement,
    certificate: Vec<u8>,
}
/// Only produced after verifying the signature and rechecking finite validity.
/// It authorizes this exact run's evidence ingress, never repair or task start.
pub struct CurrentAdmission {
    historical: HistoricalAdmission,
}
/// An admitted artifact authenticated against an independently pinned owner
/// certificate and either current ingress or signed durable prior ingress.
/// Historical signature verification alone cannot construct this type.
/// The timestamp is an ordinary explicit host-clock observation, not K2 time.
pub struct AdmissionBoundEnvelope {
    envelope: AuthenticatedEnvelope,
    issuer: [u8; 32],
    ingress_unix: u64,
    admission: AdmissionRecord,
    certificate: Vec<u8>,
    current_ingress: bool,
}
impl std::ops::Deref for AdmissionBoundEnvelope {
    type Target = AuthenticatedEnvelope;
    fn deref(&self) -> &Self::Target {
        &self.envelope
    }
}
impl AdmissionBoundEnvelope {
    pub fn admission_issuer(&self) -> [u8; 32] {
        self.issuer
    }
    pub fn ingress_unix(&self) -> u64 {
        self.ingress_unix
    }
    pub fn admission_record(&self) -> &AdmissionRecord {
        &self.admission
    }
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    pub(crate) fn is_current_ingress(&self) -> bool {
        self.current_ingress
    }
    /// Certificate + complete signed manifest + ciphertext, stored as one
    /// bounded object. No private recipient/ACU material or raw logs appear.
    pub fn complete_admitted_blob(&self) -> Result<Vec<u8>, AuthorizationError> {
        let inner = self
            .envelope
            .complete_storage_blob()
            .map_err(|_| AuthorizationError::Rejected)?;
        let mut bytes = Vec::with_capacity(12 + self.certificate.len() + inner.len());
        bytes.extend_from_slice(b"CWCIAD01");
        bytes.extend_from_slice(&(self.certificate.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.certificate);
        bytes.extend_from_slice(&inner);
        Ok(bytes)
    }
}
pub(crate) fn certify(
    admission: &CommittedAdmission,
    signer: &iroh::SecretKey,
) -> Result<Vec<u8>, AuthorizationError> {
    let statement = AdmissionStatement {
        version: 1,
        signer: *signer.public().as_bytes(),
        admission_sha256: *admission.digest(),
        record: admission.record().clone(),
    };
    let signature_hex = hex::encode(
        signer
            .sign(&signing_bytes(CERTIFICATE_DOMAIN, &statement)?)
            .to_bytes(),
    );
    canonical(&Certificate {
        statement,
        signature_hex,
    })
}
pub fn verify_historical_certificate(
    bytes: &[u8],
    owner_public_pin: [u8; 32],
) -> Result<HistoricalAdmission, AuthorizationError> {
    let certificate: Certificate = parse(bytes)?;
    let statement = &certificate.statement;
    if statement.version != 1
        || statement.signer != owner_public_pin
        || statement.admission_sha256
            != digest(
                b"chinwag-ci-admission-record-v1\0",
                &[&canonical(&statement.record)?],
            )
        || statement.record.usable_from_unix >= statement.record.expires_unix
        || statement
            .record
            .expires_unix
            .saturating_sub(statement.record.usable_from_unix)
            > 300
        || statement.record.expires_unix > statement.record.spec.expires_unix
    {
        return Err(AuthorizationError::Rejected);
    }
    verify_signature(
        CERTIFICATE_DOMAIN,
        statement,
        &certificate.signature_hex,
        owner_public_pin,
    )?;
    Ok(HistoricalAdmission {
        statement: certificate.statement,
        certificate: bytes.to_vec(),
    })
}
impl HistoricalAdmission {
    pub fn record(&self) -> &AdmissionRecord {
        &self.statement.record
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.statement.admission_sha256
    }
    pub fn require_current(self, now_unix: u64) -> Result<CurrentAdmission, AuthorizationError> {
        if now_unix < self.record().usable_from_unix || now_unix >= self.record().expires_unix {
            return Err(AuthorizationError::Lifetime);
        }
        Ok(CurrentAdmission { historical: self })
    }
}
impl CurrentAdmission {
    pub fn issuer(&self) -> [u8; 32] {
        self.historical.statement.signer
    }
    pub fn record(&self) -> &AdmissionRecord {
        self.historical.record()
    }
    pub fn digest(&self) -> &[u8; 32] {
        self.historical.digest()
    }
    pub fn expected_provenance(
        &self,
        current_policy_sha256: [u8; 32],
        current_policy_epoch: u64,
    ) -> Result<ClaimedProvenance, AuthorizationError> {
        provenance(
            &self.historical,
            current_policy_sha256,
            current_policy_epoch,
        )
    }
    /// Caller supplies the independently owner-enrolled profile and current
    /// policy, rather than trusting corresponding envelope claims.
    pub fn authenticate_envelope(
        &self,
        envelope: SealedEnvelope,
        pins: &KeyPins,
        current_policy_sha256: [u8; 32],
        current_policy_epoch: u64,
        now_unix: u64,
    ) -> Result<AdmissionBoundEnvelope, AuthorizationError> {
        if now_unix < self.record().usable_from_unix || now_unix >= self.record().expires_unix {
            return Err(AuthorizationError::Lifetime);
        }
        let authenticated = envelope::authenticate(
            &envelope.manifest,
            &envelope.ciphertext,
            &self.expected_provenance(current_policy_sha256, current_policy_epoch)?,
            pins,
            &self.record().signing_key,
        )
        .map_err(|_| AuthorizationError::Rejected)?;
        Ok(AdmissionBoundEnvelope {
            envelope: authenticated,
            issuer: self.historical.statement.signer,
            ingress_unix: now_unix,
            admission: self.record().clone(),
            certificate: self.historical.certificate.clone(),
            current_ingress: true,
        })
    }
}
pub fn parse_admitted_blob(bytes: &[u8]) -> Result<(&[u8], SealedEnvelope), AuthorizationError> {
    if bytes.len() < 12
        || bytes.len() > crate::storage::MAX_CIPHERTEXT_BYTES
        || &bytes[..8] != b"CWCIAD01"
    {
        return Err(AuthorizationError::Rejected);
    }
    let n = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| AuthorizationError::Rejected)?,
    ) as usize;
    if n == 0 || n > MAX_AUTH_BYTES || n > bytes.len() - 12 {
        return Err(AuthorizationError::Rejected);
    }
    let certificate = &bytes[12..12 + n];
    let envelope =
        envelope::parse_storage_blob(&bytes[12 + n..]).map_err(|_| AuthorizationError::Rejected)?;
    Ok((certificate, envelope))
}
/// This accepts a signed observation of PRIOR admitted ingress, never a bare
/// expired certificate. It creates read/release context, not current publication
/// authority. The caller separately reads actual bytes through its own store.
#[allow(clippy::too_many_arguments)]
pub fn recover_stored_admitted_envelope(
    blob: &[u8],
    receipt: &[u8],
    enrolled_admission_pin: [u8; 32],
    pins: &KeyPins,
    original_policy_sha256: [u8; 32],
    original_policy_epoch: u64,
    role: crate::envelope::Destination,
    store_id: [u8; 32],
) -> Result<
    (
        AdmissionBoundEnvelope,
        crate::receipt::VerifiedStorageReceipt,
    ),
    AuthorizationError,
> {
    let (certificate, sealed) = parse_admitted_blob(blob)?;
    let historical = verify_historical_certificate(certificate, enrolled_admission_pin)?;
    let expected = provenance(&historical, original_policy_sha256, original_policy_epoch)?;
    let authenticated = envelope::authenticate(
        &sealed.manifest,
        &sealed.ciphertext,
        &expected,
        pins,
        &historical.record().signing_key,
    )
    .map_err(|_| AuthorizationError::Rejected)?;
    let (verified, ingress) = crate::receipt::verify_admitted_historical(
        receipt,
        &authenticated,
        certificate,
        enrolled_admission_pin,
        historical.record(),
        role,
        store_id,
        blob,
    )
    .map_err(|_| AuthorizationError::Rejected)?;
    Ok((
        AdmissionBoundEnvelope {
            envelope: authenticated,
            issuer: enrolled_admission_pin,
            ingress_unix: ingress,
            admission: historical.record().clone(),
            certificate: certificate.to_vec(),
            current_ingress: false,
        },
        verified,
    ))
}
fn provenance(
    historical: &HistoricalAdmission,
    policy_sha256: [u8; 32],
    policy_epoch: u64,
) -> Result<ClaimedProvenance, AuthorizationError> {
    let r = historical.record();
    if policy_sha256 == [0; 32] || policy_epoch == 0 {
        return Err(AuthorizationError::Rejected);
    }
    Ok(ClaimedProvenance {
        admission_sha256: *historical.digest(),
        repository: r.spec.repository.clone(),
        repository_id: r.spec.repository_id,
        source_commit: decode_hex(&r.spec.source_commit)?,
        workflow_ref: r.spec.workflow_ref.clone(),
        workflow_commit: decode_hex(&r.spec.workflow_commit)?,
        run_id: r.run_id,
        run_attempt: r.run_attempt,
        initiating_instance: r.initiating_instance.clone(),
        intent_digest: r.intent_digest,
        command_profile_sha256: decode_hex(&r.spec.command_sha256)?,
        delivery_profile_sha256: decode_hex(&r.spec.delivery_profile_sha256)?,
        policy_sha256,
        policy_epoch,
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationStatusStatement {
    schema: String,
    version: u16,
    signer: [u8; 32],
    intent_digest: [u8; 32],
    initiating_instance: String,
    nonce: [u8; 32],
    statements: Vec<SignedRecipientKeyRevocation>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRevocationStatus {
    statement: RevocationStatusStatement,
    signature_hex: String,
}
pub(crate) fn certify_revocation_status(
    intent: &VerifiedIntent,
    nonce: [u8; 32],
    statements: Vec<SignedRecipientKeyRevocation>,
    signer: &iroh::SecretKey,
) -> Result<Vec<u8>, AuthorizationError> {
    if bool::from(nonce[..].ct_eq(&[0_u8; 32][..])) {
        return Err(AuthorizationError::Rejected);
    }
    let statement = RevocationStatusStatement {
        schema: "chinwag.ci-revocation-status.v1".into(),
        version: 1,
        signer: *signer.public().as_bytes(),
        intent_digest: *intent.original_digest(),
        initiating_instance: intent.initiating_instance().to_owned(),
        nonce,
        statements,
    };
    let signature_hex = hex::encode(
        signer
            .sign(&signing_bytes(REVOCATION_STATUS_DOMAIN, &statement)?)
            .to_bytes(),
    );
    let encoded = canonical(&SignedRevocationStatus {
        statement,
        signature_hex,
    })?;
    if encoded.len() > MAX_REVOCATION_STATUS_BYTES {
        return Err(AuthorizationError::Rejected);
    }
    Ok(encoded)
}
pub fn verify_revocation_status(
    bytes: &[u8],
    owner_public_pin: [u8; 32],
    expected_intent_digest: [u8; 32],
    expected_initiating_instance: &str,
    expected_nonce: [u8; 32],
    signers: &SeatSignerDirectory,
    into_state: &mut VerifiedRevocationState,
) -> Result<(), AuthorizationError> {
    if bytes.is_empty()
        || bytes.len() > MAX_REVOCATION_STATUS_BYTES
        || bool::from(expected_nonce[..].ct_eq(&[0_u8; 32][..]))
    {
        return Err(AuthorizationError::Rejected);
    }
    let status: SignedRevocationStatus =
        serde_json::from_slice(bytes).map_err(|_| AuthorizationError::Rejected)?;
    if canonical(&status)? != bytes {
        return Err(AuthorizationError::Rejected);
    }
    let s = &status.statement;
    if s.schema != "chinwag.ci-revocation-status.v1"
        || s.version != 1
        || !bool::from(s.signer[..].ct_eq(&owner_public_pin[..]))
        || !bool::from(s.intent_digest[..].ct_eq(&expected_intent_digest[..]))
        || s.initiating_instance != expected_initiating_instance
        || !bool::from(s.nonce[..].ct_eq(&expected_nonce[..]))
    {
        return Err(AuthorizationError::Rejected);
    }
    verify_signature(
        REVOCATION_STATUS_DOMAIN,
        s,
        &status.signature_hex,
        owner_public_pin,
    )?;
    let mut snapshot = VerifiedRevocationState::new();
    for rev in &s.statements {
        snapshot
            .ingest_signed_revocation_struct(rev, signers)
            .map_err(|_| AuthorizationError::Rejected)?;
    }
    into_state.merge_verified(&snapshot);
    Ok(())
}

#[cfg(test)]
pub(crate) fn assert_canonical_certificate_tampering_is_refused(bytes: &[u8], pin: [u8; 32]) {
    for case in 0..4 {
        let mut certificate: Certificate = parse(bytes).unwrap();
        match case {
            0 => certificate.statement.signer[0] ^= 1,
            1 => certificate.statement.admission_sha256[0] ^= 1,
            2 => certificate.statement.record.run_id += 1,
            3 => {
                let mut signature = hex::decode(&certificate.signature_hex).unwrap();
                signature[0] ^= 1;
                certificate.signature_hex = hex::encode(signature);
            }
            _ => unreachable!(),
        }
        let wire = canonical(&certificate).unwrap();
        let _: Certificate = parse(&wire).unwrap();
        assert!(verify_historical_certificate(&wire, pin).is_err());
    }
}
