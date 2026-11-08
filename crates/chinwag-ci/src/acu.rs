// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Current owner policy, finite signed destination requests, and separately
//! signed HPKE-Base encrypted ACU responses. Durable reservation precedes gate
//! unwrap; exact encrypted response commits before transmission. No remediation
//! authority, plaintext gate cache, uncertain-send retry or rollback-proof claim.

use crate::{
    admission::{AdmissionError, AdmissionLedger, ReleaseDisposition},
    authorization::{self as auth, AdmissionBoundEnvelope, AuthorizationError},
    custody::OwnerCustody,
    envelope::{AuthenticatedEnvelope, Destination, GateSecret, KeyPins, WrappedSecret},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const POLICY_DOMAIN: &[u8] = b"chinwag-ci-acu-owner-policy-v1\0";
const REQUEST_DOMAIN: &[u8] = b"chinwag-ci-acu-destination-request-v1\0";
const GRANT_DOMAIN: &[u8] = b"chinwag-ci-acu-encrypted-grant-v1\0";
#[derive(Debug, thiserror::Error)]
pub enum AcuError {
    #[error("CI ACU policy, request or encrypted grant is refused")]
    Rejected,
    #[error("CI ACU authorization is outside its finite validity")]
    Lifetime,
    #[error("CI ACU ledger is held; reconcile original state without repeating a release")]
    Ledger(#[from] AdmissionError),
}
impl From<AuthorizationError> for AcuError {
    fn from(error: AuthorizationError) -> Self {
        match error {
            AuthorizationError::Lifetime => Self::Lifetime,
            _ => Self::Rejected,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevision {
    pub epoch: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    pub version: u16,
    pub epoch: u64,
    pub issued_unix: u64,
    pub expires_unix: u64,
    pub active: bool,
    pub allow_recipient: bool,
    pub allow_archive: bool,
    pub repository_id: u64,
    pub initiating_instance: String,
    pub key_pins_sha256: [u8; 32],
    pub recipient_store_id: [u8; 32],
    pub archive_store_id: [u8; 32],
    /// Empty means only this policy's own digest/epoch. A later owner policy
    /// must explicitly admit historical envelope epochs; no automatic lineage.
    pub allowed_historical_envelopes: Vec<PolicyRevision>,
}
impl PolicySpec {
    fn validate(&self) -> Result<(), AcuError> {
        if self.version != 1
            || self.epoch == 0
            || self.repository_id == 0
            || self.initiating_instance.is_empty()
            || self.initiating_instance.len() > 193
            || self.key_pins_sha256 == [0; 32]
            || self.recipient_store_id == [0; 32]
            || self.archive_store_id == [0; 32]
            || self.recipient_store_id == self.archive_store_id
            || self.expires_unix <= self.issued_unix
            || self.expires_unix - self.issued_unix > 3600
            || self.allowed_historical_envelopes.len() > 16
        {
            return Err(AcuError::Rejected);
        }
        for (i, item) in self.allowed_historical_envelopes.iter().enumerate() {
            if item.epoch == 0
                || item.epoch >= self.epoch
                || item.sha256 == [0; 32]
                || self.allowed_historical_envelopes[..i]
                    .iter()
                    .any(|p| p.epoch == item.epoch || p.sha256 == item.sha256)
            {
                return Err(AcuError::Rejected);
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyStatement {
    signer: [u8; 32],
    spec: PolicySpec,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPolicy {
    statement: PolicyStatement,
    signature_hex: String,
}
pub struct CurrentPolicy {
    statement: PolicyStatement,
    digest: [u8; 32],
}
pub fn key_pins_digest(pins: &KeyPins) -> Result<[u8; 32], AcuError> {
    Ok(auth::digest(
        b"chinwag-ci-acu-key-pins-v1\0",
        &[&auth::canonical(pins)?],
    ))
}
pub(crate) fn sign_policy(
    spec: &PolicySpec,
    signer: &iroh::SecretKey,
) -> Result<Vec<u8>, AcuError> {
    spec.validate()?;
    let statement = PolicyStatement {
        signer: *signer.public().as_bytes(),
        spec: spec.clone(),
    };
    let signature_hex = hex::encode(
        signer
            .sign(&auth::signing_bytes(POLICY_DOMAIN, &statement)?)
            .to_bytes(),
    );
    Ok(auth::canonical(&SignedPolicy {
        statement,
        signature_hex,
    })?)
}
pub fn verify_current_policy(
    bytes: &[u8],
    enrolled_acu_pin: [u8; 32],
    now: u64,
) -> Result<CurrentPolicy, AcuError> {
    let signed: SignedPolicy = auth::parse(bytes)?;
    signed.statement.spec.validate()?;
    if signed.statement.signer != enrolled_acu_pin {
        return Err(AcuError::Rejected);
    }
    auth::verify_signature(
        POLICY_DOMAIN,
        &signed.statement,
        &signed.signature_hex,
        enrolled_acu_pin,
    )?;
    let digest = auth::digest(
        b"chinwag-ci-acu-policy-digest-v1\0",
        &[&auth::canonical(&signed.statement)?],
    );
    let policy = CurrentPolicy {
        statement: signed.statement,
        digest,
    };
    policy.check_at(now)?;
    Ok(policy)
}
impl CurrentPolicy {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn epoch(&self) -> u64 {
        self.statement.spec.epoch
    }
    pub fn signer(&self) -> [u8; 32] {
        self.statement.signer
    }
    pub fn expires_unix(&self) -> u64 {
        self.statement.spec.expires_unix
    }
    fn check_at(&self, now: u64) -> Result<(), AcuError> {
        let s = &self.statement.spec;
        if now < s.issued_unix || now >= s.expires_unix {
            return Err(AcuError::Lifetime);
        }
        Ok(())
    }
    fn authorize(
        &self,
        envelope: &AuthenticatedEnvelope,
        role: Destination,
        store: [u8; 32],
        now: u64,
    ) -> Result<(), AcuError> {
        self.check_at(now)?;
        let s = &self.statement.spec;
        let c = envelope.claims();
        let current = c.policy_sha256 == self.digest && c.policy_epoch == s.epoch;
        let historical = s
            .allowed_historical_envelopes
            .iter()
            .any(|p| p.sha256 == c.policy_sha256 && p.epoch == c.policy_epoch);
        if !s.active
            || (!current && !historical)
            || c.repository_id != s.repository_id
            || c.initiating_instance != s.initiating_instance
            || key_pins_digest(envelope.key_pins())? != s.key_pins_sha256
            || envelope.key_pins().acu_signer != self.signer()
            || match role {
                Destination::Recipient => !s.allow_recipient || store != s.recipient_store_id,
                Destination::Archive => !s.allow_archive || store != s.archive_store_id,
            }
        {
            return Err(AcuError::Rejected);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestStatement {
    version: u16,
    pub(crate) role: Destination,
    pub(crate) signer: [u8; 32],
    pub(crate) store_id: [u8; 32],
    response_base: [u8; 32],
    envelope_digest: [u8; 32],
    admission_sha256: [u8; 32],
    policy_sha256: [u8; 32],
    policy_epoch: u64,
    nonce: [u8; 32],
    issued_unix: u64,
    expires_unix: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRequest {
    statement: RequestStatement,
    signature_hex: String,
}
pub(crate) struct VerifiedRequest {
    pub(crate) statement: RequestStatement,
    pub(crate) digest: [u8; 32],
}
fn response_pin(envelope: &AuthenticatedEnvelope, role: Destination) -> [u8; 32] {
    match role {
        Destination::Recipient => envelope.key_pins().recipient_response_base,
        Destination::Archive => envelope.key_pins().archive_response_base,
    }
}
pub(crate) fn request_statement(
    envelope: &AuthenticatedEnvelope,
    policy: &CurrentPolicy,
    role: Destination,
    store_id: [u8; 32],
    now: u64,
    expires: u64,
) -> Result<RequestStatement, AcuError> {
    policy.authorize(envelope, role, store_id, now)?;
    if expires <= now || expires > policy.expires_unix() || expires - now > 300 {
        return Err(AcuError::Lifetime);
    }
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| AcuError::Rejected)?;
    if nonce == [0; 32] {
        return Err(AcuError::Rejected);
    }
    Ok(RequestStatement {
        version: 1,
        role,
        store_id,
        signer: *envelope.receipt_signing_pin(role),
        response_base: response_pin(envelope, role),
        envelope_digest: *envelope.digest(),
        admission_sha256: envelope.claims().admission_sha256,
        policy_sha256: policy.digest(),
        policy_epoch: policy.epoch(),
        nonce,
        issued_unix: now,
        expires_unix: expires,
    })
}
pub(crate) fn request_payload(statement: &RequestStatement) -> Result<Vec<u8>, AcuError> {
    Ok(auth::signing_bytes(REQUEST_DOMAIN, statement)?)
}
pub(crate) fn finish_request(
    statement: RequestStatement,
    signature_hex: String,
) -> Result<Vec<u8>, AcuError> {
    Ok(auth::canonical(&SignedRequest {
        statement,
        signature_hex,
    })?)
}
fn verify_request(
    bytes: &[u8],
    envelope: &AuthenticatedEnvelope,
    policy: &CurrentPolicy,
    now: u64,
) -> Result<VerifiedRequest, AcuError> {
    let request: SignedRequest = auth::parse(bytes)?;
    let s = &request.statement;
    policy.authorize(envelope, s.role, s.store_id, now)?;
    if now < s.issued_unix
        || now >= s.expires_unix
        || s.expires_unix <= s.issued_unix
        || s.expires_unix - s.issued_unix > 300
        || s.expires_unix > policy.expires_unix()
    {
        return Err(AcuError::Lifetime);
    }
    if s.version != 1
        || s.nonce == [0; 32]
        || s.signer != *envelope.receipt_signing_pin(s.role)
        || s.response_base != response_pin(envelope, s.role)
        || s.envelope_digest != *envelope.digest()
        || s.admission_sha256 != envelope.claims().admission_sha256
        || s.policy_sha256 != policy.digest()
        || s.policy_epoch != policy.epoch()
    {
        return Err(AcuError::Rejected);
    }
    auth::verify_signature(REQUEST_DOMAIN, s, &request.signature_hex, s.signer)?;
    Ok(VerifiedRequest {
        statement: request.statement,
        digest: auth::digest(b"chinwag-ci-acu-request-digest-v1\0", &[bytes]),
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantStatement {
    version: u16,
    signer: [u8; 32],
    request: RequestStatement,
    request_digest: [u8; 32],
    issued_unix: u64,
    encrypted_gate: WrappedSecret,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedGrant {
    statement: GrantStatement,
    signature_hex: String,
}
/// Created only after ACU signature + full request/policy/envelope correlation.
pub struct VerifiedGrant {
    statement: GrantStatement,
}
pub(crate) fn sign_grant(
    request: &VerifiedRequest,
    encrypted_gate: WrappedSecret,
    signer: &iroh::SecretKey,
    now: u64,
) -> Result<Vec<u8>, AcuError> {
    let statement = GrantStatement {
        version: 1,
        signer: *signer.public().as_bytes(),
        request: request.statement.clone(),
        request_digest: request.digest,
        issued_unix: now,
        encrypted_gate,
    };
    let signature_hex = hex::encode(
        signer
            .sign(&auth::signing_bytes(GRANT_DOMAIN, &statement)?)
            .to_bytes(),
    );
    Ok(auth::canonical(&SignedGrant {
        statement,
        signature_hex,
    })?)
}
pub fn verify_grant(
    bytes: &[u8],
    original_request: &[u8],
    envelope: &AdmissionBoundEnvelope,
    policy: &CurrentPolicy,
    now: u64,
) -> Result<VerifiedGrant, AcuError> {
    let expected = verify_request(original_request, envelope, policy, now)?;
    let grant: SignedGrant = auth::parse(bytes)?;
    let s = &grant.statement;
    if s.version != 1
        || s.signer != policy.signer()
        || s.request_digest != expected.digest
        || auth::canonical(&s.request)? != auth::canonical(&expected.statement)?
        || s.issued_unix < s.request.issued_unix
        || s.issued_unix > now
        || s.issued_unix >= s.request.expires_unix
    {
        return Err(AcuError::Rejected);
    }
    auth::verify_signature(GRANT_DOMAIN, s, &grant.signature_hex, policy.signer())?;
    Ok(VerifiedGrant {
        statement: grant.statement,
    })
}
impl VerifiedGrant {
    pub(crate) fn open(
        &self,
        owner: &OwnerCustody,
        envelope: &AuthenticatedEnvelope,
        policy: &CurrentPolicy,
        now: u64,
    ) -> Result<GateSecret, AcuError> {
        let s = &self.statement;
        policy.authorize(envelope, s.request.role, s.request.store_id, now)?;
        if now < s.request.issued_unix || now < s.issued_unix || now >= s.request.expires_unix {
            return Err(AcuError::Lifetime);
        }
        if s.request.policy_sha256 != policy.digest()
            || s.request.policy_epoch != policy.epoch()
            || s.request.envelope_digest != *envelope.digest()
            || s.signer != policy.signer()
        {
            return Err(AcuError::Rejected);
        }
        owner
            .open_gate_from_authorized_response(envelope, s.request_digest, &s.encrypted_gate)
            .map_err(|_| AcuError::Rejected)
    }
}
pub struct ReleaseLedger {
    ledger: AdmissionLedger,
    owner_pin: [u8; 32],
    admission_pin: [u8; 32],
}
impl ReleaseLedger {
    /// Distinct owner-created directory, never an admission directory. Purpose
    /// and highest observed policy epoch persist across process restarts.
    pub fn open(
        path: &Path,
        enrolled_acu_pin: [u8; 32],
        enrolled_admission_pin: [u8; 32],
    ) -> Result<Self, AcuError> {
        ed25519_dalek::VerifyingKey::from_bytes(&enrolled_acu_pin)
            .map_err(|_| AcuError::Rejected)?;
        ed25519_dalek::VerifyingKey::from_bytes(&enrolled_admission_pin)
            .map_err(|_| AcuError::Rejected)?;
        let mut ledger = AdmissionLedger::open_release(path)?;
        ledger.bind_release_enrollment(enrolled_acu_pin, enrolled_admission_pin)?;
        Ok(Self {
            ledger,
            owner_pin: enrolled_acu_pin,
            admission_pin: enrolled_admission_pin,
        })
    }
    /// The service must load the actual current owner policy per operation.
    /// Ledger monotonicity rejects returning to an older observed epoch. A
    /// wholly rolled-back owner filesystem is outside this MVP's trust boundary.
    pub fn release(
        &mut self,
        owner: &OwnerCustody,
        envelope: &AdmissionBoundEnvelope,
        policy: &CurrentPolicy,
        request: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, AcuError> {
        policy.check_at(now)?;
        if policy.signer() != self.owner_pin || envelope.admission_issuer() != self.admission_pin {
            return Err(AcuError::Rejected);
        }
        self.ledger
            .observe_policy(policy.signer(), policy.epoch(), policy.digest())?;
        let request = verify_request(request, envelope, policy, now)?;
        let scope = auth::digest(
            b"chinwag-ci-acu-nonce-scope-v1\0",
            &[&request.statement.signer, &request.statement.nonce],
        );
        match self.ledger.reserve_release(scope, request.digest)? {
            ReleaseDisposition::Ready(bytes) => Ok(bytes),
            ReleaseDisposition::Reserved(reserved) => {
                // No P exists before this durable reservation. No bytes escape
                // before the signed encrypted response is also committed.
                let bytes = owner.create_reserved_grant(envelope, &request, now)?;
                Ok(self.ledger.finish_release(reserved, bytes)?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::{AdmissionRecord, CommittedAdmission},
        custody::{OwnerRole, PublicEnrollment},
        intent::IntentSpec,
        runner_identity::RunnerIdentity,
        storage::CiphertextStore,
    };
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;
    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    struct Fixture {
        root: OwnerCustody,
        archive: OwnerCustody,
        acu: OwnerCustody,
        envelope: AdmissionBoundEnvelope,
        issuer: [u8; 32],
        policy: CurrentPolicy,
        spec: PolicySpec,
        payload: Vec<u8>,
        _directories: Vec<tempfile::TempDir>,
    }
    impl Fixture {
        fn new() -> Self {
            Self::new_at(1000)
        }
        fn new_at(base: u64) -> Self {
            let dirs: Vec<_> = (0..6).map(|_| dir()).collect();
            let store =
                |i: usize| CiphertextStore::open(&dirs[i].path().canonicalize().unwrap()).unwrap();
            let root = OwnerCustody::create_new(
                &dirs[0].path().canonicalize().unwrap(),
                OwnerRole::Recipient,
                [10; 32],
                Some((store(3), [21; 32])),
            )
            .unwrap();
            let archive = OwnerCustody::create_new(
                &dirs[1].path().canonicalize().unwrap(),
                OwnerRole::Archive,
                [11; 32],
                Some((store(4), [22; 32])),
            )
            .unwrap();
            let acu = OwnerCustody::create_new(
                &dirs[2].path().canonicalize().unwrap(),
                OwnerRole::Acu,
                [12; 32],
                None,
            )
            .unwrap();
            let PublicEnrollment::Destination(r) = root.public_enrollment().unwrap() else {
                panic!("recipient")
            };
            let PublicEnrollment::Destination(a) = archive.public_enrollment().unwrap() else {
                panic!("archive")
            };
            let PublicEnrollment::Acu { gate_base, signer } = acu.public_enrollment().unwrap()
            else {
                panic!("acu")
            };
            assert_eq!(r.receipt_signer, r.release_request_signer);
            assert_eq!(a.receipt_signer, a.release_request_signer);
            let pins = KeyPins {
                acu_gate_base: gate_base,
                recipient_psk: r.psk,
                archive_psk: a.psk,
                recipient_response_base: r.response_base,
                archive_response_base: a.response_base,
                acu_signer: signer,
                recipient_receipt_signer: r.receipt_signer,
                archive_receipt_signer: a.receipt_signer,
            };
            let spec = PolicySpec {
                version: 1,
                epoch: 1,
                issued_unix: base,
                expires_unix: base + 1000,
                active: true,
                allow_recipient: true,
                allow_archive: true,
                repository_id: 42,
                initiating_instance: "WORKHORSE#fixture".into(),
                key_pins_sha256: key_pins_digest(&pins).unwrap(),
                recipient_store_id: [21; 32],
                archive_store_id: [22; 32],
                allowed_historical_envelopes: Vec::new(),
            };
            let policy =
                verify_current_policy(&acu.sign_release_policy(&spec).unwrap(), signer, base + 1)
                    .unwrap();
            let runner = RunnerIdentity::generate().unwrap();
            let keys = runner.public_keys();
            // Synthetic typed record ONLY in cfg(test). The independent OIDC
            // tests cover actual JWT/PoP/ledger certification before this layer.
            let admission = CommittedAdmission::synthetic_fixture(AdmissionRecord {
                spec: IntentSpec {
                    schema: "chinwag.ci-dispatch-intent.v1".into(),
                    repository: "example/ci-test".into(),
                    repository_id: 42,
                    source_commit: hex::encode([2; 20]),
                    workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/test".into(),
                    workflow_commit: hex::encode([3; 20]),
                    recipient_instance: "WORKHORSE#fixture".into(),
                    delivery_profile_sha256: hex::encode([6; 32]),
                    command_sha256: hex::encode([5; 32]),
                    nonce: hex::encode([9; 32]),
                    expires_unix: base + 1000,
                },
                initiating_instance: "WORKHORSE#fixture".into(),
                intent_digest: [4; 32],
                token_sha256: [7; 32],
                issuer_jti_sha256: [8; 32],
                audience: "fixture".into(),
                run_id: 100,
                run_attempt: 1,
                signing_key: keys.signing_ed25519,
                agent_transport_key: keys.agent_transport_ed25519,
                archive_transport_key: keys.archive_transport_ed25519,
                usable_from_unix: base,
                expires_unix: base + 300,
            });
            let issuer_owner = OwnerCustody::create_new(
                &dirs[5].path().canonicalize().unwrap(),
                OwnerRole::Admission,
                [13; 32],
                None,
            )
            .unwrap();
            let PublicEnrollment::Admission { signer: issuer } =
                issuer_owner.public_enrollment().unwrap()
            else {
                panic!("issuer")
            };
            let current = auth::verify_historical_certificate(
                &issuer_owner.certify_admission(&admission).unwrap(),
                issuer,
            )
            .unwrap()
            .require_current(base + 1)
            .unwrap();
            let claims = current.expected_provenance(policy.digest(), 1).unwrap();
            let payload = vec![0x69; 100000];
            let sealed = runner
                .seal_failure(claims.clone(), pins.clone(), &payload)
                .unwrap();
            let envelope = current
                .authenticate_envelope(sealed, &pins, policy.digest(), 1, base + 2)
                .unwrap();
            Self {
                root,
                archive,
                acu,
                envelope,
                issuer,
                policy,
                spec,
                payload,
                _directories: dirs,
            }
        }
        fn policy(&self, spec: &PolicySpec) -> CurrentPolicy {
            verify_current_policy(
                &self.acu.sign_release_policy(spec).unwrap(),
                self.policy.signer(),
                1002,
            )
            .unwrap()
        }
    }
    #[test]
    fn native_wrapper_is_exact_durable_and_rejects_other_frame_peer_or_relay() {
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3;
        let f = Fixture::new_at(base);
        let e = &f.envelope;
        let relay = "https://ci-fixture.trycloudflare.com/";
        let body = e.complete_storage_blob().unwrap();
        let claim = crate::transport::fixture_observed_claim(
            e.certificate(),
            &body,
            e.admission_record().agent_transport_key,
            relay,
        );
        let bytes = f.root.persist_native_admitted(e, &claim, relay).unwrap();
        crate::receipt::assert_canonical_native_signature_tamper_refused(
            &bytes,
            e,
            Destination::Recipient,
            [21; 32],
            relay,
        );
        crate::receipt::verify_native_admitted(&bytes, e, Destination::Recipient, [21; 32], relay)
            .unwrap();
        let blob = e.complete_admitted_blob().unwrap();
        let object = crate::storage::CiphertextClaim {
            sha256: sha2::Sha256::digest(&blob).into(),
            bytes: blob.len() as u64,
        };
        assert_eq!(f.root.read_native_receipt(object).unwrap(), bytes);
        assert!(
            crate::receipt::verify_native_admitted(
                &bytes,
                e,
                Destination::Archive,
                [22; 32],
                relay
            )
            .is_err()
        );
        assert!(
            crate::receipt::verify_native_admitted(
                &bytes,
                e,
                Destination::Recipient,
                [21; 32],
                "https://other.trycloudflare.com/"
            )
            .is_err()
        );
        let wrong = crate::transport::fixture_observed_claim(
            e.certificate(),
            b"other complete frame",
            e.admission_record().archive_transport_key,
            relay,
        );
        assert!(f.archive.persist_native_admitted(e, &wrong, relay).is_err());
        let bad_peer = crate::transport::fixture_observed_claim(
            e.certificate(),
            &body,
            e.admission_record().agent_transport_key,
            relay,
        );
        assert!(
            f.archive
                .persist_native_admitted(e, &bad_peer, relay)
                .is_err()
        );
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["statement"]["before"]["relay_origin"] =
            serde_json::json!("https://forged.trycloudflare.com/");
        assert!(
            crate::receipt::verify_native_admitted(
                &serde_json::to_vec(&changed).unwrap(),
                e,
                Destination::Recipient,
                [21; 32],
                relay
            )
            .is_err()
        );
    }
    #[test]
    fn both_destinations_need_their_own_signed_request_and_verified_encrypted_grant() {
        let f = Fixture::new();
        let d = dir();
        let mut ledger = ReleaseLedger::open(
            &d.path().canonicalize().unwrap(),
            f.policy.signer(),
            f.issuer,
        )
        .unwrap();
        let wrong_dir = dir();
        let mut wrong_issuer = ReleaseLedger::open(
            &wrong_dir.path().canonicalize().unwrap(),
            f.policy.signer(),
            f.policy.signer(),
        )
        .unwrap();
        let request = f
            .root
            .create_release_request(&f.envelope, &f.policy, 1002, 1200)
            .unwrap();
        assert!(matches!(
            wrong_issuer.release(&f.acu, &f.envelope, &f.policy, &request, 1003),
            Err(AcuError::Rejected)
        ));
        for owner in [&f.root, &f.archive] {
            let request = owner
                .create_release_request(&f.envelope, &f.policy, 1002, 1200)
                .unwrap();
            let response = ledger
                .release(&f.acu, &f.envelope, &f.policy, &request, 1003)
                .unwrap();
            let verified = verify_grant(&response, &request, &f.envelope, &f.policy, 1004).unwrap();
            assert_eq!(
                &*owner
                    .open_payload_from_grant(&f.envelope, &verified, &f.policy, 1004)
                    .unwrap(),
                &f.payload
            );
            let wrong = if std::ptr::eq(owner, &f.root) {
                &f.archive
            } else {
                &f.root
            };
            assert!(
                wrong
                    .open_payload_from_grant(&f.envelope, &verified, &f.policy, 1004)
                    .is_err()
            );
            let mut forged: SignedGrant = auth::parse(&response).unwrap();
            let mut wrapped = serde_json::to_value(&forged.statement.encrypted_gate).unwrap();
            let byte = wrapped["ciphertext"][0].as_u64().unwrap();
            wrapped["ciphertext"][0] = serde_json::json!(byte ^ 1);
            forged.statement.encrypted_gate = serde_json::from_value(wrapped).unwrap();
            let forged = auth::canonical(&forged).unwrap();
            let _: SignedGrant = auth::parse(&forged).unwrap(); // Genuine signature-tamper test, canonical wire.
            assert!(verify_grant(&forged, &request, &f.envelope, &f.policy, 1004).is_err());
        }
    }
    #[test]
    fn identical_release_after_restart_returns_exact_original_encrypted_bytes_without_renewal() {
        let f = Fixture::new();
        let d = dir();
        let path = d.path().canonicalize().unwrap();
        let request = f
            .root
            .create_release_request(&f.envelope, &f.policy, 1002, 1200)
            .unwrap();
        let mut ledger = ReleaseLedger::open(&path, f.policy.signer(), f.issuer).unwrap();
        let original = ledger
            .release(&f.acu, &f.envelope, &f.policy, &request, 1003)
            .unwrap();
        drop(ledger);
        let mut reopened = ReleaseLedger::open(&path, f.policy.signer(), f.issuer).unwrap();
        assert_eq!(
            original,
            reopened
                .release(&f.acu, &f.envelope, &f.policy, &request, 1100)
                .unwrap()
        );
        assert!(matches!(
            reopened.release(&f.acu, &f.envelope, &f.policy, &request, 1200),
            Err(AcuError::Lifetime)
        ));
        let verified = verify_grant(&original, &request, &f.envelope, &f.policy, 1100).unwrap();
        assert!(
            f.root
                .open_payload_from_grant(&f.envelope, &verified, &f.policy, 1002)
                .is_err()
        );
        assert!(
            f.root
                .open_payload_from_grant(&f.envelope, &verified, &f.policy, 1200)
                .is_err()
        );
        drop(reopened);
        assert!(ReleaseLedger::open(&path, f.policy.signer(), f.policy.signer()).is_err());
        assert!(AdmissionLedger::open(&path).is_err()); // Purpose separated after lock is released.
    }
    #[test]
    fn revocation_is_persisted_before_refusal_and_older_policy_stays_refused_after_restart() {
        let f = Fixture::new();
        let d = dir();
        let path = d.path().canonicalize().unwrap();
        let request = f
            .root
            .create_release_request(&f.envelope, &f.policy, 1002, 1200)
            .unwrap();
        let mut ledger = ReleaseLedger::open(&path, f.policy.signer(), f.issuer).unwrap();
        let original = ledger
            .release(&f.acu, &f.envelope, &f.policy, &request, 1003)
            .unwrap();
        let grant = verify_grant(&original, &request, &f.envelope, &f.policy, 1004).unwrap();
        let mut revoked = f.spec.clone();
        revoked.epoch = 2;
        revoked.active = false;
        revoked.allowed_historical_envelopes.push(PolicyRevision {
            epoch: 1,
            sha256: f.policy.digest(),
        });
        let policy = f.policy(&revoked);
        assert!(
            ledger
                .release(&f.acu, &f.envelope, &policy, &request, 1005)
                .is_err()
        );
        assert!(
            f.root
                .open_payload_from_grant(&f.envelope, &grant, &policy, 1005)
                .is_err()
        );
        drop(ledger);
        let mut ledger = ReleaseLedger::open(&path, f.policy.signer(), f.issuer).unwrap();
        assert!(matches!(
            ledger.release(&f.acu, &f.envelope, &f.policy, &request, 1006),
            Err(AcuError::Ledger(AdmissionError::Conflict))
        ));
    }
    #[test]
    fn a_new_policy_must_explicitly_admit_historical_envelopes_and_role() {
        let f = Fixture::new();
        let mut next = f.spec.clone();
        next.epoch = 2;
        assert!(
            f.root
                .create_release_request(&f.envelope, &f.policy(&next), 1003, 1200)
                .is_err()
        );
        next.allowed_historical_envelopes.push(PolicyRevision {
            epoch: 1,
            sha256: f.policy.digest(),
        });
        next.allow_archive = false;
        let policy = f.policy(&next);
        assert!(
            f.root
                .create_release_request(&f.envelope, &policy, 1003, 1200)
                .is_ok()
        );
        assert!(
            f.archive
                .create_release_request(&f.envelope, &policy, 1003, 1200)
                .is_err()
        );
    }
    #[test]
    fn an_interrupted_reservation_is_held_instead_of_rewrapping_the_gate() {
        let f = Fixture::new();
        let d = dir();
        let path = d.path().canonicalize().unwrap();
        let raw = f
            .root
            .create_release_request(&f.envelope, &f.policy, 1002, 1200)
            .unwrap();
        let request = verify_request(&raw, &f.envelope, &f.policy, 1003).unwrap();
        let scope = auth::digest(
            b"chinwag-ci-acu-nonce-scope-v1\0",
            &[&request.statement.signer, &request.statement.nonce],
        );
        let mut ledger = ReleaseLedger::open(&path, f.policy.signer(), f.issuer).unwrap();
        assert!(matches!(
            ledger
                .ledger
                .reserve_release(scope, request.digest)
                .unwrap(),
            ReleaseDisposition::Reserved(_)
        ));
        drop(ledger);
        let mut ledger = ReleaseLedger::open(&path, f.policy.signer(), f.issuer).unwrap();
        assert!(matches!(
            ledger.release(&f.acu, &f.envelope, &f.policy, &raw, 1004),
            Err(AcuError::Ledger(AdmissionError::CommitUnknown))
        ));
    }
    #[test]
    fn unsigned_changed_cross_request_and_expired_authorizations_cannot_release() {
        let f = Fixture::new();
        let d = dir();
        let mut ledger = ReleaseLedger::open(
            &d.path().canonicalize().unwrap(),
            f.policy.signer(),
            f.issuer,
        )
        .unwrap();
        let raw = f
            .root
            .create_release_request(&f.envelope, &f.policy, 1002, 1200)
            .unwrap();
        for field in [
            "nonce",
            "envelope_digest",
            "response_base",
            "signer",
            "admission_sha256",
            "store_id",
        ] {
            let mut changed: SignedRequest = auth::parse(&raw).unwrap();
            let target = match field {
                "nonce" => &mut changed.statement.nonce,
                "envelope_digest" => &mut changed.statement.envelope_digest,
                "response_base" => &mut changed.statement.response_base,
                "signer" => &mut changed.statement.signer,
                "admission_sha256" => &mut changed.statement.admission_sha256,
                "store_id" => &mut changed.statement.store_id,
                _ => unreachable!(),
            };
            target[0] ^= 1;
            assert!(
                ledger
                    .release(
                        &f.acu,
                        &f.envelope,
                        &f.policy,
                        &auth::canonical(&changed).unwrap(),
                        1003
                    )
                    .is_err()
            );
        }
        let response = ledger
            .release(&f.acu, &f.envelope, &f.policy, &raw, 1003)
            .unwrap();
        let other = f
            .root
            .create_release_request(&f.envelope, &f.policy, 1002, 1200)
            .unwrap();
        assert!(verify_grant(&response, &other, &f.envelope, &f.policy, 1004).is_err());
        assert!(verify_grant(&response, &raw, &f.envelope, &f.policy, 1001).is_err());
        assert!(verify_grant(&response, &raw, &f.envelope, &f.policy, 1200).is_err());
        let mut padded = raw.clone();
        padded.push(b' ');
        assert!(
            ledger
                .release(&f.acu, &f.envelope, &f.policy, &padded, 1004)
                .is_err()
        );
        assert!(f.root.sign_release_policy(&f.spec).is_err());
    }
    #[test]
    fn cold_archive_recovery_uses_signed_durable_ingress_after_producer_admission_expires() {
        use crate::{authorization, receipt};
        let Fixture {
            root,
            archive,
            acu,
            envelope,
            policy,
            spec,
            payload,
            _directories: dirs,
            issuer,
        } = Fixture::new();
        let er = root.public_enrollment().unwrap();
        let ea = archive.public_enrollment().unwrap();
        let pins = envelope.key_pins().clone();
        let original_policy = policy.digest();
        let rr = root
            .persist_admitted_fixture(&envelope, 1003, 1003)
            .unwrap();
        let ra = archive
            .persist_admitted_fixture(&envelope, 1003, 1003)
            .unwrap();
        let vr =
            receipt::verify_admitted(&rr, &envelope, Destination::Recipient, [21; 32]).unwrap();
        let va = receipt::verify_admitted(&ra, &envelope, Destination::Archive, [22; 32]).unwrap();
        assert_eq!(
            root.read_complete_object(&vr).unwrap(),
            archive.read_complete_object(&va).unwrap()
        );
        let certificate = envelope.certificate().to_vec();
        assert!(
            authorization::verify_historical_certificate(&certificate, issuer)
                .unwrap()
                .require_current(1401)
                .is_err()
        );
        drop(root);
        drop(archive);
        drop(envelope); // No live ingress value survives.
        let store =
            |i: usize| CiphertextStore::open(&dirs[i].path().canonicalize().unwrap()).unwrap();
        let root = OwnerCustody::open_enrolled(
            &dirs[0].path().canonicalize().unwrap(),
            OwnerRole::Recipient,
            [10; 32],
            Some((store(3), [21; 32])),
            &er,
        )
        .unwrap();
        let archive = OwnerCustody::open_enrolled(
            &dirs[1].path().canonicalize().unwrap(),
            OwnerRole::Archive,
            [11; 32],
            Some((store(4), [22; 32])),
            &ea,
        )
        .unwrap();
        let mut new_spec = spec;
        new_spec.epoch = 2;
        new_spec.issued_unix = 1400;
        new_spec.expires_unix = 2000;
        new_spec.allowed_historical_envelopes.push(PolicyRevision {
            epoch: 1,
            sha256: original_policy,
        });
        let current = verify_current_policy(
            &acu.sign_release_policy(&new_spec).unwrap(),
            policy.signer(),
            1401,
        )
        .unwrap();
        let d = dir();
        let mut ledger =
            ReleaseLedger::open(&d.path().canonicalize().unwrap(), policy.signer(), issuer)
                .unwrap();
        for (owner, role, id, claim) in [
            (&root, Destination::Recipient, [21; 32], vr.object_claim()),
            (&archive, Destination::Archive, [22; 32], va.object_claim()),
        ] {
            let (blob, stored_receipt) = owner.read_admitted_object(claim).unwrap();
            let (historical, verified) = authorization::recover_stored_admitted_envelope(
                &blob,
                &stored_receipt,
                issuer,
                &pins,
                original_policy,
                1,
                role,
                id,
            )
            .unwrap();
            assert_eq!(verified.object_claim().sha256, claim.sha256);
            assert_eq!(historical.ingress_unix(), 1002);
            assert!(
                owner
                    .persist_admitted_fixture(&historical, 1401, 1401)
                    .is_err()
            ); // No publication renewal.
            let request = owner
                .create_release_request(&historical, &current, 1401, 1600)
                .unwrap();
            let response = ledger
                .release(&acu, &historical, &current, &request, 1402)
                .unwrap();
            let grant = verify_grant(&response, &request, &historical, &current, 1403).unwrap();
            assert_eq!(
                &*owner
                    .open_payload_from_grant(&historical, &grant, &current, 1403)
                    .unwrap(),
                &payload
            );
        }
    }
    #[test]
    fn bare_ciphertext_receipts_changed_ingress_and_missing_sidecars_cannot_create_historical_authority()
     {
        use crate::{authorization, receipt};
        let f = Fixture::new();
        let legacy = f.root.persist(&f.envelope).unwrap();
        let original = f
            .root
            .persist_admitted_fixture(&f.envelope, 1003, 1003)
            .unwrap();
        let verified =
            receipt::verify_admitted(&original, &f.envelope, Destination::Recipient, [21; 32])
                .unwrap();
        let blob = f.root.read_complete_object(&verified).unwrap();
        let pins = f.envelope.key_pins();
        let recover = |blob: &[u8], receipt: &[u8]| {
            authorization::recover_stored_admitted_envelope(
                blob,
                receipt,
                f.issuer,
                pins,
                f.policy.digest(),
                1,
                Destination::Recipient,
                [21; 32],
            )
        };
        assert!(recover(&blob, &legacy).is_err());
        let text = std::str::from_utf8(&original).unwrap();
        for (from, to) in [
            (
                "\"authenticated_ingress_unix\":1002",
                "\"authenticated_ingress_unix\":999",
            ),
            (
                "\"storage_observed_unix\":1003",
                "\"storage_observed_unix\":1300",
            ),
        ] {
            assert!(text.contains(from));
            assert!(recover(&blob, text.replace(from, to).as_bytes()).is_err());
        }
        let mut forged = original.clone();
        let offset = text.rfind("\"signature_hex\":\"").unwrap() + "\"signature_hex\":\"".len();
        forged[offset] = if forged[offset] == b'0' { b'1' } else { b'0' };
        assert!(recover(&blob, &forged).is_err());
        let mut changed = blob.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(recover(&changed, &original).is_err());
        assert!(
            f.root
                .persist_admitted_fixture(&f.envelope, 1300, 1300)
                .is_err()
        );
        let name = format!(
            "{}.ingress-receipt.json",
            hex::encode(verified.object_claim().sha256)
        );
        std::fs::rename(
            f._directories[3].path().join(&name),
            f._directories[3].path().join("preserved-ingress.json"),
        )
        .unwrap();
        assert!(
            f.root
                .read_admitted_object(verified.object_claim())
                .is_err()
        );
        assert!(
            f.root
                .persist_admitted_fixture(&f.envelope, 1004, 1004)
                .is_err()
        ); // Never recreates receipt/new expiry.
    }
    #[test]
    fn persistence_completing_after_admission_expiry_preserves_object_without_a_false_timely_receipt()
     {
        let f = Fixture::new();
        assert!(
            f.root
                .persist_admitted_fixture(&f.envelope, 1003, 1300)
                .is_err()
        );
        let entries: Vec<_> = std::fs::read_dir(f._directories[3].path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].to_str().unwrap().ends_with(".cwcipher"));
        assert!(
            f.root
                .persist_admitted_fixture(&f.envelope, 1004, 1004)
                .is_err()
        );
        let f = Fixture::new();
        assert!(
            f.root
                .persist_admitted_fixture(&f.envelope, 1003, 1002)
                .is_err()
        );
    }
}
