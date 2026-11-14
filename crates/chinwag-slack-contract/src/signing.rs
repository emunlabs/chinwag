// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Domain-separated `BLAKE3(RFC8785CanonicalJson)` + `Ed25519` (`verify_strict`) signing and
//! verification for `K1` beats, `OrgAdminPasskeyAttestationV1` grants, and `K2` Coordinator receipts.

use crate::ContractError;
use crate::jcs::to_jcs_bytes;
use crate::types::{
    BlindSlackBeatV1, CoordinatorDispatchReceiptBodyV1, Digest32, KeyFingerprint, LedgerActionV1,
    MAX_SLACK_BEAT_BYTES, OrgAdminPasskeyAttestationV1, SCHEMA_VERSION_V1, Signature64,
    SignedBlindSlackBeatV1, SignedSlackDispatchEnvelopeV1, SlackMetadataV1,
    UnsignedPasskeyAttestationV1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const K1_BEAT_DOMAIN: &[u8] = b"chinwag.slack.beat.v1\0";
pub const K1_PASSKEY_GRANT_DOMAIN: &[u8] = b"chinwag.slack.passkey_grant.v1\0";
pub const K2_DISPATCH_DOMAIN: &[u8] = b"chinwag.slack.dispatch.v1\0";

/// Zeroizing Ed25519 signer wrapper that redacts secret material in `Debug`.
pub struct Ed25519KeyPairSigner {
    signing_key: SigningKey,
}

impl fmt::Debug for Ed25519KeyPairSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPairSigner")
            .field("public_key", &self.public_fingerprint())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Ed25519KeyPairSigner {
    #[must_use]
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let zeroized = Zeroizing::new(*seed);
        let signing_key = SigningKey::from_bytes(&zeroized);
        Self { signing_key }
    }

    #[must_use]
    pub fn public_fingerprint(&self) -> KeyFingerprint {
        KeyFingerprint::from_bytes(self.signing_key.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn sign_raw_domain_payload(&self, signing_input: &[u8]) -> Signature64 {
        let sig: Signature = self.signing_key.sign(signing_input);
        Signature64::from_bytes(sig.to_bytes())
    }
}

/// Customer-configurable verification policy (`INV-CUSTOMER-CONFIGURABLE-NO-HARDCODING-01`).
#[derive(Clone, Debug)]
pub struct VerificationPolicyV1 {
    pub max_payload_bytes: usize,
    pub allowed_dispatch_hosts: Vec<String>,
    pub trusted_k1_keys: Option<Vec<KeyFingerprint>>,
    pub trusted_k2_keys: Option<Vec<KeyFingerprint>>,
    /// Required for `rich_symbols` verification — fails closed when `None` or empty
    /// so self-signed throwaway `OrgAdminPasskeyAttestationV1` keys can never disclose symbols.
    pub trusted_admin_passkey_keys: Option<Vec<KeyFingerprint>>,
    /// Optional authoritative wall-clock millisecond timestamp (`grant.expires_at_ms > now_ms`).
    pub now_ms: Option<u64>,
    /// Optional authoritative org authorization epoch (`grant.authorization_epoch == expected_authorization_epoch`).
    pub expected_authorization_epoch: Option<u64>,
}

impl Default for VerificationPolicyV1 {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_SLACK_BEAT_BYTES,
            allowed_dispatch_hosts: vec![
                "slack.chinwag.sh".to_owned(),
                "chinwag.sh".to_owned(),
                "docs.chinwag.sh".to_owned(),
            ],
            trusted_k1_keys: None,
            trusted_k2_keys: None,
            trusted_admin_passkey_keys: None,
            now_ms: None,
            expected_authorization_epoch: None,
        }
    }
}

impl VerificationPolicyV1 {
    #[must_use]
    pub fn from_env_or_default() -> Self {
        let mut policy = Self::default();
        if let Ok(raw) = std::env::var("CHINWAG_SLACK_ALLOWED_DISPATCH_HOSTS") {
            let parsed: Vec<String> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if !parsed.is_empty() {
                policy.allowed_dispatch_hosts = parsed;
            }
        }
        policy
    }

    #[must_use]
    pub fn with_allowed_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allowed_dispatch_hosts = hosts;
        self
    }

    fn check_key_in_allowlist(
        candidate: &KeyFingerprint,
        allowlist: &Option<Vec<KeyFingerprint>>,
    ) -> bool {
        match allowlist {
            None => true,
            Some(keys) => keys
                .iter()
                .any(|k| bool::from(k.as_bytes().ct_eq(candidate.as_bytes()))),
        }
    }
}

/// Compute `BLAKE3(RFC8785CanonicalJson(value))` and `domain || digest`.
pub fn domain_separated_jcs_signing_input<T: serde::Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<(Digest32, Vec<u8>), ContractError> {
    let jcs_bytes = to_jcs_bytes(value)?;
    let hash = blake3::hash(&jcs_bytes);
    let digest = Digest32::from_bytes(*hash.as_bytes());
    let mut input = Vec::with_capacity(domain.len() + 32);
    input.extend_from_slice(domain);
    input.extend_from_slice(digest.as_bytes());
    Ok((digest, input))
}

pub fn verify_ed25519_strict(
    pubkey: &KeyFingerprint,
    signing_input: &[u8],
    signature: &Signature64,
) -> Result<(), ContractError> {
    let vk = VerifyingKey::from_bytes(pubkey.as_bytes())
        .map_err(|_| ContractError::SignatureVerificationFailed)?;
    let sig = Signature::from_bytes(signature.as_bytes());
    vk.verify_strict(signing_input, &sig)
        .map_err(|_| ContractError::SignatureVerificationFailed)
}

pub fn sign_passkey_attestation(
    admin_signer: &Ed25519KeyPairSigner,
    grant: UnsignedPasskeyAttestationV1,
) -> Result<OrgAdminPasskeyAttestationV1, ContractError> {
    if grant.schema_version != SCHEMA_VERSION_V1 {
        return Err(ContractError::UnsupportedSchemaVersion(
            grant.schema_version,
        ));
    }
    if !bool::from(
        grant
            .admin_k1_pubkey
            .as_bytes()
            .ct_eq(admin_signer.public_fingerprint().as_bytes()),
    ) {
        return Err(ContractError::SignerKeyMismatch);
    }
    let (_, signing_input) = domain_separated_jcs_signing_input(K1_PASSKEY_GRANT_DOMAIN, &grant)?;
    let sig = admin_signer.sign_raw_domain_payload(&signing_input);
    Ok(OrgAdminPasskeyAttestationV1 {
        grant,
        admin_k1_signature: sig,
    })
}

fn verify_passkey_attestation_signature_only(
    attestation: &OrgAdminPasskeyAttestationV1,
) -> Result<(), ContractError> {
    if attestation.grant.schema_version != SCHEMA_VERSION_V1 {
        return Err(ContractError::UnsupportedSchemaVersion(
            attestation.grant.schema_version,
        ));
    }
    let (_, signing_input) =
        domain_separated_jcs_signing_input(K1_PASSKEY_GRANT_DOMAIN, &attestation.grant)?;
    verify_ed25519_strict(
        &attestation.grant.admin_k1_pubkey,
        &signing_input,
        &attestation.admin_k1_signature,
    )
}

pub fn verify_passkey_attestation(
    attestation: &OrgAdminPasskeyAttestationV1,
    policy: &VerificationPolicyV1,
) -> Result<(), ContractError> {
    verify_passkey_attestation_signature_only(attestation)?;
    let Some(allowlist) = policy.trusted_admin_passkey_keys.as_ref() else {
        return Err(ContractError::UntrustedSignerKey);
    };
    if allowlist.is_empty()
        || !allowlist.iter().any(|k| {
            bool::from(
                k.as_bytes()
                    .ct_eq(attestation.grant.admin_k1_pubkey.as_bytes()),
            )
        })
    {
        return Err(ContractError::UntrustedSignerKey);
    }
    if let Some(now_ms) = policy.now_ms
        && attestation.grant.expires_at_ms.get() <= now_ms
    {
        return Err(ContractError::PasskeyGrantExpired);
    }
    if let Some(expected_epoch) = policy.expected_authorization_epoch
        && attestation.grant.authorization_epoch.get() != expected_epoch
    {
        return Err(ContractError::UntrustedSignerKey);
    }
    Ok(())
}

pub fn sign_blind_slack_beat(
    k1_signer: &Ed25519KeyPairSigner,
    beat: BlindSlackBeatV1,
) -> Result<(Digest32, SignedBlindSlackBeatV1), ContractError> {
    beat.validate_semantics()?;
    if !bool::from(
        beat.k1_key_id
            .as_bytes()
            .ct_eq(k1_signer.public_fingerprint().as_bytes()),
    ) {
        return Err(ContractError::SignerKeyMismatch);
    }
    if let SlackMetadataV1::RichSymbols {
        passkey_attestation,
        ..
    } = &beat.metadata
    {
        verify_passkey_attestation_signature_only(passkey_attestation)?;
    }
    let (digest, signing_input) = domain_separated_jcs_signing_input(K1_BEAT_DOMAIN, &beat)?;
    let k1_signature = k1_signer.sign_raw_domain_payload(&signing_input);
    let signed = SignedBlindSlackBeatV1 { beat, k1_signature };
    let encoded_len = to_jcs_bytes(&signed)?.len();
    if encoded_len > MAX_SLACK_BEAT_BYTES {
        return Err(ContractError::PayloadTooLarge(encoded_len));
    }
    Ok((digest, signed))
}

pub fn verify_signed_blind_slack_beat(
    signed: &SignedBlindSlackBeatV1,
    policy: &VerificationPolicyV1,
) -> Result<Digest32, ContractError> {
    signed.beat.validate_semantics()?;
    if !VerificationPolicyV1::check_key_in_allowlist(
        &signed.beat.k1_key_id,
        &policy.trusted_k1_keys,
    ) {
        return Err(ContractError::UntrustedSignerKey);
    }
    if let SlackMetadataV1::RichSymbols {
        passkey_attestation,
        ..
    } = &signed.beat.metadata
    {
        verify_passkey_attestation(passkey_attestation, policy)?;
    }
    let (digest, signing_input) = domain_separated_jcs_signing_input(K1_BEAT_DOMAIN, &signed.beat)?;
    verify_ed25519_strict(&signed.beat.k1_key_id, &signing_input, &signed.k1_signature)?;
    Ok(digest)
}

pub fn sign_coordinator_dispatch_envelope(
    k2_signer: &Ed25519KeyPairSigner,
    signed_beat: SignedBlindSlackBeatV1,
    receipt: CoordinatorDispatchReceiptBodyV1,
    policy: &VerificationPolicyV1,
) -> Result<SignedSlackDispatchEnvelopeV1, ContractError> {
    let beat_digest = verify_signed_blind_slack_beat(&signed_beat, policy)?;
    validate_receipt_against_beat(&signed_beat.beat, &beat_digest, &receipt, policy)?;
    if !bool::from(
        receipt
            .k2_key_id
            .as_bytes()
            .ct_eq(k2_signer.public_fingerprint().as_bytes()),
    ) {
        return Err(ContractError::SignerKeyMismatch);
    }
    let (_, signing_input) = domain_separated_jcs_signing_input(K2_DISPATCH_DOMAIN, &receipt)?;
    let k2_signature = k2_signer.sign_raw_domain_payload(&signing_input);
    let env = SignedSlackDispatchEnvelopeV1 {
        signed_beat,
        receipt,
        k2_signature,
    };
    let encoded_len = to_jcs_bytes(&env)?.len();
    if encoded_len > policy.max_payload_bytes.min(MAX_SLACK_BEAT_BYTES) {
        return Err(ContractError::PayloadTooLarge(encoded_len));
    }
    Ok(env)
}

fn validate_receipt_against_beat(
    beat: &BlindSlackBeatV1,
    beat_digest: &Digest32,
    receipt: &CoordinatorDispatchReceiptBodyV1,
    policy: &VerificationPolicyV1,
) -> Result<(), ContractError> {
    if receipt.schema_version != SCHEMA_VERSION_V1 {
        return Err(ContractError::UnsupportedSchemaVersion(
            receipt.schema_version,
        ));
    }
    if !bool::from(receipt.beat_digest.as_bytes().ct_eq(beat_digest.as_bytes())) {
        return Err(ContractError::ReceiptBeatDigestMismatch);
    }
    if receipt.org_id != beat.org_id || receipt.event_id != beat.event_id {
        return Err(ContractError::ReceiptIdentityMismatch);
    }
    if matches!(
        receipt.ledger_action,
        LedgerActionV1::Quote
            | LedgerActionV1::Reserve
            | LedgerActionV1::LaptopSleepHold
            | LedgerActionV1::Void
    ) && receipt.credits_charged.get() != 0
    {
        return Err(ContractError::NonZeroCreditsDuringLaptopSleep);
    }
    let host = receipt
        .dispatch_audience
        .host()
        .ok_or(ContractError::DisallowedDispatchAudience)?;
    if !policy.allowed_dispatch_hosts.is_empty()
        && !policy.allowed_dispatch_hosts.iter().any(|h| h == &host)
    {
        return Err(ContractError::DisallowedDispatchAudience);
    }
    Ok(())
}

pub fn verify_k1_and_k2_envelope(
    envelope: &SignedSlackDispatchEnvelopeV1,
    policy: &VerificationPolicyV1,
) -> Result<Digest32, ContractError> {
    let beat_digest = verify_signed_blind_slack_beat(&envelope.signed_beat, policy)?;
    validate_receipt_against_beat(
        &envelope.signed_beat.beat,
        &beat_digest,
        &envelope.receipt,
        policy,
    )?;
    if !VerificationPolicyV1::check_key_in_allowlist(
        &envelope.receipt.k2_key_id,
        &policy.trusted_k2_keys,
    ) {
        return Err(ContractError::UntrustedSignerKey);
    }
    let (_, k2_input) = domain_separated_jcs_signing_input(K2_DISPATCH_DOMAIN, &envelope.receipt)?;
    verify_ed25519_strict(
        &envelope.receipt.k2_key_id,
        &k2_input,
        &envelope.k2_signature,
    )?;
    Ok(beat_digest)
}

/// Bounded pre-parse byte cap enforcement (`<= 32 KiB`) before JSON deserialization.
pub fn decode_bounded_json<T: DeserializeOwned>(
    raw: &[u8],
    max_bytes: usize,
) -> Result<T, ContractError> {
    let ceiling = max_bytes.min(MAX_SLACK_BEAT_BYTES);
    if raw.len() > ceiling {
        return Err(ContractError::PayloadTooLarge(raw.len()));
    }
    serde_json::from_slice(raw).map_err(|_| ContractError::SchemaRejected)
}

pub fn decode_and_verify_signed_beat_bytes(
    raw: &[u8],
    policy: &VerificationPolicyV1,
) -> Result<(SignedBlindSlackBeatV1, Digest32), ContractError> {
    let signed: SignedBlindSlackBeatV1 = decode_bounded_json(raw, policy.max_payload_bytes)?;
    let digest = verify_signed_blind_slack_beat(&signed, policy)?;
    Ok((signed, digest))
}

pub fn decode_and_verify_dispatch_envelope_bytes(
    raw: &[u8],
    policy: &VerificationPolicyV1,
) -> Result<(SignedSlackDispatchEnvelopeV1, Digest32), ContractError> {
    let env: SignedSlackDispatchEnvelopeV1 = decode_bounded_json(raw, policy.max_payload_bytes)?;
    let digest = verify_k1_and_k2_envelope(&env, policy)?;
    Ok((env, digest))
}
