// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Explicit Ed25519-authenticated recipient HPKE (`X25519-MLKEM768`, `0x647a`)
//! encryption-key enrollment, `.chinwag/allowed_signers` 1-to-1 seat bijection,
//! purpose separation, monotonic epoch rotation, and revocation verification.
//!
//! `.chinwag/allowed_signers` authorizes Ed25519 signing keys, which does not by
//! itself establish an HPKE encryption key. Every recipient encryption key used
//! by `chinwag-ci` (either for direct offline Base-mode `.cwcard` sealing or for
//! Enterprise 2-of-3 ACU-gated `DeliveryProfile` binding) must carry an explicit
//! domain-separated Ed25519 signature from that seat's sole registered signing
//! key over `(seat, kid, purpose, ciphersuite, kem_id, kdf_id, aead_id,
//! enc_public_key_hex, epoch, issued_unix, expires_unix, revoked)`.

use crate::envelope::{
    AEAD_ID_CHACHA20_POLY1305, AuthenticatedCwcard, CIPHERSUITE_X25519_MLKEM768, EnvelopeError,
    KDF_ID_HKDF_SHA256, KEM_ID_X25519_MLKEM768, KemPublicKey, KemSuite, XWING_PUBLIC_KEY_BYTES,
    open_cwcard_with_xwing_secret,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{Kem as KemTrait, Serializable, kem::XWing};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const RECIPIENT_KEY_SCHEMA_V1: &str = "chinwag.ci-recipient-hpke-key.v1";
pub const RECIPIENT_REVOCATION_SCHEMA_V1: &str = "chinwag.ci-recipient-hpke-revocation.v1";
pub const MAX_RECIPIENT_KEY_LIFETIME_SECONDS: u64 = 90 * 86_400;

const RECIPIENT_KEY_SIGNING_DOMAIN: &[u8] = b"chinwag-ci-recipient-hpke-key-v1\0";
const RECIPIENT_REVOCATION_SIGNING_DOMAIN: &[u8] = b"chinwag-ci-recipient-hpke-revocation-v1\0";
const MAX_ALLOWED_SIGNERS_BYTES: usize = 256 * 1024;
const MAX_SIGNED_KEY_BYTES: usize = 16 * 1024;
const MAX_SIGNED_REVOCATION_BYTES: usize = 32 * 1024;
const MAX_REVOKED_KIDS_PER_STATEMENT: usize = 256;

type HybridPrivateKey = <XWing as KemTrait>::PrivateKey;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecipientKeyError {
    #[error("CI recipient encryption-key descriptor or signer binding is refused")]
    Rejected,
    #[error("CI recipient encryption key has been revoked or superseded")]
    Revoked,
    #[error("CI recipient encryption key is outside its finite validity window")]
    Lifetime,
    #[error("CI recipient encryption-key entropy is unavailable")]
    Entropy,
}

/// Explicit single-purpose binding for each enrolled recipient HPKE key so an
/// ACU-gated recipient key can never be repurposed for offline Base-mode `.cwcard`
/// sealing (or vice versa).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecipientKeyPurpose {
    #[serde(rename = "cwcard:offline-base-v1")]
    CwcardOfflineBase,
    #[serde(rename = "acu:recipient-psk-v1")]
    AcuRecipientPsk,
    #[serde(rename = "acu:recipient-response-base-v1")]
    AcuRecipientResponseBase,
}

impl RecipientKeyPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CwcardOfflineBase => "cwcard:offline-base-v1",
            Self::AcuRecipientPsk => "acu:recipient-psk-v1",
            Self::AcuRecipientResponseBase => "acu:recipient-response-base-v1",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientKeyDescriptor {
    pub schema: String,
    pub version: u16,
    pub seat: String,
    pub kid: String,
    pub purpose: RecipientKeyPurpose,
    pub signer_ed25519: [u8; 32],
    pub ciphersuite: String,
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub enc_public_key_hex: String,
    pub epoch: u64,
    pub issued_unix: u64,
    pub expires_unix: u64,
    pub revoked: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecipientKey {
    pub descriptor: RecipientKeyDescriptor,
    pub signature_hex: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientKeyRevocation {
    pub schema: String,
    pub version: u16,
    pub seat: String,
    pub signer_ed25519: [u8; 32],
    pub min_valid_epoch: u64,
    pub revoked_kids: Vec<String>,
    pub issued_unix: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecipientKeyRevocation {
    pub statement: RecipientKeyRevocation,
    pub signature_hex: String,
}

/// Bijective 1-to-1 directory mapping canonical uppercase seat handles to their
/// sole authorized Ed25519 signing public keys (`INV-SOLE-KEYPAIR-PER-SEAT-01`).
#[derive(Clone)]
pub struct SeatSignerDirectory {
    by_seat: BTreeMap<String, [u8; 32]>,
}

impl SeatSignerDirectory {
    /// Parses `.chinwag/allowed_signers` and enforces strict 1-to-1 bijection:
    /// every non-comment line must resolve to a valid uppercase seat and a
    /// non-weak Ed25519 public key, with zero duplicate seats and zero shared
    /// public keys across seats.
    pub fn from_allowed_signers(content: &str) -> Result<Self, RecipientKeyError> {
        if content.is_empty() || content.len() > MAX_ALLOWED_SIGNERS_BYTES {
            return Err(RecipientKeyError::Rejected);
        }
        let non_comment_lines = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .count();
        if non_comment_lines == 0 {
            return Err(RecipientKeyError::Rejected);
        }
        let parsed = chinwag_swarm::identity::parse_allowed_signers(content);
        if parsed.len() != non_comment_lines {
            return Err(RecipientKeyError::Rejected);
        }
        let mut by_seat: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        for (seat_opt, pubkey) in parsed {
            let Some(seat) = seat_opt else {
                return Err(RecipientKeyError::Rejected);
            };
            insert_bijective_seat(&mut by_seat, &seat, pubkey)?;
        }
        Ok(Self { by_seat })
    }

    pub fn from_pinned_seats(entries: &[(&str, [u8; 32])]) -> Result<Self, RecipientKeyError> {
        if entries.is_empty() {
            return Err(RecipientKeyError::Rejected);
        }
        let mut by_seat: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        for (seat, pubkey) in entries {
            insert_bijective_seat(&mut by_seat, seat, *pubkey)?;
        }
        Ok(Self { by_seat })
    }

    pub fn pubkey_for_seat(&self, seat: &str) -> Option<[u8; 32]> {
        self.by_seat.get(seat).copied()
    }
}

fn insert_bijective_seat(
    by_seat: &mut BTreeMap<String, [u8; 32]>,
    seat: &str,
    pubkey: [u8; 32],
) -> Result<(), RecipientKeyError> {
    if !valid_seat(seat) || by_seat.contains_key(seat) {
        return Err(RecipientKeyError::Rejected);
    }
    let vk = VerifyingKey::from_bytes(&pubkey).map_err(|_| RecipientKeyError::Rejected)?;
    if vk.is_weak() {
        return Err(RecipientKeyError::Rejected);
    }
    for existing in by_seat.values() {
        if bool::from(existing[..].ct_eq(&pubkey[..])) {
            return Err(RecipientKeyError::Rejected);
        }
    }
    by_seat.insert(seat.to_owned(), pubkey);
    Ok(())
}

/// Monotonic verified revocation state (`kid` blacklist + seat-wide and
/// `(seat, purpose)` minimum valid epochs). Revocations are grow-only and can
/// never be rolled back.
#[derive(Clone, Default)]
pub struct VerifiedRevocationState {
    seat_min_epoch: BTreeMap<String, u64>,
    purpose_min_epoch: BTreeMap<(String, RecipientKeyPurpose), u64>,
    revoked_kids: BTreeMap<String, BTreeSet<String>>,
    latest_issued_unix: BTreeMap<String, u64>,
}

impl VerifiedRevocationState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ingest_signed_revocation(
        &mut self,
        bytes: &[u8],
        signers: &SeatSignerDirectory,
    ) -> Result<(), RecipientKeyError> {
        let signed: SignedRecipientKeyRevocation =
            parse_canonical(bytes, MAX_SIGNED_REVOCATION_BYTES)?;
        self.ingest_signed_revocation_struct(&signed, signers)
    }

    pub(crate) fn ingest_signed_revocation_struct(
        &mut self,
        signed: &SignedRecipientKeyRevocation,
        signers: &SeatSignerDirectory,
    ) -> Result<(), RecipientKeyError> {
        let reencoded = serde_json::to_vec(signed).map_err(|_| RecipientKeyError::Rejected)?;
        if reencoded.is_empty() || reencoded.len() > MAX_SIGNED_REVOCATION_BYTES {
            return Err(RecipientKeyError::Rejected);
        }
        let s = &signed.statement;
        if s.schema != RECIPIENT_REVOCATION_SCHEMA_V1
            || s.version != 1
            || !valid_seat(&s.seat)
            || s.min_valid_epoch == 0
            || s.issued_unix == 0
            || s.revoked_kids.len() > MAX_REVOKED_KIDS_PER_STATEMENT
        {
            return Err(RecipientKeyError::Rejected);
        }
        for (idx, kid) in s.revoked_kids.iter().enumerate() {
            if !valid_kid(kid) || (idx > 0 && &s.revoked_kids[idx - 1] >= kid) {
                return Err(RecipientKeyError::Rejected);
            }
        }
        let Some(expected_signer) = signers.pubkey_for_seat(&s.seat) else {
            return Err(RecipientKeyError::Rejected);
        };
        if !bool::from(s.signer_ed25519[..].ct_eq(&expected_signer[..])) {
            return Err(RecipientKeyError::Rejected);
        }
        verify_ed25519(
            &expected_signer,
            &revocation_signing_bytes(s)?,
            &signed.signature_hex,
        )?;
        if let Some(&prev_unix) = self.latest_issued_unix.get(&s.seat)
            && s.issued_unix < prev_unix
        {
            return Err(RecipientKeyError::Rejected);
        }
        self.latest_issued_unix
            .insert(s.seat.clone(), s.issued_unix);
        let floor = self.seat_min_epoch.entry(s.seat.clone()).or_insert(1);
        *floor = (*floor).max(s.min_valid_epoch);
        let set = self.revoked_kids.entry(s.seat.clone()).or_default();
        for kid in &s.revoked_kids {
            set.insert(kid.clone());
        }
        Ok(())
    }

    pub fn is_revoked(&self, seat: &str, kid: &str, epoch: u64) -> bool {
        if let Some(&min_epoch) = self.seat_min_epoch.get(seat)
            && epoch < min_epoch
        {
            return true;
        }
        self.revoked_kids
            .get(seat)
            .is_some_and(|kids| kids.contains(kid))
    }

    fn is_revoked_for_purpose(
        &self,
        seat: &str,
        purpose: RecipientKeyPurpose,
        kid: &str,
        epoch: u64,
    ) -> bool {
        if self.is_revoked(seat, kid, epoch) {
            return true;
        }
        self.purpose_min_epoch
            .get(&(seat.to_owned(), purpose))
            .is_some_and(|&min_epoch| epoch < min_epoch)
    }

    fn record_superseded_key(
        &mut self,
        seat: &str,
        purpose: RecipientKeyPurpose,
        superseded_kid: &str,
        new_min_epoch: u64,
    ) {
        self.revoked_kids
            .entry(seat.to_owned())
            .or_default()
            .insert(superseded_kid.to_owned());
        let entry = self
            .purpose_min_epoch
            .entry((seat.to_owned(), purpose))
            .or_insert(1);
        *entry = (*entry).max(new_min_epoch);
    }
}

/// Cryptographically verified recipient `X25519-MLKEM768` (`0x647a`) public key,
/// produced only after validating `.chinwag/allowed_signers` seat bijection,
/// strict Ed25519 signature, canonical ML-KEM-768 + contributory X25519 key
/// shares, finite validity window, and non-revoked status.
#[derive(Clone)]
pub struct VerifiedRecipientKey {
    descriptor: RecipientKeyDescriptor,
    public_key: KemPublicKey,
    public_key_sha256: [u8; 32],
}

impl VerifiedRecipientKey {
    pub fn seat(&self) -> &str {
        &self.descriptor.seat
    }

    pub fn kid(&self) -> &str {
        &self.descriptor.kid
    }

    pub fn epoch(&self) -> u64 {
        self.descriptor.epoch
    }

    pub fn purpose(&self) -> RecipientKeyPurpose {
        self.descriptor.purpose
    }

    pub fn kem_id(&self) -> u16 {
        self.descriptor.kem_id
    }

    pub fn ciphersuite(&self) -> &str {
        &self.descriptor.ciphersuite
    }

    pub fn issued_unix(&self) -> u64 {
        self.descriptor.issued_unix
    }

    pub fn expires_unix(&self) -> u64 {
        self.descriptor.expires_unix
    }

    pub fn public_key(&self) -> &KemPublicKey {
        &self.public_key
    }

    pub fn public_key_sha256(&self) -> [u8; 32] {
        self.public_key_sha256
    }
}

pub fn descriptor_signing_bytes(
    descriptor: &RecipientKeyDescriptor,
) -> Result<Vec<u8>, RecipientKeyError> {
    let canonical_json = serde_json::to_vec(descriptor).map_err(|_| RecipientKeyError::Rejected)?;
    Ok(framed_domain(
        RECIPIENT_KEY_SIGNING_DOMAIN,
        &[
            descriptor.schema.as_bytes(),
            &descriptor.version.to_be_bytes(),
            descriptor.seat.as_bytes(),
            descriptor.kid.as_bytes(),
            descriptor.purpose.as_str().as_bytes(),
            &descriptor.signer_ed25519,
            descriptor.ciphersuite.as_bytes(),
            &descriptor.kem_id.to_be_bytes(),
            &descriptor.kdf_id.to_be_bytes(),
            &descriptor.aead_id.to_be_bytes(),
            descriptor.enc_public_key_hex.as_bytes(),
            &descriptor.epoch.to_be_bytes(),
            &descriptor.issued_unix.to_be_bytes(),
            &descriptor.expires_unix.to_be_bytes(),
            &[u8::from(descriptor.revoked)],
            &canonical_json,
        ],
    ))
}

fn revocation_signing_bytes(
    statement: &RecipientKeyRevocation,
) -> Result<Vec<u8>, RecipientKeyError> {
    let canonical_json = serde_json::to_vec(statement).map_err(|_| RecipientKeyError::Rejected)?;
    Ok(framed_domain(
        RECIPIENT_REVOCATION_SIGNING_DOMAIN,
        &[
            statement.schema.as_bytes(),
            &statement.version.to_be_bytes(),
            statement.seat.as_bytes(),
            &statement.signer_ed25519,
            &statement.min_valid_epoch.to_be_bytes(),
            &statement.issued_unix.to_be_bytes(),
            &canonical_json,
        ],
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn sign_public_key_enrollment_descriptor(
    seat: &str,
    kid: &str,
    epoch: u64,
    purpose: RecipientKeyPurpose,
    public_key: &KemPublicKey,
    issued_unix: u64,
    expires_unix: u64,
    signer: &SigningKey,
) -> Result<SignedRecipientKey, RecipientKeyError> {
    if !valid_seat(seat)
        || !valid_kid(kid)
        || epoch == 0
        || public_key.suite() != KemSuite::X25519MlKem768
        || public_key.as_bytes().len() != XWING_PUBLIC_KEY_BYTES
    {
        return Err(RecipientKeyError::Rejected);
    }
    validate_lifetime_bounds(issued_unix, expires_unix)?;
    let vk = signer.verifying_key();
    if vk.is_weak() {
        return Err(RecipientKeyError::Rejected);
    }
    // Re-validate canonical FIPS 203 ML-KEM-768 + contributory X25519 components.
    let _ = KemPublicKey::from_x25519_mlkem768_bytes(public_key.as_bytes())
        .map_err(|_| RecipientKeyError::Rejected)?;
    let descriptor = RecipientKeyDescriptor {
        schema: RECIPIENT_KEY_SCHEMA_V1.into(),
        version: 1,
        seat: seat.to_owned(),
        kid: kid.to_owned(),
        purpose,
        signer_ed25519: vk.to_bytes(),
        ciphersuite: CIPHERSUITE_X25519_MLKEM768.into(),
        kem_id: KEM_ID_X25519_MLKEM768,
        kdf_id: KDF_ID_HKDF_SHA256,
        aead_id: AEAD_ID_CHACHA20_POLY1305,
        enc_public_key_hex: hex::encode(public_key.as_bytes()),
        epoch,
        issued_unix,
        expires_unix,
        revoked: false,
    };
    let sig = signer.sign(&descriptor_signing_bytes(&descriptor)?);
    Ok(SignedRecipientKey {
        descriptor,
        signature_hex: hex::encode(sig.to_bytes()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn sign_public_key_enrollment(
    seat: &str,
    kid: &str,
    epoch: u64,
    purpose: RecipientKeyPurpose,
    public_key: &KemPublicKey,
    issued_unix: u64,
    expires_unix: u64,
    signer: &SigningKey,
) -> Result<Vec<u8>, RecipientKeyError> {
    let signed = sign_public_key_enrollment_descriptor(
        seat,
        kid,
        epoch,
        purpose,
        public_key,
        issued_unix,
        expires_unix,
        signer,
    )?;
    serde_json::to_vec(&signed).map_err(|_| RecipientKeyError::Rejected)
}

pub fn sign_revocation_statement(
    seat: &str,
    min_valid_epoch: u64,
    revoked_kids: &[String],
    issued_unix: u64,
    signer: &SigningKey,
) -> Result<Vec<u8>, RecipientKeyError> {
    if !valid_seat(seat)
        || min_valid_epoch == 0
        || issued_unix == 0
        || revoked_kids.len() > MAX_REVOKED_KIDS_PER_STATEMENT
    {
        return Err(RecipientKeyError::Rejected);
    }
    let mut normalized_kids: Vec<String> = Vec::with_capacity(revoked_kids.len());
    for kid in revoked_kids {
        if !valid_kid(kid) {
            return Err(RecipientKeyError::Rejected);
        }
        normalized_kids.push(kid.clone());
    }
    normalized_kids.sort();
    normalized_kids.dedup();
    let vk = signer.verifying_key();
    if vk.is_weak() {
        return Err(RecipientKeyError::Rejected);
    }
    let statement = RecipientKeyRevocation {
        schema: RECIPIENT_REVOCATION_SCHEMA_V1.into(),
        version: 1,
        seat: seat.to_owned(),
        signer_ed25519: vk.to_bytes(),
        min_valid_epoch,
        revoked_kids: normalized_kids,
        issued_unix,
    };
    let sig = signer.sign(&revocation_signing_bytes(&statement)?);
    serde_json::to_vec(&SignedRecipientKeyRevocation {
        statement,
        signature_hex: hex::encode(sig.to_bytes()),
    })
    .map_err(|_| RecipientKeyError::Rejected)
}

pub fn verify_signed_recipient_key(
    bytes: &[u8],
    signers: &SeatSignerDirectory,
    revocations: &VerifiedRevocationState,
    now_unix: u64,
) -> Result<VerifiedRecipientKey, RecipientKeyError> {
    let signed: SignedRecipientKey = parse_canonical(bytes, MAX_SIGNED_KEY_BYTES)?;
    verify_signed_recipient_key_struct(&signed, signers, revocations, Some(now_unix))
}

pub(crate) fn verify_signed_recipient_key_struct(
    signed: &SignedRecipientKey,
    signers: &SeatSignerDirectory,
    revocations: &VerifiedRevocationState,
    now_unix: Option<u64>,
) -> Result<VerifiedRecipientKey, RecipientKeyError> {
    let reencoded = serde_json::to_vec(signed).map_err(|_| RecipientKeyError::Rejected)?;
    if reencoded.is_empty() || reencoded.len() > MAX_SIGNED_KEY_BYTES {
        return Err(RecipientKeyError::Rejected);
    }
    let d = &signed.descriptor;
    if d.schema != RECIPIENT_KEY_SCHEMA_V1
        || d.version != 1
        || !valid_seat(&d.seat)
        || !valid_kid(&d.kid)
        || d.ciphersuite != CIPHERSUITE_X25519_MLKEM768
        || d.kem_id != KEM_ID_X25519_MLKEM768
        || d.kdf_id != KDF_ID_HKDF_SHA256
        || d.aead_id != AEAD_ID_CHACHA20_POLY1305
        || d.epoch == 0
    {
        return Err(RecipientKeyError::Rejected);
    }
    validate_lifetime_bounds(d.issued_unix, d.expires_unix)?;
    let Some(expected_signer) = signers.pubkey_for_seat(&d.seat) else {
        return Err(RecipientKeyError::Rejected);
    };
    if !bool::from(d.signer_ed25519[..].ct_eq(&expected_signer[..])) {
        return Err(RecipientKeyError::Rejected);
    }
    verify_ed25519(
        &expected_signer,
        &descriptor_signing_bytes(d)?,
        &signed.signature_hex,
    )?;
    let raw_pk = decode_lower_hex_exact(&d.enc_public_key_hex, XWING_PUBLIC_KEY_BYTES)?;
    let public_key = KemPublicKey::from_x25519_mlkem768_bytes(&raw_pk)
        .map_err(|_| RecipientKeyError::Rejected)?;
    // Reject accidental reuse of seat signing pubkey bytes inside X25519 share.
    if bool::from(public_key.x25519_component()[..].ct_eq(&expected_signer[..])) {
        return Err(RecipientKeyError::Rejected);
    }
    if d.revoked || revocations.is_revoked_for_purpose(&d.seat, d.purpose, &d.kid, d.epoch) {
        return Err(RecipientKeyError::Revoked);
    }
    if let Some(now) = now_unix
        && (now < d.issued_unix || now >= d.expires_unix)
    {
        return Err(RecipientKeyError::Lifetime);
    }
    let public_key_sha256 = public_key.sha256();
    Ok(VerifiedRecipientKey {
        descriptor: signed.descriptor.clone(),
        public_key,
        public_key_sha256,
    })
}

/// Stateful registry enforcing initial enrollment, strict monotonic epoch
/// rotation (distinct `kid`, distinct `KemPublicKey`, strictly advancing `epoch`
/// even across active-key revocations), and automatic supersession of prior
/// epochs in `VerifiedRevocationState`.
#[derive(Default)]
pub struct RecipientKeyRegistry {
    active: BTreeMap<(String, RecipientKeyPurpose), VerifiedRecipientKey>,
    highest_epoch: BTreeMap<(String, RecipientKeyPurpose), u64>,
    latest_issued_unix: BTreeMap<(String, RecipientKeyPurpose), u64>,
    seen_kids: BTreeMap<String, BTreeSet<String>>,
    seen_pubkeys: Vec<[u8; 32]>,
    revocations: VerifiedRevocationState,
}

impl RecipientKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enroll(
        &mut self,
        bytes: &[u8],
        signers: &SeatSignerDirectory,
        now_unix: u64,
    ) -> Result<VerifiedRecipientKey, RecipientKeyError> {
        let verified = verify_signed_recipient_key(bytes, signers, &self.revocations, now_unix)?;
        let slot = (verified.seat().to_owned(), verified.purpose());
        let prev_epoch = self.highest_epoch.get(&slot).copied().unwrap_or(0);
        let prev_issued = self.latest_issued_unix.get(&slot).copied().unwrap_or(0);
        if self.active.contains_key(&slot)
            || verified.epoch() <= prev_epoch
            || verified.issued_unix() < prev_issued
            || self.has_seen_kid_or_pubkey(&verified)
        {
            return Err(RecipientKeyError::Rejected);
        }
        self.record_seen(&verified);
        self.active.insert(slot, verified.clone());
        Ok(verified)
    }

    pub fn rotate(
        &mut self,
        bytes: &[u8],
        signers: &SeatSignerDirectory,
        now_unix: u64,
    ) -> Result<VerifiedRecipientKey, RecipientKeyError> {
        let verified = verify_signed_recipient_key(bytes, signers, &self.revocations, now_unix)?;
        let slot = (verified.seat().to_owned(), verified.purpose());
        let Some(prev) = self.active.get(&slot) else {
            return Err(RecipientKeyError::Rejected);
        };
        let prev_epoch = self
            .highest_epoch
            .get(&slot)
            .copied()
            .unwrap_or(prev.epoch());
        let prev_issued = self
            .latest_issued_unix
            .get(&slot)
            .copied()
            .unwrap_or(prev.issued_unix());
        if verified.epoch() <= prev_epoch
            || verified.issued_unix() < prev_issued
            || verified.kid() == prev.kid()
            || verified.public_key() == prev.public_key()
            || self.has_seen_kid_or_pubkey(&verified)
        {
            return Err(RecipientKeyError::Rejected);
        }
        let superseded_kid = prev.kid().to_owned();
        self.revocations.record_superseded_key(
            verified.seat(),
            verified.purpose(),
            &superseded_kid,
            verified.epoch(),
        );
        self.record_seen(&verified);
        self.active.insert(slot, verified.clone());
        Ok(verified)
    }

    pub fn ingest_signed_revocation(
        &mut self,
        bytes: &[u8],
        signers: &SeatSignerDirectory,
    ) -> Result<(), RecipientKeyError> {
        self.revocations.ingest_signed_revocation(bytes, signers)?;
        let evicted: Vec<(String, RecipientKeyPurpose, String, u64)> = self
            .active
            .values()
            .filter(|key| {
                self.revocations.is_revoked_for_purpose(
                    key.seat(),
                    key.purpose(),
                    key.kid(),
                    key.epoch(),
                )
            })
            .map(|key| {
                (
                    key.seat().to_owned(),
                    key.purpose(),
                    key.kid().to_owned(),
                    key.epoch(),
                )
            })
            .collect();
        for (seat, purpose, kid, epoch) in evicted {
            self.revocations
                .record_superseded_key(&seat, purpose, &kid, epoch.saturating_add(1));
            self.active.remove(&(seat, purpose));
        }
        Ok(())
    }

    pub fn active_key(
        &self,
        seat: &str,
        purpose: RecipientKeyPurpose,
    ) -> Option<&VerifiedRecipientKey> {
        self.active.get(&(seat.to_owned(), purpose)).filter(|key| {
            !self.revocations.is_revoked_for_purpose(
                key.seat(),
                key.purpose(),
                key.kid(),
                key.epoch(),
            )
        })
    }

    pub fn revocation_state(&self) -> &VerifiedRevocationState {
        &self.revocations
    }

    fn has_seen_kid_or_pubkey(&self, candidate: &VerifiedRecipientKey) -> bool {
        let kid_seen = self
            .seen_kids
            .get(candidate.seat())
            .is_some_and(|s| s.contains(candidate.kid()));
        let digest = candidate.public_key_sha256();
        let pk_seen = self
            .seen_pubkeys
            .iter()
            .any(|existing| bool::from(existing[..].ct_eq(&digest[..])));
        kid_seen || pk_seen
    }

    fn record_seen(&mut self, verified: &VerifiedRecipientKey) {
        let slot = (verified.seat().to_owned(), verified.purpose());
        self.highest_epoch
            .entry(slot.clone())
            .and_modify(|e| *e = (*e).max(verified.epoch()))
            .or_insert(verified.epoch());
        self.latest_issued_unix
            .entry(slot)
            .and_modify(|t| *t = (*t).max(verified.issued_unix()))
            .or_insert(verified.issued_unix());
        self.seen_kids
            .entry(verified.seat().to_owned())
            .or_default()
            .insert(verified.kid().to_owned());
        self.seen_pubkeys.push(verified.public_key_sha256());
    }
}

/// Opaque recipient `X25519-MLKEM768` (`0x647a`) decapsulation key.
/// Implements zeroize-on-drop via `x_wing::DecapsulationKey` (`ZeroizeOnDrop`),
/// and deliberately omits `Debug`, `Clone`, `Serialize`, and raw secret export.
pub struct RecipientDecryptionKey {
    secret: Box<HybridPrivateKey>,
    public: KemPublicKey,
    seat: String,
    kid: String,
    epoch: u64,
    purpose: RecipientKeyPurpose,
}

impl RecipientDecryptionKey {
    pub fn generate(
        seat: &str,
        kid: &str,
        epoch: u64,
        purpose: RecipientKeyPurpose,
    ) -> Result<Self, RecipientKeyError> {
        if !valid_seat(seat) || !valid_kid(kid) || epoch == 0 {
            return Err(RecipientKeyError::Rejected);
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut seed[..]).map_err(|_| RecipientKeyError::Entropy)?;
        if bool::from(seed[..].ct_eq(&[0_u8; 32])) {
            return Err(RecipientKeyError::Entropy);
        }
        Self::from_seed_internal(&seed, seat, kid, epoch, purpose)
    }

    fn from_seed_internal(
        seed: &[u8; 32],
        seat: &str,
        kid: &str,
        epoch: u64,
        purpose: RecipientKeyPurpose,
    ) -> Result<Self, RecipientKeyError> {
        let (secret, pk) = XWing::derive_keypair(&seed[..]);
        let public = KemPublicKey::from_x25519_mlkem768_bytes(&pk.to_bytes())
            .map_err(|_| RecipientKeyError::Rejected)?;
        Ok(Self {
            secret: Box::new(secret),
            public,
            seat: seat.to_owned(),
            kid: kid.to_owned(),
            epoch,
            purpose,
        })
    }

    pub fn public_key(&self) -> &KemPublicKey {
        &self.public
    }

    pub fn seat(&self) -> &str {
        &self.seat
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn purpose(&self) -> RecipientKeyPurpose {
        self.purpose
    }

    pub fn sign_enrollment(
        &self,
        signer: &SigningKey,
        issued_unix: u64,
        expires_unix: u64,
    ) -> Result<Vec<u8>, RecipientKeyError> {
        sign_public_key_enrollment(
            &self.seat,
            &self.kid,
            self.epoch,
            self.purpose,
            &self.public,
            issued_unix,
            expires_unix,
            signer,
        )
    }

    pub fn open_cwcard(
        &self,
        cwcard: &AuthenticatedCwcard,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        open_cwcard_with_xwing_secret(
            &self.secret,
            &self.public,
            &self.seat,
            &self.kid,
            self.epoch,
            self.purpose,
            cwcard,
        )
    }
}

fn validate_lifetime_bounds(issued_unix: u64, expires_unix: u64) -> Result<(), RecipientKeyError> {
    if issued_unix == 0
        || expires_unix <= issued_unix
        || expires_unix - issued_unix > MAX_RECIPIENT_KEY_LIFETIME_SECONDS
    {
        return Err(RecipientKeyError::Lifetime);
    }
    Ok(())
}

pub(crate) fn valid_seat(seat: &str) -> bool {
    !seat.is_empty()
        && seat.len() <= 64
        && !seat.starts_with('-')
        && !seat.ends_with('-')
        && !seat.starts_with('_')
        && !seat.ends_with('_')
        && seat
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 128
        && !kid.starts_with('.')
        && !kid.ends_with('.')
        && kid.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_uppercase()
                || b.is_ascii_digit()
                || matches!(b, b'-' | b'_' | b'.' | b':')
        })
}

fn parse_canonical<T: Serialize + for<'de> Deserialize<'de>>(
    bytes: &[u8],
    max_len: usize,
) -> Result<T, RecipientKeyError> {
    if bytes.is_empty() || bytes.len() > max_len {
        return Err(RecipientKeyError::Rejected);
    }
    let parsed: T = serde_json::from_slice(bytes).map_err(|_| RecipientKeyError::Rejected)?;
    let reencoded = serde_json::to_vec(&parsed).map_err(|_| RecipientKeyError::Rejected)?;
    if reencoded != bytes {
        return Err(RecipientKeyError::Rejected);
    }
    Ok(parsed)
}

fn decode_lower_hex_exact(hex_str: &str, byte_len: usize) -> Result<Vec<u8>, RecipientKeyError> {
    if hex_str.len() != byte_len * 2
        || !hex_str
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(RecipientKeyError::Rejected);
    }
    hex::decode(hex_str).map_err(|_| RecipientKeyError::Rejected)
}

fn verify_ed25519(
    signer_pubkey: &[u8; 32],
    message: &[u8],
    signature_hex: &str,
) -> Result<(), RecipientKeyError> {
    let sig_bytes = decode_lower_hex_exact(signature_hex, 64)?;
    let vk = VerifyingKey::from_bytes(signer_pubkey).map_err(|_| RecipientKeyError::Rejected)?;
    if vk.is_weak() {
        return Err(RecipientKeyError::Rejected);
    }
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| RecipientKeyError::Rejected)?;
    vk.verify_strict(message, &sig)
        .map_err(|_| RecipientKeyError::Rejected)
}

fn framed_domain(domain_prefix: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(domain_prefix.len() + fields.iter().map(|f| 8 + f.len()).sum::<usize>());
    out.extend_from_slice(domain_prefix);
    for field in fields {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_allowed_signers_parses_with_strict_seat_pubkey_bijection() {
        let content = include_str!("../../../.chinwag/allowed_signers");
        let directory = SeatSignerDirectory::from_allowed_signers(content).unwrap();
        for seat in [
            "ALISTAIR",
            "ARCHITECT",
            "FLINT",
            "GEMINI-PM",
            "QA",
            "RUST",
            "WORKHORSE",
        ] {
            assert!(
                directory.pubkey_for_seat(seat).is_some(),
                "expected canonical seat {seat} in .chinwag/allowed_signers"
            );
        }
    }
}
