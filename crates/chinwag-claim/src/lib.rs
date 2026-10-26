//! Signed task-claim request and coordinator receipt.
//!
//! Signatures cover these canonical byte strings, not the JSON encoding.
//! This module does not enforce lease exclusivity. A future atomic store must:
//! grant only when no active row exists and `expected_revision` is 0; renew only
//! by compare-and-swap when the stored revision equals `expected_revision` and
//! the actor, session, claim id, PR, and exact files are unchanged; assign receipt
//! revision `expected_revision + 1`; return the original receipt bytes for the
//! same nonce and identical canonical signed body; reject that nonce with any
//! other body; keep an unexpired row when a socket closes or the actor session
//! is replaced; reject a renewal whose session is not current without deleting
//! that row; reject an overlapping active path even if policy lists it under
//! two PRs; and persist a max-observed timestamp, failing closed on rollback
//! instead of purging reservations.

#![forbid(unsafe_code)]

pub mod reply;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const ROOM_GENESIS: &str = "genesis";

pub const REQUEST_DOMAIN: &str = "chinwag-task-claim/v1";
pub const RECEIPT_DOMAIN: &str = "chinwag-claim-stored/v1";
pub const MAX_JSON_BYTES: usize = 4096;
pub const MAX_FILES: usize = 32;
pub const MAX_PATH_BYTES: usize = 160;
pub const MAX_TTL_SECONDS: u64 = 120;
pub const MAX_SAFE_UNIX: u64 = 9_007_199_254_740_991;

const PROTECTED: [&str; 4] = [".git", ".chinwag", ".grok", ".codex"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    InputTooLarge,
    Malformed,
    Noncanonical,
    PathRejected,
    PolicyDenied,
    Ttl,
    Overflow,
    Revision,
    Signature,
    Pin,
    Identity,
    Mismatch,
    ClockRollback,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ClaimError::InputTooLarge => "claim input exceeds its size limit",
            ClaimError::Malformed => "malformed claim json",
            ClaimError::Noncanonical => "noncanonical claim field",
            ClaimError::PathRejected => "claim path rejected",
            ClaimError::PolicyDenied => "claim path is outside the pr allowlist",
            ClaimError::Ttl => "claim lifetime is outside the 120 second bound",
            ClaimError::Overflow => "claim integer overflow",
            ClaimError::Revision => "claim revision does not match",
            ClaimError::Signature => "claim signature rejected",
            ClaimError::Pin => "coordinator pin rejected",
            ClaimError::Identity => "actor key rejected",
            ClaimError::Mismatch => "claim receipt does not match the request",
            ClaimError::ClockRollback => "coordinator clock rollback",
        })
    }
}

impl std::error::Error for ClaimError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pr {
    #[serde(rename = "PR-01")]
    Pr01,
    #[serde(rename = "PR-02")]
    Pr02,
    #[serde(rename = "PR-03")]
    Pr03,
    #[serde(rename = "PR-04")]
    Pr04,
}

impl Pr {
    fn index(self) -> usize {
        match self {
            Pr::Pr01 => 0,
            Pr::Pr02 => 1,
            Pr::Pr03 => 2,
            Pr::Pr04 => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Pr::Pr01 => "PR-01",
            Pr::Pr02 => "PR-02",
            Pr::Pr03 => "PR-03",
            Pr::Pr04 => "PR-04",
        }
    }
}

/// Immutable after the caller finishes `allow`. An empty policy denies every path.
/// The same exact path may be allowed for more than one PR. That is not a lease.
#[derive(Clone, Debug, Default)]
pub struct ClaimPolicy {
    allowed: [BTreeSet<String>; 4],
}

impl ClaimPolicy {
    pub fn allow(&mut self, pr: Pr, path: &str) -> Result<(), ClaimError> {
        validate_one_path(path)?;
        let fold = ascii_lower(path);
        for set in &self.allowed {
            for existing in set {
                if existing != path && ascii_lower(existing) == fold {
                    return Err(ClaimError::PathRejected);
                }
            }
        }
        self.allowed[pr.index()].insert(path.to_string());
        Ok(())
    }

    pub fn authorize(&self, pr: Pr, files: &[String]) -> Result<(), ClaimError> {
        validate_files(files)?;
        for file in files {
            if !self.allowed[pr.index()].contains(file) {
                return Err(ClaimError::PolicyDenied);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRequestUnsigned {
    pub claim_id: String,
    pub actor: String,
    pub session: String,
    pub nonce: String,
    pub pr: Pr,
    pub files: Vec<String>,
    pub expected_revision: u64,
    pub issued: u64,
    pub expiry: u64,
}

impl ClaimRequestUnsigned {
    pub fn validate(&self) -> Result<(), ClaimError> {
        decode_hex_exact::<32>(&self.claim_id)?;
        decode_hex_exact::<32>(&self.actor)?;
        decode_hex_exact::<32>(&self.session)?;
        decode_hex_exact::<32>(&self.nonce)?;
        if self.expected_revision > MAX_SAFE_UNIX {
            return Err(ClaimError::Overflow);
        }
        validate_lifetime(self.issued, self.expiry)?;
        validate_files(&self.files)
    }

    /// Bytes covered by the actor signature.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ClaimError> {
        self.validate()?;
        let mut out = Vec::new();
        line(&mut out, REQUEST_DOMAIN);
        field(&mut out, "room", ROOM_GENESIS);
        field(&mut out, "claim_id", &self.claim_id);
        field(&mut out, "actor", &self.actor);
        field(&mut out, "session", &self.session);
        field(&mut out, "nonce", &self.nonce);
        field(&mut out, "pr", self.pr.label());
        field(&mut out, "files", &self.files.len().to_string());
        for file in &self.files {
            line(&mut out, file);
        }
        field(
            &mut out,
            "expected_revision",
            &self.expected_revision.to_string(),
        );
        field(&mut out, "issued", &self.issued.to_string());
        field(&mut out, "expiry", &self.expiry.to_string());
        Ok(out)
    }

    pub fn sign(self, actor_key: &SigningKey) -> Result<SignedClaimRequest, ClaimError> {
        self.validate()?;
        require_key(
            &self.actor,
            &actor_key.verifying_key(),
            ClaimError::Identity,
        )?;
        let preimage = self.canonical_bytes()?;
        let signature = actor_key.sign(&preimage);
        Ok(SignedClaimRequest {
            request: self,
            signature: encode_hex(&signature.to_bytes()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedClaimRequest {
    pub request: ClaimRequestUnsigned,
    pub signature: String,
}

impl SignedClaimRequest {
    /// Canonical signed body. The receipt hashes these bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ClaimError> {
        let mut out = self.request.canonical_bytes()?;
        validate_signature_hex(&self.signature)?;
        field(&mut out, "signature", &self.signature);
        Ok(out)
    }

    pub fn request_sha256(&self) -> Result<[u8; 32], ClaimError> {
        Ok(sha256(&self.canonical_bytes()?))
    }

    pub fn request_sha256_hex(&self) -> Result<String, ClaimError> {
        Ok(encode_hex(&self.request_sha256()?))
    }

    /// Storage compares this for nonce replay. Renewal is a different body.
    pub fn same_canonical_body(&self, other: &Self) -> Result<bool, ClaimError> {
        Ok(self.canonical_bytes()? == other.canonical_bytes()?)
    }

    pub fn verify_actor(&self, actor: &VerifyingKey) -> Result<(), ClaimError> {
        self.request.validate()?;
        validate_signature_hex(&self.signature)?;
        require_key(&self.request.actor, actor, ClaimError::Identity)?;
        verify_strict(actor, &self.request.canonical_bytes()?, &self.signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReceiptUnsigned {
    pub claim_id: String,
    pub actor: String,
    pub session: String,
    pub pr: Pr,
    pub files: Vec<String>,
    pub revision: u64,
    pub issued: u64,
    pub expiry: u64,
    pub request_sha256: String,
    pub coordinator: String,
}

impl ClaimReceiptUnsigned {
    pub fn validate(&self) -> Result<(), ClaimError> {
        decode_hex_exact::<32>(&self.claim_id)?;
        decode_hex_exact::<32>(&self.actor)?;
        decode_hex_exact::<32>(&self.session)?;
        decode_hex_exact::<32>(&self.request_sha256)?;
        decode_hex_exact::<32>(&self.coordinator)?;
        if self.revision == 0 {
            return Err(ClaimError::Revision);
        }
        if self.revision > MAX_SAFE_UNIX {
            return Err(ClaimError::Overflow);
        }
        validate_lifetime(self.issued, self.expiry)?;
        validate_files(&self.files)
    }

    /// Bytes covered by the coordinator signature.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ClaimError> {
        self.validate()?;
        let mut out = Vec::new();
        line(&mut out, RECEIPT_DOMAIN);
        field(&mut out, "room", ROOM_GENESIS);
        field(&mut out, "claim_id", &self.claim_id);
        field(&mut out, "actor", &self.actor);
        field(&mut out, "session", &self.session);
        field(&mut out, "pr", self.pr.label());
        field(&mut out, "files", &self.files.len().to_string());
        for file in &self.files {
            line(&mut out, file);
        }
        field(&mut out, "revision", &self.revision.to_string());
        field(&mut out, "issued", &self.issued.to_string());
        field(&mut out, "expiry", &self.expiry.to_string());
        field(&mut out, "request_sha256", &self.request_sha256);
        field(&mut out, "coordinator", &self.coordinator);
        Ok(out)
    }

    pub fn sign(self, coordinator: &SigningKey) -> Result<SignedClaimReceipt, ClaimError> {
        self.validate()?;
        require_key(
            &self.coordinator,
            &coordinator.verifying_key(),
            ClaimError::Pin,
        )?;
        let preimage = self.canonical_bytes()?;
        let signature = coordinator.sign(&preimage);
        Ok(SignedClaimReceipt {
            receipt: self,
            signature: encode_hex(&signature.to_bytes()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedClaimReceipt {
    pub receipt: ClaimReceiptUnsigned,
    pub signature: String,
}

impl SignedClaimReceipt {
    /// Byte-identical body a future store must return for an idempotent replay.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ClaimError> {
        let mut out = self.receipt.canonical_bytes()?;
        validate_signature_hex(&self.signature)?;
        field(&mut out, "signature", &self.signature);
        Ok(out)
    }

    pub fn verify_coordinator(&self, coordinator: &VerifyingKey) -> Result<(), ClaimError> {
        self.receipt.validate()?;
        validate_signature_hex(&self.signature)?;
        require_key(&self.receipt.coordinator, coordinator, ClaimError::Pin)?;
        verify_strict(
            coordinator,
            &self.receipt.canonical_bytes()?,
            &self.signature,
        )
    }

    /// Checks signatures and exact request binding, independently of current
    /// policy, session or time. Historical resolution is not an active lease or
    /// write authority. Fresh operations enforce those gates separately.
    pub fn verify_binding(
        &self,
        request: &SignedClaimRequest,
        actor: &VerifyingKey,
        coordinator: &VerifyingKey,
    ) -> Result<(), ClaimError> {
        request.verify_actor(actor)?;
        self.verify_coordinator(coordinator)?;
        let req = &request.request;
        let got = &self.receipt;
        if req.claim_id != got.claim_id
            || req.actor != got.actor
            || req.session != got.session
            || req.pr != got.pr
            || req.files != got.files
            || req.issued != got.issued
            || req.expiry != got.expiry
        {
            return Err(ClaimError::Mismatch);
        }
        let digest = decode_hex_exact::<32>(&got.request_sha256)?;
        if request.request_sha256()? != digest {
            return Err(ClaimError::Mismatch);
        }
        revisions_match(req.expected_revision, got.revision)
    }
}

/// New grant: expected revision 0 assigns receipt revision 1.
/// Renewal: expected revision N > 0 assigns receipt revision N + 1.
/// Storage must compare-and-swap this against the stored revision.
pub fn receipt_revision_for(expected_revision: u64) -> Result<u64, ClaimError> {
    if expected_revision > MAX_SAFE_UNIX {
        return Err(ClaimError::Overflow);
    }
    let revision = expected_revision
        .checked_add(1)
        .ok_or(ClaimError::Overflow)?;
    if revision == 0 || revision > MAX_SAFE_UNIX {
        return Err(ClaimError::Overflow);
    }
    Ok(revision)
}

pub fn revisions_match(expected_revision: u64, receipt_revision: u64) -> Result<(), ClaimError> {
    let required = receipt_revision_for(expected_revision)?;
    if receipt_revision != required {
        return Err(ClaimError::Revision);
    }
    Ok(())
}

pub fn validate_lifetime(issued: u64, expiry: u64) -> Result<(), ClaimError> {
    if issued > MAX_SAFE_UNIX || expiry > MAX_SAFE_UNIX {
        return Err(ClaimError::Overflow);
    }
    if expiry <= issued {
        return Err(ClaimError::Ttl);
    }
    let ttl = expiry.checked_sub(issued).ok_or(ClaimError::Overflow)?;
    if ttl == 0 || ttl > MAX_TTL_SECONDS {
        return Err(ClaimError::Ttl);
    }
    Ok(())
}

/// Scope check only. A different session does not release the prior reservation.
/// The caller must still reject a session that is not current, without deleting the row.
pub struct RenewalGate<'a> {
    pub prior: &'a ClaimReceiptUnsigned,
    pub next: &'a ClaimRequestUnsigned,
}

impl<'a> RenewalGate<'a> {
    pub fn scope_matches(&self) -> Result<(), ClaimError> {
        self.prior.validate()?;
        self.next.validate()?;
        if self.next.expected_revision != self.prior.revision {
            return Err(ClaimError::Revision);
        }
        if self.next.claim_id != self.prior.claim_id
            || self.next.actor != self.prior.actor
            || self.next.session != self.prior.session
            || self.next.pr != self.prior.pr
            || self.next.files != self.prior.files
        {
            return Err(ClaimError::Mismatch);
        }
        Ok(())
    }
}

/// Future storage watermark. `observe` never lowers it and never clears leases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedTime {
    max_observed_unix: u64,
}

impl ObservedTime {
    pub fn at(now_unix: u64) -> Result<Self, ClaimError> {
        if now_unix > MAX_SAFE_UNIX {
            return Err(ClaimError::Overflow);
        }
        Ok(Self {
            max_observed_unix: now_unix,
        })
    }

    pub fn max_observed(self) -> u64 {
        self.max_observed_unix
    }

    pub fn observe(self, now_unix: u64) -> Result<Self, ClaimError> {
        if now_unix > MAX_SAFE_UNIX {
            return Err(ClaimError::Overflow);
        }
        if now_unix < self.max_observed_unix {
            return Err(ClaimError::ClockRollback);
        }
        Ok(Self {
            max_observed_unix: now_unix,
        })
    }
}

pub fn parse_signed_request(bytes: &[u8]) -> Result<SignedClaimRequest, ClaimError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(ClaimError::InputTooLarge);
    }
    let parsed: SignedClaimRequest =
        serde_json::from_slice(bytes).map_err(|_| ClaimError::Malformed)?;
    parsed.request.validate()?;
    validate_signature_hex(&parsed.signature)?;
    Ok(parsed)
}

pub fn parse_signed_receipt(bytes: &[u8]) -> Result<SignedClaimReceipt, ClaimError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(ClaimError::InputTooLarge);
    }
    let parsed: SignedClaimReceipt =
        serde_json::from_slice(bytes).map_err(|_| ClaimError::Malformed)?;
    parsed.receipt.validate()?;
    validate_signature_hex(&parsed.signature)?;
    Ok(parsed)
}

fn line(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
    out.push(b'\n');
}

fn field(out: &mut Vec<u8>, name: &str, value: &str) {
    line(out, &format!("{name}={value}"));
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_nibble(byte: u8) -> Result<u8, ClaimError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ClaimError::Noncanonical),
    }
}

pub fn decode_hex_exact<const N: usize>(text: &str) -> Result<[u8; N], ClaimError> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return Err(ClaimError::Noncanonical);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[index * 2])?;
        let lo = hex_nibble(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn validate_signature_hex(text: &str) -> Result<(), ClaimError> {
    decode_hex_exact::<64>(text).map(|_| ())
}

fn require_key(hex_id: &str, key: &VerifyingKey, mismatch: ClaimError) -> Result<(), ClaimError> {
    let raw = decode_hex_exact::<32>(hex_id)?;
    if raw.as_slice() != key.as_bytes().as_slice() {
        return Err(mismatch);
    }
    Ok(())
}

fn verify_strict(
    key: &VerifyingKey,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), ClaimError> {
    let bytes = decode_hex_exact::<64>(signature_hex)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| ClaimError::Signature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| ClaimError::Signature)
}

fn ascii_lower(path: &str) -> String {
    path.chars().map(|ch| ch.to_ascii_lowercase()).collect()
}

fn validate_one_path(path: &str) -> Result<(), ClaimError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || !path.is_ascii() {
        return Err(ClaimError::PathRejected);
    }
    let bytes = path.as_bytes();
    if bytes[0] == b'/'
        || bytes
            .iter()
            .any(|byte| *byte <= 0x20 || *byte == 0x7f || *byte == b'\\' || *byte == b':')
    {
        return Err(ClaimError::PathRejected);
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ClaimError::PathRejected);
        }
        if PROTECTED
            .iter()
            .any(|name| component.eq_ignore_ascii_case(name))
        {
            return Err(ClaimError::PathRejected);
        }
    }
    Ok(())
}

fn validate_files(files: &[String]) -> Result<(), ClaimError> {
    if files.is_empty() || files.len() > MAX_FILES {
        return Err(ClaimError::PathRejected);
    }
    let mut previous: Option<&str> = None;
    let mut folds = Vec::with_capacity(files.len());
    for file in files {
        validate_one_path(file)?;
        if previous.is_some_and(|prior| file.as_str() <= prior) {
            return Err(ClaimError::PathRejected);
        }
        let fold = ascii_lower(file);
        if folds.iter().any(|existing| existing == &fold) {
            return Err(ClaimError::PathRejected);
        }
        folds.push(fold);
        previous = Some(file);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "crates/chinwag-claim/src/lib.rs";

    fn actor_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn coord_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn sample_request(actor: &SigningKey) -> ClaimRequestUnsigned {
        ClaimRequestUnsigned {
            claim_id: encode_hex(&[0x11; 32]),
            actor: encode_hex(actor.verifying_key().as_bytes()),
            session: encode_hex(&[0x22; 32]),
            nonce: encode_hex(&[0x33; 32]),
            pr: Pr::Pr01,
            files: vec![SAMPLE.to_string()],
            expected_revision: 0,
            issued: 1_700_000_000,
            expiry: 1_700_000_120,
        }
    }

    fn policy_for(path: &str) -> ClaimPolicy {
        let mut policy = ClaimPolicy::default();
        policy.allow(Pr::Pr01, path).unwrap();
        policy
    }

    fn issue(request: &SignedClaimRequest, coordinator: &SigningKey) -> SignedClaimReceipt {
        ClaimReceiptUnsigned {
            claim_id: request.request.claim_id.clone(),
            actor: request.request.actor.clone(),
            session: request.request.session.clone(),
            pr: request.request.pr,
            files: request.request.files.clone(),
            revision: receipt_revision_for(request.request.expected_revision).unwrap(),
            issued: request.request.issued,
            expiry: request.request.expiry,
            request_sha256: request.request_sha256_hex().unwrap(),
            coordinator: encode_hex(coordinator.verifying_key().as_bytes()),
        }
        .sign(coordinator)
        .unwrap()
    }

    fn flip_last(text: &str) -> String {
        let mut owned = text.to_string();
        let last = owned.pop().unwrap();
        owned.push(if last == 'a' { 'b' } else { 'a' });
        owned
    }

    #[test]
    fn real_signatures_round_trip() {
        let actor = actor_key();
        let coordinator = coord_key();
        let signed = sample_request(&actor).sign(&actor).unwrap();
        let receipt = issue(&signed, &coordinator);
        let actor_vk = actor.verifying_key();
        let coord_vk = coordinator.verifying_key();
        receipt
            .verify_binding(&signed, &actor_vk, &coord_vk)
            .unwrap();
        assert_eq!(
            ClaimPolicy::default().authorize(signed.request.pr, &signed.request.files),
            Err(ClaimError::PolicyDenied)
        );
        policy_for(SAMPLE)
            .authorize(signed.request.pr, &signed.request.files)
            .unwrap();
        let parsed = parse_signed_request(&serde_json::to_vec(&signed).unwrap()).unwrap();
        assert_eq!(
            parsed.canonical_bytes().unwrap(),
            signed.canonical_bytes().unwrap()
        );
        let mut broken = signed.clone();
        broken.signature = flip_last(&broken.signature);
        assert_ne!(
            signed.request_sha256().unwrap(),
            broken.request_sha256().unwrap()
        );
        assert_eq!(broken.verify_actor(&actor_vk), Err(ClaimError::Signature));
    }

    #[test]
    fn mutation_after_signature_rejected() {
        let actor = actor_key();
        let signed = sample_request(&actor).sign(&actor).unwrap();
        let actor_vk = actor.verifying_key();
        signed.verify_actor(&actor_vk).unwrap();

        let mut files = signed.clone();
        files.request.files = vec!["crates/chinwag-seed/src/lib.rs".to_string()];
        assert_eq!(files.verify_actor(&actor_vk), Err(ClaimError::Signature));

        let mut pr = signed.clone();
        pr.request.pr = Pr::Pr02;
        assert_eq!(pr.verify_actor(&actor_vk), Err(ClaimError::Signature));

        let mut session = signed.clone();
        session.request.session = flip_last(&session.request.session);
        assert_eq!(session.verify_actor(&actor_vk), Err(ClaimError::Signature));
    }

    #[test]
    fn wrong_coordinator_pin_rejected() {
        let actor = actor_key();
        let coordinator = coord_key();
        let signed = sample_request(&actor).sign(&actor).unwrap();
        let receipt = issue(&signed, &coordinator);
        let err = receipt.verify_binding(
            &signed,
            &actor.verifying_key(),
            &other_key().verifying_key(),
        );
        assert_eq!(err, Err(ClaimError::Pin));

        let mut broken = receipt.clone();
        broken.signature = flip_last(&broken.signature);
        assert_eq!(
            broken.verify_coordinator(&coordinator.verifying_key()),
            Err(ClaimError::Signature)
        );
    }

    #[test]
    fn receipt_request_mismatch_rejected() {
        let actor = actor_key();
        let coordinator = coord_key();
        let signed = sample_request(&actor).sign(&actor).unwrap();
        let mut unsigned = issue(&signed, &coordinator).receipt;
        unsigned.files = vec!["other.rs".to_string()];
        let resigned = unsigned.sign(&coordinator).unwrap();
        assert_eq!(
            resigned.verify_binding(
                &signed,
                &actor.verifying_key(),
                &coordinator.verifying_key(),
            ),
            Err(ClaimError::Mismatch)
        );
    }

    #[test]
    fn unknown_fields_and_oversize_rejected() {
        let actor = actor_key();
        let signed = sample_request(&actor).sign(&actor).unwrap();
        let mut value = serde_json::to_value(&signed).unwrap();
        value["extra"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(parse_signed_request(&bytes), Err(ClaimError::Malformed));
        value = serde_json::to_value(&signed).unwrap();
        value["request"]["extra"] = serde_json::json!(1);
        assert_eq!(
            parse_signed_request(&serde_json::to_vec(&value).unwrap()),
            Err(ClaimError::Malformed)
        );
        let mut pr = serde_json::to_value(&signed).unwrap();
        pr["request"]["pr"] = serde_json::json!("PR-05");
        assert_eq!(
            parse_signed_request(&serde_json::to_vec(&pr).unwrap()),
            Err(ClaimError::Malformed)
        );
        assert_eq!(
            parse_signed_request(&[b' '; 4096]),
            Err(ClaimError::Malformed)
        );
        assert_eq!(
            parse_signed_request(&[b' '; 4097]),
            Err(ClaimError::InputTooLarge)
        );
        assert_eq!(
            parse_signed_receipt(&[b' '; 4097]),
            Err(ClaimError::InputTooLarge)
        );
    }

    #[test]
    fn sorted_unique_exact_policy() {
        let mut policy = ClaimPolicy::default();
        policy.allow(Pr::Pr01, "src/shared.rs").unwrap();
        policy.allow(Pr::Pr02, "src/shared.rs").unwrap();
        assert_eq!(
            policy.allow(Pr::Pr02, "src/Shared.rs"),
            Err(ClaimError::PathRejected)
        );
        policy
            .authorize(Pr::Pr01, &["src/shared.rs".to_string()])
            .unwrap();
        assert_eq!(
            policy.authorize(Pr::Pr01, &["src/other.rs".to_string()]),
            Err(ClaimError::PolicyDenied)
        );
        assert_eq!(
            policy.authorize(Pr::Pr01, &["src/Shared.rs".to_string()]),
            Err(ClaimError::PolicyDenied)
        );

        let actor = actor_key();
        let mut request = sample_request(&actor);
        for path in [
            "../secret",
            "foo/../../x",
            ".git/config",
            "src/.Git/config",
            "src/.chinwag/x",
            "src/.grok/x",
            "src/.codex/x",
            "a\\b",
            "/abs.rs",
            "foo//bar",
            "foo/./bar",
            "foo/../bar",
            "",
        ] {
            request.files = vec![path.to_string()];
            assert_eq!(request.validate(), Err(ClaimError::PathRejected), "{path}");
        }
        request.files = vec!["b.rs".to_string(), "a.rs".to_string()];
        assert_eq!(request.validate(), Err(ClaimError::PathRejected));
        request.files = vec!["a.rs".to_string(), "a.rs".to_string()];
        assert_eq!(request.validate(), Err(ClaimError::PathRejected));
        request.files = vec!["A.rs".to_string(), "a.rs".to_string()];
        assert_eq!(request.validate(), Err(ClaimError::PathRejected));
        request.files = (0..33).map(|index| format!("f{index:02}.rs")).collect();
        assert_eq!(request.validate(), Err(ClaimError::PathRejected));
        request.files = vec!["a".repeat(161)];
        assert_eq!(request.validate(), Err(ClaimError::PathRejected));
        request.claim_id = "A".repeat(64);
        request.files = vec![SAMPLE.to_string()];
        assert_eq!(request.validate(), Err(ClaimError::Noncanonical));
    }

    #[test]
    fn ttl_overflow_and_revision() {
        assert_eq!(validate_lifetime(10, 10), Err(ClaimError::Ttl));
        assert_eq!(validate_lifetime(10, 131), Err(ClaimError::Ttl));
        validate_lifetime(10, 130).unwrap();
        assert_eq!(
            validate_lifetime(MAX_SAFE_UNIX, MAX_SAFE_UNIX),
            Err(ClaimError::Ttl)
        );
        assert_eq!(
            validate_lifetime(MAX_SAFE_UNIX, MAX_SAFE_UNIX + 1),
            Err(ClaimError::Overflow)
        );
        assert_eq!(receipt_revision_for(0).unwrap(), 1);
        assert_eq!(receipt_revision_for(4).unwrap(), 5);
        revisions_match(0, 1).unwrap();
        assert_eq!(revisions_match(0, 2), Err(ClaimError::Revision));
        assert_eq!(revisions_match(0, 0), Err(ClaimError::Revision));
        assert_eq!(revisions_match(1, 1), Err(ClaimError::Revision));
        revisions_match(1, 2).unwrap();
        assert_eq!(receipt_revision_for(u64::MAX), Err(ClaimError::Overflow));
        assert_eq!(
            receipt_revision_for(MAX_SAFE_UNIX),
            Err(ClaimError::Overflow)
        );

        let actor = actor_key();
        let mut request = sample_request(&actor);
        request.issued = MAX_SAFE_UNIX + 1;
        request.expiry = MAX_SAFE_UNIX + 2;
        assert_eq!(request.validate(), Err(ClaimError::Overflow));
        request.expected_revision = u64::MAX;
        request.issued = 10;
        request.expiry = 20;
        assert_eq!(request.validate(), Err(ClaimError::Overflow));
    }

    #[test]
    fn watermark_refuses_rollback_without_lowering_the_floor() {
        let floor = ObservedTime::at(1_700_000_050).unwrap();
        assert_eq!(floor.observe(1_700_000_049), Err(ClaimError::ClockRollback));
        assert_eq!(floor.max_observed(), 1_700_000_050);
        assert_eq!(
            floor.observe(1_700_000_050).unwrap().max_observed(),
            1_700_000_050
        );
        assert_eq!(
            floor.observe(1_700_000_051).unwrap().max_observed(),
            1_700_000_051
        );
    }

    #[test]
    fn renewal_cas_is_not_a_replay() {
        let actor = actor_key();
        let coordinator = coord_key();
        let first = sample_request(&actor).sign(&actor).unwrap();
        let first_receipt = issue(&first, &coordinator);
        assert_eq!(first_receipt.receipt.revision, 1);

        let mut next = first.request.clone();
        next.expected_revision = 1;
        next.nonce = encode_hex(&[0x44; 32]);
        next.issued += 10;
        next.expiry += 10;
        let second = next.sign(&actor).unwrap();
        assert!(!first.same_canonical_body(&second).unwrap());
        RenewalGate {
            prior: &first_receipt.receipt,
            next: &second.request,
        }
        .scope_matches()
        .unwrap();
        assert_eq!(
            revisions_match(
                second.request.expected_revision,
                first_receipt.receipt.revision
            ),
            Err(ClaimError::Revision)
        );

        let second_receipt = issue(&second, &coordinator);
        assert_eq!(second_receipt.receipt.revision, 2);
        second_receipt
            .verify_binding(
                &second,
                &actor.verifying_key(),
                &coordinator.verifying_key(),
            )
            .unwrap();
        assert_eq!(
            first_receipt.verify_binding(
                &second,
                &actor.verifying_key(),
                &coordinator.verifying_key(),
            ),
            Err(ClaimError::Mismatch)
        );

        let mut other_actor = second.request.clone();
        other_actor.actor = encode_hex(other_key().verifying_key().as_bytes());
        assert_eq!(
            RenewalGate {
                prior: &first_receipt.receipt,
                next: &other_actor,
            }
            .scope_matches(),
            Err(ClaimError::Mismatch)
        );
    }

    #[test]
    fn root_duplicate_json_fields_are_rejected() {
        let actor = actor_key();
        let signed = sample_request(&actor).sign(&actor).unwrap();
        let original = serde_json::to_string(&signed).unwrap();
        let duplicate_outer = format!(
            "{{\"signature\":\"{}\",{}",
            signed.signature,
            &original[1..]
        );
        assert_eq!(
            parse_signed_request(duplicate_outer.as_bytes()),
            Err(ClaimError::Malformed)
        );
        let duplicate_inner =
            original.replacen("\"issued\":", "\"issued\":1700000000,\"issued\":", 1);
        assert_eq!(
            parse_signed_request(duplicate_inner.as_bytes()),
            Err(ClaimError::Malformed)
        );
    }

    #[test]
    fn root_renewal_cannot_change_the_session() {
        let actor = actor_key();
        let coordinator = coord_key();
        let first = sample_request(&actor).sign(&actor).unwrap();
        let receipt = issue(&first, &coordinator);
        let mut next = first.request.clone();
        next.expected_revision = receipt.receipt.revision;
        next.session = encode_hex(&[0x55; 32]);
        assert_eq!(
            RenewalGate {
                prior: &receipt.receipt,
                next: &next
            }
            .scope_matches(),
            Err(ClaimError::Mismatch)
        );
    }

    #[test]
    fn canonical_request_is_fixed_to_the_genesis_room() {
        let actor = actor_key();
        let req = sample_request(&actor);
        let expected = format!(
            "chinwag-task-claim/v1\nroom=genesis\nclaim_id={}\nactor={}\nsession={}\nnonce={}\npr=PR-01\nfiles=1\n{}\nexpected_revision=0\nissued=1700000000\nexpiry=1700000120\n",
            req.claim_id, req.actor, req.session, req.nonce, SAMPLE
        );
        assert_eq!(req.canonical_bytes().unwrap(), expected.as_bytes());
        let signed = req.sign(&actor).unwrap();
        let receipt = issue(&signed, &coord_key());
        assert!(
            receipt
                .receipt
                .canonical_bytes()
                .unwrap()
                .starts_with(b"chinwag-claim-stored/v1\nroom=genesis\n")
        );
    }
}
