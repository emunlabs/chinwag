// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Hybrid post-quantum HPKE (`X25519-MLKEM768` / `MLKEM768-X25519`, IANA/IETF
//! `draft-ietf-hpke-pq-03` & `draft-irtf-cfrg-concrete-hybrid-kems-02` KEM ID
//! `0x647a`, `HKDF-SHA256` `0x0001`, `ChaCha20Poly1305` `0x0003`) for both:
//! 1. Enterprise 2-of-3 `ACU AND (Recipient OR Archive)` envelopes (`CHWGCE01`,
//!    one payload ciphertext and three mode-separated key wraps, with explicit
//!    backward-compatible classical `X25519` `[0x0020, 1, 3]` parsing for legacy
//!    stored vectors), and
//! 2. Direct offline-capable Base-mode `.cwcard` (`CWCARD01`) sealing to an
//!    owner/seat Ed25519-authenticated `X25519-MLKEM768` recipient encryption
//!    key with mandatory runner Ed25519 origin authentication before decap.
//!
//! This cryptographic layer supplies no admission, current policy, replay
//! consumption, durable storage, qualified processing or repair authority.

use crate::recipient_key::{RecipientKeyPurpose, VerifiedRecipientKey};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use core::convert::Infallible;
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable,
    aead::ChaCha20Poly1305 as WrapAead,
    kdf::HkdfSha256,
    kem::{X25519HkdfSha256, XWing},
    rand_core::{TryCryptoRng, TryRng},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

pub const KEM_ID_X25519_MLKEM768: u16 = 0x647a;
pub const KEM_ID_X25519_LEGACY: u16 = 0x0020;
pub const KDF_ID_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_ID_CHACHA20_POLY1305: u16 = 0x0003;

pub const SUITE_X25519_MLKEM768: [u16; 3] = [
    KEM_ID_X25519_MLKEM768,
    KDF_ID_HKDF_SHA256,
    AEAD_ID_CHACHA20_POLY1305,
];
pub const SUITE_X25519_LEGACY: [u16; 3] = [
    KEM_ID_X25519_LEGACY,
    KDF_ID_HKDF_SHA256,
    AEAD_ID_CHACHA20_POLY1305,
];

pub const CIPHERSUITE_X25519_MLKEM768: &str = "X25519-MLKEM768-HKDF-SHA256-ChaCha20Poly1305";
pub const XWING_PUBLIC_KEY_BYTES: usize = 1216;
pub const XWING_MLKEM768_PK_BYTES: usize = 1184;
pub const XWING_ENCAPPED_KEY_BYTES: usize = 1120;
pub const XWING_MLKEM768_CT_BYTES: usize = 1088;
pub const X25519_KEY_BYTES: usize = 32;

pub const MAX_PLAINTEXT_BYTES: usize = 24 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_HPKE_INFO_BYTES: usize = 32 * 1024;

type HybridPrivate = <XWing as KemTrait>::PrivateKey;
type HybridPublic = <XWing as KemTrait>::PublicKey;
type HybridEncapped = <XWing as KemTrait>::EncappedKey;
type LegacyPrivate = <X25519HkdfSha256 as KemTrait>::PrivateKey;
type LegacyPublic = <X25519HkdfSha256 as KemTrait>::PublicKey;
type LegacyEncapped = <X25519HkdfSha256 as KemTrait>::EncappedKey;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("CI envelope validation or authentication failed")]
    Rejected,
    #[error("CI envelope entropy is unavailable")]
    Entropy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KemSuite {
    /// First-class hybrid post-quantum KEM `MLKEM768-X25519` (`0x647a`).
    X25519MlKem768,
    /// Legacy classical `DHKEM(X25519, HKDF-SHA256)` (`0x0020`) retained only
    /// for backward-compatible parsing of historical stored profiles/envelopes.
    X25519Legacy,
}

impl KemSuite {
    pub const fn suite_ids(self) -> [u16; 3] {
        match self {
            Self::X25519MlKem768 => SUITE_X25519_MLKEM768,
            Self::X25519Legacy => SUITE_X25519_LEGACY,
        }
    }

    pub const fn from_suite_ids(ids: [u16; 3]) -> Result<Self, EnvelopeError> {
        match ids {
            SUITE_X25519_MLKEM768 => Ok(Self::X25519MlKem768),
            SUITE_X25519_LEGACY => Ok(Self::X25519Legacy),
            _ => Err(EnvelopeError::Rejected),
        }
    }
}

/// Pre-sampled single-use OS CSPRNG buffer so `hpke::setup_sender_with_rng`
/// never panics on OS RNG failure and zeroizes ephemeral randomness on drop.
struct PreSampledEntropy<const N: usize>(Option<Zeroizing<[u8; N]>>);

impl<const N: usize> PreSampledEntropy<N> {
    fn sample() -> Result<Self, EnvelopeError> {
        let mut buf = Zeroizing::new([0_u8; N]);
        getrandom::fill(&mut buf[..]).map_err(|_| EnvelopeError::Entropy)?;
        if bool::from(buf[..].ct_eq(&[0_u8; N])) {
            return Err(EnvelopeError::Entropy);
        }
        Ok(Self(Some(buf)))
    }
}

impl<const N: usize> TryRng for PreSampledEntropy<N> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut out = [0_u8; 4];
        self.try_fill_bytes(&mut out)?;
        Ok(u32::from_le_bytes(out))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut out = [0_u8; 8];
        self.try_fill_bytes(&mut out)?;
        Ok(u64::from_le_bytes(out))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let buf = self
            .0
            .take()
            .expect("single-use pre-sampled HPKE entropy buffer");
        assert_eq!(dst.len(), N);
        dst.copy_from_slice(&buf[..]);
        Ok(())
    }
}

impl<const N: usize> TryCryptoRng for PreSampledEntropy<N> {}

#[derive(Clone)]
enum KemPublicInner {
    X25519MlKem768(Box<[u8; XWING_PUBLIC_KEY_BYTES]>),
    X25519Legacy([u8; X25519_KEY_BYTES]),
}

/// Suite-tagged HPKE encapsulation public key (`1216`-byte `X25519-MLKEM768`
/// canonical lowercase hex on wire, or legacy `32`-byte `X25519` byte array).
#[derive(Clone)]
pub struct KemPublicKey(KemPublicInner);

impl ConstantTimeEq for KemPublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        match (&self.0, &other.0) {
            (KemPublicInner::X25519MlKem768(a), KemPublicInner::X25519MlKem768(b)) => {
                a[..].ct_eq(&b[..])
            }
            (KemPublicInner::X25519Legacy(a), KemPublicInner::X25519Legacy(b)) => {
                a[..].ct_eq(&b[..])
            }
            _ => Choice::from(0),
        }
    }
}

impl PartialEq for KemPublicKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for KemPublicKey {}

impl KemPublicKey {
    pub fn from_x25519_mlkem768_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let arr: &[u8; XWING_PUBLIC_KEY_BYTES] =
            bytes.try_into().map_err(|_| EnvelopeError::Rejected)?;
        let _ = checked_xwing_public(arr)?;
        Ok(Self(KemPublicInner::X25519MlKem768(Box::new(*arr))))
    }

    pub fn from_x25519_legacy_bytes(bytes: &[u8; X25519_KEY_BYTES]) -> Result<Self, EnvelopeError> {
        let _ = checked_x25519_public(bytes)?;
        Ok(Self(KemPublicInner::X25519Legacy(*bytes)))
    }

    pub const fn suite(&self) -> KemSuite {
        match &self.0 {
            KemPublicInner::X25519MlKem768(_) => KemSuite::X25519MlKem768,
            KemPublicInner::X25519Legacy(_) => KemSuite::X25519Legacy,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            KemPublicInner::X25519MlKem768(bytes) => &bytes[..],
            KemPublicInner::X25519Legacy(bytes) => &bytes[..],
        }
    }

    pub fn sha256(&self) -> [u8; 32] {
        hash(self.as_bytes())
    }

    pub(crate) fn x25519_component(&self) -> &[u8; 32] {
        match &self.0 {
            KemPublicInner::X25519MlKem768(bytes) => bytes[XWING_MLKEM768_PK_BYTES..]
                .try_into()
                .expect("1216 - 1184 == 32"),
            KemPublicInner::X25519Legacy(bytes) => bytes,
        }
    }

    #[cfg(test)]
    pub(crate) fn as_mut_bytes_for_test(&mut self) -> &mut [u8] {
        match &mut self.0 {
            KemPublicInner::X25519MlKem768(bytes) => &mut bytes[..],
            KemPublicInner::X25519Legacy(bytes) => &mut bytes[..],
        }
    }
}

impl Serialize for KemPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            KemPublicInner::X25519MlKem768(bytes) => {
                serializer.serialize_str(&hex::encode(&bytes[..]))
            }
            KemPublicInner::X25519Legacy(bytes) => bytes.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for KemPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KemPkVisitor;
        impl<'de> de::Visitor<'de> for KemPkVisitor {
            type Value = KemPublicKey;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("canonical 2432-hex X25519-MLKEM768 public key or legacy 32-byte array")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let raw = decode_canonical_lower_hex::<XWING_PUBLIC_KEY_BYTES>(value)
                    .map_err(|_| E::custom("invalid X25519-MLKEM768 public key hex"))?;
                Ok(KemPublicKey(KemPublicInner::X25519MlKem768(raw)))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut arr = [0_u8; X25519_KEY_BYTES];
                for slot in &mut arr {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &"32 bytes"))?;
                }
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("trailing bytes in legacy X25519 key"));
                }
                Ok(KemPublicKey(KemPublicInner::X25519Legacy(arr)))
            }
        }
        deserializer.deserialize_any(KemPkVisitor)
    }
}

#[derive(Clone)]
enum EncappedInner {
    X25519MlKem768(Box<[u8; XWING_ENCAPPED_KEY_BYTES]>),
    X25519Legacy([u8; X25519_KEY_BYTES]),
}

/// Suite-tagged HPKE `enc` bytes (`1120`-byte `X25519-MLKEM768` canonical
/// lowercase hex on wire, or legacy `32`-byte `X25519` byte array).
#[derive(Clone)]
pub struct EncappedBytes(EncappedInner);

impl ConstantTimeEq for EncappedBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        match (&self.0, &other.0) {
            (EncappedInner::X25519MlKem768(a), EncappedInner::X25519MlKem768(b)) => {
                a[..].ct_eq(&b[..])
            }
            (EncappedInner::X25519Legacy(a), EncappedInner::X25519Legacy(b)) => a[..].ct_eq(&b[..]),
            _ => Choice::from(0),
        }
    }
}

impl PartialEq for EncappedBytes {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for EncappedBytes {}

impl EncappedBytes {
    pub const fn suite(&self) -> KemSuite {
        match &self.0 {
            EncappedInner::X25519MlKem768(_) => KemSuite::X25519MlKem768,
            EncappedInner::X25519Legacy(_) => KemSuite::X25519Legacy,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            EncappedInner::X25519MlKem768(bytes) => &bytes[..],
            EncappedInner::X25519Legacy(bytes) => &bytes[..],
        }
    }
}

impl Serialize for EncappedBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            EncappedInner::X25519MlKem768(bytes) => {
                serializer.serialize_str(&hex::encode(&bytes[..]))
            }
            EncappedInner::X25519Legacy(bytes) => bytes.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for EncappedBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EncVisitor;
        impl<'de> de::Visitor<'de> for EncVisitor {
            type Value = EncappedBytes;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("canonical 2240-hex X25519-MLKEM768 enc or legacy 32-byte array")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let raw = decode_canonical_lower_hex::<XWING_ENCAPPED_KEY_BYTES>(value)
                    .map_err(|_| E::custom("invalid X25519-MLKEM768 enc hex"))?;
                Ok(EncappedBytes(EncappedInner::X25519MlKem768(raw)))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut arr = [0_u8; X25519_KEY_BYTES];
                for slot in &mut arr {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &"32 bytes"))?;
                }
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("trailing bytes in legacy X25519 enc"));
                }
                Ok(EncappedBytes(EncappedInner::X25519Legacy(arr)))
            }
        }
        deserializer.deserialize_any(EncVisitor)
    }
}

fn decode_canonical_lower_hex<const N: usize>(value: &str) -> Result<Box<[u8; N]>, EnvelopeError> {
    if value.len() != 2 * N
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EnvelopeError::Rejected);
    }
    let decoded = hex::decode(value).map_err(|_| EnvelopeError::Rejected)?;
    let arr: [u8; N] = decoded.try_into().map_err(|_| EnvelopeError::Rejected)?;
    Ok(Box::new(arr))
}

/// These are claimed provenance until compared with independently verified
/// admission, dispatch and immutable command/delivery profile resolutions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedProvenance {
    pub admission_sha256: [u8; 32],
    pub repository: String,
    pub repository_id: u64,
    pub source_commit: [u8; 20],
    pub workflow_ref: String,
    pub workflow_commit: [u8; 20],
    pub run_id: u64,
    pub run_attempt: u32,
    pub initiating_instance: String,
    pub intent_digest: [u8; 32],
    pub command_profile_sha256: [u8; 32],
    pub delivery_profile_sha256: [u8; 32],
    pub policy_sha256: [u8; 32],
    pub policy_epoch: u64,
}

/// All five KEM identities are distinct; each key has exactly one mode/purpose.
/// The separately authenticated delivery profile commits these exact bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPins {
    pub acu_gate_base: KemPublicKey,
    pub recipient_psk: KemPublicKey,
    pub archive_psk: KemPublicKey,
    pub recipient_response_base: KemPublicKey,
    pub archive_response_base: KemPublicKey,
    pub acu_signer: [u8; 32],
    pub recipient_receipt_signer: [u8; 32],
    pub archive_receipt_signer: [u8; 32],
}

impl KeyPins {
    pub fn suite(&self) -> Result<KemSuite, EnvelopeError> {
        let suite = self.acu_gate_base.suite();
        for key in [
            &self.recipient_psk,
            &self.archive_psk,
            &self.recipient_response_base,
            &self.archive_response_base,
        ] {
            if key.suite() != suite {
                return Err(EnvelopeError::Rejected);
            }
        }
        Ok(suite)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destination {
    #[serde(rename = "recipient:initiating-agent")]
    Recipient,
    #[serde(rename = "archive:vault")]
    Archive,
}

impl Destination {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Recipient => b"recipient:initiating-agent",
            Self::Archive => b"archive:vault",
        }
    }

    fn psk_pin(self, pins: &KeyPins) -> &KemPublicKey {
        match self {
            Self::Recipient => &pins.recipient_psk,
            Self::Archive => &pins.archive_psk,
        }
    }

    fn response_pin(self, pins: &KeyPins) -> &KemPublicKey {
        match self {
            Self::Recipient => &pins.recipient_response_base,
            Self::Archive => &pins.archive_response_base,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreHeader {
    version: u16,
    suite: [u16; 3],
    policy: String,
    claims: ClaimedProvenance,
    keys: KeyPins,
    runner_signer: [u8; 32],
    nonce: [u8; 12],
    plaintext_bytes: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedSecret {
    enc: EncappedBytes,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    pre: PreHeader,
    acu_gate_base: WrappedSecret,
    recipient_psk: WrappedSecret,
    archive_psk: WrappedSecret,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    header: Header,
    ciphertext_sha256: [u8; 32],
    ciphertext_bytes: u64,
    signature_hex: String,
}

pub struct SealedEnvelope {
    pub manifest: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Original immutable metadata/ciphertext authenticated against trusted expected
/// pins/claims, not a coordinator admission or current ACU authorization token.
pub struct AuthenticatedEnvelope {
    manifest: Manifest,
    ciphertext: Vec<u8>,
    digest: [u8; 32],
}

impl AuthenticatedEnvelope {
    pub(crate) fn key_pins(&self) -> &KeyPins {
        &self.manifest.header.pre.keys
    }

    pub fn suite(&self) -> Result<KemSuite, EnvelopeError> {
        KemSuite::from_suite_ids(self.manifest.header.pre.suite)
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn claims(&self) -> &ClaimedProvenance {
        &self.manifest.header.pre.claims
    }

    pub fn original_manifest(&self) -> Result<Vec<u8>, EnvelopeError> {
        canonical(&self.manifest)
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn receipt_signing_pin(&self, role: Destination) -> &[u8; 32] {
        match role {
            Destination::Recipient => &self.manifest.header.pre.keys.recipient_receipt_signer,
            Destination::Archive => &self.manifest.header.pre.keys.archive_receipt_signer,
        }
    }

    pub fn complete_storage_blob(&self) -> Result<Vec<u8>, EnvelopeError> {
        let manifest = self.original_manifest()?;
        let mut bytes = b"CHWGCE01".to_vec();
        bytes.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.ciphertext.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&manifest);
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }
}

/// Parse only, never authenticate. Length bounds precede copying; metadata,
/// wraps and signature share the same durable object commit as the ciphertext.
pub fn parse_storage_blob(bytes: &[u8]) -> Result<SealedEnvelope, EnvelopeError> {
    let (manifest, ciphertext) = parse_framed_blob(bytes, b"CHWGCE01")?;
    Ok(SealedEnvelope {
        manifest,
        ciphertext,
    })
}

fn parse_framed_blob(
    bytes: &[u8],
    expected_magic: &[u8; 8],
) -> Result<(Vec<u8>, Vec<u8>), EnvelopeError> {
    if bytes.len() < 20 || &bytes[..8] != expected_magic {
        return Err(EnvelopeError::Rejected);
    }
    let manifest = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| EnvelopeError::Rejected)?,
    ) as usize;
    let ciphertext = u64::from_be_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| EnvelopeError::Rejected)?,
    );
    if manifest == 0
        || manifest > MAX_MANIFEST_BYTES
        || ciphertext < 17
        || ciphertext > (MAX_PLAINTEXT_BYTES + 16) as u64
    {
        return Err(EnvelopeError::Rejected);
    }
    let end = 20_usize
        .checked_add(manifest)
        .and_then(|v| v.checked_add(ciphertext as usize))
        .ok_or(EnvelopeError::Rejected)?;
    if bytes.len() != end {
        return Err(EnvelopeError::Rejected);
    }
    Ok((
        bytes[20..20 + manifest].to_vec(),
        bytes[20 + manifest..].to_vec(),
    ))
}

pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, EnvelopeError> {
    serde_json::to_vec(value).map_err(|_| EnvelopeError::Rejected)
}

pub(crate) fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

pub(crate) fn domain(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

fn nonzero_secret(secret: &[u8]) -> bool {
    secret.len() == 32 && !bool::from(secret.ct_eq(&[0; 32]))
}

pub(crate) fn secret() -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(&mut key[..]).map_err(|_| EnvelopeError::Entropy)?;
    if !nonzero_secret(&key[..]) {
        return Err(EnvelopeError::Entropy);
    }
    Ok(key)
}

pub(crate) fn checked_x25519_public(bytes: &[u8; 32]) -> Result<LegacyPublic, EnvelopeError> {
    // Protocol encoding rule: one canonical little-endian field element < 2^255 - 19.
    // RFC 7748 permits masking/reduction; this profile rejects aliases so byte
    // commitments and role separation cannot encode one key two ways.
    if bool::from(bytes[..].ct_eq(&[0; 32])) {
        return Err(EnvelopeError::Rejected);
    }
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if bytes.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
        return Err(EnvelopeError::Rejected);
    }
    let public = LegacyPublic::from_bytes(bytes).map_err(|_| EnvelopeError::Rejected)?;
    // DHKEM encapsulation rejects non-contributory / low-order Curve25519 points.
    let mut entropy = PreSampledEntropy::<32>::sample()?;
    let _ = <X25519HkdfSha256 as KemTrait>::encap_with_rng(&public, None, &mut entropy)
        .map_err(|_| EnvelopeError::Rejected)?;
    Ok(public)
}

pub(crate) fn checked_xwing_public(
    bytes: &[u8; XWING_PUBLIC_KEY_BYTES],
) -> Result<HybridPublic, EnvelopeError> {
    if bool::from(bytes[..].ct_eq(&[0; XWING_PUBLIC_KEY_BYTES])) {
        return Err(EnvelopeError::Rejected);
    }
    // `HybridPublic::from_bytes` runs `MlKem768EncapsulationKey::new` on `[0..1184]`
    // (FIPS 203 §7.2 modulus check rejecting any 12-bit coefficient >= 3329).
    let public = HybridPublic::from_bytes(&bytes[..]).map_err(|_| EnvelopeError::Rejected)?;
    // Strictly validate the trailing 32-byte X25519 public share `[1184..1216]`
    // for canonical `< 2^255 - 19` encoding and contributory group membership.
    let pk_x: &[u8; 32] = bytes[XWING_MLKEM768_PK_BYTES..]
        .try_into()
        .map_err(|_| EnvelopeError::Rejected)?;
    let _ = checked_x25519_public(pk_x)?;
    Ok(public)
}

pub(crate) fn checked_xwing_encapped(
    bytes: &[u8; XWING_ENCAPPED_KEY_BYTES],
) -> Result<HybridEncapped, EnvelopeError> {
    // Reject non-canonical or non-contributory X25519 ephemeral shares `ct_X`
    // (`bytes[1088..1120]`) before decapsulation.
    let ct_x: &[u8; 32] = bytes[XWING_MLKEM768_CT_BYTES..]
        .try_into()
        .map_err(|_| EnvelopeError::Rejected)?;
    let _ = checked_x25519_public(ct_x)?;
    HybridEncapped::from_bytes(&bytes[..]).map_err(|_| EnvelopeError::Rejected)
}

fn checked_kem_public(key: &KemPublicKey) -> Result<(), EnvelopeError> {
    match &key.0 {
        KemPublicInner::X25519MlKem768(bytes) => {
            let _ = checked_xwing_public(bytes)?;
            Ok(())
        }
        KemPublicInner::X25519Legacy(bytes) => {
            let _ = checked_x25519_public(bytes)?;
            Ok(())
        }
    }
}

fn checked_encapped(enc: &EncappedBytes) -> Result<(), EnvelopeError> {
    match &enc.0 {
        EncappedInner::X25519MlKem768(bytes) => {
            let _ = checked_xwing_encapped(bytes)?;
            Ok(())
        }
        EncappedInner::X25519Legacy(bytes) => {
            let _ = checked_x25519_public(bytes)?;
            Ok(())
        }
    }
}

pub(crate) fn validate_claims(
    c: &ClaimedProvenance,
    plaintext_bytes: u64,
) -> Result<(), EnvelopeError> {
    if plaintext_bytes == 0
        || plaintext_bytes > MAX_PLAINTEXT_BYTES as u64
        || c.repository.is_empty()
        || c.repository.len() > 201
        || c.repository_id == 0
        || c.workflow_ref.is_empty()
        || c.workflow_ref.len() > 1024
        || c.initiating_instance.is_empty()
        || c.initiating_instance.len() > 193
        || c.run_id == 0
        || c.run_attempt == 0
        || c.policy_epoch == 0
    {
        return Err(EnvelopeError::Rejected);
    }
    for digest in [
        c.admission_sha256,
        c.intent_digest,
        c.command_profile_sha256,
        c.delivery_profile_sha256,
        c.policy_sha256,
    ] {
        if bool::from(digest[..].ct_eq(&[0; 32])) {
            return Err(EnvelopeError::Rejected);
        }
    }
    Ok(())
}

fn validate_pre(pre: &PreHeader) -> Result<(), EnvelopeError> {
    let suite = KemSuite::from_suite_ids(pre.suite)?;
    if pre.version != 1
        || pre.policy != "ACU AND (Recipient OR Archive)"
        || pre.keys.suite()? != suite
    {
        return Err(EnvelopeError::Rejected);
    }
    validate_claims(&pre.claims, pre.plaintext_bytes)?;
    validate_key_pins(&pre.keys, &[pre.runner_signer])
}

pub(crate) fn validate_key_pins(
    k: &KeyPins,
    additional_signers: &[[u8; 32]],
) -> Result<(), EnvelopeError> {
    let _ = k.suite()?;
    let kem = [
        &k.acu_gate_base,
        &k.recipient_psk,
        &k.archive_psk,
        &k.recipient_response_base,
        &k.archive_response_base,
    ];
    let mut ed = vec![
        k.acu_signer,
        k.recipient_receipt_signer,
        k.archive_receipt_signer,
    ];
    ed.extend_from_slice(additional_signers);
    for (i, key) in kem.iter().enumerate() {
        if kem[..i].contains(key)
            || ed
                .iter()
                .any(|s| bool::from(s[..].ct_eq(&key.x25519_component()[..])))
        {
            return Err(EnvelopeError::Rejected);
        }
        checked_kem_public(key)?;
    }
    for (i, key) in ed.iter().enumerate() {
        if ed[..i]
            .iter()
            .any(|prev| bool::from(prev[..].ct_eq(&key[..])))
            || VerifyingKey::from_bytes(key)
                .map_err(|_| EnvelopeError::Rejected)?
                .is_weak()
        {
            return Err(EnvelopeError::Rejected);
        }
    }
    Ok(())
}

enum WrapMode<'a> {
    Base,
    Psk { gate: &'a [u8], id: &'a [u8] },
}

fn psk<'a>(gate: &'a [u8], id: &'a [u8]) -> Result<PskBundle<'a>, EnvelopeError> {
    // Do not allow the library's both-empty case to bypass the ACU gate.
    if !nonzero_secret(gate) || id.len() != 32 {
        return Err(EnvelopeError::Rejected);
    }
    PskBundle::new(gate, id).map_err(|_| EnvelopeError::Rejected)
}

fn wrap(
    mode: WrapMode<'_>,
    pk: &KemPublicKey,
    context: &[u8],
    value: &[u8],
) -> Result<WrappedSecret, EnvelopeError> {
    if context.len() > MAX_HPKE_INFO_BYTES {
        return Err(EnvelopeError::Rejected);
    }
    match &pk.0 {
        KemPublicInner::X25519MlKem768(raw_pk) => {
            let pk = checked_xwing_public(raw_pk)?;
            let op_mode = match mode {
                WrapMode::Base => OpModeS::Base,
                WrapMode::Psk { gate, id } => OpModeS::Psk(psk(gate, id)?),
            };
            let mut entropy = PreSampledEntropy::<64>::sample()?;
            let (enc, mut sender) = hpke::setup_sender_with_rng::<WrapAead, HkdfSha256, XWing>(
                &op_mode,
                &pk,
                context,
                &mut entropy,
            )
            .map_err(|_| EnvelopeError::Rejected)?;
            let ciphertext = sender
                .seal(value, context)
                .map_err(|_| EnvelopeError::Rejected)?;
            if ciphertext.len() != 48 {
                return Err(EnvelopeError::Rejected);
            }
            let mut enc_arr = Box::new([0_u8; XWING_ENCAPPED_KEY_BYTES]);
            enc_arr.copy_from_slice(&enc.to_bytes());
            Ok(WrappedSecret {
                enc: EncappedBytes(EncappedInner::X25519MlKem768(enc_arr)),
                ciphertext,
            })
        }
        KemPublicInner::X25519Legacy(raw_pk) => {
            let pk = checked_x25519_public(raw_pk)?;
            let op_mode = match mode {
                WrapMode::Base => OpModeS::Base,
                WrapMode::Psk { gate, id } => OpModeS::Psk(psk(gate, id)?),
            };
            let mut entropy = PreSampledEntropy::<32>::sample()?;
            let (enc, mut sender) = hpke::setup_sender_with_rng::<
                WrapAead,
                HkdfSha256,
                X25519HkdfSha256,
            >(&op_mode, &pk, context, &mut entropy)
            .map_err(|_| EnvelopeError::Rejected)?;
            let ciphertext = sender
                .seal(value, context)
                .map_err(|_| EnvelopeError::Rejected)?;
            if ciphertext.len() != 48 {
                return Err(EnvelopeError::Rejected);
            }
            Ok(WrappedSecret {
                enc: EncappedBytes(EncappedInner::X25519Legacy(enc.to_bytes().into())),
                ciphertext,
            })
        }
    }
}

enum KemPrivate {
    X25519MlKem768(Box<HybridPrivate>),
    X25519Legacy(LegacyPrivate),
}

fn generate_xwing_kem() -> Result<(KemPrivate, KemPublicKey), EnvelopeError> {
    let seed = secret()?;
    let (sk, pk) = derive_xwing_from_seed(&seed);
    checked_kem_public(&pk)?;
    Ok((sk, pk))
}

fn derive_xwing_from_seed(seed: &[u8; 32]) -> (KemPrivate, KemPublicKey) {
    let (sk, pk) = XWing::derive_keypair(&seed[..]);
    let mut raw = Box::new([0_u8; XWING_PUBLIC_KEY_BYTES]);
    raw.copy_from_slice(&pk.to_bytes());
    (
        KemPrivate::X25519MlKem768(Box::new(sk)),
        KemPublicKey(KemPublicInner::X25519MlKem768(raw)),
    )
}

fn generate_legacy_x25519_kem() -> Result<(KemPrivate, KemPublicKey), EnvelopeError> {
    let seed = secret()?;
    let (sk, pk) = X25519HkdfSha256::derive_keypair(&seed[..]);
    Ok((
        KemPrivate::X25519Legacy(sk),
        KemPublicKey(KemPublicInner::X25519Legacy(pk.to_bytes().into())),
    ))
}

fn unwrap(
    mode: WrapMode<'_>,
    sk: &KemPrivate,
    wrapped: &WrappedSecret,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if wrapped.ciphertext.len() != 48 || context.len() > MAX_HPKE_INFO_BYTES {
        return Err(EnvelopeError::Rejected);
    }
    match (sk, &wrapped.enc.0) {
        (KemPrivate::X25519MlKem768(sk), EncappedInner::X25519MlKem768(raw_enc)) => {
            let enc = checked_xwing_encapped(raw_enc)?;
            let op_mode = match mode {
                WrapMode::Base => OpModeR::Base,
                WrapMode::Psk { gate, id } => OpModeR::Psk(psk(gate, id)?),
            };
            let mut receiver =
                hpke::setup_receiver::<WrapAead, HkdfSha256, XWing>(&op_mode, sk, &enc, context)
                    .map_err(|_| EnvelopeError::Rejected)?;
            let value = Zeroizing::new(
                receiver
                    .open(&wrapped.ciphertext, context)
                    .map_err(|_| EnvelopeError::Rejected)?,
            );
            if !nonzero_secret(&value) {
                return Err(EnvelopeError::Rejected);
            }
            Ok(value)
        }
        (KemPrivate::X25519Legacy(sk), EncappedInner::X25519Legacy(raw_enc)) => {
            let _ = checked_x25519_public(raw_enc)?;
            let enc =
                LegacyEncapped::from_bytes(&raw_enc[..]).map_err(|_| EnvelopeError::Rejected)?;
            let op_mode = match mode {
                WrapMode::Base => OpModeR::Base,
                WrapMode::Psk { gate, id } => OpModeR::Psk(psk(gate, id)?),
            };
            let mut receiver = hpke::setup_receiver::<WrapAead, HkdfSha256, X25519HkdfSha256>(
                &op_mode, sk, &enc, context,
            )
            .map_err(|_| EnvelopeError::Rejected)?;
            let value = Zeroizing::new(
                receiver
                    .open(&wrapped.ciphertext, context)
                    .map_err(|_| EnvelopeError::Rejected)?,
            );
            if !nonzero_secret(&value) {
                return Err(EnvelopeError::Rejected);
            }
            Ok(value)
        }
        _ => Err(EnvelopeError::Rejected),
    }
}

fn wrap_context(pre: &[u8], role: &[u8]) -> Vec<u8> {
    domain(b"chinwag-ci-hpke-wrap-v1\0", &[pre, role])
}

fn psk_id(pre: &[u8]) -> [u8; 32] {
    hash(&domain(b"chinwag-ci-gate-psk-id-v1\0", &[pre]))
}

fn statement(header: &Header, ct_hash: &[u8; 32], ct_len: u64) -> Result<Vec<u8>, EnvelopeError> {
    Ok(domain(
        b"chinwag-ci-envelope-signature-v1\0",
        &[&canonical(header)?, ct_hash, &ct_len.to_be_bytes()],
    ))
}

pub(crate) fn seal(
    signer: &iroh::SecretKey,
    claims: ClaimedProvenance,
    pins: KeyPins,
    plaintext: &[u8],
) -> Result<SealedEnvelope, EnvelopeError> {
    let suite = pins.suite()?;
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| EnvelopeError::Entropy)?;
    let pre = PreHeader {
        version: 1,
        suite: suite.suite_ids(),
        policy: "ACU AND (Recipient OR Archive)".into(),
        claims,
        keys: pins,
        runner_signer: *signer.public().as_bytes(),
        nonce,
        plaintext_bytes: plaintext.len() as u64,
    };
    validate_pre(&pre)?;
    let h0 = canonical(&pre)?;
    let key = secret()?;
    let gate = secret()?;
    if bool::from(key[..].ct_eq(&gate[..])) {
        return Err(EnvelopeError::Entropy);
    }
    let id = psk_id(&h0);
    let gate_wrap = wrap(
        WrapMode::Base,
        &pre.keys.acu_gate_base,
        &wrap_context(&h0, b"acu:gate-base"),
        &gate[..],
    )?;
    let recipient = wrap(
        WrapMode::Psk {
            gate: &gate[..],
            id: &id,
        },
        &pre.keys.recipient_psk,
        &wrap_context(&h0, Destination::Recipient.label()),
        &key[..],
    )?;
    let archive = wrap(
        WrapMode::Psk {
            gate: &gate[..],
            id: &id,
        },
        &pre.keys.archive_psk,
        &wrap_context(&h0, Destination::Archive.label()),
        &key[..],
    )?;
    let header = Header {
        pre,
        acu_gate_base: gate_wrap,
        recipient_psk: recipient,
        archive_psk: archive,
    };
    let aad = canonical(&header)?;
    let ciphertext = ChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| EnvelopeError::Rejected)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::Rejected)?;
    let ct_hash = hash(&ciphertext);
    let ct_len = ciphertext.len() as u64;
    let signature = signer
        .sign(&statement(&header, &ct_hash, ct_len)?)
        .to_bytes();
    let manifest = canonical(&Manifest {
        header,
        ciphertext_sha256: ct_hash,
        ciphertext_bytes: ct_len,
        signature_hex: hex::encode(signature),
    })?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(EnvelopeError::Rejected);
    }
    Ok(SealedEnvelope {
        manifest,
        ciphertext,
    })
}

pub fn authenticate(
    manifest: &[u8],
    ciphertext: &[u8],
    expected: &ClaimedProvenance,
    pins: &KeyPins,
    runner_signer: &[u8; 32],
) -> Result<AuthenticatedEnvelope, EnvelopeError> {
    if manifest.len() > MAX_MANIFEST_BYTES || ciphertext.len() > MAX_PLAINTEXT_BYTES + 16 {
        return Err(EnvelopeError::Rejected);
    }
    let parsed: Manifest = serde_json::from_slice(manifest).map_err(|_| EnvelopeError::Rejected)?;
    if canonical(&parsed)? != manifest {
        return Err(EnvelopeError::Rejected);
    }
    validate_pre(&parsed.header.pre)?;
    let suite = KemSuite::from_suite_ids(parsed.header.pre.suite)?;
    if &parsed.header.pre.claims != expected
        || &parsed.header.pre.keys != pins
        || !bool::from(parsed.header.pre.runner_signer[..].ct_eq(&runner_signer[..]))
        || parsed.ciphertext_bytes != ciphertext.len() as u64
        || parsed.ciphertext_bytes != parsed.header.pre.plaintext_bytes + 16
        || !bool::from(parsed.ciphertext_sha256[..].ct_eq(&hash(ciphertext)[..]))
        || parsed.signature_hex.len() != 128
    {
        return Err(EnvelopeError::Rejected);
    }
    for wrap_entry in [
        &parsed.header.acu_gate_base,
        &parsed.header.recipient_psk,
        &parsed.header.archive_psk,
    ] {
        if wrap_entry.ciphertext.len() != 48 || wrap_entry.enc.suite() != suite {
            return Err(EnvelopeError::Rejected);
        }
        checked_encapped(&wrap_entry.enc)?;
    }
    verify_runner_ed25519(
        runner_signer,
        &statement(
            &parsed.header,
            &parsed.ciphertext_sha256,
            parsed.ciphertext_bytes,
        )?,
        &parsed.signature_hex,
    )?;
    let digest = hash(&domain(b"chinwag-ci-complete-envelope-v1\0", &[manifest]));
    Ok(AuthenticatedEnvelope {
        manifest: parsed,
        ciphertext: ciphertext.to_vec(),
        digest,
    })
}

fn verify_runner_ed25519(
    runner_signer: &[u8; 32],
    signed_statement: &[u8],
    signature_hex: &str,
) -> Result<(), EnvelopeError> {
    if signature_hex.len() != 128
        || !signature_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EnvelopeError::Rejected);
    }
    let signature = hex::decode(signature_hex).map_err(|_| EnvelopeError::Rejected)?;
    let vk = VerifyingKey::from_bytes(runner_signer).map_err(|_| EnvelopeError::Rejected)?;
    if vk.is_weak() {
        return Err(EnvelopeError::Rejected);
    }
    vk.verify_strict(
        signed_statement,
        &Signature::from_slice(&signature).map_err(|_| EnvelopeError::Rejected)?,
    )
    .map_err(|_| EnvelopeError::Rejected)
}

// ============================================================================
// Direct Offline-Capable Base HPKE `.cwcard` Mode (`CWCARD01`, `0x647a` ONLY)
// ============================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CwcardPreHeader {
    schema: String,
    version: u16,
    mode: String,
    ciphersuite: String,
    suite: [u16; 3],
    recipient_seat: String,
    recipient_kid: String,
    recipient_key_epoch: u64,
    recipient_enc_pk_sha256: [u8; 32],
    claims: ClaimedProvenance,
    runner_signer: [u8; 32],
    sealed_unix: u64,
    plaintext_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CwcardHeader {
    pre: CwcardPreHeader,
    enc: EncappedBytes,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CwcardManifest {
    header: CwcardHeader,
    ciphertext_sha256: [u8; 32],
    ciphertext_bytes: u64,
    signature_hex: String,
}

/// Offline-sealed `.cwcard` envelope (`X25519-MLKEM768` HPKE Base mode + runner
/// Ed25519 signature). Decryptable locally by the recipient without an ACU
/// round-trip once authenticated against the verified recipient key and runner.
#[derive(Clone)]
pub struct SealedCwcard {
    pub manifest: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl SealedCwcard {
    pub fn to_cwcard_blob(&self) -> Result<Vec<u8>, EnvelopeError> {
        if self.manifest.is_empty()
            || self.manifest.len() > MAX_MANIFEST_BYTES
            || self.ciphertext.len() < 17
            || self.ciphertext.len() > MAX_PLAINTEXT_BYTES + 16
        {
            return Err(EnvelopeError::Rejected);
        }
        let mut bytes = b"CWCARD01".to_vec();
        bytes.extend_from_slice(&(self.manifest.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.ciphertext.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.manifest);
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }
}

pub fn parse_cwcard_blob(bytes: &[u8]) -> Result<SealedCwcard, EnvelopeError> {
    let (manifest, ciphertext) = parse_framed_blob(bytes, b"CWCARD01")?;
    Ok(SealedCwcard {
        manifest,
        ciphertext,
    })
}

/// Origin-authenticated offline `.cwcard`, ready for local `RecipientDecryptionKey::open_cwcard`.
pub struct AuthenticatedCwcard {
    manifest: CwcardManifest,
    ciphertext: Vec<u8>,
    digest: [u8; 32],
}

impl AuthenticatedCwcard {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn claims(&self) -> &ClaimedProvenance {
        &self.manifest.header.pre.claims
    }

    pub fn recipient_seat(&self) -> &str {
        &self.manifest.header.pre.recipient_seat
    }

    pub fn recipient_kid(&self) -> &str {
        &self.manifest.header.pre.recipient_kid
    }

    pub fn recipient_key_epoch(&self) -> u64 {
        self.manifest.header.pre.recipient_key_epoch
    }

    pub fn recipient_enc_pk_sha256(&self) -> &[u8; 32] {
        &self.manifest.header.pre.recipient_enc_pk_sha256
    }

    pub fn sealed_unix(&self) -> u64 {
        self.manifest.header.pre.sealed_unix
    }
}

fn cwcard_hpke_info(pre: &CwcardPreHeader) -> Result<[u8; 63], EnvelopeError> {
    let pre_digest = hash(&canonical(pre)?);
    let mut info = [0_u8; 63];
    let prefix = b"chinwag-ci-cwcard-hpke-info-v1\0";
    info[..31].copy_from_slice(prefix);
    info[31..].copy_from_slice(&pre_digest);
    Ok(info)
}

fn cwcard_signature_statement(
    header: &CwcardHeader,
    ct_hash: &[u8; 32],
    ct_len: u64,
) -> Result<Vec<u8>, EnvelopeError> {
    Ok(domain(
        b"chinwag-ci-cwcard-signature-v1\0",
        &[&canonical(header)?, ct_hash, &ct_len.to_be_bytes()],
    ))
}

fn validate_cwcard_pre(
    pre: &CwcardPreHeader,
    recipient_key: &VerifiedRecipientKey,
) -> Result<(), EnvelopeError> {
    if pre.schema != "chinwag.ci-cwcard.v1"
        || pre.version != 1
        || pre.mode != "HPKE_BASE_OFFLINE_V1"
        || pre.ciphersuite != CIPHERSUITE_X25519_MLKEM768
        || pre.suite != SUITE_X25519_MLKEM768
        || recipient_key.purpose() != RecipientKeyPurpose::CwcardOfflineBase
        || pre.recipient_seat != recipient_key.seat()
        || pre.recipient_kid != recipient_key.kid()
        || pre.recipient_key_epoch != recipient_key.epoch()
        || !bool::from(
            pre.recipient_enc_pk_sha256[..].ct_eq(&recipient_key.public_key_sha256()[..]),
        )
        || pre.sealed_unix < recipient_key.issued_unix()
        || pre.sealed_unix >= recipient_key.expires_unix()
        || bool::from(
            pre.runner_signer[..].ct_eq(&recipient_key.public_key().x25519_component()[..]),
        )
    {
        return Err(EnvelopeError::Rejected);
    }
    let vk = VerifyingKey::from_bytes(&pre.runner_signer).map_err(|_| EnvelopeError::Rejected)?;
    if vk.is_weak() {
        return Err(EnvelopeError::Rejected);
    }
    validate_claims(&pre.claims, pre.plaintext_bytes)
}

pub(crate) fn seal_cwcard_offline(
    signer: &iroh::SecretKey,
    claims: ClaimedProvenance,
    recipient_key: &VerifiedRecipientKey,
    sealed_unix: u64,
    plaintext: &[u8],
) -> Result<SealedCwcard, EnvelopeError> {
    let pre = CwcardPreHeader {
        schema: "chinwag.ci-cwcard.v1".into(),
        version: 1,
        mode: "HPKE_BASE_OFFLINE_V1".into(),
        ciphersuite: CIPHERSUITE_X25519_MLKEM768.into(),
        suite: SUITE_X25519_MLKEM768,
        recipient_seat: recipient_key.seat().to_owned(),
        recipient_kid: recipient_key.kid().to_owned(),
        recipient_key_epoch: recipient_key.epoch(),
        recipient_enc_pk_sha256: recipient_key.public_key_sha256(),
        claims,
        runner_signer: *signer.public().as_bytes(),
        sealed_unix,
        plaintext_bytes: plaintext.len() as u64,
    };
    validate_cwcard_pre(&pre, recipient_key)?;
    let KemPublicInner::X25519MlKem768(raw_pk) = &recipient_key.public_key().0 else {
        return Err(EnvelopeError::Rejected);
    };
    let pk = checked_xwing_public(raw_pk)?;
    let info = cwcard_hpke_info(&pre)?;
    let mut entropy = PreSampledEntropy::<64>::sample()?;
    let (enc, mut sender) = hpke::setup_sender_with_rng::<WrapAead, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        &info,
        &mut entropy,
    )
    .map_err(|_| EnvelopeError::Rejected)?;
    let mut enc_arr = Box::new([0_u8; XWING_ENCAPPED_KEY_BYTES]);
    enc_arr.copy_from_slice(&enc.to_bytes());
    let header = CwcardHeader {
        pre,
        enc: EncappedBytes(EncappedInner::X25519MlKem768(enc_arr)),
    };
    let aad = canonical(&header)?;
    let ciphertext = sender
        .seal(plaintext, &aad)
        .map_err(|_| EnvelopeError::Rejected)?;
    let ct_hash = hash(&ciphertext);
    let ct_len = ciphertext.len() as u64;
    let signature = signer
        .sign(&cwcard_signature_statement(&header, &ct_hash, ct_len)?)
        .to_bytes();
    let manifest = canonical(&CwcardManifest {
        header,
        ciphertext_sha256: ct_hash,
        ciphertext_bytes: ct_len,
        signature_hex: hex::encode(signature),
    })?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(EnvelopeError::Rejected);
    }
    Ok(SealedCwcard {
        manifest,
        ciphertext,
    })
}

pub fn authenticate_cwcard_offline(
    sealed: &SealedCwcard,
    expected_claims: &ClaimedProvenance,
    verified_recipient_key: &VerifiedRecipientKey,
    runner_signer: &[u8; 32],
) -> Result<AuthenticatedCwcard, EnvelopeError> {
    if sealed.manifest.is_empty()
        || sealed.manifest.len() > MAX_MANIFEST_BYTES
        || sealed.ciphertext.len() < 17
        || sealed.ciphertext.len() > MAX_PLAINTEXT_BYTES + 16
    {
        return Err(EnvelopeError::Rejected);
    }
    let parsed: CwcardManifest =
        serde_json::from_slice(&sealed.manifest).map_err(|_| EnvelopeError::Rejected)?;
    if canonical(&parsed)? != sealed.manifest {
        return Err(EnvelopeError::Rejected);
    }
    validate_cwcard_pre(&parsed.header.pre, verified_recipient_key)?;
    if parsed.header.enc.suite() != KemSuite::X25519MlKem768
        || &parsed.header.pre.claims != expected_claims
        || !bool::from(parsed.header.pre.runner_signer[..].ct_eq(&runner_signer[..]))
        || parsed.ciphertext_bytes != sealed.ciphertext.len() as u64
        || parsed.ciphertext_bytes != parsed.header.pre.plaintext_bytes + 16
        || !bool::from(parsed.ciphertext_sha256[..].ct_eq(&hash(&sealed.ciphertext)[..]))
    {
        return Err(EnvelopeError::Rejected);
    }
    checked_encapped(&parsed.header.enc)?;
    verify_runner_ed25519(
        runner_signer,
        &cwcard_signature_statement(
            &parsed.header,
            &parsed.ciphertext_sha256,
            parsed.ciphertext_bytes,
        )?,
        &parsed.signature_hex,
    )?;
    let digest = hash(&domain(
        b"chinwag-ci-complete-cwcard-v1\0",
        &[&sealed.manifest],
    ));
    Ok(AuthenticatedCwcard {
        manifest: parsed,
        ciphertext: sealed.ciphertext.clone(),
        digest,
    })
}

pub(crate) fn open_cwcard_with_xwing_secret(
    secret: &HybridPrivate,
    public: &KemPublicKey,
    seat: &str,
    kid: &str,
    epoch: u64,
    purpose: RecipientKeyPurpose,
    cwcard: &AuthenticatedCwcard,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let pre = &cwcard.manifest.header.pre;
    if purpose != RecipientKeyPurpose::CwcardOfflineBase
        || seat != pre.recipient_seat
        || kid != pre.recipient_kid
        || epoch != pre.recipient_key_epoch
        || !bool::from(public.sha256()[..].ct_eq(&pre.recipient_enc_pk_sha256[..]))
    {
        return Err(EnvelopeError::Rejected);
    }
    let EncappedInner::X25519MlKem768(raw_enc) = &cwcard.manifest.header.enc.0 else {
        return Err(EnvelopeError::Rejected);
    };
    let enc = checked_xwing_encapped(raw_enc)?;
    let info = cwcard_hpke_info(pre)?;
    let aad = canonical(&cwcard.manifest.header)?;
    let mut receiver =
        hpke::setup_receiver::<WrapAead, HkdfSha256, XWing>(&OpModeR::Base, secret, &enc, &info)
            .map_err(|_| EnvelopeError::Rejected)?;
    let plaintext = Zeroizing::new(
        receiver
            .open(&cwcard.ciphertext, &aad)
            .map_err(|_| EnvelopeError::Rejected)?,
    );
    if plaintext.len() as u64 != pre.plaintext_bytes {
        return Err(EnvelopeError::Rejected);
    }
    Ok(plaintext)
}

// ============================================================================
// Opaque Mode-Specific Role Keys (`X25519-MLKEM768` by default)
// ============================================================================

pub struct AcuGateKey {
    secret: KemPrivate,
    public: KemPublicKey,
}

pub struct DestinationKey {
    secret: KemPrivate,
    public: KemPublicKey,
    role: Destination,
}

pub struct ResponseKey {
    secret: KemPrivate,
    public: KemPublicKey,
    role: Destination,
}

pub struct GateSecret {
    secret: Zeroizing<Vec<u8>>,
    envelope: [u8; 32],
}

impl AcuGateKey {
    pub(crate) fn from_owner_seed(seed: &[u8; 32]) -> Self {
        let (secret, public) = derive_xwing_from_seed(seed);
        Self { secret, public }
    }

    pub fn generate() -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_xwing_kem()?;
        Ok(Self { secret, public })
    }

    /// Generates a classical `X25519` (`0x0020`) key strictly for backward-compatible
    /// profile/envelope parsing tests. Production custody always generates `0x647a`.
    pub fn generate_legacy_x25519() -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_legacy_x25519_kem()?;
        Ok(Self { secret, public })
    }

    pub fn public(&self) -> KemPublicKey {
        self.public.clone()
    }

    /// The holder must independently authorize the signed request/current
    /// policy and consume replay state BEFORE calling this cryptographic step.
    pub fn unwrap_for_authorized_release(
        &self,
        envelope: &AuthenticatedEnvelope,
    ) -> Result<GateSecret, EnvelopeError> {
        let pre = &envelope.manifest.header.pre;
        if self.public != pre.keys.acu_gate_base {
            return Err(EnvelopeError::Rejected);
        }
        let secret = unwrap(
            WrapMode::Base,
            &self.secret,
            &envelope.manifest.header.acu_gate_base,
            &wrap_context(&canonical(pre)?, b"acu:gate-base"),
        )?;
        Ok(GateSecret {
            secret,
            envelope: envelope.digest,
        })
    }
}

impl DestinationKey {
    pub(crate) fn from_owner_seed(role: Destination, seed: &[u8; 32]) -> Self {
        let (secret, public) = derive_xwing_from_seed(seed);
        Self {
            secret,
            public,
            role,
        }
    }

    pub fn generate(role: Destination) -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_xwing_kem()?;
        Ok(Self {
            secret,
            public,
            role,
        })
    }

    pub fn generate_legacy_x25519(role: Destination) -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_legacy_x25519_kem()?;
        Ok(Self {
            secret,
            public,
            role,
        })
    }

    pub fn public(&self) -> KemPublicKey {
        self.public.clone()
    }

    pub fn open(
        &self,
        envelope: &AuthenticatedEnvelope,
        gate: &GateSecret,
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let header = &envelope.manifest.header;
        if self.public != *self.role.psk_pin(&header.pre.keys)
            || !bool::from(gate.envelope[..].ct_eq(&envelope.digest[..]))
        {
            return Err(EnvelopeError::Rejected);
        }
        let h0 = canonical(&header.pre)?;
        let id = psk_id(&h0);
        let wrapped = match self.role {
            Destination::Recipient => &header.recipient_psk,
            Destination::Archive => &header.archive_psk,
        };
        let key = unwrap(
            WrapMode::Psk {
                gate: &gate.secret,
                id: &id,
            },
            &self.secret,
            wrapped,
            &wrap_context(&h0, self.role.label()),
        )?;
        let aad = canonical(header)?;
        let plaintext = Zeroizing::new(
            ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| EnvelopeError::Rejected)?
                .decrypt(
                    Nonce::from_slice(&header.pre.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| EnvelopeError::Rejected)?,
        );
        if plaintext.len() as u64 != header.pre.plaintext_bytes {
            return Err(EnvelopeError::Rejected);
        }
        Ok(plaintext)
    }
}

fn response_context(
    envelope: &AuthenticatedEnvelope,
    role: Destination,
    request_digest: &[u8; 32],
) -> Vec<u8> {
    domain(
        b"chinwag-ci-acu-release-base-v1\0",
        &[
            &envelope.digest,
            role.label(),
            role.response_pin(&envelope.manifest.header.pre.keys)
                .as_bytes(),
            request_digest,
        ],
    )
}

impl GateSecret {
    /// Ciphertext only; application must separately sign the complete release
    /// statement and bind its nonce/epoch/expiry to the authenticated request.
    pub fn wrap_response(
        &self,
        envelope: &AuthenticatedEnvelope,
        role: Destination,
        request_digest: [u8; 32],
    ) -> Result<WrappedSecret, EnvelopeError> {
        if !bool::from(self.envelope[..].ct_eq(&envelope.digest[..]))
            || bool::from(request_digest[..].ct_eq(&[0; 32]))
        {
            return Err(EnvelopeError::Rejected);
        }
        wrap(
            WrapMode::Base,
            role.response_pin(&envelope.manifest.header.pre.keys),
            &response_context(envelope, role, &request_digest),
            &self.secret,
        )
    }
}

impl ResponseKey {
    pub(crate) fn from_owner_seed(role: Destination, seed: &[u8; 32]) -> Self {
        let (secret, public) = derive_xwing_from_seed(seed);
        Self {
            secret,
            public,
            role,
        }
    }

    pub fn generate(role: Destination) -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_xwing_kem()?;
        Ok(Self {
            secret,
            public,
            role,
        })
    }

    pub fn generate_legacy_x25519(role: Destination) -> Result<Self, EnvelopeError> {
        let (secret, public) = generate_legacy_x25519_kem()?;
        Ok(Self {
            secret,
            public,
            role,
        })
    }

    pub fn public(&self) -> KemPublicKey {
        self.public.clone()
    }

    /// Verify the ACU's separately signed current-policy grant first. Successful
    /// Base decryption by itself authenticates no sender or release authority.
    pub fn open_gate_from_verified_grant(
        &self,
        envelope: &AuthenticatedEnvelope,
        request_digest: [u8; 32],
        wrapped: &WrappedSecret,
    ) -> Result<GateSecret, EnvelopeError> {
        if self.public != *self.role.response_pin(&envelope.manifest.header.pre.keys)
            || bool::from(request_digest[..].ct_eq(&[0; 32]))
        {
            return Err(EnvelopeError::Rejected);
        }
        let secret = unwrap(
            WrapMode::Base,
            &self.secret,
            wrapped,
            &response_context(envelope, self.role, &request_digest),
        )?;
        Ok(GateSecret {
            secret,
            envelope: envelope.digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        acu: AcuGateKey,
        recipient: DestinationKey,
        archive: DestinationKey,
        recipient_response: ResponseKey,
        archive_response: ResponseKey,
        signer: iroh::SecretKey,
        claims: ClaimedProvenance,
        pins: KeyPins,
    }

    impl Fixture {
        fn new() -> Self {
            let acu = AcuGateKey::generate().unwrap();
            let recipient = DestinationKey::generate(Destination::Recipient).unwrap();
            let archive = DestinationKey::generate(Destination::Archive).unwrap();
            let recipient_response = ResponseKey::generate(Destination::Recipient).unwrap();
            let archive_response = ResponseKey::generate(Destination::Archive).unwrap();
            let signing = || {
                let seed = secret().unwrap();
                iroh::SecretKey::from_bytes(&seed)
            };
            let signer = signing();
            let pins = KeyPins {
                acu_gate_base: acu.public(),
                recipient_psk: recipient.public(),
                archive_psk: archive.public(),
                recipient_response_base: recipient_response.public(),
                archive_response_base: archive_response.public(),
                acu_signer: *signing().public().as_bytes(),
                recipient_receipt_signer: *signing().public().as_bytes(),
                archive_receipt_signer: *signing().public().as_bytes(),
            };
            let claims = ClaimedProvenance {
                admission_sha256: [1; 32],
                repository: "example/ci-test".into(),
                repository_id: 42,
                source_commit: [2; 20],
                workflow_ref: "example/ci-test/.github/workflows/ci.yml@refs/heads/proof".into(),
                workflow_commit: [3; 20],
                run_id: 100,
                run_attempt: 1,
                initiating_instance: "WORKHORSE#test-instance-1234".into(),
                intent_digest: [4; 32],
                command_profile_sha256: [5; 32],
                delivery_profile_sha256: [6; 32],
                policy_sha256: [7; 32],
                policy_epoch: 1,
            };
            Self {
                acu,
                recipient,
                archive,
                recipient_response,
                archive_response,
                signer,
                claims,
                pins,
            }
        }

        fn seal(&self, plain: &[u8]) -> SealedEnvelope {
            seal(&self.signer, self.claims.clone(), self.pins.clone(), plain).unwrap()
        }

        fn auth(&self, sealed: &SealedEnvelope) -> Result<AuthenticatedEnvelope, EnvelopeError> {
            authenticate(
                &sealed.manifest,
                &sealed.ciphertext,
                &self.claims,
                &self.pins,
                self.signer.public().as_bytes(),
            )
        }
    }

    #[test]
    fn both_destinations_open_the_same_large_ciphertext_only_with_the_acu_gate() {
        let f = Fixture::new();
        let plaintext: Vec<u8> = (0..700_000).map(|i| (i % 251) as u8).collect();
        let sealed = f.seal(&plaintext);
        let env = f.auth(&sealed).unwrap();
        assert_eq!(env.suite().unwrap(), KemSuite::X25519MlKem768);
        assert_eq!(env.manifest.header.pre.suite, SUITE_X25519_MLKEM768);
        assert_eq!(env.original_manifest().unwrap(), sealed.manifest);
        assert_eq!(env.ciphertext(), sealed.ciphertext);
        let gate = f.acu.unwrap_for_authorized_release(&env).unwrap();
        for (role, response, destination, request) in [
            (
                Destination::Recipient,
                &f.recipient_response,
                &f.recipient,
                [11; 32],
            ),
            (
                Destination::Archive,
                &f.archive_response,
                &f.archive,
                [12; 32],
            ),
        ] {
            let encrypted = gate.wrap_response(&env, role, request).unwrap();
            assert_eq!(encrypted.enc.as_bytes().len(), XWING_ENCAPPED_KEY_BYTES);
            let delivered = response
                .open_gate_from_verified_grant(&env, request, &encrypted)
                .unwrap();
            assert_eq!(&*destination.open(&env, &delivered).unwrap(), &plaintext);
        }
        assert_eq!(env.claims().run_id, 100);
    }

    #[test]
    fn missing_or_wrong_gate_cannot_open_either_destination_even_in_collusion() {
        let f = Fixture::new();
        let env = f.auth(&f.seal(b"full failure output")).unwrap();
        let h0 = canonical(&env.manifest.header.pre).unwrap();
        let id = psk_id(&h0);
        for gate in [vec![], vec![0; 32], vec![9; 31], vec![9; 33]] {
            assert!(psk(&gate, &id).is_err());
        }
        assert!(psk(&[9; 32], &[]).is_err());
        let wrong = GateSecret {
            secret: Zeroizing::new(vec![9; 32]),
            envelope: env.digest,
        };
        assert!(f.recipient.open(&env, &wrong).is_err());
        assert!(f.archive.open(&env, &wrong).is_err());
        let right = f.acu.unwrap_for_authorized_release(&env).unwrap();
        assert!(
            DestinationKey::generate(Destination::Recipient)
                .unwrap()
                .open(&env, &right)
                .is_err()
        );
        assert!(
            unwrap(
                WrapMode::Psk {
                    gate: &right.secret,
                    id: &id
                },
                &f.acu.secret,
                &env.manifest.header.recipient_psk,
                &wrap_context(&h0, Destination::Recipient.label())
            )
            .is_err()
        );
    }

    #[test]
    fn release_ciphertext_is_bound_to_request_role_response_key_and_envelope() {
        let f = Fixture::new();
        let env = f.auth(&f.seal(b"failure one")).unwrap();
        let other = f.auth(&f.seal(b"failure two")).unwrap();
        let gate = f.acu.unwrap_for_authorized_release(&env).unwrap();
        let wrapped = gate
            .wrap_response(&env, Destination::Recipient, [11; 32])
            .unwrap();
        assert!(
            f.archive_response
                .open_gate_from_verified_grant(&env, [11; 32], &wrapped)
                .is_err()
        );
        assert!(
            f.recipient_response
                .open_gate_from_verified_grant(&env, [12; 32], &wrapped)
                .is_err()
        );
        assert!(
            f.recipient_response
                .open_gate_from_verified_grant(&other, [11; 32], &wrapped)
                .is_err()
        );
        assert!(f.archive.open(&other, &gate).is_err());
        assert!(
            gate.wrap_response(&other, Destination::Recipient, [11; 32])
                .is_err()
        );
    }

    #[test]
    fn every_signed_component_and_exact_expected_provenance_is_authenticated() {
        let f = Fixture::new();
        let sealed = f.seal(b"failure output");
        let mut corrupt = sealed.ciphertext.clone();
        corrupt[0] ^= 1;
        assert!(
            authenticate(
                &sealed.manifest,
                &corrupt,
                &f.claims,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
        let original: serde_json::Value = serde_json::from_slice(&sealed.manifest).unwrap();
        for path in [
            "/header/pre/claims/run_id",
            "/header/pre/claims/policy_epoch",
            "/header/pre/nonce/0",
            "/header/recipient_psk/ciphertext/0",
            "/header/acu_gate_base/ciphertext/0",
            "/ciphertext_bytes",
        ] {
            let mut v = original.clone();
            let field = v.pointer_mut(path).unwrap();
            let n = field.as_u64().unwrap();
            *field = serde_json::json!(n ^ 1);
            let parsed: Manifest = serde_json::from_value(v).unwrap();
            assert!(
                authenticate(
                    &canonical(&parsed).unwrap(),
                    &sealed.ciphertext,
                    &f.claims,
                    &f.pins,
                    f.signer.public().as_bytes()
                )
                .is_err(),
                "{path}"
            );
        }
        // Mutate both ML-KEM-768 ct_M (char 0) and X25519 ct_X (char 2176) in `enc` hex:
        for char_idx in [0_usize, 2176] {
            let mut v = original.clone();
            let hex_str = v["header"]["archive_psk"]["enc"]
                .as_str()
                .unwrap()
                .to_owned();
            let mut chars: Vec<u8> = hex_str.into_bytes();
            chars[char_idx] = if chars[char_idx] == b'0' { b'1' } else { b'0' };
            v["header"]["archive_psk"]["enc"] =
                serde_json::json!(String::from_utf8(chars).unwrap());
            let parsed: Manifest = serde_json::from_value(v).unwrap();
            assert!(
                authenticate(
                    &canonical(&parsed).unwrap(),
                    &sealed.ciphertext,
                    &f.claims,
                    &f.pins,
                    f.signer.public().as_bytes()
                )
                .is_err()
            );
        }
        let mut different = f.claims.clone();
        different.source_commit[0] ^= 1;
        assert!(
            authenticate(
                &sealed.manifest,
                &sealed.ciphertext,
                &different,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
        let mut extra = sealed.manifest.clone();
        extra.push(b' ');
        assert!(
            authenticate(
                &extra,
                &sealed.ciphertext,
                &f.claims,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
        let duplicate = String::from_utf8(sealed.manifest.clone())
            .unwrap()
            .replacen("{\"header\":", "{\"ciphertext_bytes\":30,\"header\":", 1);
        assert!(
            authenticate(
                duplicate.as_bytes(),
                &sealed.ciphertext,
                &f.claims,
                &f.pins,
                f.signer.public().as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn all_wraps_are_in_payload_aad_and_cannot_be_transplanted_or_downgraded() {
        let f = Fixture::new();
        let sealed = f.seal(b"failure output");
        let original_env = f.auth(&sealed).unwrap();
        let mut manifest: Manifest = serde_json::from_slice(&sealed.manifest).unwrap();
        manifest.header.recipient_psk.ciphertext[0] ^= 1;
        manifest.signature_hex = hex::encode(
            f.signer
                .sign(
                    &statement(
                        &manifest.header,
                        &manifest.ciphertext_sha256,
                        manifest.ciphertext_bytes,
                    )
                    .unwrap(),
                )
                .to_bytes(),
        );
        let corrupt = SealedEnvelope {
            manifest: canonical(&manifest).unwrap(),
            ciphertext: sealed.ciphertext,
        };
        let env = f.auth(&corrupt).unwrap();
        let gate = f.acu.unwrap_for_authorized_release(&env).unwrap();
        assert!(f.archive.open(&env, &gate).is_err());
        let h0 = canonical(&original_env.manifest.header.pre).unwrap();
        assert!(
            unwrap(
                WrapMode::Base,
                &f.recipient.secret,
                &original_env.manifest.header.recipient_psk,
                &wrap_context(&h0, Destination::Recipient.label())
            )
            .is_err()
        );
    }

    #[test]
    fn mode_key_aliases_weak_signers_invalid_sizes_and_reused_material_are_refused() {
        let f = Fixture::new();
        let mut pins = f.pins.clone();
        pins.recipient_response_base = pins.recipient_psk.clone();
        assert!(seal(&f.signer, f.claims.clone(), pins, b"test").is_err());
        assert!(seal(&f.signer, f.claims.clone(), f.pins.clone(), b"").is_err());
        let mut pins = f.pins.clone();
        pins.acu_signer = [0; 32];
        assert!(seal(&f.signer, f.claims.clone(), pins, b"test").is_err());
        let first = f.seal(b"same report");
        let second = f.seal(b"same report");
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(first.manifest, second.manifest);
    }

    #[test]
    fn external_response_pins_must_be_canonical_and_contributory_in_both_mlkem_and_x25519() {
        let f = Fixture::new();
        // 1. Unreduced FIPS 203 ML-KEM-768 12-bit coefficient >= 3329 in `[0..1184]`
        let mut unreduced_mlkem = f.pins.archive_response_base.clone();
        {
            let b = unreduced_mlkem.as_mut_bytes_for_test();
            b[0] = 0x01;
            b[1] = (b[1] & 0xf0) | 0x0d; // 3329
        }
        let mut pins = f.pins.clone();
        pins.archive_response_base = unreduced_mlkem;
        assert!(seal(&f.signer, f.claims.clone(), pins, b"failure").is_err());

        // 2. Non-canonical / low-order X25519 share in `[1184..1216]`
        let mut low_order = [0_u8; 32];
        low_order[0] = 1;
        let mut high_bit_alias = *f.pins.recipient_response_base.x25519_component();
        high_bit_alias[31] |= 0x80;
        let mut modulus = [0xff_u8; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        for invalid_x in [low_order, high_bit_alias, modulus] {
            let mut bad_pin = f.pins.archive_response_base.clone();
            bad_pin.as_mut_bytes_for_test()[XWING_MLKEM768_PK_BYTES..].copy_from_slice(&invalid_x);
            let mut pins = f.pins.clone();
            pins.archive_response_base = bad_pin;
            assert!(seal(&f.signer, f.claims.clone(), pins, b"failure").is_err());
        }
    }
}
