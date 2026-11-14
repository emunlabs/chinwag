// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `SignedHpkeBlobV1` (`CHWGHPKE` v2 · `1,408`-Byte Framing) Hybrid Post-Quantum
//! Envelope & `K1 + K2` `Ed25519` Verify-Before-Decrypt Pipeline (`CHWG-0200` ·
//! `INV-VERIFY-BEFORE-DECRYPT-01`).
//!
//! Wire layout (`1,408` fixed header/tag bytes + `ciphertext_len` payload bytes):
//! - `0..8`     (`8 B`)   : Magic `b"CHWGHPKE"`
//! - `8..12`    (`4 B`)   : `version = 2` (`u8`), `suite = 1` (`u8`), `flags` (`u16` BE)
//! - `12..20` (`8 B`): `kem_id = 0x647a` (`X25519-MLKEM768`), `kdf_id = 0x0001` (`HKDF-SHA256`),
//!   `aead_id = 0x0003` (`ChaCha20Poly1305`), `reserved = 0` (`u16` BE)
//! - `20..52`   (`32 B`)  : `sender_key_id` (`BLAKE3` of `K1` Ed25519 verifying key)
//! - `52..84`   (`32 B`)  : `recipient_key_id` (`BLAKE3` of recipient `1,216`-byte `XWing` public key)
//! - `84..116`  (`32 B`)  : `t_coalesce` (keyed `BLAKE3` blinded routing commitment)
//! - `116..124` (`8 B`)   : `sequence` (`u64` BE, strictly `>= 1`)
//! - `124..132` (`8 B`)   : `timestamp_unix_micros` (`u64` BE)
//! - `132..1252`(`1120 B`): `encapsulated_key` (`X25519-MLKEM768` / `XWing` `enc`)
//! - `1252..1316`(`64 B`) : `origin_sig_k1` (`OriginSigV1` `Ed25519` signature by `K1`)
//! - `1316..1380`(`64 B`) : `relay_sig_k2` (`CloudRelayBlobSigV1` `Ed25519` signature by `K2`)
//! - `1380..1384`(`4 B`)  : `header_crc32c` (`u32` BE `CRC-32C` over `wire[0..1380]`)
//! - `1384..1392`(`8 B`)  : `ciphertext_len` (`u64` BE)
//! - `1392..1408`(`16 B`) : `aead_tag` (`16 B` `ChaCha20-Poly1305` authentication tag)
//! - `1408..`             : `ciphertext_payload` (`ciphertext_len` bytes, sealed with `wire[0..1252]` as AAD)

use crate::relay_failover::{FailoverError, ReplayWindow, validate_timestamp_window};
use core::convert::Infallible;
use crc::{CRC_32_ISCSI, Crc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::XWing,
    rand_core::{TryCryptoRng, TryRng},
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const CHWGHPKE_MAGIC: &[u8; 8] = b"CHWGHPKE";
pub const CHWGHPKE_VERSION_V2: u8 = 2;
pub const CHWGHPKE_SUITE_PQ_HYBRID: u8 = 1;

pub const HPKE_KEM_X25519_MLKEM768: u16 = 0x647a;
pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

pub const FLAG_DIRECT_P2P_K1_ONLY: u16 = 0x0001;
pub const FLAG_CLOUD_RELAY_K2_SIGNED: u16 = 0x0002;

pub const SIGNED_HPKE_FIXED_FRAME_BYTES: usize = 1408;
pub const XWING_PUBLIC_KEY_BYTES: usize = 1216;
pub const XWING_ENCAPSULATED_KEY_BYTES: usize = 1120;
pub const AEAD_TAG_BYTES: usize = 16;

/// Hard upper bound (`16 MiB`) on a single `SignedHpkeBlobV1` ciphertext payload.
pub const MAX_SIGNED_HPKE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Default maximum allowed clock skew (`5 minutes` in microseconds).
pub const DEFAULT_MAX_CLOCK_SKEW_MICROS: u64 = 300_000_000;

const HPKE_KEY_SCHEDULE_INFO: &[u8] = b"chinwag-signed-hpke-blob-v1/0x647a\0";
const ORIGIN_SIG_V1_DOMAIN: &[u8] = b"chinwag-origin-sig-v1/k1\0";
const RELAY_SIG_V1_DOMAIN: &[u8] = b"chinwag-cloud-relay-blob-sig-v1/k2\0";
const T_COALESCE_KEY_CONTEXT: &str = "chinwag-blind-coalesce-v1 2026";

const CRC32C_CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignedHpkeError {
    #[error("wire frame truncated or exceeds 16 MiB payload limit")]
    InvalidFrameLength,
    #[error("invalid CHWGHPKE v2 magic, version, or ciphersuite identifiers")]
    UnsupportedHeaderSuite,
    #[error("CRC-32C header integrity check failed before cryptographic processing")]
    HeaderCrcMismatch,
    #[error("replay or timestamp freshness check failed: {0}")]
    ReplayOrFreshness(#[from] FailoverError),
    #[error("unknown or weak origin K1 Ed25519 signer key_id")]
    UnknownOriginSigner,
    #[error("OriginSigV1 (K1) Ed25519 verify_strict failed — decapsulation aborted")]
    OriginSignatureInvalid,
    #[error(
        "CloudRelayBlobSigV1 (K2) missing or Ed25519 verify_strict failed — decapsulation aborted"
    )]
    RelaySignatureInvalid,
    #[error("recipient X25519-MLKEM768 key fingerprint mismatch or invalid key material")]
    RecipientKeyMismatch,
    #[error("HPKE X25519-MLKEM768 encapsulation or AEAD open failed")]
    HpkeCryptoFailed,
    #[error("OS CSPRNG entropy unavailable")]
    EntropyUnavailable,
}

/// Computes RFC 3720 / Castagnoli `CRC-32C` (`CRC_32_ISCSI`).
pub fn compute_crc32c(bytes: &[u8]) -> u32 {
    CRC32C_CASTAGNOLI.checksum(bytes)
}

/// Computes a blinded `t_coalesce` routing commitment using keyed `BLAKE3` KDF + MAC
/// so edge relays can coalesce matrix shards without learning repository/branch names.
pub fn derive_blinded_coalesce_tag(
    shared_room_secret: &[u8; 32],
    routing_topic: &[u8],
) -> [u8; 32] {
    let subkey = blake3::derive_key(T_COALESCE_KEY_CONTEXT, shared_room_secret);
    *blake3::keyed_hash(&subkey, routing_topic).as_bytes()
}

/// Generates a fresh `X25519-MLKEM768` (`0x647a`) recipient keypair (`32 B` secret seed, `1216 B` public key).
pub fn generate_xwing_keypair()
-> Result<(Zeroizing<[u8; 32]>, [u8; XWING_PUBLIC_KEY_BYTES]), SignedHpkeError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| SignedHpkeError::EntropyUnavailable)?;
    if bool::from(seed[..].ct_eq(&[0u8; 32])) {
        return Err(SignedHpkeError::EntropyUnavailable);
    }
    Ok(derive_xwing_keypair_deterministic(&seed))
}

/// Deterministically derives an `X25519-MLKEM768` (`0x647a`) keypair from a 32-byte `ikm` seed.
pub fn derive_xwing_keypair_deterministic(
    seed: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, [u8; XWING_PUBLIC_KEY_BYTES]) {
    let (sk, pk) = XWing::derive_keypair(seed);
    let mut sk_out = Zeroizing::new([0u8; 32]);
    sk_out.copy_from_slice(sk.to_bytes().as_slice());
    let mut pk_out = [0u8; XWING_PUBLIC_KEY_BYTES];
    pk_out.copy_from_slice(pk.to_bytes().as_slice());
    (sk_out, pk_out)
}

struct PreSampled64 {
    buf: Zeroizing<[u8; 64]>,
    offset: usize,
    overflowed: bool,
}

impl PreSampled64 {
    fn from_os_csprng() -> Result<Self, SignedHpkeError> {
        let mut buf = Zeroizing::new([0u8; 64]);
        getrandom::fill(&mut buf[..]).map_err(|_| SignedHpkeError::EntropyUnavailable)?;
        if bool::from(buf[..].ct_eq(&[0u8; 64])) {
            return Err(SignedHpkeError::EntropyUnavailable);
        }
        Ok(Self {
            buf,
            offset: 0,
            overflowed: false,
        })
    }

    fn finish(self) -> Result<(), SignedHpkeError> {
        if self.overflowed || self.offset != 64 {
            return Err(SignedHpkeError::EntropyUnavailable);
        }
        Ok(())
    }
}

impl TryRng for PreSampled64 {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut out = [0u8; 4];
        self.try_fill_bytes(&mut out)?;
        Ok(u32::from_le_bytes(out))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut out = [0u8; 8];
        self.try_fill_bytes(&mut out)?;
        Ok(u64::from_le_bytes(out))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let avail = 64usize.saturating_sub(self.offset);
        if self.overflowed || dst.len() > avail {
            self.overflowed = true;
            dst.fill(0);
            return Ok(());
        }
        let end = self.offset + dst.len();
        dst.copy_from_slice(&self.buf[self.offset..end]);
        self.buf[self.offset..end].fill(0);
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for PreSampled64 {}

/// Pinned `K1` origin `Ed25519` verifying keys indexed by `BLAKE3(pubkey)`.
#[derive(Debug, Clone, Default)]
pub struct OriginKeyRing {
    by_key_id: BTreeMap<[u8; 32], VerifyingKey>,
}

impl OriginKeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enroll(&mut self, pubkey_bytes: [u8; 32]) -> Result<[u8; 32], SignedHpkeError> {
        let vk = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| SignedHpkeError::UnknownOriginSigner)?;
        if vk.is_weak() {
            return Err(SignedHpkeError::UnknownOriginSigner);
        }
        let key_id = *blake3::hash(&pubkey_bytes).as_bytes();
        self.by_key_id.insert(key_id, vk);
        Ok(key_id)
    }

    pub fn lookup(&self, key_id: &[u8; 32]) -> Option<&VerifyingKey> {
        self.by_key_id.get(key_id)
    }
}

/// Pinned `K2` regional blind-relay `Ed25519` verifying keys supporting active + rollover keys
/// across multiple geographic regions.
#[derive(Debug, Clone, Default)]
pub struct RelayKeyRing {
    verifiers: Vec<VerifyingKey>,
}

impl RelayKeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enroll(&mut self, pubkey_bytes: [u8; 32]) -> Result<(), SignedHpkeError> {
        let vk = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| SignedHpkeError::RelaySignatureInvalid)?;
        if vk.is_weak() {
            return Err(SignedHpkeError::RelaySignatureInvalid);
        }
        if !self.verifiers.iter().any(|existing| existing == &vk) {
            self.verifiers.push(vk);
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.verifiers.is_empty()
    }
}

/// Verification policy for `K2` (`CloudRelayBlobSigV1`):
/// - `RequireCloudK2`: mandatory for all frames arriving over `WSS :443` cloud relays!
/// - `AllowDirectP2pK1Only`: permitted ONLY on authenticated direct `QUIC` P2P sockets.
#[derive(Debug, Clone, Copy)]
pub enum RelaySignaturePolicy<'a> {
    RequireCloudK2(&'a RelayKeyRing),
    AllowDirectP2pK1Only,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealBlobParams<'a> {
    pub origin_signing_key_k1: &'a SigningKey,
    pub recipient_xwing_public: &'a [u8; XWING_PUBLIC_KEY_BYTES],
    pub t_coalesce: [u8; 32],
    pub sequence: u64,
    pub timestamp_unix_micros: u64,
    pub plaintext: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPlaintextBlob {
    pub sender_key_id: [u8; 32],
    pub recipient_key_id: [u8; 32],
    pub t_coalesce: [u8; 32],
    pub sequence: u64,
    pub timestamp_unix_micros: u64,
    pub flags: u16,
    pub plaintext: Zeroizing<Vec<u8>>,
}

fn origin_sig_k1_preimage(
    aad_header_0_1252: &[u8],
    ciphertext_len: u64,
    aead_tag: &[u8; AEAD_TAG_BYTES],
    ciphertext_payload: &[u8],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(aead_tag);
    hasher.update(ciphertext_payload);
    let body_digest = hasher.finalize();

    let mut out = Vec::with_capacity(ORIGIN_SIG_V1_DOMAIN.len() + 1252 + 8 + 32);
    out.extend_from_slice(ORIGIN_SIG_V1_DOMAIN);
    out.extend_from_slice(aad_header_0_1252);
    out.extend_from_slice(&ciphertext_len.to_be_bytes());
    out.extend_from_slice(body_digest.as_bytes());
    out
}

fn relay_sig_k2_preimage(
    header_with_k1_0_1316: &[u8],
    ciphertext_len: u64,
    aead_tag: &[u8; AEAD_TAG_BYTES],
    ciphertext_payload: &[u8],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(aead_tag);
    hasher.update(ciphertext_payload);
    let body_digest = hasher.finalize();

    let mut out = Vec::with_capacity(RELAY_SIG_V1_DOMAIN.len() + 1316 + 8 + 32);
    out.extend_from_slice(RELAY_SIG_V1_DOMAIN);
    out.extend_from_slice(header_with_k1_0_1316);
    out.extend_from_slice(&ciphertext_len.to_be_bytes());
    out.extend_from_slice(body_digest.as_bytes());
    out
}

/// Seals a `SignedHpkeBlobV1` (`CHWGHPKE` v2) frame with `X25519-MLKEM768` (`0x647a`)
/// and signs `OriginSigV1` (`K1`). Optionally attaches `CloudRelayBlobSigV1` (`K2`)
/// immediately or leaves `FLAG_DIRECT_P2P_K1_ONLY` set for later blind-relay `K2`
/// counter-signing via [`countersign_relay_blob_k2`].
pub fn seal_signed_hpke_blob_v1(
    params: SealBlobParams<'_>,
    optional_relay_k2: Option<&SigningKey>,
) -> Result<Vec<u8>, SignedHpkeError> {
    if params.sequence == 0 {
        return Err(SignedHpkeError::ReplayOrFreshness(
            FailoverError::ZeroSequence,
        ));
    }
    if params.timestamp_unix_micros == 0 {
        return Err(SignedHpkeError::ReplayOrFreshness(
            FailoverError::TimestampSkew {
                packet_micros: 0,
                now_micros: 0,
            },
        ));
    }
    if params.plaintext.len() > MAX_SIGNED_HPKE_PAYLOAD_BYTES {
        return Err(SignedHpkeError::InvalidFrameLength);
    }

    let origin_vk = params.origin_signing_key_k1.verifying_key();
    if origin_vk.is_weak() {
        return Err(SignedHpkeError::UnknownOriginSigner);
    }
    let pk = <XWing as KemTrait>::PublicKey::from_bytes(params.recipient_xwing_public)
        .map_err(|_| SignedHpkeError::RecipientKeyMismatch)?;

    let sender_key_id = *blake3::hash(&origin_vk.to_bytes()).as_bytes();
    let recipient_key_id = *blake3::hash(params.recipient_xwing_public).as_bytes();

    let mut rng = PreSampled64::from_os_csprng()?;
    let (enc, mut sender_ctx) = hpke::setup_sender_with_rng::<
        HpkeChaCha20Poly1305,
        HkdfSha256,
        XWing,
    >(&OpModeS::Base, &pk, HPKE_KEY_SCHEDULE_INFO, &mut rng)
    .map_err(|_| SignedHpkeError::HpkeCryptoFailed)?;
    rng.finish()?;

    let enc_bytes = enc.to_bytes();
    if enc_bytes.len() != XWING_ENCAPSULATED_KEY_BYTES {
        return Err(SignedHpkeError::HpkeCryptoFailed);
    }

    let flags = if optional_relay_k2.is_some() {
        FLAG_CLOUD_RELAY_K2_SIGNED
    } else {
        FLAG_DIRECT_P2P_K1_ONLY
    };

    let ciphertext_len = params.plaintext.len() as u64;
    let mut wire = Vec::with_capacity(SIGNED_HPKE_FIXED_FRAME_BYTES + params.plaintext.len());

    // 0..8: Magic
    wire.extend_from_slice(CHWGHPKE_MAGIC);
    // 8..12: version (1B), suite (1B), flags (2B BE)
    wire.push(CHWGHPKE_VERSION_V2);
    wire.push(CHWGHPKE_SUITE_PQ_HYBRID);
    wire.extend_from_slice(&flags.to_be_bytes());
    // 12..20: kem_id, kdf_id, aead_id, reserved
    wire.extend_from_slice(&HPKE_KEM_X25519_MLKEM768.to_be_bytes());
    wire.extend_from_slice(&HPKE_KDF_HKDF_SHA256.to_be_bytes());
    wire.extend_from_slice(&HPKE_AEAD_CHACHA20_POLY1305.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    // 20..52: sender_key_id
    wire.extend_from_slice(&sender_key_id);
    // 52..84: recipient_key_id
    wire.extend_from_slice(&recipient_key_id);
    // 84..116: t_coalesce
    wire.extend_from_slice(&params.t_coalesce);
    // 116..124: sequence
    wire.extend_from_slice(&params.sequence.to_be_bytes());
    // 124..132: timestamp_unix_micros
    wire.extend_from_slice(&params.timestamp_unix_micros.to_be_bytes());
    // 132..1252: encapsulated_key (1120 B)
    wire.extend_from_slice(enc_bytes.as_slice());
    debug_assert_eq!(wire.len(), 1252);

    // Seal plaintext with `wire[0..1252]` bound as RFC 9180 AAD!
    // Note: flags bit is bound into AAD so no relay can strip K2 mode without breaking AEAD + K1!
    let sealed_ct_and_tag = sender_ctx
        .seal(params.plaintext, &wire[0..1252])
        .map_err(|_| SignedHpkeError::HpkeCryptoFailed)?;
    if sealed_ct_and_tag.len() != params.plaintext.len() + AEAD_TAG_BYTES {
        return Err(SignedHpkeError::HpkeCryptoFailed);
    }
    let (ct_payload, tag_slice) = sealed_ct_and_tag.split_at(params.plaintext.len());
    let mut aead_tag = [0u8; AEAD_TAG_BYTES];
    aead_tag.copy_from_slice(tag_slice);

    // 1252..1316: OriginSigV1 (K1)
    let k1_msg = origin_sig_k1_preimage(&wire[0..1252], ciphertext_len, &aead_tag, ct_payload);
    let sig_k1 = params.origin_signing_key_k1.sign(&k1_msg);
    wire.extend_from_slice(&sig_k1.to_bytes());
    debug_assert_eq!(wire.len(), 1316);

    // 1316..1380: CloudRelayBlobSigV1 (K2) or 64 zero bytes on direct P2P
    if let Some(relay_sk) = optional_relay_k2 {
        if relay_sk.verifying_key().is_weak() {
            return Err(SignedHpkeError::RelaySignatureInvalid);
        }
        let k2_msg = relay_sig_k2_preimage(&wire[0..1316], ciphertext_len, &aead_tag, ct_payload);
        let sig_k2 = relay_sk.sign(&k2_msg);
        wire.extend_from_slice(&sig_k2.to_bytes());
    } else {
        wire.extend_from_slice(&[0u8; 64]);
    }
    debug_assert_eq!(wire.len(), 1380);

    // 1380..1384: CRC-32C over `wire[0..1380]`
    let crc = compute_crc32c(&wire[0..1380]);
    wire.extend_from_slice(&crc.to_be_bytes());
    // 1384..1392: ciphertext_len
    wire.extend_from_slice(&ciphertext_len.to_be_bytes());
    // 1392..1408: aead_tag (16 B)
    wire.extend_from_slice(&aead_tag);
    debug_assert_eq!(wire.len(), SIGNED_HPKE_FIXED_FRAME_BYTES);

    // 1408..1408+ciphertext_len: ciphertext_payload
    wire.extend_from_slice(ct_payload);
    Ok(wire)
}

/// Seals a `SignedHpkeBlobV1` framed explicitly for cloud relay transit (`FLAG_CLOUD_RELAY_K2_SIGNED`)
/// with an empty `relay_sig_k2` slot ready for a zero-knowledge regional blind relay to
/// verify `K1` and counter-sign via [`countersign_relay_blob_k2`] without ever seeing plaintext.
pub fn seal_for_blind_relay_transit(
    params: SealBlobParams<'_>,
) -> Result<Vec<u8>, SignedHpkeError> {
    if params.sequence == 0 {
        return Err(SignedHpkeError::ReplayOrFreshness(
            FailoverError::ZeroSequence,
        ));
    }
    if params.timestamp_unix_micros == 0 {
        return Err(SignedHpkeError::ReplayOrFreshness(
            FailoverError::TimestampSkew {
                packet_micros: 0,
                now_micros: 0,
            },
        ));
    }
    if params.plaintext.len() > MAX_SIGNED_HPKE_PAYLOAD_BYTES {
        return Err(SignedHpkeError::InvalidFrameLength);
    }

    let origin_vk = params.origin_signing_key_k1.verifying_key();
    if origin_vk.is_weak() {
        return Err(SignedHpkeError::UnknownOriginSigner);
    }
    let pk = <XWing as KemTrait>::PublicKey::from_bytes(params.recipient_xwing_public)
        .map_err(|_| SignedHpkeError::RecipientKeyMismatch)?;

    let sender_key_id = *blake3::hash(&origin_vk.to_bytes()).as_bytes();
    let recipient_key_id = *blake3::hash(params.recipient_xwing_public).as_bytes();

    let mut rng = PreSampled64::from_os_csprng()?;
    let (enc, mut sender_ctx) = hpke::setup_sender_with_rng::<
        HpkeChaCha20Poly1305,
        HkdfSha256,
        XWing,
    >(&OpModeS::Base, &pk, HPKE_KEY_SCHEDULE_INFO, &mut rng)
    .map_err(|_| SignedHpkeError::HpkeCryptoFailed)?;
    rng.finish()?;

    let enc_bytes = enc.to_bytes();
    let ciphertext_len = params.plaintext.len() as u64;
    let mut wire = Vec::with_capacity(SIGNED_HPKE_FIXED_FRAME_BYTES + params.plaintext.len());

    wire.extend_from_slice(CHWGHPKE_MAGIC);
    wire.push(CHWGHPKE_VERSION_V2);
    wire.push(CHWGHPKE_SUITE_PQ_HYBRID);
    wire.extend_from_slice(&FLAG_CLOUD_RELAY_K2_SIGNED.to_be_bytes());
    wire.extend_from_slice(&HPKE_KEM_X25519_MLKEM768.to_be_bytes());
    wire.extend_from_slice(&HPKE_KDF_HKDF_SHA256.to_be_bytes());
    wire.extend_from_slice(&HPKE_AEAD_CHACHA20_POLY1305.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&sender_key_id);
    wire.extend_from_slice(&recipient_key_id);
    wire.extend_from_slice(&params.t_coalesce);
    wire.extend_from_slice(&params.sequence.to_be_bytes());
    wire.extend_from_slice(&params.timestamp_unix_micros.to_be_bytes());
    wire.extend_from_slice(enc_bytes.as_slice());

    let sealed_ct_and_tag = sender_ctx
        .seal(params.plaintext, &wire[0..1252])
        .map_err(|_| SignedHpkeError::HpkeCryptoFailed)?;
    let (ct_payload, tag_slice) = sealed_ct_and_tag.split_at(params.plaintext.len());
    let mut aead_tag = [0u8; AEAD_TAG_BYTES];
    aead_tag.copy_from_slice(tag_slice);

    let k1_msg = origin_sig_k1_preimage(&wire[0..1252], ciphertext_len, &aead_tag, ct_payload);
    let sig_k1 = params.origin_signing_key_k1.sign(&k1_msg);
    wire.extend_from_slice(&sig_k1.to_bytes());
    // Empty K2 slot before edge relay counter-signature
    wire.extend_from_slice(&[0u8; 64]);
    let crc = compute_crc32c(&wire[0..1380]);
    wire.extend_from_slice(&crc.to_be_bytes());
    wire.extend_from_slice(&ciphertext_len.to_be_bytes());
    wire.extend_from_slice(&aead_tag);
    wire.extend_from_slice(ct_payload);
    Ok(wire)
}

/// Zero-knowledge regional relay gate: verifies framing, CRC-32C, and `OriginSigV1` (`K1`)
/// with ZERO recipient secret keys, then stamps `CloudRelayBlobSigV1` (`K2`) and updates
/// `header_crc32c`. Any unauthenticated or corrupted frame is dropped at the edge!
pub fn countersign_relay_blob_k2(
    mut wire: Vec<u8>,
    origin_ring: &OriginKeyRing,
    relay_signing_key_k2: &SigningKey,
) -> Result<Vec<u8>, SignedHpkeError> {
    let parsed = parse_and_check_crc(&wire)?;
    if parsed.flags != FLAG_CLOUD_RELAY_K2_SIGNED {
        return Err(SignedHpkeError::UnsupportedHeaderSuite);
    }
    if relay_signing_key_k2.verifying_key().is_weak() {
        return Err(SignedHpkeError::RelaySignatureInvalid);
    }

    let origin_vk = origin_ring
        .lookup(&parsed.sender_key_id)
        .ok_or(SignedHpkeError::UnknownOriginSigner)?;
    let k1_msg = origin_sig_k1_preimage(
        &wire[0..1252],
        parsed.ciphertext_len,
        &parsed.aead_tag,
        &wire[SIGNED_HPKE_FIXED_FRAME_BYTES..],
    );
    origin_vk
        .verify_strict(&k1_msg, &Signature::from_bytes(&parsed.origin_sig_k1))
        .map_err(|_| SignedHpkeError::OriginSignatureInvalid)?;

    let k2_msg = relay_sig_k2_preimage(
        &wire[0..1316],
        parsed.ciphertext_len,
        &parsed.aead_tag,
        &wire[SIGNED_HPKE_FIXED_FRAME_BYTES..],
    );
    let sig_k2 = relay_signing_key_k2.sign(&k2_msg);
    wire[1316..1380].copy_from_slice(&sig_k2.to_bytes());
    let updated_crc = compute_crc32c(&wire[0..1380]);
    wire[1380..1384].copy_from_slice(&updated_crc.to_be_bytes());
    Ok(wire)
}

struct ParsedWireHeader {
    flags: u16,
    sender_key_id: [u8; 32],
    recipient_key_id: [u8; 32],
    t_coalesce: [u8; 32],
    sequence: u64,
    timestamp_unix_micros: u64,
    origin_sig_k1: [u8; 64],
    relay_sig_k2: [u8; 64],
    ciphertext_len: u64,
    aead_tag: [u8; AEAD_TAG_BYTES],
}

fn parse_and_check_crc(wire: &[u8]) -> Result<ParsedWireHeader, SignedHpkeError> {
    if wire.len() < SIGNED_HPKE_FIXED_FRAME_BYTES {
        return Err(SignedHpkeError::InvalidFrameLength);
    }
    if &wire[0..8] != CHWGHPKE_MAGIC {
        return Err(SignedHpkeError::UnsupportedHeaderSuite);
    }
    let version = wire[8];
    let suite = wire[9];
    let flags = u16::from_be_bytes([wire[10], wire[11]]);
    let kem_id = u16::from_be_bytes([wire[12], wire[13]]);
    let kdf_id = u16::from_be_bytes([wire[14], wire[15]]);
    let aead_id = u16::from_be_bytes([wire[16], wire[17]]);
    let reserved = u16::from_be_bytes([wire[18], wire[19]]);

    if version != CHWGHPKE_VERSION_V2
        || suite != CHWGHPKE_SUITE_PQ_HYBRID
        || kem_id != HPKE_KEM_X25519_MLKEM768
        || kdf_id != HPKE_KDF_HKDF_SHA256
        || aead_id != HPKE_AEAD_CHACHA20_POLY1305
        || reserved != 0
        || !matches!(flags, FLAG_DIRECT_P2P_K1_ONLY | FLAG_CLOUD_RELAY_K2_SIGNED)
    {
        return Err(SignedHpkeError::UnsupportedHeaderSuite);
    }

    let expected_crc = u32::from_be_bytes([wire[1380], wire[1381], wire[1382], wire[1383]]);
    let actual_crc = compute_crc32c(&wire[0..1380]);
    if expected_crc != actual_crc {
        return Err(SignedHpkeError::HeaderCrcMismatch);
    }

    let ciphertext_len = u64::from_be_bytes(wire[1384..1392].try_into().unwrap());
    let payload_usize =
        usize::try_from(ciphertext_len).map_err(|_| SignedHpkeError::InvalidFrameLength)?;
    if payload_usize > MAX_SIGNED_HPKE_PAYLOAD_BYTES
        || wire.len() != SIGNED_HPKE_FIXED_FRAME_BYTES + payload_usize
    {
        return Err(SignedHpkeError::InvalidFrameLength);
    }

    let mut sender_key_id = [0u8; 32];
    sender_key_id.copy_from_slice(&wire[20..52]);
    let mut recipient_key_id = [0u8; 32];
    recipient_key_id.copy_from_slice(&wire[52..84]);
    let mut t_coalesce = [0u8; 32];
    t_coalesce.copy_from_slice(&wire[84..116]);
    let sequence = u64::from_be_bytes(wire[116..124].try_into().unwrap());
    let timestamp_unix_micros = u64::from_be_bytes(wire[124..132].try_into().unwrap());
    let mut origin_sig_k1 = [0u8; 64];
    origin_sig_k1.copy_from_slice(&wire[1252..1316]);
    let mut relay_sig_k2 = [0u8; 64];
    relay_sig_k2.copy_from_slice(&wire[1316..1380]);
    let mut aead_tag = [0u8; AEAD_TAG_BYTES];
    aead_tag.copy_from_slice(&wire[1392..1408]);

    Ok(ParsedWireHeader {
        flags,
        sender_key_id,
        recipient_key_id,
        t_coalesce,
        sequence,
        timestamp_unix_micros,
        origin_sig_k1,
        relay_sig_k2,
        ciphertext_len,
        aead_tag,
    })
}

/// Verifies `CRC-32C`, timestamp window, 128-slot `ReplayWindow`, `OriginSigV1` (`K1`),
/// and `CloudRelayBlobSigV1` (`K2`) STRICTLY BEFORE running `X25519-MLKEM768` HPKE
/// decapsulation (`INV-VERIFY-BEFORE-DECRYPT-01`).
pub fn verify_and_open_signed_hpke_blob(
    wire: &[u8],
    origin_ring: &OriginKeyRing,
    relay_policy: RelaySignaturePolicy<'_>,
    recipient_xwing_secret: &[u8; 32],
    replay_window: &mut ReplayWindow,
    now_unix_micros: u64,
    max_clock_skew_micros: u64,
) -> Result<VerifiedPlaintextBlob, SignedHpkeError> {
    verify_and_open_with_decap_counter(
        wire,
        origin_ring,
        relay_policy,
        recipient_xwing_secret,
        replay_window,
        now_unix_micros,
        max_clock_skew_micros,
        None,
    )
}

/// Identical to [`verify_and_open_signed_hpke_blob`], plus an optional atomic
/// `decap_counter` incremented immediately prior to `XWing` decapsulation so
/// security tests can assert `decap_counter == 0` on every rejected unauthenticated input.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_open_with_decap_counter(
    wire: &[u8],
    origin_ring: &OriginKeyRing,
    relay_policy: RelaySignaturePolicy<'_>,
    recipient_xwing_secret: &[u8; 32],
    replay_window: &mut ReplayWindow,
    now_unix_micros: u64,
    max_clock_skew_micros: u64,
    decap_counter: Option<&AtomicUsize>,
) -> Result<VerifiedPlaintextBlob, SignedHpkeError> {
    // Stage 1: Structural & CRC-32C integrity gate (zero crypto allocations)
    let parsed = parse_and_check_crc(wire)?;

    // Stage 2: Freshness & non-mutating replay pre-check
    validate_timestamp_window(
        parsed.timestamp_unix_micros,
        now_unix_micros,
        max_clock_skew_micros,
    )?;
    replay_window.check_unseen(parsed.sequence)?;

    let ct_payload = &wire[SIGNED_HPKE_FIXED_FRAME_BYTES..];

    // Stage 3: Mandatory OriginSigV1 (K1) Ed25519 verify_strict
    let origin_vk = origin_ring
        .lookup(&parsed.sender_key_id)
        .ok_or(SignedHpkeError::UnknownOriginSigner)?;
    let k1_msg = origin_sig_k1_preimage(
        &wire[0..1252],
        parsed.ciphertext_len,
        &parsed.aead_tag,
        ct_payload,
    );
    origin_vk
        .verify_strict(&k1_msg, &Signature::from_bytes(&parsed.origin_sig_k1))
        .map_err(|_| SignedHpkeError::OriginSignatureInvalid)?;

    // Stage 4: Mandatory CloudRelayBlobSigV1 (K2) Ed25519 verify_strict on cloud relay path
    match relay_policy {
        RelaySignaturePolicy::RequireCloudK2(relay_ring) => {
            if parsed.flags != FLAG_CLOUD_RELAY_K2_SIGNED || relay_ring.is_empty() {
                return Err(SignedHpkeError::RelaySignatureInvalid);
            }
            let k2_msg = relay_sig_k2_preimage(
                &wire[0..1316],
                parsed.ciphertext_len,
                &parsed.aead_tag,
                ct_payload,
            );
            let k2_sig = Signature::from_bytes(&parsed.relay_sig_k2);
            let verified_any = relay_ring
                .verifiers
                .iter()
                .any(|vk| vk.verify_strict(&k2_msg, &k2_sig).is_ok());
            if !verified_any {
                return Err(SignedHpkeError::RelaySignatureInvalid);
            }
        }
        RelaySignaturePolicy::AllowDirectP2pK1Only => {
            if parsed.flags != FLAG_DIRECT_P2P_K1_ONLY
                || !bool::from(parsed.relay_sig_k2.ct_eq(&[0u8; 64]))
            {
                return Err(SignedHpkeError::RelaySignatureInvalid);
            }
        }
    }

    // Stage 5: Verify recipient key fingerprint before KEM decapsulation
    let sk = <XWing as KemTrait>::PrivateKey::from_bytes(recipient_xwing_secret)
        .map_err(|_| SignedHpkeError::RecipientKeyMismatch)?;
    let derived_pk = XWing::sk_to_pk(&sk).to_bytes();
    let expected_recipient_id = *blake3::hash(derived_pk.as_slice()).as_bytes();
    if !bool::from(parsed.recipient_key_id.ct_eq(&expected_recipient_id)) {
        return Err(SignedHpkeError::RecipientKeyMismatch);
    }

    // Stage 6: NOW (and only now!) invoke X25519-MLKEM768 decapsulation & ChaCha20Poly1305 open
    if let Some(counter) = decap_counter {
        counter.fetch_add(1, Ordering::SeqCst);
    }

    let enc = <XWing as KemTrait>::EncappedKey::from_bytes(&wire[132..1252])
        .map_err(|_| SignedHpkeError::HpkeCryptoFailed)?;
    let mut receiver_ctx = hpke::setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk,
        &enc,
        HPKE_KEY_SCHEDULE_INFO,
    )
    .map_err(|_| SignedHpkeError::HpkeCryptoFailed)?;

    let mut combined_ct = Vec::with_capacity(ct_payload.len() + AEAD_TAG_BYTES);
    combined_ct.extend_from_slice(ct_payload);
    combined_ct.extend_from_slice(&parsed.aead_tag);

    let plaintext = Zeroizing::new(
        receiver_ctx
            .open(&combined_ct, &wire[0..1252])
            .map_err(|_| SignedHpkeError::HpkeCryptoFailed)?,
    );

    // Commit sequence into ReplayWindow ONLY after full cryptographic authentication!
    replay_window.record_verified(parsed.sequence)?;

    Ok(VerifiedPlaintextBlob {
        sender_key_id: parsed.sender_key_id,
        recipient_key_id: parsed.recipient_key_id,
        t_coalesce: parsed.t_coalesce,
        sequence: parsed.sequence,
        timestamp_unix_micros: parsed.timestamp_unix_micros,
        flags: parsed.flags,
        plaintext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_matches_rfc3720_iscsi_known_answer_vector() {
        assert_eq!(compute_crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn signed_hpke_blob_v1_exact_1408_framing_and_blind_relay_k2_roundtrip() {
        let origin_sk = SigningKey::from_bytes(&[0x21u8; 32]);
        let relay_us_sk = SigningKey::from_bytes(&[0x31u8; 32]);
        let relay_eu_sk = SigningKey::from_bytes(&[0x32u8; 32]);
        let (recipient_sk, recipient_pk) = generate_xwing_keypair().unwrap();

        let mut origin_ring = OriginKeyRing::new();
        origin_ring
            .enroll(origin_sk.verifying_key().to_bytes())
            .unwrap();

        let mut relay_ring = RelayKeyRing::new();
        relay_ring
            .enroll(relay_us_sk.verifying_key().to_bytes())
            .unwrap();
        relay_ring
            .enroll(relay_eu_sk.verifying_key().to_bytes())
            .unwrap();

        let room_secret = [0x9au8; 32];
        let t_coalesce = derive_blinded_coalesce_tag(&room_secret, b"job-matrix-42");
        let now_micros = 1_790_000_000_000_000u64;
        let payload = b"encrypted multi-region failover capsule";

        // 1. Origin seals with K1; blind EU failover relay verifies K1 and attaches K2
        let unsigned_k2_frame = seal_for_blind_relay_transit(SealBlobParams {
            origin_signing_key_k1: &origin_sk,
            recipient_xwing_public: &recipient_pk,
            t_coalesce,
            sequence: 1,
            timestamp_unix_micros: now_micros,
            plaintext: payload,
        })
        .unwrap();
        assert_eq!(
            unsigned_k2_frame.len(),
            SIGNED_HPKE_FIXED_FRAME_BYTES + payload.len()
        );

        // If an unsigned K2 frame is injected directly onto a cloud verifier, ZERO decapsulations occur!
        let decap_calls = AtomicUsize::new(0);
        let mut replay = ReplayWindow::new();
        assert_eq!(
            verify_and_open_with_decap_counter(
                &unsigned_k2_frame,
                &origin_ring,
                RelaySignaturePolicy::RequireCloudK2(&relay_ring),
                &recipient_sk,
                &mut replay,
                now_micros,
                DEFAULT_MAX_CLOCK_SKEW_MICROS,
                Some(&decap_calls),
            ),
            Err(SignedHpkeError::RelaySignatureInvalid)
        );
        assert_eq!(decap_calls.load(Ordering::SeqCst), 0);
        // Replay window must remain untouched (`highest_seq == 0`) after failed K2 check!
        assert_eq!(replay.highest_seq(), 0);

        // 2. EU failover blind relay counter-signs K2 without possessing `recipient_sk`
        let dual_signed =
            countersign_relay_blob_k2(unsigned_k2_frame, &origin_ring, &relay_eu_sk).unwrap();

        let opened = verify_and_open_with_decap_counter(
            &dual_signed,
            &origin_ring,
            RelaySignaturePolicy::RequireCloudK2(&relay_ring),
            &recipient_sk,
            &mut replay,
            now_micros,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_calls),
        )
        .unwrap();
        assert_eq!(decap_calls.load(Ordering::SeqCst), 1);
        assert_eq!(opened.plaintext.as_slice(), payload);
        assert_eq!(opened.sequence, 1);
        assert_eq!(opened.t_coalesce, t_coalesce);
        assert_eq!(replay.highest_seq(), 1);

        // 3. Replaying the exact dual-signed packet is blocked BEFORE HPKE decapsulation!
        assert_eq!(
            verify_and_open_with_decap_counter(
                &dual_signed,
                &origin_ring,
                RelaySignaturePolicy::RequireCloudK2(&relay_ring),
                &recipient_sk,
                &mut replay,
                now_micros,
                DEFAULT_MAX_CLOCK_SKEW_MICROS,
                Some(&decap_calls),
            ),
            Err(SignedHpkeError::ReplayOrFreshness(
                FailoverError::DuplicateReplay(1)
            ))
        );
        assert_eq!(
            decap_calls.load(Ordering::SeqCst),
            1,
            "replayed frame must NEVER trigger XWing decapsulation"
        );
    }

    #[test]
    fn verify_before_decrypt_aborts_before_xwing_decap_on_tampered_ciphertext_k1_k2_or_crc() {
        let origin_sk = SigningKey::from_bytes(&[0x41u8; 32]);
        let relay_sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let (recipient_sk, recipient_pk) = generate_xwing_keypair().unwrap();

        let mut origin_ring = OriginKeyRing::new();
        origin_ring
            .enroll(origin_sk.verifying_key().to_bytes())
            .unwrap();
        let mut relay_ring = RelayKeyRing::new();
        relay_ring
            .enroll(relay_sk.verifying_key().to_bytes())
            .unwrap();

        let now_micros = 1_790_000_000_000_000u64;
        let valid_wire = seal_signed_hpke_blob_v1(
            SealBlobParams {
                origin_signing_key_k1: &origin_sk,
                recipient_xwing_public: &recipient_pk,
                t_coalesce: [0x11u8; 32],
                sequence: 7,
                timestamp_unix_micros: now_micros,
                plaintext: b"top-secret payload",
            },
            Some(&relay_sk),
        )
        .unwrap();

        let decap_calls = AtomicUsize::new(0);
        let mut replay = ReplayWindow::new();

        // Case A: Tamper 1 bit of ciphertext payload -> CRC passes (payload is past 1380),
        // K1 `OriginSigV1` catches body BLAKE3 mismatch -> 0 decapsulations!
        let mut bad_ct = valid_wire.clone();
        *bad_ct.last_mut().unwrap() ^= 0x80;
        assert_eq!(
            verify_and_open_with_decap_counter(
                &bad_ct,
                &origin_ring,
                RelaySignaturePolicy::RequireCloudK2(&relay_ring),
                &recipient_sk,
                &mut replay,
                now_micros,
                DEFAULT_MAX_CLOCK_SKEW_MICROS,
                Some(&decap_calls),
            ),
            Err(SignedHpkeError::OriginSignatureInvalid)
        );
        assert_eq!(decap_calls.load(Ordering::SeqCst), 0);

        // Case B: Tamper encapsulated_key (`132..1252`) AND recompute CRC-32C -> K1 catches it -> 0 decapsulations!
        let mut bad_enc = valid_wire.clone();
        bad_enc[200] ^= 0x01;
        let forged_crc = compute_crc32c(&bad_enc[0..1380]);
        bad_enc[1380..1384].copy_from_slice(&forged_crc.to_be_bytes());
        assert_eq!(
            verify_and_open_with_decap_counter(
                &bad_enc,
                &origin_ring,
                RelaySignaturePolicy::RequireCloudK2(&relay_ring),
                &recipient_sk,
                &mut replay,
                now_micros,
                DEFAULT_MAX_CLOCK_SKEW_MICROS,
                Some(&decap_calls),
            ),
            Err(SignedHpkeError::OriginSignatureInvalid)
        );
        assert_eq!(decap_calls.load(Ordering::SeqCst), 0);

        // Case C: Rogue relay re-signs K2 over valid K1 -> K2 ring rejects -> 0 decapsulations!
        let rogue_relay_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let rogue_wire = seal_signed_hpke_blob_v1(
            SealBlobParams {
                origin_signing_key_k1: &origin_sk,
                recipient_xwing_public: &recipient_pk,
                t_coalesce: [0x11u8; 32],
                sequence: 8,
                timestamp_unix_micros: now_micros,
                plaintext: b"rogue relay test",
            },
            Some(&rogue_relay_sk),
        )
        .unwrap();
        assert_eq!(
            verify_and_open_with_decap_counter(
                &rogue_wire,
                &origin_ring,
                RelaySignaturePolicy::RequireCloudK2(&relay_ring),
                &recipient_sk,
                &mut replay,
                now_micros,
                DEFAULT_MAX_CLOCK_SKEW_MICROS,
                Some(&decap_calls),
            ),
            Err(SignedHpkeError::RelaySignatureInvalid)
        );
        assert_eq!(decap_calls.load(Ordering::SeqCst), 0);

        // Case D: Direct P2P frame (`FLAG_DIRECT_P2P_K1_ONLY`) succeeds on `AllowDirectP2pK1Only`
        // but is strictly rejected if replayed onto `RequireCloudK2`!
        let p2p_wire = seal_signed_hpke_blob_v1(
            SealBlobParams {
                origin_signing_key_k1: &origin_sk,
                recipient_xwing_public: &recipient_pk,
                t_coalesce: [0x22u8; 32],
                sequence: 9,
                timestamp_unix_micros: now_micros,
                plaintext: b"direct lan quic frame",
            },
            None,
        )
        .unwrap();
        assert_eq!(
            verify_and_open_with_decap_counter(
                &p2p_wire,
                &origin_ring,
                RelaySignaturePolicy::RequireCloudK2(&relay_ring),
                &recipient_sk,
                &mut replay,
                now_micros,
                DEFAULT_MAX_CLOCK_SKEW_MICROS,
                Some(&decap_calls),
            ),
            Err(SignedHpkeError::RelaySignatureInvalid)
        );
        assert_eq!(decap_calls.load(Ordering::SeqCst), 0);

        let p2p_open = verify_and_open_with_decap_counter(
            &p2p_wire,
            &origin_ring,
            RelaySignaturePolicy::AllowDirectP2pK1Only,
            &recipient_sk,
            &mut replay,
            now_micros,
            DEFAULT_MAX_CLOCK_SKEW_MICROS,
            Some(&decap_calls),
        )
        .unwrap();
        assert_eq!(p2p_open.plaintext.as_slice(), b"direct lan quic frame");
        assert_eq!(decap_calls.load(Ordering::SeqCst), 1);
    }
}
