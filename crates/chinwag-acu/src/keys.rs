// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Self-generated `BLS12-381` $\mathbb{G}_1$-only seat keypairs (`48` B compressed `pk1`),
//! bundled post-quantum hybrid `0x647a` (`X25519-MLKEM768` / `XWing`) KEM keypairs (`1216` B `pq_pk`),
//! and strong Fiat–Shamir Schnorr Proof-of-Possession rogue-key verification (`ePrint v2` §4, §6.1).
//!
//! Crucially, **no $\mathbb{G}_2$ element $g_2^{sk_i}$ is ever published**: keeping classical pairing
//! public keys strictly in $\mathbb{G}_1$ preserves Decisional Diffie–Hellman in $\mathbb{G}_1$ (`SXDH`
//! on asymmetric Type-3 `BLS12-381`), while binding each seat's `1216`-byte `X25519-MLKEM768` (`0x647a`)
//! public key directly into its `seat_id`-scoped Schnorr Proof-of-Possession and validating both
//! FIPS 203 §7.2 `ML-KEM-768` encapsulation coefficients (`< 3329`) and canonical contributory
//! Curve25519 points (`< 2^255 - 19`, non-8-torsion).

use crate::AcuError;
use crate::framing::{hash_to_nonzero_scalar, lp64_str};
use bls12_381::{G1Affine, G1Projective, Scalar};
use core::convert::Infallible;
use ff::Field;
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{X25519HkdfSha256, XWing},
    rand_core::{TryCryptoRng, TryRng},
};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Maximum UTF-8 byte length permitted for a canonical seat or key-branch identifier.
pub(crate) const MAX_SEAT_ID_BYTES: usize = 512;

/// Hybrid post-quantum KEM ID (`MLKEM768-X25519` / `XWing` `0x647a`).
pub const KEM_ID_X25519_MLKEM768: u16 = 0x647a;
/// Canonical byte length of an `X25519-MLKEM768` (`0x647a`) public key (`1184` B ML-KEM-768 + `32` B X25519).
pub const XWING_PUBLIC_KEY_BYTES: usize = 1216;
/// Canonical byte length of the ML-KEM-768 public key prefix inside `XWing`.
pub const XWING_MLKEM768_PK_BYTES: usize = 1184;
/// Canonical byte length of an `X25519-MLKEM768` (`0x647a`) encapsulated key (`1088` B ML-KEM-768 + `32` B X25519).
pub const XWING_ENCAPPED_KEY_BYTES: usize = 1120;
/// Canonical byte length of the ML-KEM-768 ciphertext prefix inside `XWing`.
pub const XWING_MLKEM768_CT_BYTES: usize = 1088;
/// Canonical byte length of a `0x647a` seed (`32` B).
pub const XWING_SEED_BYTES: usize = 32;

const SEAT_POP_NONCE_SALT: &[u8] = b"chinwag-acu/v2/seat-pop-nonce-salt";
const SEAT_POP_NONCE_INFO: &[u8] = b"chinwag-acu/v2/seat-pop-nonce-wide";
const SEAT_POP_CHALLENGE_DST: &[u8] = b"chinwag.acu.v2.seat-pop-challenge";
const DET_PQ_SEED_SALT: &[u8] = b"chinwag-acu/v2/det-from-scalar-pq-seed-salt";
const DET_PQ_SEED_INFO: &[u8] = b"chinwag-acu/v2/det-from-scalar-pq-seed-info";

type XWingPrivate = <XWing as KemTrait>::PrivateKey;
type XWingPublic = <XWing as KemTrait>::PublicKey;
type XWingEncapped = <XWing as KemTrait>::EncappedKey;
type X25519Public = <X25519HkdfSha256 as KemTrait>::PublicKey;

/// Pre-sampled cursor-backed CSPRNG adapter bridging `rand_core 0.6` (`RngCore + CryptoRng`)
/// into `hpke = "=0.15.1"`'s `rand_core 0.9` (`TryRng + TryCryptoRng`), zeroizing every
/// consumed slice immediately and scrubbing any residual bytes on drop.
pub(crate) struct PreSampledEntropy<const N: usize> {
    buf: Zeroizing<[u8; N]>,
    offset: usize,
    overflowed: bool,
}

impl<const N: usize> PreSampledEntropy<N> {
    pub(crate) fn from_rng(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, AcuError> {
        let mut buf = Zeroizing::new([0u8; N]);
        rng.fill_bytes(&mut buf[..]);
        if bool::from(buf[..].ct_eq(&[0u8; N])) {
            return Err(AcuError::InvalidSecretKey);
        }
        Ok(Self {
            buf,
            offset: 0,
            overflowed: false,
        })
    }

    fn from_fixed_bytes(bytes: [u8; N]) -> Self {
        Self {
            buf: Zeroizing::new(bytes),
            offset: 0,
            overflowed: false,
        }
    }

    pub(crate) fn finish(self) -> Result<(), AcuError> {
        if self.overflowed || self.offset != N {
            return Err(AcuError::SerializationError(
                "HPKE pre-sampled entropy length mismatch",
            ));
        }
        Ok(())
    }
}

impl<const N: usize> TryRng for PreSampledEntropy<N> {
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
        let available = N.saturating_sub(self.offset);
        if self.overflowed || dst.len() > available {
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

impl<const N: usize> TryCryptoRng for PreSampledEntropy<N> {}

/// Validate a canonical `< 2^255 - 19`, contributory (non-low-order) X25519 public share.
pub(crate) fn checked_x25519_public(bytes: &[u8; 32]) -> Result<X25519Public, AcuError> {
    if bool::from(bytes[..].ct_eq(&[0u8; 32])) {
        return Err(AcuError::SerializationError("zero X25519 public share"));
    }
    let mut modulus = [0xffu8; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if bytes.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
        return Err(AcuError::SerializationError(
            "non-canonical X25519 field encoding >= 2^255 - 19",
        ));
    }
    let public = X25519Public::from_bytes(bytes)
        .map_err(|_| AcuError::SerializationError("invalid X25519 public key"))?;
    // Any clamped X25519 scalar `8 * k` has `gcd(k, ell) = 1` (`2^251 <= k < 2^252 < ell`),
    // so deterministic trial encapsulation rejects all 8-torsion points without OS RNG side effects.
    let mut det_probe = PreSampledEntropy::<32>::from_fixed_bytes([0x42u8; 32]);
    let _ = <X25519HkdfSha256 as KemTrait>::encap_with_rng(&public, None, &mut det_probe)
        .map_err(|_| AcuError::SerializationError("non-contributory low-order X25519 point"))?;
    det_probe.finish()?;
    Ok(public)
}

/// Validate a `1216`-byte `X25519-MLKEM768` (`0x647a`) public key (FIPS 203 §7.2 modulus check on
/// `[0..1184]` + canonical contributory Curve25519 check on `[1184..1216]`).
pub(crate) fn checked_xwing_public(
    bytes: &[u8; XWING_PUBLIC_KEY_BYTES],
) -> Result<XWingPublic, AcuError> {
    if bool::from(bytes[..].ct_eq(&[0u8; XWING_PUBLIC_KEY_BYTES])) {
        return Err(AcuError::SerializationError("zero XWing public key"));
    }
    let public = XWingPublic::from_bytes(&bytes[..])
        .map_err(|_| AcuError::SerializationError("invalid ML-KEM-768 / XWing public key"))?;
    let pk_x: &[u8; 32] = bytes[XWING_MLKEM768_PK_BYTES..]
        .try_into()
        .map_err(|_| AcuError::SerializationError("XWing X25519 slice mismatch"))?;
    let _ = checked_x25519_public(pk_x)?;
    Ok(public)
}

/// Validate an `1120`-byte `X25519-MLKEM768` (`0x647a`) encapsulated ciphertext (`ct_M || ct_X`).
pub(crate) fn checked_xwing_encapped(
    bytes: &[u8; XWING_ENCAPPED_KEY_BYTES],
) -> Result<XWingEncapped, AcuError> {
    let ct_x: &[u8; 32] = bytes[XWING_MLKEM768_CT_BYTES..]
        .try_into()
        .map_err(|_| AcuError::SerializationError("XWing encapped X25519 slice mismatch"))?;
    let _ = checked_x25519_public(ct_x)?;
    XWingEncapped::from_bytes(&bytes[..])
        .map_err(|_| AcuError::SerializationError("invalid XWing encapsulated key"))
}

/// Validate that a seat identifier is non-empty, bounded in length, and free of ASCII control characters
/// so domain-separated transcripts can never suffer control-character confusion.
#[must_use]
pub(crate) fn is_valid_seat_id(seat_id: &str) -> bool {
    !seat_id.trim().is_empty()
        && seat_id.len() <= MAX_SEAT_ID_BYTES
        && !seat_id.chars().any(char::is_control)
}

/// Hybrid post-quantum `X25519-MLKEM768` (`0x647a`) decapsulation key held by a seat.
///
/// Zeroized on drop and redacted in [`fmt::Debug`].
pub struct SeatPqSecretKey {
    seed: Zeroizing<[u8; XWING_SEED_BYTES]>,
    sk: Box<XWingPrivate>,
}

impl Clone for SeatPqSecretKey {
    fn clone(&self) -> Self {
        let (sk, _) = XWing::derive_keypair(&self.seed[..]);
        Self {
            seed: self.seed.clone(),
            sk: Box::new(sk),
        }
    }
}

impl fmt::Debug for SeatPqSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatPqSecretKey")
            .field("seed", &"<REDACTED>")
            .field("sk", &"<REDACTED>")
            .finish()
    }
}

impl SeatPqSecretKey {
    /// Derive an `X25519-MLKEM768` (`0x647a`) keypair from a non-zero 32-byte CSPRNG seed.
    pub fn from_seed(seed: [u8; XWING_SEED_BYTES]) -> Result<(Self, SeatPqPublicKey), AcuError> {
        if bool::from(seed[..].ct_eq(&[0u8; XWING_SEED_BYTES])) {
            return Err(AcuError::InvalidSecretKey);
        }
        let seed_box = Zeroizing::new(seed);
        let (sk, pk) = XWing::derive_keypair(&seed_box[..]);
        let mut raw_pk = Box::new([0u8; XWING_PUBLIC_KEY_BYTES]);
        raw_pk.copy_from_slice(&pk.to_bytes());
        let _ = checked_xwing_public(&raw_pk)?;
        Ok((
            Self {
                seed: seed_box,
                sk: Box::new(sk),
            },
            SeatPqPublicKey { bytes: raw_pk },
        ))
    }

    /// Open a Base-mode `0x647a` (`XWing`, `HKDF-SHA256`, `ChaCha20Poly1305`) HPKE capsule.
    pub fn open_base(
        &self,
        encapped: &[u8; XWING_ENCAPPED_KEY_BYTES],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AcuError> {
        let enc = checked_xwing_encapped(encapped)?;
        let mut receiver = hpke::setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &self.sk,
            &enc,
            info,
        )
        .map_err(|_| AcuError::AeadFailure)?;
        let pt = receiver
            .open(ciphertext, aad)
            .map_err(|_| AcuError::AeadFailure)?;
        Ok(Zeroizing::new(pt))
    }
}

/// Hybrid post-quantum `X25519-MLKEM768` (`0x647a`) encapsulation public key (`1216` bytes).
#[derive(Clone)]
pub struct SeatPqPublicKey {
    bytes: Box<[u8; XWING_PUBLIC_KEY_BYTES]>,
}

impl PartialEq for SeatPqPublicKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.bytes[..].ct_eq(&other.bytes[..]))
    }
}

impl Eq for SeatPqPublicKey {}

impl fmt::Debug for SeatPqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatPqPublicKey")
            .field("suite", &"0x647a (X25519-MLKEM768)")
            .field("len", &XWING_PUBLIC_KEY_BYTES)
            .finish()
    }
}

impl SeatPqPublicKey {
    /// Construct and validate a [`SeatPqPublicKey`] from its canonical `1216`-byte representation.
    pub fn from_bytes(bytes: &[u8; XWING_PUBLIC_KEY_BYTES]) -> Result<Self, AcuError> {
        let _ = checked_xwing_public(bytes)?;
        let mut boxed = Box::new([0u8; XWING_PUBLIC_KEY_BYTES]);
        boxed.copy_from_slice(bytes);
        Ok(Self { bytes: boxed })
    }

    /// Borrow the canonical `1216`-byte `X25519-MLKEM768` public key encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_BYTES] {
        &self.bytes
    }

    /// Validate FIPS 203 §7.2 `ML-KEM-768` modulus bounds and contributory Curve25519 membership.
    #[must_use]
    pub fn verify_consistency(&self) -> bool {
        checked_xwing_public(&self.bytes).is_ok()
    }

    /// Seal `plaintext` in Base-mode `0x647a` (`XWing`, `HKDF-SHA256`, `ChaCha20Poly1305`) HPKE.
    pub fn seal_base(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<([u8; XWING_ENCAPPED_KEY_BYTES], Vec<u8>), AcuError> {
        let pk = checked_xwing_public(&self.bytes)?;
        let mut entropy = PreSampledEntropy::<64>::from_rng(rng)?;
        let (enc, mut sender) = hpke::setup_sender_with_rng::<
            HpkeChaCha20Poly1305,
            HkdfSha256,
            XWing,
        >(&OpModeS::Base, &pk, info, &mut entropy)
        .map_err(|_| AcuError::AeadFailure)?;
        entropy.finish()?;
        let ct = sender
            .seal(plaintext, aad)
            .map_err(|_| AcuError::AeadFailure)?;
        let mut enc_bytes = [0u8; XWING_ENCAPPED_KEY_BYTES];
        enc_bytes.copy_from_slice(&enc.to_bytes());
        Ok((enc_bytes, ct))
    }
}

/// Secret key bundle held exclusively by a single seat, Archive Unit, or ACU:
/// - Classical pairing scalar $sk_i \in \mathbb{F}_r^*$ (`BLS12-381` $\mathbb{G}_1$-only public key), and
/// - Independent post-quantum hybrid `0x647a` (`X25519-MLKEM768`) decapsulation key (`pq_sk`).
///
/// Zeroized on drop and redacted in [`fmt::Debug`].
pub struct SeatSecretKey {
    pub(crate) seat_id: String,
    pub(crate) sk: Scalar,
    pub(crate) pq_sk: SeatPqSecretKey,
}

impl Drop for SeatSecretKey {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

impl fmt::Debug for SeatSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatSecretKey")
            .field("seat_id", &self.seat_id)
            .field("sk", &"<REDACTED>")
            .field("pq_sk", &"<REDACTED>")
            .finish()
    }
}

impl SeatSecretKey {
    /// Return the canonical seat identifier bound to this secret key.
    #[must_use]
    pub fn seat_id(&self) -> &str {
        &self.seat_id
    }

    /// Borrow this seat's hybrid post-quantum `0x647a` (`X25519-MLKEM768`) decapsulation key.
    #[must_use]
    pub fn pq_secret_key(&self) -> &SeatPqSecretKey {
        &self.pq_sk
    }

    /// Generate a fresh seat keypair with **independent** CSPRNG entropy for $sk \in \mathbb{F}_r^*$
    /// and the `0x647a` (`X25519-MLKEM768`) seed so quantum compromise of `BLS12-381` reveals `0` bits
    /// about `pq_sk`.
    pub fn generate(
        seat_id: impl Into<String>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, SeatPublicKey), AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        let sk = sample_nonzero_scalar(rng);
        let mut pq_seed = Zeroizing::new([0u8; XWING_SEED_BYTES]);
        loop {
            rng.fill_bytes(&mut pq_seed[..]);
            if !bool::from(pq_seed[..].ct_eq(&[0u8; XWING_SEED_BYTES])) {
                break;
            }
        }
        Self::from_scalar_and_pq_seed(seat_id, sk, *pq_seed)
    }

    /// Generate a fresh seat keypair directly from the operating system CSPRNG (`OsRng`).
    pub fn generate_os_rng(seat_id: impl Into<String>) -> Result<(Self, SeatPublicKey), AcuError> {
        Self::generate(seat_id, &mut OsRng)
    }

    /// Construct a seat keypair from explicit independent $sk \in \mathbb{F}_r^*$ and `0x647a` seed.
    pub fn from_scalar_and_pq_seed(
        seat_id: impl Into<String>,
        mut sk: Scalar,
        pq_seed: [u8; XWING_SEED_BYTES],
    ) -> Result<(Self, SeatPublicKey), AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            sk.zeroize();
            return Err(AcuError::InvalidSeatId);
        }
        if bool::from(sk.is_zero()) {
            return Err(AcuError::InvalidSecretKey);
        }
        let (pq_sk, pq_pk) = match SeatPqSecretKey::from_seed(pq_seed) {
            Ok(pair) => pair,
            Err(err) => {
                sk.zeroize();
                return Err(err);
            }
        };
        let pk1 = G1Projective::generator() * sk;
        let pk1_aff = G1Affine::from(pk1);
        let (pop_challenge, pop_response) = prove_seat_pop(&seat_id, &sk, &pk1_aff, &pq_pk)?;
        let public = SeatPublicKey {
            seat_id: seat_id.clone(),
            pk1,
            pq_pk,
            pop_challenge,
            pop_response,
        };
        let secret = Self { seat_id, sk, pq_sk };
        Ok((secret, public))
    }

    /// Deterministic constructor from an explicit non-zero scalar $sk \in \mathbb{F}_r^*$
    /// (deriving a deterministic test `0x647a` seed via domain-separated HKDF when an independent
    /// seed is not supplied; production callers MUST prefer [`SeatSecretKey::generate`]).
    pub fn from_scalar(
        seat_id: impl Into<String>,
        mut sk: Scalar,
    ) -> Result<(Self, SeatPublicKey), AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            sk.zeroize();
            return Err(AcuError::InvalidSeatId);
        }
        if bool::from(sk.is_zero()) {
            return Err(AcuError::InvalidSecretKey);
        }
        let sk_bytes = Zeroizing::new(sk.to_bytes());
        let mut ikm = Zeroizing::new(Vec::with_capacity(40 + seat_id.len()));
        ikm.extend_from_slice(&*sk_bytes);
        lp64_str(&mut ikm, &seat_id);
        let hk = Hkdf::<Sha256>::new(Some(DET_PQ_SEED_SALT), &ikm);
        let mut pq_seed = Zeroizing::new([0u8; XWING_SEED_BYTES]);
        hk.expand(DET_PQ_SEED_INFO, &mut pq_seed[..])
            .map_err(|_| AcuError::InvalidSecretKey)?;
        if bool::from(pq_seed[..].ct_eq(&[0u8; XWING_SEED_BYTES])) {
            pq_seed[0] = 1;
        }
        Self::from_scalar_and_pq_seed(seat_id, sk, *pq_seed)
    }
}

/// Public key material for a seat or Access Control Unit (`ACU`):
/// - `48`-byte compressed `BLS12-381` $\mathbb{G}_1$ key $pk_1 = sk \cdot G_1$ (zero $\mathbb{G}_2$ elements),
/// - `1216`-byte `X25519-MLKEM768` (`0x647a`) hybrid post-quantum public key `pq_pk`, and
/// - `64`-byte strong Fiat–Shamir Schnorr Proof-of-Possession `(pop_challenge, pop_response)`
///   binding `(seat_id, G_1, pk_1, pq_pk, R_1)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatPublicKey {
    /// Canonical identifier of the seat or key branch (e.g., `"branch:8687872"` or `"acu:98939834"`).
    pub seat_id: String,
    /// Public key component in $\mathbb{G}_1$: $pk_1 = sk \cdot G_1$ (never in $\mathbb{G}_2$).
    pub pk1: G1Projective,
    /// Bundled `1216`-byte `X25519-MLKEM768` (`0x647a`) hybrid post-quantum encapsulation key.
    pub pq_pk: SeatPqPublicKey,
    /// Strong Fiat–Shamir Schnorr proof-of-possession challenge $c \in \mathbb{F}_r^*$ bound to `(seat_id, pk1, pq_pk)`.
    pub pop_challenge: Scalar,
    /// Strong Fiat–Shamir Schnorr proof-of-possession response $z = k + c \cdot sk \in \mathbb{F}_r^*$.
    pub pop_response: Scalar,
}

impl SeatPublicKey {
    /// ALISTAIR Gate: Verify that:
    /// 1. `seat_id` is well-formed (`<= 512` bytes, non-empty, control-free),
    /// 2. `pk1` is non-identity and prime-$r$ torsion-free in $\mathbb{G}_1$ (`Lim–Lee` subgroup gate),
    /// 3. `pq_pk` passes FIPS 203 §7.2 `ML-KEM-768` modulus validation and contributory Curve25519 validation, and
    /// 4. `(pop_challenge, pop_response)` satisfies the constant-time strong Fiat–Shamir Schnorr PoP
    ///    binding `(seat_id, G_1, pk_1, pq_pk, R_1)`.
    #[must_use]
    pub fn verify_consistency(&self) -> bool {
        if !is_valid_seat_id(&self.seat_id) || !self.pq_pk.verify_consistency() {
            return false;
        }
        let pk1_aff = G1Affine::from(self.pk1);
        if bool::from(pk1_aff.is_identity())
            || !bool::from(pk1_aff.is_torsion_free())
            || bool::from(self.pop_challenge.is_zero())
            || bool::from(self.pop_response.is_zero())
        {
            return false;
        }
        let r1 = G1Projective::generator() * self.pop_response - self.pk1 * self.pop_challenge;
        let r1_aff = G1Affine::from(r1);
        if bool::from(r1_aff.is_identity()) {
            return false;
        }
        let Ok(expected_c) =
            compute_seat_pop_challenge(&self.seat_id, &pk1_aff, &self.pq_pk, &r1_aff)
        else {
            return false;
        };
        bool::from(self.pop_challenge.to_bytes().ct_eq(&expected_c.to_bytes()))
    }

    /// Serialize `(pk1, pq_pk, (pop_challenge, pop_response))` into canonical compressed $\mathbb{G}_1$
    /// (`48` B), `0x647a` `XWing` (`1216` B), and Schnorr PoP (`64` B) byte arrays.
    #[must_use]
    pub fn to_wire_bytes(&self) -> ([u8; 48], [u8; XWING_PUBLIC_KEY_BYTES], [u8; 64]) {
        let (pk1_bytes, pop_bytes) = self.to_compressed_bytes();
        let mut pq_bytes = [0u8; XWING_PUBLIC_KEY_BYTES];
        pq_bytes.copy_from_slice(self.pq_pk.as_bytes());
        (pk1_bytes, pq_bytes, pop_bytes)
    }

    /// Serialize `(pk1, (pop_challenge, pop_response))` into compressed $\mathbb{G}_1$ (`48` B)
    /// and Schnorr PoP (`64` B) arrays.
    #[must_use]
    pub fn to_compressed_bytes(&self) -> ([u8; 48], [u8; 64]) {
        let pk1_bytes = G1Affine::from(self.pk1).to_compressed();
        let mut pop_bytes = [0u8; 64];
        pop_bytes[..32].copy_from_slice(&self.pop_challenge.to_bytes());
        pop_bytes[32..].copy_from_slice(&self.pop_response.to_bytes());
        (pk1_bytes, pop_bytes)
    }

    /// Deserialize a [`SeatPublicKey`] from compressed $\mathbb{G}_1$ (`48` B), `0x647a` `XWing`
    /// (`1216` B), and Schnorr Proof-of-Possession (`64` B) arrays, enforcing subgroup, FIPS 203,
    /// Curve25519, and PoP verification.
    pub fn from_wire_bytes(
        seat_id: impl Into<String>,
        pk1_bytes: &[u8; 48],
        pq_pk_bytes: &[u8; XWING_PUBLIC_KEY_BYTES],
        pop_bytes: &[u8; 64],
    ) -> Result<Self, AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        let pq_pk = SeatPqPublicKey::from_bytes(pq_pk_bytes)
            .map_err(|_| AcuError::InvalidPublicKey(seat_id.clone()))?;
        let pk1_aff: Option<G1Affine> = G1Affine::from_compressed(pk1_bytes).into();
        let mut c_arr = [0u8; 32];
        let mut z_arr = [0u8; 32];
        c_arr.copy_from_slice(&pop_bytes[..32]);
        z_arr.copy_from_slice(&pop_bytes[32..]);
        let pop_challenge: Option<Scalar> = Scalar::from_bytes(&c_arr).into();
        let pop_response: Option<Scalar> = Scalar::from_bytes(&z_arr).into();
        let (Some(pk1_aff), Some(pop_challenge), Some(pop_response)) =
            (pk1_aff, pop_challenge, pop_response)
        else {
            return Err(AcuError::InvalidPublicKey(seat_id));
        };
        let pk = Self {
            seat_id: seat_id.clone(),
            pk1: G1Projective::from(pk1_aff),
            pq_pk,
            pop_challenge,
            pop_response,
        };
        if !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id));
        }
        Ok(pk)
    }
}

fn prove_seat_pop(
    seat_id: &str,
    sk: &Scalar,
    pk1_aff: &G1Affine,
    pq_pk: &SeatPqPublicKey,
) -> Result<(Scalar, Scalar), AcuError> {
    let mut sk_bytes = Zeroizing::new(sk.to_bytes());
    let pk1_compressed = pk1_aff.to_compressed();
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        32 + 8 + seat_id.len() + 48 + XWING_PUBLIC_KEY_BYTES,
    ));
    ikm.extend_from_slice(&*sk_bytes);
    sk_bytes.zeroize();
    lp64_str(&mut ikm, seat_id);
    ikm.extend_from_slice(&pk1_compressed);
    ikm.extend_from_slice(pq_pk.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(SEAT_POP_NONCE_SALT), &ikm);
    let g1 = G1Projective::generator();

    for ctr in 0u32.. {
        let mut info = Vec::with_capacity(SEAT_POP_NONCE_INFO.len() + 4);
        info.extend_from_slice(SEAT_POP_NONCE_INFO);
        info.extend_from_slice(&ctr.to_be_bytes());

        let mut wide = Zeroizing::new([0u8; 64]);
        hk.expand(&info, &mut *wide)
            .map_err(|_| AcuError::InvalidSecretKey)?;
        let mut k = Scalar::from_bytes_wide(&wide);
        wide.zeroize();
        if bool::from(k.is_zero()) {
            continue;
        }
        let r1_aff = G1Affine::from(g1 * k);
        if bool::from(r1_aff.is_identity()) {
            k.zeroize();
            continue;
        }
        let c = compute_seat_pop_challenge(seat_id, pk1_aff, pq_pk, &r1_aff)?;
        let z = k + c * *sk;
        k.zeroize();
        if !bool::from(z.is_zero()) {
            return Ok((c, z));
        }
    }
    unreachable!("unbounded u32 counter finds valid Schnorr PoP nonce on ctr = 0 w.h.p.")
}

fn compute_seat_pop_challenge(
    seat_id: &str,
    pk1_aff: &G1Affine,
    pq_pk: &SeatPqPublicKey,
    r1_aff: &G1Affine,
) -> Result<Scalar, AcuError> {
    let mut msg = Vec::with_capacity(8 + seat_id.len() + 48 * 3 + XWING_PUBLIC_KEY_BYTES);
    lp64_str(&mut msg, seat_id);
    msg.extend_from_slice(&G1Affine::generator().to_compressed());
    msg.extend_from_slice(&pk1_aff.to_compressed());
    msg.extend_from_slice(pq_pk.as_bytes());
    msg.extend_from_slice(&r1_aff.to_compressed());
    hash_to_nonzero_scalar(&msg, SEAT_POP_CHALLENGE_DST)
}

/// Sample a uniformly random non-zero scalar from $\mathbb{F}_r^*$.
pub(crate) fn sample_nonzero_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Scalar {
    loop {
        let candidate = Scalar::random(&mut *rng);
        if !bool::from(candidate.is_zero()) {
            return candidate;
        }
    }
}
