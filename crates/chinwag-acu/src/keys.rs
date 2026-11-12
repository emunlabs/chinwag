// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Self-generated BLS12-381 $\mathbb{G}_1$ seat keypairs and Schnorr Proof-of-Possession rogue-key verification.
//!
//! In Chinwag's Access Control Unit (`ACU`) pairing-based threshold encryption (with dynamic policy
//! evolution mechanics derived from ePrint 2026/1141, hardened under SXDH on `BLS12-381` for `CHWG-0271`),
//! there is no central trusted dealer. Every seat (human developer, autonomous coding agent,
//! Archive Unit, or always-on `ACU`) generates its own scalar secret $sk_i \in \mathbb{F}_r^*$ and publishes
//! $pk_{i,1} = g_1^{sk_i} \in \mathbb{G}_1^*$ together with a deterministic Fiat–Shamir Schnorr
//! Proof-of-Possession $(c_i, z_i) \in (\mathbb{F}_r^*)^2$ bound to `seat_id` and $pk_{i,1}$.
//!
//! Crucially, **no $\mathbb{G}_2$ element $g_2^{sk_i}$ is ever published**: keeping seat public keys
//! strictly in $\mathbb{G}_1$ preserves the Decisional Diffie–Hellman assumption in $\mathbb{G}_1$ (SXDH
//! on asymmetric Type-3 `BLS12-381`), preventing any passive observer from using the pairing as a
//! DDH/unmasking oracle on row ciphertexts.

use crate::AcuError;
use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Maximum UTF-8 byte length permitted for a canonical seat or key-branch identifier.
pub(crate) const MAX_SEAT_ID_BYTES: usize = 512;

const SEAT_POP_NONCE_SALT: &[u8] = b"chinwag-acu/v2/seat-pop-nonce-salt";
const SEAT_POP_NONCE_INFO: &[u8] = b"chinwag-acu/v2/seat-pop-nonce-wide";
const SEAT_POP_CHALLENGE_DOMAIN: &[u8] = b"chinwag-acu/v2/seat-pop-challenge";
const SEAT_POP_CHALLENGE_SALT: &[u8] = b"chinwag-acu/v2/seat-pop-challenge-salt";
const SEAT_POP_CHALLENGE_INFO: &[u8] = b"chinwag-acu/v2/seat-pop-challenge-wide";

/// Validate that a seat identifier is non-empty, bounded in length, and free of ASCII control characters
/// so textual/binary domain-separated preimages can never suffer newline or delimiter injection.
#[must_use]
pub(crate) fn is_valid_seat_id(seat_id: &str) -> bool {
    !seat_id.trim().is_empty()
        && seat_id.len() <= MAX_SEAT_ID_BYTES
        && !seat_id.chars().any(char::is_control)
}

/// Secret scalar key $sk_i \in \mathbb{F}_r^*$ held exclusively by a single seat or ACU.
///
/// Zeroized on drop and redacted in [`fmt::Debug`] so secret key material is never leaked
/// into logs, panic messages, or debug traces.
pub struct SeatSecretKey {
    pub(crate) seat_id: String,
    pub(crate) sk: Scalar,
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
            .finish()
    }
}

impl SeatSecretKey {
    /// Return the canonical seat identifier bound to this secret key.
    #[must_use]
    pub fn seat_id(&self) -> &str {
        &self.seat_id
    }

    /// Generate a fresh seat keypair using the provided cryptographically secure RNG.
    pub fn generate(
        seat_id: impl Into<String>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Self, SeatPublicKey), AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        let sk = sample_nonzero_scalar(rng);
        Self::from_scalar(seat_id, sk)
    }

    /// Generate a fresh seat keypair directly from the operating system CSPRNG (`OsRng`).
    pub fn generate_os_rng(seat_id: impl Into<String>) -> Result<(Self, SeatPublicKey), AcuError> {
        Self::generate(seat_id, &mut OsRng)
    }

    /// Construct a seat keypair from an explicit non-zero scalar $sk \in \mathbb{F}_r^*$,
    /// producing a deterministic Fiat–Shamir Schnorr Proof-of-Possession bound to `seat_id`.
    pub fn from_scalar(
        seat_id: impl Into<String>,
        sk: Scalar,
    ) -> Result<(Self, SeatPublicKey), AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        if bool::from(sk.is_zero()) {
            return Err(AcuError::InvalidSecretKey);
        }
        let pk1 = G1Projective::generator() * sk;
        let pk1_aff = G1Affine::from(pk1);
        let (pop_challenge, pop_response) = prove_seat_pop(&seat_id, &sk, &pk1_aff);
        let public = SeatPublicKey {
            seat_id: seat_id.clone(),
            pk1,
            pop_challenge,
            pop_response,
        };
        let secret = Self { seat_id, sk };
        Ok((secret, public))
    }
}

/// Public key material for a seat or Access Control Unit (`ACU`) in $\mathbb{G}_1$, accompanied
/// by a `seat_id`-bound Schnorr Proof-of-Possession `(pop_challenge, pop_response)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatPublicKey {
    /// Canonical identifier of the seat or key branch (e.g., `"branch:8687872"` or `"acu:98939834"`).
    pub seat_id: String,
    /// Public key component in $\mathbb{G}_1$: $pk_1 = g_1^{sk}$.
    pub pk1: G1Projective,
    /// Fiat–Shamir Schnorr proof-of-possession challenge $c \in \mathbb{F}_r^*$ bound to `seat_id` and `pk1`.
    pub pop_challenge: Scalar,
    /// Fiat–Shamir Schnorr proof-of-possession response $z = k + c \cdot sk \in \mathbb{F}_r^*$.
    pub pop_response: Scalar,
}

impl SeatPublicKey {
    /// ALISTAIR Gate: Verify that this public key is non-identity, prime-order torsion-free in $\mathbb{G}_1$,
    /// has a valid seat identifier, and carries a valid constant-time-verified Schnorr Proof-of-Possession
    /// of $sk = \log_{g_1}(pk_1)$ bound to `self.seat_id`:
    ///
    /// $$R_1 = g_1 \cdot z - pk_1 \cdot c, \qquad c \stackrel{!}{=} H_{\text{PoP}}(\text{seat\_id}, g_1, pk_1, R_1)$$
    ///
    /// Rejects any malformed, identity, torsion-subgroup, rogue, or cross-seat cloned public key.
    #[must_use]
    pub fn verify_consistency(&self) -> bool {
        if !is_valid_seat_id(&self.seat_id) {
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
        let expected_c = compute_seat_pop_challenge(&self.seat_id, &pk1_aff, &r1_aff);
        bool::from(self.pop_challenge.to_bytes().ct_eq(&expected_c.to_bytes()))
    }

    /// Serialize `(pk1, (pop_challenge, pop_response))` into canonical Zcash/IETF BLS12-381 compressed
    /// $\mathbb{G}_1$ bytes (`48` bytes) and canonical $\mathbb{F}_r$ proof-of-possession bytes (`64` bytes).
    #[must_use]
    pub fn to_compressed_bytes(&self) -> ([u8; 48], [u8; 64]) {
        let pk1_bytes = G1Affine::from(self.pk1).to_compressed();
        let mut pop_bytes = [0u8; 64];
        pop_bytes[..32].copy_from_slice(&self.pop_challenge.to_bytes());
        pop_bytes[32..].copy_from_slice(&self.pop_response.to_bytes());
        (pk1_bytes, pop_bytes)
    }

    /// Deserialize a [`SeatPublicKey`] from compressed $\mathbb{G}_1$ (`48` bytes) and Schnorr
    /// Proof-of-Possession (`64` bytes) arrays, enforcing subgroup membership and proof verification.
    pub fn from_compressed_bytes(
        seat_id: impl Into<String>,
        pk1_bytes: &[u8; 48],
        pop_bytes: &[u8; 64],
    ) -> Result<Self, AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
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
            pop_challenge,
            pop_response,
        };
        if !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id));
        }
        Ok(pk)
    }
}

fn prove_seat_pop(seat_id: &str, sk: &Scalar, pk1_aff: &G1Affine) -> (Scalar, Scalar) {
    let mut sk_bytes = Zeroizing::new(sk.to_bytes());
    let pk1_compressed = pk1_aff.to_compressed();
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 4 + seat_id.len() + 48));
    ikm.extend_from_slice(&*sk_bytes);
    sk_bytes.zeroize();
    ikm.extend_from_slice(&(seat_id.len() as u32).to_be_bytes());
    ikm.extend_from_slice(seat_id.as_bytes());
    ikm.extend_from_slice(&pk1_compressed);

    let hk = Hkdf::<Sha256>::new(Some(SEAT_POP_NONCE_SALT), &ikm);
    let g1 = G1Projective::generator();

    for ctr in 0u32.. {
        let mut info = Vec::with_capacity(SEAT_POP_NONCE_INFO.len() + 4);
        info.extend_from_slice(SEAT_POP_NONCE_INFO);
        info.extend_from_slice(&ctr.to_be_bytes());

        let mut wide = Zeroizing::new([0u8; 64]);
        hk.expand(&info, &mut *wide)
            .expect("64-byte HKDF-SHA256 output is always valid");
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
        let c = compute_seat_pop_challenge(seat_id, pk1_aff, &r1_aff);
        if bool::from(c.is_zero()) {
            k.zeroize();
            continue;
        }
        let z = k + c * *sk;
        k.zeroize();
        if !bool::from(z.is_zero()) {
            return (c, z);
        }
    }
    unreachable!("unbounded u32 counter finds valid Schnorr PoP nonce on ctr = 0 w.h.p.")
}

fn compute_seat_pop_challenge(seat_id: &str, pk1_aff: &G1Affine, r1_aff: &G1Affine) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(SEAT_POP_CHALLENGE_DOMAIN);
    hasher.update((seat_id.len() as u32).to_be_bytes());
    hasher.update(seat_id.as_bytes());
    hasher.update(G1Affine::generator().to_compressed());
    hasher.update(pk1_aff.to_compressed());
    hasher.update(r1_aff.to_compressed());
    let digest = hasher.finalize();

    let hk = Hkdf::<Sha256>::new(Some(SEAT_POP_CHALLENGE_SALT), &digest);
    let mut wide = [0u8; 64];
    hk.expand(SEAT_POP_CHALLENGE_INFO, &mut wide)
        .expect("64-byte HKDF-SHA256 output is always valid");
    Scalar::from_bytes_wide(&wide)
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
