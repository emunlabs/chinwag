// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Self-generated BLS12-381 seat keypairs and bilinear rogue-key consistency verification.
//!
//! In Chinwag's Access Control Unit (`ACU`) pairing-based encryption (with dynamic policy
//! evolution mechanics derived from ePrint 2026/1141), there is no central trusted dealer.
//! Every seat (human developer, autonomous coding agent, Archive Unit, or always-on `ACU`)
//! generates its own scalar secret $sk_i \in \mathbb{F}_r^*$ and publishes
//! $(pk_{i,1} = g_1^{sk_i} \in \mathbb{G}_1, pk_{i,2} = g_2^{sk_i} \in \mathbb{G}_2)$.
//! Before any encryptor or policy-evolution operator uses a seat's public key, it enforces
//! [`SeatPublicKey::verify_consistency`] via the bilinear check $e(pk_{i,1}, g_2) = e(g_1, pk_{i,2})$.

use crate::AcuError;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use ff::Field;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::fmt;
use zeroize::Zeroize;

/// Maximum UTF-8 byte length permitted for a canonical seat or key-branch identifier.
pub(crate) const MAX_SEAT_ID_BYTES: usize = 512;

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

    /// Construct a seat keypair from an explicit non-zero scalar $sk \in \mathbb{F}_r^*$.
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
        let pk2 = G2Projective::generator() * sk;
        let public = SeatPublicKey {
            seat_id: seat_id.clone(),
            pk1,
            pk2,
        };
        let secret = Self { seat_id, sk };
        Ok((secret, public))
    }
}

/// Public key material for a seat or Access Control Unit (`ACU`) in $\mathbb{G}_1 \times \mathbb{G}_2$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatPublicKey {
    /// Canonical identifier of the seat or key branch (e.g., `"branch:8687872"` or `"acu:98939834"`).
    pub seat_id: String,
    /// Public key component in $\mathbb{G}_1$: $pk_1 = g_1^{sk}$.
    pub pk1: G1Projective,
    /// Public key component in $\mathbb{G}_2$: $pk_2 = g_2^{sk}$.
    pub pk2: G2Projective,
}

impl SeatPublicKey {
    /// ALISTAIR Gate: Verify that this public key is non-identity, has a valid seat identifier,
    /// and satisfies the bilinear discrete-log consistency equation:
    ///
    /// $$e(pk_1, g_2) = e(g_1, pk_2)$$
    ///
    /// Rejects any malformed, identity, or rogue public key before encryption or policy update.
    #[must_use]
    pub fn verify_consistency(&self) -> bool {
        if !is_valid_seat_id(&self.seat_id) {
            return false;
        }
        if bool::from(self.pk1.is_identity()) || bool::from(self.pk2.is_identity()) {
            return false;
        }
        let lhs = pairing(&G1Affine::from(self.pk1), &G2Affine::generator());
        let rhs = pairing(&G1Affine::generator(), &G2Affine::from(self.pk2));
        lhs == rhs
    }

    /// Serialize `(pk1, pk2)` into canonical Zcash/IETF BLS12-381 compressed bytes (`48` bytes for $\mathbb{G}_1$, `96` bytes for $\mathbb{G}_2$).
    #[must_use]
    pub fn to_compressed_bytes(&self) -> ([u8; 48], [u8; 96]) {
        (
            G1Affine::from(self.pk1).to_compressed(),
            G2Affine::from(self.pk2).to_compressed(),
        )
    }

    /// Deserialize a [`SeatPublicKey`] from compressed $\mathbb{G}_1$ and $\mathbb{G}_2$ byte arrays,
    /// enforcing subgroup membership and bilinear consistency before returning.
    pub fn from_compressed_bytes(
        seat_id: impl Into<String>,
        pk1_bytes: &[u8; 48],
        pk2_bytes: &[u8; 96],
    ) -> Result<Self, AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        let pk1_aff: Option<G1Affine> = G1Affine::from_compressed(pk1_bytes).into();
        let pk2_aff: Option<G2Affine> = G2Affine::from_compressed(pk2_bytes).into();
        let (Some(pk1_aff), Some(pk2_aff)) = (pk1_aff, pk2_aff) else {
            return Err(AcuError::InvalidPublicKey(seat_id));
        };
        let pk = Self {
            seat_id: seat_id.clone(),
            pk1: G1Projective::from(pk1_aff),
            pk2: G2Projective::from(pk2_aff),
        };
        if !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id));
        }
        Ok(pk)
    }
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
