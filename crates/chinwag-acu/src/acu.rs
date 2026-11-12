// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Pairing-based Access Control Unit (`ACU`) core encryption, partial decryption, Chaum–Pedersen
//! DLEQ share verification across $(\mathbb{G}_1, \mathbb{G}_T)$, combiner, deterministic `CHWGACU2`
//! binary serialization with ACU-sealed basis commitments + row randomness scalars, and all 4 dynamic
//! policy evolution operations (`insert_key`, `insert_sibling_key`, `escalate_threshold`, and
//! `revoke_and_rerandomize`).
//!
//! Dynamic policy evolution mechanics are derived from the pairing-based DASTE paper:
//! *Decentralized Ad-Hoc Access-Structured Threshold Encryption with Dynamic Policy Evolution*
//! (ePrint 2026/1141), hardened under SXDH on `BLS12-381` for Chinwag (`CHWG-0271`):
//! 1. **Zero $\mathbb{G}_2$ Secret-Key / Row-Randomness Leakage (`[P0-R2-1]` Fix):**
//!    Seat public keys (`pk_1 = g_1^{sk}`) and row ciphertexts `(c_1 = g_1^{\lambda_j} + pk_1^{r_j}, c_3 = g_1^{r_j})`
//!    live strictly in $\mathbb{G}_1$, preserving Decisional Diffie–Hellman in $\mathbb{G}_1$ so no passive
//!    observer can use the pairing as an unmasking oracle.
//! 2. **Chaum–Pedersen NIZK DLEQ Share Verification across $(\mathbb{G}_1, \mathbb{G}_T)$:**
//!    Each partial decryption share $D_j = e(c_{j,1} - c_{j,3} \cdot sk_j, g_2) = e(g_1, g_2)^{\lambda_j} \in \mathbb{G}_T$
//!    carries a Fiat–Shamir Chaum–Pedersen DLEQ proof $(c, z)$ proving
//!    $\log_{g_1}(pk_{j,1}) = \log_{e(c_{j,3}, g_2)}(e(c_{j,1}, g_2) - D_j)$ without exposing $g_2^{sk_j}$
//!    or cleartext basis commitments.
//! 3. **ACU-Sealed Basis Commitments & Algebraic Row Witnesses (`[P1-R2-2]` Fix):**
//!    Both $V_0, \dots, V_{k-1} \in \mathbb{G}_1^k$ (including $V_0 = g_1^s$) and cumulative row
//!    randomness scalars $r_0, \dots, r_{\ell-1} \in (\mathbb{F}_r^*)^\ell$ are sealed exclusively under
//!    `pk_ACU` via ephemeral `BLS12-381` $\mathbb{G}_1$ KEM + `HKDF-SHA256` + `ChaCha20-Poly1305` with
//!    injective binary AAD and verified algebraically against `ct.rows` on every unseal.

use crate::AcuError;
use crate::keys::{
    MAX_SEAT_ID_BYTES, SeatPublicKey, SeatSecretKey, is_valid_seat_id, sample_nonzero_scalar,
};
use crate::lsss::{
    LsssMatrix, MAX_SERIALIZED_COLS, MAX_SERIALIZED_ROWS, find_reconstruction_weights,
    submatrix_rank,
};
use bls12_381::{G1Affine, G1Projective, G2Affine, Gt, Scalar, pairing};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ff::Field;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const LEGACY_ACU_CT_MAGIC: &[u8; 8] = b"CHWGACU1";
const ACU_CT_MAGIC: &[u8; 8] = b"CHWGACU2";
const BASIS_SEAL_HKDF_SALT: &[u8] = b"chinwag-acu/v2/basis-seal-hkdf-salt";
const BASIS_SEAL_HKDF_INFO: &[u8] = b"chinwag-acu/v2/basis-seal-chacha20poly1305-key";
const BASIS_SEAL_AAD_DOMAIN: &[u8] = b"chinwag-acu/v2/basis-seal-aad";

const DLEQ_NONCE_SALT: &[u8] = b"chinwag-acu/v2/partial-share-dleq-nonce-salt";
const DLEQ_NONCE_INFO: &[u8] = b"chinwag-acu/v2/partial-share-dleq-nonce-wide";
const DLEQ_CHALLENGE_DOMAIN: &[u8] = b"chinwag-acu/v2/partial-share-dleq-challenge";
const DLEQ_CHALLENGE_SALT: &[u8] = b"chinwag-acu/v2/partial-share-dleq-challenge-salt";
const DLEQ_CHALLENGE_INFO: &[u8] = b"chinwag-acu/v2/partial-share-dleq-challenge-wide";

const G1_COMPRESSED_BYTES: usize = 48;
const SCALAR_BYTES: usize = 32;
const POLY1305_TAG_BYTES: usize = 16;

/// RAII wrapper zeroizing transient $\mathbb{G}_1$ basis commitments and $\mathbb{F}_r$ row scalars on drop.
struct UnsealedBasisState {
    basis: Vec<G1Projective>,
    row_scalars: Vec<Scalar>,
}

impl Drop for UnsealedBasisState {
    fn drop(&mut self) {
        for elem in &mut self.basis {
            elem.zeroize();
        }
        for scalar in &mut self.row_scalars {
            scalar.zeroize();
        }
    }
}

/// Basis commitments $V_0, \dots, V_{k-1} \in \mathbb{G}_1^k$ (where $V_0 = g_1^s$) and cumulative
/// row randomness scalars $r_0, \dots, r_{\ell-1} \in (\mathbb{F}_r^*)^\ell$ encrypted exclusively
/// to the ACU operator's BLS12-381 $\mathbb{G}_1$ public key (`pk_ACU`) via ephemeral `BLS12-381`
/// $\mathbb{G}_1$ KEM + `HKDF-SHA256` + `ChaCha20-Poly1305`.
///
/// Bound via injective binary AAD to `policy_epoch`, `acu_seat_id`, `cols`, `num_rows`, `c0_g1`,
/// and the full LSSS matrix and row ciphertexts, and algebraically verified against `ct.rows` upon
/// unsealing so untrusted relays, storage buckets, and unauthorized seats never observe cleartext
/// $V_0 = g_1^s$ and cannot forge synthetic cut-and-paste ciphertexts against `CisoAcuFatClient`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBasisCommitments {
    /// Canonical seat identifier of the ACU operator whose `pk_ACU` seals these commitments.
    pub acu_seat_id: String,
    /// Ephemeral KEM encapsulation point $E_{\text{kem}} = g_1^{r_{\text{kem}}} \in \mathbb{G}_1$.
    pub ephemeral_pk1: G1Projective,
    /// 96-bit ChaCha20-Poly1305 nonce.
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 ciphertext + 16-byte Poly1305 tag encrypting $48 \cdot k + 32 \cdot \ell$ bytes.
    pub ciphertext: Vec<u8>,
}

/// A single row of an [`AcuCiphertext`] bound to recipient seat `seat_id` in $\mathbb{G}_1$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextRow {
    /// Zero-based row index inside [`AcuCiphertext::rows`].
    pub row_index: usize,
    /// Seat or branch identifier $\rho(j)$ (e.g., `"branch:8687872"` or `"acu:98939834"`).
    pub seat_id: String,
    /// LSSS matrix row vector $M_j \in \mathbb{F}_r^k$.
    pub matrix_row: Vec<Scalar>,
    /// Share ciphertext component $c_{j,1} = g_1^{\lambda_j} + pk_{\rho(j),1}^{r_j} \in \mathbb{G}_1$.
    pub c1: G1Projective,
    /// Ephemeral randomness component $c_{j,3} = g_1^{r_j} \in \mathbb{G}_1^*$.
    pub c3: G1Projective,
}

/// Pairing-based ACU header ciphertext (`CHWGACU2`) supporting in-place dynamic policy evolution
/// by the ACU operator without decrypting $c_0$ or exposing cleartext basis commitments $V_m = g_1^{v_m}$
/// or $\mathbb{G}_2$ blinding witnesses on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcuCiphertext {
    /// Monotonically increasing policy epoch counter (starts at `1` upon initial encryption).
    pub policy_epoch: u64,
    /// Masked $\mathbb{G}_1$ preimage $c_{0,\mathbb{G}_1} = K_{\mathbb{G}_1} + g_1^s \in \mathbb{G}_1$
    /// such that $c_0 = e(c_{0,\mathbb{G}_1}, g_2) = K + e(g_1, g_2)^s \in \mathbb{G}_T$.
    /// Serializes canonically in 48 compressed bytes (`G1Affine::to_compressed`).
    pub c0_g1: G1Projective,
    /// Masked target-group payload key $c_0 = K + e(g_1, g_2)^s \in \mathbb{G}_T$.
    pub c0: Gt,
    /// Basis commitments $V_0, \dots, V_{k-1} \in \mathbb{G}_1^k$ and row scalars $r_0, \dots, r_{\ell-1}$
    /// sealed exclusively under `pk_ACU`.
    pub sealed_basis: SealedBasisCommitments,
    /// Current LSSS policy matrix $(M, \rho)$ over $\mathbb{F}_r$.
    pub matrix: LsssMatrix,
    /// Per-row ciphertext components matching `matrix.rows`.
    pub rows: Vec<CiphertextRow>,
}

impl AcuCiphertext {
    /// Validate full in-memory structural equivalence between `self.matrix` and `self.rows`.
    pub fn validate_structure(&self) -> Result<(), AcuError> {
        self.matrix.validate()?;
        if self.rows.len() != self.matrix.rows.len() {
            return Err(AcuError::DimensionMismatch {
                expected: self.matrix.rows.len(),
                actual: self.rows.len(),
            });
        }
        for (expected_idx, (row, (mat_seat, mat_vec))) in
            self.rows.iter().zip(self.matrix.rows.iter()).enumerate()
        {
            if row.row_index != expected_idx || row.seat_id != *mat_seat {
                return Err(AcuError::SerializationError(
                    "AcuCiphertext rows/matrix seat or index mismatch",
                ));
            }
            if row.matrix_row != *mat_vec {
                return Err(AcuError::DimensionMismatch {
                    expected: mat_vec.len(),
                    actual: row.matrix_row.len(),
                });
            }
        }
        Ok(())
    }

    /// Serialize this [`AcuCiphertext`] into a deterministic, self-framing binary format
    /// (`CHWGACU2`) using canonical Zcash/IETF compressed BLS12-381 $\mathbb{G}_1$ points (`48` bytes),
    /// `32`-byte little-endian $\mathbb{F}_r$ scalars, and ACU-sealed basis commitments + row scalars.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ACU_CT_MAGIC);
        out.extend_from_slice(&self.policy_epoch.to_be_bytes());
        out.extend_from_slice(&(self.matrix.cols as u32).to_be_bytes());
        out.extend_from_slice(&(self.rows.len() as u32).to_be_bytes());
        out.extend_from_slice(&G1Affine::from(self.c0_g1).to_compressed());

        let acu_seat_bytes = self.sealed_basis.acu_seat_id.as_bytes();
        out.extend_from_slice(&(acu_seat_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(acu_seat_bytes);
        out.extend_from_slice(&G1Affine::from(self.sealed_basis.ephemeral_pk1).to_compressed());
        out.extend_from_slice(&self.sealed_basis.nonce);
        out.extend_from_slice(&(self.sealed_basis.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.sealed_basis.ciphertext);

        for row in &self.rows {
            out.extend_from_slice(&(row.row_index as u32).to_be_bytes());
            let seat_bytes = row.seat_id.as_bytes();
            out.extend_from_slice(&(seat_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(seat_bytes);
            for scalar in &row.matrix_row {
                out.extend_from_slice(&scalar.to_bytes());
            }
            out.extend_from_slice(&G1Affine::from(row.c1).to_compressed());
            out.extend_from_slice(&G1Affine::from(row.c3).to_compressed());
        }
        out
    }

    /// Deserialize an [`AcuCiphertext`] from its canonical `CHWGACU2` binary representation,
    /// failing closed on legacy insecure `CHWGACU1` wire blobs, curve subgroup violations,
    /// identity points, non-canonical scalars, or structural mismatches.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AcuError> {
        let mut cursor = 0usize;
        let magic = take_slice(bytes, &mut cursor, 8)?;
        if magic == LEGACY_ACU_CT_MAGIC {
            return Err(AcuError::InsecureLegacyFormat("CHWGACU1"));
        }
        if magic != ACU_CT_MAGIC {
            return Err(AcuError::SerializationError("invalid AcuCiphertext magic"));
        }
        let policy_epoch = read_u64_be(bytes, &mut cursor)?;
        if policy_epoch == 0 {
            return Err(AcuError::SerializationError("policy_epoch must be >= 1"));
        }
        let cols = read_u32_be(bytes, &mut cursor)? as usize;
        let num_rows = read_u32_be(bytes, &mut cursor)? as usize;
        if cols == 0
            || cols > MAX_SERIALIZED_COLS
            || num_rows == 0
            || num_rows > MAX_SERIALIZED_ROWS
        {
            return Err(AcuError::SerializationError(
                "invalid AcuCiphertext dimensions",
            ));
        }

        let c0_g1 = read_nonidentity_g1_compressed(bytes, &mut cursor)?;
        let c0 = pairing(&G1Affine::from(c0_g1), &G2Affine::generator());

        let acu_seat_len = read_u32_be(bytes, &mut cursor)? as usize;
        if acu_seat_len == 0 || acu_seat_len > MAX_SEAT_ID_BYTES {
            return Err(AcuError::SerializationError("invalid acu_seat_id length"));
        }
        let acu_seat_slice = take_slice(bytes, &mut cursor, acu_seat_len)?;
        let acu_seat_id = std::str::from_utf8(acu_seat_slice)
            .map_err(|_| AcuError::SerializationError("acu_seat_id is not valid UTF-8"))?
            .to_string();
        if !is_valid_seat_id(&acu_seat_id) {
            return Err(AcuError::InvalidSeatId);
        }

        let ephemeral_pk1 = read_nonidentity_g1_compressed(bytes, &mut cursor)?;
        let nonce_slice = take_slice(bytes, &mut cursor, 12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_slice);

        let expected_sealed_len = expected_sealed_basis_len(cols, num_rows)?;
        let sealed_ct_len = read_u32_be(bytes, &mut cursor)? as usize;
        if sealed_ct_len != expected_sealed_len {
            return Err(AcuError::SerializationError(
                "invalid sealed_basis ciphertext length",
            ));
        }
        let sealed_ciphertext = take_slice(bytes, &mut cursor, sealed_ct_len)?.to_vec();
        let sealed_basis = SealedBasisCommitments {
            acu_seat_id,
            ephemeral_pk1,
            nonce,
            ciphertext: sealed_ciphertext,
        };

        let mut rows = Vec::with_capacity(num_rows);
        let mut matrix_rows = Vec::with_capacity(num_rows);
        for expected_idx in 0..num_rows {
            let row_index = read_u32_be(bytes, &mut cursor)? as usize;
            if row_index != expected_idx {
                return Err(AcuError::SerializationError("non-contiguous row_index"));
            }
            let seat_len = read_u32_be(bytes, &mut cursor)? as usize;
            if seat_len == 0 || seat_len > MAX_SEAT_ID_BYTES {
                return Err(AcuError::SerializationError("invalid seat_id length"));
            }
            let seat_slice = take_slice(bytes, &mut cursor, seat_len)?;
            let seat_id = std::str::from_utf8(seat_slice)
                .map_err(|_| AcuError::SerializationError("seat_id is not valid UTF-8"))?
                .to_string();
            if !is_valid_seat_id(&seat_id) {
                return Err(AcuError::InvalidSeatId);
            }

            let mut matrix_row = Vec::with_capacity(cols);
            for _ in 0..cols {
                matrix_row.push(read_scalar(bytes, &mut cursor)?);
            }
            let c1 = read_g1_compressed(bytes, &mut cursor)?;
            let c3 = read_nonidentity_g1_compressed(bytes, &mut cursor)?;

            matrix_rows.push((seat_id.clone(), matrix_row.clone()));
            rows.push(CiphertextRow {
                row_index,
                seat_id,
                matrix_row,
                c1,
                c3,
            });
        }

        if cursor != bytes.len() {
            return Err(AcuError::SerializationError(
                "trailing bytes in AcuCiphertext",
            ));
        }

        let matrix = LsssMatrix {
            cols,
            rows: matrix_rows,
        };
        matrix.validate()?;

        Ok(Self {
            policy_epoch,
            c0_g1,
            c0,
            sealed_basis,
            matrix,
            rows,
        })
    }
}

/// Partial decryption share $D_j = e(g_1, g_2)^{\lambda_j} \in \mathbb{G}_T$ emitted by seat $\rho(j)$,
/// accompanied by a Chaum–Pedersen NIZK DLEQ proof across $(\mathbb{G}_1, \mathbb{G}_T)$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialDecryptionShare {
    /// Row index $j$ in [`AcuCiphertext::rows`] that this partial share decrypts.
    pub row_index: usize,
    /// Seat identifier $\rho(j)$ that produced this share.
    pub seat_id: String,
    /// Policy epoch of the ciphertext when this share was computed (`>= 1`).
    pub policy_epoch: u64,
    /// Unblinded pairing share $D_j = e(c_{j,1} - c_{j,3} \cdot sk_j, g_2) = e(g_1, g_2)^{\lambda_j} \in \mathbb{G}_T$.
    pub value: Gt,
    /// Chaum–Pedersen DLEQ Fiat–Shamir challenge $c \in \mathbb{F}_r^*$.
    pub dleq_challenge: Scalar,
    /// Chaum–Pedersen DLEQ response $z = k + c \cdot sk_j \in \mathbb{F}_r^*$.
    pub dleq_response: Scalar,
}

/// Sample a fresh target-group secret $K = e(K_{\mathbb{G}_1}, g_2) \in \mathbb{G}_T$ and encrypt it
/// under `matrix` and `seat_keys`, sealing the basis commitments $V_0, \dots, V_{k-1}$ and row scalars
/// exclusively under `acu_pk` (`CHWGACU2`).
pub fn acu_encrypt(
    matrix: &LsssMatrix,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    acu_pk: &SeatPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(AcuCiphertext, Gt), AcuError> {
    let mut k_scalar = sample_nonzero_scalar(rng);
    let mut payload_g1 = G1Projective::generator() * k_scalar;
    k_scalar.zeroize();
    let res = acu_encrypt_with_g1(&payload_g1, matrix, seat_keys, acu_pk, rng);
    payload_g1.zeroize();
    res
}

/// Encrypt a target-group element $K = e(K_{\mathbb{G}_1}, g_2) \in \mathbb{G}_T$ (given its
/// non-identity $\mathbb{G}_1$ preimage `payload_g1`) under an [`LsssMatrix`] and a directory of
/// verified [`SeatPublicKey`]s, sealing the basis commitments $V_0, \dots, V_{k-1} \in \mathbb{G}_1^k$
/// and row randomness scalars $r_0, \dots, r_{\ell-1} \in (\mathbb{F}_r^*)^\ell$ exclusively under
/// `acu_pk` (`CHWGACU2`).
///
/// Every referenced [`SeatPublicKey`] and `acu_pk` is verified via [`SeatPublicKey::verify_consistency`]
/// before encryption proceeds; any missing, malformed, or rogue key fails closed.
pub fn acu_encrypt_with_g1(
    payload_g1: &G1Projective,
    matrix: &LsssMatrix,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    acu_pk: &SeatPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(AcuCiphertext, Gt), AcuError> {
    matrix.validate()?;
    let payload_aff = G1Affine::from(*payload_g1);
    if bool::from(payload_aff.is_identity()) || !bool::from(payload_aff.is_torsion_free()) {
        return Err(AcuError::InvalidSecretKey);
    }
    if !acu_pk.verify_consistency() {
        return Err(AcuError::InvalidPublicKey(acu_pk.seat_id.clone()));
    }
    if let Some(dir_acu_pk) = seat_keys.get(&acu_pk.seat_id)
        && dir_acu_pk != acu_pk
    {
        return Err(AcuError::InvalidPublicKey(acu_pk.seat_id.clone()));
    }

    // Pre-verify every recipient seat's Schnorr Proof-of-Possession (ALISTAIR rogue-key gate).
    for (seat_id, _) in &matrix.rows {
        let pk = seat_keys
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.clone()))?;
        if pk.seat_id != *seat_id || !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id.clone()));
        }
    }

    let g1 = G1Projective::generator();
    let g2_aff = G2Affine::generator();

    // Sample secret column vector v = (s, v_1, ..., v_{k-1}) in (F_r^*)^k ensuring c0_g1 != O.
    let k = matrix.cols;
    let mut v = Zeroizing::new(Vec::with_capacity(k));
    let (s, c0_g1) = loop {
        let candidate_s = sample_nonzero_scalar(rng);
        let candidate_c0_g1 = *payload_g1 + g1 * candidate_s;
        if !bool::from(candidate_c0_g1.is_identity()) {
            break (candidate_s, candidate_c0_g1);
        }
    };
    v.push(s);
    for _ in 1..k {
        v.push(sample_nonzero_scalar(rng));
    }

    let payload_key = pairing(&payload_aff, &g2_aff);
    let c0 = pairing(&G1Affine::from(c0_g1), &g2_aff);

    // Transient basis commitments V_m = g1^(v_m) and row scalars r_j (zeroized automatically on drop).
    let mut unsealed_state = UnsealedBasisState {
        basis: v.iter().map(|vm| g1 * vm).collect(),
        row_scalars: Vec::with_capacity(matrix.rows.len()),
    };

    // Construct per-row ciphertexts strictly in G1
    let mut rows = Vec::with_capacity(matrix.rows.len());
    for (row_index, (seat_id, matrix_row)) in matrix.rows.iter().enumerate() {
        let pk = &seat_keys[seat_id];
        let mut lambda_j = inner_product(matrix_row, &v);
        let r_j = sample_nonzero_scalar(rng);

        let c1 = g1 * lambda_j + pk.pk1 * r_j;
        let c3 = g1 * r_j;

        lambda_j.zeroize();
        unsealed_state.row_scalars.push(r_j);

        rows.push(CiphertextRow {
            row_index,
            seat_id: seat_id.clone(),
            matrix_row: matrix_row.clone(),
            c1,
            c3,
        });
    }
    v.zeroize();

    let policy_epoch = 1u64;
    let sealed_basis = seal_basis_commitments(
        &unsealed_state.basis,
        &unsealed_state.row_scalars,
        &acu_pk.seat_id,
        &acu_pk.pk1,
        policy_epoch,
        &c0_g1,
        &rows,
        rng,
    )?;

    Ok((
        AcuCiphertext {
            policy_epoch,
            c0_g1,
            c0,
            sealed_basis,
            matrix: matrix.clone(),
            rows,
        },
        payload_key,
    ))
}

/// **Dynamic Policy Operation 1 — Semantically Neutral Key Insertion (`insert_key`)**:
///
/// Executed exclusively by the ACU operator holding `acu_sk`:
/// 1. Unseals `({V_m}, {r_j})` from `ct.sealed_basis` (verifying AAD binding, `acu_sk`, and algebraic row witnesses).
/// 2. Evaluates $g_1^{\lambda_{\text{new}}} = \sum_{m=0}^{k-1} V_m \cdot r_{\text{new},m}$ homomorphically
///    in $\mathbb{G}_1$ without decrypting $c_0$.
/// 3. Blinds with fresh row randomness $r_{\text{new}} \xleftarrow{\$} \mathbb{F}_r^*$, appends the row,
///    and re-seals `({V_m}, {r_j})` under `pk_ACU` with fresh randomness at `policy_epoch + 1`.
pub fn insert_key(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    new_seat: &SeatPublicKey,
    new_row: Vec<Scalar>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<usize, AcuError> {
    ct.validate_structure()?;
    let mut state = unseal_basis_commitments(ct, acu_sk)?;

    if new_row.len() != ct.matrix.cols {
        return Err(AcuError::DimensionMismatch {
            expected: ct.matrix.cols,
            actual: new_row.len(),
        });
    }
    if new_row.iter().all(|s| bool::from(s.is_zero())) {
        return Err(AcuError::InvalidAccessTree("LSSS row cannot be all zero"));
    }
    if !new_seat.verify_consistency() {
        return Err(AcuError::InvalidPublicKey(new_seat.seat_id.clone()));
    }

    let mut g1_lambda_new = commit_row_in_g1(&state.basis, &new_row);

    let g1 = G1Projective::generator();
    let r_new = sample_nonzero_scalar(rng);

    let c1 = g1_lambda_new + new_seat.pk1 * r_new;
    let c3 = g1 * r_new;
    g1_lambda_new.zeroize();

    let row_index = ct.rows.len();
    if row_index >= MAX_SERIALIZED_ROWS {
        return Err(AcuError::SerializationError(
            "invalid AcuCiphertext dimensions",
        ));
    }
    let new_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;

    let mut new_rows = ct.rows.clone();
    new_rows.push(CiphertextRow {
        row_index,
        seat_id: new_seat.seat_id.clone(),
        matrix_row: new_row.clone(),
        c1,
        c3,
    });
    state.row_scalars.push(r_new);

    let mut acu_pk1 = g1 * acu_sk.sk;
    let re_sealed_res = seal_basis_commitments(
        &state.basis,
        &state.row_scalars,
        &ct.sealed_basis.acu_seat_id,
        &acu_pk1,
        new_epoch,
        &ct.c0_g1,
        &new_rows,
        rng,
    );
    acu_pk1.zeroize();
    let new_sealed_basis = re_sealed_res?;

    ct.matrix.rows.push((new_seat.seat_id.clone(), new_row));
    ct.rows = new_rows;
    ct.sealed_basis = new_sealed_basis;
    ct.policy_epoch = new_epoch;

    Ok(row_index)
}

/// Convenience helper for Shadow-KV warm-forking: unseals `ct.sealed_basis` with `acu_sk`,
/// inserts `new_seat` as a disjunctive (`OR`) sibling of `sibling_row_index`, and re-seals
/// `basis_commitments` and `row_scalars` with fresh randomness at `policy_epoch + 1`.
pub fn insert_sibling_key(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    sibling_row_index: usize,
    new_seat: &SeatPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<usize, AcuError> {
    if sibling_row_index >= ct.rows.len() {
        return Err(AcuError::RowIndexOutOfBounds {
            index: sibling_row_index,
            total_rows: ct.rows.len(),
        });
    }
    let sibling_row = ct.rows[sibling_row_index].matrix_row.clone();
    insert_key(ct, acu_sk, new_seat, sibling_row, rng)
}

/// **Dynamic Policy Operation 2 — Threshold Escalation (`escalate_threshold`)**:
///
/// Executed exclusively by the ACU operator holding `acu_sk` without decrypting $c_0$:
/// 1. Unseals `({V_m}, {r_j})` from `ct.sealed_basis`, verifies algebraic row commitments across all
///    rows against `seat_keys`, and extracts each affected row's exact Vandermonde abscissa $x_j \in \mathbb{F}_r^*$
///    (preserving true abscissas even if intermediate siblings were pruned in an earlier revocation).
/// 2. Samples $\Delta t$ fresh non-zero column secrets $u_1, \dots, u_{\Delta t} \xleftarrow{\$} \mathbb{F}_r^*$,
///    extends affected rows with $x_j^t, \dots, x_j^{t + \Delta t - 1}$, and zero-pads unaffected rows.
/// 3. Rotates $c_{0,\mathbb{G}_1}$, $c_0$, $\{V_m'\}$, and **all** rows (affected and unaffected) by a fresh
///    blinding delta $\Delta v = (\Delta s, \Delta v_1, \dots, \Delta v_{\text{new\_cols}-1}) \in (\mathbb{F}_r^*)^{\text{new\_cols}}$
///    and non-canceling row randomness $r'_j$ (`r_j + r'_j != 0`), then re-seals `({V_m'}, {r_j'})` under
///    `pk_ACU` with fresh randomness at `policy_epoch + 1`.
pub fn escalate_threshold(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    affected_row_indices: &[usize],
    delta_t: usize,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    ct.validate_structure()?;
    let mut state = unseal_basis_commitments(ct, acu_sk)?;

    if delta_t == 0 {
        return Err(AcuError::InvalidThreshold {
            threshold: 0,
            children: affected_row_indices.len(),
        });
    }
    if affected_row_indices.is_empty() {
        return Err(AcuError::InvalidThreshold {
            threshold: delta_t,
            children: 0,
        });
    }

    let mut affected_set = BTreeSet::new();
    for &idx in affected_row_indices {
        if idx >= ct.rows.len() {
            return Err(AcuError::RowIndexOutOfBounds {
                index: idx,
                total_rows: ct.rows.len(),
            });
        }
        affected_set.insert(idx);
    }

    let unique_affected: Vec<usize> = affected_set.iter().copied().collect();
    let current_rank = submatrix_rank(&ct.matrix, &unique_affected);
    if current_rank == 0 {
        return Err(AcuError::InvalidAccessTree("affected rows have zero rank"));
    }
    if current_rank + delta_t > unique_affected.len() {
        return Err(AcuError::InvalidThreshold {
            threshold: current_rank + delta_t,
            children: unique_affected.len(),
        });
    }

    // Extract and algebraically verify each affected row's Vandermonde abscissa x_j in F_r^*.
    let first_row = &ct.rows[unique_affected[0]].matrix_row;
    let mut diff_cols = Vec::new();
    let mut has_nonzero_parent = false;
    for (col, &first_val) in first_row.iter().enumerate().take(ct.matrix.cols) {
        let all_equal = unique_affected[1..]
            .iter()
            .all(|&r_idx| ct.rows[r_idx].matrix_row[col] == first_val);
        if all_equal {
            if !bool::from(first_val.is_zero()) {
                has_nonzero_parent = true;
            }
        } else {
            diff_cols.push(col);
        }
    }
    if !has_nonzero_parent {
        return Err(AcuError::InvalidAccessTree(
            "affected rows do not share a non-zero parent label",
        ));
    }

    let mut abscissa_by_row: BTreeMap<usize, Scalar> = BTreeMap::new();
    if current_rank == 1 {
        if !diff_cols.is_empty() {
            return Err(AcuError::InvalidAccessTree(
                "rank-1 affected rows do not share an identical OR parent vector",
            ));
        }
        for (pos, &r_idx) in unique_affected.iter().enumerate() {
            abscissa_by_row.insert(r_idx, Scalar::from((pos + 1) as u64));
        }
    } else {
        if diff_cols.len() != current_rank - 1 {
            return Err(AcuError::InvalidAccessTree(
                "affected rows do not form a valid sibling threshold gate",
            ));
        }
        for (r_idx, row) in ct.rows.iter().enumerate() {
            if !affected_set.contains(&r_idx)
                && diff_cols
                    .iter()
                    .any(|&c| !bool::from(row.matrix_row[c].is_zero()))
            {
                return Err(AcuError::InvalidAccessTree(
                    "affected_row_indices omits sibling rows of the target threshold gate",
                ));
            }
        }
        let degree_one_col = diff_cols[0];
        let mut seen_x: BTreeSet<[u8; 32]> = BTreeSet::new();
        for &r_idx in &unique_affected {
            let x_j = ct.rows[r_idx].matrix_row[degree_one_col];
            if bool::from(x_j.is_zero()) || !seen_x.insert(x_j.to_bytes()) {
                return Err(AcuError::InvalidAccessTree(
                    "affected threshold rows lack distinct non-zero Vandermonde abscissas",
                ));
            }
            for (deg_offset, &col_idx) in diff_cols.iter().enumerate() {
                let expected_pow = scalar_pow(x_j, (deg_offset + 1) as u64);
                if ct.rows[r_idx].matrix_row[col_idx] != expected_pow {
                    return Err(AcuError::InvalidAccessTree(
                        "affected rows violate Vandermonde threshold structure",
                    ));
                }
            }
            abscissa_by_row.insert(r_idx, x_j);
        }
    }

    let new_cols = ct
        .matrix
        .cols
        .checked_add(delta_t)
        .filter(|&c| c <= MAX_SERIALIZED_COLS)
        .ok_or(AcuError::SerializationError(
            "invalid AcuCiphertext dimensions",
        ))?;

    // Verify public keys and algebraic row commitments for ALL rows in `ct.rows`.
    for (row, &r_j) in ct.rows.iter().zip(state.row_scalars.iter()) {
        let pk = seat_keys
            .get(&row.seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(row.seat_id.clone()))?;
        if pk.seat_id != row.seat_id || !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(row.seat_id.clone()));
        }
        let mut expected_c1 = commit_row_in_g1(&state.basis, &row.matrix_row) + pk.pk1 * r_j;
        let matches = expected_c1 == row.c1;
        expected_c1.zeroize();
        if !matches {
            return Err(AcuError::BasisUnsealFailed);
        }
    }

    let g1 = G1Projective::generator();
    let g2_aff = G2Affine::generator();

    // Sample delta_t fresh column secrets u_1..u_{delta_t} and extend state.basis.
    let mut u = Zeroizing::new(Vec::with_capacity(delta_t));
    for _ in 0..delta_t {
        let u_m = sample_nonzero_scalar(rng);
        state.basis.push(g1 * u_m);
        u.push(u_m);
    }

    let mut new_matrix = ct.matrix.clone();
    let mut new_rows = ct.rows.clone();

    let base_exp = current_rank;
    for (row_idx, (new_row, (_, new_mat_row))) in new_rows
        .iter_mut()
        .zip(new_matrix.rows.iter_mut())
        .enumerate()
    {
        if let Some(&x_j) = abscissa_by_row.get(&row_idx) {
            let mut x_pow = scalar_pow(x_j, base_exp as u64);
            let mut delta_lambda = Scalar::ZERO;

            for m in 0..delta_t {
                new_mat_row.push(x_pow);
                new_row.matrix_row.push(x_pow);
                delta_lambda += u[m] * x_pow;
                x_pow *= x_j;
            }

            new_row.c1 += g1 * delta_lambda;
            delta_lambda.zeroize();
        } else {
            for _ in 0..delta_t {
                new_mat_row.push(Scalar::ZERO);
                new_row.matrix_row.push(Scalar::ZERO);
            }
        }
    }
    u.zeroize();
    new_matrix.cols = new_cols;

    // Rotate c0_g1, c0, state.basis[0..new_cols], and ALL rows by fresh blinding delta_v
    // so new-epoch shares (e.g. D_ACU) cannot be downgraded onto cached prior-epoch ciphertexts.
    let mut delta_v = Zeroizing::new(Vec::with_capacity(new_cols));
    let (delta_s, new_c0_g1) = loop {
        let candidate_ds = sample_nonzero_scalar(rng);
        let candidate_c0_g1 = ct.c0_g1 + g1 * candidate_ds;
        let candidate_v0 = state.basis[0] + g1 * candidate_ds;
        if !bool::from(candidate_c0_g1.is_identity()) && !bool::from(candidate_v0.is_identity()) {
            break (candidate_ds, candidate_c0_g1);
        }
    };
    delta_v.push(delta_s);
    state.basis[0] += g1 * delta_s;

    for vm in state.basis.iter_mut().skip(1) {
        let dv_m = loop {
            let candidate = sample_nonzero_scalar(rng);
            if !bool::from((*vm + g1 * candidate).is_identity()) {
                break candidate;
            }
        };
        *vm += g1 * dv_m;
        delta_v.push(dv_m);
    }

    let new_c0 = pairing(&G1Affine::from(new_c0_g1), &g2_aff);

    for (row, r_j) in new_rows.iter_mut().zip(state.row_scalars.iter_mut()) {
        let pk = &seat_keys[&row.seat_id];
        let mut rot_lambda = inner_product(&row.matrix_row, &delta_v);
        let mut r_prime = loop {
            let candidate = sample_nonzero_scalar(rng);
            if !bool::from((*r_j + candidate).is_zero()) {
                break candidate;
            }
        };

        row.c1 += g1 * rot_lambda + pk.pk1 * r_prime;
        row.c3 += g1 * r_prime;
        *r_j += r_prime;

        rot_lambda.zeroize();
        r_prime.zeroize();
    }
    delta_v.zeroize();

    let new_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;

    let mut acu_pk1 = g1 * acu_sk.sk;
    let re_sealed_res = seal_basis_commitments(
        &state.basis,
        &state.row_scalars,
        &ct.sealed_basis.acu_seat_id,
        &acu_pk1,
        new_epoch,
        &new_c0_g1,
        &new_rows,
        rng,
    );
    acu_pk1.zeroize();
    let new_sealed_basis = re_sealed_res?;

    ct.c0_g1 = new_c0_g1;
    ct.c0 = new_c0;
    ct.matrix = new_matrix;
    ct.rows = new_rows;
    ct.sealed_basis = new_sealed_basis;
    ct.policy_epoch = new_epoch;
    Ok(())
}

/// **Dynamic Policy Operation 3 & 4 — Subtree Revocation + Ciphertext Rerandomization (`revoke_and_rerandomize`)**:
///
/// Executed exclusively by the ACU operator holding `acu_sk`:
/// 1. Unseals `({V_m}, {r_j})` from `ct.sealed_basis`.
/// 2. Prunes all rows matching `revoked_seat_ids`, re-indexes surviving rows, and verifies algebraic
///    commitments for all surviving rows against `seat_keys`.
/// 3. Samples a fresh blinding vector $\Delta v = (\Delta s, \Delta v_1, \dots, \Delta v_{k-1}) \in (\mathbb{F}_r^*)^k$.
/// 4. Rotates $c_{0,\mathbb{G}_1} \mathrel{+}= g_1 \cdot \Delta s$, $c_0 = e(c_{0,\mathbb{G}_1}', g_2)$,
///    and $V_m' = V_m + g_1 \cdot \Delta v_m$.
/// 5. Shifts every surviving row $j$ by $\Delta \lambda_j = \langle M_j, \Delta v \rangle$ and non-canceling $r'_j$,
///    then re-seals `({V_m'}, {r_j'})` under `pk_ACU` with fresh randomness at `policy_epoch + 1`.
pub fn revoke_and_rerandomize(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    revoked_seat_ids: &[&str],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    ct.validate_structure()?;
    let mut state = unseal_basis_commitments(ct, acu_sk)?;

    let revoked_set: BTreeSet<&str> = revoked_seat_ids.iter().copied().collect();

    // Retain only non-revoked rows and their corresponding cumulative row scalars.
    let mut surviving_rows = Vec::new();
    let mut surviving_matrix_rows = Vec::new();
    let mut surviving_scalars = Zeroizing::new(Vec::new());
    for (row, &r_j) in ct.rows.iter().zip(state.row_scalars.iter()) {
        if !revoked_set.contains(row.seat_id.as_str()) {
            let mut cloned = row.clone();
            cloned.row_index = surviving_rows.len();
            surviving_matrix_rows.push((cloned.seat_id.clone(), cloned.matrix_row.clone()));
            surviving_rows.push(cloned);
            surviving_scalars.push(r_j);
        }
    }

    if surviving_rows.is_empty() {
        return Err(AcuError::EmptyPolicy);
    }

    // Verify all surviving seats have valid public keys in `seat_keys` and match the unsealed commitments.
    for (row, &r_j) in surviving_rows.iter().zip(surviving_scalars.iter()) {
        let pk = seat_keys
            .get(&row.seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(row.seat_id.clone()))?;
        if pk.seat_id != row.seat_id || !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(row.seat_id.clone()));
        }
        let mut expected_c1 = commit_row_in_g1(&state.basis, &row.matrix_row) + pk.pk1 * r_j;
        let matches = expected_c1 == row.c1;
        expected_c1.zeroize();
        if !matches {
            return Err(AcuError::BasisUnsealFailed);
        }
    }

    let g1 = G1Projective::generator();
    let g2_aff = G2Affine::generator();
    let k = ct.matrix.cols;

    // Sample fresh blinding delta vector delta_v = (delta_s, delta_v1, ..., delta_v_{k-1}),
    // ensuring rotated c0_g1 and rotated V_m' are non-identity.
    let mut delta_v = Zeroizing::new(Vec::with_capacity(k));
    let (delta_s, new_c0_g1) = loop {
        let candidate_ds = sample_nonzero_scalar(rng);
        let candidate_c0_g1 = ct.c0_g1 + g1 * candidate_ds;
        let candidate_v0 = state.basis[0] + g1 * candidate_ds;
        if !bool::from(candidate_c0_g1.is_identity()) && !bool::from(candidate_v0.is_identity()) {
            break (candidate_ds, candidate_c0_g1);
        }
    };
    delta_v.push(delta_s);
    state.basis[0] += g1 * delta_s;

    for vm in state.basis.iter_mut().skip(1) {
        let dv_m = loop {
            let candidate = sample_nonzero_scalar(rng);
            if !bool::from((*vm + g1 * candidate).is_identity()) {
                break candidate;
            }
        };
        *vm += g1 * dv_m;
        delta_v.push(dv_m);
    }

    let new_c0 = pairing(&G1Affine::from(new_c0_g1), &g2_aff);

    // Rerandomize all surviving rows with delta_lambda_j = <M_j, delta_v> and non-canceling r'_j.
    for (row, r_j) in surviving_rows.iter_mut().zip(surviving_scalars.iter_mut()) {
        let pk = &seat_keys[&row.seat_id];
        let mut delta_lambda = inner_product(&row.matrix_row, &delta_v);
        let mut r_prime = loop {
            let candidate = sample_nonzero_scalar(rng);
            if !bool::from((*r_j + candidate).is_zero()) {
                break candidate;
            }
        };

        row.c1 += g1 * delta_lambda + pk.pk1 * r_prime;
        row.c3 += g1 * r_prime;
        *r_j += r_prime;

        delta_lambda.zeroize();
        r_prime.zeroize();
    }
    delta_v.zeroize();

    let new_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;

    let mut acu_pk1 = g1 * acu_sk.sk;
    let re_sealed_res = seal_basis_commitments(
        &state.basis,
        &surviving_scalars,
        &ct.sealed_basis.acu_seat_id,
        &acu_pk1,
        new_epoch,
        &new_c0_g1,
        &surviving_rows,
        rng,
    );
    acu_pk1.zeroize();
    let new_sealed_basis = re_sealed_res?;

    ct.c0_g1 = new_c0_g1;
    ct.c0 = new_c0;
    ct.matrix.rows = surviving_matrix_rows;
    ct.rows = surviving_rows;
    ct.sealed_basis = new_sealed_basis;
    ct.policy_epoch = new_epoch;
    Ok(())
}

/// Compute a partial decryption share $D_j \in \mathbb{G}_T$ with its Chaum–Pedersen DLEQ proof for
/// `ct.rows[row_index]` bound to `ct.policy_epoch` using seat secret key `sk`:
///
/// $$D_j = e(c_{j,1} - c_{j,3} \cdot sk, g_2) = e(g_1, g_2)^{\lambda_j}$$
pub fn acu_partial_decrypt(
    ct: &AcuCiphertext,
    row_index: usize,
    sk: &SeatSecretKey,
) -> Result<PartialDecryptionShare, AcuError> {
    let row = ct
        .rows
        .get(row_index)
        .ok_or(AcuError::RowIndexOutOfBounds {
            index: row_index,
            total_rows: ct.rows.len(),
        })?;
    Ok(acu_partial_decrypt_at_epoch(row, sk, ct.policy_epoch))
}

/// Compute a partial decryption share $D_j \in \mathbb{G}_T$ and Chaum–Pedersen NIZK DLEQ proof
/// bound to a specific `policy_epoch`.
#[must_use]
pub fn acu_partial_decrypt_at_epoch(
    row: &CiphertextRow,
    sk: &SeatSecretKey,
    policy_epoch: u64,
) -> PartialDecryptionShare {
    let g2_aff = G2Affine::generator();
    let mut unmasked_g1 = row.c1 - row.c3 * sk.sk;
    let value = pairing(&G1Affine::from(unmasked_g1), &g2_aff);
    unmasked_g1.zeroize();

    let mut pk1_proj = G1Projective::generator() * sk.sk;
    let pk1_aff = G1Affine::from(pk1_proj);
    pk1_proj.zeroize();

    let c1_aff = G1Affine::from(row.c1);
    let c3_aff = G1Affine::from(row.c3);
    let b_t = pairing(&c3_aff, &g2_aff);
    let y_t = pairing(&c1_aff, &g2_aff) - value;

    let (dleq_challenge, dleq_response) = prove_partial_share_dleq(
        row.row_index,
        &row.seat_id,
        policy_epoch,
        &sk.sk,
        &pk1_aff,
        &c1_aff,
        &c3_aff,
        &value,
        &b_t,
        &y_t,
    );

    PartialDecryptionShare {
        row_index: row.row_index,
        seat_id: row.seat_id.clone(),
        policy_epoch,
        value,
        dleq_challenge,
        dleq_response,
    }
}

/// Verify that a [`PartialDecryptionShare`] $D_j$ is well-formed with respect to `row` and `pk`:
/// 1. Checks `policy_epoch >= 1`, `row.row_index == share.row_index`,
///    `row.seat_id == share.seat_id == pk.seat_id`, [`verify_row_randomness_witness`], and
///    [`SeatPublicKey::verify_consistency`].
/// 2. Verifies the Chaum–Pedersen NIZK DLEQ proof $(c, z)$ across $(\mathbb{G}_1, \mathbb{G}_T)$ proving:
///
/// $$\log_{g_1}(pk_{\rho(j),1}) = \log_{e(c_{j,3}, g_2)}\!\big(e(c_{j,1}, g_2) - D_j\big)$$
///
/// Because $c_{j,1} = g_1^{\lambda_j} + pk_{\rho(j),1}^{r_j}$ and $c_{j,3} = g_1^{r_j} \in \mathbb{G}_1^*$,
/// special soundness of DLEQ uniquely pins $D_j = e(g_1, g_2)^{\lambda_j}$ for `row`'s current epoch
/// **without exposing $g_2^{sk_j}$ or cleartext `basis_commitments`**.
#[must_use]
pub fn acu_verify_partial_share(
    row: &CiphertextRow,
    pk: &SeatPublicKey,
    share: &PartialDecryptionShare,
) -> bool {
    if share.policy_epoch == 0
        || row.row_index != share.row_index
        || row.seat_id != share.seat_id
        || row.seat_id != pk.seat_id
    {
        return false;
    }
    if !verify_row_randomness_witness(row) || !pk.verify_consistency() {
        return false;
    }
    if bool::from(share.dleq_challenge.is_zero()) || bool::from(share.dleq_response.is_zero()) {
        return false;
    }

    let g2_aff = G2Affine::generator();
    let pk1_aff = G1Affine::from(pk.pk1);
    let c1_aff = G1Affine::from(row.c1);
    let c3_aff = G1Affine::from(row.c3);

    let b_t = pairing(&c3_aff, &g2_aff);
    if b_t == Gt::identity() {
        return false;
    }
    let y_t = pairing(&c1_aff, &g2_aff) - share.value;

    let r1 = G1Projective::generator() * share.dleq_response - pk.pk1 * share.dleq_challenge;
    let r1_aff = G1Affine::from(r1);
    let r_t = b_t * share.dleq_response - y_t * share.dleq_challenge;
    if bool::from(r1_aff.is_identity()) || r_t == Gt::identity() {
        return false;
    }

    let expected_c = compute_partial_share_dleq_challenge(
        share.row_index,
        &share.seat_id,
        share.policy_epoch,
        &pk1_aff,
        &c1_aff,
        &c3_aff,
        &share.value,
        &b_t,
        &y_t,
        &r1_aff,
        &r_t,
    );
    bool::from(
        share
            .dleq_challenge
            .to_bytes()
            .ct_eq(&expected_c.to_bytes()),
    )
}

/// Check that a [`CiphertextRow`]'s $\mathbb{G}_1$ components `(c1, c3)` and LSSS row vector
/// are structurally valid, prime-order torsion-free, and have non-identity `c3`.
#[must_use]
pub fn verify_row_randomness_witness(row: &CiphertextRow) -> bool {
    if !is_valid_seat_id(&row.seat_id)
        || row.matrix_row.is_empty()
        || row.matrix_row.len() > MAX_SERIALIZED_COLS
        || row.matrix_row.iter().all(|s| bool::from(s.is_zero()))
    {
        return false;
    }
    let c1_aff = G1Affine::from(row.c1);
    let c3_aff = G1Affine::from(row.c3);
    !bool::from(c3_aff.is_identity())
        && bool::from(c1_aff.is_torsion_free())
        && bool::from(c3_aff.is_torsion_free())
}

/// Combine a set of [`PartialDecryptionShare`]s for `ct` using exact LSSS Gaussian elimination
/// weights $\{\omega_j\}_{j \in S}$ to recover the target-group key $K \in \mathbb{G}_T$:
///
/// $$K = c_0 - \sum_{j \in S} \omega_j D_j$$
///
/// Strictly verifies every contributed share via `policy_epoch`, row/seat binding, and
/// [`acu_verify_partial_share`] against `seat_keys` (requiring zero cleartext `basis_commitments`),
/// so stale shares from prior epochs (`D_old` before `revoke_and_rerandomize`) or corrupted
/// shares fail closed immediately.
pub fn acu_combine(
    ct: &AcuCiphertext,
    shares: &[PartialDecryptionShare],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
) -> Result<Gt, AcuError> {
    combine_inner(ct, shares, Some(seat_keys))
}

/// Perform pure LSSS linear combination $K = c_0 - \sum_{j \in S} \omega_j D_j$ enforcing
/// `policy_epoch` and row/seat binding without DLEQ-verifying individual shares upfront
/// (used in tests to prove that even if share verification is skipped, stale epoch-1 shares
/// cannot cancel the rotated $c_0^{(2)}$ blinding factor and fail ChaCha20-Poly1305 AEAD authentication).
pub fn acu_combine_unverified(
    ct: &AcuCiphertext,
    shares: &[PartialDecryptionShare],
) -> Result<Gt, AcuError> {
    combine_inner(ct, shares, None)
}

fn combine_inner(
    ct: &AcuCiphertext,
    shares: &[PartialDecryptionShare],
    seat_keys_opt: Option<&BTreeMap<String, SeatPublicKey>>,
) -> Result<Gt, AcuError> {
    ct.validate_structure()?;
    if ct.policy_epoch == 0 {
        return Err(AcuError::SerializationError("policy_epoch must be >= 1"));
    }
    let expected_sealed_len = expected_sealed_basis_len(ct.matrix.cols, ct.rows.len())?;
    if ct.sealed_basis.ciphertext.len() != expected_sealed_len {
        return Err(AcuError::SerializationError(
            "invalid sealed_basis ciphertext length",
        ));
    }

    let mut share_by_row: BTreeMap<usize, &PartialDecryptionShare> = BTreeMap::new();
    let mut available_indices = Vec::new();

    for share in shares {
        if share.policy_epoch != ct.policy_epoch {
            return Err(AcuError::EpochMismatch {
                expected: ct.policy_epoch,
                actual: share.policy_epoch,
            });
        }
        let Some(row) = ct.rows.get(share.row_index) else {
            return Err(AcuError::InvalidPartialShare {
                row_index: share.row_index,
                seat_id: share.seat_id.clone(),
            });
        };
        if row.seat_id != share.seat_id {
            return Err(AcuError::InvalidPartialShare {
                row_index: share.row_index,
                seat_id: share.seat_id.clone(),
            });
        }
        if let Some(seat_keys) = seat_keys_opt {
            let pk = seat_keys
                .get(&row.seat_id)
                .ok_or_else(|| AcuError::UnknownSeat(row.seat_id.clone()))?;
            if !acu_verify_partial_share(row, pk, share) {
                return Err(AcuError::InvalidPartialShare {
                    row_index: share.row_index,
                    seat_id: share.seat_id.clone(),
                });
            }
        }
        match share_by_row.entry(share.row_index) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(share);
                available_indices.push(share.row_index);
            }
            std::collections::btree_map::Entry::Occupied(existing) => {
                let prev = existing.get();
                if prev.value != share.value
                    || prev.dleq_challenge != share.dleq_challenge
                    || prev.dleq_response != share.dleq_response
                {
                    return Err(AcuError::InvalidPartialShare {
                        row_index: share.row_index,
                        seat_id: share.seat_id.clone(),
                    });
                }
            }
        }
    }

    let weights = find_reconstruction_weights(&ct.matrix, &available_indices)?;
    let mut blinding_gt = Gt::identity();
    for (row_idx, omega_j) in weights {
        let share = share_by_row[&row_idx];
        blinding_gt += share.value * omega_j;
    }

    Ok(ct.c0 - blinding_gt)
}

#[allow(clippy::too_many_arguments)]
fn prove_partial_share_dleq(
    row_index: usize,
    seat_id: &str,
    policy_epoch: u64,
    sk: &Scalar,
    pk1_aff: &G1Affine,
    c1_aff: &G1Affine,
    c3_aff: &G1Affine,
    value: &Gt,
    b_t: &Gt,
    y_t: &Gt,
) -> (Scalar, Scalar) {
    if bool::from(c3_aff.is_identity()) || *b_t == Gt::identity() || policy_epoch == 0 {
        return (Scalar::ZERO, Scalar::ZERO);
    }

    let mut sk_bytes = Zeroizing::new(sk.to_bytes());
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 8 + 4 + 4 + seat_id.len() + 48 * 3));
    ikm.extend_from_slice(&*sk_bytes);
    sk_bytes.zeroize();
    ikm.extend_from_slice(&policy_epoch.to_be_bytes());
    ikm.extend_from_slice(&(row_index as u32).to_be_bytes());
    ikm.extend_from_slice(&(seat_id.len() as u32).to_be_bytes());
    ikm.extend_from_slice(seat_id.as_bytes());
    ikm.extend_from_slice(&pk1_aff.to_compressed());
    ikm.extend_from_slice(&c1_aff.to_compressed());
    ikm.extend_from_slice(&c3_aff.to_compressed());

    let hk = Hkdf::<Sha256>::new(Some(DLEQ_NONCE_SALT), &ikm);
    let g1 = G1Projective::generator();

    for ctr in 0u32.. {
        let mut info = Vec::with_capacity(DLEQ_NONCE_INFO.len() + 4);
        info.extend_from_slice(DLEQ_NONCE_INFO);
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
        let r_t = *b_t * k;
        if bool::from(r1_aff.is_identity()) || r_t == Gt::identity() {
            k.zeroize();
            continue;
        }
        let c = compute_partial_share_dleq_challenge(
            row_index,
            seat_id,
            policy_epoch,
            pk1_aff,
            c1_aff,
            c3_aff,
            value,
            b_t,
            y_t,
            &r1_aff,
            &r_t,
        );
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
    unreachable!("unbounded u32 counter finds valid DLEQ nonce on ctr = 0 w.h.p.")
}

#[allow(clippy::too_many_arguments)]
fn compute_partial_share_dleq_challenge(
    row_index: usize,
    seat_id: &str,
    policy_epoch: u64,
    pk1_aff: &G1Affine,
    c1_aff: &G1Affine,
    c3_aff: &G1Affine,
    value: &Gt,
    b_t: &Gt,
    y_t: &Gt,
    r1_aff: &G1Affine,
    r_t: &Gt,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(DLEQ_CHALLENGE_DOMAIN);
    hasher.update(policy_epoch.to_be_bytes());
    hasher.update((row_index as u32).to_be_bytes());
    hasher.update((seat_id.len() as u32).to_be_bytes());
    hasher.update(seat_id.as_bytes());
    hasher.update(G1Affine::generator().to_compressed());
    hasher.update(G2Affine::generator().to_compressed());
    hasher.update(pk1_aff.to_compressed());
    hasher.update(c1_aff.to_compressed());
    hasher.update(c3_aff.to_compressed());
    hasher.update(r1_aff.to_compressed());
    for gt_elem in [value, b_t, y_t, r_t] {
        let repr = Zeroizing::new(format!("{gt_elem:?}"));
        hasher.update((repr.len() as u32).to_be_bytes());
        hasher.update(repr.as_bytes());
    }
    let digest = hasher.finalize();

    let hk = Hkdf::<Sha256>::new(Some(DLEQ_CHALLENGE_SALT), &digest);
    let mut wide = [0u8; 64];
    hk.expand(DLEQ_CHALLENGE_INFO, &mut wide)
        .expect("64-byte HKDF-SHA256 output is always valid");
    Scalar::from_bytes_wide(&wide)
}

pub(crate) fn expected_sealed_basis_len(cols: usize, num_rows: usize) -> Result<usize, AcuError> {
    if cols == 0 || cols > MAX_SERIALIZED_COLS || num_rows == 0 || num_rows > MAX_SERIALIZED_ROWS {
        return Err(AcuError::SerializationError(
            "invalid AcuCiphertext dimensions",
        ));
    }
    let basis_bytes = cols
        .checked_mul(G1_COMPRESSED_BYTES)
        .ok_or(AcuError::SerializationError("sealed_basis length overflow"))?;
    let scalar_bytes = num_rows
        .checked_mul(SCALAR_BYTES)
        .ok_or(AcuError::SerializationError("sealed_basis length overflow"))?;
    basis_bytes
        .checked_add(scalar_bytes)
        .and_then(|n| n.checked_add(POLY1305_TAG_BYTES))
        .ok_or(AcuError::SerializationError("sealed_basis length overflow"))
}

fn derive_basis_seal_key(
    ephemeral_pk1: &G1Projective,
    acu_pk1: &G1Projective,
    shared_z: &G1Projective,
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; G1_COMPRESSED_BYTES * 3]);
    ikm[0..48].copy_from_slice(&G1Affine::from(*ephemeral_pk1).to_compressed());
    ikm[48..96].copy_from_slice(&G1Affine::from(*acu_pk1).to_compressed());
    ikm[96..144].copy_from_slice(&G1Affine::from(*shared_z).to_compressed());

    let hk = Hkdf::<Sha256>::new(Some(BASIS_SEAL_HKDF_SALT), &*ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(BASIS_SEAL_HKDF_INFO, &mut *okm)
        .expect("32-byte HKDF-SHA256 output is always valid");
    okm
}

fn encode_basis_seal_aad(
    policy_epoch: u64,
    acu_seat_id: &str,
    cols: usize,
    c0_g1: &G1Projective,
    rows: &[CiphertextRow],
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(BASIS_SEAL_AAD_DOMAIN);
    aad.extend_from_slice(&policy_epoch.to_be_bytes());
    aad.extend_from_slice(&(acu_seat_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(acu_seat_id.as_bytes());
    aad.extend_from_slice(&(cols as u32).to_be_bytes());
    aad.extend_from_slice(&(rows.len() as u32).to_be_bytes());
    aad.extend_from_slice(&G1Affine::from(*c0_g1).to_compressed());
    for row in rows {
        aad.extend_from_slice(&(row.row_index as u32).to_be_bytes());
        aad.extend_from_slice(&(row.seat_id.len() as u32).to_be_bytes());
        aad.extend_from_slice(row.seat_id.as_bytes());
        aad.extend_from_slice(&(row.matrix_row.len() as u32).to_be_bytes());
        for scalar in &row.matrix_row {
            aad.extend_from_slice(&scalar.to_bytes());
        }
        aad.extend_from_slice(&G1Affine::from(row.c1).to_compressed());
        aad.extend_from_slice(&G1Affine::from(row.c3).to_compressed());
    }
    aad
}

#[allow(clippy::too_many_arguments)]
fn seal_basis_commitments(
    basis_commitments: &[G1Projective],
    row_scalars: &[Scalar],
    acu_seat_id: &str,
    acu_pk1: &G1Projective,
    policy_epoch: u64,
    c0_g1: &G1Projective,
    rows: &[CiphertextRow],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<SealedBasisCommitments, AcuError> {
    if !is_valid_seat_id(acu_seat_id) {
        return Err(AcuError::InvalidSeatId);
    }
    let acu_pk1_aff = G1Affine::from(*acu_pk1);
    if bool::from(acu_pk1_aff.is_identity())
        || !bool::from(acu_pk1_aff.is_torsion_free())
        || basis_commitments.is_empty()
        || row_scalars.len() != rows.len()
        || rows.is_empty()
    {
        return Err(AcuError::InvalidPublicKey(acu_seat_id.to_string()));
    }

    let cols = basis_commitments.len();
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        cols * G1_COMPRESSED_BYTES + row_scalars.len() * SCALAR_BYTES,
    ));
    for vm in basis_commitments {
        if bool::from(vm.is_identity()) {
            return Err(AcuError::SerializationError("identity basis commitment"));
        }
        let mut compressed = G1Affine::from(*vm).to_compressed();
        plaintext.extend_from_slice(&compressed);
        compressed.zeroize();
    }
    for r_j in row_scalars {
        if bool::from(r_j.is_zero()) {
            return Err(AcuError::SerializationError("zero row randomness scalar"));
        }
        let mut s_bytes = r_j.to_bytes();
        plaintext.extend_from_slice(&s_bytes);
        s_bytes.zeroize();
    }

    let g1 = G1Projective::generator();
    let mut r_kem = sample_nonzero_scalar(rng);
    let ephemeral_pk1 = g1 * r_kem;
    let mut shared_z = *acu_pk1 * r_kem;
    r_kem.zeroize();

    let sym_key = derive_basis_seal_key(&ephemeral_pk1, acu_pk1, &shared_z);
    shared_z.zeroize();

    let aad = encode_basis_seal_aad(policy_epoch, acu_seat_id, cols, c0_g1, rows);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*sym_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AcuError::AeadFailure)?;

    Ok(SealedBasisCommitments {
        acu_seat_id: acu_seat_id.to_string(),
        ephemeral_pk1,
        nonce,
        ciphertext,
    })
}

/// Cryptographically authenticate `ct` against `acu_sk` AND verify that every row `j` in `ct.rows`
/// algebraically matches `commit_row_in_g1(&basis, &row.matrix_row) + pk_j.pk1 * r_j == row.c1`
/// and `g_1 * r_j == row.c3` against the caller-supplied public-key directory lookup, zeroizing
/// unsealed secrets immediately on return.
pub(crate) fn verify_sealed_basis_with_lookup<'a, F>(
    ct: &AcuCiphertext,
    acu_sk: &SeatSecretKey,
    mut lookup_pk: F,
) -> Result<(), AcuError>
where
    F: FnMut(&str) -> Option<&'a SeatPublicKey>,
{
    let state = unseal_basis_commitments(ct, acu_sk)?;
    for (row, &r_j) in ct.rows.iter().zip(state.row_scalars.iter()) {
        let pk = lookup_pk(&row.seat_id).ok_or(AcuError::BasisUnsealFailed)?;
        if pk.seat_id != row.seat_id || !pk.verify_consistency() {
            return Err(AcuError::BasisUnsealFailed);
        }
        let mut expected_c1 = commit_row_in_g1(&state.basis, &row.matrix_row) + pk.pk1 * r_j;
        let matches = expected_c1 == row.c1;
        expected_c1.zeroize();
        if !matches {
            return Err(AcuError::BasisUnsealFailed);
        }
    }
    Ok(())
}

fn unseal_basis_commitments(
    ct: &AcuCiphertext,
    acu_sk: &SeatSecretKey,
) -> Result<UnsealedBasisState, AcuError> {
    if ct.policy_epoch == 0
        || !is_valid_seat_id(&ct.sealed_basis.acu_seat_id)
        || acu_sk.seat_id != ct.sealed_basis.acu_seat_id
    {
        return Err(AcuError::BasisUnsealFailed);
    }
    ct.validate_structure()
        .map_err(|_| AcuError::BasisUnsealFailed)?;
    let eph_aff = G1Affine::from(ct.sealed_basis.ephemeral_pk1);
    let c0_aff = G1Affine::from(ct.c0_g1);
    if bool::from(eph_aff.is_identity())
        || !bool::from(eph_aff.is_torsion_free())
        || bool::from(c0_aff.is_identity())
        || !bool::from(c0_aff.is_torsion_free())
        || !ct.rows.iter().all(verify_row_randomness_witness)
    {
        return Err(AcuError::BasisUnsealFailed);
    }
    let expected_len = expected_sealed_basis_len(ct.matrix.cols, ct.rows.len())
        .map_err(|_| AcuError::BasisUnsealFailed)?;
    if ct.sealed_basis.ciphertext.len() != expected_len {
        return Err(AcuError::BasisUnsealFailed);
    }
    if ct.c0 != pairing(&c0_aff, &G2Affine::generator()) {
        return Err(AcuError::BasisUnsealFailed);
    }

    let g1 = G1Projective::generator();
    let mut acu_pk1 = g1 * acu_sk.sk;
    let mut shared_z = ct.sealed_basis.ephemeral_pk1 * acu_sk.sk;
    if bool::from(acu_pk1.is_identity()) || bool::from(shared_z.is_identity()) {
        acu_pk1.zeroize();
        shared_z.zeroize();
        return Err(AcuError::BasisUnsealFailed);
    }

    let sym_key = derive_basis_seal_key(&ct.sealed_basis.ephemeral_pk1, &acu_pk1, &shared_z);
    acu_pk1.zeroize();
    shared_z.zeroize();

    let aad = encode_basis_seal_aad(
        ct.policy_epoch,
        &ct.sealed_basis.acu_seat_id,
        ct.matrix.cols,
        &ct.c0_g1,
        &ct.rows,
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*sym_key));
    let decrypted = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&ct.sealed_basis.nonce),
                Payload {
                    msg: &ct.sealed_basis.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| AcuError::BasisUnsealFailed)?,
    );

    let basis_bytes_len = ct.matrix.cols * G1_COMPRESSED_BYTES;
    let scalar_bytes_len = ct.rows.len() * SCALAR_BYTES;
    if decrypted.len() != basis_bytes_len + scalar_bytes_len {
        return Err(AcuError::BasisUnsealFailed);
    }

    let mut state = UnsealedBasisState {
        basis: Vec::with_capacity(ct.matrix.cols),
        row_scalars: Vec::with_capacity(ct.rows.len()),
    };

    for chunk in decrypted[..basis_bytes_len].chunks_exact(G1_COMPRESSED_BYTES) {
        let mut arr = [0u8; G1_COMPRESSED_BYTES];
        arr.copy_from_slice(chunk);
        let aff_opt: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
        arr.zeroize();
        let Some(aff) = aff_opt else {
            return Err(AcuError::BasisUnsealFailed);
        };
        if bool::from(aff.is_identity()) || !bool::from(aff.is_torsion_free()) {
            return Err(AcuError::BasisUnsealFailed);
        }
        state.basis.push(G1Projective::from(aff));
    }

    for chunk in decrypted[basis_bytes_len..].chunks_exact(SCALAR_BYTES) {
        let mut arr = [0u8; SCALAR_BYTES];
        arr.copy_from_slice(chunk);
        let sc_opt: Option<Scalar> = Scalar::from_bytes(&arr).into();
        arr.zeroize();
        let Some(sc) = sc_opt else {
            return Err(AcuError::BasisUnsealFailed);
        };
        if bool::from(sc.is_zero()) {
            return Err(AcuError::BasisUnsealFailed);
        }
        state.row_scalars.push(sc);
    }

    // Algebraic cut-and-paste & forged-basis defense (`[P1-R2-2]`):
    // 1. Every row's randomness point `c3` MUST equal `g1 * r_j` (prevents wrapping any foreign row
    //    with unknown discrete-log randomness `r_victim` into a synthetic `AcuCiphertext`).
    // 2. Every row assigned to `acu_sk.seat_id` MUST unblind under `acu_sk.sk` to the exact LSSS
    //    linear commitment `commit_row_in_g1(&state.basis, &row.matrix_row)`.
    for (row, &r_j) in ct.rows.iter().zip(state.row_scalars.iter()) {
        if g1 * r_j != row.c3 {
            return Err(AcuError::BasisUnsealFailed);
        }
        if row.seat_id == acu_sk.seat_id {
            let mut unmasked = row.c1 - row.c3 * acu_sk.sk;
            let expected = commit_row_in_g1(&state.basis, &row.matrix_row);
            let ok = unmasked == expected;
            unmasked.zeroize();
            if !ok {
                return Err(AcuError::BasisUnsealFailed);
            }
        }
    }

    Ok(state)
}

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    a.iter()
        .zip(b.iter())
        .fold(Scalar::ZERO, |acc, (&x, &y)| acc + x * y)
}

fn commit_row_in_g1(basis_commitments: &[G1Projective], row: &[Scalar]) -> G1Projective {
    basis_commitments
        .iter()
        .zip(row.iter())
        .fold(G1Projective::identity(), |acc, (&v_m, &r_m)| {
            acc + v_m * r_m
        })
}

fn scalar_pow(base: Scalar, exp: u64) -> Scalar {
    let mut result = Scalar::ONE;
    for _ in 0..exp {
        result *= base;
    }
    result
}

pub(crate) fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], AcuError> {
    let end = cursor
        .checked_add(len)
        .ok_or(AcuError::SerializationError("byte slice length overflow"))?;
    if end > bytes.len() {
        return Err(AcuError::SerializationError(
            "unexpected end of serialized bytes",
        ));
    }
    let slice = &bytes[*cursor..end];
    *cursor = end;
    Ok(slice)
}

pub(crate) fn read_u32_be(bytes: &[u8], cursor: &mut usize) -> Result<u32, AcuError> {
    let s = take_slice(bytes, cursor, 4)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(s);
    Ok(u32::from_be_bytes(arr))
}

pub(crate) fn read_u64_be(bytes: &[u8], cursor: &mut usize) -> Result<u64, AcuError> {
    let s = take_slice(bytes, cursor, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(s);
    Ok(u64::from_be_bytes(arr))
}

fn read_g1_compressed(bytes: &[u8], cursor: &mut usize) -> Result<G1Projective, AcuError> {
    let s = take_slice(bytes, cursor, G1_COMPRESSED_BYTES)?;
    let mut arr = [0u8; G1_COMPRESSED_BYTES];
    arr.copy_from_slice(s);
    let aff: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
    let aff = aff.ok_or(AcuError::SerializationError(
        "invalid compressed G1Affine point",
    ))?;
    if !bool::from(aff.is_torsion_free()) {
        return Err(AcuError::SerializationError(
            "non-torsion-free G1Affine point",
        ));
    }
    Ok(G1Projective::from(aff))
}

fn read_nonidentity_g1_compressed(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<G1Projective, AcuError> {
    let pt = read_g1_compressed(bytes, cursor)?;
    if bool::from(pt.is_identity()) {
        return Err(AcuError::SerializationError(
            "identity G1 point rejected in AcuCiphertext",
        ));
    }
    Ok(pt)
}

fn read_scalar(bytes: &[u8], cursor: &mut usize) -> Result<Scalar, AcuError> {
    let s = take_slice(bytes, cursor, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(s);
    let scalar: Option<Scalar> = Scalar::from_bytes(&arr).into();
    scalar.ok_or(AcuError::SerializationError("non-canonical F_r scalar"))
}
