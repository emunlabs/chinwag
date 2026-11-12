// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Pairing-based Access Control Unit (`ACU`) core encryption, partial decryption, share verification,
//! combiner, deterministic `CHWGACU2` binary serialization with ACU-sealed basis commitments, and all 4
//! dynamic policy evolution operations (`insert_key`, `insert_sibling_key`, `escalate_threshold`,
//! and `revoke_and_rerandomize`).
//!
//! Dynamic policy evolution mechanics are derived from the pairing-based DASTE paper:
//! *Decentralized Ad-Hoc Access-Structured Threshold Encryption with Dynamic Policy Evolution*
//! (ePrint 2026/1141), hardened for Chinwag (`CHWG-0271`) so basis commitments
//! $V_0, \dots, V_{k-1} \in \mathbb{G}_1^k$ (including $V_0 = g_1^s$) are **sealed exclusively
//! under the ACU operator's key (`pk_ACU`)** via ephemeral `BLS12-381` $\mathbb{G}_1$ KEM +
//! `HKDF-SHA256` + `ChaCha20-Poly1305` bound via injective binary AAD to `policy_epoch`,
//! `acu_seat_id`, `c0_g1`, and the LSSS matrix/rows.

use crate::AcuError;
use crate::keys::{
    MAX_SEAT_ID_BYTES, SeatPublicKey, SeatSecretKey, is_valid_seat_id, sample_nonzero_scalar,
};
use crate::lsss::{LsssMatrix, find_reconstruction_weights, submatrix_rank};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar, pairing};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ff::Field;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const LEGACY_ACU_CT_MAGIC: &[u8; 8] = b"CHWGACU1";
const ACU_CT_MAGIC: &[u8; 8] = b"CHWGACU2";
const BASIS_SEAL_HKDF_SALT: &[u8] = b"chinwag-acu/v2/basis-seal-hkdf-salt";
const BASIS_SEAL_HKDF_INFO: &[u8] = b"chinwag-acu/v2/basis-seal-chacha20poly1305-key";
const BASIS_SEAL_AAD_DOMAIN: &[u8] = b"chinwag-acu/v2/basis-seal-aad";

const G1_COMPRESSED_BYTES: usize = 48;
const G2_COMPRESSED_BYTES: usize = 96;
const POLY1305_TAG_BYTES: usize = 16;

const MAX_SERIALIZED_ROWS: usize = 4096;
const MAX_SERIALIZED_COLS: usize = 4096;

/// RAII wrapper zeroizing transient $\mathbb{G}_1$ basis commitment vectors on drop across all exit paths.
struct ZeroizeG1Vec(Vec<G1Projective>);

impl Drop for ZeroizeG1Vec {
    fn drop(&mut self) {
        for elem in &mut self.0 {
            elem.zeroize();
        }
    }
}

/// Basis commitments $V_0, \dots, V_{k-1} \in \mathbb{G}_1^k$ (where $V_0 = g_1^s$)
/// encrypted exclusively to the ACU operator's BLS12-381 public key (`pk_ACU`) via
/// ephemeral `BLS12-381` $\mathbb{G}_1$ KEM + `HKDF-SHA256` + `ChaCha20-Poly1305`.
///
/// Bound via injective binary AAD to `policy_epoch`, `acu_seat_id`, `cols`, `c0_g1`, and the
/// full LSSS matrix and row ciphertexts so untrusted relays, storage buckets, and single-branch
/// holders never observe cleartext $V_0 = g_1^s$ and cannot maul policy headers across epochs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBasisCommitments {
    /// Canonical seat identifier of the ACU operator whose `pk_ACU` seals these commitments.
    pub acu_seat_id: String,
    /// Ephemeral KEM encapsulation point $E_{\text{kem}} = g_1^{r_{\text{kem}}} \in \mathbb{G}_1$.
    pub ephemeral_pk1: G1Projective,
    /// 96-bit ChaCha20-Poly1305 nonce.
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 ciphertext + 16-byte Poly1305 tag encrypting $48 \cdot k$ compressed $\mathbb{G}_1$ bytes.
    pub ciphertext: Vec<u8>,
}

/// A single row of an [`AcuCiphertext`] bound to recipient seat `seat_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextRow {
    /// Zero-based row index inside [`AcuCiphertext::rows`].
    pub row_index: usize,
    /// Seat or branch identifier $\rho(j)$ (e.g., `"branch:8687872"` or `"acu:98939834"`).
    pub seat_id: String,
    /// LSSS matrix row vector $M_j \in \mathbb{F}_r^k$.
    pub matrix_row: Vec<Scalar>,
    /// Share ciphertext component $c_{j,1} = g_1^{\lambda_j} \cdot pk_{\rho(j),1}^{r_j} \in \mathbb{G}_1$.
    pub c1: G1Projective,
    /// Ephemeral randomness component $c_{j,2} = g_2^{r_j} \in \mathbb{G}_2$.
    pub c2: G2Projective,
    /// Ephemeral randomness witness $c_{j,3} = g_1^{r_j} \in \mathbb{G}_1$.
    pub c3: G1Projective,
}

/// Pairing-based ACU header ciphertext (`CHWGACU2`) supporting in-place dynamic policy evolution
/// by the ACU operator without decrypting $c_0$ or exposing cleartext basis commitments $V_m = g_1^{v_m}$
/// on the wire or to untrusted relays/buckets.
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
    /// Basis commitments $V_0, \dots, V_{k-1} \in \mathbb{G}_1^k$ sealed exclusively under `pk_ACU`.
    pub sealed_basis: SealedBasisCommitments,
    /// Current LSSS policy matrix $(M, \rho)$ over $\mathbb{F}_r$.
    pub matrix: LsssMatrix,
    /// Per-row ciphertext components matching `matrix.rows`.
    pub rows: Vec<CiphertextRow>,
}

impl AcuCiphertext {
    /// Serialize this [`AcuCiphertext`] into a deterministic, self-framing binary format
    /// (`CHWGACU2`) using canonical Zcash/IETF compressed BLS12-381 points (`48` bytes for $\mathbb{G}_1$,
    /// `96` bytes for $\mathbb{G}_2$), `32`-byte little-endian $\mathbb{F}_r$ scalars, and
    /// ACU-sealed basis commitments (`SealedBasisCommitments`).
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
            out.extend_from_slice(&G2Affine::from(row.c2).to_compressed());
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

        let expected_sealed_len = expected_sealed_basis_len(cols)?;
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
            let c2 = read_nonidentity_g2_compressed(bytes, &mut cursor)?;
            let c3 = read_nonidentity_g1_compressed(bytes, &mut cursor)?;

            matrix_rows.push((seat_id.clone(), matrix_row.clone()));
            rows.push(CiphertextRow {
                row_index,
                seat_id,
                matrix_row,
                c1,
                c2,
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

/// Partial decryption share $D_j = e(g_1, g_2)^{\lambda_j} \in \mathbb{G}_T$ emitted by seat $\rho(j)$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialDecryptionShare {
    /// Row index $j$ in [`AcuCiphertext::rows`] that this partial share decrypts.
    pub row_index: usize,
    /// Seat identifier $\rho(j)$ that produced this share.
    pub seat_id: String,
    /// Policy epoch of the ciphertext when this share was computed (`>= 1`).
    pub policy_epoch: u64,
    /// Unblinded pairing share $D_j = e(c_{j,1}, g_2) + e(g_1, c_{j,2} \cdot (-sk_j)) = e(g_1, g_2)^{\lambda_j} \in \mathbb{G}_T$.
    pub value: Gt,
}

/// Sample a fresh target-group secret $K = e(K_{\mathbb{G}_1}, g_2) \in \mathbb{G}_T$ and encrypt it
/// under `matrix` and `seat_keys`, sealing the basis commitments $V_0, \dots, V_{k-1}$ exclusively
/// under `acu_pk` (`CHWGACU2`).
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
/// exclusively under `acu_pk` (`CHWGACU2`).
///
/// Every referenced [`SeatPublicKey`] and `acu_pk` is verified via [`SeatPublicKey::verify_consistency`]
/// before encryption proceeds; any missing, inconsistent, or rogue key fails closed.
pub fn acu_encrypt_with_g1(
    payload_g1: &G1Projective,
    matrix: &LsssMatrix,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    acu_pk: &SeatPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(AcuCiphertext, Gt), AcuError> {
    matrix.validate()?;
    if bool::from(payload_g1.is_identity()) {
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

    // Pre-verify every recipient seat's public key consistency (ALISTAIR rogue-key gate).
    for (seat_id, _) in &matrix.rows {
        let pk = seat_keys
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.clone()))?;
        if pk.seat_id != *seat_id || !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id.clone()));
        }
    }

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
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

    let payload_key = pairing(&G1Affine::from(*payload_g1), &g2_aff);
    let c0 = pairing(&G1Affine::from(c0_g1), &g2_aff);

    // Transient basis commitments V_m = g1^(v_m) for m = 0..k (zeroized automatically on drop).
    let basis_commitments = ZeroizeG1Vec(v.iter().map(|vm| g1 * vm).collect());

    // Construct per-row ciphertexts
    let mut rows = Vec::with_capacity(matrix.rows.len());
    for (row_index, (seat_id, matrix_row)) in matrix.rows.iter().enumerate() {
        let pk = &seat_keys[seat_id];
        let mut lambda_j = inner_product(matrix_row, &v);
        let mut r_j = sample_nonzero_scalar(rng);

        let c1 = g1 * lambda_j + pk.pk1 * r_j;
        let c2 = g2 * r_j;
        let c3 = g1 * r_j;

        lambda_j.zeroize();
        r_j.zeroize();

        rows.push(CiphertextRow {
            row_index,
            seat_id: seat_id.clone(),
            matrix_row: matrix_row.clone(),
            c1,
            c2,
            c3,
        });
    }
    v.zeroize();

    let policy_epoch = 1u64;
    let sealed_basis = seal_basis_commitments(
        &basis_commitments.0,
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
/// 1. Unseals $\{V_m\}$ from `ct.sealed_basis` (verifying `ct`'s AAD binding and `acu_sk`).
/// 2. Evaluates $g_1^{\lambda_{\text{new}}} = \sum_{m=0}^{k-1} V_m \cdot r_{\text{new},m}$ homomorphically
///    in $\mathbb{G}_1$ without knowing $s$ or decrypting $c_0$.
/// 3. Blinds with fresh row randomness $r_{\text{new}} \xleftarrow{\$} \mathbb{F}_r^*$, appends the row,
///    and re-seals $\{V_m\}$ under `pk_ACU` with fresh randomness at `policy_epoch + 1`.
pub fn insert_key(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    new_seat: &SeatPublicKey,
    new_row: Vec<Scalar>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<usize, AcuError> {
    ct.matrix.validate()?;
    let basis_commitments = unseal_basis_commitments(ct, acu_sk)?;

    if new_row.len() != ct.matrix.cols {
        return Err(AcuError::DimensionMismatch {
            expected: ct.matrix.cols,
            actual: new_row.len(),
        });
    }
    if !new_seat.verify_consistency() {
        return Err(AcuError::InvalidPublicKey(new_seat.seat_id.clone()));
    }

    let mut g1_lambda_new = commit_row_in_g1(&basis_commitments.0, &new_row);

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let mut r_new = sample_nonzero_scalar(rng);

    let c1 = g1_lambda_new + new_seat.pk1 * r_new;
    let c2 = g2 * r_new;
    let c3 = g1 * r_new;
    g1_lambda_new.zeroize();
    r_new.zeroize();

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
        c2,
        c3,
    });

    let mut acu_pk1 = g1 * acu_sk.sk;
    let re_sealed_res = seal_basis_commitments(
        &basis_commitments.0,
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
/// `basis_commitments` with fresh randomness at `policy_epoch + 1`.
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
/// 1. Unseals $\{V_m\}$ from `ct.sealed_basis`.
/// 2. Samples $\Delta t$ fresh non-zero column secrets $u_1, \dots, u_{\Delta t} \xleftarrow{\$} \mathbb{F}_r^*$
///    and appends $g_1^{u_1}, \dots, g_1^{u_{\Delta t}}$ to $\{V_m'\}$.
/// 3. Extends each affected row $j$ with Vandermonde powers of $x_j = j + 1$ starting at the
///    sub-gate's current Vandermonde degree and shifts `row.c1` with fresh row randomness $r'_j$.
/// 4. Zero-pads unaffected rows and re-seals $\{V_m'\}$ under `pk_ACU` with fresh randomness at `policy_epoch + 1`.
pub fn escalate_threshold(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    affected_row_indices: &[usize],
    delta_t: usize,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    ct.matrix.validate()?;
    let mut basis_commitments = unseal_basis_commitments(ct, acu_sk)?;

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
    let current_rank = submatrix_rank(&ct.matrix, &unique_affected).max(1);
    if current_rank + delta_t > unique_affected.len() {
        return Err(AcuError::InvalidThreshold {
            threshold: current_rank + delta_t,
            children: unique_affected.len(),
        });
    }

    let new_cols = ct
        .matrix
        .cols
        .checked_add(delta_t)
        .filter(|&c| c <= MAX_SERIALIZED_COLS)
        .ok_or(AcuError::SerializationError(
            "invalid AcuCiphertext dimensions",
        ))?;

    // Verify public keys for all affected rows before mutating state.
    for &idx in &unique_affected {
        let seat_id = &ct.rows[idx].seat_id;
        let pk = seat_keys
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.clone()))?;
        if pk.seat_id != *seat_id || !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id.clone()));
        }
    }

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    // Sample delta_t fresh column secrets u_1..u_{delta_t} and extend basis_commitments.
    let mut u = Zeroizing::new(Vec::with_capacity(delta_t));
    for _ in 0..delta_t {
        let u_m = sample_nonzero_scalar(rng);
        basis_commitments.0.push(g1 * u_m);
        u.push(u_m);
    }

    let mut new_matrix = ct.matrix.clone();
    let mut new_rows = ct.rows.clone();

    let base_exp = current_rank;
    for row_idx in 0..new_rows.len() {
        if affected_set.contains(&row_idx) {
            let x_j = Scalar::from((row_idx + 1) as u64);
            let mut x_pow = scalar_pow(x_j, base_exp as u64);
            let mut delta_lambda = Scalar::ZERO;

            for m in 0..delta_t {
                new_matrix.rows[row_idx].1.push(x_pow);
                new_rows[row_idx].matrix_row.push(x_pow);
                delta_lambda += u[m] * x_pow;
                x_pow *= x_j;
            }

            let pk = &seat_keys[&new_rows[row_idx].seat_id];
            let mut r_prime = sample_nonzero_scalar(rng);
            new_rows[row_idx].c1 += g1 * delta_lambda + pk.pk1 * r_prime;
            new_rows[row_idx].c2 += g2 * r_prime;
            new_rows[row_idx].c3 += g1 * r_prime;
            delta_lambda.zeroize();
            r_prime.zeroize();
        } else {
            for _ in 0..delta_t {
                new_matrix.rows[row_idx].1.push(Scalar::ZERO);
                new_rows[row_idx].matrix_row.push(Scalar::ZERO);
            }
        }
    }
    u.zeroize();

    new_matrix.cols = new_cols;
    let new_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;

    let mut acu_pk1 = g1 * acu_sk.sk;
    let re_sealed_res = seal_basis_commitments(
        &basis_commitments.0,
        &ct.sealed_basis.acu_seat_id,
        &acu_pk1,
        new_epoch,
        &ct.c0_g1,
        &new_rows,
        rng,
    );
    acu_pk1.zeroize();
    let new_sealed_basis = re_sealed_res?;

    ct.matrix = new_matrix;
    ct.rows = new_rows;
    ct.sealed_basis = new_sealed_basis;
    ct.policy_epoch = new_epoch;
    Ok(())
}

/// **Dynamic Policy Operation 3 & 4 — Subtree Revocation + Ciphertext Rerandomization (`revoke_and_rerandomize`)**:
///
/// Executed exclusively by the ACU operator holding `acu_sk`:
/// 1. Unseals $\{V_m\}$ from `ct.sealed_basis`.
/// 2. Prunes all rows matching `revoked_seat_ids` and re-indexes surviving rows.
/// 3. Samples a fresh blinding vector $\Delta v = (\Delta s, \Delta v_1, \dots, \Delta v_{k-1}) \in (\mathbb{F}_r^*)^k$.
/// 4. Rotates $c_{0,\mathbb{G}_1} \mathrel{+}= g_1 \cdot \Delta s$, $c_0 = e(c_{0,\mathbb{G}_1}', g_2)$,
///    and $V_m' = V_m + g_1 \cdot \Delta v_m$.
/// 5. Shifts every surviving row $j$ by $\Delta \lambda_j = \langle M_j, \Delta v \rangle$ and fresh $r'_j$,
///    then re-seals $\{V_m'\}$ under `pk_ACU` with fresh randomness at `policy_epoch + 1`.
pub fn revoke_and_rerandomize(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    revoked_seat_ids: &[&str],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    ct.matrix.validate()?;
    let mut basis_commitments = unseal_basis_commitments(ct, acu_sk)?;

    let revoked_set: BTreeSet<&str> = revoked_seat_ids.iter().copied().collect();

    // Retain only non-revoked rows.
    let mut surviving_rows = Vec::new();
    let mut surviving_matrix_rows = Vec::new();
    for row in &ct.rows {
        if !revoked_set.contains(row.seat_id.as_str()) {
            let mut cloned = row.clone();
            cloned.row_index = surviving_rows.len();
            surviving_matrix_rows.push((cloned.seat_id.clone(), cloned.matrix_row.clone()));
            surviving_rows.push(cloned);
        }
    }

    if surviving_rows.is_empty() {
        return Err(AcuError::EmptyPolicy);
    }

    // Verify all surviving seats have valid public keys in `seat_keys`.
    for row in &surviving_rows {
        let pk = seat_keys
            .get(&row.seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(row.seat_id.clone()))?;
        if pk.seat_id != row.seat_id || !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(row.seat_id.clone()));
        }
    }

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let g2_aff = G2Affine::generator();
    let k = ct.matrix.cols;

    // Sample fresh blinding delta vector delta_v = (delta_s, delta_v1, ..., delta_v_{k-1}),
    // ensuring rotated c0_g1 and rotated V_m' are non-identity.
    let mut delta_v = Zeroizing::new(Vec::with_capacity(k));
    let (delta_s, new_c0_g1) = loop {
        let candidate_ds = sample_nonzero_scalar(rng);
        let candidate_c0_g1 = ct.c0_g1 + g1 * candidate_ds;
        let candidate_v0 = basis_commitments.0[0] + g1 * candidate_ds;
        if !bool::from(candidate_c0_g1.is_identity()) && !bool::from(candidate_v0.is_identity()) {
            break (candidate_ds, candidate_c0_g1);
        }
    };
    delta_v.push(delta_s);
    basis_commitments.0[0] += g1 * delta_s;

    for vm in basis_commitments.0.iter_mut().skip(1) {
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

    // Rerandomize all surviving rows with delta_lambda_j = <M_j, delta_v> and fresh r'_j.
    for row in &mut surviving_rows {
        let pk = &seat_keys[&row.seat_id];
        let mut delta_lambda = inner_product(&row.matrix_row, &delta_v);
        let mut r_prime = sample_nonzero_scalar(rng);

        row.c1 += g1 * delta_lambda + pk.pk1 * r_prime;
        row.c2 += g2 * r_prime;
        row.c3 += g1 * r_prime;

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
        &basis_commitments.0,
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

/// Compute a partial decryption share $D_j \in \mathbb{G}_T$ for `ct.rows[row_index]` bound
/// to `ct.policy_epoch` using seat secret key `sk`:
///
/// $$D_j = e(c_{j,1}, g_2) + e(g_1, c_{j,2} \cdot (-sk)) = e(g_1, g_2)^{\lambda_j}$$
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

/// Compute a partial decryption share $D_j \in \mathbb{G}_T$ bound to a specific `policy_epoch`.
#[must_use]
pub fn acu_partial_decrypt_at_epoch(
    row: &CiphertextRow,
    sk: &SeatSecretKey,
    policy_epoch: u64,
) -> PartialDecryptionShare {
    let g1_aff = G1Affine::generator();
    let g2_aff = G2Affine::generator();
    let mut neg_sk = -sk.sk;
    let c2_neg_sk = G2Affine::from(row.c2 * neg_sk);
    neg_sk.zeroize();
    let value = pairing(&G1Affine::from(row.c1), &g2_aff) + pairing(&g1_aff, &c2_neg_sk);

    PartialDecryptionShare {
        row_index: row.row_index,
        seat_id: row.seat_id.clone(),
        policy_epoch,
        value,
    }
}

/// Verify that a [`PartialDecryptionShare`] $D_j$ is well-formed with respect to `row` and `pk`:
/// 1. Checks `row.row_index == share.row_index`, `row.seat_id == share.seat_id == pk.seat_id`,
///    and [`SeatPublicKey::verify_consistency`].
/// 2. Checks non-identity row randomness witness: $e(c_{j,3}, g_2) = e(g_1, c_{j,2})$.
/// 3. Checks bilinear decryption soundness: $D_j = e(c_{j,1}, g_2) + e(c_{j,3}, -pk_{\rho(j),2})$.
///
/// Because $c_{j,1} = g_1^{\lambda_j} + pk_{\rho(j),1}^{r_j}$ and $c_{j,3} = g_1^{r_j}$, this equation
/// uniquely pins $D_j = e(g_1, g_2)^{\lambda_j}$ for `row`'s current epoch **without requiring
/// cleartext `basis_commitments`**.
#[must_use]
pub fn acu_verify_partial_share(
    row: &CiphertextRow,
    pk: &SeatPublicKey,
    share: &PartialDecryptionShare,
) -> bool {
    if row.row_index != share.row_index || row.seat_id != share.seat_id || row.seat_id != pk.seat_id
    {
        return false;
    }
    if bool::from(row.c2.is_identity()) || bool::from(row.c3.is_identity()) {
        return false;
    }
    if !pk.verify_consistency() {
        return false;
    }
    let g1_aff = G1Affine::generator();
    let g2_aff = G2Affine::generator();

    // Check row randomness witness: e(c3, g2) == e(g1, c2)
    let row_witness_ok =
        pairing(&G1Affine::from(row.c3), &g2_aff) == pairing(&g1_aff, &G2Affine::from(row.c2));
    if !row_witness_ok {
        return false;
    }

    // Check D_j == e(c1, g2) + e(c3, -pk2)
    let expected = pairing(&G1Affine::from(row.c1), &g2_aff)
        + pairing(&G1Affine::from(row.c3), &G2Affine::from(-pk.pk2));
    share.value == expected
}

/// Check that a [`CiphertextRow`]'s randomness components `(c2, c3)` are non-identity and
/// satisfy the bilinear witness equation $e(c_3, g_2) = e(g_1, c_2)$.
#[must_use]
pub fn verify_row_randomness_witness(row: &CiphertextRow) -> bool {
    if bool::from(row.c2.is_identity()) || bool::from(row.c3.is_identity()) {
        return false;
    }
    pairing(&G1Affine::from(row.c3), &G2Affine::generator())
        == pairing(&G1Affine::generator(), &G2Affine::from(row.c2))
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
/// `policy_epoch` and row/seat binding without pairing-verifying individual shares upfront
/// (used in tests to prove that even if pairing verification is skipped, stale epoch-1 shares
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
    ct.matrix.validate()?;
    if ct.policy_epoch == 0 {
        return Err(AcuError::SerializationError("policy_epoch must be >= 1"));
    }
    if ct.rows.len() != ct.matrix.rows.len() {
        return Err(AcuError::DimensionMismatch {
            expected: ct.matrix.rows.len(),
            actual: ct.rows.len(),
        });
    }
    let expected_sealed_len = expected_sealed_basis_len(ct.matrix.cols)?;
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
                if existing.get().value != share.value {
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

pub(crate) fn expected_sealed_basis_len(cols: usize) -> Result<usize, AcuError> {
    if cols == 0 || cols > MAX_SERIALIZED_COLS {
        return Err(AcuError::SerializationError(
            "invalid AcuCiphertext dimensions",
        ));
    }
    cols.checked_mul(G1_COMPRESSED_BYTES)
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
        aad.extend_from_slice(&G2Affine::from(row.c2).to_compressed());
        aad.extend_from_slice(&G1Affine::from(row.c3).to_compressed());
    }
    aad
}

fn seal_basis_commitments(
    basis_commitments: &[G1Projective],
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
    if bool::from(acu_pk1.is_identity()) || basis_commitments.is_empty() {
        return Err(AcuError::InvalidPublicKey(acu_seat_id.to_string()));
    }

    let cols = basis_commitments.len();
    let mut plaintext = Zeroizing::new(Vec::with_capacity(cols * G1_COMPRESSED_BYTES));
    for vm in basis_commitments {
        if bool::from(vm.is_identity()) {
            return Err(AcuError::SerializationError("identity basis commitment"));
        }
        let mut compressed = G1Affine::from(*vm).to_compressed();
        plaintext.extend_from_slice(&compressed);
        compressed.zeroize();
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

fn unseal_basis_commitments(
    ct: &AcuCiphertext,
    acu_sk: &SeatSecretKey,
) -> Result<ZeroizeG1Vec, AcuError> {
    if ct.policy_epoch == 0
        || !is_valid_seat_id(&ct.sealed_basis.acu_seat_id)
        || acu_sk.seat_id != ct.sealed_basis.acu_seat_id
    {
        return Err(AcuError::BasisUnsealFailed);
    }
    if bool::from(ct.sealed_basis.ephemeral_pk1.is_identity())
        || bool::from(ct.c0_g1.is_identity())
        || ct.rows.len() != ct.matrix.rows.len()
    {
        return Err(AcuError::BasisUnsealFailed);
    }
    let expected_len =
        expected_sealed_basis_len(ct.matrix.cols).map_err(|_| AcuError::BasisUnsealFailed)?;
    if ct.sealed_basis.ciphertext.len() != expected_len {
        return Err(AcuError::BasisUnsealFailed);
    }
    if ct.c0 != pairing(&G1Affine::from(ct.c0_g1), &G2Affine::generator()) {
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

    if decrypted.len() != ct.matrix.cols * G1_COMPRESSED_BYTES {
        return Err(AcuError::BasisUnsealFailed);
    }

    let mut basis = ZeroizeG1Vec(Vec::with_capacity(ct.matrix.cols));
    for chunk in decrypted.chunks_exact(G1_COMPRESSED_BYTES) {
        let mut arr = [0u8; G1_COMPRESSED_BYTES];
        arr.copy_from_slice(chunk);
        let aff_opt: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
        arr.zeroize();
        let Some(aff) = aff_opt else {
            return Err(AcuError::BasisUnsealFailed);
        };
        let proj = G1Projective::from(aff);
        if bool::from(proj.is_identity()) {
            return Err(AcuError::BasisUnsealFailed);
        }
        basis.0.push(proj);
    }

    Ok(basis)
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

fn read_g2_compressed(bytes: &[u8], cursor: &mut usize) -> Result<G2Projective, AcuError> {
    let s = take_slice(bytes, cursor, G2_COMPRESSED_BYTES)?;
    let mut arr = [0u8; G2_COMPRESSED_BYTES];
    arr.copy_from_slice(s);
    let aff: Option<G2Affine> = G2Affine::from_compressed(&arr).into();
    let aff = aff.ok_or(AcuError::SerializationError(
        "invalid compressed G2Affine point",
    ))?;
    Ok(G2Projective::from(aff))
}

fn read_nonidentity_g2_compressed(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<G2Projective, AcuError> {
    let pt = read_g2_compressed(bytes, cursor)?;
    if bool::from(pt.is_identity()) {
        return Err(AcuError::SerializationError(
            "identity G2 point rejected in AcuCiphertext",
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
