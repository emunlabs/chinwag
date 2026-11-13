// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Pairing-based Access Control Unit (`ACU`) core encryption (`CHWGACU3`), zero-$V_0$
//! policy-matched independent $\mathbb{G}_1$-LSSS `SBC` slots (`ePrint v2` §6.1 Step 4 &
//! Theorem 3(ii)), single-pairing pure-$\mathbb{G}_1$ coalition combine (`ePrint v2` §6.2),
//! blind row locators $\ell_j$ + oblivious ECDH recipient hints (`UI v5` `F-01`, `ePrint v2` §7),
//! and all dynamic policy evolution operations:
//! - [`revoke_and_rerandomize`] (ciphertext-only homomorphic with self-lockout guard) &
//!   [`emergency_lock_and_rerandomize`] (explicit CISO kill-switch lockout),
//! - [`escalate_threshold`] / [`escalate_gate_threshold`] (ciphertext-only, subtree-consistent
//!   $x_{g,c}$ & simultaneous full-$\mathbb{F}_r^k$ $\Delta v$ rerandomization),
//! - [`insert_sibling_key`] via [`WarmForkRequest`] (`Shadow-KV` warm fork with 3-equation
//!   HVZK Chaum–Pedersen equality proof — neither `ACU` nor custodian alone can forge or decrypt),
//! - [`insert_authorized_seat`] via [`CoalitionInsertionRowShare`] (`ePrint v2` §6.3 Op 3 live
//!   $V_0^{(E)}$ reconstruction + `SBC` compaction to a single slot).

use crate::AcuError;
use crate::framing::{
    gt_canonical_bytes, hash_to_nonzero_scalar, lp64_str, read_g1_compressed, read_lp64,
    read_lp64_str, read_nonidentity_g1_compressed, read_scalar, read_u8, read_u32_be, read_u64_be,
    sample_uniform_scalar, take_slice,
};
use crate::keys::{
    MAX_SEAT_ID_BYTES, SeatPublicKey, SeatSecretKey, is_valid_seat_id, sample_nonzero_scalar,
};
use crate::lsss::{
    LsssMatrix, MAX_SERIALIZED_COLS, MAX_SERIALIZED_ROWS, find_reconstruction_weights,
    rows_span_target,
};
use crate::share::{
    DleqMode, PartialDecryptionShare, RowPok, RowUpdateProof, batch_verify_partial_shares,
    emit_partial_share_with_mode, prove_row_pok, prove_update_row_pok,
    verify_partial_share_for_object, verify_row_randomness_chain,
};
use bls12_381::{G1Affine, G1Projective, G2Affine, Gt, Scalar, pairing};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ff::Field;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const LEGACY_ACU_CT_MAGIC_V1: &[u8; 8] = b"CHWGACU1";
const LEGACY_ACU_CT_MAGIC_V2: &[u8; 8] = b"CHWGACU2";
/// Canonical `v2`-parity `AcuCiphertext` wire magic (`CHWGACU3` — zero-$V_0$ policy-matched `SBC_E`).
pub const ACU_CT_MAGIC: &[u8; 8] = b"CHWGACU3";

const SBC_HKDF_SALT: &[u8] = b"chinwag-acu/v3/sbc-slot-hkdf-salt";
const SBC_HKDF_INFO_DOMAIN: &[u8] = b"chinwag-acu/v3/sbc-slot-chacha20poly1305-key";
const SBC_AAD_DOMAIN: &[u8] = b"chinwag-acu/v3/sbc-slot-aad";
const ROW_LOCATOR_DOMAIN: &[u8] = b"chinwag.acu.v2.row-loc";
const OBLIVIOUS_HINT_DOMAIN: &[u8] = b"chinwag-acu-hint-v2";
const WARM_FORK_DST: &[u8] = b"chinwag.acu.v2.warm-fork-hvzk";
const HEADER_DIGEST_DOMAIN: &[u8] = b"chinwag.acu.v2.header-digest";

const MAX_SBC_SLOTS: usize = 256;
const MAX_ROW_UPDATES: usize = 256;
const POLY1305_TAG_BYTES: usize = 16;

/// Compute the `32`-byte per-object keyed blind row locator $\ell_j$ (`ePrint v2` §6.1 Step 2):
/// $\ell_j = \mathsf{HMAC\text{-}SHA256}(k_{\mathsf{idx}},\, \text{"chinwag.acu.v2.row-loc"} \parallel O \parallel E_8 \parallel j_4 \parallel \mathsf{LP}(\mathsf{seat\_id}))$.
#[must_use]
pub fn compute_blind_row_locator(
    locator_key: &[u8; 32],
    object_digest: &[u8; 32],
    epoch: u64,
    row_index: u32,
    seat_id: &str,
) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(locator_key).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(ROW_LOCATOR_DOMAIN);
    mac.update(object_digest);
    mac.update(&epoch.to_be_bytes());
    mac.update(&row_index.to_be_bytes());
    mac.update(&(seat_id.len() as u64).to_be_bytes());
    mac.update(seat_id.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Compute the `8`-byte zero-extra-mul oblivious recipient ECDH hint (`UI v5` `F-01`):
/// `BLAKE3("chinwag-acu-hint-v2" || compressed(r_j * pk_i))[..8]`.
#[must_use]
pub fn compute_oblivious_key_hint(shared_point: &G1Projective) -> [u8; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OBLIVIOUS_HINT_DOMAIN);
    hasher.update(&G1Affine::from(*shared_point).to_compressed());
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

/// A single two-element $\mathbb{G}_1$ row of an [`AcuCiphertext`] (`ePrint v2` §6.1 Step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CiphertextRow {
    /// Stable 32-byte object identifier $O$ binding shares and randomness proofs to this object.
    pub object_digest: [u8; 32],
    /// Zero-based row index $j$ inside [`AcuCiphertext::rows`].
    pub row_index: usize,
    /// Seat or branch identifier $\rho(j)$ (e.g., `"branch:8687872"` or `"blind:..."` on Blind Relay wire).
    pub seat_id: String,
    /// Per-object `32`-byte keyed blind row locator $\ell_j$.
    pub row_locator: [u8; 32],
    /// `8`-byte oblivious ECDH hint `BLAKE3("chinwag-acu-hint-v2" || compressed(init_r_j * pk_i))[..8]`.
    pub oblivious_hint: [u8; 8],
    /// LSSS matrix row vector $M_j \in \mathbb{F}_r^k$.
    pub matrix_row: Vec<Scalar>,
    /// Share ciphertext component $c_{j,1} = \lambda_j G_1 + r_j pk_{\rho(j)} \in \mathbb{G}_1$.
    pub c1: G1Projective,
    /// Ephemeral randomness component $c_{j,2} = r_j G_1 \in \mathbb{G}_1^*$.
    pub c2: G1Projective,
    /// Epoch at which this row was initially created (`1` or insertion epoch).
    pub init_epoch: u64,
    /// Row index at `init_epoch` bound into `row_pok`.
    pub init_row_index: u32,
    /// Canonical SHA-256 digest of the `LsssMatrix` at `init_epoch` bound into `row_pok`
    /// (prevents cut-and-paste of `ACU` rows across synthetic matrices without `acu_sk`).
    pub init_matrix_digest: [u8; 32],
    /// Initial `c1` at `init_epoch` prior to homomorphic rerandomizations.
    pub init_c1: G1Projective,
    /// Initial `c2` at `init_epoch` prior to homomorphic rerandomizations.
    pub init_c2: G1Projective,
    /// `64`-byte Schnorr proof $\pi^{\mathsf{row}}_j$ of knowledge of $r_j^{(0)}$ in `init_c2`.
    pub row_pok: RowPok,
    /// Verifiable homomorphic rerandomization updates $\pi^{\mathsf{upd}}_{r,j}$ (`c1 = init_c1 + \sum \Delta c1`).
    pub updates: Vec<RowUpdateProof>,
}

impl CiphertextRow {
    /// Check in $O(1)$ (`1` $\mathbb{G}_1$ scalar mul, `0` pairings) whether `secret_key` matches
    /// this row's `oblivious_hint` without inspecting `seat_id` (`UI v5` `F-01`).
    #[must_use]
    pub fn matches_oblivious_hint(&self, secret_key: &SeatSecretKey) -> bool {
        let shared = self.init_c2 * secret_key.sk;
        let expected = compute_oblivious_key_hint(&shared);
        bool::from(self.oblivious_hint.ct_eq(&expected))
    }
}

/// Policy-matched independent $\mathbb{G}_1$-LSSS Sealed Basis Commitment slot (`ePrint v2` §6.1 Step 4).
///
/// Encrypts **only** auxiliary column commitments $(V_{\text{col\_offset}}, \dots, V_{\text{col\_offset}+\text{col\_count}-1})$
/// (`col_offset >= 1` strictly — **never $V_0 = s G_1$!**) under an independent target-group secret
/// $K_{\mathsf{sbc}} \in \mathbb{G}_T$ and independent sharing vector $v_{\mathsf{sbc}} \in \mathbb{F}_r^k$
/// over the current `(M_E, \rho_E)` policy (zero KDM cycles, zero unilateral `ACU` decryption, and
/// zero sub-threshold escalation rollback).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SbcSlot {
    /// Epoch at which this slot's symmetric ciphertext was sealed (`>= 1`).
    pub created_epoch: u64,
    /// Starting auxiliary column index (`>= 1` strictly; column `0` / $V_0$ is forbidden).
    pub col_offset: usize,
    /// Number of auxiliary $\mathbb{G}_1$ commitments encrypted in `ciphertext` (`48 * col_count + 16` B).
    pub col_count: usize,
    /// Independent $\mathbb{G}_1$ preimage $c_{0,\mathsf{sbc},\mathbb{G}_1} = \kappa_{\mathsf{sbc}} G_1 + s_{\mathsf{sbc}} G_1$.
    pub c0_g1: G1Projective,
    /// `96`-bit ChaCha20-Poly1305 nonce.
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 ciphertext encrypting `col_count` compressed `48`-byte $\mathbb{G}_1$ points.
    pub ciphertext: Vec<u8>,
    /// Policy-matched $\mathbb{G}_1$-LSSS rows aligned 1-to-1 with [`AcuCiphertext::rows`].
    pub rows: Vec<CiphertextRow>,
}

/// Pairing-based ACU header ciphertext (`CHWGACU3`) with zero-$V_0$ policy-matched `SBC` slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcuCiphertext {
    /// Stable 32-byte object digest $O$.
    pub object_digest: [u8; 32],
    /// Monotonically increasing policy epoch counter (`>= 1`).
    pub policy_epoch: u64,
    /// Seat identifier of the `ACU` operator authorized to apply ciphertext-only policy evolutions
    /// (holds **zero** unilateral decryption capability over `c0` or `sbc_slots`).
    pub acu_seat_id: String,
    /// Masked $\mathbb{G}_1$ preimage $c_{0,\mathbb{G}_1} = K_{\mathbb{G}_1} + s^{(E)} G_1 \in \mathbb{G}_1$.
    pub c0_g1: G1Projective,
    /// Masked target-group payload key $c_0 = e(c_{0,\mathbb{G}_1}, G_2) = K_{\mathbb{G}_T} \cdot g_T^{s^{(E)}} \in \mathbb{G}_T$.
    pub c0: Gt,
    /// Current LSSS policy matrix $(M_E, \rho_E, \mathcal{D}_{\mathsf{gate}})$ over $\mathbb{F}_r$.
    pub matrix: LsssMatrix,
    /// Per-row two-element $\mathbb{G}_1$ ciphertexts and randomness proofs.
    pub rows: Vec<CiphertextRow>,
    /// Zero-$V_0$ policy-matched independent $\mathbb{G}_1$-LSSS auxiliary commitment slots $\mathsf{SBC}_E$.
    pub sbc_slots: Vec<SbcSlot>,
    /// Algebraic Schnorr signature under `acu_pk.pk1` authenticating dynamic policy evolutions (`policy_epoch >= 2`).
    pub acu_epoch_auth: Option<RowPok>,
}

impl AcuCiphertext {
    /// Compute the deterministic 32-byte SHA-256 digest $h_{H_E}$ of this `AcuCiphertext` header.
    #[must_use]
    pub fn header_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(HEADER_DIGEST_DOMAIN);
        h.update(self.to_bytes());
        h.finalize().into()
    }

    /// Validate full structural equivalence across `self.matrix`, `self.rows`, and all `self.sbc_slots`,
    /// including strict zero-$V_0$ enforcement (`slot.col_offset >= 1` and exact ciphertext byte lengths).
    pub fn validate_structure(&self) -> Result<(), AcuError> {
        if self.policy_epoch == 0 {
            return Err(AcuError::SerializationError("policy_epoch must be >= 1"));
        }
        if !is_valid_seat_id(&self.acu_seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
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
            if row.row_index != expected_idx
                || row.seat_id != *mat_seat
                || !bool::from(row.object_digest.ct_eq(&self.object_digest))
            {
                return Err(AcuError::SerializationError(
                    "AcuCiphertext rows/matrix seat, object_digest, or index mismatch",
                ));
            }
            if row.matrix_row != *mat_vec {
                return Err(AcuError::DimensionMismatch {
                    expected: mat_vec.len(),
                    actual: row.matrix_row.len(),
                });
            }
            if row.updates.len() > MAX_ROW_UPDATES {
                return Err(AcuError::SerializationError("too many row updates"));
            }
        }

        if self.sbc_slots.is_empty() || self.sbc_slots.len() > MAX_SBC_SLOTS {
            return Err(AcuError::SerializationError("invalid sbc_slots count"));
        }
        for slot in &self.sbc_slots {
            if slot.created_epoch == 0 || slot.created_epoch > self.policy_epoch {
                return Err(AcuError::SerializationError("invalid SbcSlot epoch"));
            }
            // HARD ZERO-V_0 INVARIANT: column 0 (`s * G_1`) may NEVER appear in any SbcSlot!
            if slot.col_offset == 0 {
                return Err(AcuError::SerializationError(
                    "SbcSlot col_offset == 0 forbidden (zero-V_0 invariant)",
                ));
            }
            let end_col = slot
                .col_offset
                .checked_add(slot.col_count)
                .ok_or(AcuError::SerializationError("SbcSlot column overflow"))?;
            if self.matrix.cols == 1 {
                if slot.col_offset != 1 || slot.col_count != 0 {
                    return Err(AcuError::SerializationError(
                        "SbcSlot non-empty on 1-column matrix",
                    ));
                }
            } else if end_col > self.matrix.cols {
                return Err(AcuError::DimensionMismatch {
                    expected: self.matrix.cols,
                    actual: end_col,
                });
            }
            let expected_ct_len = slot
                .col_count
                .checked_mul(48)
                .and_then(|n| n.checked_add(POLY1305_TAG_BYTES))
                .ok_or(AcuError::SerializationError("SbcSlot ciphertext overflow"))?;
            if slot.ciphertext.len() != expected_ct_len {
                return Err(AcuError::SerializationError(
                    "SbcSlot ciphertext length mismatch",
                ));
            }
            if slot.rows.len() != self.rows.len() {
                return Err(AcuError::DimensionMismatch {
                    expected: self.rows.len(),
                    actual: slot.rows.len(),
                });
            }
            for (idx, (s_row, m_row)) in slot.rows.iter().zip(self.rows.iter()).enumerate() {
                if s_row.row_index != idx
                    || s_row.seat_id != m_row.seat_id
                    || s_row.matrix_row != m_row.matrix_row
                    || !bool::from(s_row.object_digest.ct_eq(&self.object_digest))
                {
                    return Err(AcuError::SerializationError("SbcSlot row alignment error"));
                }
            }
        }
        Ok(())
    }

    /// Serialize this [`AcuCiphertext`] into canonical `CHWGACU3` bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_internal(false)
    }

    /// Serialize this [`AcuCiphertext`] into Blind-Relay / R2-Parquet `CHWGACU3` bytes where every
    /// cleartext `seat_id` is replaced on the wire by its pseudonymous blind locator handle
    /// (`"blind:<hex>"`), leaking zero roster strings to $\mathcal{A}_1$ (`UI v5` `F-01`, `ePrint v2` §7).
    #[must_use]
    pub fn to_blind_bytes(&self) -> Vec<u8> {
        self.encode_internal(true)
    }

    fn encode_internal(&self, blind_seats: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ACU_CT_MAGIC);
        out.extend_from_slice(&self.object_digest);
        out.extend_from_slice(&self.policy_epoch.to_be_bytes());

        let acu_wire_id = if blind_seats {
            let loc = compute_blind_row_locator(
                &self.object_digest,
                &self.object_digest,
                1,
                u32::MAX,
                &self.acu_seat_id,
            );
            blind_handle_from_locator(&loc)
        } else {
            self.acu_seat_id.clone()
        };
        lp64_str(&mut out, &acu_wire_id);

        out.extend_from_slice(&(self.matrix.cols as u32).to_be_bytes());
        out.extend_from_slice(&(self.rows.len() as u32).to_be_bytes());
        out.extend_from_slice(&G1Affine::from(self.c0_g1).to_compressed());
        self.matrix.encode_gates(&mut out);

        for row in &self.rows {
            encode_ciphertext_row(&mut out, row, blind_seats);
        }

        out.extend_from_slice(&(self.sbc_slots.len() as u32).to_be_bytes());
        for slot in &self.sbc_slots {
            out.extend_from_slice(&slot.created_epoch.to_be_bytes());
            out.extend_from_slice(&(slot.col_offset as u32).to_be_bytes());
            out.extend_from_slice(&(slot.col_count as u32).to_be_bytes());
            out.extend_from_slice(&G1Affine::from(slot.c0_g1).to_compressed());
            out.extend_from_slice(&slot.nonce);
            out.extend_from_slice(&(slot.ciphertext.len() as u64).to_be_bytes());
            out.extend_from_slice(&slot.ciphertext);
            for s_row in &slot.rows {
                encode_ciphertext_row(&mut out, s_row, blind_seats);
            }
        }
        match &self.acu_epoch_auth {
            None => out.push(0u8),
            Some(pok) => {
                out.push(1u8);
                out.extend_from_slice(&pok.to_bytes());
            }
        }
        out
    }

    /// Compute the canonical core digest covered by `acu_epoch_auth` (`acu_sk.sk` Schnorr signature)
    /// across dynamic policy evolutions (`policy_epoch >= 2`), invariant across `to_blind_bytes` -> `resolve_blind_seats`.
    fn epoch_auth_core_digest(&self) -> [u8; 32] {
        let mut copy = self.clone();
        copy.acu_epoch_auth = None;
        let encoded = copy.to_bytes();
        let mut h = Sha256::new();
        h.update(b"chinwag.acu.v2.epoch-auth-core");
        h.update((encoded.len() as u64).to_be_bytes());
        h.update(&encoded);
        h.finalize().into()
    }

    pub(crate) fn sign_epoch_auth(&mut self, acu_sk: &SeatSecretKey) -> Result<(), AcuError> {
        let core = self.epoch_auth_core_digest();
        let g1 = G1Projective::generator();
        let pk1_aff = G1Affine::from(g1 * acu_sk.sk);
        let sk_bytes = Zeroizing::new(acu_sk.sk.to_bytes());
        for ctr in 0u32.. {
            let mut nonce_msg = Zeroizing::new([0u8; 68]);
            nonce_msg[..32].copy_from_slice(&*sk_bytes);
            nonce_msg[32..64].copy_from_slice(&core);
            nonce_msg[64..68].copy_from_slice(&ctr.to_be_bytes());
            let mut k = hash_to_nonzero_scalar(&nonce_msg[..], b"chinwag.acu.v2.epoch-auth-k")?;
            let r_aff = G1Affine::from(g1 * k);
            if bool::from(r_aff.is_identity()) {
                k.zeroize();
                continue;
            }
            let mut ch_msg = [0u8; 32 + 48 + 48];
            ch_msg[..32].copy_from_slice(&core);
            ch_msg[32..80].copy_from_slice(&pk1_aff.to_compressed());
            ch_msg[80..128].copy_from_slice(&r_aff.to_compressed());
            let ch = hash_to_nonzero_scalar(&ch_msg, b"chinwag.acu.v2.epoch-auth-ch")?;
            let z = k + ch * acu_sk.sk;
            k.zeroize();
            if !bool::from(z.is_zero()) {
                self.acu_epoch_auth = Some(RowPok {
                    challenge: ch,
                    response: z,
                });
                return Ok(());
            }
        }
        unreachable!("unbounded counter finds valid epoch_auth nonce w.h.p.")
    }

    fn verify_epoch_auth(&self, acu_pk: &SeatPublicKey, pok: &RowPok) -> bool {
        if self.policy_epoch < 2
            || bool::from(pok.challenge.is_zero())
            || bool::from(pok.response.is_zero())
        {
            return false;
        }
        let core = self.epoch_auth_core_digest();
        let pk1_aff = G1Affine::from(acu_pk.pk1);
        let r_pt = G1Projective::generator() * pok.response - acu_pk.pk1 * pok.challenge;
        let r_aff = G1Affine::from(r_pt);
        if bool::from(r_aff.is_identity()) {
            return false;
        }
        let mut ch_msg = [0u8; 32 + 48 + 48];
        ch_msg[..32].copy_from_slice(&core);
        ch_msg[32..80].copy_from_slice(&pk1_aff.to_compressed());
        ch_msg[80..128].copy_from_slice(&r_aff.to_compressed());
        let Ok(expected) = hash_to_nonzero_scalar(&ch_msg, b"chinwag.acu.v2.epoch-auth-ch") else {
            return false;
        };
        bool::from(pok.challenge.to_bytes().ct_eq(&expected.to_bytes()))
    }

    /// Cryptographically authenticate this [`AcuCiphertext`] (`CHWGACU3`) before any online custodian
    /// (`CisoAcuFatClient`) applies its secret key:
    /// 1. Validates structure and zero-$V_0$ `SbcSlot` bounds,
    /// 2. Enforces either `acu_epoch_auth` (Schnorr proof under `acu_pk.pk1` for dynamic policy evolutions)
    ///    OR exact initial matrix digest match (`row.init_matrix_digest == self.matrix.canonical_digest()`
    ///    with `updates.is_empty()` and `init_epoch == policy_epoch`), blocking cut-and-paste row splicing, and
    /// 3. Verifies every row's pure-$\mathbb{G}_1$ `RowPok` + `RowUpdateProof` randomness chain across
    ///    both `self.rows` and `self.sbc_slots`.
    pub fn verify_authenticity<'a>(
        &self,
        acu_pk: &SeatPublicKey,
        seat_lookup: impl Fn(&str) -> Option<&'a SeatPublicKey>,
    ) -> Result<(), AcuError> {
        self.validate_structure()?;
        if self.acu_seat_id != acu_pk.seat_id || !acu_pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(self.acu_seat_id.clone()));
        }

        let current_mat_digest = self.matrix.canonical_digest();
        match &self.acu_epoch_auth {
            Some(pok) => {
                if !self.verify_epoch_auth(acu_pk, pok) {
                    return Err(AcuError::BasisUnsealFailed);
                }
            }
            None => {
                for row in &self.rows {
                    if !bool::from(row.init_matrix_digest.ct_eq(&current_mat_digest)) {
                        return Err(AcuError::InvalidRowPok);
                    }
                    if row.init_epoch != self.policy_epoch || !row.updates.is_empty() {
                        return Err(AcuError::BasisUnsealFailed);
                    }
                }
                for slot in &self.sbc_slots {
                    if slot.created_epoch != self.policy_epoch {
                        return Err(AcuError::BasisUnsealFailed);
                    }
                    for s_row in &slot.rows {
                        if !bool::from(s_row.init_matrix_digest.ct_eq(&current_mat_digest)) {
                            return Err(AcuError::InvalidRowPok);
                        }
                        if s_row.init_epoch != slot.created_epoch || !s_row.updates.is_empty() {
                            return Err(AcuError::BasisUnsealFailed);
                        }
                    }
                }
            }
        }

        for row in &self.rows {
            let pk = seat_lookup(&row.seat_id)
                .ok_or_else(|| AcuError::UnknownSeat(row.seat_id.clone()))?;
            if !verify_row_randomness_chain(&self.object_digest, row, pk) {
                return Err(AcuError::InvalidRowPok);
            }
        }
        for slot in &self.sbc_slots {
            for s_row in &slot.rows {
                let pk = seat_lookup(&s_row.seat_id)
                    .ok_or_else(|| AcuError::UnknownSeat(s_row.seat_id.clone()))?;
                if !verify_row_randomness_chain(&self.object_digest, s_row, pk) {
                    return Err(AcuError::InvalidRowPok);
                }
            }
        }
        Ok(())
    }

    /// Resolve pseudonymous `"blind:..."` seat handles back to canonical seat IDs using a workspace
    /// `locator_key` and known `seat_keys` directory (or oblivious ECDH hints).
    pub fn resolve_blind_seats(
        &mut self,
        locator_key: &[u8; 32],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
    ) {
        for cand_id in seat_keys.keys() {
            let acu_loc = compute_blind_row_locator(
                &self.object_digest,
                &self.object_digest,
                1,
                u32::MAX,
                cand_id,
            );
            if self.acu_seat_id == blind_handle_from_locator(&acu_loc) {
                self.acu_seat_id = cand_id.clone();
                break;
            }
        }
        for idx in 0..self.rows.len() {
            let row = &self.rows[idx];
            let mut matched: Option<String> = None;
            for cand_id in seat_keys.keys() {
                let cand_loc = compute_blind_row_locator(
                    locator_key,
                    &self.object_digest,
                    row.init_epoch,
                    row.init_row_index,
                    cand_id,
                );
                if bool::from(cand_loc.ct_eq(&row.row_locator)) {
                    matched = Some(cand_id.clone());
                    break;
                }
            }
            if let Some(real_id) = matched {
                self.rows[idx].seat_id.clone_from(&real_id);
                self.matrix.rows[idx].0.clone_from(&real_id);
                for slot in &mut self.sbc_slots {
                    slot.rows[idx].seat_id.clone_from(&real_id);
                }
            }
        }
    }

    /// Deserialize an [`AcuCiphertext`] from canonical `CHWGACU3` bytes, failing closed with
    /// [`AcuError::InsecureLegacyFormat`] on both `CHWGACU1` (cleartext $V_0$) and `CHWGACU2`
    /// (`acu_pk`-only `SealedBasisCommitments` unilateral backdoor).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AcuError> {
        let mut cursor = 0usize;
        let magic = take_slice(bytes, &mut cursor, 8)?;
        if magic == LEGACY_ACU_CT_MAGIC_V1 {
            return Err(AcuError::InsecureLegacyFormat("CHWGACU1"));
        }
        if magic == LEGACY_ACU_CT_MAGIC_V2 {
            return Err(AcuError::InsecureLegacyFormat("CHWGACU2"));
        }
        if magic != ACU_CT_MAGIC {
            return Err(AcuError::SerializationError("invalid AcuCiphertext magic"));
        }

        let obj_slice = take_slice(bytes, &mut cursor, 32)?;
        let mut object_digest = [0u8; 32];
        object_digest.copy_from_slice(obj_slice);

        let policy_epoch = read_u64_be(bytes, &mut cursor)?;
        if policy_epoch == 0 {
            return Err(AcuError::SerializationError("policy_epoch must be >= 1"));
        }

        let acu_seat_id = read_lp64_str(bytes, &mut cursor, MAX_SEAT_ID_BYTES)?;
        if !is_valid_seat_id(&acu_seat_id) {
            return Err(AcuError::InvalidSeatId);
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

        let c0_g1 = read_g1_compressed(bytes, &mut cursor)?;
        let c0 = pairing(&G1Affine::from(c0_g1), &G2Affine::generator());
        let gates = LsssMatrix::decode_gates(bytes, &mut cursor, num_rows)?;

        let mut rows = Vec::with_capacity(num_rows);
        let mut matrix_rows = Vec::with_capacity(num_rows);
        for expected_idx in 0..num_rows {
            let row =
                decode_ciphertext_row(bytes, &mut cursor, &object_digest, expected_idx, cols)?;
            matrix_rows.push((row.seat_id.clone(), row.matrix_row.clone()));
            rows.push(row);
        }

        let num_slots = read_u32_be(bytes, &mut cursor)? as usize;
        if num_slots == 0 || num_slots > MAX_SBC_SLOTS {
            return Err(AcuError::SerializationError("invalid sbc_slots count"));
        }
        let mut sbc_slots = Vec::with_capacity(num_slots);
        for _ in 0..num_slots {
            let created_epoch = read_u64_be(bytes, &mut cursor)?;
            let col_offset = read_u32_be(bytes, &mut cursor)? as usize;
            let col_count = read_u32_be(bytes, &mut cursor)? as usize;
            if col_offset == 0 {
                return Err(AcuError::SerializationError(
                    "SbcSlot col_offset == 0 forbidden (zero-V_0 invariant)",
                ));
            }
            let max_ct_len = col_count
                .checked_mul(48)
                .and_then(|n| n.checked_add(POLY1305_TAG_BYTES))
                .ok_or(AcuError::SerializationError("SbcSlot ciphertext overflow"))?;
            let slot_c0_g1 = read_g1_compressed(bytes, &mut cursor)?;
            let nonce_slice = take_slice(bytes, &mut cursor, 12)?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(nonce_slice);
            let ct_slice = read_lp64(bytes, &mut cursor, max_ct_len)?;
            if ct_slice.len() != max_ct_len {
                return Err(AcuError::SerializationError(
                    "SbcSlot ciphertext length mismatch",
                ));
            }
            let mut slot_rows = Vec::with_capacity(num_rows);
            for expected_idx in 0..num_rows {
                slot_rows.push(decode_ciphertext_row(
                    bytes,
                    &mut cursor,
                    &object_digest,
                    expected_idx,
                    cols,
                )?);
            }
            sbc_slots.push(SbcSlot {
                created_epoch,
                col_offset,
                col_count,
                c0_g1: slot_c0_g1,
                nonce,
                ciphertext: ct_slice.to_vec(),
                rows: slot_rows,
            });
        }

        let has_epoch_auth = read_u8(bytes, &mut cursor)?;
        let acu_epoch_auth = match has_epoch_auth {
            0 => None,
            1 => {
                let auth_slice = take_slice(bytes, &mut cursor, 64)?;
                let mut auth_arr = [0u8; 64];
                auth_arr.copy_from_slice(auth_slice);
                Some(RowPok::from_bytes(&auth_arr)?)
            }
            _ => {
                return Err(AcuError::SerializationError(
                    "invalid acu_epoch_auth presence tag",
                ));
            }
        };

        if cursor != bytes.len() {
            return Err(AcuError::SerializationError(
                "trailing bytes in AcuCiphertext",
            ));
        }

        let matrix = LsssMatrix {
            cols,
            rows: matrix_rows,
            gates,
        };
        let ct = Self {
            object_digest,
            policy_epoch,
            acu_seat_id,
            c0_g1,
            c0,
            matrix,
            rows,
            sbc_slots,
            acu_epoch_auth,
        };
        ct.validate_structure()?;
        Ok(ct)
    }
}

fn blind_handle_from_locator(locator: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(6 + 32);
    s.push_str("blind:");
    for &b in &locator[..16] {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn encode_ciphertext_row(out: &mut Vec<u8>, row: &CiphertextRow, blind_seats: bool) {
    out.extend_from_slice(&(row.row_index as u32).to_be_bytes());
    let wire_seat = if blind_seats {
        blind_handle_from_locator(&row.row_locator)
    } else {
        row.seat_id.clone()
    };
    lp64_str(out, &wire_seat);
    out.extend_from_slice(&row.row_locator);
    out.extend_from_slice(&row.oblivious_hint);
    for scalar in &row.matrix_row {
        out.extend_from_slice(&scalar.to_bytes());
    }
    out.extend_from_slice(&G1Affine::from(row.c1).to_compressed());
    out.extend_from_slice(&G1Affine::from(row.c2).to_compressed());
    out.extend_from_slice(&row.init_epoch.to_be_bytes());
    out.extend_from_slice(&row.init_row_index.to_be_bytes());
    out.extend_from_slice(&row.init_matrix_digest);
    out.extend_from_slice(&G1Affine::from(row.init_c1).to_compressed());
    out.extend_from_slice(&G1Affine::from(row.init_c2).to_compressed());
    out.extend_from_slice(&row.row_pok.to_bytes());
    out.extend_from_slice(&(row.updates.len() as u32).to_be_bytes());
    for upd in &row.updates {
        out.extend_from_slice(&upd.epoch.to_be_bytes());
        out.extend_from_slice(&upd.prev_header_digest);
        out.extend_from_slice(&upd.row_index.to_be_bytes());
        out.extend_from_slice(&G1Affine::from(upd.delta_c1).to_compressed());
        out.extend_from_slice(&G1Affine::from(upd.delta_c2).to_compressed());
        out.extend_from_slice(&upd.pok.to_bytes());
    }
}

fn decode_ciphertext_row(
    bytes: &[u8],
    cursor: &mut usize,
    object_digest: &[u8; 32],
    expected_idx: usize,
    cols: usize,
) -> Result<CiphertextRow, AcuError> {
    let row_index = read_u32_be(bytes, cursor)? as usize;
    if row_index != expected_idx {
        return Err(AcuError::SerializationError("non-contiguous row_index"));
    }
    let seat_id = read_lp64_str(bytes, cursor, MAX_SEAT_ID_BYTES)?;
    if !is_valid_seat_id(&seat_id) {
        return Err(AcuError::InvalidSeatId);
    }
    let loc_slice = take_slice(bytes, cursor, 32)?;
    let mut row_locator = [0u8; 32];
    row_locator.copy_from_slice(loc_slice);

    let hint_slice = take_slice(bytes, cursor, 8)?;
    let mut oblivious_hint = [0u8; 8];
    oblivious_hint.copy_from_slice(hint_slice);

    let mut matrix_row = Vec::with_capacity(cols);
    for _ in 0..cols {
        matrix_row.push(read_scalar(bytes, cursor)?);
    }
    let c1 = read_g1_compressed(bytes, cursor)?;
    let c2 = read_nonidentity_g1_compressed(bytes, cursor)?;
    let init_epoch = read_u64_be(bytes, cursor)?;
    if init_epoch == 0 {
        return Err(AcuError::SerializationError("init_epoch must be >= 1"));
    }
    let init_row_index = read_u32_be(bytes, cursor)?;
    let imat_slice = take_slice(bytes, cursor, 32)?;
    let mut init_matrix_digest = [0u8; 32];
    init_matrix_digest.copy_from_slice(imat_slice);
    let init_c1 = read_g1_compressed(bytes, cursor)?;
    let init_c2 = read_nonidentity_g1_compressed(bytes, cursor)?;
    let pok_slice = take_slice(bytes, cursor, 64)?;
    let mut pok_arr = [0u8; 64];
    pok_arr.copy_from_slice(pok_slice);
    let row_pok = RowPok::from_bytes(&pok_arr)?;

    let num_updates = read_u32_be(bytes, cursor)? as usize;
    if num_updates > MAX_ROW_UPDATES {
        return Err(AcuError::SerializationError("too many row updates"));
    }
    let mut updates = Vec::with_capacity(num_updates);
    for _ in 0..num_updates {
        let epoch = read_u64_be(bytes, cursor)?;
        let prev_slice = take_slice(bytes, cursor, 32)?;
        let mut prev_header_digest = [0u8; 32];
        prev_header_digest.copy_from_slice(prev_slice);
        let upd_row_idx = read_u32_be(bytes, cursor)?;
        let delta_c1 = read_g1_compressed(bytes, cursor)?;
        let delta_c2 = read_nonidentity_g1_compressed(bytes, cursor)?;
        let upok_slice = take_slice(bytes, cursor, 64)?;
        let mut upok_arr = [0u8; 64];
        upok_arr.copy_from_slice(upok_slice);
        let pok = RowPok::from_bytes(&upok_arr)?;
        updates.push(RowUpdateProof {
            epoch,
            prev_header_digest,
            row_index: upd_row_idx,
            delta_c1,
            delta_c2,
            pok,
        });
    }

    Ok(CiphertextRow {
        object_digest: *object_digest,
        row_index,
        seat_id,
        row_locator,
        oblivious_hint,
        matrix_row,
        c1,
        c2,
        init_epoch,
        init_row_index,
        init_matrix_digest,
        init_c1,
        init_c2,
        row_pok,
        updates,
    })
}

/// Sample a fresh target-group secret $K_{\mathbb{G}_T} \in \mathbb{G}_T^*$ and encrypt it under
/// `matrix` (`CHWGACU3` zero-$V_0$ policy-matched `SBC`).
pub fn acu_encrypt(
    matrix: &LsssMatrix,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    acu_pk: &SeatPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(AcuCiphertext, Gt), AcuError> {
    let mut k_scalar = sample_nonzero_scalar(rng);
    let mut payload_g1 = G1Projective::generator() * k_scalar;
    k_scalar.zeroize();
    let mut obj_digest = [0u8; 32];
    rng.fill_bytes(&mut obj_digest);
    let mut loc_key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut loc_key[..]);
    let res = acu_encrypt_with_g1_and_context(
        &payload_g1,
        &obj_digest,
        &loc_key,
        matrix,
        seat_keys,
        acu_pk,
        rng,
    );
    payload_g1.zeroize();
    res
}

/// Encrypt a target-group element $K_{\mathbb{G}_T} = e(\text{payload\_g1}, G_2)$ under `matrix`
/// with a fresh CSPRNG object digest (`CHWGACU3`).
pub fn acu_encrypt_with_g1(
    payload_g1: &G1Projective,
    matrix: &LsssMatrix,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    acu_pk: &SeatPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(AcuCiphertext, Gt), AcuError> {
    let mut obj_digest = [0u8; 32];
    rng.fill_bytes(&mut obj_digest);
    let mut loc_key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut loc_key[..]);
    acu_encrypt_with_g1_and_context(
        payload_g1,
        &obj_digest,
        &loc_key,
        matrix,
        seat_keys,
        acu_pk,
        rng,
    )
}

/// Encrypt a target-group element $K_{\mathbb{G}_T} = e(\text{payload\_g1}, G_2)$ bound to an
/// explicit `object_digest` ($O$) and workspace `locator_key` ($k_{\mathsf{idx}}$).
pub fn acu_encrypt_with_g1_and_context(
    payload_g1: &G1Projective,
    object_digest: &[u8; 32],
    locator_key: &[u8; 32],
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
    let k = matrix.cols;

    // Full F_r^k uniform sharing vector (including 0, exact 0 statistical distance in Theorem 3(ii)).
    let mut v = Zeroizing::new(Vec::with_capacity(k));
    for _ in 0..k {
        v.push(sample_uniform_scalar(rng));
    }

    let c0_g1 = *payload_g1 + g1 * v[0];
    let payload_key = pairing(&payload_aff, &g2_aff);
    let c0 = pairing(&G1Affine::from(c0_g1), &g2_aff);

    let rows = build_lsss_rows(object_digest, 1, locator_key, matrix, &v, seat_keys, rng)?;

    // Auxiliary commitments ONLY: V_1 = v_1 * G_1 .. V_{k-1} = v_{k-1} * G_1 (OMIT V_0 = s * G_1!).
    let mut v_aux: Vec<G1Projective> = v[1..].iter().map(|vm| g1 * vm).collect();
    let slot1 = seal_sbc_slot(
        object_digest,
        1,
        1,
        &v_aux,
        locator_key,
        matrix,
        seat_keys,
        rng,
    )?;
    for pt in &mut v_aux {
        pt.zeroize();
    }

    let ct = AcuCiphertext {
        object_digest: *object_digest,
        policy_epoch: 1,
        acu_seat_id: acu_pk.seat_id.clone(),
        c0_g1,
        c0,
        matrix: matrix.clone(),
        rows,
        sbc_slots: vec![slot1],
        acu_epoch_auth: None,
    };
    ct.validate_structure()?;
    Ok((ct, payload_key))
}

fn build_lsss_rows(
    object_digest: &[u8; 32],
    epoch: u64,
    locator_key: &[u8; 32],
    matrix: &LsssMatrix,
    v: &[Scalar],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<CiphertextRow>, AcuError> {
    let g1 = G1Projective::generator();
    let init_matrix_digest = matrix.canonical_digest();
    let mut rows = Vec::with_capacity(matrix.rows.len());
    for (row_idx, (seat_id, m_row)) in matrix.rows.iter().enumerate() {
        let pk = seat_keys
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.clone()))?;
        let mut lambda_j = m_row
            .iter()
            .zip(v.iter())
            .fold(Scalar::ZERO, |acc, (&m, &vm)| acc + m * vm);
        let mut r_j = sample_nonzero_scalar(rng);
        let shared_pt = pk.pk1 * r_j;
        let c1 = g1 * lambda_j + shared_pt;
        let c2 = g1 * r_j;
        lambda_j.zeroize();

        let row_locator =
            compute_blind_row_locator(locator_key, object_digest, epoch, row_idx as u32, seat_id);
        let oblivious_hint = compute_oblivious_key_hint(&shared_pt);
        let row_pok = prove_row_pok(
            object_digest,
            &init_matrix_digest,
            epoch,
            row_idx as u32,
            &row_locator,
            &pk.pk1,
            &c1,
            &c2,
            &r_j,
            rng,
        )?;
        r_j.zeroize();

        rows.push(CiphertextRow {
            object_digest: *object_digest,
            row_index: row_idx,
            seat_id: seat_id.clone(),
            row_locator,
            oblivious_hint,
            matrix_row: m_row.clone(),
            c1,
            c2,
            init_epoch: epoch,
            init_row_index: row_idx as u32,
            init_matrix_digest,
            init_c1: c1,
            init_c2: c2,
            row_pok,
            updates: Vec::new(),
        });
    }
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn seal_sbc_slot(
    object_digest: &[u8; 32],
    epoch: u64,
    col_offset: usize,
    aux_points: &[G1Projective],
    locator_key: &[u8; 32],
    matrix: &LsssMatrix,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<SbcSlot, AcuError> {
    if col_offset == 0 {
        return Err(AcuError::SerializationError(
            "SbcSlot col_offset == 0 forbidden (zero-V_0 invariant)",
        ));
    }
    let g1 = G1Projective::generator();
    let g2_aff = G2Affine::generator();

    let mut kappa_sbc = sample_nonzero_scalar(rng);
    let mut k_sbc_g1 = g1 * kappa_sbc;
    kappa_sbc.zeroize();
    let k_sbc_gt = pairing(&G1Affine::from(k_sbc_g1), &g2_aff);

    let mut v_sbc = Zeroizing::new(Vec::with_capacity(matrix.cols));
    for _ in 0..matrix.cols {
        v_sbc.push(sample_uniform_scalar(rng));
    }
    let c0_g1 = k_sbc_g1 + g1 * v_sbc[0];
    k_sbc_g1.zeroize();

    let mut slot_loc_key = Zeroizing::new([0u8; 32]);
    let mut slot_mac = <HmacSha256 as Mac>::new_from_slice(locator_key)
        .expect("HMAC-SHA256 accepts 32-byte locator key");
    slot_mac.update(b"sbc-slot-loc");
    slot_mac.update(&epoch.to_be_bytes());
    slot_loc_key.copy_from_slice(&slot_mac.finalize().into_bytes());

    let slot_rows = build_lsss_rows(
        object_digest,
        epoch,
        &slot_loc_key,
        matrix,
        &v_sbc,
        seat_keys,
        rng,
    )?;

    let mut pt_bytes = Zeroizing::new(Vec::with_capacity(aux_points.len() * 48));
    for pt in aux_points {
        pt_bytes.extend_from_slice(&G1Affine::from(*pt).to_compressed());
    }

    let sym_key = derive_sbc_slot_key(
        &k_sbc_gt,
        object_digest,
        epoch,
        col_offset,
        aux_points.len(),
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*sym_key));
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let aad = encode_sbc_slot_aad(object_digest, epoch, col_offset, aux_points.len());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt_bytes,
                aad: &aad,
            },
        )
        .map_err(|_| AcuError::AeadFailure)?;

    Ok(SbcSlot {
        created_epoch: epoch,
        col_offset,
        col_count: aux_points.len(),
        c0_g1,
        nonce,
        ciphertext,
        rows: slot_rows,
    })
}

fn unseal_sbc_slot_with_weights(
    object_digest: &[u8; 32],
    slot: &SbcSlot,
    weights: &[(usize, Scalar)],
    slot_shares_by_row: &BTreeMap<usize, G1Projective>,
) -> Result<Vec<G1Projective>, AcuError> {
    let mut s_sbc_g1 = G1Projective::identity();
    for &(row_idx, omega) in weights {
        let share_pt = slot_shares_by_row
            .get(&row_idx)
            .ok_or(AcuError::PolicyNotSatisfied)?;
        s_sbc_g1 += *share_pt * omega;
    }
    let mut k_sbc_g1 = slot.c0_g1 - s_sbc_g1;
    let k_sbc_gt = pairing(&G1Affine::from(k_sbc_g1), &G2Affine::generator());
    k_sbc_g1.zeroize();

    let sym_key = derive_sbc_slot_key(
        &k_sbc_gt,
        object_digest,
        slot.created_epoch,
        slot.col_offset,
        slot.col_count,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*sym_key));
    let aad = encode_sbc_slot_aad(
        object_digest,
        slot.created_epoch,
        slot.col_offset,
        slot.col_count,
    );
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&slot.nonce),
                Payload {
                    msg: &slot.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| AcuError::BasisUnsealFailed)?,
    );
    if pt.len() != slot.col_count * 48 {
        return Err(AcuError::BasisUnsealFailed);
    }
    let mut cursor = 0usize;
    let mut points = Vec::with_capacity(slot.col_count);
    for _ in 0..slot.col_count {
        points.push(read_g1_compressed(&pt, &mut cursor).map_err(|_| AcuError::BasisUnsealFailed)?);
    }
    Ok(points)
}

fn derive_sbc_slot_key(
    k_sbc_gt: &Gt,
    object_digest: &[u8; 32],
    created_epoch: u64,
    col_offset: usize,
    col_count: usize,
) -> Result<Zeroizing<[u8; 32]>, AcuError> {
    let gt_bytes = gt_canonical_bytes(k_sbc_gt)?;
    let hk = Hkdf::<Sha256>::new(Some(SBC_HKDF_SALT), &*gt_bytes);
    let mut info = Vec::with_capacity(SBC_HKDF_INFO_DOMAIN.len() + 32 + 8 + 8);
    info.extend_from_slice(SBC_HKDF_INFO_DOMAIN);
    info.extend_from_slice(object_digest);
    info.extend_from_slice(&created_epoch.to_be_bytes());
    info.extend_from_slice(&(col_offset as u32).to_be_bytes());
    info.extend_from_slice(&(col_count as u32).to_be_bytes());

    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *key)
        .map_err(|_| AcuError::AeadFailure)?;
    Ok(key)
}

fn encode_sbc_slot_aad(
    object_digest: &[u8; 32],
    created_epoch: u64,
    col_offset: usize,
    col_count: usize,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SBC_AAD_DOMAIN.len() + 32 + 8 + 8);
    aad.extend_from_slice(SBC_AAD_DOMAIN);
    aad.extend_from_slice(object_digest);
    aad.extend_from_slice(&created_epoch.to_be_bytes());
    aad.extend_from_slice(&(col_offset as u32).to_be_bytes());
    aad.extend_from_slice(&(col_count as u32).to_be_bytes());
    aad
}

/// Compute a verifiable `48`-byte $\mathbb{G}_1$ partial decryption share (default Mode A `Compact` `64` B)
/// at `row`'s latest recorded epoch (`updates.last().map_or(init_epoch, |u| u.epoch)`).
#[must_use]
pub fn acu_partial_decrypt(
    row: &CiphertextRow,
    secret_key: &SeatSecretKey,
) -> PartialDecryptionShare {
    let latest_epoch = row.updates.last().map_or(row.init_epoch, |u| u.epoch);
    acu_partial_decrypt_at_epoch(row, secret_key, latest_epoch)
}

/// Compute a verifiable `48`-byte $\mathbb{G}_1$ partial decryption share (default Mode A `Compact` `64` B)
/// at `policy_epoch`.
#[must_use]
pub fn acu_partial_decrypt_at_epoch(
    row: &CiphertextRow,
    secret_key: &SeatSecretKey,
    policy_epoch: u64,
) -> PartialDecryptionShare {
    emit_partial_share_with_mode(
        &row.object_digest,
        row,
        secret_key,
        policy_epoch,
        DleqMode::Compact,
    )
}

/// Compute a verifiable `48`-byte $\mathbb{G}_1$ partial decryption share in an explicit [`DleqMode`]
/// (`Compact` `64` B or `Batchable` `128` B).
#[must_use]
pub fn acu_partial_decrypt_with_mode(
    row: &CiphertextRow,
    secret_key: &SeatSecretKey,
    policy_epoch: u64,
    mode: DleqMode,
) -> PartialDecryptionShare {
    emit_partial_share_with_mode(&row.object_digest, row, secret_key, policy_epoch, mode)
}

/// Verify a [`PartialDecryptionShare`] purely in $\mathbb{G}_1$ (`0` pairings!) against `row` and `seat_pk`.
#[must_use]
pub fn acu_verify_partial_share(
    row: &CiphertextRow,
    seat_pk: &SeatPublicKey,
    share: &PartialDecryptionShare,
) -> bool {
    verify_partial_share_for_object(&row.object_digest, share.policy_epoch, row, seat_pk, share)
}

/// Verify the complete pure-$\mathbb{G}_1$ row-randomness proof chain (`row_pok` + `updates`) on `row`.
#[must_use]
pub fn verify_row_randomness_witness(row: &CiphertextRow, seat_pk: &SeatPublicKey) -> bool {
    verify_row_randomness_chain(&row.object_digest, row, seat_pk)
}

/// Combine verified `48`-byte $\mathbb{G}_1$ partial decryption shares using **only 1 pairing total**:
///
/// $$S = \sum_{j \in \Gamma} \omega_j S_j = s^{(E)} G_1 \in \mathbb{G}_1, \qquad
///   K_{\mathbb{G}_T} = e(c_{0,\mathbb{G}_1} - S,\, G_2) = c_0 \cdot e(S, G_2)^{-1}.$$
///
/// Automatically uses fast batch verification when Mode B (`Batchable`) shares are supplied, and
/// isolates the exact offending row via recursive binary splitting if a batch fails.
pub fn acu_combine(
    ct: &AcuCiphertext,
    shares: &[PartialDecryptionShare],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
) -> Result<Gt, AcuError> {
    ct.validate_structure()?;

    // Pre-check epoch, bounds, and seat existence so callers receive deterministic typed errors.
    for share in shares {
        if share.policy_epoch != ct.policy_epoch {
            return Err(AcuError::EpochMismatch {
                expected: ct.policy_epoch,
                actual: share.policy_epoch,
            });
        }
        let row = ct
            .rows
            .get(share.row_index)
            .ok_or(AcuError::RowIndexOutOfBounds {
                index: share.row_index,
                total_rows: ct.rows.len(),
            })?;
        let pk = seat_keys
            .get(&row.seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(row.seat_id.clone()))?;
        if !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(row.seat_id.clone()));
        }
    }

    if !shares.is_empty()
        && !batch_verify_partial_shares(
            &ct.object_digest,
            ct.policy_epoch,
            &ct.rows,
            seat_keys,
            shares,
        )
    {
        for share in shares {
            let row = &ct.rows[share.row_index];
            let pk = &seat_keys[&row.seat_id];
            if !verify_partial_share_for_object(&ct.object_digest, ct.policy_epoch, row, pk, share)
            {
                return Err(AcuError::InvalidPartialShare {
                    row_index: share.row_index,
                    seat_id: share.seat_id.clone(),
                });
            }
        }
        return Err(AcuError::InvalidPartialShare {
            row_index: shares[0].row_index,
            seat_id: shares[0].seat_id.clone(),
        });
    }

    acu_combine_unverified(ct, shares)
}

/// Combine partial decryption shares in $\mathbb{G}_1$ using **1 pairing total** when DLEQ proofs
/// have already been verified upstream (still enforces structural, epoch, and `object_digest` checks).
pub fn acu_combine_unverified(
    ct: &AcuCiphertext,
    shares: &[PartialDecryptionShare],
) -> Result<Gt, AcuError> {
    ct.validate_structure()?;
    if shares.is_empty() {
        return Err(AcuError::PolicyNotSatisfied);
    }

    let mut share_by_row: BTreeMap<usize, &PartialDecryptionShare> = BTreeMap::new();
    let mut available_indices = Vec::with_capacity(shares.len());
    for share in shares {
        if share.policy_epoch != ct.policy_epoch {
            return Err(AcuError::EpochMismatch {
                expected: ct.policy_epoch,
                actual: share.policy_epoch,
            });
        }
        let row = ct
            .rows
            .get(share.row_index)
            .ok_or(AcuError::RowIndexOutOfBounds {
                index: share.row_index,
                total_rows: ct.rows.len(),
            })?;
        if share.seat_id != row.seat_id || !bool::from(share.object_digest.ct_eq(&ct.object_digest))
        {
            return Err(AcuError::InvalidPartialShare {
                row_index: share.row_index,
                seat_id: share.seat_id.clone(),
            });
        }
        if let Some(existing) = share_by_row.get(&share.row_index) {
            if existing.share_g1 != share.share_g1 {
                return Err(AcuError::InvalidPartialShare {
                    row_index: share.row_index,
                    seat_id: share.seat_id.clone(),
                });
            }
        } else {
            share_by_row.insert(share.row_index, share);
            available_indices.push(share.row_index);
        }
    }

    let weights = find_reconstruction_weights(&ct.matrix, &available_indices)?;
    let mut s_g1 = G1Projective::identity();
    for (row_idx, omega) in weights {
        let share = share_by_row
            .get(&row_idx)
            .ok_or(AcuError::PolicyNotSatisfied)?;
        s_g1 += share.share_g1 * omega;
    }

    let mut payload_g1 = ct.c0_g1 - s_g1;
    let payload_gt = pairing(&G1Affine::from(payload_g1), &G2Affine::generator());
    payload_g1.zeroize();
    Ok(payload_gt)
}

fn verify_acu_operator(
    ct: &AcuCiphertext,
    acu_sk: &SeatSecretKey,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
) -> Result<(), AcuError> {
    if acu_sk.seat_id != ct.acu_seat_id {
        return Err(AcuError::UnauthorizedPolicyOperator);
    }
    let acu_pk = seat_keys
        .get(&ct.acu_seat_id)
        .ok_or_else(|| AcuError::UnknownSeat(ct.acu_seat_id.clone()))?;
    if !acu_pk.verify_consistency() {
        return Err(AcuError::InvalidPublicKey(ct.acu_seat_id.clone()));
    }
    let derived_pk1 = G1Projective::generator() * acu_sk.sk;
    if !bool::from(
        G1Affine::from(derived_pk1)
            .to_compressed()
            .ct_eq(&G1Affine::from(acu_pk.pk1).to_compressed()),
    ) {
        return Err(AcuError::UnauthorizedPolicyOperator);
    }
    Ok(())
}

/// Ciphertext-only homomorphic revocation and rerandomization (`ePrint v2` §6.3 Op 1).
///
/// Operates **without** unsealing `sbc_slots` or knowing $V_0 = s G_1$, **refusing self-lockout**
/// (`Err(AcuError::PolicyUnsatisfiableAfterRevocation)`) if pruning `revoked_seat_ids` would leave
/// $(1, 0, \dots, 0) \notin \mathsf{span}(M_{E+1})$ (for example on a `2-of-2` policy without an
/// archive fallback). For intentional CISO kill-switch lockout on a `2-of-2` split-key ciphertext,
/// call [`emergency_lock_and_rerandomize`].
pub fn revoke_and_rerandomize(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    revoked_seat_ids: &[&str],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    revoke_internal(ct, acu_sk, revoked_seat_ids, seat_keys, false, rng)
}

/// Explicit CISO emergency kill-switch revocation & rerandomization: identical to
/// [`revoke_and_rerandomize`], except permitted to prune a `2-of-2` policy into an intentionally
/// unsatisfiable `PolicyNotSatisfied` locked state (`test_1` instant CISO branch kill-switch).
pub fn emergency_lock_and_rerandomize(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    revoked_seat_ids: &[&str],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    revoke_internal(ct, acu_sk, revoked_seat_ids, seat_keys, true, rng)
}

fn revoke_internal(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    revoked_seat_ids: &[&str],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    allow_unsatisfiable_lockout: bool,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    ct.validate_structure()?;
    verify_acu_operator(ct, acu_sk, seat_keys)?;

    let revoked: BTreeSet<&str> = revoked_seat_ids.iter().copied().collect();
    let keep_mask: Vec<bool> = ct
        .rows
        .iter()
        .map(|r| !revoked.contains(r.seat_id.as_str()))
        .collect();
    if !keep_mask.iter().any(|&keep| keep) {
        return Err(AcuError::PolicyUnsatisfiableAfterRevocation);
    }

    let mut next_matrix = ct.matrix.clone();
    next_matrix.retain_rows(&keep_mask)?;
    let surviving_indices: Vec<usize> = (0..next_matrix.rows.len()).collect();
    if !allow_unsatisfiable_lockout
        && find_reconstruction_weights(&next_matrix, &surviving_indices).is_err()
    {
        return Err(AcuError::PolicyUnsatisfiableAfterRevocation);
    }

    for (seat_id, _) in &next_matrix.rows {
        let pk = seat_keys
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.clone()))?;
        if !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id.clone()));
        }
    }

    let prev_digest = ct.header_digest();
    let next_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;
    let k = next_matrix.cols;
    let g1 = G1Projective::generator();

    // Sample delta_s in F_r^* and delta_v_1..delta_v_{k-1} in F_r.
    let mut delta_v = Zeroizing::new(Vec::with_capacity(k));
    delta_v.push(sample_nonzero_scalar(rng));
    for _ in 1..k {
        delta_v.push(sample_uniform_scalar(rng));
    }

    let next_c0_g1 = ct.c0_g1 + g1 * delta_v[0];
    let next_c0 = pairing(&G1Affine::from(next_c0_g1), &G2Affine::generator());

    let next_rows = rerandomize_kept_rows(
        &ct.object_digest,
        next_epoch,
        &prev_digest,
        &ct.rows,
        &keep_mask,
        &delta_v,
        seat_keys,
        rng,
    )?;

    // Tighten and rerandomize EVERY existing SbcSlot homomorphically (without unsealing!).
    let mut next_slots = Vec::with_capacity(ct.sbc_slots.len() + 1);
    for slot in &ct.sbc_slots {
        let mut dv_sbc = Zeroizing::new(Vec::with_capacity(k));
        dv_sbc.push(sample_nonzero_scalar(rng));
        for _ in 1..k {
            dv_sbc.push(sample_uniform_scalar(rng));
        }
        let slot_next_c0 = slot.c0_g1 + g1 * dv_sbc[0];
        let slot_next_rows = rerandomize_kept_rows(
            &ct.object_digest,
            next_epoch,
            &prev_digest,
            &slot.rows,
            &keep_mask,
            &dv_sbc,
            seat_keys,
            rng,
        )?;
        next_slots.push(SbcSlot {
            created_epoch: slot.created_epoch,
            col_offset: slot.col_offset,
            col_count: slot.col_count,
            c0_g1: slot_next_c0,
            nonce: slot.nonce,
            ciphertext: slot.ciphertext.clone(),
            rows: slot_next_rows,
        });
    }

    if k > 1 {
        let mut delta_aux: Vec<G1Projective> = delta_v[1..].iter().map(|s| g1 * s).collect();
        let mut fresh_loc_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut fresh_loc_key[..]);
        let delta_slot = seal_sbc_slot(
            &ct.object_digest,
            next_epoch,
            1,
            &delta_aux,
            &fresh_loc_key,
            &next_matrix,
            seat_keys,
            rng,
        )?;
        for pt in &mut delta_aux {
            pt.zeroize();
        }
        next_slots.push(delta_slot);
    }

    ct.policy_epoch = next_epoch;
    ct.c0_g1 = next_c0_g1;
    ct.c0 = next_c0;
    ct.matrix = next_matrix;
    ct.rows = next_rows;
    ct.sbc_slots = next_slots;
    ct.sign_epoch_auth(acu_sk)?;
    ct.validate_structure()
}

#[allow(clippy::too_many_arguments)]
fn rerandomize_kept_rows(
    object_digest: &[u8; 32],
    next_epoch: u64,
    prev_digest: &[u8; 32],
    old_rows: &[CiphertextRow],
    keep_mask: &[bool],
    delta_v: &[Scalar],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<CiphertextRow>, AcuError> {
    let g1 = G1Projective::generator();
    let mut next_rows = Vec::new();
    for (keep, old_row) in keep_mask.iter().zip(old_rows.iter()) {
        if !*keep {
            continue;
        }
        let new_idx = next_rows.len();
        let pk = seat_keys
            .get(&old_row.seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(old_row.seat_id.clone()))?;
        let mut delta_lambda = old_row
            .matrix_row
            .iter()
            .zip(delta_v.iter())
            .fold(Scalar::ZERO, |acc, (&m, &dv)| acc + m * dv);
        let mut r_prime = sample_nonzero_scalar(rng);
        let delta_c1 = g1 * delta_lambda + pk.pk1 * r_prime;
        let delta_c2 = g1 * r_prime;
        delta_lambda.zeroize();

        let pok = prove_update_row_pok(
            object_digest,
            next_epoch,
            prev_digest,
            new_idx as u32,
            &pk.pk1,
            &delta_c1,
            &delta_c2,
            &r_prime,
            rng,
        )?;
        r_prime.zeroize();

        let mut updates = old_row.updates.clone();
        updates.push(RowUpdateProof {
            epoch: next_epoch,
            prev_header_digest: *prev_digest,
            row_index: new_idx as u32,
            delta_c1,
            delta_c2,
            pok,
        });

        next_rows.push(CiphertextRow {
            object_digest: *object_digest,
            row_index: new_idx,
            seat_id: old_row.seat_id.clone(),
            row_locator: old_row.row_locator,
            oblivious_hint: old_row.oblivious_hint,
            matrix_row: old_row.matrix_row.clone(),
            c1: old_row.c1 + delta_c1,
            c2: old_row.c2 + delta_c2,
            init_epoch: old_row.init_epoch,
            init_row_index: old_row.init_row_index,
            init_matrix_digest: old_row.init_matrix_digest,
            init_c1: old_row.init_c1,
            init_c2: old_row.init_c2,
            row_pok: old_row.row_pok,
            updates,
        });
    }
    Ok(next_rows)
}

/// Ciphertext-only subtree-consistent threshold escalation (`ePrint v2` §6.3 Op 2) resolved by
/// matching leaf row indices `gate_row_indices`.
pub fn escalate_threshold(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    gate_row_indices: &[usize],
    delta_t: usize,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    let gate_id = ct.matrix.resolve_gate_for_rows(gate_row_indices)?;
    escalate_gate_threshold(ct, acu_sk, gate_id, delta_t, seat_keys, rng)
}

/// Ciphertext-only subtree-consistent threshold escalation by `gate_id` (`ePrint v2` §6.3 Op 2):
/// 1. Shares Vandermonde scalar $x_{g,c}$ identically across every leaf row $j \in C_{g,c}$ (fixing
///    nested `OR` / `AND` subtrees beneath threshold gates),
/// 2. Simultaneously samples fresh rerandomization scalars $\Delta v = (\Delta s, \Delta v_1, \dots, \Delta v_{k_E-1})$
///    alongside $u_1, \dots, u_{\Delta t} \in \mathbb{F}_r^{\Delta t}$, updating $c'_0$ and shifting all
///    rows so cached pre-escalation shares are algebraically useless, and
/// 3. Escalates & rerandomizes all existing `sbc_slots` homomorphically while sealing
///    $(\Delta V_{\text{aux}}, u_1 G_1, \dots, u_{\Delta t} G_1)$ into a fresh slot under $(M_{E+1}, \rho_{E+1})$.
pub fn escalate_gate_threshold(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    gate_id: usize,
    delta_t: usize,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), AcuError> {
    ct.validate_structure()?;
    verify_acu_operator(ct, acu_sk, seat_keys)?;

    for (seat_id, _) in &ct.matrix.rows {
        let pk = seat_keys
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.clone()))?;
        if !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id.clone()));
        }
    }

    let old_k = ct.matrix.cols;
    let mut next_matrix = ct.matrix.clone();
    let row_tails = next_matrix.escalate_gate(gate_id, delta_t)?;
    let new_k = next_matrix.cols;

    let prev_digest = ct.header_digest();
    let next_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;
    let g1 = G1Projective::generator();

    // Sample full extended shift vector `[delta_s, delta_v_1..delta_v_{old_k-1}, u_1..u_{delta_t}]`.
    let mut full_shift = Zeroizing::new(Vec::with_capacity(new_k));
    full_shift.push(sample_nonzero_scalar(rng));
    for _ in 1..new_k {
        full_shift.push(sample_uniform_scalar(rng));
    }
    let _ = old_k;

    let next_c0_g1 = ct.c0_g1 + g1 * full_shift[0];
    let next_c0 = pairing(&G1Affine::from(next_c0_g1), &G2Affine::generator());

    let next_rows = escalate_rows_homomorphically(
        &ct.object_digest,
        next_epoch,
        &prev_digest,
        &ct.rows,
        &row_tails,
        &full_shift,
        seat_keys,
        rng,
    )?;

    let mut next_slots = Vec::with_capacity(ct.sbc_slots.len() + 1);
    for slot in &ct.sbc_slots {
        let mut sbc_shift = Zeroizing::new(Vec::with_capacity(new_k));
        sbc_shift.push(sample_nonzero_scalar(rng));
        for _ in 1..new_k {
            sbc_shift.push(sample_uniform_scalar(rng));
        }
        let slot_next_c0 = slot.c0_g1 + g1 * sbc_shift[0];
        let slot_next_rows = escalate_rows_homomorphically(
            &ct.object_digest,
            next_epoch,
            &prev_digest,
            &slot.rows,
            &row_tails,
            &sbc_shift,
            seat_keys,
            rng,
        )?;
        next_slots.push(SbcSlot {
            created_epoch: slot.created_epoch,
            col_offset: slot.col_offset,
            col_count: slot.col_count,
            c0_g1: slot_next_c0,
            nonce: slot.nonce,
            ciphertext: slot.ciphertext.clone(),
            rows: slot_next_rows,
        });
    }

    let mut delta_and_u_aux: Vec<G1Projective> = full_shift[1..].iter().map(|s| g1 * s).collect();
    let mut fresh_loc_key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut fresh_loc_key[..]);
    let new_slot = seal_sbc_slot(
        &ct.object_digest,
        next_epoch,
        1,
        &delta_and_u_aux,
        &fresh_loc_key,
        &next_matrix,
        seat_keys,
        rng,
    )?;
    for pt in &mut delta_and_u_aux {
        pt.zeroize();
    }
    next_slots.push(new_slot);

    ct.policy_epoch = next_epoch;
    ct.c0_g1 = next_c0_g1;
    ct.c0 = next_c0;
    ct.matrix = next_matrix;
    ct.rows = next_rows;
    ct.sbc_slots = next_slots;
    ct.sign_epoch_auth(acu_sk)?;
    ct.validate_structure()
}

#[allow(clippy::too_many_arguments)]
fn escalate_rows_homomorphically(
    object_digest: &[u8; 32],
    next_epoch: u64,
    prev_digest: &[u8; 32],
    old_rows: &[CiphertextRow],
    row_tails: &[Vec<Scalar>],
    full_shift: &[Scalar],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<CiphertextRow>, AcuError> {
    let g1 = G1Projective::generator();
    let mut next_rows = Vec::with_capacity(old_rows.len());
    for (idx, (old_row, tail)) in old_rows.iter().zip(row_tails.iter()).enumerate() {
        let pk = seat_keys
            .get(&old_row.seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(old_row.seat_id.clone()))?;
        let mut ext_row = Vec::with_capacity(old_row.matrix_row.len() + tail.len());
        ext_row.extend_from_slice(&old_row.matrix_row);
        ext_row.extend_from_slice(tail);

        let mut delta_lambda = ext_row
            .iter()
            .zip(full_shift.iter())
            .fold(Scalar::ZERO, |acc, (&m, &s)| acc + m * s);
        let mut r_prime = sample_nonzero_scalar(rng);
        let delta_c1 = g1 * delta_lambda + pk.pk1 * r_prime;
        let delta_c2 = g1 * r_prime;
        delta_lambda.zeroize();

        let pok = prove_update_row_pok(
            object_digest,
            next_epoch,
            prev_digest,
            idx as u32,
            &pk.pk1,
            &delta_c1,
            &delta_c2,
            &r_prime,
            rng,
        )?;
        r_prime.zeroize();

        let mut updates = old_row.updates.clone();
        updates.push(RowUpdateProof {
            epoch: next_epoch,
            prev_header_digest: *prev_digest,
            row_index: idx as u32,
            delta_c1,
            delta_c2,
            pok,
        });

        next_rows.push(CiphertextRow {
            object_digest: *object_digest,
            row_index: idx,
            seat_id: old_row.seat_id.clone(),
            row_locator: old_row.row_locator,
            oblivious_hint: old_row.oblivious_hint,
            matrix_row: ext_row,
            c1: old_row.c1 + delta_c1,
            c2: old_row.c2 + delta_c2,
            init_epoch: old_row.init_epoch,
            init_row_index: old_row.init_row_index,
            init_matrix_digest: old_row.init_matrix_digest,
            init_c1: old_row.init_c1,
            init_c2: old_row.init_c2,
            row_pok: old_row.row_pok,
            updates,
        });
    }
    Ok(next_rows)
}

/// 3-equation pure-$\mathbb{G}_1$ HVZK Chaum–Pedersen proof that `(new_c1, new_c2)` under `new_pk`
/// encrypts the exact same hidden share $\lambda_{\text{sib}} G_1$ as `(sib_c1, sib_c2)` under `sib_pk`
/// without revealing $\lambda_{\text{sib}} G_1$ to the `ACU` operator!
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiblingRowTransfer {
    /// Sibling's re-encrypted $c'_1 = (c_1 - sk_{\text{sib}} c_2) + r_{\text{new}} pk_{\text{new}} \in \mathbb{G}_1$.
    pub new_c1: G1Projective,
    /// Sibling's fresh ephemeral randomness $c'_2 = r_{\text{new}} G_1 \in \mathbb{G}_1^*$.
    pub new_c2: G1Projective,
    /// Oblivious ECDH hint for the new sibling seat (`r_new * pk_new`).
    pub oblivious_hint: [u8; 8],
    /// `64`-byte initial `RowPok` on `(new_c1, new_c2)` at `target_epoch`.
    pub row_pok: RowPok,
    /// Per-object blind row locator $\ell_{\text{new}}$.
    pub row_locator: [u8; 32],
    /// HVZK 3-equation challenge $\mathsf{ch} \in \mathbb{F}_r^*$.
    pub challenge: Scalar,
    /// HVZK response $z_1 = k_1 + \mathsf{ch} \cdot sk_{\text{sib}} \pmod{r}$.
    pub response_sk: Scalar,
    /// HVZK response $z_2 = k_2 + \mathsf{ch} \cdot r_{\text{new}} \pmod{r}$.
    pub response_r: Scalar,
}

/// Custodian-signed blinded warm-fork authorization (`Shadow-KV` `OR`-branch attachment) that
/// neither `acu_sk` alone nor `sib_sk` alone can forge into a threshold bypass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarmForkRequest {
    /// Expected `object_digest` ($O$).
    pub object_digest: [u8; 32],
    /// Current `policy_epoch` ($E$).
    pub base_epoch: u64,
    /// Existing non-ACU custodian row index being warm-forked.
    pub existing_row_index: usize,
    /// Seat ID of the new sibling branch.
    pub new_seat_id: String,
    /// Blinded HVZK transfer of the main ciphertext row.
    pub main_transfer: SiblingRowTransfer,
    /// Blinded HVZK transfers of each `SbcSlot` row aligned with `existing_row_index`.
    pub sbc_transfers: Vec<SiblingRowTransfer>,
}

impl WarmForkRequest {
    /// Construct a blinded [`WarmForkRequest`] as the non-ACU custodian holding `existing_sk`.
    pub fn create(
        ct: &AcuCiphertext,
        existing_row_index: usize,
        existing_sk: &SeatSecretKey,
        new_pk: &SeatPublicKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        ct.validate_structure()?;
        if !new_pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(new_pk.seat_id.clone()));
        }
        let sib_row = ct
            .rows
            .get(existing_row_index)
            .ok_or(AcuError::RowIndexOutOfBounds {
                index: existing_row_index,
                total_rows: ct.rows.len(),
            })?;
        // Forbid warm-forking the ACU row itself!
        if sib_row.seat_id == ct.acu_seat_id || existing_sk.seat_id != sib_row.seat_id {
            return Err(AcuError::UnauthorizedPolicyOperator);
        }

        let target_epoch = ct
            .policy_epoch
            .checked_add(1)
            .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;
        let new_row_index = ct.rows.len() as u32;
        let sib_pk1 = G1Projective::generator() * existing_sk.sk;

        let mut next_mat = ct.matrix.clone();
        next_mat.attach_sibling(existing_row_index, new_pk.seat_id.clone())?;
        let target_mat_digest = next_mat.canonical_digest();

        let mut loc_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut loc_key[..]);

        let main_transfer = build_sibling_transfer(
            &ct.object_digest,
            &target_mat_digest,
            target_epoch,
            new_row_index,
            0,
            &loc_key,
            sib_row,
            &existing_sk.sk,
            &sib_pk1,
            new_pk,
            rng,
        )?;

        let mut sbc_transfers = Vec::with_capacity(ct.sbc_slots.len());
        for (slot_idx, slot) in ct.sbc_slots.iter().enumerate() {
            let slot_sib = &slot.rows[existing_row_index];
            sbc_transfers.push(build_sibling_transfer(
                &ct.object_digest,
                &target_mat_digest,
                target_epoch,
                new_row_index,
                (slot_idx + 1) as u32,
                &loc_key,
                slot_sib,
                &existing_sk.sk,
                &sib_pk1,
                new_pk,
                rng,
            )?);
        }

        Ok(Self {
            object_digest: ct.object_digest,
            base_epoch: ct.policy_epoch,
            existing_row_index,
            new_seat_id: new_pk.seat_id.clone(),
            main_transfer,
            sbc_transfers,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn build_sibling_transfer(
    object_digest: &[u8; 32],
    target_mat_digest: &[u8; 32],
    target_epoch: u64,
    new_row_index: u32,
    domain_slot_idx: u32,
    loc_key: &[u8; 32],
    sib_row: &CiphertextRow,
    sib_sk: &Scalar,
    sib_pk1: &G1Projective,
    new_pk: &SeatPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<SiblingRowTransfer, AcuError> {
    let g1 = G1Projective::generator();
    let mut r_new = sample_nonzero_scalar(rng);
    let mut hidden_s = sib_row.c1 - sib_row.c2 * *sib_sk;
    let shared_new = new_pk.pk1 * r_new;
    let new_c1 = hidden_s + shared_new;
    let new_c2 = g1 * r_new;
    hidden_s.zeroize();

    let row_locator = compute_blind_row_locator(
        loc_key,
        object_digest,
        target_epoch,
        new_row_index,
        &new_pk.seat_id,
    );
    let oblivious_hint = compute_oblivious_key_hint(&shared_new);
    let row_pok = prove_row_pok(
        object_digest,
        target_mat_digest,
        target_epoch,
        new_row_index,
        &row_locator,
        &new_pk.pk1,
        &new_c1,
        &new_c2,
        &r_new,
        rng,
    )?;

    loop {
        let mut k1 = sample_nonzero_scalar(rng);
        let mut k2 = sample_nonzero_scalar(rng);
        let t1 = g1 * k1;
        let t2 = g1 * k2;
        let t3 = sib_row.c2 * k1 - new_pk.pk1 * k2;
        let ch = compute_warm_fork_challenge(
            object_digest,
            target_epoch,
            new_row_index,
            domain_slot_idx,
            sib_pk1,
            &new_pk.pk1,
            &sib_row.c1,
            &sib_row.c2,
            &new_c1,
            &new_c2,
            &t1,
            &t2,
            &t3,
        )?;
        let z1 = k1 + ch * *sib_sk;
        let z2 = k2 + ch * r_new;
        k1.zeroize();
        k2.zeroize();
        if !bool::from(z1.is_zero()) && !bool::from(z2.is_zero()) {
            r_new.zeroize();
            return Ok(SiblingRowTransfer {
                new_c1,
                new_c2,
                oblivious_hint,
                row_pok,
                row_locator,
                challenge: ch,
                response_sk: z1,
                response_r: z2,
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_sibling_transfer(
    object_digest: &[u8; 32],
    target_mat_digest: &[u8; 32],
    target_epoch: u64,
    new_row_index: u32,
    domain_slot_idx: u32,
    sib_row: &CiphertextRow,
    sib_pk1: &G1Projective,
    new_pk: &SeatPublicKey,
    tr: &SiblingRowTransfer,
) -> bool {
    if bool::from(tr.challenge.is_zero())
        || bool::from(tr.response_sk.is_zero())
        || bool::from(tr.response_r.is_zero())
    {
        return false;
    }
    if !crate::share::verify_initial_row_pok(
        object_digest,
        target_mat_digest,
        target_epoch,
        new_row_index,
        &tr.row_locator,
        &new_pk.pk1,
        &tr.new_c1,
        &tr.new_c2,
        &tr.row_pok,
    ) {
        return false;
    }
    let g1 = G1Projective::generator();
    let t1 = g1 * tr.response_sk - *sib_pk1 * tr.challenge;
    let t2 = g1 * tr.response_r - tr.new_c2 * tr.challenge;
    let diff_c1 = sib_row.c1 - tr.new_c1;
    let t3 = sib_row.c2 * tr.response_sk - new_pk.pk1 * tr.response_r - diff_c1 * tr.challenge;

    let Ok(expected) = compute_warm_fork_challenge(
        object_digest,
        target_epoch,
        new_row_index,
        domain_slot_idx,
        sib_pk1,
        &new_pk.pk1,
        &sib_row.c1,
        &sib_row.c2,
        &tr.new_c1,
        &tr.new_c2,
        &t1,
        &t2,
        &t3,
    ) else {
        return false;
    };
    bool::from(tr.challenge.to_bytes().ct_eq(&expected.to_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn compute_warm_fork_challenge(
    object_digest: &[u8; 32],
    target_epoch: u64,
    new_row_index: u32,
    domain_slot_idx: u32,
    sib_pk1: &G1Projective,
    new_pk1: &G1Projective,
    sib_c1: &G1Projective,
    sib_c2: &G1Projective,
    new_c1: &G1Projective,
    new_c2: &G1Projective,
    t1: &G1Projective,
    t2: &G1Projective,
    t3: &G1Projective,
) -> Result<Scalar, AcuError> {
    let mut msg = Vec::with_capacity(32 + 8 + 8 + 48 * 10);
    msg.extend_from_slice(object_digest);
    msg.extend_from_slice(&target_epoch.to_be_bytes());
    msg.extend_from_slice(&new_row_index.to_be_bytes());
    msg.extend_from_slice(&domain_slot_idx.to_be_bytes());
    msg.extend_from_slice(&G1Affine::generator().to_compressed());
    for pt in [sib_pk1, new_pk1, sib_c1, sib_c2, new_c1, new_c2, t1, t2, t3] {
        msg.extend_from_slice(&G1Affine::from(*pt).to_compressed());
    }
    hash_to_nonzero_scalar(&msg, WARM_FORK_DST)
}

/// Attach a `Shadow-KV` warm-fork `OR` sibling leaf verified jointly by `acu_sk` and a
/// custodian-issued [`WarmForkRequest`] (preserving strict `ACU`-blindness).
pub fn insert_sibling_key(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    warm_fork: &WarmForkRequest,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
) -> Result<usize, AcuError> {
    ct.validate_structure()?;
    verify_acu_operator(ct, acu_sk, seat_keys)?;

    if !bool::from(warm_fork.object_digest.ct_eq(&ct.object_digest)) {
        return Err(AcuError::InvalidMetadata);
    }
    if warm_fork.base_epoch != ct.policy_epoch {
        return Err(AcuError::EpochMismatch {
            expected: ct.policy_epoch,
            actual: warm_fork.base_epoch,
        });
    }
    if warm_fork.sbc_transfers.len() != ct.sbc_slots.len() {
        return Err(AcuError::DimensionMismatch {
            expected: ct.sbc_slots.len(),
            actual: warm_fork.sbc_transfers.len(),
        });
    }
    let sib_row =
        ct.rows
            .get(warm_fork.existing_row_index)
            .ok_or(AcuError::RowIndexOutOfBounds {
                index: warm_fork.existing_row_index,
                total_rows: ct.rows.len(),
            })?;
    if sib_row.seat_id == ct.acu_seat_id || warm_fork.new_seat_id == ct.acu_seat_id {
        return Err(AcuError::UnauthorizedPolicyOperator);
    }
    let sib_pk = seat_keys
        .get(&sib_row.seat_id)
        .ok_or_else(|| AcuError::UnknownSeat(sib_row.seat_id.clone()))?;
    let new_pk = seat_keys
        .get(&warm_fork.new_seat_id)
        .ok_or_else(|| AcuError::UnknownSeat(warm_fork.new_seat_id.clone()))?;
    if !sib_pk.verify_consistency() || !new_pk.verify_consistency() {
        return Err(AcuError::InvalidPublicKey(warm_fork.new_seat_id.clone()));
    }

    let next_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;
    let new_row_idx = ct.rows.len();

    let mut next_matrix = ct.matrix.clone();
    let attached_idx =
        next_matrix.attach_sibling(warm_fork.existing_row_index, warm_fork.new_seat_id.clone())?;
    debug_assert_eq!(attached_idx, new_row_idx);
    let target_mat_digest = next_matrix.canonical_digest();

    if !verify_sibling_transfer(
        &ct.object_digest,
        &target_mat_digest,
        next_epoch,
        new_row_idx as u32,
        0,
        sib_row,
        &sib_pk.pk1,
        new_pk,
        &warm_fork.main_transfer,
    ) {
        return Err(AcuError::InvalidRowPok);
    }
    for (slot_idx, (slot, tr)) in ct
        .sbc_slots
        .iter()
        .zip(warm_fork.sbc_transfers.iter())
        .enumerate()
    {
        if !verify_sibling_transfer(
            &ct.object_digest,
            &target_mat_digest,
            next_epoch,
            new_row_idx as u32,
            (slot_idx + 1) as u32,
            &slot.rows[warm_fork.existing_row_index],
            &sib_pk.pk1,
            new_pk,
            tr,
        ) {
            return Err(AcuError::InvalidRowPok);
        }
    }

    let cloned_vec = sib_row.matrix_row.clone();

    ct.rows.push(CiphertextRow {
        object_digest: ct.object_digest,
        row_index: new_row_idx,
        seat_id: warm_fork.new_seat_id.clone(),
        row_locator: warm_fork.main_transfer.row_locator,
        oblivious_hint: warm_fork.main_transfer.oblivious_hint,
        matrix_row: cloned_vec.clone(),
        c1: warm_fork.main_transfer.new_c1,
        c2: warm_fork.main_transfer.new_c2,
        init_epoch: next_epoch,
        init_row_index: new_row_idx as u32,
        init_matrix_digest: target_mat_digest,
        init_c1: warm_fork.main_transfer.new_c1,
        init_c2: warm_fork.main_transfer.new_c2,
        row_pok: warm_fork.main_transfer.row_pok,
        updates: Vec::new(),
    });

    for (slot, tr) in ct.sbc_slots.iter_mut().zip(warm_fork.sbc_transfers.iter()) {
        slot.rows.push(CiphertextRow {
            object_digest: ct.object_digest,
            row_index: new_row_idx,
            seat_id: warm_fork.new_seat_id.clone(),
            row_locator: tr.row_locator,
            oblivious_hint: tr.oblivious_hint,
            matrix_row: cloned_vec.clone(),
            c1: tr.new_c1,
            c2: tr.new_c2,
            init_epoch: next_epoch,
            init_row_index: new_row_idx as u32,
            init_matrix_digest: target_mat_digest,
            init_c1: tr.new_c1,
            init_c2: tr.new_c2,
            row_pok: tr.row_pok,
            updates: Vec::new(),
        });
    }

    ct.matrix = next_matrix;
    ct.policy_epoch = next_epoch;
    ct.sign_epoch_auth(acu_sk)?;
    ct.validate_structure()?;
    Ok(new_row_idx)
}

/// Coalition share bundle for a single row $j \in \Gamma$ during [`insert_authorized_seat`]
/// (`ePrint v2` §6.3 Op 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoalitionInsertionRowShare {
    /// Verified $\mathbb{G}_1$ partial decryption share on `ct.rows[row_index]`.
    pub main_share: PartialDecryptionShare,
    /// Verified $\mathbb{G}_1$ partial decryption shares on each `ct.sbc_slots[q].rows[row_index]`.
    pub sbc_shares: Vec<PartialDecryptionShare>,
}

impl CoalitionInsertionRowShare {
    /// Emit a [`CoalitionInsertionRowShare`] for `row_index` using `secret_key` (`0` pairings).
    pub fn issue_for_row(
        ct: &AcuCiphertext,
        row_index: usize,
        secret_key: &SeatSecretKey,
    ) -> Result<Self, AcuError> {
        let row = ct
            .rows
            .get(row_index)
            .ok_or(AcuError::RowIndexOutOfBounds {
                index: row_index,
                total_rows: ct.rows.len(),
            })?;
        if row.seat_id != secret_key.seat_id {
            return Err(AcuError::UnauthorizedPolicyOperator);
        }
        let main_share = acu_partial_decrypt_at_epoch(row, secret_key, ct.policy_epoch);
        let mut sbc_shares = Vec::with_capacity(ct.sbc_slots.len());
        for slot in &ct.sbc_slots {
            sbc_shares.push(acu_partial_decrypt_at_epoch(
                &slot.rows[row_index],
                secret_key,
                ct.policy_epoch,
            ));
        }
        Ok(Self {
            main_share,
            sbc_shares,
        })
    }
}

/// Coalition-authorized general seat insertion (`ePrint v2` §6.3 Op 3):
/// 1. Verifies an authorized coalition $\Gamma \models (M_E, \rho_E)$,
/// 2. Reconstructs $V_0^{(E)} = \sum_{j \in \Gamma} \omega_j S_j = s^{(E)} G_1$ in $\mathbb{G}_1$
///    **without evaluating $e(\cdot, G_2)$ on `c0` or recovering $K_{\mathbb{G}_T}$**,
/// 3. Unseals and folds $V_{\text{aux}}^{(E)} = (V_1^{(E)}, \dots, V_{k_E-1}^{(E)})$ across `sbc_slots`,
/// 4. Enforces non-ACU span exclusion (`AcuError::SlotSpanExposesSecret`) so adding `new_row`
///    cannot let non-ACU seats bypass an `ACU`-conjunctive policy,
/// 5. Appends `(new_seat_id, new_row_vec)` with a fresh `RowPok`, and
/// 6. Compacts `ct.sbc_slots` back to a **single** fresh `SbcSlot` under `(M_{E+1}, \rho_{E+1})`.
pub fn insert_authorized_seat(
    ct: &mut AcuCiphertext,
    acu_sk: &SeatSecretKey,
    new_seat_id: impl Into<String>,
    new_row_vec: Vec<Scalar>,
    coalition: &[CoalitionInsertionRowShare],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<usize, AcuError> {
    ct.validate_structure()?;
    verify_acu_operator(ct, acu_sk, seat_keys)?;

    let new_seat_id = new_seat_id.into();
    if !is_valid_seat_id(&new_seat_id) {
        return Err(AcuError::InvalidSeatId);
    }
    if new_row_vec.len() != ct.matrix.cols {
        return Err(AcuError::DimensionMismatch {
            expected: ct.matrix.cols,
            actual: new_row_vec.len(),
        });
    }
    if new_row_vec.iter().all(|s| bool::from(s.is_zero())) {
        return Err(AcuError::InvalidAccessTree("LSSS row cannot be all zero"));
    }
    let new_pk = seat_keys
        .get(&new_seat_id)
        .ok_or_else(|| AcuError::UnknownSeat(new_seat_id.clone()))?;
    if !new_pk.verify_consistency() {
        return Err(AcuError::InvalidPublicKey(new_seat_id));
    }
    if ct.rows.len() >= MAX_SERIALIZED_ROWS {
        return Err(AcuError::SerializationError(
            "invalid AcuCiphertext dimensions",
        ));
    }

    // Non-ACU span safety check: if non-ACU rows currently do NOT span e_0 (i.e. ACU is mandatory),
    // forbid inserting a non-ACU row whose addition would let non-ACU seats span e_0 without ACU!
    if new_seat_id != ct.acu_seat_id {
        let existing_non_acu: Vec<Vec<Scalar>> = ct
            .matrix
            .rows
            .iter()
            .filter(|(s, _)| *s != ct.acu_seat_id)
            .map(|(_, r)| r.clone())
            .collect();
        if !rows_span_target(ct.matrix.cols, &existing_non_acu) {
            let mut candidate_non_acu = existing_non_acu;
            candidate_non_acu.push(new_row_vec.clone());
            if rows_span_target(ct.matrix.cols, &candidate_non_acu) {
                return Err(AcuError::SlotSpanExposesSecret);
            }
        }
    }

    if coalition.is_empty() {
        return Err(AcuError::PolicyNotSatisfied);
    }

    let mut available_indices = Vec::with_capacity(coalition.len());
    let mut main_by_row: BTreeMap<usize, G1Projective> = BTreeMap::new();
    let mut slot_by_row: Vec<BTreeMap<usize, G1Projective>> =
        vec![BTreeMap::new(); ct.sbc_slots.len()];

    for bundle in coalition {
        if bundle.sbc_shares.len() != ct.sbc_slots.len() {
            return Err(AcuError::DimensionMismatch {
                expected: ct.sbc_slots.len(),
                actual: bundle.sbc_shares.len(),
            });
        }
        let row_idx = bundle.main_share.row_index;
        let row = ct.rows.get(row_idx).ok_or(AcuError::RowIndexOutOfBounds {
            index: row_idx,
            total_rows: ct.rows.len(),
        })?;
        let pk = seat_keys
            .get(&row.seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(row.seat_id.clone()))?;
        if bundle.main_share.policy_epoch != ct.policy_epoch {
            return Err(AcuError::EpochMismatch {
                expected: ct.policy_epoch,
                actual: bundle.main_share.policy_epoch,
            });
        }
        if !verify_partial_share_for_object(
            &ct.object_digest,
            ct.policy_epoch,
            row,
            pk,
            &bundle.main_share,
        ) {
            return Err(AcuError::InvalidPartialShare {
                row_index: row_idx,
                seat_id: bundle.main_share.seat_id.clone(),
            });
        }
        for (q, sbc_share) in bundle.sbc_shares.iter().enumerate() {
            if !verify_partial_share_for_object(
                &ct.object_digest,
                ct.policy_epoch,
                &ct.sbc_slots[q].rows[row_idx],
                pk,
                sbc_share,
            ) {
                return Err(AcuError::InvalidPartialShare {
                    row_index: row_idx,
                    seat_id: sbc_share.seat_id.clone(),
                });
            }
            slot_by_row[q].insert(row_idx, sbc_share.share_g1);
        }
        if main_by_row
            .insert(row_idx, bundle.main_share.share_g1)
            .is_none()
        {
            available_indices.push(row_idx);
        }
    }

    let weights = find_reconstruction_weights(&ct.matrix, &available_indices)?;

    // Reconstruct V_0^{(E)} = s^{(E)} * G_1 live in G_1 WITHOUT computing K_{G_T}!
    let mut v0_g1 = G1Projective::identity();
    for &(row_idx, omega) in &weights {
        let s_pt = main_by_row
            .get(&row_idx)
            .ok_or(AcuError::PolicyNotSatisfied)?;
        v0_g1 += *s_pt * omega;
    }

    // Fold V_aux^{(E)} = (V_1^{(E)}, ..., V_{k-1}^{(E)}) across all slots.
    let aux_len = ct.matrix.cols.saturating_sub(1);
    let mut v_aux = vec![G1Projective::identity(); aux_len];
    for (q, slot) in ct.sbc_slots.iter().enumerate() {
        let slot_pts =
            unseal_sbc_slot_with_weights(&ct.object_digest, slot, &weights, &slot_by_row[q])?;
        for (m, pt) in slot_pts.into_iter().enumerate() {
            v_aux[slot.col_offset - 1 + m] += pt;
        }
    }

    // Evaluate lambda_new * G_1 = new_row[0] * V_0 + sum_{d=1..k-1} new_row[d] * V_d.
    let mut lambda_new_g1 = v0_g1 * new_row_vec[0];
    for (d, aux_pt) in v_aux.iter().enumerate() {
        lambda_new_g1 += *aux_pt * new_row_vec[d + 1];
    }
    v0_g1.zeroize();

    let next_epoch = ct
        .policy_epoch
        .checked_add(1)
        .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;
    let new_row_idx = ct.rows.len();

    let g1 = G1Projective::generator();
    let mut r_new = sample_nonzero_scalar(rng);
    let shared_new = new_pk.pk1 * r_new;
    let new_c1 = lambda_new_g1 + shared_new;
    let new_c2 = g1 * r_new;
    lambda_new_g1.zeroize();

    let mut next_matrix = ct.matrix.clone();
    let appended_idx =
        next_matrix.append_authorized_row(new_seat_id.clone(), new_row_vec.clone())?;
    debug_assert_eq!(appended_idx, new_row_idx);
    let target_mat_digest = next_matrix.canonical_digest();

    let mut loc_key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut loc_key[..]);
    let row_locator = compute_blind_row_locator(
        &loc_key,
        &ct.object_digest,
        next_epoch,
        new_row_idx as u32,
        &new_seat_id,
    );
    let oblivious_hint = compute_oblivious_key_hint(&shared_new);
    let row_pok = prove_row_pok(
        &ct.object_digest,
        &target_mat_digest,
        next_epoch,
        new_row_idx as u32,
        &row_locator,
        &new_pk.pk1,
        &new_c1,
        &new_c2,
        &r_new,
        rng,
    )?;
    r_new.zeroize();

    let compacted_slot = seal_sbc_slot(
        &ct.object_digest,
        next_epoch,
        1,
        &v_aux,
        &loc_key,
        &next_matrix,
        seat_keys,
        rng,
    )?;
    for pt in &mut v_aux {
        pt.zeroize();
    }

    ct.rows.push(CiphertextRow {
        object_digest: ct.object_digest,
        row_index: new_row_idx,
        seat_id: new_seat_id,
        row_locator,
        oblivious_hint,
        matrix_row: new_row_vec,
        c1: new_c1,
        c2: new_c2,
        init_epoch: next_epoch,
        init_row_index: new_row_idx as u32,
        init_matrix_digest: target_mat_digest,
        init_c1: new_c1,
        init_c2: new_c2,
        row_pok,
        updates: Vec::new(),
    });
    ct.matrix = next_matrix;
    ct.sbc_slots = vec![compacted_slot];
    ct.policy_epoch = next_epoch;
    ct.sign_epoch_auth(acu_sk)?;
    ct.validate_structure()?;
    Ok(new_row_idx)
}
