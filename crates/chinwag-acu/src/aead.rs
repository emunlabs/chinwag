// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Dual-Secret Hybrid Post-Quantum AEAD Envelope (`CHWGAEA2` wrapping `CHWGACU3` + `0x647a`
//! `X25519-MLKEM768` non-ACU LSSS capsules + `48`-byte wrapped `DEK` indirection) implementing
//! `ePrint v2` Construction `con:archive` (§6.1–§6.3) and `CHWG-PAT-11B-v2` `[0024]`:
//! 1. **Immutable Payload `C_1` (`C_{E+1} == C_1`):** Payload `aead_ciphertext` is encrypted once
//!    under a random non-zero 256-bit `DEK` with epoch-independent `associated_data` bound to $O$,
//!    so `aead_immutable_blake3` never changes across revocations, escalations, insertions, or PQ rotations.
//! 2. **48-Byte Wrapped-DEK Slot (`wrapped_dek`):** `DEK` (`32` B) is sealed under
//!    `k_kek = HKDF-SHA256(Canon_Fp12(K_GT) || Canon_Fr(K_PQ), info = O || dek_wrap_epoch_be8)`.
//! 3. **Access-Structured Non-ACU Post-Quantum Projection `(M^{pq}, \rho^{pq})`:** `ACU` holds
//!    **zero** post-quantum rows (`project_non_acu`), while $K_{\mathsf{PQ}} \in \mathbb{F}_r^*$ is
//!    secret-shared across non-ACU custodians via `0x647a` (`X25519-MLKEM768`) capsules (`< t`
//!    corrupted custodians + quantum `ACU` learn `0` bits of $K_{\mathsf{PQ}}$).
//! 4. **Payload-Preserving PQ Forward Rotation ([`EncryptedCiPayload::rotate_pq_key`]):** Re-wraps
//!    only the `48`-byte `wrapped_dek` under fresh $(K'_{\mathbb{G}_T}, K'_{\mathsf{PQ}})$ with
//!    **zero re-encryption of multi-megabyte `aead_ciphertext` (`C_1`)**.

use crate::AcuError;
use crate::acu::{
    AcuCiphertext, acu_combine, acu_combine_unverified, acu_encrypt_with_g1_and_context,
    compute_blind_row_locator,
};
use crate::framing::{
    gt_canonical_bytes, lp64, lp64_str, read_lp64, read_lp64_str, read_scalar, read_u8,
    read_u32_be, read_u64_be, sample_uniform_scalar, take_slice,
};
use crate::keys::{
    MAX_SEAT_ID_BYTES, SeatPublicKey, SeatSecretKey, XWING_ENCAPPED_KEY_BYTES, is_valid_seat_id,
    sample_nonzero_scalar,
};
use crate::lsss::{
    AccessTree, LsssMatrix, MAX_SERIALIZED_COLS, MAX_SERIALIZED_ROWS, find_reconstruction_weights,
    project_non_acu,
};
use crate::share::PartialDecryptionShare;
use blake3;
use bls12_381::{G1Projective, Gt, Scalar};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ff::Field;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Default key-branch identifier for the responsible Human / AI Agent Seat in the Split-Key CI pattern.
pub const DEFAULT_AGENT_BRANCH_ID: &str = "branch:8687872";
/// Default key-branch identifier for the Always-On Revocation Access Control Unit (`ACU`).
pub const DEFAULT_REVOCATION_ACU_ID: &str = "branch:98939834";
/// Default seat identifier for the Zero-Plaintext-At-Rest Message Archive Unit (`archive:vault`).
pub const DEFAULT_MESSAGE_ARCHIVE_ID: &str = "archive:vault";

const LEGACY_ENCRYPTED_PAYLOAD_MAGIC: &[u8; 8] = b"CHWGAEAD";
/// Canonical `v2`-parity hybrid AEAD envelope magic (`CHWGAEA2`).
pub const ENCRYPTED_PAYLOAD_MAGIC: &[u8; 8] = b"CHWGAEA2";

const OBJECT_DIGEST_DOMAIN: &[u8] = b"chinwag-acu/v2/object-id";
const PAYLOAD_AAD_DOMAIN: &[u8] = b"chinwag-acu/v2/pay-aad";
const IMMUTABLE_AEAD_HASH_DOMAIN: &[u8] = b"chinwag-acu/v2/aead-immutable";
const KEK_HKDF_SALT: &[u8] = b"chinwag-acu/v2/kek";
const DEK_WRAP_AAD_DOMAIN: &[u8] = b"chinwag-acu/v2/dek-aad";
const PQ_ROW_INFO_DOMAIN: &[u8] = b"chinwag.acu.v2.pq-row";
const PQSBC_HKDF_SALT: &[u8] = b"chinwag-acu/v2/pqsbc-salt";
const PQSBC_HKDF_INFO_DOMAIN: &[u8] = b"chinwag-acu/v2/pqsbc-key";
const PQSBC_AAD_DOMAIN: &[u8] = b"chinwag-acu/v2/pqsbc-aad";
const GT_STANDALONE_HKDF_SALT: &[u8] = b"chinwag-acu/v2/gt-chacha20poly1305-salt";

const MAX_SERIALIZED_BLOB_BYTES: usize = 16 * 1024 * 1024;
/// Exact byte length of `ChaCha20Poly1305(32-byte DEK)` = `32 + 16 = 48` bytes.
pub const WRAPPED_DEK_BYTES: usize = 48;
/// Exact byte length of `ChaCha20Poly1305(mu_m (32 B) || mu_sbc_m (32 B))` = `64 + 16 = 80` bytes.
pub const PQ_CAPSULE_CIPHERTEXT_BYTES: usize = 80;

pub(crate) fn is_valid_metadata_token(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

/// A single `0x647a` (`X25519-MLKEM768`) row capsule inside [`PqLsssHeader`] (`ePrint v2` §6.1 Step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCapsuleRow {
    /// Zero-based row index $m$ in [`PqLsssHeader::matrix`].
    pub row_index: usize,
    /// Non-ACU custodian seat identifier $\rho^{\mathsf{pq}}(m)$ (never equals `acu_seat_id`).
    pub seat_id: String,
    /// Per-object `32`-byte keyed blind row locator $\ell^{\mathsf{pq}}_m$.
    pub row_locator: [u8; 32],
    /// LSSS matrix row vector $M^{\mathsf{pq}}_m \in \mathbb{F}_r^{k_{\mathsf{pq}}}$.
    pub matrix_row: Vec<Scalar>,
    /// `1120`-byte `X25519-MLKEM768` (`0x647a`) encapsulated key.
    pub encapped_key: [u8; XWING_ENCAPPED_KEY_BYTES],
    /// `80`-byte HPKE `SealBase` ciphertext encrypting `Canon_Fr(mu_m) || Canon_Fr(mu_sbc_m)`.
    pub ciphertext: [u8; PQ_CAPSULE_CIPHERTEXT_BYTES],
}

/// Access-structured non-ACU post-quantum header $(M^{\mathsf{pq}}, \rho^{\mathsf{pq}})$ (`ePrint v2` §6.1 Step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqLsssHeader {
    /// Wrap epoch matching [`EncryptedCiPayload::dek_wrap_epoch`].
    pub wrap_epoch: u64,
    /// Non-ACU compiled LSSS matrix $(M^{\mathsf{pq}}, \rho^{\mathsf{pq}})$.
    pub matrix: LsssMatrix,
    /// Per-row `0x647a` hybrid PQ capsules (`0` rows belong to `ACU`).
    pub rows: Vec<PqCapsuleRow>,
    /// Nonce for `ct_pqsbc`.
    pub pqsbc_nonce: [u8; 12],
    /// Independent symmetric ciphertext sealing auxiliary PQ scalars $(v^{\mathsf{pq}}_1, \dots, v^{\mathsf{pq}}_{k_{\mathsf{pq}}-1})$
    /// under `HKDF(Canon_Fr(K_pqsbc))` (zero KDM cycle).
    pub ct_pqsbc: Vec<u8>,
}

impl PqLsssHeader {
    pub fn validate(&self, acu_seat_id: &str) -> Result<(), AcuError> {
        if self.wrap_epoch == 0 {
            return Err(AcuError::SerializationError("PqLsssHeader wrap_epoch == 0"));
        }
        self.matrix.validate()?;
        if self.rows.len() != self.matrix.rows.len() {
            return Err(AcuError::DimensionMismatch {
                expected: self.matrix.rows.len(),
                actual: self.rows.len(),
            });
        }
        for (idx, (row, (m_seat, m_vec))) in
            self.rows.iter().zip(self.matrix.rows.iter()).enumerate()
        {
            // HARD QUANTUM ACU-BLINDNESS INVARIANT: ACU MUST hold 0 rows in PqLsssHeader!
            if row.seat_id == acu_seat_id || *m_seat == acu_seat_id {
                return Err(AcuError::SerializationError(
                    "ACU seat forbidden inside PqLsssHeader (quantum gate-blindness invariant)",
                ));
            }
            if row.row_index != idx || row.seat_id != *m_seat || row.matrix_row != *m_vec {
                return Err(AcuError::SerializationError(
                    "PqLsssHeader row/matrix mismatch",
                ));
            }
        }
        let expected_pqsbc_len = self
            .matrix
            .cols
            .saturating_sub(1)
            .checked_mul(32)
            .and_then(|n| n.checked_add(16))
            .ok_or(AcuError::SerializationError("ct_pqsbc length overflow"))?;
        if self.ct_pqsbc.len() != expected_pqsbc_len {
            return Err(AcuError::SerializationError("ct_pqsbc length mismatch"));
        }
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>, blind_seats: bool) {
        out.extend_from_slice(&self.wrap_epoch.to_be_bytes());
        out.extend_from_slice(&(self.matrix.cols as u32).to_be_bytes());
        out.extend_from_slice(&(self.rows.len() as u32).to_be_bytes());
        self.matrix.encode_gates(out);
        out.extend_from_slice(&self.pqsbc_nonce);
        lp64(out, &self.ct_pqsbc);
        for row in &self.rows {
            out.extend_from_slice(&(row.row_index as u32).to_be_bytes());
            let wire_seat = if blind_seats {
                blind_pq_handle(&row.row_locator)
            } else {
                row.seat_id.clone()
            };
            lp64_str(out, &wire_seat);
            out.extend_from_slice(&row.row_locator);
            for s in &row.matrix_row {
                out.extend_from_slice(&s.to_bytes());
            }
            out.extend_from_slice(&row.encapped_key);
            out.extend_from_slice(&row.ciphertext);
        }
    }

    fn decode_from(bytes: &[u8], cursor: &mut usize, acu_seat_id: &str) -> Result<Self, AcuError> {
        let wrap_epoch = read_u64_be(bytes, cursor)?;
        let cols = read_u32_be(bytes, cursor)? as usize;
        let num_rows = read_u32_be(bytes, cursor)? as usize;
        if cols == 0
            || cols > MAX_SERIALIZED_COLS
            || num_rows == 0
            || num_rows > MAX_SERIALIZED_ROWS
        {
            return Err(AcuError::SerializationError(
                "invalid PqLsssHeader dimensions",
            ));
        }
        let gates = LsssMatrix::decode_gates(bytes, cursor, num_rows)?;
        let pqsbc_nonce_slice = take_slice(bytes, cursor, 12)?;
        let mut pqsbc_nonce = [0u8; 12];
        pqsbc_nonce.copy_from_slice(pqsbc_nonce_slice);

        let expected_pqsbc = cols
            .saturating_sub(1)
            .checked_mul(32)
            .and_then(|n| n.checked_add(16))
            .ok_or(AcuError::SerializationError("ct_pqsbc overflow"))?;
        let ct_pqsbc = read_lp64(bytes, cursor, expected_pqsbc)?.to_vec();

        let mut rows = Vec::with_capacity(num_rows);
        let mut matrix_rows = Vec::with_capacity(num_rows);
        for expected_idx in 0..num_rows {
            let row_index = read_u32_be(bytes, cursor)? as usize;
            if row_index != expected_idx {
                return Err(AcuError::SerializationError("non-contiguous PQ row_index"));
            }
            let seat_id = read_lp64_str(bytes, cursor, MAX_SEAT_ID_BYTES)?;
            if !is_valid_seat_id(&seat_id) {
                return Err(AcuError::InvalidSeatId);
            }
            let loc_slice = take_slice(bytes, cursor, 32)?;
            let mut row_locator = [0u8; 32];
            row_locator.copy_from_slice(loc_slice);

            let mut matrix_row = Vec::with_capacity(cols);
            for _ in 0..cols {
                matrix_row.push(read_scalar(bytes, cursor)?);
            }
            let enc_slice = take_slice(bytes, cursor, XWING_ENCAPPED_KEY_BYTES)?;
            let mut encapped_key = [0u8; XWING_ENCAPPED_KEY_BYTES];
            encapped_key.copy_from_slice(enc_slice);

            let ct_slice = take_slice(bytes, cursor, PQ_CAPSULE_CIPHERTEXT_BYTES)?;
            let mut ciphertext = [0u8; PQ_CAPSULE_CIPHERTEXT_BYTES];
            ciphertext.copy_from_slice(ct_slice);

            matrix_rows.push((seat_id.clone(), matrix_row.clone()));
            rows.push(PqCapsuleRow {
                row_index,
                seat_id,
                row_locator,
                matrix_row,
                encapped_key,
                ciphertext,
            });
        }

        let header = Self {
            wrap_epoch,
            matrix: LsssMatrix {
                cols,
                rows: matrix_rows,
                gates,
            },
            rows,
            pqsbc_nonce,
            ct_pqsbc,
        };
        header.validate(acu_seat_id)?;
        Ok(header)
    }
}

fn blind_pq_handle(locator: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(8 + 32);
    s.push_str("blindpq:");
    for &b in &locator[..16] {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decapsulated post-quantum LSSS share $(\mu_m, \mu^{\mathsf{sbc}}_m) \in \mathbb{F}_r^2$ held by
/// a non-ACU custodian (`zeroized` on drop and redacted in `Debug`).
#[derive(Clone)]
pub struct PqDecryptionShare {
    /// Object identifier $O$ binding this PQ share.
    pub object_digest: [u8; 32],
    /// Wrap epoch matching [`EncryptedCiPayload::dek_wrap_epoch`].
    pub wrap_epoch: u64,
    /// Row index $m$ in [`PqLsssHeader::rows`].
    pub pq_row_index: usize,
    /// Non-ACU seat identifier $\rho^{\mathsf{pq}}(m)$.
    pub seat_id: String,
    pub(crate) mu: Scalar,
    pub(crate) mu_sbc: Scalar,
}

impl Drop for PqDecryptionShare {
    fn drop(&mut self) {
        self.mu.zeroize();
        self.mu_sbc.zeroize();
    }
}

impl PartialEq for PqDecryptionShare {
    fn eq(&self, other: &Self) -> bool {
        self.wrap_epoch == other.wrap_epoch
            && self.pq_row_index == other.pq_row_index
            && self.seat_id == other.seat_id
            && bool::from(self.object_digest.ct_eq(&other.object_digest))
            && bool::from(self.mu.to_bytes().ct_eq(&other.mu.to_bytes()))
            && bool::from(self.mu_sbc.to_bytes().ct_eq(&other.mu_sbc.to_bytes()))
    }
}

impl Eq for PqDecryptionShare {}

impl std::fmt::Debug for PqDecryptionShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqDecryptionShare")
            .field("wrap_epoch", &self.wrap_epoch)
            .field("pq_row_index", &self.pq_row_index)
            .field("seat_id", &self.seat_id)
            .field("mu", &"<REDACTED>")
            .field("mu_sbc", &"<REDACTED>")
            .finish()
    }
}

/// Dual-Secret Hybrid `CHWGAEA2` CI/CD & Zero-Plaintext-At-Rest Inbox Envelope (`ePrint v2` §6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedCiPayload {
    /// Dynamic classical pairing ACU header (`CHWGACU3`) encapsulating $K_{\mathbb{G}_T} \in \mathbb{G}_T$.
    pub acu_ciphertext: AcuCiphertext,
    /// Access-structured non-ACU post-quantum `0x647a` header encapsulating $K_{\mathsf{PQ}} \in \mathbb{F}_r$
    /// (`None` only when a degenerate test policy has zero non-ACU leaves).
    pub pq_header: Option<PqLsssHeader>,
    /// Monotonic `DEK` wrap epoch (`1` initially; unchanged across ciphertext-only `revoke_and_rerandomize`
    /// and `escalate_threshold`, incremented by [`EncryptedCiPayload::rotate_pq_key`]).
    pub dek_wrap_epoch: u64,
    /// `96`-bit ChaCha20-Poly1305 nonce for `wrapped_dek`.
    pub dek_wrap_nonce: [u8; 12],
    /// `48`-byte wrapped `DEK` (`ChaCha20Poly1305(k_kek, dek_wrap_nonce, dek_aad, DEK)`).
    pub wrapped_dek: [u8; WRAPPED_DEK_BYTES],
    /// Immutable SHA-256 digest $h_C = \mathsf{SHA256}(C_1)$ of `aead_ciphertext`.
    pub c1_sha256: [u8; 32],
    /// `96`-bit ChaCha20-Poly1305 nonce for immutable `aead_ciphertext` (`C_1`).
    pub nonce: [u8; 12],
    /// Canonical epoch-independent associated data (`AAD_pay`) bound to `object_digest`, `repo_id`, and `task_id`.
    pub associated_data: Vec<u8>,
    /// Immutable ChaCha20-Poly1305 payload ciphertext `C_1` (`C_{E+1} == C_1` across all epochs!).
    pub aead_ciphertext: Vec<u8>,
}

impl EncryptedCiPayload {
    /// Compute `aead_immutable_blake3` over ONLY the immutable symmetric tuple
    /// `(nonce, associated_data, aead_ciphertext)` (`UI v5` `F-02`):
    /// **strictly invariant** across `revoke_and_rerandomize`, `escalate_threshold`, `insert_sibling_key`,
    /// `insert_authorized_seat`, and `rotate_pq_key`!
    #[must_use]
    pub fn immutable_aead_blake3(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(IMMUTABLE_AEAD_HASH_DOMAIN);
        h.update(&self.nonce);
        h.update(&(self.associated_data.len() as u64).to_be_bytes());
        h.update(&self.associated_data);
        h.update(&(self.aead_ciphertext.len() as u64).to_be_bytes());
        h.update(&self.aead_ciphertext);
        *h.finalize().as_bytes()
    }

    /// Serialize this [`EncryptedCiPayload`] into canonical `CHWGAEA2` binary bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_internal(false)
    }

    /// Serialize this [`EncryptedCiPayload`] into Blind-Relay / R2-Parquet `CHWGAEA2` bytes where
    /// all cleartext seat IDs inside `acu_ciphertext` and `pq_header` are replaced by blind handles.
    #[must_use]
    pub fn to_blind_bytes(&self) -> Vec<u8> {
        self.encode_internal(true)
    }

    fn encode_internal(&self, blind_seats: bool) -> Vec<u8> {
        let acu_bytes = if blind_seats {
            self.acu_ciphertext.to_blind_bytes()
        } else {
            self.acu_ciphertext.to_bytes()
        };
        let mut out = Vec::with_capacity(
            128 + self.associated_data.len() + self.aead_ciphertext.len() + acu_bytes.len(),
        );
        out.extend_from_slice(ENCRYPTED_PAYLOAD_MAGIC);
        out.extend_from_slice(&self.dek_wrap_epoch.to_be_bytes());
        out.extend_from_slice(&self.dek_wrap_nonce);
        out.extend_from_slice(&self.wrapped_dek);
        out.extend_from_slice(&self.c1_sha256);
        out.extend_from_slice(&self.nonce);
        lp64(&mut out, &self.associated_data);
        lp64(&mut out, &self.aead_ciphertext);
        lp64(&mut out, &acu_bytes);
        match &self.pq_header {
            None => out.push(0u8),
            Some(pq) => {
                out.push(1u8);
                let mut pq_buf = Vec::new();
                pq.encode_into(&mut pq_buf, blind_seats);
                lp64(&mut out, &pq_buf);
            }
        }
        out
    }

    /// Resolve blind seat handles across both `acu_ciphertext` and `pq_header` using `locator_key`.
    pub fn resolve_blind_seats(
        &mut self,
        locator_key: &[u8; 32],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
    ) {
        self.acu_ciphertext
            .resolve_blind_seats(locator_key, seat_keys);
        if let Some(pq) = &mut self.pq_header {
            for idx in 0..pq.rows.len() {
                let row = &pq.rows[idx];
                let mut matched = None;
                for cand_id in seat_keys.keys() {
                    let cand_loc = compute_blind_row_locator(
                        locator_key,
                        &self.acu_ciphertext.object_digest,
                        pq.wrap_epoch,
                        idx as u32,
                        cand_id,
                    );
                    if bool::from(cand_loc.ct_eq(&row.row_locator)) {
                        matched = Some(cand_id.clone());
                        break;
                    }
                }
                if let Some(real_id) = matched {
                    pq.rows[idx].seat_id.clone_from(&real_id);
                    pq.matrix.rows[idx].0.clone_from(&real_id);
                }
            }
        }
    }

    /// Deserialize an [`EncryptedCiPayload`] from canonical `CHWGAEA2` bytes, failing closed with
    /// [`AcuError::InsecureLegacyFormat`] on legacy `CHWGAEAD`, `CHWGACU1`, or `CHWGACU2` wire blobs.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AcuError> {
        if bytes.len() > MAX_SERIALIZED_BLOB_BYTES {
            return Err(AcuError::SerializationError(
                "EncryptedCiPayload exceeds max size",
            ));
        }
        let mut cursor = 0usize;
        let magic = take_slice(bytes, &mut cursor, 8)?;
        if magic == LEGACY_ENCRYPTED_PAYLOAD_MAGIC {
            return Err(AcuError::InsecureLegacyFormat("CHWGAEAD"));
        }
        if magic != ENCRYPTED_PAYLOAD_MAGIC {
            return Err(AcuError::SerializationError(
                "invalid EncryptedCiPayload magic",
            ));
        }
        let dek_wrap_epoch = read_u64_be(bytes, &mut cursor)?;
        if dek_wrap_epoch == 0 {
            return Err(AcuError::SerializationError("dek_wrap_epoch must be >= 1"));
        }
        let dw_nonce_slice = take_slice(bytes, &mut cursor, 12)?;
        let mut dek_wrap_nonce = [0u8; 12];
        dek_wrap_nonce.copy_from_slice(dw_nonce_slice);

        let wdek_slice = take_slice(bytes, &mut cursor, WRAPPED_DEK_BYTES)?;
        let mut wrapped_dek = [0u8; WRAPPED_DEK_BYTES];
        wrapped_dek.copy_from_slice(wdek_slice);

        let c1_hash_slice = take_slice(bytes, &mut cursor, 32)?;
        let mut c1_sha256 = [0u8; 32];
        c1_sha256.copy_from_slice(c1_hash_slice);

        let nonce_slice = take_slice(bytes, &mut cursor, 12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_slice);

        let associated_data = read_lp64(bytes, &mut cursor, MAX_SERIALIZED_BLOB_BYTES)?.to_vec();
        if associated_data.is_empty() {
            return Err(AcuError::SerializationError("empty associated_data"));
        }
        let aead_ciphertext = read_lp64(bytes, &mut cursor, MAX_SERIALIZED_BLOB_BYTES)?.to_vec();
        if aead_ciphertext.len() < 16 {
            return Err(AcuError::SerializationError(
                "aead_ciphertext shorter than Poly1305 tag",
            ));
        }
        let actual_c1_hash: [u8; 32] = Sha256::digest(&aead_ciphertext).into();
        if !bool::from(actual_c1_hash.ct_eq(&c1_sha256)) {
            return Err(AcuError::SerializationError("c1_sha256 integrity mismatch"));
        }

        let acu_slice = read_lp64(bytes, &mut cursor, MAX_SERIALIZED_BLOB_BYTES)?;
        let acu_ciphertext = AcuCiphertext::from_bytes(acu_slice)?;

        let has_pq = read_u8(bytes, &mut cursor)?;
        let pq_header = match has_pq {
            0 => None,
            1 => {
                let pq_slice = read_lp64(bytes, &mut cursor, MAX_SERIALIZED_BLOB_BYTES)?;
                let mut pq_cur = 0usize;
                let pq =
                    PqLsssHeader::decode_from(pq_slice, &mut pq_cur, &acu_ciphertext.acu_seat_id)?;
                if pq_cur != pq_slice.len() || pq.wrap_epoch != dek_wrap_epoch {
                    return Err(AcuError::SerializationError(
                        "PqLsssHeader trailing bytes or wrap_epoch mismatch",
                    ));
                }
                Some(pq)
            }
            _ => {
                return Err(AcuError::SerializationError(
                    "invalid pq_header presence tag",
                ));
            }
        };

        if cursor != bytes.len() {
            return Err(AcuError::SerializationError(
                "trailing bytes in EncryptedCiPayload",
            ));
        }

        Ok(Self {
            acu_ciphertext,
            pq_header,
            dek_wrap_epoch,
            dek_wrap_nonce,
            wrapped_dek,
            c1_sha256,
            nonce,
            associated_data,
            aead_ciphertext,
        })
    }

    /// Build Brian's canonical 2-of-2 Split-Key Instant Revocation policy (`agent AND acu`).
    #[must_use]
    pub fn build_split_key_acu_policy(agent_branch_id: &str, acu_branch_id: &str) -> AccessTree {
        AccessTree::And(vec![
            AccessTree::Leaf(agent_branch_id.to_string()),
            AccessTree::Leaf(acu_branch_id.to_string()),
        ])
    }

    /// Encrypt a CI/CD root-cause payload under the 2-of-2 Split-Key ACU policy (`agent AND acu`).
    pub fn encrypt_split_key_with_acu(
        plaintext: &[u8],
        agent_pk: &SeatPublicKey,
        acu_pk: &SeatPublicKey,
        repo_id: &str,
        task_id: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        let tree = Self::build_split_key_acu_policy(&agent_pk.seat_id, &acu_pk.seat_id);
        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(agent_pk.seat_id.clone(), agent_pk.clone());
        seat_keys.insert(acu_pk.seat_id.clone(), acu_pk.clone());
        Self::encrypt(plaintext, &tree, &seat_keys, acu_pk, repo_id, task_id, rng)
    }

    /// Build the canonical **Zero-Plaintext-At-Rest Inbox + Forensic Archive** 2-of-3 policy
    /// (`ACU AND (Recipient OR Archive)`).
    #[must_use]
    pub fn build_acu_recipient_or_archive_policy(
        acu_seat_id: &str,
        recipient_seat_id: &str,
        archive_seat_id: &str,
    ) -> AccessTree {
        AccessTree::And(vec![
            AccessTree::Leaf(acu_seat_id.to_string()),
            AccessTree::Or(vec![
                AccessTree::Leaf(recipient_seat_id.to_string()),
                AccessTree::Leaf(archive_seat_id.to_string()),
            ]),
        ])
    }

    /// Encrypt a bus message or CI/CD payload under `ACU AND (Recipient OR Archive)`.
    pub fn encrypt_with_acu_and_archive(
        plaintext: &[u8],
        acu_pk: &SeatPublicKey,
        recipient_pk: &SeatPublicKey,
        archive_pk: &SeatPublicKey,
        repo_id: &str,
        task_id: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        let tree = Self::build_acu_recipient_or_archive_policy(
            &acu_pk.seat_id,
            &recipient_pk.seat_id,
            &archive_pk.seat_id,
        );
        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(acu_pk.seat_id.clone(), acu_pk.clone());
        seat_keys.insert(recipient_pk.seat_id.clone(), recipient_pk.clone());
        seat_keys.insert(archive_pk.seat_id.clone(), archive_pk.clone());
        Self::encrypt(plaintext, &tree, &seat_keys, acu_pk, repo_id, task_id, rng)
    }

    /// Encrypt `plaintext` under an arbitrary monotone [`AccessTree`] using Dual-Secret Hybrid
    /// `CHWGAEA2` (`BLS12-381` `CHWGACU3` + non-ACU `0x647a` `X25519-MLKEM768` capsules + `48` B `wrapped_dek`).
    pub fn encrypt(
        plaintext: &[u8],
        tree: &AccessTree,
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        acu_pk: &SeatPublicKey,
        repo_id: &str,
        task_id: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        let mut locator_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut locator_key[..]);
        Self::encrypt_with_locator_key(
            plaintext,
            tree,
            seat_keys,
            acu_pk,
            repo_id,
            task_id,
            &locator_key,
            rng,
        )
    }

    /// Encrypt `plaintext` using an explicit workspace `locator_key` ($k_{\mathsf{idx}}$) for
    /// deterministic blind row locators across `acu_ciphertext` and `pq_header`.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_with_locator_key(
        plaintext: &[u8],
        tree: &AccessTree,
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        acu_pk: &SeatPublicKey,
        repo_id: &str,
        task_id: &str,
        locator_key: &[u8; 32],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        if !is_valid_metadata_token(repo_id) || !is_valid_metadata_token(task_id) {
            return Err(AcuError::InvalidMetadata);
        }
        if plaintext.len() > MAX_SERIALIZED_BLOB_BYTES / 2 {
            return Err(AcuError::SerializationError("plaintext exceeds max size"));
        }

        let matrix = LsssMatrix::from_tree(tree)?;

        // 1. Sample immutable 256-bit DEK != 0^256 and encrypt C_1 ONCE with epoch-independent AAD_pay.
        let mut dek = Zeroizing::new([0u8; 32]);
        loop {
            rng.fill_bytes(&mut dek[..]);
            if !bool::from(dek[..].ct_eq(&[0u8; 32])) {
                break;
            }
        }
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let object_digest = compute_object_digest(repo_id, task_id, &nonce);
        let associated_data = encode_payload_aad(&object_digest, repo_id, task_id);

        let pay_cipher = ChaCha20Poly1305::new(Key::from_slice(&*dek));
        let aead_ciphertext = pay_cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| AcuError::AeadFailure)?;
        let c1_sha256: [u8; 32] = Sha256::digest(&aead_ciphertext).into();

        // 2. Seal classical pairing header CHWGACU3 at policy_epoch = 1.
        let mut k_scalar = sample_nonzero_scalar(rng);
        let mut payload_g1 = G1Projective::generator() * k_scalar;
        k_scalar.zeroize();
        let (acu_ciphertext, mut k_gt) = acu_encrypt_with_g1_and_context(
            &payload_g1,
            &object_digest,
            locator_key,
            &matrix,
            seat_keys,
            acu_pk,
            rng,
        )?;
        payload_g1.zeroize();

        // 3. Project non-ACU policy T_conf = T|_{ACU=true} and seal 0x647a PQ capsules (ACU gets 0 rows!).
        let dek_wrap_epoch = 1u64;
        let (pq_header, mut k_pq) = match project_non_acu(tree, &acu_pk.seat_id)? {
            None => (None, Scalar::ZERO),
            Some(conf_tree) => {
                let pq_matrix = LsssMatrix::from_tree(&conf_tree)?;
                let (hdr, secret_pq) = build_pq_lsss_header(
                    &object_digest,
                    dek_wrap_epoch,
                    locator_key,
                    &pq_matrix,
                    &acu_pk.seat_id,
                    seat_keys,
                    rng,
                )?;
                (Some(hdr), secret_pq)
            }
        };

        // 4. Wrap 32-byte DEK into 48-byte `wrapped_dek` under HKDF(Canon_Fp12(K_GT) || Canon_Fr(K_PQ)).
        let k_kek = derive_hybrid_kek(&k_gt, &k_pq, &object_digest, dek_wrap_epoch)?;
        k_gt.zeroize();
        k_pq.zeroize();

        let mut dek_wrap_nonce = [0u8; 12];
        rng.fill_bytes(&mut dek_wrap_nonce);
        let wrapped_dek = wrap_dek_slot(
            &k_kek,
            &dek_wrap_nonce,
            &object_digest,
            dek_wrap_epoch,
            &c1_sha256,
            &dek,
        )?;

        Ok(Self {
            acu_ciphertext,
            pq_header,
            dek_wrap_epoch,
            dek_wrap_nonce,
            wrapped_dek,
            c1_sha256,
            nonce,
            associated_data,
            aead_ciphertext,
        })
    }

    /// Decapsulate a single post-quantum `0x647a` row capsule `pq_row_index` using a non-ACU
    /// custodian's [`SeatSecretKey`].
    pub fn decapsulate_pq_share(
        &self,
        pq_row_index: usize,
        secret_key: &SeatSecretKey,
    ) -> Result<PqDecryptionShare, AcuError> {
        let Some(pq) = &self.pq_header else {
            return Err(AcuError::PolicyNotSatisfied);
        };
        let row = pq
            .rows
            .get(pq_row_index)
            .ok_or(AcuError::RowIndexOutOfBounds {
                index: pq_row_index,
                total_rows: pq.rows.len(),
            })?;
        if row.seat_id != secret_key.seat_id {
            return Err(AcuError::UnauthorizedPolicyOperator);
        }
        let info = encode_pq_row_info(
            &self.acu_ciphertext.object_digest,
            pq.wrap_epoch,
            &row.row_locator,
        );
        let opened = secret_key.pq_sk.open_base(
            &row.encapped_key,
            &info,
            &self.acu_ciphertext.object_digest,
            &row.ciphertext,
        )?;
        if opened.len() != 64 {
            return Err(AcuError::AeadFailure);
        }
        let mut cur = 0usize;
        let mu = read_scalar(&opened, &mut cur)?;
        let mu_sbc = read_scalar(&opened, &mut cur)?;
        Ok(PqDecryptionShare {
            object_digest: self.acu_ciphertext.object_digest,
            wrap_epoch: pq.wrap_epoch,
            pq_row_index,
            seat_id: secret_key.seat_id.clone(),
            mu,
            mu_sbc,
        })
    }

    /// Decapsulate all `0x647a` PQ capsules in `self.pq_header` addressed to `secret_key.seat_id()`.
    pub fn decapsulate_pq_shares_for_seat(
        &self,
        secret_key: &SeatSecretKey,
    ) -> Result<Vec<PqDecryptionShare>, AcuError> {
        let Some(pq) = &self.pq_header else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for row in &pq.rows {
            if row.seat_id == secret_key.seat_id {
                out.push(self.decapsulate_pq_share(row.row_index, secret_key)?);
            }
        }
        Ok(out)
    }

    /// Prune revoked non-ACU seats from `self.pq_header` alongside classical `revoke_and_rerandomize`.
    pub fn prune_revoked_pq_capsules(&mut self, revoked_seat_ids: &[&str]) -> Result<(), AcuError> {
        let Some(pq) = &mut self.pq_header else {
            return Ok(());
        };
        let revoked: BTreeSet<&str> = revoked_seat_ids.iter().copied().collect();
        let keep_mask: Vec<bool> = pq
            .rows
            .iter()
            .map(|r| !revoked.contains(r.seat_id.as_str()))
            .collect();
        if !keep_mask.iter().any(|&k| k) {
            return Err(AcuError::PolicyUnsatisfiableAfterRevocation);
        }
        let mut next_matrix = pq.matrix.clone();
        next_matrix.retain_rows(&keep_mask)?;
        let surviving: Vec<usize> = (0..next_matrix.rows.len()).collect();
        if find_reconstruction_weights(&next_matrix, &surviving).is_err() {
            return Err(AcuError::PolicyUnsatisfiableAfterRevocation);
        }

        let mut next_rows = Vec::new();
        for (keep, old_row) in keep_mask.iter().zip(pq.rows.iter()) {
            if *keep {
                let mut cloned = old_row.clone();
                cloned.row_index = next_rows.len();
                next_rows.push(cloned);
            }
        }
        pq.matrix = next_matrix;
        pq.rows = next_rows;
        pq.validate(&self.acu_ciphertext.acu_seat_id)
    }

    /// Attach a `0x647a` post-quantum sibling capsule for a `Shadow-KV` warm-fork seat using the
    /// authorizing sibling custodian's `existing_sk` (`ACU` never touches `K_PQ`!).
    pub fn attach_pq_sibling_capsule(
        &mut self,
        existing_sk: &SeatSecretKey,
        new_pk: &SeatPublicKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<usize, AcuError> {
        if !new_pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(new_pk.seat_id.clone()));
        }
        if new_pk.seat_id == self.acu_ciphertext.acu_seat_id
            || existing_sk.seat_id == self.acu_ciphertext.acu_seat_id
        {
            return Err(AcuError::UnauthorizedPolicyOperator);
        }
        let Some(pq_idx) = self.pq_header.as_ref().and_then(|pq| {
            pq.rows
                .iter()
                .position(|r| r.seat_id == existing_sk.seat_id)
        }) else {
            return Err(AcuError::UnknownSeat(existing_sk.seat_id.clone()));
        };
        let share = self.decapsulate_pq_share(pq_idx, existing_sk)?;

        let pq = self.pq_header.as_mut().expect("checked Some above");
        let new_row_idx = pq.matrix.attach_sibling(pq_idx, new_pk.seat_id.clone())?;
        let m_vec = pq.matrix.rows[new_row_idx].1.clone();

        let mut pt = Zeroizing::new([0u8; 64]);
        pt[..32].copy_from_slice(&share.mu.to_bytes());
        pt[32..].copy_from_slice(&share.mu_sbc.to_bytes());

        let mut loc_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut loc_key[..]);
        let row_locator = compute_blind_row_locator(
            &loc_key,
            &self.acu_ciphertext.object_digest,
            pq.wrap_epoch,
            new_row_idx as u32,
            &new_pk.seat_id,
        );

        let info = encode_pq_row_info(
            &self.acu_ciphertext.object_digest,
            pq.wrap_epoch,
            &row_locator,
        );
        let (encapped_key, ct_vec) =
            new_pk
                .pq_pk
                .seal_base(&info, &self.acu_ciphertext.object_digest, &pt[..], rng)?;
        if ct_vec.len() != PQ_CAPSULE_CIPHERTEXT_BYTES {
            return Err(AcuError::AeadFailure);
        }
        let mut ciphertext = [0u8; PQ_CAPSULE_CIPHERTEXT_BYTES];
        ciphertext.copy_from_slice(&ct_vec);

        pq.rows.push(PqCapsuleRow {
            row_index: new_row_idx,
            seat_id: new_pk.seat_id.clone(),
            row_locator,
            matrix_row: m_vec,
            encapped_key,
            ciphertext,
        });
        pq.validate(&self.acu_ciphertext.acu_seat_id)?;
        Ok(new_row_idx)
    }

    /// Append a coalition-authorized non-ACU `0x647a` post-quantum seat (`new_seat_id`, `new_pq_row_vec`)
    /// to `self.pq_header` using `coalition_pq_shares` (`ePrint v2` §6.3 Op 3):
    /// - Reconstructs $K_{\mathsf{PQ}} = v^{\mathsf{pq}}_0$ and $K_{\mathsf{pqsbc}} = v^{\mathsf{sbc}}_0$,
    ///   decrypting `ct_pqsbc` to recover $(v^{\mathsf{pq}}_1, \dots, v^{\mathsf{pq}}_{k_{\mathsf{pq}}-1})$,
    /// - Re-seals `PqLsssHeader` over the extended matrix with the **identical** $v^{\mathsf{pq}}$
    ///   and fresh $v'^{\mathsf{sbc}}$ (zero KDM cycle; `dek_wrap_epoch`, `wrapped_dek`, and `C_1` stay untouched!).
    pub fn insert_authorized_pq_seat(
        &mut self,
        new_seat_id: impl Into<String>,
        new_pq_row_vec: Vec<Scalar>,
        coalition_pq_shares: &[PqDecryptionShare],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<usize, AcuError> {
        let new_seat_id = new_seat_id.into();
        if !is_valid_seat_id(&new_seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        if new_seat_id == self.acu_ciphertext.acu_seat_id {
            return Err(AcuError::UnauthorizedPolicyOperator);
        }
        let new_pk = seat_keys
            .get(&new_seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(new_seat_id.clone()))?;
        if !new_pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(new_seat_id));
        }
        let Some(pq) = &self.pq_header else {
            return Err(AcuError::PolicyNotSatisfied);
        };
        if new_pq_row_vec.len() != pq.matrix.cols {
            return Err(AcuError::DimensionMismatch {
                expected: pq.matrix.cols,
                actual: new_pq_row_vec.len(),
            });
        }
        if coalition_pq_shares.is_empty() {
            return Err(AcuError::PolicyNotSatisfied);
        }

        let mut mu_by_row: BTreeMap<usize, (Scalar, Scalar)> = BTreeMap::new();
        let mut indices = Vec::with_capacity(coalition_pq_shares.len());
        for s in coalition_pq_shares {
            if s.wrap_epoch != self.dek_wrap_epoch {
                return Err(AcuError::EpochMismatch {
                    expected: self.dek_wrap_epoch,
                    actual: s.wrap_epoch,
                });
            }
            let row = pq
                .rows
                .get(s.pq_row_index)
                .ok_or(AcuError::RowIndexOutOfBounds {
                    index: s.pq_row_index,
                    total_rows: pq.rows.len(),
                })?;
            if s.seat_id != row.seat_id
                || !bool::from(s.object_digest.ct_eq(&self.acu_ciphertext.object_digest))
            {
                return Err(AcuError::InvalidPartialShare {
                    row_index: s.pq_row_index,
                    seat_id: s.seat_id.clone(),
                });
            }
            if mu_by_row.insert(s.pq_row_index, (s.mu, s.mu_sbc)).is_none() {
                indices.push(s.pq_row_index);
            }
        }

        let weights = find_reconstruction_weights(&pq.matrix, &indices)?;
        let mut v_pq_0 = Scalar::ZERO;
        let mut v_pqsbc_0 = Scalar::ZERO;
        for (idx, omega) in weights {
            let &(mu, mu_sbc) = mu_by_row.get(&idx).ok_or(AcuError::PolicyNotSatisfied)?;
            v_pq_0 += mu * omega;
            v_pqsbc_0 += mu_sbc * omega;
        }

        let aux_cols = pq.matrix.cols.saturating_sub(1);
        let k_pqsbc_bytes = Zeroizing::new(v_pqsbc_0.to_bytes());
        v_pqsbc_0.zeroize();

        let hk = Hkdf::<Sha256>::new(Some(PQSBC_HKDF_SALT), &*k_pqsbc_bytes);
        let mut info = Vec::with_capacity(PQSBC_HKDF_INFO_DOMAIN.len() + 40);
        info.extend_from_slice(PQSBC_HKDF_INFO_DOMAIN);
        info.extend_from_slice(&self.acu_ciphertext.object_digest);
        info.extend_from_slice(&pq.wrap_epoch.to_be_bytes());
        let mut pqsbc_key = Zeroizing::new([0u8; 32]);
        hk.expand(&info, &mut *pqsbc_key)
            .map_err(|_| AcuError::AeadFailure)?;

        let mut pqsbc_aad = Vec::with_capacity(PQSBC_AAD_DOMAIN.len() + 40);
        pqsbc_aad.extend_from_slice(PQSBC_AAD_DOMAIN);
        pqsbc_aad.extend_from_slice(&self.acu_ciphertext.object_digest);
        pqsbc_aad.extend_from_slice(&pq.wrap_epoch.to_be_bytes());

        let pqsbc_cipher = ChaCha20Poly1305::new(Key::from_slice(&*pqsbc_key));
        let pqsbc_pt = Zeroizing::new(
            pqsbc_cipher
                .decrypt(
                    Nonce::from_slice(&pq.pqsbc_nonce),
                    Payload {
                        msg: &pq.ct_pqsbc,
                        aad: &pqsbc_aad,
                    },
                )
                .map_err(|_| AcuError::BasisUnsealFailed)?,
        );
        if pqsbc_pt.len() != aux_cols * 32 {
            v_pq_0.zeroize();
            return Err(AcuError::BasisUnsealFailed);
        }

        let mut v_pq = Zeroizing::new(Vec::with_capacity(pq.matrix.cols));
        v_pq.push(v_pq_0);
        v_pq_0.zeroize();
        let mut cur = 0usize;
        for _ in 0..aux_cols {
            v_pq.push(read_scalar(&pqsbc_pt, &mut cur)?);
        }

        let mut next_pq_matrix = pq.matrix.clone();
        let new_row_idx = next_pq_matrix.append_authorized_row(new_seat_id, new_pq_row_vec)?;

        let mut loc_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut loc_key[..]);
        let updated_hdr = seal_pq_lsss_header_from_vector(
            &self.acu_ciphertext.object_digest,
            pq.wrap_epoch,
            &loc_key,
            &next_pq_matrix,
            &self.acu_ciphertext.acu_seat_id,
            seat_keys,
            &v_pq,
            rng,
        )?;
        self.pq_header = Some(updated_hdr);
        Ok(new_row_idx)
    }

    /// Coalition-authorized **Post-Quantum KEK Forward Rotation (`RotatePQKey`, `ePrint v2` §6.3 Op 4)**:
    /// 1. Combines verified `pairing_shares` + `pq_shares` to unwrap the `32`-byte `DEK` from
    ///    the `48`-byte `wrapped_dek` slot,
    /// 2. Samples fresh $(K'_{\mathbb{G}_T}, K'_{\mathsf{PQ}})$ over the current surviving policies
    ///    (pruning any seats already removed from `acu_ciphertext.matrix` out of `pq_header` as well),
    /// 3. Increments both `policy_epoch` and `dek_wrap_epoch`, re-wrapping only `wrapped_dek` (`48` B)
    ///    while **leaving `aead_ciphertext` (`C_1`), `nonce`, `associated_data`, and
    ///    `immutable_aead_blake3()` 100% untouched byte-for-byte (`C_{E+1} == C_1`)!**
    pub fn rotate_pq_key(
        &mut self,
        acu_pk: &SeatPublicKey,
        pairing_shares: &[PartialDecryptionShare],
        pq_shares: &[PqDecryptionShare],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), AcuError> {
        if acu_pk.seat_id != self.acu_ciphertext.acu_seat_id || !acu_pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(acu_pk.seat_id.clone()));
        }
        let mut old_gt = acu_combine(&self.acu_ciphertext, pairing_shares, seat_keys)?;
        let mut old_pq = self.combine_pq_shares(pq_shares)?;
        let old_kek = derive_hybrid_kek(
            &old_gt,
            &old_pq,
            &self.acu_ciphertext.object_digest,
            self.dek_wrap_epoch,
        )?;
        old_gt.zeroize();
        old_pq.zeroize();

        let dek = unwrap_dek_slot(
            &old_kek,
            &self.dek_wrap_nonce,
            &self.acu_ciphertext.object_digest,
            self.dek_wrap_epoch,
            &self.c1_sha256,
            &self.wrapped_dek,
        )?;

        let next_policy_epoch = self
            .acu_ciphertext
            .policy_epoch
            .checked_add(1)
            .ok_or(AcuError::SerializationError("policy_epoch overflow"))?;
        let next_wrap_epoch = self
            .dek_wrap_epoch
            .checked_add(1)
            .ok_or(AcuError::SerializationError("dek_wrap_epoch overflow"))?;

        let mut loc_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut loc_key[..]);

        // Re-seal fresh classical pairing header over the current `self.acu_ciphertext.matrix`
        // preserving `self.acu_ciphertext.object_digest` and advancing `policy_epoch`.
        let mut k_scalar = sample_nonzero_scalar(rng);
        let mut payload_g1 = G1Projective::generator() * k_scalar;
        k_scalar.zeroize();
        let (mut fresh_acu_ct, mut new_gt) = acu_encrypt_with_g1_and_context(
            &payload_g1,
            &self.acu_ciphertext.object_digest,
            &loc_key,
            &self.acu_ciphertext.matrix,
            seat_keys,
            acu_pk,
            rng,
        )?;
        payload_g1.zeroize();
        fresh_acu_ct.policy_epoch = next_policy_epoch;

        // Synchronize PQ matrix with currently active non-ACU seats and seal fresh 0x647a capsules!
        let active_seats: BTreeSet<&str> = fresh_acu_ct
            .rows
            .iter()
            .map(|r| r.seat_id.as_str())
            .collect();
        let (fresh_pq_hdr, mut new_pq) = match &self.pq_header {
            None => (None, Scalar::ZERO),
            Some(existing_pq) => {
                let keep_mask: Vec<bool> = existing_pq
                    .rows
                    .iter()
                    .map(|r| active_seats.contains(r.seat_id.as_str()))
                    .collect();
                let mut next_pq_matrix = existing_pq.matrix.clone();
                next_pq_matrix.retain_rows(&keep_mask)?;
                let (hdr, secret_pq) = build_pq_lsss_header(
                    &fresh_acu_ct.object_digest,
                    next_wrap_epoch,
                    &loc_key,
                    &next_pq_matrix,
                    &acu_pk.seat_id,
                    seat_keys,
                    rng,
                )?;
                (Some(hdr), secret_pq)
            }
        };

        let new_kek = derive_hybrid_kek(
            &new_gt,
            &new_pq,
            &fresh_acu_ct.object_digest,
            next_wrap_epoch,
        )?;
        new_gt.zeroize();
        new_pq.zeroize();

        let mut next_wrap_nonce = [0u8; 12];
        rng.fill_bytes(&mut next_wrap_nonce);
        let next_wrapped_dek = wrap_dek_slot(
            &new_kek,
            &next_wrap_nonce,
            &fresh_acu_ct.object_digest,
            next_wrap_epoch,
            &self.c1_sha256,
            &dek,
        )?;

        self.acu_ciphertext = fresh_acu_ct;
        self.pq_header = fresh_pq_hdr;
        self.dek_wrap_epoch = next_wrap_epoch;
        self.dek_wrap_nonce = next_wrap_nonce;
        self.wrapped_dek = next_wrapped_dek;
        Ok(())
    }

    /// Decrypt this Dual-Secret Hybrid `CHWGAEA2` payload using verified classical `pairing_shares`
    /// (`48` B $\mathbb{G}_1$ + `DLEQ`) and post-quantum `pq_shares` (`0x647a` `X25519-MLKEM768`).
    pub fn decrypt(
        &self,
        pairing_shares: &[PartialDecryptionShare],
        pq_shares: &[PqDecryptionShare],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
    ) -> Result<Vec<u8>, AcuError> {
        let mut recovered_gt = acu_combine(&self.acu_ciphertext, pairing_shares, seat_keys)?;
        let mut recovered_pq = self.combine_pq_shares(pq_shares)?;
        let res = self.decrypt_with_dual_secrets(&recovered_gt, &recovered_pq);
        recovered_gt.zeroize();
        recovered_pq.zeroize();
        res
    }

    /// Ergonomic helper for single-custodian + `ACU` coalitions (e.g. `Agent + ACU` or `Archive + ACU`):
    /// automatically decapsulates `local_custodian_sk`'s `0x647a` PQ capsule(s) and calls [`Self::decrypt`].
    pub fn decrypt_with_local_key(
        &self,
        pairing_shares: &[PartialDecryptionShare],
        local_custodian_sk: &SeatSecretKey,
        seat_keys: &BTreeMap<String, SeatPublicKey>,
    ) -> Result<Vec<u8>, AcuError> {
        let pq_shares = self.decapsulate_pq_shares_for_seat(local_custodian_sk)?;
        self.decrypt(pairing_shares, &pq_shares, seat_keys)
    }

    /// Combine `pairing_shares` without re-checking individual DLEQ proofs (`acu_combine_unverified`),
    /// combine `pq_shares`, unwrap `DEK`, and authenticate `aead_ciphertext` via Poly1305.
    pub fn decrypt_unverified(
        &self,
        pairing_shares: &[PartialDecryptionShare],
        pq_shares: &[PqDecryptionShare],
    ) -> Result<Vec<u8>, AcuError> {
        let mut recovered_gt = acu_combine_unverified(&self.acu_ciphertext, pairing_shares)?;
        let mut recovered_pq = self.combine_pq_shares(pq_shares)?;
        let res = self.decrypt_with_dual_secrets(&recovered_gt, &recovered_pq);
        recovered_gt.zeroize();
        recovered_pq.zeroize();
        res
    }

    fn combine_pq_shares(&self, pq_shares: &[PqDecryptionShare]) -> Result<Scalar, AcuError> {
        let Some(pq) = &self.pq_header else {
            return Ok(Scalar::ZERO);
        };
        if pq_shares.is_empty() {
            return Err(AcuError::PolicyNotSatisfied);
        }
        let mut by_row: BTreeMap<usize, Scalar> = BTreeMap::new();
        let mut indices = Vec::with_capacity(pq_shares.len());
        for s in pq_shares {
            if s.wrap_epoch != self.dek_wrap_epoch {
                return Err(AcuError::EpochMismatch {
                    expected: self.dek_wrap_epoch,
                    actual: s.wrap_epoch,
                });
            }
            let row = pq
                .rows
                .get(s.pq_row_index)
                .ok_or(AcuError::RowIndexOutOfBounds {
                    index: s.pq_row_index,
                    total_rows: pq.rows.len(),
                })?;
            if s.seat_id != row.seat_id
                || !bool::from(s.object_digest.ct_eq(&self.acu_ciphertext.object_digest))
            {
                return Err(AcuError::InvalidPartialShare {
                    row_index: s.pq_row_index,
                    seat_id: s.seat_id.clone(),
                });
            }
            if by_row.insert(s.pq_row_index, s.mu).is_none() {
                indices.push(s.pq_row_index);
            }
        }
        let weights = find_reconstruction_weights(&pq.matrix, &indices)?;
        let mut k_pq = Scalar::ZERO;
        for (idx, omega) in weights {
            let mu = by_row.get(&idx).ok_or(AcuError::PolicyNotSatisfied)?;
            k_pq += *mu * omega;
        }
        Ok(k_pq)
    }

    fn decrypt_with_dual_secrets(
        &self,
        recovered_gt: &Gt,
        recovered_pq: &Scalar,
    ) -> Result<Vec<u8>, AcuError> {
        let actual_c1_hash: [u8; 32] = Sha256::digest(&self.aead_ciphertext).into();
        if !bool::from(actual_c1_hash.ct_eq(&self.c1_sha256)) {
            return Err(AcuError::AeadFailure);
        }
        let k_kek = derive_hybrid_kek(
            recovered_gt,
            recovered_pq,
            &self.acu_ciphertext.object_digest,
            self.dek_wrap_epoch,
        )?;
        let dek = unwrap_dek_slot(
            &k_kek,
            &self.dek_wrap_nonce,
            &self.acu_ciphertext.object_digest,
            self.dek_wrap_epoch,
            &self.c1_sha256,
            &self.wrapped_dek,
        )?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*dek));
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.aead_ciphertext,
                    aad: &self.associated_data,
                },
            )
            .map_err(|_| AcuError::AeadFailure)
    }
}

/// Derive a 256-bit key from a `BLS12-381` target-group element $K \in \mathbb{G}_T$ using its
/// canonical `576`-byte $\mathbb{F}_{p^{12}}$ representation (`gt_canonical_bytes` — **zero**
/// `Debug` formatting or heap `String` allocations!).
pub fn derive_aead_key_from_gt(
    element: &Gt,
    associated_data: &[u8],
) -> Result<Zeroizing<[u8; 32]>, AcuError> {
    let canonical_fp12 = gt_canonical_bytes(element)?;
    let hk = Hkdf::<Sha256>::new(Some(GT_STANDALONE_HKDF_SALT), &*canonical_fp12);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(associated_data, &mut *okm)
        .map_err(|_| AcuError::AeadFailure)?;
    Ok(okm)
}

fn derive_hybrid_kek(
    k_gt: &Gt,
    k_pq: &Scalar,
    object_digest: &[u8; 32],
    dek_wrap_epoch: u64,
) -> Result<Zeroizing<[u8; 32]>, AcuError> {
    let gt_bytes = gt_canonical_bytes(k_gt)?;
    let pq_bytes = Zeroizing::new(k_pq.to_bytes());
    let mut ikm = Zeroizing::new([0u8; 576 + 32]);
    ikm[..576].copy_from_slice(&*gt_bytes);
    ikm[576..].copy_from_slice(&*pq_bytes);

    let hk = Hkdf::<Sha256>::new(Some(KEK_HKDF_SALT), &*ikm);
    let mut info = [0u8; 40];
    info[..32].copy_from_slice(object_digest);
    info[32..].copy_from_slice(&dek_wrap_epoch.to_be_bytes());

    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *kek)
        .map_err(|_| AcuError::AeadFailure)?;
    Ok(kek)
}

fn wrap_dek_slot(
    k_kek: &[u8; 32],
    dek_wrap_nonce: &[u8; 12],
    object_digest: &[u8; 32],
    dek_wrap_epoch: u64,
    c1_sha256: &[u8; 32],
    dek: &[u8; 32],
) -> Result<[u8; WRAPPED_DEK_BYTES], AcuError> {
    let aad = encode_dek_wrap_aad(object_digest, dek_wrap_epoch, c1_sha256);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_kek));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(dek_wrap_nonce),
            Payload {
                msg: dek,
                aad: &aad,
            },
        )
        .map_err(|_| AcuError::AeadFailure)?;
    if ct.len() != WRAPPED_DEK_BYTES {
        return Err(AcuError::AeadFailure);
    }
    let mut out = [0u8; WRAPPED_DEK_BYTES];
    out.copy_from_slice(&ct);
    Ok(out)
}

fn unwrap_dek_slot(
    k_kek: &[u8; 32],
    dek_wrap_nonce: &[u8; 12],
    object_digest: &[u8; 32],
    dek_wrap_epoch: u64,
    c1_sha256: &[u8; 32],
    wrapped_dek: &[u8; WRAPPED_DEK_BYTES],
) -> Result<Zeroizing<[u8; 32]>, AcuError> {
    let aad = encode_dek_wrap_aad(object_digest, dek_wrap_epoch, c1_sha256);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(k_kek));
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(dek_wrap_nonce),
                Payload {
                    msg: wrapped_dek,
                    aad: &aad,
                },
            )
            .map_err(|_| AcuError::AeadFailure)?,
    );
    if pt.len() != 32 || bool::from(pt[..].ct_eq(&[0u8; 32])) {
        return Err(AcuError::AeadFailure);
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&pt);
    Ok(dek)
}

fn build_pq_lsss_header(
    object_digest: &[u8; 32],
    wrap_epoch: u64,
    locator_key: &[u8; 32],
    pq_matrix: &LsssMatrix,
    acu_seat_id: &str,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(PqLsssHeader, Scalar), AcuError> {
    let k_pq_cols = pq_matrix.cols;
    let mut v_pq = Zeroizing::new(Vec::with_capacity(k_pq_cols));
    v_pq.push(sample_nonzero_scalar(rng));
    for _ in 1..k_pq_cols {
        v_pq.push(sample_uniform_scalar(rng));
    }
    let secret_pq = v_pq[0];
    let hdr = seal_pq_lsss_header_from_vector(
        object_digest,
        wrap_epoch,
        locator_key,
        pq_matrix,
        acu_seat_id,
        seat_keys,
        &v_pq,
        rng,
    )?;
    Ok((hdr, secret_pq))
}

#[allow(clippy::too_many_arguments)]
fn seal_pq_lsss_header_from_vector(
    object_digest: &[u8; 32],
    wrap_epoch: u64,
    locator_key: &[u8; 32],
    pq_matrix: &LsssMatrix,
    acu_seat_id: &str,
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    v_pq: &[Scalar],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<PqLsssHeader, AcuError> {
    let k_pq_cols = pq_matrix.cols;
    if v_pq.len() != k_pq_cols {
        return Err(AcuError::DimensionMismatch {
            expected: k_pq_cols,
            actual: v_pq.len(),
        });
    }

    let mut v_pqsbc = Zeroizing::new(Vec::with_capacity(k_pq_cols));
    v_pqsbc.push(sample_nonzero_scalar(rng));
    for _ in 1..k_pq_cols {
        v_pqsbc.push(sample_uniform_scalar(rng));
    }

    let mut rows = Vec::with_capacity(pq_matrix.rows.len());
    for (idx, (seat_id, m_row)) in pq_matrix.rows.iter().enumerate() {
        if seat_id == acu_seat_id {
            return Err(AcuError::SerializationError(
                "ACU seat forbidden inside PqLsssHeader",
            ));
        }
        let pk = seat_keys
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.clone()))?;
        if !pk.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id.clone()));
        }
        let mut mu_m = m_row
            .iter()
            .zip(v_pq.iter())
            .fold(Scalar::ZERO, |acc, (&m, &v)| acc + m * v);
        let mut mu_sbc_m = m_row
            .iter()
            .zip(v_pqsbc.iter())
            .fold(Scalar::ZERO, |acc, (&m, &v)| acc + m * v);

        let mut pt = Zeroizing::new([0u8; 64]);
        pt[..32].copy_from_slice(&mu_m.to_bytes());
        pt[32..].copy_from_slice(&mu_sbc_m.to_bytes());
        mu_m.zeroize();
        mu_sbc_m.zeroize();

        let row_locator =
            compute_blind_row_locator(locator_key, object_digest, wrap_epoch, idx as u32, seat_id);
        let info = encode_pq_row_info(object_digest, wrap_epoch, &row_locator);
        let (encapped_key, ct_vec) = pk.pq_pk.seal_base(&info, object_digest, &pt[..], rng)?;
        if ct_vec.len() != PQ_CAPSULE_CIPHERTEXT_BYTES {
            return Err(AcuError::AeadFailure);
        }
        let mut ciphertext = [0u8; PQ_CAPSULE_CIPHERTEXT_BYTES];
        ciphertext.copy_from_slice(&ct_vec);

        rows.push(PqCapsuleRow {
            row_index: idx,
            seat_id: seat_id.clone(),
            row_locator,
            matrix_row: m_row.clone(),
            encapped_key,
            ciphertext,
        });
    }

    // Seal auxiliary PQ scalars v_pq[1..] under independent K_pqsbc = v_pqsbc[0] (zero KDM cycle).
    let mut pqsbc_pt = Zeroizing::new(Vec::with_capacity((k_pq_cols - 1) * 32));
    for s in &v_pq[1..] {
        pqsbc_pt.extend_from_slice(&s.to_bytes());
    }
    let k_pqsbc_bytes = Zeroizing::new(v_pqsbc[0].to_bytes());
    let hk = Hkdf::<Sha256>::new(Some(PQSBC_HKDF_SALT), &*k_pqsbc_bytes);
    let mut info = Vec::with_capacity(PQSBC_HKDF_INFO_DOMAIN.len() + 40);
    info.extend_from_slice(PQSBC_HKDF_INFO_DOMAIN);
    info.extend_from_slice(object_digest);
    info.extend_from_slice(&wrap_epoch.to_be_bytes());
    let mut pqsbc_key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *pqsbc_key)
        .map_err(|_| AcuError::AeadFailure)?;

    let mut pqsbc_nonce = [0u8; 12];
    rng.fill_bytes(&mut pqsbc_nonce);
    let mut pqsbc_aad = Vec::with_capacity(PQSBC_AAD_DOMAIN.len() + 40);
    pqsbc_aad.extend_from_slice(PQSBC_AAD_DOMAIN);
    pqsbc_aad.extend_from_slice(object_digest);
    pqsbc_aad.extend_from_slice(&wrap_epoch.to_be_bytes());

    let pqsbc_cipher = ChaCha20Poly1305::new(Key::from_slice(&*pqsbc_key));
    let ct_pqsbc = pqsbc_cipher
        .encrypt(
            Nonce::from_slice(&pqsbc_nonce),
            Payload {
                msg: &pqsbc_pt,
                aad: &pqsbc_aad,
            },
        )
        .map_err(|_| AcuError::AeadFailure)?;

    let hdr = PqLsssHeader {
        wrap_epoch,
        matrix: pq_matrix.clone(),
        rows,
        pqsbc_nonce,
        ct_pqsbc,
    };
    hdr.validate(acu_seat_id)?;
    Ok(hdr)
}

fn compute_object_digest(repo_id: &str, task_id: &str, nonce: &[u8; 12]) -> [u8; 32] {
    let mut pre =
        Vec::with_capacity(OBJECT_DIGEST_DOMAIN.len() + 16 + repo_id.len() + task_id.len() + 12);
    pre.extend_from_slice(OBJECT_DIGEST_DOMAIN);
    lp64_str(&mut pre, repo_id);
    lp64_str(&mut pre, task_id);
    pre.extend_from_slice(nonce);
    Sha256::digest(&pre).into()
}

fn encode_payload_aad(object_digest: &[u8; 32], repo_id: &str, task_id: &str) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(PAYLOAD_AAD_DOMAIN.len() + 32 + 16 + repo_id.len() + task_id.len());
    aad.extend_from_slice(PAYLOAD_AAD_DOMAIN);
    aad.extend_from_slice(object_digest);
    lp64_str(&mut aad, repo_id);
    lp64_str(&mut aad, task_id);
    aad
}

fn encode_dek_wrap_aad(
    object_digest: &[u8; 32],
    dek_wrap_epoch: u64,
    c1_sha256: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DEK_WRAP_AAD_DOMAIN.len() + 32 + 8 + 32);
    aad.extend_from_slice(DEK_WRAP_AAD_DOMAIN);
    aad.extend_from_slice(object_digest);
    aad.extend_from_slice(&dek_wrap_epoch.to_be_bytes());
    aad.extend_from_slice(c1_sha256);
    aad
}

fn encode_pq_row_info(
    object_digest: &[u8; 32],
    wrap_epoch: u64,
    row_locator: &[u8; 32],
) -> Vec<u8> {
    let mut info = Vec::with_capacity(PQ_ROW_INFO_DOMAIN.len() + 32 + 8 + 32);
    info.extend_from_slice(PQ_ROW_INFO_DOMAIN);
    info.extend_from_slice(object_digest);
    info.extend_from_slice(&wrap_epoch.to_be_bytes());
    info.extend_from_slice(row_locator);
    info
}
