// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! # `chinwag-acu`
//!
//! Pure-safe-Rust (`#![forbid(unsafe_code)]`) implementation of the **Chinwag Access Control Unit (`ACU`)**
//! hybrid post-quantum & pairing-based threshold encryption engine (`CHWGACU3` + `CHWGAEA2` +
//! `AcuEnvelopeHeaderV2`), aligned 1-to-1 with:
//! - IACR ePrint `v2` (*Access-Structured Threshold Encryption with Ciphertext-Only Policy
//!   Strengthening, Dual-Mode Share Verification, and Hybrid Post-Quantum Envelopes*),
//! - USPTO Provisional `CHWG-PAT-11B-v2`, and
//! - Chinwag UI v5 PRD `v1.3` (`AcuEnvelopeHeaderV2`, `F-01`–`F-03`).
//!
//! ## Core Cryptographic Architecture
//! 1. **Zero-$V_0$ Threshold-Sealed Auxiliary Basis Slots ([`acu`], `CHWGACU3`):**
//!    - Eliminates any single-operator `SealedBasisCommitments` encryption of $V_0 = s G_1$ under
//!      $\mathsf{pk}_{\mathsf{ACU}}$: `ACU` holds **only** its LSSS row share(s), so compromising
//!      $\mathsf{sk}_{\mathsf{ACU}}$ alone is information-theoretically blind to $K_{\mathbb{G}_T}$
//!      on every conjunctive policy.
//!    - Auxiliary basis commitments $V_1, \dots, V_{k-1} \in \mathbb{G}_1^{k-1}$ (`col_offset >= 1`,
//!      never $V_0$) are sealed inside policy-threshold [`SbcSlot`]s under independent random keys.
//! 2. **48-Byte Pure-$\mathbb{G}_1$ Partial Shares & Dual-Mode DLEQ ([`share`], `CHWGSHR2`):**
//!    - Custodians emit $S_j = c_{j,1} - sk_{\rho(j)} c_{j,2} \in \mathbb{G}_1$ (`48` B compressed,
//!      `0` pairings at emission) with either `Mode A` (`64` B compact Chaum–Pedersen DLEQ) or
//!      `Mode B` (`128` B commitment-carrying DLEQ supporting randomized `(alpha_j, beta_j)` batch
//!      verification + $O(b \log |\Gamma|)$ binary-splitting fault isolation) and reconstruct with
//!      **exact 1 pairing** (`acu_combine`).
//!    - Every row carries an initial [`RowPok`] bound to `(object_digest, init_matrix_digest, init_epoch)`
//!      plus append-only [`RowUpdateProof`]s, defeating cross-object and synthetic-policy cut-and-paste
//!      oracles (`test_16`, `test_20`).
//! 3. **Ciphertext-Only Policy Strengthening & Coalition Seat Insertion ([`acu`], [`lsss`]):**
//!    - [`revoke_and_rerandomize`]: Ciphertext-only row pruning + full share rerandomization with
//!      mandatory satisfiability guard ([`AcuError::PolicyUnsatisfiableAfterRevocation`]); intentional
//!      kill-switch lockout uses [`emergency_lock_and_rerandomize`].
//!    - [`escalate_threshold`] / [`escalate_gate_threshold`]: Subtree-consistent Vandermonde column
//!      extension (`GateDescriptor`) + simultaneous rerandomization of all rows (`0` custodian round-trips).
//!    - [`WarmForkRequest`] + [`insert_sibling_key`]: Custodian-blinded 3-equation HVZK `Shadow-KV`
//!      warm-fork attachment (`ACU` never sees $\lambda_{\text{sib}} G_1$).
//!    - [`CoalitionInsertionRowShare`] + [`insert_authorized_seat`]: Live $\mathbb{G}_1$ reconstruction
//!      of $V_0^{(E)}$ without evaluating $K_{\mathbb{G}_T}$, guarded by non-ACU span exclusion.
//! 4. **Dual-Secret Hybrid Post-Quantum Envelope ([`aead`], `CHWGAEA2` + `0x647a` `X25519-MLKEM768`):**
//!    - Wraps each seat key with a validated `1216`-byte `0x647a` `X25519-MLKEM768` keypair bound into
//!      the strong Fiat–Shamir Schnorr Proof-of-Possession ([`keys`]).
//!    - Projects out `ACU` via [`project_non_acu`] (`ACU` holds `0` PQ rows!), wraps a random 256-bit
//!      `DEK` into a `48`-byte `wrapped_dek` slot under `HKDF(Canon_Fp12(K_GT) || Canon_Fr(K_PQ))`,
//!      keeps payload `C_1` (`aead_ciphertext`) immutable across all evolutions, and supports
//!      payload-preserving [`EncryptedCiPayload::rotate_pq_key`].
//! 5. **Blind Hash-Chained Archive & Selective Merkle Export ([`archive`], [`AcuEnvelopeHeaderV2`]):**
//!    - Chains `aead_immutable_blake3` (`F-02`), encrypts routing metadata (`F-01`), separates outer
//!      `ArchiveRowSign` from inner `SeatAuthorSign` (`F-03`), emits keyed `HMAC-SHA256` [`BlindIndexTags`],
//!      and verifies `--public-safe` 4-leaf salted Merkle `.cwcard` bundles ([`PublicSafeExportBundle`]).

#![forbid(unsafe_code)]

pub mod acu;
pub mod aead;
pub mod archive;
pub mod framing;
pub mod keys;
pub mod lsss;
pub mod protocol;
pub mod share;

#[cfg(test)]
mod attack_tests;

pub use acu::{
    ACU_CT_MAGIC, AcuCiphertext, CiphertextRow, CoalitionInsertionRowShare, SbcSlot,
    SiblingRowTransfer, WarmForkRequest, acu_combine, acu_combine_unverified, acu_encrypt,
    acu_encrypt_with_g1, acu_encrypt_with_g1_and_context, acu_partial_decrypt,
    acu_partial_decrypt_at_epoch, acu_partial_decrypt_with_mode, acu_verify_partial_share,
    compute_blind_row_locator, compute_oblivious_key_hint, emergency_lock_and_rerandomize,
    escalate_gate_threshold, escalate_threshold, insert_authorized_seat, insert_sibling_key,
    revoke_and_rerandomize, verify_row_randomness_witness,
};
pub use aead::{
    DEFAULT_AGENT_BRANCH_ID, DEFAULT_MESSAGE_ARCHIVE_ID, DEFAULT_REVOCATION_ACU_ID,
    ENCRYPTED_PAYLOAD_MAGIC, EncryptedCiPayload, PQ_CAPSULE_CIPHERTEXT_BYTES, PqCapsuleRow,
    PqDecryptionShare, PqLsssHeader, WRAPPED_DEK_BYTES, derive_aead_key_from_gt,
};
pub use archive::{
    ACU_ENVELOPE_HEADER_V2_VERSION, AcuEnvelopeHeaderV2, AcuEnvelopeV2Record,
    AcuParquetArchiveStore, ArchiveSearchFilter, ArchivedMessageRow, BlindIndexTags, CacheHit,
    DEFAULT_ACTIVE_CHANNEL_PAGE_SIZE, DEFAULT_DUCKDB_MEMORY_LIMIT, DEFAULT_DUCKDB_THREADS,
    DecryptedArchiveRecord, DuckDbArchiveConfig, EnvelopeMetadataBox, HivePartitionKey,
    PolicyEvolutionReceipt, PublicExportLeaves, PublicSafeExportBundle, SealedAuthorMessage,
    SharedFatClientArchiveHandle, verify_envelope_v2_chain,
};
pub use framing::{
    GT_CANONICAL_BYTES, expand_message_xmd_sha256, gt_canonical_bytes, hash_to_nonzero_scalar,
    hash_to_scalar,
};
pub use keys::{
    KEM_ID_X25519_MLKEM768, SeatPqPublicKey, SeatPqSecretKey, SeatPublicKey, SeatSecretKey,
    XWING_ENCAPPED_KEY_BYTES, XWING_MLKEM768_CT_BYTES, XWING_MLKEM768_PK_BYTES,
    XWING_PUBLIC_KEY_BYTES, XWING_SEED_BYTES,
};
pub use lsss::{
    AccessTree, GateChild, GateDescriptor, LsssMatrix, find_reconstruction_weights,
    project_non_acu, rows_span_target,
};
pub use protocol::{
    AcuAuditDecision, AcuPolicySignature, AcuShareRequest, AcuShareResponse, AllowedSignerRecord,
    AllowedSignersRegistry, AuditLogEntry, CHINWAG_MESH_TOPIC, CisoAcuFatClient,
    DEFAULT_CISO_ACU_ID, SignedAgentPrSubmission, ci_validate_and_encrypt_root_cause,
    ci_validate_and_encrypt_with_acu_and_archive,
};
pub use share::{
    DleqMode, DleqProof, PartialDecryptionShare, RowPok, RowUpdateProof,
    batch_verify_partial_shares, batch_verify_partial_shares_with_rng,
    emit_partial_share_with_mode, isolate_invalid_partial_shares, verify_initial_row_pok,
    verify_partial_share_for_object, verify_row_randomness_chain, verify_update_row_pok,
};

use thiserror::Error;

/// Errors returned by ACU key validation, LSSS solving, dynamic policy evolution,
/// `iroh` P2P share issuance, hybrid post-quantum decapsulation, or AEAD wrapping.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum AcuError {
    /// Seat identifier is empty, whitespace-only, overlong, or contains ASCII control characters.
    #[error("seat identifier must be non-empty, <= 512 bytes, and free of control characters")]
    InvalidSeatId,

    /// Secret scalar is zero in $\mathbb{F}_r$, PQ seed is all-zero, or $\mathbb{G}_1$ payload preimage is identity.
    #[error("secret key scalar or seed must be non-zero")]
    InvalidSecretKey,

    /// Public key failed subgroup, FIPS 203 `ML-KEM-768`, Curve25519, or Schnorr PoP check.
    #[error("public key for seat '{0}' failed consistency or proof-of-possession check")]
    InvalidPublicKey(String),

    /// Referenced seat ID is missing from the provided public key directory.
    #[error("seat '{0}' not found in public key directory")]
    UnknownSeat(String),

    /// Seat has been revoked by the CISO ACU or in `.chinwag/allowed_signers`.
    #[error("seat '{0}' has been revoked")]
    SeatRevoked(String),

    /// Ed25519 or `RowPok` epoch signature verification failed.
    #[error("Ed25519 signature verification failed for {0}")]
    SignatureVerificationFailed(&'static str),

    /// Access tree or LSSS matrix has no leaves/rows.
    #[error("access policy must contain at least one leaf row")]
    EmptyPolicy,

    /// Access tree or gate descriptor is malformed.
    #[error("invalid access tree: {0}")]
    InvalidAccessTree(&'static str),

    /// Threshold $t$ is outside $1 \le t \le n$.
    #[error("invalid threshold {threshold} for gate with {children} children")]
    InvalidThreshold {
        /// Requested threshold $t$.
        threshold: usize,
        /// Number of children $n$.
        children: usize,
    },

    /// Matrix row or commitment vector dimension does not match `matrix.cols`.
    #[error("LSSS dimension mismatch: expected {expected} columns, got {actual}")]
    DimensionMismatch {
        /// Expected column count.
        expected: usize,
        /// Actual column count.
        actual: usize,
    },

    /// Row index is out of bounds for the current LSSS matrix.
    #[error("row index {index} out of bounds for matrix with {total_rows} rows")]
    RowIndexOutOfBounds {
        /// Requested row index.
        index: usize,
        /// Total rows in matrix.
        total_rows: usize,
    },

    /// Provided set of rows does not span the target vector $(1, 0, \dots, 0) \in \mathbb{F}_r^k$.
    #[error("available shares do not satisfy the access policy")]
    PolicyNotSatisfied,

    /// Pruning `revoked_seat_ids` would leave the policy permanently unsatisfiable without explicit emergency lock.
    #[error(
        "revoking requested seats leaves policy unsatisfiable (use emergency_lock_and_rerandomize for intentional lockout)"
    )]
    PolicyUnsatisfiableAfterRevocation,

    /// Partial decryption share or PQ share epoch does not match the ciphertext's current epoch.
    #[error("partial decryption share epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch {
        /// Ciphertext's current epoch.
        expected: u64,
        /// Share's recorded epoch.
        actual: u64,
    },

    /// Partial decryption share failed DLEQ or row/seat binding verification.
    #[error("partial decryption share for row {row_index} (seat '{seat_id}') is invalid or stale")]
    InvalidPartialShare {
        /// Row index of the rejected share.
        row_index: usize,
        /// Seat identifier of the rejected share.
        seat_id: String,
    },

    /// Row randomness Schnorr proof-of-knowledge (`RowPok` / `RowUpdateProof`) or warm-fork HVZK proof failed.
    #[error("ciphertext row randomness proof-of-knowledge (RowPok) failed verification")]
    InvalidRowPok,

    /// Replayed `request_id` arrived with a mutated `(requester_seat, policy_epoch, header_digest)` tuple.
    #[error("replayed request_id conflicts with previously recorded request digest")]
    ReplayConflict,

    /// Inserting a non-ACU row would allow non-ACU seats to span $(1, 0, \dots, 0)$ without the mandatory ACU seat.
    #[error("candidate row allows non-ACU seats to bypass mandatory ACU conjunction")]
    SlotSpanExposesSecret,

    /// Caller seat is not authorized to perform an ACU policy operation or warm-fork transfer.
    #[error("caller seat is not authorized to perform this policy operation")]
    UnauthorizedPolicyOperator,

    /// Repository, task, or `iroh` topic metadata is empty or invalid.
    #[error("CI payload or iroh protocol metadata is invalid")]
    InvalidMetadata,

    /// Legacy wire format (`CHWGACU1`, `CHWGACU2`, `CHWGAEAD`, or `CHWGSHR1`) was rejected fail-closed.
    #[error("insecure legacy wire format '{0}' rejected (expected CHWGACU3 / CHWGAEA2)")]
    InsecureLegacyFormat(&'static str),

    /// Unsealing an `SbcSlot` or authenticating an `AcuCiphertext` header failed.
    #[error("ACU slot unsealing or ciphertext authenticity verification failed")]
    BasisUnsealFailed,

    /// Binary serialization or deserialization of a wire blob failed.
    #[error("binary serialization error: {0}")]
    SerializationError(&'static str),

    /// ChaCha20-Poly1305 or HPKE `0x647a` AEAD authentication tag verification failed.
    #[error("AEAD or HPKE authentication failed")]
    AeadFailure,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar, pairing};
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use ed25519_dalek::SigningKey;
    use ff::Field;
    use hkdf::Hkdf;
    use rand_core::OsRng;
    use sha2::Sha256;
    use std::collections::BTreeMap;

    const SAMPLE_CI_ROOT_CAUSE_JSON: &[u8] = br#"{
        "collapsed_shards": 20,
        "root_cause": "PostgreSQL test container port 5432 collision across parallel runners",
        "fix_hint": "Bind ephemeral testcontainers port per nextest slot",
        "finops_credits_spent": 1
    }"#;

    #[test]
    fn test_1_brians_split_key_ci_cd_and_acu_instant_revocation() {
        let mut rng = OsRng;
        let (sk_agent, pk_agent) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let (sk_acu, pk_acu) =
            SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();

        assert!(pk_agent.verify_consistency());
        assert!(pk_acu.verify_consistency());

        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(pk_agent.seat_id.clone(), pk_agent.clone());
        seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());

        let mut payload = EncryptedCiPayload::encrypt_split_key_with_acu(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &pk_agent,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-CI-COLLAPSE-01",
            &mut rng,
        )
        .unwrap();

        assert_eq!(payload.acu_ciphertext.policy_epoch, 1);
        assert_eq!(payload.acu_ciphertext.rows.len(), 2);
        assert_eq!(
            payload.acu_ciphertext.acu_seat_id,
            DEFAULT_REVOCATION_ACU_ID
        );
        // ACU holds 0 rows inside PqLsssHeader!
        let pq_hdr = payload.pq_header.as_ref().unwrap();
        assert_eq!(pq_hdr.rows.len(), 1);
        assert_eq!(pq_hdr.rows[0].seat_id, DEFAULT_AGENT_BRANCH_ID);

        let row_agent = &payload.acu_ciphertext.rows[0];
        let row_acu = &payload.acu_ciphertext.rows[1];
        let d_acu =
            acu_partial_decrypt_at_epoch(row_acu, &sk_acu, payload.acu_ciphertext.policy_epoch);
        assert!(acu_verify_partial_share(row_acu, &pk_acu, &d_acu));

        let d_agent =
            acu_partial_decrypt_at_epoch(row_agent, &sk_agent, payload.acu_ciphertext.policy_epoch);
        assert_eq!(
            payload.decrypt_with_local_key(std::slice::from_ref(&d_agent), &sk_agent, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            payload.decrypt_with_local_key(std::slice::from_ref(&d_acu), &sk_agent, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );

        let decrypted = payload
            .decrypt_with_local_key(&[d_agent, d_acu], &sk_agent, &seat_keys)
            .unwrap();
        assert_eq!(decrypted, SAMPLE_CI_ROOT_CAUSE_JSON);

        // Standard `revoke_and_rerandomize` guards against accidental 2-of-2 self-lockout;
        // intentional emergency kill-switch lockout uses `emergency_lock_and_rerandomize`.
        let cached_pq_agent = payload.decapsulate_pq_shares_for_seat(&sk_agent).unwrap();
        assert_eq!(
            revoke_and_rerandomize(
                &mut payload.acu_ciphertext,
                &sk_acu,
                &[DEFAULT_AGENT_BRANCH_ID],
                &seat_keys,
                &mut rng,
            ),
            Err(AcuError::PolicyUnsatisfiableAfterRevocation)
        );
        emergency_lock_and_rerandomize(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &[DEFAULT_AGENT_BRANCH_ID],
            &seat_keys,
            &mut rng,
        )
        .unwrap();

        assert_eq!(payload.acu_ciphertext.policy_epoch, 2);
        assert_eq!(payload.acu_ciphertext.rows.len(), 1);
        assert_eq!(
            payload.acu_ciphertext.rows[0].seat_id,
            DEFAULT_REVOCATION_ACU_ID
        );

        let d_acu_epoch2 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk_acu,
            payload.acu_ciphertext.policy_epoch,
        );
        assert_eq!(
            payload.decrypt(&[d_acu_epoch2], &cached_pq_agent, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
    }

    #[test]
    fn test_2_lewko_waters_nested_tree_and_gaussian_elimination() {
        let mut rng = OsRng;
        let (_sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let seat_names = [
            "seat:pm",
            "seat:architect",
            "seat:rust",
            "seat:qa-1",
            "seat:qa-2",
        ];
        let mut secret_keys = BTreeMap::new();
        let mut public_keys = BTreeMap::new();
        public_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
        for name in seat_names {
            let (sk, pk) = SeatSecretKey::generate(name, &mut rng).unwrap();
            secret_keys.insert(name.to_string(), sk);
            public_keys.insert(name.to_string(), pk);
        }

        let tree = AccessTree::And(vec![
            AccessTree::Or(vec![
                AccessTree::Leaf("seat:pm".to_string()),
                AccessTree::Leaf("seat:architect".to_string()),
            ]),
            AccessTree::Threshold {
                threshold: 2,
                children: vec![
                    AccessTree::Leaf("seat:rust".to_string()),
                    AccessTree::Leaf("seat:qa-1".to_string()),
                    AccessTree::Leaf("seat:qa-2".to_string()),
                ],
            },
        ]);

        let matrix = LsssMatrix::from_tree(&tree).unwrap();
        assert_eq!(matrix.rows.len(), 5);
        assert_eq!(matrix.cols, 3);

        assert_eq!(
            find_reconstruction_weights(&matrix, &[0, 2]),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            find_reconstruction_weights(&matrix, &[2, 3, 4]),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            find_reconstruction_weights(&matrix, &[0, 1, 4]),
            Err(AcuError::PolicyNotSatisfied)
        );

        let payload = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &tree,
            &public_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-NESTED-LSSS-02",
            &mut rng,
        )
        .unwrap();

        let authorized_sets: &[&[usize]] = &[
            &[0, 2, 3],
            &[0, 3, 4],
            &[1, 2, 4],
            &[1, 3, 4],
            &[0, 1, 2, 3, 4],
        ];

        for &set in authorized_sets {
            let mut shares = Vec::with_capacity(set.len());
            let mut pq_shares = Vec::with_capacity(set.len());
            for &idx in set {
                let row = &payload.acu_ciphertext.rows[idx];
                let sk = &secret_keys[&row.seat_id];
                shares.push(acu_partial_decrypt_at_epoch(
                    row,
                    sk,
                    payload.acu_ciphertext.policy_epoch,
                ));
                pq_shares.extend(payload.decapsulate_pq_shares_for_seat(sk).unwrap());
            }
            let recovered = payload.decrypt(&shares, &pq_shares, &public_keys).unwrap();
            assert_eq!(recovered, SAMPLE_CI_ROOT_CAUSE_JSON);
        }
    }

    #[test]
    fn test_3_insert_key_warm_fork_without_decrypting_c0() {
        let mut rng = OsRng;
        let (sk_agent1, pk_agent1) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let (sk_acu, pk_acu) =
            SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();
        let (sk_warm_fork, pk_warm_fork) =
            SeatSecretKey::generate("branch:77441122", &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(pk_agent1.seat_id.clone(), pk_agent1.clone());
        seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
        seat_keys.insert(pk_warm_fork.seat_id.clone(), pk_warm_fork.clone());

        let mut payload = EncryptedCiPayload::encrypt_split_key_with_acu(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &pk_agent1,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-WARM-FORK-03",
            &mut rng,
        )
        .unwrap();

        let original_c0 = payload.acu_ciphertext.c0;
        let original_aead_ct = payload.aead_ciphertext.clone();
        let original_immutable_hash = payload.immutable_aead_blake3();

        let warm_fork_req = WarmForkRequest::create(
            &payload.acu_ciphertext,
            0,
            &sk_agent1,
            &pk_warm_fork,
            &mut rng,
        )
        .unwrap();
        let new_row_idx = insert_sibling_key(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &warm_fork_req,
            &seat_keys,
        )
        .unwrap();
        let pq_row_idx = payload
            .attach_pq_sibling_capsule(&sk_agent1, &pk_warm_fork, &mut rng)
            .unwrap();

        assert_eq!(new_row_idx, 2);
        assert_eq!(pq_row_idx, 1);
        assert_eq!(payload.acu_ciphertext.policy_epoch, 2);
        assert_eq!(payload.acu_ciphertext.c0, original_c0);
        assert_eq!(payload.aead_ciphertext, original_aead_ct);
        assert_eq!(payload.immutable_aead_blake3(), original_immutable_hash);

        let d_warm_fork = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[new_row_idx],
            &sk_warm_fork,
            payload.acu_ciphertext.policy_epoch,
        );
        assert_eq!(
            payload.decrypt_with_local_key(
                std::slice::from_ref(&d_warm_fork),
                &sk_warm_fork,
                &seat_keys
            ),
            Err(AcuError::PolicyNotSatisfied)
        );

        let d_acu = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            &sk_acu,
            payload.acu_ciphertext.policy_epoch,
        );
        let recovered = payload
            .decrypt_with_local_key(&[d_warm_fork, d_acu], &sk_warm_fork, &seat_keys)
            .unwrap();
        assert_eq!(recovered, SAMPLE_CI_ROOT_CAUSE_JSON);
    }

    #[test]
    fn test_4_escalate_threshold_1_of_3_to_2_of_3_and_3_of_3() {
        let mut rng = OsRng;
        let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let (sk1, pk1) = SeatSecretKey::generate("seat:alpha", &mut rng).unwrap();
        let (sk2, pk2) = SeatSecretKey::generate("seat:beta", &mut rng).unwrap();
        let (sk3, pk3) = SeatSecretKey::generate("seat:gamma", &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
        seat_keys.insert(pk1.seat_id.clone(), pk1);
        seat_keys.insert(pk2.seat_id.clone(), pk2);
        seat_keys.insert(pk3.seat_id.clone(), pk3);

        let tree = AccessTree::Or(vec![
            AccessTree::Leaf("seat:alpha".to_string()),
            AccessTree::Leaf("seat:beta".to_string()),
            AccessTree::Leaf("seat:gamma".to_string()),
        ]);

        let mut payload = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &tree,
            &seat_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-ESCALATE-04",
            &mut rng,
        )
        .unwrap();

        let pq1 = payload.decapsulate_pq_shares_for_seat(&sk1).unwrap();
        let pq2 = payload.decapsulate_pq_shares_for_seat(&sk2).unwrap();
        let pq3 = payload.decapsulate_pq_shares_for_seat(&sk3).unwrap();

        let d1_ep1 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk1,
            payload.acu_ciphertext.policy_epoch,
        );
        assert_eq!(
            payload.decrypt(&[d1_ep1], &pq1, &seat_keys).unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );

        let original_c0 = payload.acu_ciphertext.c0;
        escalate_threshold(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &[0, 1, 2],
            1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();

        assert_eq!(payload.acu_ciphertext.policy_epoch, 2);
        assert_ne!(payload.acu_ciphertext.c0, original_c0);
        assert_eq!(payload.acu_ciphertext.matrix.cols, 2);

        let d1_ep2 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk1,
            payload.acu_ciphertext.policy_epoch,
        );
        let d2_ep2 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            &sk2,
            payload.acu_ciphertext.policy_epoch,
        );
        let d3_ep2 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[2],
            &sk3,
            payload.acu_ciphertext.policy_epoch,
        );

        assert_eq!(
            payload.decrypt(std::slice::from_ref(&d1_ep2), &pq1, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            payload.decrypt(std::slice::from_ref(&d2_ep2), &pq2, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );

        let mut pq12 = pq1.clone();
        pq12.extend(pq2.clone());
        let mut pq23 = pq2.clone();
        pq23.extend(pq3.clone());
        let mut pq123 = pq12.clone();
        pq123.extend(pq3);

        assert_eq!(
            payload
                .decrypt(&[d1_ep2, d2_ep2.clone()], &pq12, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
        assert_eq!(
            payload
                .decrypt(&[d2_ep2, d3_ep2], &pq23, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );

        escalate_threshold(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &[0, 1, 2],
            1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        assert_eq!(payload.acu_ciphertext.policy_epoch, 3);
        assert_eq!(payload.acu_ciphertext.matrix.cols, 3);

        let d1_ep3 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk1,
            payload.acu_ciphertext.policy_epoch,
        );
        let d2_ep3 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            &sk2,
            payload.acu_ciphertext.policy_epoch,
        );
        let d3_ep3 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[2],
            &sk3,
            payload.acu_ciphertext.policy_epoch,
        );

        assert_eq!(
            payload.decrypt(&[d1_ep3.clone(), d2_ep3.clone()], &pq12, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            payload
                .decrypt(&[d1_ep3, d2_ep3, d3_ep3], &pq123, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
    }

    #[test]
    fn test_5_revoke_and_rerandomize_invalidates_cached_epoch1_partial_shares() {
        let mut rng = OsRng;
        let (sk_revoked, pk_revoked) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let (sk_survivor, pk_survivor) =
            SeatSecretKey::generate("branch:77441122", &mut rng).unwrap();
        let (sk_acu, pk_acu) =
            SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(pk_revoked.seat_id.clone(), pk_revoked);
        seat_keys.insert(pk_survivor.seat_id.clone(), pk_survivor);
        seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());

        let tree = AccessTree::And(vec![
            AccessTree::Or(vec![
                AccessTree::Leaf(DEFAULT_AGENT_BRANCH_ID.to_string()),
                AccessTree::Leaf("branch:77441122".to_string()),
            ]),
            AccessTree::Leaf(DEFAULT_REVOCATION_ACU_ID.to_string()),
        ]);

        let mut payload = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &tree,
            &seat_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-REVOKE-RERAND-05",
            &mut rng,
        )
        .unwrap();

        let d_old_revoked = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk_revoked,
            payload.acu_ciphertext.policy_epoch,
        );
        let d_acu_epoch1 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[2],
            &sk_acu,
            payload.acu_ciphertext.policy_epoch,
        );

        assert_eq!(
            payload
                .decrypt_with_local_key(
                    &[d_old_revoked.clone(), d_acu_epoch1.clone()],
                    &sk_revoked,
                    &seat_keys
                )
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );

        let c0_epoch1 = payload.acu_ciphertext.c0;

        revoke_and_rerandomize(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &[DEFAULT_AGENT_BRANCH_ID],
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        payload
            .prune_revoked_pq_capsules(&[DEFAULT_AGENT_BRANCH_ID])
            .unwrap();

        assert_eq!(payload.acu_ciphertext.policy_epoch, 2);
        assert_ne!(payload.acu_ciphertext.c0, c0_epoch1);
        assert_eq!(payload.acu_ciphertext.rows.len(), 2);
        assert_eq!(payload.acu_ciphertext.rows[0].seat_id, "branch:77441122");
        assert_eq!(
            payload.acu_ciphertext.rows[1].seat_id,
            DEFAULT_REVOCATION_ACU_ID
        );

        let pq_survivor = payload
            .decapsulate_pq_shares_for_seat(&sk_survivor)
            .unwrap();

        assert_eq!(
            payload.decrypt(
                &[d_old_revoked, d_acu_epoch1.clone()],
                &pq_survivor,
                &seat_keys
            ),
            Err(AcuError::EpochMismatch {
                expected: 2,
                actual: 1
            })
        );

        let mut forged_d_acu_from_ep1 = d_acu_epoch1;
        forged_d_acu_from_ep1.row_index = 1;
        forged_d_acu_from_ep1.policy_epoch = 2;

        let d_survivor_ep2 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk_survivor,
            payload.acu_ciphertext.policy_epoch,
        );

        assert_eq!(
            payload.decrypt(
                &[d_survivor_ep2.clone(), forged_d_acu_from_ep1.clone()],
                &pq_survivor,
                &seat_keys
            ),
            Err(AcuError::InvalidPartialShare {
                row_index: 1,
                seat_id: DEFAULT_REVOCATION_ACU_ID.to_string(),
            })
        );

        assert_eq!(
            payload.decrypt_unverified(
                &[d_survivor_ep2.clone(), forged_d_acu_from_ep1],
                &pq_survivor
            ),
            Err(AcuError::AeadFailure)
        );

        let d_acu_ep2 = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            &sk_acu,
            payload.acu_ciphertext.policy_epoch,
        );
        let recovered = payload
            .decrypt(&[d_survivor_ep2, d_acu_ep2], &pq_survivor, &seat_keys)
            .unwrap();
        assert_eq!(recovered, SAMPLE_CI_ROOT_CAUSE_JSON);
    }

    #[test]
    fn test_6_alistair_rogue_key_rejection_and_secret_redaction() {
        let mut rng = OsRng;
        let (_sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let (sk, mut pk) = SeatSecretKey::generate("seat:honest", &mut rng).unwrap();

        assert_eq!(sk.seat_id(), "seat:honest");
        let debug_str = format!("{sk:?}");
        assert!(debug_str.contains("<REDACTED>"));
        assert!(!debug_str.contains("0x"));

        let (pk1_bytes, pq_pk_bytes, pop_bytes) = pk.to_wire_bytes();
        let decoded =
            SeatPublicKey::from_wire_bytes("seat:honest", &pk1_bytes, &pq_pk_bytes, &pop_bytes)
                .unwrap();
        assert_eq!(decoded, pk);

        // Cross-seat key cloning under a different `seat_id` MUST fail Schnorr PoP!
        assert_eq!(
            SeatPublicKey::from_wire_bytes(
                "seat:rogue-clone",
                &pk1_bytes,
                &pq_pk_bytes,
                &pop_bytes
            ),
            Err(AcuError::InvalidPublicKey("seat:rogue-clone".to_string()))
        );

        // Mutating `pq_pk` bytes MUST fail Schnorr PoP (since `pq_pk` is bound into the PoP transcript)!
        let mut tampered_pq = pq_pk_bytes;
        tampered_pq[XWING_MLKEM768_PK_BYTES] ^= 0x04;
        assert_eq!(
            SeatPublicKey::from_wire_bytes("seat:honest", &pk1_bytes, &tampered_pq, &pop_bytes),
            Err(AcuError::InvalidPublicKey("seat:honest".to_string()))
        );

        // Mutating `pk1` without knowing the new discrete log MUST fail Schnorr PoP!
        pk.pk1 += G1Projective::generator();
        assert!(!pk.verify_consistency());

        let (bad_pk1, bad_pq, bad_pop) = pk.to_wire_bytes();
        assert_eq!(
            SeatPublicKey::from_wire_bytes("seat:honest", &bad_pk1, &bad_pq, &bad_pop),
            Err(AcuError::InvalidPublicKey("seat:honest".to_string()))
        );

        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
        seat_keys.insert(pk.seat_id.clone(), pk.clone());
        let tree = AccessTree::Leaf("seat:honest".to_string());
        let err = EncryptedCiPayload::encrypt(
            b"secret",
            &tree,
            &seat_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-ROGUE-06",
            &mut rng,
        );
        assert_eq!(
            err,
            Err(AcuError::InvalidPublicKey("seat:honest".to_string()))
        );

        // Also reject rogue acu_pk even when recipient keys are honest!
        let (_honest_sk, honest_pk) =
            SeatSecretKey::generate("seat:honest-recipient", &mut rng).unwrap();
        let mut honest_dir = BTreeMap::new();
        honest_dir.insert(honest_pk.seat_id.clone(), honest_pk);
        let mut rogue_acu_pk = pk_acu;
        rogue_acu_pk.pop_response += Scalar::ONE;
        let rogue_acu_err = EncryptedCiPayload::encrypt(
            b"secret",
            &AccessTree::Leaf("seat:honest-recipient".to_string()),
            &honest_dir,
            &rogue_acu_pk,
            "emunlabs/chinwag",
            "CHWG-ROGUE-ACU-06",
            &mut rng,
        );
        assert_eq!(
            rogue_acu_err,
            Err(AcuError::InvalidPublicKey(DEFAULT_CISO_ACU_ID.to_string()))
        );

        assert!(matches!(
            SeatSecretKey::from_scalar("seat:zero", Scalar::ZERO),
            Err(AcuError::InvalidSecretKey)
        ));
    }

    #[test]
    fn test_7_bls12_381_published_ietf_generator_and_lsss_known_answer_vectors() {
        const IETF_BLS12_381_G1_GEN_COMPRESSED: [u8; 48] = [
            0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ];

        let (_sk_one, pk_one) = SeatSecretKey::from_scalar("kat:one", Scalar::ONE).unwrap();
        let (g1_bytes, _pop_bytes) = pk_one.to_compressed_bytes();
        assert_eq!(g1_bytes, IETF_BLS12_381_G1_GEN_COMPRESSED);
        assert!(pk_one.verify_consistency());

        let tree = EncryptedCiPayload::build_split_key_acu_policy(
            DEFAULT_AGENT_BRANCH_ID,
            DEFAULT_REVOCATION_ACU_ID,
        );
        let matrix = LsssMatrix::from_tree(&tree).unwrap();
        assert_eq!(matrix.rows[0].1, vec![Scalar::ONE, Scalar::from(1u64)]);
        assert_eq!(matrix.rows[1].1, vec![Scalar::ONE, Scalar::from(2u64)]);

        let weights = find_reconstruction_weights(&matrix, &[0, 1]).unwrap();
        assert_eq!(weights, vec![(0, Scalar::from(2u64)), (1, -Scalar::ONE)]);
    }

    #[test]
    fn test_8_ciso_fat_client_iroh_p2p_acu_protocol_and_dual_sig_ci_runner() {
        let mut rng = OsRng;

        let (agent_acu_sk, agent_acu_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent_ed25519_sk = SigningKey::from_bytes(&[0x42u8; 32]);

        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0x99u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        registry
            .register_seat(
                DEFAULT_AGENT_BRANCH_ID,
                agent_ed25519_sk.verifying_key(),
                agent_acu_pk.clone(),
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            )
            .unwrap();

        let pr_submission = SignedAgentPrSubmission::create_signed(
            DEFAULT_AGENT_BRANCH_ID,
            "emunlabs/chinwag",
            "refs/pull/42/head",
            "8123089ce0a26e94052babb94d946ef14d0ad462",
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor branch:8687872\n\nfeat: add ACU gate"
                .to_vec(),
            [0xAAu8; 32],
            &agent_ed25519_sk,
        );

        let mut tampered = pr_submission.clone();
        tampered.inner_commit_payload.push(b'!');
        assert_eq!(
            ci_validate_and_encrypt_root_cause(
                &tampered,
                DEFAULT_CISO_ACU_ID,
                &registry,
                SAMPLE_CI_ROOT_CAUSE_JSON,
                "CHWG-IROH-ACU-08",
                &mut rng,
            ),
            Err(AcuError::SignatureVerificationFailed("inner_commit"))
        );

        let encrypted_ci = ci_validate_and_encrypt_root_cause(
            &pr_submission,
            DEFAULT_CISO_ACU_ID,
            &registry,
            SAMPLE_CI_ROOT_CAUSE_JSON,
            "CHWG-IROH-ACU-08",
            &mut rng,
        )
        .unwrap();

        let mut ciso_fat_client = CisoAcuFatClient::new(acu_sk, acu_pk.clone(), acu_ed25519_sk);
        assert_eq!(ciso_fat_client.acu_public_key(), &acu_pk);

        let acu_row = encrypted_ci.acu_ciphertext.rows[1].clone();
        let share_req = AcuShareRequest::create_signed(
            "req-0001",
            DEFAULT_AGENT_BRANCH_ID,
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-IROH-ACU-08",
            encrypted_ci.acu_ciphertext.policy_epoch,
            encrypted_ci.acu_ciphertext.clone(),
            acu_row.clone(),
            1_793_800_000_000,
            &agent_ed25519_sk,
        );

        let share_resp = ciso_fat_client
            .handle_iroh_share_request(&share_req, &registry)
            .unwrap();
        assert_eq!(share_resp.audit_entry.decision, AcuAuditDecision::Granted);
        assert_eq!(ciso_fat_client.audit_log().len(), 1);

        share_resp.verify_by_agent(&acu_row, &registry).unwrap();
        let d_agent = acu_partial_decrypt_at_epoch(
            &encrypted_ci.acu_ciphertext.rows[0],
            &agent_acu_sk,
            encrypted_ci.acu_ciphertext.policy_epoch,
        );
        let active_keys = registry.active_acu_keys();
        let recovered = encrypted_ci
            .decrypt_with_local_key(
                &[d_agent, share_resp.partial_share],
                &agent_acu_sk,
                &active_keys,
            )
            .unwrap();
        assert_eq!(recovered, SAMPLE_CI_ROOT_CAUSE_JSON);

        ciso_fat_client.instant_revoke(DEFAULT_AGENT_BRANCH_ID);
        let denied = ciso_fat_client.handle_iroh_share_request(&share_req, &registry);
        assert_eq!(
            denied,
            Err(AcuError::SeatRevoked(DEFAULT_AGENT_BRANCH_ID.to_string()))
        );
        assert_eq!(ciso_fat_client.audit_log().len(), 2);
        assert_eq!(
            ciso_fat_client.audit_log()[1].decision,
            AcuAuditDecision::Denied
        );
    }

    #[test]
    fn test_9_zero_plaintext_inbox_and_ciso_archive_investigation() {
        let mut rng = OsRng;

        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0x11u8; 32]);

        let (agent_acu_sk, agent_acu_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent_ed25519_sk = SigningKey::from_bytes(&[0x22u8; 32]);

        let (archive_acu_sk, archive_acu_pk) =
            SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();
        let archive_ed25519_sk = SigningKey::from_bytes(&[0x33u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        registry
            .register_seat(
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_AGENT_BRANCH_ID,
                agent_ed25519_sk.verifying_key(),
                agent_acu_pk,
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_MESSAGE_ARCHIVE_ID,
                archive_ed25519_sk.verifying_key(),
                archive_acu_pk,
            )
            .unwrap();

        let pr_submission = SignedAgentPrSubmission::create_signed(
            DEFAULT_AGENT_BRANCH_ID,
            "emunlabs/chinwag",
            "refs/pull/99/head",
            "b1745094d9cb9014361fca30c7de3535c140dd20",
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor branch:8687872\n\nfeat: zero-plaintext inbox"
                .to_vec(),
            [0xBBu8; 32],
            &agent_ed25519_sk,
        );

        let mut inbox_ciphertext = ci_validate_and_encrypt_with_acu_and_archive(
            &pr_submission,
            DEFAULT_CISO_ACU_ID,
            DEFAULT_MESSAGE_ARCHIVE_ID,
            &registry,
            SAMPLE_CI_ROOT_CAUSE_JSON,
            "CHWG-ZERO-PLAINTEXT-INBOX-09",
            &mut rng,
        )
        .unwrap();

        assert_eq!(inbox_ciphertext.acu_ciphertext.rows.len(), 3);
        assert_eq!(
            inbox_ciphertext.acu_ciphertext.rows[0].seat_id,
            DEFAULT_CISO_ACU_ID
        );
        assert_eq!(
            inbox_ciphertext.acu_ciphertext.rows[1].seat_id,
            DEFAULT_AGENT_BRANCH_ID
        );
        assert_eq!(
            inbox_ciphertext.acu_ciphertext.rows[2].seat_id,
            DEFAULT_MESSAGE_ARCHIVE_ID
        );

        let mut ciso_fat_client = CisoAcuFatClient::new(acu_sk, acu_pk, acu_ed25519_sk);
        let active_keys_ep1 = registry.active_acu_keys();

        let live_req = AcuShareRequest::create_signed(
            "req-live-01",
            DEFAULT_AGENT_BRANCH_ID,
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-ZERO-PLAINTEXT-INBOX-09",
            inbox_ciphertext.acu_ciphertext.policy_epoch,
            inbox_ciphertext.acu_ciphertext.clone(),
            inbox_ciphertext.acu_ciphertext.rows[0].clone(),
            1_793_800_010_000,
            &agent_ed25519_sk,
        );
        let live_resp = ciso_fat_client
            .handle_iroh_share_request(&live_req, &registry)
            .unwrap();
        let d_agent_ep1 = acu_partial_decrypt_at_epoch(
            &inbox_ciphertext.acu_ciphertext.rows[1],
            &agent_acu_sk,
            inbox_ciphertext.acu_ciphertext.policy_epoch,
        );
        let live_plaintext = inbox_ciphertext
            .decrypt_with_local_key(
                &[live_resp.partial_share, d_agent_ep1.clone()],
                &agent_acu_sk,
                &active_keys_ep1,
            )
            .unwrap();
        assert_eq!(live_plaintext, SAMPLE_CI_ROOT_CAUSE_JSON);

        // Compromise resistance: `Coding Agent + Archive Unit` WITHOUT the CISO's ACU FAILS closed!
        let d_archive_ep1 = acu_partial_decrypt_at_epoch(
            &inbox_ciphertext.acu_ciphertext.rows[2],
            &archive_acu_sk,
            inbox_ciphertext.acu_ciphertext.policy_epoch,
        );
        let mut pq_both = inbox_ciphertext
            .decapsulate_pq_shares_for_seat(&agent_acu_sk)
            .unwrap();
        pq_both.extend(
            inbox_ciphertext
                .decapsulate_pq_shares_for_seat(&archive_acu_sk)
                .unwrap(),
        );
        assert_eq!(
            inbox_ciphertext.decrypt(&[d_agent_ep1, d_archive_ep1], &pq_both, &active_keys_ep1),
            Err(AcuError::PolicyNotSatisfied)
        );

        let active_keys = registry.active_acu_keys();
        ciso_fat_client
            .revoke_and_rerandomize(
                &mut inbox_ciphertext.acu_ciphertext,
                &[DEFAULT_AGENT_BRANCH_ID],
                &active_keys,
                &mut rng,
            )
            .unwrap();
        inbox_ciphertext
            .prune_revoked_pq_capsules(&[DEFAULT_AGENT_BRANCH_ID])
            .unwrap();
        registry.revoke_seat(DEFAULT_AGENT_BRANCH_ID).unwrap();
        ciso_fat_client.instant_revoke(DEFAULT_AGENT_BRANCH_ID);

        assert_eq!(inbox_ciphertext.acu_ciphertext.policy_epoch, 2);
        assert_eq!(inbox_ciphertext.acu_ciphertext.rows.len(), 2);
        assert_eq!(
            inbox_ciphertext.acu_ciphertext.rows[0].seat_id,
            DEFAULT_CISO_ACU_ID
        );
        assert_eq!(
            inbox_ciphertext.acu_ciphertext.rows[1].seat_id,
            DEFAULT_MESSAGE_ARCHIVE_ID
        );

        let archive_req = AcuShareRequest::create_signed(
            "req-forensic-02",
            DEFAULT_MESSAGE_ARCHIVE_ID,
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-ZERO-PLAINTEXT-INBOX-09",
            inbox_ciphertext.acu_ciphertext.policy_epoch,
            inbox_ciphertext.acu_ciphertext.clone(),
            inbox_ciphertext.acu_ciphertext.rows[0].clone(),
            1_793_800_020_000,
            &archive_ed25519_sk,
        );
        let archive_resp = ciso_fat_client
            .authorize_archive_investigation(
                &archive_req,
                DEFAULT_MESSAGE_ARCHIVE_ID,
                "SEC-INCIDENT-2026-1107",
                &registry,
            )
            .unwrap();
        assert_eq!(
            archive_resp.audit_entry.decision,
            AcuAuditDecision::GrantedArchiveInvestigation
        );
        assert_eq!(
            archive_resp.audit_entry.reason,
            "forensic_investigation:SEC-INCIDENT-2026-1107"
        );

        let d_archive_ep2 = acu_partial_decrypt_at_epoch(
            &inbox_ciphertext.acu_ciphertext.rows[1],
            &archive_acu_sk,
            inbox_ciphertext.acu_ciphertext.policy_epoch,
        );
        let active_keys_ep2 = registry.active_acu_keys();
        let forensic_plaintext = inbox_ciphertext
            .decrypt_with_local_key(
                &[archive_resp.partial_share, d_archive_ep2],
                &archive_acu_sk,
                &active_keys_ep2,
            )
            .unwrap();
        assert_eq!(forensic_plaintext, SAMPLE_CI_ROOT_CAUSE_JSON);
    }

    #[test]
    fn test_10_duckdb_parquet_archive_cleartext_metadata_search_and_ciso_blob_decryption() {
        use std::sync::Arc;

        let mut rng = OsRng;
        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0x11u8; 32]);

        let (_agent1_sk, agent1_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent1_ed25519_sk = SigningKey::from_bytes(&[0x22u8; 32]);

        let (_agent2_sk, agent2_pk) = SeatSecretKey::generate("branch:77441122", &mut rng).unwrap();
        let agent2_ed25519_sk = SigningKey::from_bytes(&[0x33u8; 32]);

        let (archive_sk, archive_pk) =
            SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();
        let archive_ed25519_sk = SigningKey::from_bytes(&[0x44u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        registry
            .register_seat(
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_AGENT_BRANCH_ID,
                agent1_ed25519_sk.verifying_key(),
                agent1_pk,
            )
            .unwrap();
        registry
            .register_seat(
                "branch:77441122",
                agent2_ed25519_sk.verifying_key(),
                agent2_pk,
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_MESSAGE_ARCHIVE_ID,
                archive_ed25519_sk.verifying_key(),
                archive_pk,
            )
            .unwrap();

        let duckdb_cfg =
            DuckDbArchiveConfig::cloudflare_r2("cf-acct-99887766", "chinwag-archive").unwrap();
        let init_sql = duckdb_cfg.to_httpfs_init_sql().unwrap();
        assert!(init_sql.contains("SET threads = 2;"));
        assert!(init_sql.contains("SET memory_limit = '1GB';"));
        assert!(init_sql.contains("SET s3_region = 'auto';"));
        assert!(
            init_sql.contains("SET s3_endpoint = 'cf-acct-99887766.r2.cloudflarestorage.com';")
        );
        assert!(init_sql.contains("SET s3_url_style = 'path';"));

        let (cache_sql, cache_params) = duckdb_cfg
            .build_populate_active_channel_cache_sql("emunlabs", "#eng", 50)
            .unwrap();
        assert!(cache_sql.contains("CREATE TEMP TABLE IF NOT EXISTS active_channel_cache AS"));
        assert!(cache_sql.contains(
            "read_parquet('s3://chinwag-archive/org_id=emunlabs/year=*/month=*/day=*/*.parquet', hive_partitioning = true)"
        ));
        assert_eq!(cache_params, vec!["#eng".to_string()]);

        let (scroll_sql, scroll_params) = duckdb_cfg
            .build_scroll_older_chunk_sql("emunlabs", "#eng", 1_793_800_003_000, 50)
            .unwrap();
        assert!(scroll_sql.contains("WHERE room = $1 AND timestamp_utc < $2"));
        assert_eq!(
            scroll_params,
            vec!["#eng".to_string(), "1793800003000".to_string()]
        );

        let part_day1 = HivePartitionKey::new("emunlabs", 2026, 11, 6).unwrap();
        let part_day2 = HivePartitionKey::new("emunlabs", 2026, 11, 7).unwrap();
        assert_eq!(
            part_day2.s3_parquet_uri("chinwag-archive").unwrap(),
            "s3://chinwag-archive/org_id=emunlabs/year=2026/month=11/day=07/archive.parquet"
        );
        assert_eq!(
            part_day2.r2_parquet_uri("chinwag-archive").unwrap(),
            "r2://chinwag-archive/org_id=emunlabs/year=2026/month=11/day=07/archive.parquet"
        );

        let mut store = AcuParquetArchiveStore::new();
        type TestFixtureRow<'a> = (
            &'a HivePartitionKey,
            &'a str,
            u64,
            &'a str,
            &'a str,
            &'a str,
            &'a str,
            &'a [u8],
        );
        let entries: &[TestFixtureRow<'_>] = &[
            (
                &part_day1,
                "msg-1",
                1_793_800_001_000,
                DEFAULT_AGENT_BRANCH_ID,
                "branch:77441122",
                "#eng",
                "CHWG-101",
                b"msg-1: secret root-cause from branch:8687872 on CHWG-101",
            ),
            (
                &part_day1,
                "msg-2",
                1_793_800_002_000,
                "branch:77441122",
                DEFAULT_AGENT_BRANCH_ID,
                "#eng",
                "CHWG-101",
                b"msg-2: reply from branch:77441122 on CHWG-101",
            ),
            (
                &part_day2,
                "msg-3",
                1_793_800_003_000,
                DEFAULT_AGENT_BRANCH_ID,
                "branch:77441122",
                "#ci",
                "CHWG-202",
                b"msg-3: unrelated ticket CHWG-202",
            ),
            (
                &part_day2,
                "msg-4",
                1_793_800_004_000,
                DEFAULT_AGENT_BRANCH_ID,
                "branch:77441122",
                "#eng",
                "CHWG-101",
                b"msg-4: second secret update from branch:8687872 on CHWG-101",
            ),
            (
                &part_day2,
                "msg-5",
                1_793_800_005_000,
                "branch:77441122",
                DEFAULT_AGENT_BRANCH_ID,
                "#ci",
                "CHWG-202",
                b"msg-5: another unrelated message",
            ),
        ];

        for &(part, msg_id, ts, sender, recipient, room, task, body) in entries {
            let sender_sk = if sender == DEFAULT_AGENT_BRANCH_ID {
                &agent1_ed25519_sk
            } else {
                &agent2_ed25519_sk
            };
            store
                .append_signed_message(
                    part.clone(),
                    msg_id,
                    ts,
                    sender,
                    recipient,
                    room,
                    task,
                    body,
                    sender_sk,
                    &registry,
                    &mut rng,
                )
                .unwrap();
        }

        let (hit1, page1) = store.load_channel_window("emunlabs", "#eng", None, 2);
        assert_eq!(hit1, CacheHit::R2ParquetRangeFetch);
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].message_id, "msg-4");
        assert_eq!(page1[1].message_id, "msg-2");

        let (hit2, page2) = store.load_channel_window("emunlabs", "#eng", None, 2);
        assert_eq!(hit2, CacheHit::ActiveChannelRamCache);
        assert_eq!(page2, page1);

        let (hit3, page3) =
            store.load_channel_window("emunlabs", "#eng", Some(1_793_800_002_000), 2);
        assert_eq!(hit3, CacheHit::R2ParquetRangeFetch);
        assert_eq!(page3.len(), 1);
        assert_eq!(page3[0].message_id, "msg-1");

        let mut filter = ArchiveSearchFilter::new("emunlabs");
        filter.sender_seat = Some(DEFAULT_AGENT_BRANCH_ID.to_string());
        filter.task_id = Some("CHWG-101".to_string());

        let (query_sql, bind_params) = duckdb_cfg.build_read_parquet_query(&filter).unwrap();
        assert!(query_sql.contains("WHERE sender_seat = $1 AND task_id = $2"));
        assert_eq!(
            bind_params,
            vec![DEFAULT_AGENT_BRANCH_ID.to_string(), "CHWG-101".to_string()]
        );

        let ciso_fat_client = CisoAcuFatClient::new(acu_sk, acu_pk, acu_ed25519_sk);
        let shared_handle = SharedFatClientArchiveHandle::new(store, ciso_fat_client);
        let join_handle = shared_handle.spawn_blocking_investigation(
            filter,
            "TICKET-R2-PARQUET-10".to_string(),
            archive_ed25519_sk,
            Arc::new(archive_sk),
            registry,
        );

        let decrypted_records = join_handle.join().unwrap().unwrap();
        assert_eq!(decrypted_records.len(), 2);
        assert_eq!(decrypted_records[0].message_id, "msg-4");
        assert_eq!(
            decrypted_records[0].plaintext,
            b"msg-4: second secret update from branch:8687872 on CHWG-101"
        );
        assert_eq!(decrypted_records[1].message_id, "msg-1");
        assert_eq!(
            decrypted_records[1].plaintext,
            b"msg-1: secret root-cause from branch:8687872 on CHWG-101"
        );
    }

    #[test]
    fn test_11_archive_blob_binary_roundtrip_tamper_rejection_and_post_revocation_forensics() {
        let mut rng = OsRng;
        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0x51u8; 32]);

        let (agent_sk, agent_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent_ed25519_sk = SigningKey::from_bytes(&[0x61u8; 32]);

        let (archive_sk, archive_pk) =
            SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();
        let archive_ed25519_sk = SigningKey::from_bytes(&[0x71u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        registry
            .register_seat(
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_AGENT_BRANCH_ID,
                agent_ed25519_sk.verifying_key(),
                agent_pk,
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_MESSAGE_ARCHIVE_ID,
                archive_ed25519_sk.verifying_key(),
                archive_pk,
            )
            .unwrap();

        let partition = HivePartitionKey::new("emunlabs", 2026, 11, 7).unwrap();
        let mut store = AcuParquetArchiveStore::new();
        let row = store
            .append_signed_message(
                partition,
                "msg-forensic-11",
                1_793_800_100_000,
                DEFAULT_AGENT_BRANCH_ID,
                DEFAULT_AGENT_BRANCH_ID,
                "#eng",
                "CHWG-FORENSIC-11",
                SAMPLE_CI_ROOT_CAUSE_JSON,
                &agent_ed25519_sk,
                &registry,
                &mut rng,
            )
            .unwrap();

        let decoded_payload = EncryptedCiPayload::from_bytes(&row.acu_ciphertext).unwrap();
        assert_eq!(decoded_payload.to_bytes(), row.acu_ciphertext);

        let mut ciso_fat_client = CisoAcuFatClient::new(acu_sk, acu_pk, acu_ed25519_sk.clone());
        store.update_row_by_id("msg-forensic-11", |r| {
            let last = r.acu_ciphertext.len() - 1;
            r.acu_ciphertext[last] ^= 0x01;
        });
        let filter = ArchiveSearchFilter::new("emunlabs");
        assert_eq!(
            store.ciso_investigate_and_decrypt(
                &filter,
                "INCIDENT-TAMPER",
                &mut ciso_fat_client,
                &archive_ed25519_sk,
                &archive_sk,
                &registry,
            ),
            Err(AcuError::SignatureVerificationFailed("archive_row"))
        );

        store.update_row_by_id("msg-forensic-11", |r| {
            let last = r.acu_ciphertext.len() - 1;
            r.acu_ciphertext[last] ^= 0x01;
        });

        let mut unauthorized_err = None;
        store.update_row_by_id("msg-forensic-11", |r| {
            if let Err(e) = r.revoke_and_rerandomize_in_place(
                &agent_sk,
                &[DEFAULT_AGENT_BRANCH_ID],
                &registry,
                DEFAULT_AGENT_BRANCH_ID,
                &agent_ed25519_sk,
                &mut rng,
            ) {
                unauthorized_err = Some(e);
            }
        });
        assert_eq!(unauthorized_err, Some(AcuError::UnauthorizedPolicyOperator));

        let mut err_opt = None;
        let acu_sk_ref = ciso_fat_client.acu_secret_key();
        store.update_row_by_id("msg-forensic-11", |r| {
            if let Err(e) = r.revoke_and_rerandomize_in_place(
                acu_sk_ref,
                &[DEFAULT_AGENT_BRANCH_ID],
                &registry,
                DEFAULT_CISO_ACU_ID,
                &acu_ed25519_sk,
                &mut rng,
            ) {
                err_opt = Some(e);
            }
        });
        assert_eq!(err_opt, None);
        registry.revoke_seat(DEFAULT_AGENT_BRANCH_ID).unwrap();
        ciso_fat_client.instant_revoke(DEFAULT_AGENT_BRANCH_ID);

        let updated_row = store.search_metadata(&filter)[0];
        assert_eq!(updated_row.policy_epoch, 2);
        let epoch2_payload = EncryptedCiPayload::from_bytes(&updated_row.acu_ciphertext).unwrap();
        assert_eq!(epoch2_payload.acu_ciphertext.rows.len(), 2);
        assert!(
            epoch2_payload
                .acu_ciphertext
                .rows
                .iter()
                .all(|r| r.seat_id != DEFAULT_AGENT_BRANCH_ID)
        );

        let recovered = store
            .ciso_investigate_and_decrypt(
                &filter,
                "INCIDENT-EPOCH2-FORENSICS",
                &mut ciso_fat_client,
                &archive_ed25519_sk,
                &archive_sk,
                &registry,
            )
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].policy_epoch, 2);
        assert_eq!(recovered[0].plaintext, SAMPLE_CI_ROOT_CAUSE_JSON);
    }

    #[test]
    fn test_12_chwg_0283_zero_cleartext_v0_on_wire_and_untrusted_relay_cannot_unmask() {
        let mut rng = OsRng;
        let (sk_agent, pk_agent) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let (sk_acu, pk_acu) =
            SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();
        let (_rogue_sk, rogue_pk) = SeatSecretKey::generate("branch:rogue", &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(pk_agent.seat_id.clone(), pk_agent.clone());
        seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
        seat_keys.insert(rogue_pk.seat_id.clone(), rogue_pk.clone());

        let tree =
            EncryptedCiPayload::build_split_key_acu_policy(&pk_agent.seat_id, &pk_acu.seat_id);
        let matrix = LsssMatrix::from_tree(&tree).unwrap();

        let k_scalar = Scalar::from(0xDEAD_BEEF_CAFE_BABEu64);
        let payload_g1 = G1Projective::generator() * k_scalar;
        let (ct, expected_k_gt) =
            acu_encrypt_with_g1(&payload_g1, &matrix, &seat_keys, &pk_acu, &mut rng).unwrap();

        let v0_g1 = ct.c0_g1 - payload_g1;
        assert_eq!(
            pairing(&G1Affine::from(ct.c0_g1 - v0_g1), &G2Affine::generator()),
            expected_k_gt
        );
        let v0_compressed = G1Affine::from(v0_g1).to_compressed();
        let neg_v0_compressed = G1Affine::from(-v0_g1).to_compressed();

        let ct_wire = ct.to_bytes();
        assert_eq!(&ct_wire[..8], b"CHWGACU3");
        assert!(
            !ct_wire
                .windows(48)
                .any(|w| w == v0_compressed || w == neg_v0_compressed),
            "compressed V_0 = s*G1 or -V_0 must NEVER appear anywhere on the wire!"
        );

        let mut candidate_g1_points = vec![pk_agent.pk1, -pk_agent.pk1, pk_acu.pk1, -pk_acu.pk1];
        for window in ct_wire.windows(48) {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(window);
            let aff_opt: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
            if let Some(aff) = aff_opt {
                let p = G1Projective::from(aff);
                candidate_g1_points.push(p);
                candidate_g1_points.push(-p);
            }
        }
        for cand in &candidate_g1_points {
            let unmasked = pairing(&G1Affine::from(ct.c0_g1 - cand), &G2Affine::generator());
            assert_ne!(
                unmasked, expected_k_gt,
                "untrusted relay recovered K_GT from wire G1 point without any secret key!"
            );
        }

        let true_d_agent = acu_partial_decrypt_at_epoch(&ct.rows[0], &sk_agent, ct.policy_epoch);
        let true_d_acu = acu_partial_decrypt_at_epoch(&ct.rows[1], &sk_acu, ct.policy_epoch);
        let g2_aff = G2Affine::generator();
        let true_d_agent_gt = pairing(&G1Affine::from(true_d_agent.share_g1), &g2_aff);
        let true_d_acu_gt = pairing(&G1Affine::from(true_d_acu.share_g1), &g2_aff);

        let pub_row0_c1_gt = pairing(&G1Affine::from(ct.rows[0].c1), &g2_aff);
        let pub_row0_c2_gt = pairing(&G1Affine::from(ct.rows[0].c2), &g2_aff);
        let pub_row1_c1_gt = pairing(&G1Affine::from(ct.rows[1].c1), &g2_aff);
        let pub_row1_c2_gt = pairing(&G1Affine::from(ct.rows[1].c2), &g2_aff);
        let pub_pk_agent_gt = pairing(&G1Affine::from(pk_agent.pk1), &g2_aff);
        let pub_pk_acu_gt = pairing(&G1Affine::from(pk_acu.pk1), &g2_aff);
        for probe_d0 in [
            pub_row0_c1_gt,
            pub_row0_c1_gt - pub_row0_c2_gt,
            pub_row0_c1_gt - pub_pk_agent_gt,
            pub_row0_c1_gt - pub_row0_c2_gt - pub_pk_agent_gt,
        ] {
            assert_ne!(probe_d0, true_d_agent_gt);
            for probe_d1 in [
                pub_row1_c1_gt,
                pub_row1_c1_gt - pub_row1_c2_gt,
                pub_row1_c1_gt - pub_pk_acu_gt,
                pub_row1_c1_gt - pub_row1_c2_gt - pub_pk_acu_gt,
            ] {
                assert_ne!(probe_d1, true_d_acu_gt);
                let lsss_combo = probe_d0 * Scalar::from(2u64) - probe_d1;
                assert_ne!(ct.c0 - lsss_combo, expected_k_gt);
            }
        }

        let mut payload = EncryptedCiPayload::encrypt_split_key_with_acu(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &pk_agent,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-0283-RELAY-UNMASK-CHECK",
            &mut rng,
        )
        .unwrap();
        let payload_wire = payload.to_bytes();
        assert_eq!(&payload_wire[..8], b"CHWGAEA2");
        assert!(payload_wire.windows(8).any(|w| w == b"CHWGACU3"));
        assert!(!payload_wire.windows(8).any(|w| w == b"CHWGACU1"));
        assert!(!payload_wire.windows(8).any(|w| w == b"CHWGACU2"));

        let cipher_probe = |cand_gt: &bls12_381::Gt| -> bool {
            let Ok(sym_key) = derive_aead_key_from_gt(cand_gt, &payload.associated_data) else {
                return false;
            };
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&*sym_key));
            cipher
                .decrypt(
                    Nonce::from_slice(&payload.nonce),
                    Payload {
                        msg: &payload.aead_ciphertext,
                        aad: &payload.associated_data,
                    },
                )
                .is_ok()
        };

        for window in payload_wire.windows(48) {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(window);
            let aff_opt: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
            if let Some(aff) = aff_opt {
                let p = G1Projective::from(aff);
                for sign_p in [p, -p] {
                    let cand_gt = pairing(
                        &G1Affine::from(payload.acu_ciphertext.c0_g1 - sign_p),
                        &G2Affine::generator(),
                    );
                    assert!(
                        !cipher_probe(&cand_gt),
                        "untrusted relay decrypted CHWGAEA2 by subtracting serialized G1 point!"
                    );
                }
            }
        }

        // Compromised single branch (`sk_agent` without `sk_acu`) CANNOT perform ACU policy evolutions!
        let wf =
            WarmForkRequest::create(&payload.acu_ciphertext, 0, &sk_agent, &rogue_pk, &mut rng)
                .unwrap();
        assert_eq!(
            insert_sibling_key(&mut payload.acu_ciphertext, &sk_agent, &wf, &seat_keys),
            Err(AcuError::UnauthorizedPolicyOperator)
        );
        assert_eq!(
            escalate_threshold(
                &mut payload.acu_ciphertext,
                &sk_agent,
                &[0, 1],
                1,
                &seat_keys,
                &mut rng,
            ),
            Err(AcuError::UnauthorizedPolicyOperator)
        );
        assert_eq!(
            revoke_and_rerandomize(
                &mut payload.acu_ciphertext,
                &sk_agent,
                &[DEFAULT_REVOCATION_ACU_ID],
                &seat_keys,
                &mut rng,
            ),
            Err(AcuError::UnauthorizedPolicyOperator)
        );

        let d_agent = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk_agent,
            payload.acu_ciphertext.policy_epoch,
        );
        let d_acu = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            &sk_acu,
            payload.acu_ciphertext.policy_epoch,
        );
        assert_eq!(
            payload
                .decrypt_with_local_key(&[d_agent, d_acu], &sk_agent, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
    }

    #[test]
    fn test_13_chwg_0283_rejects_legacy_chwgacu1_chwgacu2_and_tampered_slot_or_header() {
        let mut rng = OsRng;
        let (sk_agent, pk_agent) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let (sk_acu, pk_acu) =
            SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();
        let (sk_other_acu, _pk_other_acu) =
            SeatSecretKey::generate(DEFAULT_REVOCATION_ACU_ID, &mut rng).unwrap();
        let (_sk_fork, pk_fork) = SeatSecretKey::generate("branch:fork-13", &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(pk_agent.seat_id.clone(), pk_agent.clone());
        seat_keys.insert(pk_acu.seat_id.clone(), pk_acu.clone());
        seat_keys.insert(pk_fork.seat_id.clone(), pk_fork.clone());

        let payload1 = EncryptedCiPayload::encrypt_split_key_with_acu(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &pk_agent,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-0283-LEGACY-AND-AAD-1",
            &mut rng,
        )
        .unwrap();
        let payload2 = EncryptedCiPayload::encrypt_split_key_with_acu(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &pk_agent,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-0283-LEGACY-AND-AAD-2",
            &mut rng,
        )
        .unwrap();

        // 1. Legacy `CHWGACU1`, `CHWGACU2`, and `CHWGAEAD` wire blobs fail closed with `InsecureLegacyFormat`!
        for legacy_magic in [b"CHWGACU1", b"CHWGACU2"] {
            let mut legacy_ct_bytes = payload1.acu_ciphertext.to_bytes();
            legacy_ct_bytes[..8].copy_from_slice(legacy_magic);
            assert!(matches!(
                AcuCiphertext::from_bytes(&legacy_ct_bytes),
                Err(AcuError::InsecureLegacyFormat(_))
            ));
        }
        let mut legacy_payload_bytes = payload1.to_bytes();
        legacy_payload_bytes[..8].copy_from_slice(b"CHWGAEAD");
        assert_eq!(
            EncryptedCiPayload::from_bytes(&legacy_payload_bytes),
            Err(AcuError::InsecureLegacyFormat("CHWGAEAD"))
        );

        // 2. Wrong ACU scalar with matching `acu_seat_id` fails operator verification!
        let wf =
            WarmForkRequest::create(&payload1.acu_ciphertext, 0, &sk_agent, &pk_fork, &mut rng)
                .unwrap();
        let mut ct_wrong_key = payload1.acu_ciphertext.clone();
        assert_eq!(
            insert_sibling_key(&mut ct_wrong_key, &sk_other_acu, &wf, &seat_keys),
            Err(AcuError::UnauthorizedPolicyOperator)
        );
        assert_eq!(ct_wrong_key, payload1.acu_ciphertext);

        // 3. Bit-flip in `sbc_slots[0].ciphertext` fails closed on `insert_authorized_seat` (`BasisUnsealFailed`).
        let c0_share =
            CoalitionInsertionRowShare::issue_for_row(&payload1.acu_ciphertext, 0, &sk_agent)
                .unwrap();
        let c1_share =
            CoalitionInsertionRowShare::issue_for_row(&payload1.acu_ciphertext, 1, &sk_acu)
                .unwrap();
        let mut ct_tampered_slot = payload1.acu_ciphertext.clone();
        ct_tampered_slot.sbc_slots[0].ciphertext[0] ^= 0x80;
        assert_eq!(
            insert_authorized_seat(
                &mut ct_tampered_slot,
                &sk_acu,
                "branch:fork-13",
                vec![Scalar::ONE, Scalar::ONE],
                &[c0_share, c1_share],
                &seat_keys,
                &mut rng,
            ),
            Err(AcuError::BasisUnsealFailed)
        );

        // 4. Splicing `payload2.acu_ciphertext.sbc_slots` onto `payload1.acu_ciphertext` fails `verify_authenticity`!
        assert!(
            payload1
                .acu_ciphertext
                .verify_authenticity(&pk_acu, |id| seat_keys.get(id))
                .is_ok()
        );
        let mut ct_spliced = payload1.acu_ciphertext.clone();
        ct_spliced.sbc_slots = payload2.acu_ciphertext.sbc_slots.clone();
        assert!(
            ct_spliced
                .verify_authenticity(&pk_acu, |id| seat_keys.get(id))
                .is_err()
        );

        // 5. Tampering with header fields (`policy_epoch`, `row.c1`, `row.matrix_row`) fails `verify_authenticity`!
        let mut ct_bad_epoch = payload1.acu_ciphertext.clone();
        ct_bad_epoch.policy_epoch = 99;
        assert!(
            ct_bad_epoch
                .verify_authenticity(&pk_acu, |id| seat_keys.get(id))
                .is_err()
        );

        let mut ct_bad_row_c1 = payload1.acu_ciphertext.clone();
        ct_bad_row_c1.rows[0].c1 += G1Projective::generator();
        assert!(
            ct_bad_row_c1
                .verify_authenticity(&pk_acu, |id| seat_keys.get(id))
                .is_err()
        );

        let mut ct_bad_matrix = payload1.acu_ciphertext.clone();
        ct_bad_matrix.rows[0].matrix_row[1] += Scalar::ONE;
        ct_bad_matrix.matrix.rows[0].1[1] += Scalar::ONE;
        assert!(
            ct_bad_matrix
                .verify_authenticity(&pk_acu, |id| seat_keys.get(id))
                .is_err()
        );
    }

    #[test]
    fn test_14_chwg_0283_full_wire_roundtrip_across_all_four_policy_evolutions() {
        let mut rng = OsRng;
        let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let (sk_a, pk_a) = SeatSecretKey::generate("branch:alpha", &mut rng).unwrap();
        let (sk_b, pk_b) = SeatSecretKey::generate("branch:beta", &mut rng).unwrap();
        let (sk_c, pk_c) = SeatSecretKey::generate("branch:gamma", &mut rng).unwrap();
        let (sk_d, pk_d) = SeatSecretKey::generate("branch:delta", &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        for pk in [&pk_acu, &pk_a, &pk_b, &pk_c, &pk_d] {
            seat_keys.insert(pk.seat_id.clone(), (*pk).clone());
        }

        // Epoch 1: `(branch:alpha OR branch:beta) AND acu:98939834`
        let tree = AccessTree::And(vec![
            AccessTree::Or(vec![
                AccessTree::Leaf("branch:alpha".to_string()),
                AccessTree::Leaf("branch:beta".to_string()),
            ]),
            AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
        ]);
        let ep1_payload = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &tree,
            &seat_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-0283-ALL-FOUR-EVOLUTIONS",
            &mut rng,
        )
        .unwrap();
        let ep1_immutable_hash = ep1_payload.immutable_aead_blake3();
        let mut wire = ep1_payload.to_bytes();

        // Epoch 1 -> Epoch 2 via `insert_authorized_seat` + `insert_authorized_pq_seat` (append `branch:gamma`)
        let mut p = EncryptedCiPayload::from_bytes(&wire).unwrap();
        assert_eq!(p.acu_ciphertext.policy_epoch, 1);
        let alpha_row_vec = p.acu_ciphertext.rows[0].matrix_row.clone();
        let c_alpha =
            CoalitionInsertionRowShare::issue_for_row(&p.acu_ciphertext, 0, &sk_a).unwrap();
        let c_acu =
            CoalitionInsertionRowShare::issue_for_row(&p.acu_ciphertext, 2, &sk_acu).unwrap();
        let idx_c = insert_authorized_seat(
            &mut p.acu_ciphertext,
            &sk_acu,
            "branch:gamma",
            alpha_row_vec,
            &[c_alpha, c_acu],
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        let pq_alpha = p.decapsulate_pq_shares_for_seat(&sk_a).unwrap();
        let pq_alpha_vec = p.pq_header.as_ref().unwrap().rows[0].matrix_row.clone();
        p.insert_authorized_pq_seat(
            "branch:gamma",
            pq_alpha_vec,
            &pq_alpha,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        assert_eq!(idx_c, 3);
        assert_eq!(p.acu_ciphertext.policy_epoch, 2);
        assert_eq!(p.immutable_aead_blake3(), ep1_immutable_hash);
        wire = p.to_bytes();

        // Epoch 2 -> Epoch 3 via `WarmForkRequest` + `insert_sibling_key` + `attach_pq_sibling_capsule` (`branch:delta` sibling of `branch:beta`)
        let mut p = EncryptedCiPayload::from_bytes(&wire).unwrap();
        let d_c_ep2 = acu_partial_decrypt_at_epoch(
            &p.acu_ciphertext.rows[3],
            &sk_c,
            p.acu_ciphertext.policy_epoch,
        );
        let d_acu_ep2 = acu_partial_decrypt_at_epoch(
            &p.acu_ciphertext.rows[2],
            &sk_acu,
            p.acu_ciphertext.policy_epoch,
        );
        assert_eq!(
            p.decrypt_with_local_key(&[d_c_ep2, d_acu_ep2], &sk_c, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
        let wf_req = WarmForkRequest::create(&p.acu_ciphertext, 1, &sk_b, &pk_d, &mut rng).unwrap();
        let idx_d =
            insert_sibling_key(&mut p.acu_ciphertext, &sk_acu, &wf_req, &seat_keys).unwrap();
        p.attach_pq_sibling_capsule(&sk_b, &pk_d, &mut rng).unwrap();
        assert_eq!(idx_d, 4);
        assert_eq!(p.acu_ciphertext.policy_epoch, 3);
        wire = p.to_bytes();

        // Epoch 3 -> Epoch 4 via `escalate_threshold` on `{alpha, beta, gamma, delta}` (rows `[0, 1, 3, 4]`: 1-of-4 -> 2-of-4)
        let mut p = EncryptedCiPayload::from_bytes(&wire).unwrap();
        let d_d_ep3 = acu_partial_decrypt_at_epoch(
            &p.acu_ciphertext.rows[4],
            &sk_d,
            p.acu_ciphertext.policy_epoch,
        );
        let d_acu_ep3 = acu_partial_decrypt_at_epoch(
            &p.acu_ciphertext.rows[2],
            &sk_acu,
            p.acu_ciphertext.policy_epoch,
        );
        assert_eq!(
            p.decrypt_with_local_key(&[d_d_ep3, d_acu_ep3], &sk_d, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
        escalate_threshold(
            &mut p.acu_ciphertext,
            &sk_acu,
            &[0, 1, 3, 4],
            1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        assert_eq!(p.acu_ciphertext.policy_epoch, 4);
        wire = p.to_bytes();

        // Epoch 4: 1 branch + ACU fails (`PolicyNotSatisfied`), 2 branches + ACU succeeds!
        let mut p = EncryptedCiPayload::from_bytes(&wire).unwrap();
        let d_a_ep4 = acu_partial_decrypt_at_epoch(
            &p.acu_ciphertext.rows[0],
            &sk_a,
            p.acu_ciphertext.policy_epoch,
        );
        let d_b_ep4 = acu_partial_decrypt_at_epoch(
            &p.acu_ciphertext.rows[1],
            &sk_b,
            p.acu_ciphertext.policy_epoch,
        );
        let d_acu_ep4 = acu_partial_decrypt_at_epoch(
            &p.acu_ciphertext.rows[2],
            &sk_acu,
            p.acu_ciphertext.policy_epoch,
        );
        let mut pq_ab = p.decapsulate_pq_shares_for_seat(&sk_a).unwrap();
        pq_ab.extend(p.decapsulate_pq_shares_for_seat(&sk_b).unwrap());
        assert_eq!(
            p.decrypt_with_local_key(&[d_a_ep4.clone(), d_acu_ep4.clone()], &sk_a, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            p.decrypt(&[d_a_ep4, d_b_ep4, d_acu_ep4], &pq_ab, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );

        // Epoch 4 -> Epoch 5 via `revoke_and_rerandomize` + `prune_revoked_pq_capsules` (`branch:alpha`, `branch:delta`)
        let ep4_c0 = p.acu_ciphertext.c0;
        revoke_and_rerandomize(
            &mut p.acu_ciphertext,
            &sk_acu,
            &["branch:alpha", "branch:delta"],
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        p.prune_revoked_pq_capsules(&["branch:alpha", "branch:delta"])
            .unwrap();
        assert_eq!(p.acu_ciphertext.policy_epoch, 5);
        assert_ne!(p.acu_ciphertext.c0, ep4_c0);
        wire = p.to_bytes();

        // Final wire round-trip at Epoch 5: remaining rows `[branch:beta (0), acu:98939834 (1), branch:gamma (2)]`
        let p_final = EncryptedCiPayload::from_bytes(&wire).unwrap();
        assert_eq!(p_final.immutable_aead_blake3(), ep1_immutable_hash);
        assert_eq!(p_final.acu_ciphertext.rows.len(), 3);
        assert_eq!(p_final.acu_ciphertext.rows[0].seat_id, "branch:beta");
        assert_eq!(p_final.acu_ciphertext.rows[1].seat_id, DEFAULT_CISO_ACU_ID);
        assert_eq!(p_final.acu_ciphertext.rows[2].seat_id, "branch:gamma");

        let d_b_ep5 = acu_partial_decrypt_at_epoch(
            &p_final.acu_ciphertext.rows[0],
            &sk_b,
            p_final.acu_ciphertext.policy_epoch,
        );
        let d_acu_ep5 = acu_partial_decrypt_at_epoch(
            &p_final.acu_ciphertext.rows[1],
            &sk_acu,
            p_final.acu_ciphertext.policy_epoch,
        );
        let d_c_ep5 = acu_partial_decrypt_at_epoch(
            &p_final.acu_ciphertext.rows[2],
            &sk_c,
            p_final.acu_ciphertext.policy_epoch,
        );
        let mut pq_bc = p_final.decapsulate_pq_shares_for_seat(&sk_b).unwrap();
        pq_bc.extend(p_final.decapsulate_pq_shares_for_seat(&sk_c).unwrap());
        assert_eq!(
            p_final.decrypt_with_local_key(
                &[d_b_ep5.clone(), d_acu_ep5.clone()],
                &sk_b,
                &seat_keys
            ),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            p_final
                .decrypt(&[d_b_ep5, d_c_ep5, d_acu_ep5], &pq_bc, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
    }

    #[test]
    fn test_15_published_rfc5869_hkdf_rfc8439_chacha20poly1305_and_bls12_381_g2_vectors() {
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm);

        let rfc8439_key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let rfc8439_nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let rfc8439_aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let rfc8439_pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct_and_tag: [u8; 130] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
            0xd0, 0x60, 0x06, 0x91,
        ];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&rfc8439_key));
        let produced = cipher
            .encrypt(
                Nonce::from_slice(&rfc8439_nonce),
                Payload {
                    msg: rfc8439_pt,
                    aad: &rfc8439_aad,
                },
            )
            .unwrap();
        assert_eq!(produced.as_slice(), &expected_ct_and_tag);

        let mut bad_aad = rfc8439_aad;
        bad_aad[0] ^= 0x01;
        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(&rfc8439_nonce),
                    Payload {
                        msg: &produced,
                        aad: &bad_aad,
                    },
                )
                .is_err()
        );

        const IETF_BLS12_381_G2_GEN_COMPRESSED: [u8; 96] = [
            0x93, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27,
            0x4f, 0x65, 0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a, 0xb5, 0xda, 0x61, 0xbb,
            0xdc, 0x7f, 0x50, 0x49, 0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac,
            0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e, 0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91,
            0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51, 0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40,
            0x3b, 0x02, 0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77, 0x0b, 0xac, 0x03, 0x26,
            0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8,
        ];
        assert_eq!(
            G2Affine::generator().to_compressed(),
            IETF_BLS12_381_G2_GEN_COMPRESSED
        );

        const EXPECTED_GT_GEN_KAT_KEY: [u8; 32] = [
            0xac, 0x99, 0x30, 0xbb, 0xb1, 0x64, 0xed, 0x02, 0x5b, 0xdf, 0x78, 0xf7, 0x7e, 0xba,
            0x46, 0x17, 0x15, 0x01, 0x53, 0x09, 0xc0, 0x8a, 0x8a, 0xd7, 0xee, 0x3e, 0xb7, 0xba,
            0xb8, 0x23, 0xba, 0x78,
        ];
        let gt_gen = pairing(&G1Affine::generator(), &G2Affine::generator());
        let gt_kat_aad = b"chinwag-acu-gt-kat-v1";
        let derived_gt_key_1 = derive_aead_key_from_gt(&gt_gen, gt_kat_aad).unwrap();
        let derived_gt_key_2 = derive_aead_key_from_gt(&gt_gen, gt_kat_aad).unwrap();
        assert_eq!(*derived_gt_key_1, EXPECTED_GT_GEN_KAT_KEY);
        assert_eq!(*derived_gt_key_1, *derived_gt_key_2);
        let derived_gt_key_diff_aad =
            derive_aead_key_from_gt(&gt_gen, b"chinwag-acu-gt-kat-v2").unwrap();
        assert_ne!(*derived_gt_key_1, *derived_gt_key_diff_aad);
    }

    #[test]
    fn test_16_seat_id_and_metadata_validation_and_malformed_row_witness_rejection() {
        let mut rng = OsRng;
        assert_eq!(
            SeatSecretKey::generate("bad\nseat", &mut rng).unwrap_err(),
            AcuError::InvalidSeatId
        );
        assert_eq!(
            SeatSecretKey::generate("   ", &mut rng).unwrap_err(),
            AcuError::InvalidSeatId
        );
        assert_eq!(
            SeatSecretKey::generate("x".repeat(513), &mut rng).unwrap_err(),
            AcuError::InvalidSeatId
        );

        let (_agent_sk, agent_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent_ed25519_sk = SigningKey::from_bytes(&[0x31u8; 32]);
        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0x32u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        registry
            .register_seat(
                DEFAULT_AGENT_BRANCH_ID,
                agent_ed25519_sk.verifying_key(),
                agent_pk.clone(),
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            )
            .unwrap();

        assert_eq!(
            EncryptedCiPayload::encrypt_split_key_with_acu(
                b"payload",
                &agent_pk,
                &acu_pk,
                "bad\nrepo",
                "CHWG-0283",
                &mut rng,
            ),
            Err(AcuError::InvalidMetadata)
        );

        let payload = EncryptedCiPayload::encrypt_split_key_with_acu(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &agent_pk,
            &acu_pk,
            "emunlabs/chinwag",
            "CHWG-0283-WITNESS-GATE",
            &mut rng,
        )
        .unwrap();

        let mut bad_acu_row = payload.acu_ciphertext.rows[1].clone();
        assert!(verify_row_randomness_witness(&bad_acu_row, &acu_pk));
        bad_acu_row.c2 = G1Projective::identity();
        assert!(!verify_row_randomness_witness(&bad_acu_row, &acu_pk));

        let req = AcuShareRequest::create_signed(
            "req-bad-witness",
            DEFAULT_AGENT_BRANCH_ID,
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-0283-WITNESS-GATE",
            payload.acu_ciphertext.policy_epoch,
            payload.acu_ciphertext.clone(),
            bad_acu_row,
            1_793_800_999_000,
            &agent_ed25519_sk,
        );

        let mut ciso_fat_client = CisoAcuFatClient::new(acu_sk, acu_pk.clone(), acu_ed25519_sk);
        assert_eq!(
            ciso_fat_client.handle_iroh_share_request(&req, &registry),
            Err(AcuError::InvalidRowPok)
        );
        assert_eq!(ciso_fat_client.audit_log().len(), 1);
        assert_eq!(
            ciso_fat_client.audit_log()[0].decision,
            AcuAuditDecision::Denied
        );
        assert_eq!(
            ciso_fat_client.audit_log()[0].reason,
            "invalid_acu_row_witness"
        );

        let mut forged_ct = payload.acu_ciphertext.clone();
        let r_forged = Scalar::from(7u64);
        forged_ct.rows[1].c1 =
            G1Projective::generator() * Scalar::from(42u64) + acu_pk.pk1 * r_forged;
        forged_ct.rows[1].c2 = G1Projective::generator() * r_forged;
        forged_ct.rows[1].init_c1 = forged_ct.rows[1].c1;
        forged_ct.rows[1].init_c2 = forged_ct.rows[1].c2;

        let forged_req = AcuShareRequest::create_signed(
            "req-forged-row-pok",
            DEFAULT_AGENT_BRANCH_ID,
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-0283-WITNESS-GATE",
            forged_ct.policy_epoch,
            forged_ct.clone(),
            forged_ct.rows[1].clone(),
            1_793_801_000_000,
            &agent_ed25519_sk,
        );
        assert!(
            ciso_fat_client
                .handle_iroh_share_request(&forged_req, &registry)
                .is_err()
        );

        // Pure-G1 Chaum-Pedersen DLEQ tamper checks on `PartialDecryptionShare`:
        let valid_share = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            ciso_fat_client.acu_secret_key(),
            payload.acu_ciphertext.policy_epoch,
        );
        assert!(acu_verify_partial_share(
            &payload.acu_ciphertext.rows[1],
            &acu_pk,
            &valid_share
        ));

        let mut bad_c = valid_share.clone();
        if let DleqProof::Compact { challenge, .. } = &mut bad_c.proof {
            *challenge += Scalar::ONE;
        }
        assert!(!acu_verify_partial_share(
            &payload.acu_ciphertext.rows[1],
            &acu_pk,
            &bad_c
        ));

        let mut bad_z = valid_share.clone();
        if let DleqProof::Compact { response, .. } = &mut bad_z.proof {
            *response += Scalar::ONE;
        }
        assert!(!acu_verify_partial_share(
            &payload.acu_ciphertext.rows[1],
            &acu_pk,
            &bad_z
        ));

        let mut bad_val = valid_share;
        bad_val.share_g1 += G1Projective::generator();
        assert!(!acu_verify_partial_share(
            &payload.acu_ciphertext.rows[1],
            &acu_pk,
            &bad_val
        ));
    }

    #[test]
    fn test_17_alistair_p1_1_escalate_threshold_post_revocation_preserves_vandermonde_abscissas() {
        let mut rng = OsRng;
        let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let (sk_a, pk_a) = SeatSecretKey::generate("branch:a", &mut rng).unwrap();
        let (_sk_b, pk_b) = SeatSecretKey::generate("branch:b", &mut rng).unwrap();
        let (_sk_c, pk_c) = SeatSecretKey::generate("branch:c", &mut rng).unwrap();
        let (sk_d, pk_d) = SeatSecretKey::generate("branch:d", &mut rng).unwrap();
        let (sk_e, pk_e) = SeatSecretKey::generate("branch:e", &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        for pk in [&pk_acu, &pk_a, &pk_b, &pk_c, &pk_d, &pk_e] {
            seat_keys.insert(pk.seat_id.clone(), (*pk).clone());
        }

        let tree = AccessTree::Threshold {
            threshold: 2,
            children: vec![
                AccessTree::Leaf("branch:a".to_string()),
                AccessTree::Leaf("branch:b".to_string()),
                AccessTree::Leaf("branch:c".to_string()),
                AccessTree::Leaf("branch:d".to_string()),
                AccessTree::Leaf("branch:e".to_string()),
            ],
        };
        let mut payload = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &tree,
            &seat_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-0283-P1-1-POST-REVOKE-ESCALATE",
            &mut rng,
        )
        .unwrap();

        assert_eq!(
            escalate_threshold(
                &mut payload.acu_ciphertext,
                &sk_acu,
                &[0, 1, 2],
                1,
                &seat_keys,
                &mut rng,
            ),
            Err(AcuError::InvalidAccessTree(
                "gate_row_indices do not match any compiled gate subtree"
            ))
        );

        revoke_and_rerandomize(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &["branch:b", "branch:c"],
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        payload
            .prune_revoked_pq_capsules(&["branch:b", "branch:c"])
            .unwrap();
        seat_keys.remove("branch:b");
        seat_keys.remove("branch:c");
        assert_eq!(payload.acu_ciphertext.rows.len(), 3);

        assert!(
            escalate_threshold(
                &mut payload.acu_ciphertext,
                &sk_acu,
                &[0, 1],
                1,
                &seat_keys,
                &mut rng,
            )
            .is_err()
        );

        escalate_threshold(
            &mut payload.acu_ciphertext,
            &sk_acu,
            &[0, 1, 2],
            1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        assert_eq!(payload.acu_ciphertext.policy_epoch, 3);
        assert_eq!(
            payload.acu_ciphertext.rows[0].matrix_row[2],
            Scalar::from(1u64)
        );
        assert_eq!(
            payload.acu_ciphertext.rows[1].matrix_row[2],
            Scalar::from(16u64)
        );
        assert_eq!(
            payload.acu_ciphertext.rows[2].matrix_row[2],
            Scalar::from(25u64)
        );

        let d_a = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[0],
            &sk_a,
            payload.acu_ciphertext.policy_epoch,
        );
        let d_d = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            &sk_d,
            payload.acu_ciphertext.policy_epoch,
        );
        let d_e = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[2],
            &sk_e,
            payload.acu_ciphertext.policy_epoch,
        );
        let mut pq_ade = payload.decapsulate_pq_shares_for_seat(&sk_a).unwrap();
        pq_ade.extend(payload.decapsulate_pq_shares_for_seat(&sk_d).unwrap());
        pq_ade.extend(payload.decapsulate_pq_shares_for_seat(&sk_e).unwrap());

        assert_eq!(
            payload.decrypt(&[d_a.clone(), d_d.clone()], &pq_ade, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            payload.decrypt(&[d_a.clone(), d_e.clone()], &pq_ade, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            payload.decrypt(&[d_d.clone(), d_e.clone()], &pq_ade, &seat_keys),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            payload
                .decrypt(&[d_a, d_d, d_e], &pq_ade, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );

        let nested_tree = AccessTree::And(vec![
            AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
            AccessTree::Threshold {
                threshold: 2,
                children: vec![
                    AccessTree::Leaf("branch:a".to_string()),
                    AccessTree::Leaf("branch:d".to_string()),
                    AccessTree::Leaf("branch:e".to_string()),
                ],
            },
        ]);
        let mut nested = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &nested_tree,
            &seat_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-0283-P1-1-NESTED-GATE",
            &mut rng,
        )
        .unwrap();
        assert!(
            escalate_threshold(
                &mut nested.acu_ciphertext,
                &sk_acu,
                &[0, 1, 2],
                1,
                &seat_keys,
                &mut rng,
            )
            .is_err()
        );
        escalate_threshold(
            &mut nested.acu_ciphertext,
            &sk_acu,
            &[1, 2, 3],
            1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        let n_acu = acu_partial_decrypt_at_epoch(
            &nested.acu_ciphertext.rows[0],
            &sk_acu,
            nested.acu_ciphertext.policy_epoch,
        );
        let n_a = acu_partial_decrypt_at_epoch(
            &nested.acu_ciphertext.rows[1],
            &sk_a,
            nested.acu_ciphertext.policy_epoch,
        );
        let n_d = acu_partial_decrypt_at_epoch(
            &nested.acu_ciphertext.rows[2],
            &sk_d,
            nested.acu_ciphertext.policy_epoch,
        );
        let n_e = acu_partial_decrypt_at_epoch(
            &nested.acu_ciphertext.rows[3],
            &sk_e,
            nested.acu_ciphertext.policy_epoch,
        );
        let mut n_pq = nested.decapsulate_pq_shares_for_seat(&sk_a).unwrap();
        n_pq.extend(nested.decapsulate_pq_shares_for_seat(&sk_d).unwrap());
        n_pq.extend(nested.decapsulate_pq_shares_for_seat(&sk_e).unwrap());
        assert_eq!(
            nested.decrypt(
                &[n_acu.clone(), n_a.clone(), n_d.clone()],
                &n_pq,
                &seat_keys
            ),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            nested
                .decrypt(&[n_acu, n_a, n_d, n_e], &n_pq, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
    }

    #[test]
    fn test_18_alistair_p1_2_escalate_threshold_rotates_all_rows_blocking_cross_epoch_downgrade() {
        let mut rng = OsRng;
        let (sk_acu, pk_acu) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let (sk_a, pk_a) = SeatSecretKey::generate("branch:alpha", &mut rng).unwrap();
        let (sk_b, pk_b) = SeatSecretKey::generate("branch:beta", &mut rng).unwrap();
        let (_sk_c, pk_c) = SeatSecretKey::generate("branch:gamma", &mut rng).unwrap();

        let mut seat_keys = BTreeMap::new();
        for pk in [&pk_acu, &pk_a, &pk_b, &pk_c] {
            seat_keys.insert(pk.seat_id.clone(), (*pk).clone());
        }

        let tree = AccessTree::And(vec![
            AccessTree::Or(vec![
                AccessTree::Leaf("branch:alpha".to_string()),
                AccessTree::Leaf("branch:beta".to_string()),
                AccessTree::Leaf("branch:gamma".to_string()),
            ]),
            AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
        ]);
        let ep1_cached = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &tree,
            &seat_keys,
            &pk_acu,
            "emunlabs/chinwag",
            "CHWG-0283-P1-2-NO-DOWNGRADE",
            &mut rng,
        )
        .unwrap();
        let mut ep2_evolved = ep1_cached.clone();

        escalate_threshold(
            &mut ep2_evolved.acu_ciphertext,
            &sk_acu,
            &[0, 1, 2],
            1,
            &seat_keys,
            &mut rng,
        )
        .unwrap();
        assert_eq!(ep2_evolved.acu_ciphertext.policy_epoch, 2);
        assert_ne!(
            ep2_evolved.acu_ciphertext.rows[3].c1,
            ep1_cached.acu_ciphertext.rows[3].c1
        );

        let d_a_ep1 = acu_partial_decrypt_at_epoch(
            &ep1_cached.acu_ciphertext.rows[0],
            &sk_a,
            ep1_cached.acu_ciphertext.policy_epoch,
        );
        let pq_a_ep1 = ep1_cached.decapsulate_pq_shares_for_seat(&sk_a).unwrap();
        let mut d_acu_ep2_relabeled = acu_partial_decrypt_at_epoch(
            &ep2_evolved.acu_ciphertext.rows[3],
            &sk_acu,
            ep2_evolved.acu_ciphertext.policy_epoch,
        );
        d_acu_ep2_relabeled.policy_epoch = 1;

        assert_eq!(
            ep1_cached.decrypt(
                &[d_a_ep1.clone(), d_acu_ep2_relabeled.clone()],
                &pq_a_ep1,
                &seat_keys
            ),
            Err(AcuError::InvalidPartialShare {
                row_index: 3,
                seat_id: DEFAULT_CISO_ACU_ID.to_string(),
            })
        );
        assert_eq!(
            ep1_cached.decrypt_unverified(&[d_a_ep1, d_acu_ep2_relabeled], &pq_a_ep1),
            Err(AcuError::AeadFailure)
        );

        let d_a_ep2 = acu_partial_decrypt_at_epoch(
            &ep2_evolved.acu_ciphertext.rows[0],
            &sk_a,
            ep2_evolved.acu_ciphertext.policy_epoch,
        );
        let d_b_ep2 = acu_partial_decrypt_at_epoch(
            &ep2_evolved.acu_ciphertext.rows[1],
            &sk_b,
            ep2_evolved.acu_ciphertext.policy_epoch,
        );
        let d_acu_ep2 = acu_partial_decrypt_at_epoch(
            &ep2_evolved.acu_ciphertext.rows[3],
            &sk_acu,
            ep2_evolved.acu_ciphertext.policy_epoch,
        );
        let mut pq_ab = ep2_evolved.decapsulate_pq_shares_for_seat(&sk_a).unwrap();
        pq_ab.extend(ep2_evolved.decapsulate_pq_shares_for_seat(&sk_b).unwrap());
        assert_eq!(
            ep2_evolved
                .decrypt(&[d_a_ep2, d_b_ep2, d_acu_ep2], &pq_ab, &seat_keys)
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );
    }

    #[test]
    fn test_19_alistair_p1_3_archive_ticket_gate_revoked_proxy_block_and_audit_hash_verification() {
        let mut rng = OsRng;
        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0x41u8; 32]);

        let (_agent1_sk, agent1_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent1_ed25519_sk = SigningKey::from_bytes(&[0x42u8; 32]);

        let (sibling_sk, sibling_pk) = SeatSecretKey::generate("branch:sibling", &mut rng).unwrap();
        let sibling_ed25519_sk = SigningKey::from_bytes(&[0x43u8; 32]);

        let (_bystander_sk, bystander_pk) =
            SeatSecretKey::generate("branch:bystander", &mut rng).unwrap();
        let bystander_ed25519_sk = SigningKey::from_bytes(&[0x44u8; 32]);

        let (_archive_sk, archive_pk) =
            SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();
        let archive_ed25519_sk = SigningKey::from_bytes(&[0x45u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        for (id, vk, pk) in [
            (
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            ),
            (
                DEFAULT_AGENT_BRANCH_ID,
                agent1_ed25519_sk.verifying_key(),
                agent1_pk.clone(),
            ),
            (
                "branch:sibling",
                sibling_ed25519_sk.verifying_key(),
                sibling_pk.clone(),
            ),
            (
                "branch:bystander",
                bystander_ed25519_sk.verifying_key(),
                bystander_pk.clone(),
            ),
            (
                DEFAULT_MESSAGE_ARCHIVE_ID,
                archive_ed25519_sk.verifying_key(),
                archive_pk.clone(),
            ),
        ] {
            registry.register_seat(id, vk, pk).unwrap();
        }

        let tree = AccessTree::And(vec![
            AccessTree::Leaf(DEFAULT_CISO_ACU_ID.to_string()),
            AccessTree::Or(vec![
                AccessTree::Leaf(DEFAULT_AGENT_BRANCH_ID.to_string()),
                AccessTree::Leaf("branch:sibling".to_string()),
                AccessTree::Leaf(DEFAULT_MESSAGE_ARCHIVE_ID.to_string()),
            ]),
        ]);
        let seat_keys = registry.active_acu_keys();
        let mut payload = EncryptedCiPayload::encrypt(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &tree,
            &seat_keys,
            &acu_pk,
            "emunlabs/chinwag",
            "CHWG-0283-P1-3-PROXY-AND-ARCHIVE-GATE",
            &mut rng,
        )
        .unwrap();

        let mut ciso_fat_client = CisoAcuFatClient::new(acu_sk, acu_pk, acu_ed25519_sk);

        let archive_live_req = AcuShareRequest::create_signed(
            "req-archive-bypass",
            DEFAULT_MESSAGE_ARCHIVE_ID,
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-0283-P1-3-PROXY-AND-ARCHIVE-GATE",
            payload.acu_ciphertext.policy_epoch,
            payload.acu_ciphertext.clone(),
            payload.acu_ciphertext.rows[0].clone(),
            1_793_802_001_000,
            &archive_ed25519_sk,
        );
        assert_eq!(
            ciso_fat_client.handle_iroh_share_request(&archive_live_req, &registry),
            Err(AcuError::InvalidMetadata)
        );
        assert_eq!(
            ciso_fat_client.audit_log()[0].reason,
            "archive_seat_requires_investigation_ticket"
        );

        let bystander_req = AcuShareRequest::create_signed(
            "req-bystander-proxy",
            "branch:bystander",
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-0283-P1-3-PROXY-AND-ARCHIVE-GATE",
            payload.acu_ciphertext.policy_epoch,
            payload.acu_ciphertext.clone(),
            payload.acu_ciphertext.rows[0].clone(),
            1_793_802_002_000,
            &bystander_ed25519_sk,
        );
        assert_eq!(
            ciso_fat_client.handle_iroh_share_request(&bystander_req, &registry),
            Err(AcuError::PolicyNotSatisfied)
        );
        assert_eq!(
            ciso_fat_client.audit_log()[1].reason,
            "requester_not_in_ciphertext_policy"
        );

        ciso_fat_client.instant_revoke(DEFAULT_AGENT_BRANCH_ID);
        let sibling_ep1_req = AcuShareRequest::create_signed(
            "req-sibling-unpruned-ep1",
            "branch:sibling",
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-0283-P1-3-PROXY-AND-ARCHIVE-GATE",
            payload.acu_ciphertext.policy_epoch,
            payload.acu_ciphertext.clone(),
            payload.acu_ciphertext.rows[0].clone(),
            1_793_802_003_000,
            &sibling_ed25519_sk,
        );
        assert_eq!(
            ciso_fat_client.handle_iroh_share_request(&sibling_ep1_req, &registry),
            Err(AcuError::SeatRevoked(DEFAULT_AGENT_BRANCH_ID.to_string()))
        );
        assert_eq!(
            ciso_fat_client.audit_log()[2].reason,
            "ciphertext_contains_unpruned_revoked_seat"
        );

        registry.revoke_seat(DEFAULT_AGENT_BRANCH_ID).unwrap();
        let active_keys_ep2 = registry.active_acu_keys();
        ciso_fat_client
            .revoke_and_rerandomize(
                &mut payload.acu_ciphertext,
                &[DEFAULT_AGENT_BRANCH_ID],
                &active_keys_ep2,
                &mut rng,
            )
            .unwrap();
        payload
            .prune_revoked_pq_capsules(&[DEFAULT_AGENT_BRANCH_ID])
            .unwrap();
        let sibling_ep2_req = AcuShareRequest::create_signed(
            "req-sibling-pruned-ep2",
            "branch:sibling",
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-0283-P1-3-PROXY-AND-ARCHIVE-GATE",
            payload.acu_ciphertext.policy_epoch,
            payload.acu_ciphertext.clone(),
            payload.acu_ciphertext.rows[0].clone(),
            1_793_802_004_000,
            &sibling_ed25519_sk,
        );
        let mut sibling_resp = ciso_fat_client
            .handle_iroh_share_request(&sibling_ep2_req, &registry)
            .unwrap();
        sibling_resp
            .verify_by_agent(&payload.acu_ciphertext.rows[0], &registry)
            .unwrap();

        let d_sibling = acu_partial_decrypt_at_epoch(
            &payload.acu_ciphertext.rows[1],
            &sibling_sk,
            payload.acu_ciphertext.policy_epoch,
        );
        assert_eq!(
            payload
                .decrypt_with_local_key(
                    &[sibling_resp.partial_share.clone(), d_sibling],
                    &sibling_sk,
                    &active_keys_ep2
                )
                .unwrap(),
            SAMPLE_CI_ROOT_CAUSE_JSON
        );

        sibling_resp.audit_entry.reason = "forged_reason".to_string();
        assert_eq!(
            sibling_resp.verify_by_agent(&payload.acu_ciphertext.rows[0], &registry),
            Err(AcuError::SignatureVerificationFailed("audit_entry"))
        );
    }

    #[test]
    fn test_20_alistair_p1_r2_2_cut_and_paste_row_into_synthetic_policy_and_archive_metadata_laundering_rejected()
     {
        let mut rng = OsRng;
        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0x51u8; 32]);

        let (_agent_sk, agent_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent_ed25519_sk = SigningKey::from_bytes(&[0x52u8; 32]);

        let (_bystander_sk, bystander_pk) =
            SeatSecretKey::generate("branch:bystander", &mut rng).unwrap();
        let bystander_ed25519_sk = SigningKey::from_bytes(&[0x53u8; 32]);

        let (_archive_sk, archive_pk) =
            SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();
        let archive_ed25519_sk = SigningKey::from_bytes(&[0x54u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        for (id, vk, pk) in [
            (
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            ),
            (
                DEFAULT_AGENT_BRANCH_ID,
                agent_ed25519_sk.verifying_key(),
                agent_pk.clone(),
            ),
            (
                "branch:bystander",
                bystander_ed25519_sk.verifying_key(),
                bystander_pk.clone(),
            ),
            (
                DEFAULT_MESSAGE_ARCHIVE_ID,
                archive_ed25519_sk.verifying_key(),
                archive_pk.clone(),
            ),
        ] {
            registry.register_seat(id, vk, pk).unwrap();
        }

        let victim = EncryptedCiPayload::encrypt_with_acu_and_archive(
            SAMPLE_CI_ROOT_CAUSE_JSON,
            &acu_pk,
            &agent_pk,
            &archive_pk,
            "emunlabs/chinwag",
            "CHWG-0283-CUT-AND-PASTE-VICTIM",
            &mut rng,
        )
        .unwrap();

        let mut ciso_fat_client =
            CisoAcuFatClient::new(acu_sk, acu_pk.clone(), acu_ed25519_sk.clone());
        ciso_fat_client.instant_revoke(DEFAULT_AGENT_BRANCH_ID);

        // 1. Cut-and-paste oracle attempt: `bystander` encrypts a fresh 2-row `CHWGACU3` ciphertext
        // under `acu AND bystander` (with the exact same `object_digest`) and splices `victim_acu_row`
        // into row 0! Because `RowPok` binds `init_matrix_digest`, `verify_authenticity` rejects!
        let synth_tree =
            EncryptedCiPayload::build_split_key_acu_policy("branch:bystander", DEFAULT_CISO_ACU_ID);
        let synth_matrix = LsssMatrix::from_tree(&synth_tree).unwrap();
        let active_keys = registry.active_acu_keys();
        let payload_g1 = G1Projective::generator() * Scalar::from(77u64);
        let (mut synthetic_ct, _) = acu_encrypt_with_g1_and_context(
            &payload_g1,
            &victim.acu_ciphertext.object_digest,
            &[0x33u8; 32],
            &synth_matrix,
            &active_keys,
            &acu_pk,
            &mut rng,
        )
        .unwrap();

        let mut spliced_victim_acu_row = victim.acu_ciphertext.rows[0].clone();
        spliced_victim_acu_row.row_index = 1;
        spliced_victim_acu_row.matrix_row = synthetic_ct.rows[1].matrix_row.clone();
        synthetic_ct.rows[1] = spliced_victim_acu_row.clone();

        let cut_and_paste_req = AcuShareRequest::create_signed(
            "req-cut-and-paste-oracle",
            "branch:bystander",
            DEFAULT_CISO_ACU_ID,
            "emunlabs/chinwag",
            "CHWG-0283-CUT-AND-PASTE-VICTIM",
            1,
            synthetic_ct,
            spliced_victim_acu_row,
            1_793_803_001_000,
            &bystander_ed25519_sk,
        );
        assert_eq!(
            ciso_fat_client.handle_iroh_share_request(&cut_and_paste_req, &registry),
            Err(AcuError::InvalidRowPok)
        );
        assert_eq!(
            ciso_fat_client.audit_log()[0].reason,
            "invalid_acu_row_witness"
        );

        // 2. Archive metadata-laundering defense & immutable `sender_seat`:
        let partition = HivePartitionKey::new("emunlabs", 2026, 11, 12).unwrap();
        let mut store = AcuParquetArchiveStore::new();
        let mut archived_row = store
            .append_signed_message(
                partition,
                "msg-meta-launder-20",
                1_793_803_010_000,
                DEFAULT_AGENT_BRANCH_ID,
                DEFAULT_AGENT_BRANCH_ID,
                "#eng",
                "CHWG-0283-ARCHIVE-META",
                SAMPLE_CI_ROOT_CAUSE_JSON,
                &agent_ed25519_sk,
                &registry,
                &mut rng,
            )
            .unwrap();

        archived_row.room = "#forged-room".to_string();
        assert_eq!(
            archived_row.revoke_and_rerandomize_in_place(
                ciso_fat_client.acu_secret_key(),
                &[DEFAULT_AGENT_BRANCH_ID],
                &registry,
                DEFAULT_CISO_ACU_ID,
                &acu_ed25519_sk,
                &mut rng,
            ),
            Err(AcuError::SignatureVerificationFailed("archive_row"))
        );

        archived_row.room = "#eng".to_string();
        archived_row
            .revoke_and_rerandomize_in_place(
                ciso_fat_client.acu_secret_key(),
                &[DEFAULT_AGENT_BRANCH_ID],
                &registry,
                DEFAULT_CISO_ACU_ID,
                &acu_ed25519_sk,
                &mut rng,
            )
            .unwrap();
        assert_eq!(archived_row.sender_seat, DEFAULT_AGENT_BRANCH_ID);
        assert_eq!(
            archived_row.rerandomized_by_seat.as_deref(),
            Some(DEFAULT_CISO_ACU_ID)
        );
        assert_eq!(archived_row.policy_epoch, 2);
        archived_row.verify_row_signature(&registry).unwrap();
    }

    #[test]
    fn test_21_chwg_0271_archive_sender_non_repudiation_and_impersonation_rejection() {
        use ed25519_dalek::Signer;

        let mut rng = OsRng;
        let (acu_sk, acu_pk) = SeatSecretKey::generate(DEFAULT_CISO_ACU_ID, &mut rng).unwrap();
        let acu_ed25519_sk = SigningKey::from_bytes(&[0xA1u8; 32]);

        let (_agent_sk, agent_pk) =
            SeatSecretKey::generate(DEFAULT_AGENT_BRANCH_ID, &mut rng).unwrap();
        let agent_ed25519_sk = SigningKey::from_bytes(&[0xA2u8; 32]);

        let (_bystander_sk, bystander_pk) =
            SeatSecretKey::generate("branch:bystander", &mut rng).unwrap();
        let bystander_ed25519_sk = SigningKey::from_bytes(&[0xA3u8; 32]);

        let (archive_sk, archive_pk) =
            SeatSecretKey::generate(DEFAULT_MESSAGE_ARCHIVE_ID, &mut rng).unwrap();
        let archive_ed25519_sk = SigningKey::from_bytes(&[0xA4u8; 32]);

        let mut registry = AllowedSignersRegistry::new();
        registry
            .register_seat(
                DEFAULT_CISO_ACU_ID,
                acu_ed25519_sk.verifying_key(),
                acu_pk.clone(),
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_AGENT_BRANCH_ID,
                agent_ed25519_sk.verifying_key(),
                agent_pk,
            )
            .unwrap();
        registry
            .register_seat(
                "branch:bystander",
                bystander_ed25519_sk.verifying_key(),
                bystander_pk.clone(),
            )
            .unwrap();
        registry
            .register_seat(
                DEFAULT_MESSAGE_ARCHIVE_ID,
                archive_ed25519_sk.verifying_key(),
                archive_pk.clone(),
            )
            .unwrap();

        let partition = HivePartitionKey::new("emunlabs", 2026, 11, 12).unwrap();
        let mut store = AcuParquetArchiveStore::new();
        let _ = store.load_channel_window("emunlabs", "#eng", None, 10);
        let _authentic = store
            .append_signed_message(
                partition,
                "msg-impersonation-target-21",
                1_793_804_001_000,
                DEFAULT_AGENT_BRANCH_ID,
                "branch:bystander",
                "#eng",
                "CHWG-0271-IMPERSONATION",
                b"authentic message from branch:8687872",
                &agent_ed25519_sk,
                &registry,
                &mut rng,
            )
            .unwrap();
        let (cache_hit_after_append, cached_rows) =
            store.load_channel_window("emunlabs", "#eng", None, 10);
        assert_eq!(cache_hit_after_append, CacheHit::R2ParquetRangeFetch);
        assert_eq!(cached_rows.len(), 1);

        registry.revoke_seat(DEFAULT_AGENT_BRANCH_ID).unwrap();
        let mut ciso_fat_client =
            CisoAcuFatClient::new(acu_sk, acu_pk.clone(), acu_ed25519_sk.clone());
        ciso_fat_client.instant_revoke(DEFAULT_AGENT_BRANCH_ID);

        let forged_payload = EncryptedCiPayload::encrypt_with_acu_and_archive(
            b"forged payload impersonating branch:bystander",
            &acu_pk,
            &bystander_pk,
            &archive_pk,
            "emunlabs",
            "CHWG-0271-IMPERSONATION",
            &mut rng,
        )
        .unwrap();
        let forged_ct_bytes = forged_payload.to_bytes();
        let fake_sender_sig = agent_ed25519_sk
            .sign(&archive::ArchivedMessageRow::sender_body_signing_preimage(
                "msg-impersonation-target-21",
                1_793_804_001_000,
                "branch:bystander",
                "branch:bystander",
                "#eng",
                "CHWG-0271-IMPERSONATION",
                &forged_payload.nonce,
                &forged_payload.associated_data,
                &forged_payload.aead_ciphertext,
            ))
            .to_bytes()
            .to_vec();

        store.update_row_by_id("msg-impersonation-target-21", |r| {
            r.sender_seat = "branch:bystander".to_string();
            r.recipient_seat = "branch:bystander".to_string();
            r.policy_epoch = 2;
            r.rerandomized_by_seat = Some(DEFAULT_AGENT_BRANCH_ID.to_string());
            r.sender_ed25519_sig.clone_from(&fake_sender_sig);
            r.acu_ciphertext.clone_from(&forged_ct_bytes);
            let preimage = archive::ArchivedMessageRow::signing_preimage(
                &r.message_id,
                r.timestamp_utc,
                &r.sender_seat,
                &r.recipient_seat,
                &r.room,
                &r.task_id,
                r.policy_epoch,
                r.rerandomized_by_seat.as_deref(),
                &r.sender_ed25519_sig,
                &r.acu_ciphertext,
            );
            r.ed25519_sig = agent_ed25519_sk.sign(&preimage).to_bytes().to_vec();
        });
        let filter = ArchiveSearchFilter::new("emunlabs");
        assert_eq!(
            store.ciso_investigate_and_decrypt(
                &filter,
                "INCIDENT-IMPERSONATION-A",
                &mut ciso_fat_client,
                &archive_ed25519_sk,
                &archive_sk,
                &registry,
            ),
            Err(AcuError::SignatureVerificationFailed(
                "unauthorized_re_signer"
            ))
        );

        let mut epoch2_payload = forged_payload;
        revoke_and_rerandomize(
            &mut epoch2_payload.acu_ciphertext,
            ciso_fat_client.acu_secret_key(),
            &[],
            &registry.active_acu_keys(),
            &mut rng,
        )
        .unwrap();
        let epoch2_ct_bytes = epoch2_payload.to_bytes();
        store.update_row_by_id("msg-impersonation-target-21", |r| {
            r.sender_seat = "branch:bystander".to_string();
            r.recipient_seat = "branch:bystander".to_string();
            r.policy_epoch = 2;
            r.rerandomized_by_seat = Some(DEFAULT_CISO_ACU_ID.to_string());
            r.sender_ed25519_sig.clone_from(&fake_sender_sig);
            r.acu_ciphertext = epoch2_ct_bytes;
            let preimage = archive::ArchivedMessageRow::signing_preimage(
                &r.message_id,
                r.timestamp_utc,
                &r.sender_seat,
                &r.recipient_seat,
                &r.room,
                &r.task_id,
                r.policy_epoch,
                r.rerandomized_by_seat.as_deref(),
                &r.sender_ed25519_sig,
                &r.acu_ciphertext,
            );
            r.ed25519_sig = acu_ed25519_sk.sign(&preimage).to_bytes().to_vec();
        });
        assert_eq!(
            store.ciso_investigate_and_decrypt(
                &filter,
                "INCIDENT-IMPERSONATION-B",
                &mut ciso_fat_client,
                &archive_ed25519_sk,
                &archive_sk,
                &registry,
            ),
            Err(AcuError::SignatureVerificationFailed("archive_sender_body"))
        );
    }
}
