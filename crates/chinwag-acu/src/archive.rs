// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Cloudflare R2 / S3 Parquet + DuckDB (`httpfs`) Encrypted Message Archive, Blind Hash-Chained
//! [`AcuEnvelopeHeaderV2`] (`F-01`, `F-02`, `F-03` & `ePrint v2` §§6–7), Join-Resistant
//! `ArchiveRowSign` + Inner `SeatAuthorSign` (`SealedAuthorMessage`), `HMAC-SHA256` Blind Index Tags,
//! 4-Leaf Salted Merkle `--public-safe` Selective Openings (`PublicSafeExportBundle`), Hybrid
//! Active-Channel RAM Cache (`active_channel_cache`), and Off-UI-Thread CISO Forensic Decryption.

use crate::AcuError;
use crate::acu::{acu_partial_decrypt_at_epoch, revoke_and_rerandomize};
use crate::aead::{DEFAULT_MESSAGE_ARCHIVE_ID, EncryptedCiPayload, is_valid_metadata_token};
use crate::framing::{lp64_bytes, lp64_str, read_lp64_bytes, read_lp64_str};
use crate::keys::{SeatSecretKey, is_valid_seat_id};
use crate::protocol::{
    AcuPolicySignature, AcuShareRequest, AllowedSignersRegistry, CisoAcuFatClient,
    DEFAULT_CISO_ACU_ID,
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const ARCHIVE_ROW_SIG_DOMAIN: &[u8] = b"chinwag-parquet-archive-row/v5";
const ARCHIVE_SENDER_BODY_SIG_DOMAIN: &[u8] = b"chinwag-parquet-archive-sender-body/v2";
const ENVELOPE_V2_SIG_DOMAIN: &[u8] = b"chinwag.acu.v2.archive-row-sign";
const ENVELOPE_V2_CHAIN_DOMAIN: &[u8] = b"chinwag.acu.v2.envelope-chain-link";
const ENVELOPE_V2_META_KDF_INFO: &[u8] = b"chinwag.acu.v2.meta-box-key";
const ENVELOPE_V2_META_AAD_DOMAIN: &[u8] = b"chinwag.acu.v2.meta-box-aad";
const SEAT_AUTHOR_SIGN_DOMAIN: &[u8] = b"chinwag.acu.v2.seat-author-sign";
const SEAT_AUTHOR_MAGIC: &[u8; 8] = b"CHWGAUT2";
const MERKLE_LEAF_DOMAIN: &[u8] = b"chinwag.acu.v2.merkle-leaf";
const MERKLE_NODE_DOMAIN: &[u8] = b"chinwag.acu.v2.merkle-node";
const MERKLE_ROOT_DOMAIN: &[u8] = b"chinwag.acu.v2.merkle-root";
const BLIND_TAG_SENDER_DOMAIN: &[u8] = b"chinwag.acu.v2.blind-tag.sender";
const BLIND_TAG_RECIPIENT_DOMAIN: &[u8] = b"chinwag.acu.v2.blind-tag.recipient";
const BLIND_TAG_ROOM_DOMAIN: &[u8] = b"chinwag.acu.v2.blind-tag.room";
const BLIND_TAG_TASK_DOMAIN: &[u8] = b"chinwag.acu.v2.blind-tag.task";

/// Canonical `version` byte for [`AcuEnvelopeHeaderV2`].
pub const ACU_ENVELOPE_HEADER_V2_VERSION: u8 = 2;

/// Default DuckDB background worker thread cap on the CISO/developer fat client so local
/// web workbench (`127.0.0.1:5487`) UI rendering threads are never starved.
pub const DEFAULT_DUCKDB_THREADS: u8 = 2;

/// Default DuckDB RAM cap on the CISO/developer fat client.
pub const DEFAULT_DUCKDB_MEMORY_LIMIT: &str = "1GB";

/// Default number of recent messages cached per active room in RAM (`active_channel_cache`).
pub const DEFAULT_ACTIVE_CHANNEL_PAGE_SIZE: usize = 50;

// ============================================================================
// Slice F: Inner `SeatAuthorSign` (`SealedAuthorMessage`), `BlindIndexTags`,
//          `AcuEnvelopeHeaderV2`, & 4-Leaf Salted Merkle `--public-safe` Export
// ============================================================================

/// Inner `SeatAuthorSign` payload sealed **inside** the immutable `CHWGAEA2` `C_1` ciphertext
/// (`ePrint v2` §7.1): keeps `author_seat_id` and its Ed25519 signature strictly invisible to
/// Blind Relay and Parquet `.keys` SQL-JOIN observers while preserving cryptographic non-repudiation
/// upon authorized decryption!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedAuthorMessage {
    /// Author seat ID (e.g., `"branch:8687872"`).
    pub author_seat_id: String,
    /// Flow or message identifier bound into the inner signature.
    pub message_id: String,
    /// UTC timestamp in milliseconds since Unix epoch.
    pub timestamp_utc: u64,
    /// Inner application plaintext bytes.
    pub body: Vec<u8>,
    /// Detached Ed25519 `SeatAuthorSign` signature (`64` B).
    #[serde(with = "crate::framing::serde_bytes64")]
    pub author_signature: [u8; 64],
}

impl SealedAuthorMessage {
    /// Sign `(author_seat_id, message_id, timestamp_utc, body)` under `author_ed25519_sk` and
    /// serialize into canonical `CHWGAUT2` inner bytes ready to encrypt inside `C_1`.
    #[must_use]
    pub fn seal_and_sign(
        author_seat_id: impl Into<String>,
        message_id: impl Into<String>,
        timestamp_utc: u64,
        body: Vec<u8>,
        author_ed25519_sk: &SigningKey,
    ) -> Self {
        let author_seat_id = author_seat_id.into();
        let message_id = message_id.into();
        let preimage = Self::signing_preimage(&author_seat_id, &message_id, timestamp_utc, &body);
        let sig: Signature = author_ed25519_sk.sign(&preimage);
        Self {
            author_seat_id,
            message_id,
            timestamp_utc,
            body,
            author_signature: sig.to_bytes(),
        }
    }

    /// Encode this [`SealedAuthorMessage`] to deterministic `CHWGAUT2` bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.body.len());
        out.extend_from_slice(SEAT_AUTHOR_MAGIC);
        lp64_str(&mut out, &self.author_seat_id);
        lp64_str(&mut out, &self.message_id);
        out.extend_from_slice(&self.timestamp_utc.to_be_bytes());
        lp64_bytes(&mut out, &self.body);
        out.extend_from_slice(&self.author_signature);
        out
    }

    /// Parse and cryptographically verify an inner `CHWGAUT2` [`SealedAuthorMessage`] against
    /// `.chinwag/allowed_signers` (`get_any` supports historical forensic verification after revocation).
    pub fn from_bytes_and_verify(
        bytes: &[u8],
        registry: &AllowedSignersRegistry,
    ) -> Result<Self, AcuError> {
        if bytes.len() < 8 + 8 + 8 + 8 + 8 + 64 || &bytes[..8] != SEAT_AUTHOR_MAGIC {
            return Err(AcuError::SerializationError(
                "invalid CHWGAUT2 SealedAuthorMessage header",
            ));
        }
        let mut offset = 8usize;
        let author_seat_id = read_lp64_str(bytes, &mut offset, 256)?.to_string();
        let message_id = read_lp64_str(bytes, &mut offset, 256)?.to_string();
        if offset + 8 > bytes.len() {
            return Err(AcuError::SerializationError(
                "truncated SealedAuthorMessage timestamp",
            ));
        }
        let mut ts_arr = [0u8; 8];
        ts_arr.copy_from_slice(&bytes[offset..offset + 8]);
        offset += 8;
        let timestamp_utc = u64::from_be_bytes(ts_arr);
        let body = read_lp64_bytes(bytes, &mut offset, 64 * 1024 * 1024)?.to_vec();
        if offset + 64 != bytes.len() {
            return Err(AcuError::SerializationError(
                "trailing or truncated SealedAuthorMessage signature",
            ));
        }
        let mut author_signature = [0u8; 64];
        author_signature.copy_from_slice(&bytes[offset..offset + 64]);

        if !is_valid_seat_id(&author_seat_id) || !is_valid_metadata_token(&message_id) {
            return Err(AcuError::InvalidMetadata);
        }
        let rec = registry.get_any(&author_seat_id)?;
        let preimage = Self::signing_preimage(&author_seat_id, &message_id, timestamp_utc, &body);
        let sig = Signature::from_bytes(&author_signature);
        rec.ed25519_verifying_key
            .verify_strict(&preimage, &sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("seat_author_sign"))?;

        Ok(Self {
            author_seat_id,
            message_id,
            timestamp_utc,
            body,
            author_signature,
        })
    }

    fn signing_preimage(
        author_seat_id: &str,
        message_id: &str,
        timestamp_utc: u64,
        body: &[u8],
    ) -> Vec<u8> {
        let body_hash = Sha256::digest(body);
        let mut out = Vec::with_capacity(SEAT_AUTHOR_SIGN_DOMAIN.len() + 96);
        out.extend_from_slice(SEAT_AUTHOR_SIGN_DOMAIN);
        lp64_str(&mut out, author_seat_id);
        lp64_str(&mut out, message_id);
        out.extend_from_slice(&timestamp_utc.to_be_bytes());
        out.extend_from_slice(&body_hash);
        out
    }
}

/// Keyed `HMAC-SHA256` blind Parquet index tags (`ePrint v2` §7.2): enables sub-second DuckDB
/// equality predicate pushdown for holders of `index_key` while preventing `.keys` SQL-JOIN
/// de-anonymization against storage-only adversaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindIndexTags {
    /// `HMAC-SHA256(k_index, "sender" || LP(org_id) || LP(sender_seat))`.
    pub sender_tag: [u8; 32],
    /// `HMAC-SHA256(k_index, "recipient" || LP(org_id) || LP(recipient_seat))`.
    pub recipient_tag: [u8; 32],
    /// `HMAC-SHA256(k_index, "room" || LP(org_id) || LP(room))`.
    pub room_tag: [u8; 32],
    /// `HMAC-SHA256(k_index, "task" || LP(org_id) || LP(task_id))`.
    pub task_tag: [u8; 32],
}

impl BlindIndexTags {
    /// Compute keyed `HMAC-SHA256` blind index tags for `(org_id, sender_seat, recipient_seat, room, task_id)`.
    #[must_use]
    pub fn compute(
        index_key: &[u8; 32],
        org_id: &str,
        sender_seat: &str,
        recipient_seat: &str,
        room: &str,
        task_id: &str,
    ) -> Self {
        Self {
            sender_tag: compute_blind_hmac_tag(
                index_key,
                BLIND_TAG_SENDER_DOMAIN,
                org_id,
                sender_seat,
            ),
            recipient_tag: compute_blind_hmac_tag(
                index_key,
                BLIND_TAG_RECIPIENT_DOMAIN,
                org_id,
                recipient_seat,
            ),
            room_tag: compute_blind_hmac_tag(index_key, BLIND_TAG_ROOM_DOMAIN, org_id, room),
            task_tag: compute_blind_hmac_tag(index_key, BLIND_TAG_TASK_DOMAIN, org_id, task_id),
        }
    }

    /// Constant-time match check against an expected sender tag.
    #[must_use]
    pub fn matches_sender(&self, index_key: &[u8; 32], org_id: &str, sender_seat: &str) -> bool {
        let expected =
            compute_blind_hmac_tag(index_key, BLIND_TAG_SENDER_DOMAIN, org_id, sender_seat);
        bool::from(self.sender_tag.ct_eq(&expected))
    }
}

fn compute_blind_hmac_tag(
    index_key: &[u8; 32],
    domain: &[u8],
    org_id: &str,
    token: &str,
) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(index_key)
        .expect("HMAC-SHA256 accepts 32-byte index key");
    let mut buf = Vec::with_capacity(domain.len() + org_id.len() + token.len() + 16);
    buf.extend_from_slice(domain);
    lp64_str(&mut buf, org_id);
    lp64_str(&mut buf, token);
    mac.update(&buf);
    mac.finalize().into_bytes().into()
}

/// Encrypted metadata payload sealed inside [`AcuEnvelopeHeaderV2::encrypted_meta_box`] under `k_route`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeMetadataBox {
    /// Flow run identifier (e.g., `"flow-run-9912"`).
    pub flow_run_id: String,
    /// DAG node identifier (e.g., `"node_fix_ci"`).
    pub node_id: String,
    /// Author/sender seat identifier (invisible to Blind Relay).
    pub sender_seat: String,
    /// Visibility tier (e.g., `"org_internal"` or `"ciso_restricted"`).
    pub visibility: String,
}

/// Four-leaf input tuple for [`AcuEnvelopeHeaderV2::public_export_merkle_root`] (`UI v5` `F-02`):
/// Leaves `0` and `1` hold the `--public-safe` summary and gate metrics; Leaves `2` and `3` hold
/// private DAG topology and vault/audit metadata salted with 256-bit CSPRNG randomness so
/// `--public-safe` openings leak `0` bits about private leaves!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicExportLeaves {
    /// 256-bit random salt for Leaf 0 (`public_summary`).
    pub salt_0: [u8; 32],
    /// Leaf 0: `--public-safe` run summary bytes (e.g., title, status, net hours saved).
    pub public_summary: Vec<u8>,
    /// 256-bit random salt for Leaf 1 (`public_gate_metrics`).
    pub salt_1: [u8; 32],
    /// Leaf 1: `--public-safe` gate counts & DORA speed metrics.
    pub public_gate_metrics: Vec<u8>,
    /// 256-bit random salt for Leaf 2 (`private_topology`).
    pub salt_2: [u8; 32],
    /// Leaf 2: private DAG fan-out/retry topology (redacted in `--public-safe` exports).
    pub private_topology: Vec<u8>,
    /// 256-bit random salt for Leaf 3 (`private_audit_context`).
    pub salt_3: [u8; 32],
    /// Leaf 3: private seat/worktree audit context (redacted in `--public-safe` exports).
    pub private_audit_context: Vec<u8>,
}

impl PublicExportLeaves {
    /// Sample fresh 256-bit CSPRNG salts for all 4 Merkle leaves.
    pub fn new_salted(
        public_summary: Vec<u8>,
        public_gate_metrics: Vec<u8>,
        private_topology: Vec<u8>,
        private_audit_context: Vec<u8>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        let mut salt_0 = [0u8; 32];
        let mut salt_1 = [0u8; 32];
        let mut salt_2 = [0u8; 32];
        let mut salt_3 = [0u8; 32];
        rng.fill_bytes(&mut salt_0);
        rng.fill_bytes(&mut salt_1);
        rng.fill_bytes(&mut salt_2);
        rng.fill_bytes(&mut salt_3);
        Self {
            salt_0,
            public_summary,
            salt_1,
            public_gate_metrics,
            salt_2,
            private_topology,
            salt_3,
            private_audit_context,
        }
    }

    /// Compute `(merkle_root, sibling_h23)` over the 4 salted leaves.
    #[must_use]
    pub fn compute_root_and_private_subtree(&self) -> ([u8; 32], [u8; 32]) {
        let h0 = merkle_leaf_blake3(0, &self.salt_0, &self.public_summary);
        let h1 = merkle_leaf_blake3(1, &self.salt_1, &self.public_gate_metrics);
        let h2 = merkle_leaf_blake3(2, &self.salt_2, &self.private_topology);
        let h3 = merkle_leaf_blake3(3, &self.salt_3, &self.private_audit_context);
        let h01 = merkle_node_blake3(&h0, &h1);
        let h23 = merkle_node_blake3(&h2, &h3);
        let root = merkle_root_blake3(&h01, &h23);
        (root, h23)
    }
}

fn merkle_leaf_blake3(leaf_index: u8, salt: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MERKLE_LEAF_DOMAIN);
    h.update(&[leaf_index]);
    h.update(salt);
    h.update(&(data.len() as u64).to_be_bytes());
    h.update(data);
    *h.finalize().as_bytes()
}

fn merkle_node_blake3(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MERKLE_NODE_DOMAIN);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

fn merkle_root_blake3(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MERKLE_ROOT_DOMAIN);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Selective `--public-safe` Merkle export bundle (`chinwag flow export --public-safe` / `.cwcard`
/// Slack unfurl): reveals ONLY Leaves `0` and `1` plus the blinded 32-byte `private_subtree_h23`
/// sibling hash, verifiable against `header`'s `archive_row_sig` with `0` secret keys!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSafeExportBundle {
    /// Envelope sequence number.
    pub seq: u64,
    /// Previous blind chain link digest.
    pub prev_header_blake3: [u8; 32],
    /// Immutable payload `C_1` BLAKE3 digest.
    pub aead_immutable_blake3: [u8; 32],
    /// Keyed 16-byte run locator.
    pub run_locator: [u8; 16],
    /// Committed 4-leaf Merkle root signed by `archive_row_sig`.
    pub public_export_merkle_root: [u8; 32],
    /// Encrypted metadata nonce (committed in `archive_row_sig` preimage).
    pub meta_nonce: [u8; 12],
    /// Encrypted metadata ciphertext digest `BLAKE3(encrypted_meta_box)` so the raw box need not even be shipped if desired,
    /// or full `encrypted_meta_box` for exact `ArchiveRowSign` verification.
    pub encrypted_meta_box: Vec<u8>,
    /// Outer repo-scoped `ArchiveRowSign` Ed25519 signature (`64` B).
    #[serde(with = "crate::framing::serde_bytes64")]
    pub archive_row_sig: [u8; 64],
    /// Salt for Leaf 0.
    pub salt_0: [u8; 32],
    /// Revealed Leaf 0 (`public_summary`).
    pub public_summary: Vec<u8>,
    /// Salt for Leaf 1.
    pub salt_1: [u8; 32],
    /// Revealed Leaf 1 (`public_gate_metrics`).
    pub public_gate_metrics: Vec<u8>,
    /// Blinded 32-byte sibling subtree hash `H(Leaf_2 || Leaf_3)` (`0` private bytes revealed!).
    pub private_subtree_h23: [u8; 32],
}

impl PublicSafeExportBundle {
    /// Cryptographically verify both the outer `ArchiveRowSign` Ed25519 signature AND the 4-leaf
    /// Merkle opening for `(public_summary, public_gate_metrics)` in constant time.
    pub fn verify(&self, archive_verifying_key: &VerifyingKey) -> Result<(), AcuError> {
        let h0 = merkle_leaf_blake3(0, &self.salt_0, &self.public_summary);
        let h1 = merkle_leaf_blake3(1, &self.salt_1, &self.public_gate_metrics);
        let h01 = merkle_node_blake3(&h0, &h1);
        let computed_root = merkle_root_blake3(&h01, &self.private_subtree_h23);
        if !bool::from(computed_root.ct_eq(&self.public_export_merkle_root)) {
            return Err(AcuError::SignatureVerificationFailed(
                "public_export_merkle_root",
            ));
        }

        let preimage = AcuEnvelopeHeaderV2::archive_row_sign_preimage(
            ACU_ENVELOPE_HEADER_V2_VERSION,
            self.seq,
            &self.prev_header_blake3,
            &self.aead_immutable_blake3,
            &self.run_locator,
            &self.public_export_merkle_root,
            &self.meta_nonce,
            &self.encrypted_meta_box,
        );
        let sig = Signature::from_bytes(&self.archive_row_sig);
        archive_verifying_key
            .verify_strict(&preimage, &sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("archive_row_sign"))
    }
}

/// Signed receipt attached alongside an [`AcuEnvelopeV2Record`] whenever its mutable `CHWGACU3` /
/// `CHWGAEA2` policy header evolves in-place (`RevokeAndRerandomize`, `EscalateThreshold`,
/// `InsertAuthorizedSeat`, `InsertSiblingKey`, or `RotatePQKey`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvolutionReceipt {
    /// Envelope sequence number evolved in-place.
    pub seq: u64,
    /// Previous policy epoch (`E`).
    pub from_epoch: u64,
    /// New policy epoch (`E + 1`).
    pub to_epoch: u64,
    /// Immutable `C_1` digest (`aead_immutable_blake3` MUST match `AcuEnvelopeHeaderV2::aead_immutable_blake3`).
    pub aead_immutable_blake3: [u8; 32],
    /// Detached `AcuPolicySign` signature over the evolved `AcuCiphertext` header at `to_epoch`.
    pub policy_signature: AcuPolicySignature,
}

/// Blind Hash-Chained Envelope Header (`UI v5` §7 `F-01`, `F-02`, `F-03` & `ePrint v2` §§6–7):
///
/// Chains `aead_immutable_blake3` (`BLAKE3(nonce || aad || C_1)`) inside `prev_header_blake3`
/// rather than the mutable `CHWGACU3` policy header `H_E`, so in-place policy evolution on
/// `seq = 42` **never** invalidates `prev_header_blake3` on `seq = 43..N`!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcuEnvelopeHeaderV2 {
    /// Envelope format version (`= 2`).
    pub version: u8,
    /// Monotonic sequence number within the workspace/channel log.
    pub seq: u64,
    /// `BLAKE3` chain link of record `seq - 1` (`[0u8; 32]` at genesis `seq = 1`).
    pub prev_header_blake3: [u8; 32],
    /// Immutable payload digest `EncryptedCiPayload::immutable_aead_blake3()` (`C_{E+1} == C_1`).
    pub aead_immutable_blake3: [u8; 32],
    /// Keyed 16-byte run locator `BLAKE3_keyed(k_route, "run/v2:" || flow_run_id)[..16]`.
    pub run_locator: [u8; 16],
    /// Per-object 16-byte blind row locator prefixes (`ell_j[..16]`, opaque to Blind Relay & `.keys` JOINs).
    pub recipient_hints: Vec<[u8; 16]>,
    /// 4-leaf salted Merkle root supporting selective `--public-safe` openings (`PublicSafeExportBundle`).
    pub public_export_merkle_root: [u8; 32],
    /// 96-bit nonce for `encrypted_meta_box`.
    pub meta_nonce: [u8; 12],
    /// `ChaCha20-Poly1305` ciphertext under `k_route` sealing [`EnvelopeMetadataBox`].
    pub encrypted_meta_box: Vec<u8>,
    /// Repo-scoped outer `ArchiveRowSign` Ed25519 signature (`64` B; inner `SeatAuthorSign` lives inside `C_1`).
    #[serde(with = "crate::framing::serde_bytes64")]
    pub archive_row_sig: [u8; 64],
}

impl AcuEnvelopeHeaderV2 {
    /// Compute the keyed 16-byte `run_locator` from `route_key` and `flow_run_id`.
    #[must_use]
    pub fn compute_run_locator(route_key: &[u8; 32], flow_run_id: &str) -> [u8; 16] {
        let mut h = blake3::Hasher::new_keyed(route_key);
        h.update(b"run/v2:");
        h.update(&(flow_run_id.len() as u64).to_be_bytes());
        h.update(flow_run_id.as_bytes());
        let full = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full.as_bytes()[..16]);
        out
    }

    /// Compute the immutable `BLAKE3` chain link passed into record `seq + 1`'s `prev_header_blake3`.
    ///
    /// Covers ONLY immutable envelope fields and `aead_immutable_blake3` (`C_1`), so in-place
    /// `RevokeAndRerandomize` / `EscalateThreshold` / `RotatePQKey` never breaks downstream links!
    #[must_use]
    pub fn chain_link_blake3(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(ENVELOPE_V2_CHAIN_DOMAIN);
        h.update(&[self.version]);
        h.update(&self.seq.to_be_bytes());
        h.update(&self.prev_header_blake3);
        h.update(&self.aead_immutable_blake3);
        h.update(&self.run_locator);
        h.update(&self.public_export_merkle_root);
        h.update(&self.meta_nonce);
        h.update(&(self.encrypted_meta_box.len() as u64).to_be_bytes());
        h.update(&self.encrypted_meta_box);
        h.update(&self.archive_row_sig);
        *h.finalize().as_bytes()
    }

    /// Decrypt `encrypted_meta_box` using the workspace's 256-bit `route_key`.
    pub fn open_metadata_box(&self, route_key: &[u8; 32]) -> Result<EnvelopeMetadataBox, AcuError> {
        let key = derive_meta_box_key(route_key)?;
        let aad = Self::meta_box_aad(
            self.version,
            self.seq,
            &self.prev_header_blake3,
            &self.aead_immutable_blake3,
            &self.run_locator,
            &self.public_export_merkle_root,
        );
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&self.meta_nonce),
                Payload {
                    msg: &self.encrypted_meta_box,
                    aad: &aad,
                },
            )
            .map_err(|_| AcuError::AeadFailure)?;
        serde_json::from_slice(&plain)
            .map_err(|_| AcuError::SerializationError("invalid EnvelopeMetadataBox JSON"))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn archive_row_sign_preimage(
        version: u8,
        seq: u64,
        prev_header_blake3: &[u8; 32],
        aead_immutable_blake3: &[u8; 32],
        run_locator: &[u8; 16],
        public_export_merkle_root: &[u8; 32],
        meta_nonce: &[u8; 12],
        encrypted_meta_box: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + encrypted_meta_box.len());
        out.extend_from_slice(ENVELOPE_V2_SIG_DOMAIN);
        out.push(version);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(prev_header_blake3);
        out.extend_from_slice(aead_immutable_blake3);
        out.extend_from_slice(run_locator);
        out.extend_from_slice(public_export_merkle_root);
        out.extend_from_slice(meta_nonce);
        lp64_bytes(&mut out, encrypted_meta_box);
        out
    }

    fn meta_box_aad(
        version: u8,
        seq: u64,
        prev_header_blake3: &[u8; 32],
        aead_immutable_blake3: &[u8; 32],
        run_locator: &[u8; 16],
        public_export_merkle_root: &[u8; 32],
    ) -> Vec<u8> {
        let mut aad =
            Vec::with_capacity(ENVELOPE_V2_META_AAD_DOMAIN.len() + 1 + 8 + 32 + 32 + 16 + 32);
        aad.extend_from_slice(ENVELOPE_V2_META_AAD_DOMAIN);
        aad.push(version);
        aad.extend_from_slice(&seq.to_be_bytes());
        aad.extend_from_slice(prev_header_blake3);
        aad.extend_from_slice(aead_immutable_blake3);
        aad.extend_from_slice(run_locator);
        aad.extend_from_slice(public_export_merkle_root);
        aad
    }
}

fn derive_meta_box_key(route_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, AcuError> {
    let hk = Hkdf::<Sha256>::new(Some(b"chinwag.acu.v2.meta-box-salt"), route_key);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(ENVELOPE_V2_META_KDF_INFO, &mut *key)
        .map_err(|_| AcuError::SerializationError("HKDF expand failed for meta_box"))?;
    Ok(key)
}

/// Complete blind-chained archive record pairing an immutable [`AcuEnvelopeHeaderV2`] with its
/// dynamically evolvable [`EncryptedCiPayload`] (`CHWGAEA2` + `CHWGACU3`), optional
/// [`PolicyEvolutionReceipt`] history, and 4-leaf Merkle export witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcuEnvelopeV2Record {
    /// Blind hash-chained envelope header (`version = 2`).
    pub header: AcuEnvelopeHeaderV2,
    /// `CHWGAEA2` + `CHWGACU3` payload (`immutable_aead_blake3()` stays constant across policy evolutions).
    pub payload: EncryptedCiPayload,
    /// Detached `AcuPolicySign` signature authenticating the current `payload.acu_ciphertext` epoch.
    pub current_policy_sig: AcuPolicySignature,
    /// Append-only history of in-place policy evolutions on this envelope (`seq`).
    pub evolution_receipts: Vec<PolicyEvolutionReceipt>,
    /// Keyed `HMAC-SHA256` blind index tags for Parquet predicate pushdown.
    pub blind_tags: BlindIndexTags,
    export_leaves: PublicExportLeaves,
}

impl AcuEnvelopeV2Record {
    /// Seal a new [`AcuEnvelopeV2Record`] at sequence `seq` chained from `prev_header_blake3`.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        seq: u64,
        prev_header_blake3: [u8; 32],
        route_key: &[u8; 32],
        index_key: &[u8; 32],
        org_id: &str,
        recipient_seat: &str,
        room: &str,
        task_id: &str,
        meta: &EnvelopeMetadataBox,
        export_leaves: PublicExportLeaves,
        payload: EncryptedCiPayload,
        policy_signer_seat_id: &str,
        policy_signer_ed25519_sk: &SigningKey,
        archive_row_signing_key: &SigningKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        if seq == 0 {
            return Err(AcuError::InvalidMetadata);
        }
        let aead_immutable_blake3 = payload.immutable_aead_blake3();
        let run_locator = AcuEnvelopeHeaderV2::compute_run_locator(route_key, &meta.flow_run_id);
        let recipient_hints = payload
            .acu_ciphertext
            .rows
            .iter()
            .map(|r| {
                let mut hint = [0u8; 16];
                hint.copy_from_slice(&r.row_locator[..16]);
                hint
            })
            .collect();
        let (public_export_merkle_root, _) = export_leaves.compute_root_and_private_subtree();

        let mut meta_nonce = [0u8; 12];
        rng.fill_bytes(&mut meta_nonce);
        let meta_plain = serde_json::to_vec(meta)
            .map_err(|_| AcuError::SerializationError("failed to serialize EnvelopeMetadataBox"))?;
        let meta_key = derive_meta_box_key(route_key)?;
        let meta_aad = AcuEnvelopeHeaderV2::meta_box_aad(
            ACU_ENVELOPE_HEADER_V2_VERSION,
            seq,
            &prev_header_blake3,
            &aead_immutable_blake3,
            &run_locator,
            &public_export_merkle_root,
        );
        let encrypted_meta_box = ChaCha20Poly1305::new(Key::from_slice(&*meta_key))
            .encrypt(
                Nonce::from_slice(&meta_nonce),
                Payload {
                    msg: &meta_plain,
                    aad: &meta_aad,
                },
            )
            .map_err(|_| AcuError::SerializationError("meta_box AEAD encryption failed"))?;

        let sig_preimage = AcuEnvelopeHeaderV2::archive_row_sign_preimage(
            ACU_ENVELOPE_HEADER_V2_VERSION,
            seq,
            &prev_header_blake3,
            &aead_immutable_blake3,
            &run_locator,
            &public_export_merkle_root,
            &meta_nonce,
            &encrypted_meta_box,
        );
        let archive_sig: Signature = archive_row_signing_key.sign(&sig_preimage);

        let header = AcuEnvelopeHeaderV2 {
            version: ACU_ENVELOPE_HEADER_V2_VERSION,
            seq,
            prev_header_blake3,
            aead_immutable_blake3,
            run_locator,
            recipient_hints,
            public_export_merkle_root,
            meta_nonce,
            encrypted_meta_box,
            archive_row_sig: archive_sig.to_bytes(),
        };

        let current_policy_sig = AcuPolicySignature::sign(
            policy_signer_seat_id,
            &payload.acu_ciphertext,
            policy_signer_ed25519_sk,
        );
        let blind_tags = BlindIndexTags::compute(
            index_key,
            org_id,
            &meta.sender_seat,
            recipient_seat,
            room,
            task_id,
        );

        Ok(Self {
            header,
            payload,
            current_policy_sig,
            evolution_receipts: Vec::new(),
            blind_tags,
            export_leaves,
        })
    }

    /// Apply an in-place `RevokeAndRerandomize` + PQ capsule pruning on this record (`e.g. seq = 42`)
    /// **without** modifying `header.aead_immutable_blake3`, `header.archive_row_sig`, or
    /// `header.chain_link_blake3()` — so `seq = 43..N` remain 100% hash-chain valid!
    pub fn revoke_and_rerandomize_in_place(
        &mut self,
        acu_sk: &SeatSecretKey,
        revoked_seat_ids: &[&str],
        registry: &AllowedSignersRegistry,
        acu_ed25519_sk: &SigningKey,
        archive_verifying_key: &VerifyingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<PolicyEvolutionReceipt, AcuError> {
        self.verify_integrity(archive_verifying_key, registry)?;
        let from_epoch = self.payload.acu_ciphertext.policy_epoch;
        let active_keys = registry.active_acu_keys();

        revoke_and_rerandomize(
            &mut self.payload.acu_ciphertext,
            acu_sk,
            revoked_seat_ids,
            &active_keys,
            rng,
        )?;
        if !revoked_seat_ids.is_empty() {
            self.payload.prune_revoked_pq_capsules(revoked_seat_ids)?;
        }

        // Refresh blind `recipient_hints` to match the rerandomized surviving rows.
        self.header.recipient_hints = self
            .payload
            .acu_ciphertext
            .rows
            .iter()
            .map(|r| {
                let mut hint = [0u8; 16];
                hint.copy_from_slice(&r.row_locator[..16]);
                hint
            })
            .collect();

        let after_immutable = self.payload.immutable_aead_blake3();
        if !bool::from(after_immutable.ct_eq(&self.header.aead_immutable_blake3)) {
            return Err(AcuError::InvalidMetadata);
        }

        let to_epoch = self.payload.acu_ciphertext.policy_epoch;
        let new_policy_sig = AcuPolicySignature::sign(
            acu_sk.seat_id(),
            &self.payload.acu_ciphertext,
            acu_ed25519_sk,
        );
        let receipt = PolicyEvolutionReceipt {
            seq: self.header.seq,
            from_epoch,
            to_epoch,
            aead_immutable_blake3: after_immutable,
            policy_signature: new_policy_sig.clone(),
        };
        self.current_policy_sig = new_policy_sig;
        self.evolution_receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Verify this record's `ArchiveRowSign`, `aead_immutable_blake3` payload binding, and current
    /// `AcuPolicySign` epoch signature.
    pub fn verify_integrity(
        &self,
        archive_verifying_key: &VerifyingKey,
        registry: &AllowedSignersRegistry,
    ) -> Result<(), AcuError> {
        if self.header.version != ACU_ENVELOPE_HEADER_V2_VERSION || self.header.seq == 0 {
            return Err(AcuError::InvalidMetadata);
        }
        let actual_immutable = self.payload.immutable_aead_blake3();
        if !bool::from(actual_immutable.ct_eq(&self.header.aead_immutable_blake3)) {
            return Err(AcuError::SignatureVerificationFailed(
                "aead_immutable_blake3_mismatch",
            ));
        }
        let preimage = AcuEnvelopeHeaderV2::archive_row_sign_preimage(
            self.header.version,
            self.header.seq,
            &self.header.prev_header_blake3,
            &self.header.aead_immutable_blake3,
            &self.header.run_locator,
            &self.header.public_export_merkle_root,
            &self.header.meta_nonce,
            &self.header.encrypted_meta_box,
        );
        let sig = Signature::from_bytes(&self.header.archive_row_sig);
        archive_verifying_key
            .verify_strict(&preimage, &sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("archive_row_sign"))?;

        self.current_policy_sig
            .verify(&self.payload.acu_ciphertext, registry)?;
        if (self.payload.acu_ciphertext.policy_epoch >= 2 || !self.evolution_receipts.is_empty())
            && self.current_policy_sig.signer_seat_id != self.payload.acu_ciphertext.acu_seat_id
        {
            return Err(AcuError::UnauthorizedPolicyOperator);
        }

        let mut prev_to_epoch = 1u64;
        for receipt in &self.evolution_receipts {
            if receipt.seq != self.header.seq {
                return Err(AcuError::InvalidMetadata);
            }
            if receipt.from_epoch == 0
                || receipt.from_epoch >= receipt.to_epoch
                || receipt.from_epoch < prev_to_epoch
                || receipt.to_epoch > self.payload.acu_ciphertext.policy_epoch
            {
                return Err(AcuError::EpochMismatch {
                    expected: prev_to_epoch,
                    actual: receipt.from_epoch,
                });
            }
            if receipt.policy_signature.signer_seat_id != self.payload.acu_ciphertext.acu_seat_id {
                return Err(AcuError::UnauthorizedPolicyOperator);
            }
            if !bool::from(
                receipt
                    .aead_immutable_blake3
                    .ct_eq(&self.header.aead_immutable_blake3),
            ) {
                return Err(AcuError::SignatureVerificationFailed(
                    "evolution_receipt_immutable_mismatch",
                ));
            }
            prev_to_epoch = receipt.to_epoch;
        }

        let acu_rec = registry.get_any(&self.payload.acu_ciphertext.acu_seat_id)?;
        self.payload
            .acu_ciphertext
            .verify_authenticity(&acu_rec.acu_public_key, |seat_id| {
                registry
                    .get_any(seat_id)
                    .ok()
                    .map(|rec| &rec.acu_public_key)
            })?;
        Ok(())
    }

    /// Export a selective `--public-safe` Merkle proof bundle revealing ONLY Leaves `0` and `1`
    /// (`public_summary` + `public_gate_metrics`) while keeping Leaves `2` and `3` (`private_topology`
    /// + `private_audit_context`) cryptographically blinded behind `private_subtree_h23`.
    #[must_use]
    pub fn export_public_safe(&self) -> PublicSafeExportBundle {
        let (_, private_subtree_h23) = self.export_leaves.compute_root_and_private_subtree();
        PublicSafeExportBundle {
            seq: self.header.seq,
            prev_header_blake3: self.header.prev_header_blake3,
            aead_immutable_blake3: self.header.aead_immutable_blake3,
            run_locator: self.header.run_locator,
            public_export_merkle_root: self.header.public_export_merkle_root,
            meta_nonce: self.header.meta_nonce,
            encrypted_meta_box: self.header.encrypted_meta_box.clone(),
            archive_row_sig: self.header.archive_row_sig,
            salt_0: self.export_leaves.salt_0,
            public_summary: self.export_leaves.public_summary.clone(),
            salt_1: self.export_leaves.salt_1,
            public_gate_metrics: self.export_leaves.public_gate_metrics.clone(),
            private_subtree_h23,
        }
    }
}

/// Verify an ordered slice of [`AcuEnvelopeV2Record`]s (`seq = 1..=N`), checking every record's
/// `ArchiveRowSign`, `aead_immutable_blake3`, `AcuPolicySign`, and unbroken `prev_header_blake3`
/// hash chain across in-place policy evolutions!
pub fn verify_envelope_v2_chain(
    records: &[AcuEnvelopeV2Record],
    archive_verifying_key: &VerifyingKey,
    registry: &AllowedSignersRegistry,
) -> Result<(), AcuError> {
    let mut expected_prev = [0u8; 32];
    for (idx, rec) in records.iter().enumerate() {
        let expected_seq = (idx + 1) as u64;
        if rec.header.seq != expected_seq {
            return Err(AcuError::InvalidMetadata);
        }
        if !bool::from(rec.header.prev_header_blake3.ct_eq(&expected_prev)) {
            return Err(AcuError::SignatureVerificationFailed(
                "prev_header_blake3_chain_broken",
            ));
        }
        rec.verify_integrity(archive_verifying_key, registry)?;
        expected_prev = rec.header.chain_link_blake3();
    }
    Ok(())
}

// ============================================================================
// Cloudflare R2 / S3 Parquet Message Archive & Hybrid Active-Channel Cache
// ============================================================================

/// Hive-partitioned key for Cloudflare R2 / S3 Parquet message archives:
/// `org_id=<org_id>/year=<YYYY>/month=<MM>/day=<DD>/archive.parquet`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HivePartitionKey {
    /// Organization / tenant identifier.
    pub org_id: String,
    /// Four-digit UTC year (e.g., `2026`).
    pub year: u16,
    /// Two-digit UTC month (`1..=12`).
    pub month: u8,
    /// Two-digit UTC day (`1..=31`).
    pub day: u8,
}

impl HivePartitionKey {
    /// Create and validate a [`HivePartitionKey`].
    pub fn new(org_id: impl Into<String>, year: u16, month: u8, day: u8) -> Result<Self, AcuError> {
        let org_id = org_id.into();
        if !is_safe_storage_token(&org_id) || !(1..=12).contains(&month) || !(1..=31).contains(&day)
        {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(Self {
            org_id,
            year,
            month,
            day,
        })
    }

    /// Format the S3-compatible Cloudflare R2 URI for this Hive partition:
    /// `s3://{bucket}/org_id={org_id}/year={year:04}/month={month:02}/day={day:02}/archive.parquet`.
    pub fn s3_parquet_uri(&self, bucket: &str) -> Result<String, AcuError> {
        if !is_safe_storage_token(bucket) || !is_safe_storage_token(&self.org_id) {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "s3://{bucket}/org_id={}/year={:04}/month={:02}/day={:02}/archive.parquet",
            self.org_id, self.year, self.month, self.day
        ))
    }

    /// Format the native DuckDB `r2://` URI for this Hive partition:
    /// `r2://{bucket}/org_id={org_id}/year={year:04}/month={month:02}/day={day:02}/archive.parquet`.
    pub fn r2_parquet_uri(&self, bucket: &str) -> Result<String, AcuError> {
        if !is_safe_storage_token(bucket) || !is_safe_storage_token(&self.org_id) {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "r2://{bucket}/org_id={}/year={:04}/month={:02}/day={:02}/archive.parquet",
            self.org_id, self.year, self.month, self.day
        ))
    }

    /// Format the Hive-partitioned wildcard URI across all dates for an organization on S3/R2:
    /// `s3://{bucket}/org_id={org_id}/year=*/month=*/day=*/*.parquet`.
    pub fn s3_glob_uri(bucket: &str, org_id: &str) -> Result<String, AcuError> {
        if !is_safe_storage_token(bucket) || !is_safe_storage_token(org_id) {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "s3://{bucket}/org_id={org_id}/year=*/month=*/day=*/*.parquet"
        ))
    }
}

/// A single row in the Cloudflare R2 Parquet Message Archive table.
///
/// The message body is sealed inside the `acu_ciphertext` BLOB column (`CHWGAEA2` wrapping
/// `CHWGACU3`) under `ACU AND (Recipient OR Archive)` with zero-$V_0$ `SbcSlot`s and `0x647A`
/// non-ACU LSSS-PQ.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedMessageRow {
    /// Unique message identifier.
    pub message_id: String,
    /// UTC timestamp in milliseconds since Unix epoch.
    pub timestamp_utc: u64,
    /// Original sender seat identifier (immutable across post-revocation rerandomization).
    pub sender_seat: String,
    /// Recipient seat identifier (e.g., `"GEMINI-PM"` or `"branch:8687872"`).
    pub recipient_seat: String,
    /// Bus room / channel name (e.g., `"#eng"` or `"#ci"`).
    pub room: String,
    /// Associated ticket or task identifier (e.g., `"CHWG-101"`).
    pub task_id: String,
    /// Current ACU policy epoch of `acu_ciphertext`.
    pub policy_epoch: u64,
    /// Optional CISO ACU seat (`acu:98939834`) that re-signed this row after in-place `revoke_and_rerandomize`.
    pub rerandomized_by_seat: Option<String>,
    /// Immutable Ed25519 non-repudiation signature by `sender_seat` over the canonical
    /// routing metadata and immutable AEAD envelope `(nonce, associated_data, SHA-256(aead_ciphertext))`.
    pub sender_ed25519_sig: Vec<u8>,
    /// Ed25519 signature over the canonical row metadata, `sender_ed25519_sig`, and `SHA-256(acu_ciphertext)`.
    pub ed25519_sig: Vec<u8>,
    /// Deterministic binary serialization (`EncryptedCiPayload::to_bytes`) of the message payload.
    pub acu_ciphertext: Vec<u8>,
}

impl ArchivedMessageRow {
    /// Verify both the outer `ed25519_sig` AND the immutable `sender_ed25519_sig` against
    /// `.chinwag/allowed_signers` BEFORE attempting pairing or AEAD decryption.
    pub fn verify_row_signature(&self, registry: &AllowedSignersRegistry) -> Result<(), AcuError> {
        if !is_valid_metadata_token(&self.message_id)
            || !is_valid_seat_id(&self.sender_seat)
            || !is_valid_seat_id(&self.recipient_seat)
            || !is_valid_metadata_token(&self.room)
            || !is_valid_metadata_token(&self.task_id)
        {
            return Err(AcuError::InvalidMetadata);
        }
        if self.ed25519_sig.len() != 64 || self.sender_ed25519_sig.len() != 64 {
            return Err(AcuError::SignatureVerificationFailed("archive_row_sig_len"));
        }

        let preimage = Self::signing_preimage(
            &self.message_id,
            self.timestamp_utc,
            &self.sender_seat,
            &self.recipient_seat,
            &self.room,
            &self.task_id,
            self.policy_epoch,
            self.rerandomized_by_seat.as_deref(),
            &self.sender_ed25519_sig,
            &self.acu_ciphertext,
        );
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.ed25519_sig);
        let sig = Signature::from_bytes(&sig_bytes);

        match self.rerandomized_by_seat.as_deref() {
            None => {
                if self.policy_epoch != 1 {
                    return Err(AcuError::SignatureVerificationFailed("archive_row_epoch"));
                }
                let sender_rec = registry.get_any(&self.sender_seat)?;
                sender_rec
                    .ed25519_verifying_key
                    .verify_strict(&preimage, &sig)
                    .map_err(|_| AcuError::SignatureVerificationFailed("archive_row"))?;
            }
            Some(re_signer) => {
                if self.policy_epoch < 2 {
                    return Err(AcuError::SignatureVerificationFailed("archive_row_epoch"));
                }
                if re_signer != DEFAULT_CISO_ACU_ID {
                    return Err(AcuError::SignatureVerificationFailed(
                        "unauthorized_re_signer",
                    ));
                }
                let acu_signer_rec = registry.get_active(re_signer)?;
                acu_signer_rec
                    .ed25519_verifying_key
                    .verify_strict(&preimage, &sig)
                    .map_err(|_| AcuError::SignatureVerificationFailed("archive_row"))?;
            }
        }

        let payload = EncryptedCiPayload::from_bytes(&self.acu_ciphertext)?;
        if payload.acu_ciphertext.policy_epoch != self.policy_epoch {
            return Err(AcuError::EpochMismatch {
                expected: self.policy_epoch,
                actual: payload.acu_ciphertext.policy_epoch,
            });
        }
        if payload.acu_ciphertext.acu_seat_id != DEFAULT_CISO_ACU_ID {
            return Err(AcuError::SignatureVerificationFailed(
                "unauthorized_re_signer",
            ));
        }
        if let Some(re_signer) = self.rerandomized_by_seat.as_deref()
            && re_signer != payload.acu_ciphertext.acu_seat_id
        {
            return Err(AcuError::SignatureVerificationFailed(
                "unauthorized_re_signer",
            ));
        }

        let sender_rec = registry.get_any(&self.sender_seat)?;
        let sender_body_preimage = Self::sender_body_signing_preimage(
            &self.message_id,
            self.timestamp_utc,
            &self.sender_seat,
            &self.recipient_seat,
            &self.room,
            &self.task_id,
            &payload.nonce,
            &payload.associated_data,
            &payload.aead_ciphertext,
        );
        let mut sender_sig_bytes = [0u8; 64];
        sender_sig_bytes.copy_from_slice(&self.sender_ed25519_sig);
        let sender_sig = Signature::from_bytes(&sender_sig_bytes);
        sender_rec
            .ed25519_verifying_key
            .verify_strict(&sender_body_preimage, &sender_sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("archive_sender_body"))
    }

    /// Prune `revoked_seat_ids` (both classical LSSS rows AND `0x647A` PQ capsules) and
    /// cryptographically rerandomize this archived row's `acu_ciphertext` BLOB in-place using
    /// `acu_sk` (`0` $V_0$ unsealing, `0` bulk `C_1` re-encryption!), preserving `sender_seat`
    /// + `sender_ed25519_sig` and re-signing with `re_signer_ed25519_sk`.
    pub fn revoke_and_rerandomize_in_place(
        &mut self,
        acu_sk: &SeatSecretKey,
        revoked_seat_ids: &[&str],
        registry: &AllowedSignersRegistry,
        re_signer_seat_id: &str,
        re_signer_ed25519_sk: &SigningKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), AcuError> {
        self.verify_row_signature(registry)?;
        if re_signer_seat_id != acu_sk.seat_id() {
            return Err(AcuError::SignatureVerificationFailed("re_signer_mismatch"));
        }
        let signer_rec = registry.get_active(re_signer_seat_id)?;
        if signer_rec.ed25519_verifying_key != re_signer_ed25519_sk.verifying_key() {
            return Err(AcuError::SignatureVerificationFailed("re_signer_mismatch"));
        }
        let mut payload = EncryptedCiPayload::from_bytes(&self.acu_ciphertext)?;
        let active_keys = registry.active_acu_keys();
        revoke_and_rerandomize(
            &mut payload.acu_ciphertext,
            acu_sk,
            revoked_seat_ids,
            &active_keys,
            rng,
        )?;
        if !revoked_seat_ids.is_empty() {
            payload.prune_revoked_pq_capsules(revoked_seat_ids)?;
        }

        if re_signer_seat_id != DEFAULT_CISO_ACU_ID
            || re_signer_seat_id != payload.acu_ciphertext.acu_seat_id
        {
            return Err(AcuError::SignatureVerificationFailed(
                "unauthorized_re_signer",
            ));
        }
        let new_epoch = payload.acu_ciphertext.policy_epoch;
        let new_ciphertext = payload.to_bytes();
        let preimage = Self::signing_preimage(
            &self.message_id,
            self.timestamp_utc,
            &self.sender_seat,
            &self.recipient_seat,
            &self.room,
            &self.task_id,
            new_epoch,
            Some(re_signer_seat_id),
            &self.sender_ed25519_sig,
            &new_ciphertext,
        );
        let sig: Signature = re_signer_ed25519_sk.sign(&preimage);
        self.policy_epoch = new_epoch;
        self.acu_ciphertext = new_ciphertext;
        self.rerandomized_by_seat = Some(re_signer_seat_id.to_string());
        self.ed25519_sig = sig.to_bytes().to_vec();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sender_body_signing_preimage(
        message_id: &str,
        timestamp_utc: u64,
        sender_seat: &str,
        recipient_seat: &str,
        room: &str,
        task_id: &str,
        nonce: &[u8; 12],
        associated_data: &[u8],
        aead_ciphertext: &[u8],
    ) -> Vec<u8> {
        let aead_hash = Sha256::digest(aead_ciphertext);
        let mut out = Vec::with_capacity(256 + associated_data.len());
        out.extend_from_slice(ARCHIVE_SENDER_BODY_SIG_DOMAIN);
        lp64_str(&mut out, message_id);
        out.extend_from_slice(&timestamp_utc.to_be_bytes());
        lp64_str(&mut out, sender_seat);
        lp64_str(&mut out, recipient_seat);
        lp64_str(&mut out, room);
        lp64_str(&mut out, task_id);
        out.extend_from_slice(nonce);
        lp64_bytes(&mut out, associated_data);
        out.extend_from_slice(&aead_hash);
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn signing_preimage(
        message_id: &str,
        timestamp_utc: u64,
        sender_seat: &str,
        recipient_seat: &str,
        room: &str,
        task_id: &str,
        policy_epoch: u64,
        rerandomized_by_seat: Option<&str>,
        sender_ed25519_sig: &[u8],
        acu_ciphertext: &[u8],
    ) -> Vec<u8> {
        let blob_hash = Sha256::digest(acu_ciphertext);
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(ARCHIVE_ROW_SIG_DOMAIN);
        lp64_str(&mut out, message_id);
        out.extend_from_slice(&timestamp_utc.to_be_bytes());
        lp64_str(&mut out, sender_seat);
        lp64_str(&mut out, recipient_seat);
        lp64_str(&mut out, room);
        lp64_str(&mut out, task_id);
        out.extend_from_slice(&policy_epoch.to_be_bytes());
        match rerandomized_by_seat {
            Some(re_signer) => {
                out.push(1u8);
                lp64_str(&mut out, re_signer);
            }
            None => out.push(0u8),
        }
        lp64_bytes(&mut out, sender_ed25519_sig);
        out.extend_from_slice(&blob_hash);
        out
    }
}

/// Cleartext metadata predicate filter for DuckDB `read_parquet` queries over Cloudflare R2 / S3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveSearchFilter {
    /// Organization identifier for Hive partition pruning (`org_id=...`).
    pub org_id: String,
    /// Optional exact match on `sender_seat`.
    pub sender_seat: Option<String>,
    /// Optional exact match on `recipient_seat`.
    pub recipient_seat: Option<String>,
    /// Optional exact match on `room` (e.g., `"#eng"`).
    pub room: Option<String>,
    /// Optional exact match on `task_id` (e.g., `"CHWG-101"`).
    pub task_id: Option<String>,
    /// Optional inclusive lower bound on `timestamp_utc`.
    pub timestamp_start_utc: Option<u64>,
    /// Optional inclusive upper bound on `timestamp_utc`.
    pub timestamp_end_utc: Option<u64>,
    /// Maximum number of rows to return (`1..=1000`, defaults to `50`).
    pub limit: usize,
}

impl ArchiveSearchFilter {
    /// Create a new metadata filter for `org_id` with default `limit = 50`.
    #[must_use]
    pub fn new(org_id: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            sender_seat: None,
            recipient_seat: None,
            room: None,
            task_id: None,
            timestamp_start_utc: None,
            timestamp_end_utc: None,
            limit: DEFAULT_ACTIVE_CHANNEL_PAGE_SIZE,
        }
    }
}

/// DuckDB `httpfs` + Cloudflare R2 (S3-compatible API) configuration with UI-thread resource caps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuckDbArchiveConfig {
    /// R2 / S3 bucket name (e.g., `"chinwag-archive"`).
    pub bucket: String,
    /// Cloudflare account ID for R2 (e.g., `"cf-acct-99887766"`).
    pub r2_account_id: Option<String>,
    /// S3-compatible endpoint host (`"<account_id>.r2.cloudflarestorage.com"`).
    pub s3_endpoint: String,
    /// S3 region (`"auto"` for Cloudflare R2).
    pub s3_region: String,
    /// Maximum DuckDB worker threads (`SET threads = 2;`) to protect web workbench responsiveness.
    pub threads: u8,
    /// Maximum DuckDB RAM allocation (`SET memory_limit = '1GB';`).
    pub memory_limit: String,
}

impl DuckDbArchiveConfig {
    /// Primary constructor for **Cloudflare R2** using R2's S3-compatible API
    /// (`<account_id>.r2.cloudflarestorage.com`, `s3_region = 'auto'`, `threads = 2`, `memory_limit = '1GB'`).
    pub fn cloudflare_r2(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Result<Self, AcuError> {
        let account_id = account_id.into();
        let bucket = bucket.into();
        if !is_safe_storage_token(&account_id) || !is_safe_storage_token(&bucket) {
            return Err(AcuError::InvalidMetadata);
        }
        let s3_endpoint = format!("{account_id}.r2.cloudflarestorage.com");
        Ok(Self {
            bucket,
            r2_account_id: Some(account_id),
            s3_endpoint,
            s3_region: "auto".to_string(),
            threads: DEFAULT_DUCKDB_THREADS,
            memory_limit: DEFAULT_DUCKDB_MEMORY_LIMIT.to_string(),
        })
    }

    /// Generate the DuckDB session initialization SQL enforcing background thread/memory limits
    /// and configuring `httpfs` for Cloudflare R2's S3-compatible API.
    pub fn to_httpfs_init_sql(&self) -> Result<String, AcuError> {
        if self.threads == 0
            || !is_safe_storage_token(&self.memory_limit)
            || !is_safe_storage_token(&self.s3_region)
            || !is_safe_storage_token(&self.s3_endpoint)
        {
            return Err(AcuError::InvalidMetadata);
        }
        Ok(format!(
            "SET threads = {};\nSET memory_limit = '{}';\nINSTALL httpfs;\nLOAD httpfs;\nSET s3_region = '{}';\nSET s3_endpoint = '{}';\nSET s3_url_style = 'path';",
            self.threads, self.memory_limit, self.s3_region, self.s3_endpoint
        ))
    }

    /// Generate the parameterized DuckDB `read_parquet` SQL query and positional bind parameters
    /// (`$1`, `$2`, ...) pushing metadata predicates down into Parquet row-group headers.
    pub fn build_read_parquet_query(
        &self,
        filter: &ArchiveSearchFilter,
    ) -> Result<(String, Vec<String>), AcuError> {
        let glob_uri = HivePartitionKey::s3_glob_uri(&self.bucket, &filter.org_id)?;
        let limit = filter.limit.clamp(1, 1000);

        let mut clauses = Vec::new();
        let mut params = Vec::new();

        if let Some(ref sender) = filter.sender_seat {
            params.push(sender.clone());
            clauses.push(format!("sender_seat = ${}", params.len()));
        }
        if let Some(ref recipient) = filter.recipient_seat {
            params.push(recipient.clone());
            clauses.push(format!("recipient_seat = ${}", params.len()));
        }
        if let Some(ref room) = filter.room {
            params.push(room.clone());
            clauses.push(format!("room = ${}", params.len()));
        }
        if let Some(ref task_id) = filter.task_id {
            params.push(task_id.clone());
            clauses.push(format!("task_id = ${}", params.len()));
        }
        if let Some(start_ts) = filter.timestamp_start_utc {
            params.push(start_ts.to_string());
            clauses.push(format!("timestamp_utc >= ${}", params.len()));
        }
        if let Some(end_ts) = filter.timestamp_end_utc {
            params.push(end_ts.to_string());
            clauses.push(format!("timestamp_utc <= ${}", params.len()));
        }

        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!("\nWHERE {}", clauses.join(" AND "))
        };

        let sql = format!(
            "SELECT message_id, timestamp_utc, sender_seat, recipient_seat, room, task_id, policy_epoch, rerandomized_by_seat, sender_ed25519_sig, ed25519_sig, acu_ciphertext\nFROM read_parquet('{glob_uri}', hive_partitioning = true){where_sql}\nORDER BY timestamp_utc DESC\nLIMIT {limit};"
        );
        Ok((sql, params))
    }

    /// **Hybrid Active-Channel Cache (Step 1 SQL):** Generate the DuckDB SQL to populate the
    /// in-memory `active_channel_cache` temp table when a user first clicks a channel (`room`).
    pub fn build_populate_active_channel_cache_sql(
        &self,
        org_id: &str,
        room: &str,
        limit: usize,
    ) -> Result<(String, Vec<String>), AcuError> {
        let glob_uri = HivePartitionKey::s3_glob_uri(&self.bucket, org_id)?;
        let clamped_limit = limit.clamp(1, 1000);
        let sql = format!(
            "CREATE TEMP TABLE IF NOT EXISTS active_channel_cache AS\nSELECT message_id, timestamp_utc, sender_seat, recipient_seat, room, task_id, policy_epoch, rerandomized_by_seat, sender_ed25519_sig, ed25519_sig, acu_ciphertext\nFROM read_parquet('{glob_uri}', hive_partitioning = true)\nWHERE room = $1\nORDER BY timestamp_utc DESC\nLIMIT {clamped_limit};"
        );
        Ok((sql, vec![room.to_string()]))
    }

    /// **Hybrid Active-Channel Cache (Step 3 SQL):** Generate the DuckDB cursor-paginated SQL
    /// when the user scrolls up past the oldest cached message (`timestamp_utc < before_timestamp_utc`).
    pub fn build_scroll_older_chunk_sql(
        &self,
        org_id: &str,
        room: &str,
        before_timestamp_utc: u64,
        limit: usize,
    ) -> Result<(String, Vec<String>), AcuError> {
        let glob_uri = HivePartitionKey::s3_glob_uri(&self.bucket, org_id)?;
        let clamped_limit = limit.clamp(1, 1000);
        let sql = format!(
            "SELECT message_id, timestamp_utc, sender_seat, recipient_seat, room, task_id, policy_epoch, rerandomized_by_seat, sender_ed25519_sig, ed25519_sig, acu_ciphertext\nFROM read_parquet('{glob_uri}', hive_partitioning = true)\nWHERE room = $1 AND timestamp_utc < $2\nORDER BY timestamp_utc DESC\nLIMIT {clamped_limit};"
        );
        Ok((
            sql,
            vec![room.to_string(), before_timestamp_utc.to_string()],
        ))
    }
}

/// Indicates whether a channel window query was served in `0` network hops from the
/// fat client's in-RAM `active_channel_cache` or fetched via an R2 Parquet Range query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheHit {
    /// Served in `0` network hops from the fat client's in-RAM `active_channel_cache`.
    ActiveChannelRamCache,
    /// Fetched from Cloudflare R2 Parquet storage and merged into `active_channel_cache`.
    R2ParquetRangeFetch,
}

/// Decrypted message record returned strictly in RAM to the CISO / recipient fat client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedArchiveRecord {
    /// Message identifier.
    pub message_id: String,
    /// UTC timestamp.
    pub timestamp_utc: u64,
    /// Sender seat identifier.
    pub sender_seat: String,
    /// Recipient seat identifier.
    pub recipient_seat: String,
    /// Bus room / channel.
    pub room: String,
    /// Associated task or ticket ID.
    pub task_id: String,
    /// Policy epoch at the time of decryption.
    pub policy_epoch: u64,
    /// Decrypted plaintext bytes (held strictly in RAM; never written back to disk).
    pub plaintext: Vec<u8>,
}

/// Hive-partitioned Parquet Archive engine + Hybrid Active-Channel RAM Cache (`active_channel_cache`).
#[derive(Clone, Debug, Default)]
pub struct AcuParquetArchiveStore {
    partitions: BTreeMap<HivePartitionKey, Vec<ArchivedMessageRow>>,
    active_channel_cache: BTreeMap<(String, String), Vec<ArchivedMessageRow>>,
}

impl AcuParquetArchiveStore {
    /// Create a new empty archive store + active-channel cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encrypt a bus message or CI/CD alert under the canonical Zero-Plaintext-At-Rest policy
    /// (`ACU AND (recipient_seat OR archive:vault)`) using `CHWGAEA2` + `CHWGACU3`, sign both the
    /// immutable sender body commitment (`sender_ed25519_sig`) and routing metadata +
    /// `SHA-256(acu_ciphertext)` (`ed25519_sig`), and append to its R2 Hive partition.
    #[allow(clippy::too_many_arguments)]
    pub fn append_signed_message(
        &mut self,
        partition: HivePartitionKey,
        message_id: impl Into<String>,
        timestamp_utc: u64,
        sender_seat: impl Into<String>,
        recipient_seat: impl Into<String>,
        room: impl Into<String>,
        task_id: impl Into<String>,
        plaintext: &[u8],
        sender_ed25519_sk: &SigningKey,
        registry: &AllowedSignersRegistry,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<ArchivedMessageRow, AcuError> {
        let message_id = message_id.into();
        let sender_seat = sender_seat.into();
        let recipient_seat = recipient_seat.into();
        let room = room.into();
        let task_id = task_id.into();

        if !is_valid_metadata_token(&message_id)
            || !is_valid_seat_id(&sender_seat)
            || !is_valid_seat_id(&recipient_seat)
            || !is_valid_metadata_token(&room)
            || !is_valid_metadata_token(&task_id)
        {
            return Err(AcuError::InvalidMetadata);
        }

        let sender_rec = registry.get_active(&sender_seat)?;
        if sender_rec.ed25519_verifying_key != sender_ed25519_sk.verifying_key() {
            return Err(AcuError::SignatureVerificationFailed("sender_key_mismatch"));
        }

        let acu_rec = registry.get_active(DEFAULT_CISO_ACU_ID)?;
        let recipient_rec = registry.get_active(&recipient_seat)?;
        let archive_rec = registry.get_active(DEFAULT_MESSAGE_ARCHIVE_ID)?;

        let encrypted_payload = EncryptedCiPayload::encrypt_with_acu_and_archive(
            plaintext,
            &acu_rec.acu_public_key,
            &recipient_rec.acu_public_key,
            &archive_rec.acu_public_key,
            &partition.org_id,
            &task_id,
            rng,
        )?;

        let policy_epoch = encrypted_payload.acu_ciphertext.policy_epoch;
        let sender_body_preimage = ArchivedMessageRow::sender_body_signing_preimage(
            &message_id,
            timestamp_utc,
            &sender_seat,
            &recipient_seat,
            &room,
            &task_id,
            &encrypted_payload.nonce,
            &encrypted_payload.associated_data,
            &encrypted_payload.aead_ciphertext,
        );
        let sender_sig: Signature = sender_ed25519_sk.sign(&sender_body_preimage);
        let sender_ed25519_sig = sender_sig.to_bytes().to_vec();
        let acu_ciphertext = encrypted_payload.to_bytes();

        let preimage = ArchivedMessageRow::signing_preimage(
            &message_id,
            timestamp_utc,
            &sender_seat,
            &recipient_seat,
            &room,
            &task_id,
            policy_epoch,
            None,
            &sender_ed25519_sig,
            &acu_ciphertext,
        );
        let sig: Signature = sender_ed25519_sk.sign(&preimage);

        let row = ArchivedMessageRow {
            message_id,
            timestamp_utc,
            sender_seat,
            recipient_seat,
            room,
            task_id,
            policy_epoch,
            rerandomized_by_seat: None,
            sender_ed25519_sig,
            ed25519_sig: sig.to_bytes().to_vec(),
            acu_ciphertext,
        };

        let cache_key = (partition.org_id.clone(), row.room.clone());
        self.partitions
            .entry(partition)
            .or_default()
            .push(row.clone());
        self.active_channel_cache.remove(&cache_key);
        Ok(row)
    }

    /// Execute a fast metadata search across Hive partitions without touching or decrypting any
    /// `acu_ciphertext` BLOBs.
    #[must_use]
    pub fn search_metadata(&self, filter: &ArchiveSearchFilter) -> Vec<&ArchivedMessageRow> {
        let mut matches: Vec<&ArchivedMessageRow> = self
            .partitions
            .iter()
            .filter(|(part, _)| part.org_id == filter.org_id)
            .flat_map(|(_, rows)| rows.iter())
            .filter(|row| {
                filter
                    .sender_seat
                    .as_ref()
                    .is_none_or(|s| &row.sender_seat == s)
                    && filter
                        .recipient_seat
                        .as_ref()
                        .is_none_or(|r| &row.recipient_seat == r)
                    && filter.room.as_ref().is_none_or(|rm| &row.room == rm)
                    && filter.task_id.as_ref().is_none_or(|t| &row.task_id == t)
                    && filter
                        .timestamp_start_utc
                        .is_none_or(|start| row.timestamp_utc >= start)
                    && filter
                        .timestamp_end_utc
                        .is_none_or(|end| row.timestamp_utc <= end)
            })
            .collect();

        matches.sort_by_key(|b| std::cmp::Reverse(b.timestamp_utc));
        matches.truncate(filter.limit.clamp(1, 1000));
        matches
    }

    /// **Hybrid Active-Channel Cache (`active_channel_cache`):**
    /// - Serves cached channels in `0` network hops or fetches/paginates from R2 Parquet partitions.
    pub fn load_channel_window(
        &mut self,
        org_id: &str,
        room: &str,
        before_timestamp_utc: Option<u64>,
        limit: usize,
    ) -> (CacheHit, Vec<ArchivedMessageRow>) {
        let clamped_limit = limit.clamp(1, 1000);
        let cache_key = (org_id.to_string(), room.to_string());

        if before_timestamp_utc.is_none()
            && let Some(cached) = self.active_channel_cache.get(&cache_key)
        {
            let slice: Vec<ArchivedMessageRow> =
                cached.iter().take(clamped_limit).cloned().collect();
            return (CacheHit::ActiveChannelRamCache, slice);
        }

        let mut filter = ArchiveSearchFilter::new(org_id);
        filter.room = Some(room.to_string());
        filter.limit = clamped_limit;
        if let Some(cursor_ts) = before_timestamp_utc {
            filter.timestamp_end_utc = Some(cursor_ts.saturating_sub(1));
        }

        let fetched: Vec<ArchivedMessageRow> =
            self.search_metadata(&filter).into_iter().cloned().collect();

        let entry = self.active_channel_cache.entry(cache_key).or_default();
        for row in &fetched {
            if !entry
                .iter()
                .any(|existing| existing.message_id == row.message_id)
            {
                entry.push(row.clone());
            }
        }
        entry.sort_by_key(|b| std::cmp::Reverse(b.timestamp_utc));

        (CacheHit::R2ParquetRangeFetch, fetched)
    }

    /// Mutate an archived row in-place by `message_id`.
    pub fn update_row_by_id(
        &mut self,
        message_id: &str,
        mutate: impl FnOnce(&mut ArchivedMessageRow),
    ) -> bool {
        for rows in self.partitions.values_mut() {
            for row in rows.iter_mut() {
                if row.message_id == message_id {
                    mutate(row);
                    self.active_channel_cache.clear();
                    return true;
                }
            }
        }
        false
    }

    /// Execute a CISO forensic investigation query combining `48`-byte pure-$\mathbb{G}_1$ shares
    /// ($S_{\text{ACU}} + S_{\text{Archive}}$ -> `1` pairing) + `0x647A` `archive_acu_sk` PQ capsule
    /// strictly in RAM (`Verify-Before-Decrypt`).
    pub fn ciso_investigate_and_decrypt(
        &self,
        filter: &ArchiveSearchFilter,
        investigation_ticket: &str,
        ciso_acu: &mut CisoAcuFatClient,
        archive_ed25519_sk: &SigningKey,
        archive_acu_sk: &SeatSecretKey,
        registry: &AllowedSignersRegistry,
    ) -> Result<Vec<DecryptedArchiveRecord>, AcuError> {
        let matching_rows = self.search_metadata(filter);
        let active_keys = registry.active_acu_keys();
        let mut out = Vec::with_capacity(matching_rows.len());

        for row in matching_rows {
            row.verify_row_signature(registry)?;

            let payload = EncryptedCiPayload::from_bytes(&row.acu_ciphertext)?;
            if payload.acu_ciphertext.policy_epoch != row.policy_epoch {
                return Err(AcuError::EpochMismatch {
                    expected: row.policy_epoch,
                    actual: payload.acu_ciphertext.policy_epoch,
                });
            }

            let acu_row = payload
                .acu_ciphertext
                .rows
                .iter()
                .find(|r| r.seat_id == DEFAULT_CISO_ACU_ID)
                .ok_or_else(|| AcuError::UnknownSeat(DEFAULT_CISO_ACU_ID.to_string()))?
                .clone();

            let archive_row = payload
                .acu_ciphertext
                .rows
                .iter()
                .find(|r| r.seat_id == DEFAULT_MESSAGE_ARCHIVE_ID)
                .ok_or_else(|| AcuError::UnknownSeat(DEFAULT_MESSAGE_ARCHIVE_ID.to_string()))?;

            let req = AcuShareRequest::create_signed(
                format!("forensic-{}-{}", investigation_ticket, row.message_id),
                DEFAULT_MESSAGE_ARCHIVE_ID,
                DEFAULT_CISO_ACU_ID,
                &filter.org_id,
                &row.task_id,
                payload.acu_ciphertext.policy_epoch,
                payload.acu_ciphertext.clone(),
                acu_row.clone(),
                row.timestamp_utc,
                archive_ed25519_sk,
            );
            let resp = ciso_acu.authorize_archive_investigation(
                &req,
                DEFAULT_MESSAGE_ARCHIVE_ID,
                investigation_ticket,
                registry,
            )?;
            resp.verify_by_agent(&acu_row, registry)?;

            let d_archive = acu_partial_decrypt_at_epoch(
                archive_row,
                archive_acu_sk,
                payload.acu_ciphertext.policy_epoch,
            );
            let plaintext = payload.decrypt_with_local_key(
                &[resp.partial_share, d_archive],
                archive_acu_sk,
                &active_keys,
            )?;

            out.push(DecryptedArchiveRecord {
                message_id: row.message_id.clone(),
                timestamp_utc: row.timestamp_utc,
                sender_seat: row.sender_seat.clone(),
                recipient_seat: row.recipient_seat.clone(),
                room: row.room.clone(),
                task_id: row.task_id.clone(),
                policy_epoch: row.policy_epoch,
                plaintext,
            });
        }

        Ok(out)
    }
}

/// Thread-safe handle wrapping [`AcuParquetArchiveStore`] and [`CisoAcuFatClient`] so the
/// local web workbench (`127.0.0.1:5487`) UI thread can offload blocking DuckDB R2 Range queries
/// and BLS12-381 pairing + `0x647A` KEM math onto a background OS thread.
#[derive(Clone)]
pub struct SharedFatClientArchiveHandle {
    store: Arc<Mutex<AcuParquetArchiveStore>>,
    ciso_acu: Arc<Mutex<CisoAcuFatClient>>,
}

impl SharedFatClientArchiveHandle {
    /// Wrap an archive store and CISO ACU fat client in a thread-safe handle.
    #[must_use]
    pub fn new(store: AcuParquetArchiveStore, ciso_acu: CisoAcuFatClient) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            ciso_acu: Arc::new(Mutex::new(ciso_acu)),
        }
    }

    /// Offload a metadata search + BLS12-381 pairing decryption investigation onto a dedicated
    /// background worker thread so the fat client's UI rendering thread never drops a frame.
    #[must_use]
    pub fn spawn_blocking_investigation(
        &self,
        filter: ArchiveSearchFilter,
        investigation_ticket: String,
        archive_ed25519_sk: SigningKey,
        archive_acu_sk: Arc<SeatSecretKey>,
        registry: AllowedSignersRegistry,
    ) -> JoinHandle<Result<Vec<DecryptedArchiveRecord>, AcuError>> {
        let store = Arc::clone(&self.store);
        let ciso_acu = Arc::clone(&self.ciso_acu);

        thread::spawn(move || {
            let store_guard = store
                .lock()
                .map_err(|_| AcuError::SerializationError("archive store mutex poisoned"))?;
            let mut acu_guard = ciso_acu
                .lock()
                .map_err(|_| AcuError::SerializationError("ciso acu mutex poisoned"))?;

            store_guard.ciso_investigate_and_decrypt(
                &filter,
                &investigation_ticket,
                &mut acu_guard,
                &archive_ed25519_sk,
                &archive_acu_sk,
                &registry,
            )
        })
    }

    /// Load a channel window via the thread-safe handle.
    pub fn load_channel_window(
        &self,
        org_id: &str,
        room: &str,
        before_timestamp_utc: Option<u64>,
        limit: usize,
    ) -> Result<(CacheHit, Vec<ArchivedMessageRow>), AcuError> {
        let mut store_guard = self
            .store
            .lock()
            .map_err(|_| AcuError::SerializationError("archive store mutex poisoned"))?;
        Ok(store_guard.load_channel_window(org_id, room, before_timestamp_utc, limit))
    }

    /// Append a signed message using the OS CSPRNG (`OsRng`).
    #[allow(clippy::too_many_arguments)]
    pub fn append_signed_message_os_rng(
        &self,
        partition: HivePartitionKey,
        message_id: impl Into<String>,
        timestamp_utc: u64,
        sender_seat: impl Into<String>,
        recipient_seat: impl Into<String>,
        room: impl Into<String>,
        task_id: impl Into<String>,
        plaintext: &[u8],
        sender_ed25519_sk: &SigningKey,
        registry: &AllowedSignersRegistry,
    ) -> Result<ArchivedMessageRow, AcuError> {
        let mut store_guard = self
            .store
            .lock()
            .map_err(|_| AcuError::SerializationError("archive store mutex poisoned"))?;
        store_guard.append_signed_message(
            partition,
            message_id,
            timestamp_utc,
            sender_seat,
            recipient_seat,
            room,
            task_id,
            plaintext,
            sender_ed25519_sk,
            registry,
            &mut OsRng,
        )
    }
}

fn is_safe_storage_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}
