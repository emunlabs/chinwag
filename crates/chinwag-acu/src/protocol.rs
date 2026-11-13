// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! CISO Fat-Client / `iroh` P2P (`chinwag-mesh`) Access Control Unit (`ACU`) protocol,
//! `.chinwag/allowed_signers` (`chinwag-config.git`) dual-key registry, CI/CD dual-signature
//! verification (`inner_commit` + `outer_envelope`), zero-$V_0$ dynamic policy evolution,
//! `AcuPolicySign` header verification, `request_id` replay fencing, and pure-$\mathbb{G}_1$
//! (`48 B`) partial-share issuance with tamper-evident audit logging.

use crate::AcuError;
use crate::acu::{
    AcuCiphertext, CiphertextRow, CoalitionInsertionRowShare, WarmForkRequest,
    acu_partial_decrypt_at_epoch, acu_verify_partial_share, emergency_lock_and_rerandomize,
    escalate_threshold, insert_authorized_seat, insert_sibling_key, revoke_and_rerandomize,
    verify_row_randomness_witness,
};
use crate::aead::{DEFAULT_MESSAGE_ARCHIVE_ID, EncryptedCiPayload, is_valid_metadata_token};
use crate::framing::{lp64_bytes, lp64_str};
use crate::keys::{SeatPublicKey, SeatSecretKey, is_valid_seat_id};
use crate::share::PartialDecryptionShare;
use bls12_381::{G1Affine, Scalar};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

/// Canonical `iroh` gossip/RPC mesh topic for ACU partial decryption requests.
pub const CHINWAG_MESH_TOPIC: &str = "chinwag-mesh";

/// Canonical CISO ACU identifier in `.chinwag/allowed_signers`.
pub const DEFAULT_CISO_ACU_ID: &str = "acu:98939834";

const INNER_COMMIT_DOMAIN: &[u8] = b"chinwag-git-inner-commit/v2";
const OUTER_ENVELOPE_DOMAIN: &[u8] = b"chinwag-pr-outer-envelope/v2";
const ACU_POLICY_SIGN_DOMAIN: &[u8] = b"chinwag.acu.v2.policy-sign";
const ACU_SHARE_REQ_DOMAIN: &[u8] = b"chinwag-iroh-acu-share-req/v3";
const ACU_SHARE_RESP_DOMAIN: &[u8] = b"chinwag-iroh-acu-share-resp/v3";
const ACU_AUDIT_DOMAIN: &[u8] = b"chinwag-acu-audit/v3";

/// Verified entry from `.chinwag/allowed_signers` in `chinwag-config.git` (Artifacts)
/// binding a seat's Ed25519 identity key to its BLS12-381 $\mathbb{G}_1$ + `0x647A` PQ ACU public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedSignerRecord {
    /// Seat or ACU identifier (e.g., `"branch:8687872"` or `"acu:98939834"`).
    pub seat_id: String,
    /// Ed25519 verifying key for Git commit and `iroh` P2P message authentication.
    pub ed25519_verifying_key: VerifyingKey,
    /// Self-generated BLS12-381 $\mathbb{G}_1$ + `0x647A` PQ ACU public key with Schnorr PoP.
    pub acu_public_key: SeatPublicKey,
    /// Whether this seat has been revoked in `.chinwag/allowed_signers`.
    pub revoked: bool,
}

/// In-memory representation of `.chinwag/allowed_signers` from `chinwag-config.git`.
#[derive(Clone, Debug, Default)]
pub struct AllowedSignersRegistry {
    records: BTreeMap<String, AllowedSignerRecord>,
}

impl AllowedSignersRegistry {
    /// Create an empty `.chinwag/allowed_signers` registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a seat's Ed25519 verifying key and BLS12-381 + `0x647A` ACU public key after
    /// enforcing the ALISTAIR Schnorr Proof-of-Possession + FIPS 203 / Lim-Lee subgroup gates.
    pub fn register_seat(
        &mut self,
        seat_id: impl Into<String>,
        ed25519_verifying_key: VerifyingKey,
        acu_public_key: SeatPublicKey,
    ) -> Result<(), AcuError> {
        let seat_id = seat_id.into();
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        if acu_public_key.seat_id != seat_id || !acu_public_key.verify_consistency() {
            return Err(AcuError::InvalidPublicKey(seat_id));
        }
        self.records.insert(
            seat_id.clone(),
            AllowedSignerRecord {
                seat_id,
                ed25519_verifying_key,
                acu_public_key,
                revoked: false,
            },
        );
        Ok(())
    }

    /// Mark a seat as revoked in `.chinwag/allowed_signers`.
    pub fn revoke_seat(&mut self, seat_id: &str) -> Result<(), AcuError> {
        let rec = self
            .records
            .get_mut(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.to_string()))?;
        rec.revoked = true;
        Ok(())
    }

    /// Look up an active (non-revoked) signer record in `.chinwag/allowed_signers`.
    pub fn get_active(&self, seat_id: &str) -> Result<&AllowedSignerRecord, AcuError> {
        let rec = self
            .records
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.to_string()))?;
        if rec.revoked {
            return Err(AcuError::SeatRevoked(seat_id.to_string()));
        }
        Ok(rec)
    }

    /// Look up any signer record (including historical/revoked seats for forensic signature
    /// verification of pre-revocation archived messages) in `.chinwag/allowed_signers`.
    pub fn get_any(&self, seat_id: &str) -> Result<&AllowedSignerRecord, AcuError> {
        self.records
            .get(seat_id)
            .ok_or_else(|| AcuError::UnknownSeat(seat_id.to_string()))
    }

    /// Export all active BLS12-381 + `0x647A` public keys as a directory map for ACU operations.
    #[must_use]
    pub fn active_acu_keys(&self) -> BTreeMap<String, SeatPublicKey> {
        self.records
            .iter()
            .filter(|(_, rec)| !rec.revoked)
            .map(|(k, rec)| (k.clone(), rec.acu_public_key.clone()))
            .collect()
    }
}

/// Detached Ed25519 header authentication (`AcuPolicySign`, `ePrint v2` §6.2) over an
/// [`AcuCiphertext`]'s canonical `object_digest`, `policy_epoch`, and serialized header digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcuPolicySignature {
    /// Registered seat ID in `.chinwag/allowed_signers` that signed this policy header.
    pub signer_seat_id: String,
    /// Ed25519 signature bytes (`64` B).
    #[serde(with = "crate::framing::serde_bytes64")]
    pub signature: [u8; 64],
}

impl AcuPolicySignature {
    /// Sign `acu_ciphertext`'s canonical header digest under `signing_key`.
    #[must_use]
    pub fn sign(
        signer_seat_id: impl Into<String>,
        acu_ciphertext: &AcuCiphertext,
        signing_key: &SigningKey,
    ) -> Self {
        let signer_seat_id = signer_seat_id.into();
        let preimage = Self::canonical_preimage(&signer_seat_id, acu_ciphertext);
        let sig: Signature = signing_key.sign(&preimage);
        Self {
            signer_seat_id,
            signature: sig.to_bytes(),
        }
    }

    /// Verify this `AcuPolicySignature` against `acu_ciphertext` and `.chinwag/allowed_signers`.
    pub fn verify(
        &self,
        acu_ciphertext: &AcuCiphertext,
        registry: &AllowedSignersRegistry,
    ) -> Result<(), AcuError> {
        if !is_valid_seat_id(&self.signer_seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        let rec = registry.get_any(&self.signer_seat_id)?;
        let preimage = Self::canonical_preimage(&self.signer_seat_id, acu_ciphertext);
        let sig = Signature::from_bytes(&self.signature);
        rec.ed25519_verifying_key
            .verify_strict(&preimage, &sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("acu_policy_signature"))
    }

    fn canonical_preimage(signer_seat_id: &str, acu_ciphertext: &AcuCiphertext) -> Vec<u8> {
        let ct_bytes = acu_ciphertext.to_bytes();
        let header_digest = Sha256::digest(&ct_bytes);
        let mut out = Vec::with_capacity(ACU_POLICY_SIGN_DOMAIN.len() + 64 + 32 + 8 + 32);
        out.extend_from_slice(ACU_POLICY_SIGN_DOMAIN);
        lp64_str(&mut out, signer_seat_id);
        out.extend_from_slice(&acu_ciphertext.object_digest);
        out.extend_from_slice(&acu_ciphertext.policy_epoch.to_be_bytes());
        out.extend_from_slice(&header_digest);
        out
    }
}

/// Dual-signed PR submission sent by an agent (e.g., `"branch:8687872"`) to the CI/CD runner.
/// Carries both the inner Git commit signature and the outer PR envelope signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAgentPrSubmission {
    /// Submitting agent seat ID (e.g., `"branch:8687872"`).
    pub agent_seat_id: String,
    /// Target repository identifier (e.g., `"emunlabs/chinwag"`).
    pub repo_id: String,
    /// Pull request reference (e.g., `"refs/pull/108/head"`).
    pub pr_ref: String,
    /// Git commit OID hex string.
    pub commit_oid: String,
    /// Canonical Git commit payload bytes covered by `inner_commit_signature`.
    pub inner_commit_payload: Vec<u8>,
    /// Ed25519 signature over the inner Git commit payload.
    pub inner_commit_signature: [u8; 64],
    /// Fresh 256-bit anti-replay nonce for the outer PR transport envelope.
    pub outer_envelope_nonce: [u8; 32],
    /// Ed25519 signature over the outer PR envelope binding `inner_commit_signature`.
    pub outer_envelope_signature: [u8; 64],
}

impl SignedAgentPrSubmission {
    /// Sign both the inner commit payload and outer PR transport envelope with the agent's Ed25519 key.
    #[must_use]
    pub fn create_signed(
        agent_seat_id: impl Into<String>,
        repo_id: impl Into<String>,
        pr_ref: impl Into<String>,
        commit_oid: impl Into<String>,
        inner_commit_payload: Vec<u8>,
        outer_envelope_nonce: [u8; 32],
        agent_ed25519_sk: &SigningKey,
    ) -> Self {
        let agent_seat_id = agent_seat_id.into();
        let repo_id = repo_id.into();
        let pr_ref = pr_ref.into();
        let commit_oid = commit_oid.into();

        let inner_preimage =
            Self::inner_preimage(&agent_seat_id, &repo_id, &commit_oid, &inner_commit_payload);
        let inner_sig: Signature = agent_ed25519_sk.sign(&inner_preimage);
        let inner_commit_signature = inner_sig.to_bytes();

        let outer_preimage = Self::outer_preimage(
            &agent_seat_id,
            &repo_id,
            &pr_ref,
            &commit_oid,
            &inner_commit_signature,
            &outer_envelope_nonce,
        );
        let outer_sig: Signature = agent_ed25519_sk.sign(&outer_preimage);
        let outer_envelope_signature = outer_sig.to_bytes();

        Self {
            agent_seat_id,
            repo_id,
            pr_ref,
            commit_oid,
            inner_commit_payload,
            inner_commit_signature,
            outer_envelope_nonce,
            outer_envelope_signature,
        }
    }

    /// Validate both the inner commit signature and the outer envelope signature against
    /// the agent's Ed25519 public key in `.chinwag/allowed_signers`.
    pub fn verify_dual_signatures(
        &self,
        registry: &AllowedSignersRegistry,
    ) -> Result<(), AcuError> {
        if !is_valid_seat_id(&self.agent_seat_id)
            || !is_valid_metadata_token(&self.repo_id)
            || !is_valid_metadata_token(&self.pr_ref)
            || !is_valid_metadata_token(&self.commit_oid)
        {
            return Err(AcuError::InvalidMetadata);
        }
        let record = registry.get_active(&self.agent_seat_id)?;
        let vk = &record.ed25519_verifying_key;

        let inner_sig = Signature::from_bytes(&self.inner_commit_signature);
        let inner_preimage = Self::inner_preimage(
            &self.agent_seat_id,
            &self.repo_id,
            &self.commit_oid,
            &self.inner_commit_payload,
        );
        vk.verify_strict(&inner_preimage, &inner_sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("inner_commit"))?;

        let outer_sig = Signature::from_bytes(&self.outer_envelope_signature);
        let outer_preimage = Self::outer_preimage(
            &self.agent_seat_id,
            &self.repo_id,
            &self.pr_ref,
            &self.commit_oid,
            &self.inner_commit_signature,
            &self.outer_envelope_nonce,
        );
        vk.verify_strict(&outer_preimage, &outer_sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("outer_envelope"))?;

        Ok(())
    }

    fn inner_preimage(
        agent_seat_id: &str,
        repo_id: &str,
        commit_oid: &str,
        inner_commit_payload: &[u8],
    ) -> Vec<u8> {
        let payload_hash = Sha256::digest(inner_commit_payload);
        let mut out = Vec::with_capacity(INNER_COMMIT_DOMAIN.len() + 128 + 32);
        out.extend_from_slice(INNER_COMMIT_DOMAIN);
        lp64_str(&mut out, agent_seat_id);
        lp64_str(&mut out, repo_id);
        lp64_str(&mut out, commit_oid);
        out.extend_from_slice(&payload_hash);
        out
    }

    fn outer_preimage(
        agent_seat_id: &str,
        repo_id: &str,
        pr_ref: &str,
        commit_oid: &str,
        inner_commit_signature: &[u8; 64],
        outer_envelope_nonce: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(OUTER_ENVELOPE_DOMAIN.len() + 160 + 96);
        out.extend_from_slice(OUTER_ENVELOPE_DOMAIN);
        lp64_str(&mut out, agent_seat_id);
        lp64_str(&mut out, repo_id);
        lp64_str(&mut out, pr_ref);
        lp64_str(&mut out, commit_oid);
        out.extend_from_slice(inner_commit_signature);
        out.extend_from_slice(outer_envelope_nonce);
        out
    }
}

/// CI/CD Runner Gate:
/// 1. Looks up the submitting agent (`branch:8687872`) and CISO ACU (`acu:98939834`) in
///    `chinwag-config.git` (`.chinwag/allowed_signers` in Artifacts).
/// 2. Validates BOTH the inner Git commit signature and the outer PR envelope signature.
/// 3. Encrypts the failed CI root-cause alert under the `2-of-2` Split-Key policy
///    (`agent_seat_id AND acu_seat_id`) using `CHWGACU3` + `CHWGAEA2` (`0` $V_0$ backdoor).
pub fn ci_validate_and_encrypt_root_cause(
    submission: &SignedAgentPrSubmission,
    acu_seat_id: &str,
    registry: &AllowedSignersRegistry,
    root_cause_plaintext: &[u8],
    task_id: &str,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EncryptedCiPayload, AcuError> {
    submission.verify_dual_signatures(registry)?;
    let agent_rec = registry.get_active(&submission.agent_seat_id)?;
    let acu_rec = registry.get_active(acu_seat_id)?;

    EncryptedCiPayload::encrypt_split_key_with_acu(
        root_cause_plaintext,
        &agent_rec.acu_public_key,
        &acu_rec.acu_public_key,
        &submission.repo_id,
        task_id,
        rng,
    )
}

/// CI/CD Runner Gate with Zero-Plaintext-At-Rest Inbox & Forensic Archive (`ACU AND (Recipient OR Archive)`):
/// 1. Validates both the inner Git commit signature and the outer PR envelope signature against `.chinwag/allowed_signers`.
/// 2. Looks up the CISO ACU (`acu:98939834`), submitting Agent (`branch:8687872`), and Message Archive Unit (`archive:vault`).
/// 3. Encrypts the failed CI root-cause payload under `ACU AND (Agent OR Archive)` with zero-$V_0$ policy-matched
///    `SbcSlot`s and `0x647A` non-ACU LSSS-PQ (`CHWGACU3` + `CHWGAEA2`).
pub fn ci_validate_and_encrypt_with_acu_and_archive(
    submission: &SignedAgentPrSubmission,
    acu_seat_id: &str,
    archive_seat_id: &str,
    registry: &AllowedSignersRegistry,
    root_cause_plaintext: &[u8],
    task_id: &str,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EncryptedCiPayload, AcuError> {
    submission.verify_dual_signatures(registry)?;
    let acu_rec = registry.get_active(acu_seat_id)?;
    let agent_rec = registry.get_active(&submission.agent_seat_id)?;
    let archive_rec = registry.get_active(archive_seat_id)?;

    EncryptedCiPayload::encrypt_with_acu_and_archive(
        root_cause_plaintext,
        &acu_rec.acu_public_key,
        &agent_rec.acu_public_key,
        &archive_rec.acu_public_key,
        &submission.repo_id,
        task_id,
        rng,
    )
}

/// Request sent over the `iroh` P2P bus (`chinwag-mesh`) from a waking Agent (`branch:8687872`)
/// or Archive Unit (`archive:vault`) to the CISO's `chinwag` fat client (`acu:98939834`)
/// asking for a `48`-byte pure-$\mathbb{G}_1$ partial decryption share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcuShareRequest {
    /// Unique request identifier enforced against the durable `replay_fence`.
    pub request_id: String,
    /// `iroh` P2P topic (`"chinwag-mesh"`).
    pub iroh_topic: String,
    /// Requesting agent or archive seat ID (e.g., `"branch:8687872"` or `"archive:vault"`).
    pub requester_seat_id: String,
    /// Target CISO ACU seat ID (e.g., `"acu:98939834"`).
    pub acu_seat_id: String,
    /// Repository identifier.
    pub repo_id: String,
    /// CI/CD task identifier.
    pub task_id: String,
    /// Policy epoch of the ciphertext (`>= 1`).
    pub policy_epoch: u64,
    /// Full `CHWGACU3` header whose `RowPok` + `init_matrix_digest` / `acu_epoch_auth` bind every policy row.
    pub acu_ciphertext: AcuCiphertext,
    /// The ACU's ciphertext row from [`EncryptedCiPayload`].
    pub acu_row: CiphertextRow,
    /// Detached `AcuPolicySign` header signature over `acu_ciphertext`.
    pub policy_signature: Option<AcuPolicySignature>,
    /// Request timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Ed25519 signature over the canonical request bytes by `requester_seat_id`.
    pub requester_signature: [u8; 64],
}

impl AcuShareRequest {
    /// Create and sign an [`AcuShareRequest`] (including its `AcuPolicySign` header signature)
    /// to transmit over `iroh` (`chinwag-mesh`).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        request_id: impl Into<String>,
        requester_seat_id: impl Into<String>,
        acu_seat_id: impl Into<String>,
        repo_id: impl Into<String>,
        task_id: impl Into<String>,
        policy_epoch: u64,
        acu_ciphertext: AcuCiphertext,
        acu_row: CiphertextRow,
        timestamp_ms: u64,
        requester_ed25519_sk: &SigningKey,
    ) -> Self {
        let requester_seat_id = requester_seat_id.into();
        let policy_sig =
            AcuPolicySignature::sign(&requester_seat_id, &acu_ciphertext, requester_ed25519_sk);
        Self::create_signed_with_policy_sig(
            request_id,
            requester_seat_id,
            acu_seat_id,
            repo_id,
            task_id,
            policy_epoch,
            acu_ciphertext,
            acu_row,
            Some(policy_sig),
            timestamp_ms,
            requester_ed25519_sk,
        )
    }

    /// Create and sign an [`AcuShareRequest`] carrying an explicit `AcuPolicySignature`
    /// (for example signed earlier by a CI runner or `ACU` policy operator).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed_with_policy_sig(
        request_id: impl Into<String>,
        requester_seat_id: impl Into<String>,
        acu_seat_id: impl Into<String>,
        repo_id: impl Into<String>,
        task_id: impl Into<String>,
        policy_epoch: u64,
        acu_ciphertext: AcuCiphertext,
        acu_row: CiphertextRow,
        policy_signature: Option<AcuPolicySignature>,
        timestamp_ms: u64,
        requester_ed25519_sk: &SigningKey,
    ) -> Self {
        let request_id = request_id.into();
        let requester_seat_id = requester_seat_id.into();
        let acu_seat_id = acu_seat_id.into();
        let repo_id = repo_id.into();
        let task_id = task_id.into();
        let iroh_topic = CHINWAG_MESH_TOPIC.to_string();

        let preimage = Self::canonical_preimage(
            &request_id,
            &iroh_topic,
            &requester_seat_id,
            &acu_seat_id,
            &repo_id,
            &task_id,
            policy_epoch,
            &acu_ciphertext,
            &acu_row,
            policy_signature.as_ref(),
            timestamp_ms,
        );
        let sig: Signature = requester_ed25519_sk.sign(&preimage);

        Self {
            request_id,
            iroh_topic,
            requester_seat_id,
            acu_seat_id,
            repo_id,
            task_id,
            policy_epoch,
            acu_ciphertext,
            acu_row,
            policy_signature,
            timestamp_ms,
            requester_signature: sig.to_bytes(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn canonical_preimage(
        request_id: &str,
        iroh_topic: &str,
        requester_seat_id: &str,
        acu_seat_id: &str,
        repo_id: &str,
        task_id: &str,
        policy_epoch: u64,
        acu_ciphertext: &AcuCiphertext,
        acu_row: &CiphertextRow,
        policy_signature: Option<&AcuPolicySignature>,
        timestamp_ms: u64,
    ) -> Vec<u8> {
        let ct_bytes = acu_ciphertext.to_bytes();
        let mut out = Vec::with_capacity(ct_bytes.len() + 512);
        out.extend_from_slice(ACU_SHARE_REQ_DOMAIN);
        lp64_str(&mut out, request_id);
        lp64_str(&mut out, iroh_topic);
        lp64_str(&mut out, requester_seat_id);
        lp64_str(&mut out, acu_seat_id);
        lp64_str(&mut out, repo_id);
        lp64_str(&mut out, task_id);
        out.extend_from_slice(&policy_epoch.to_be_bytes());
        lp64_bytes(&mut out, &ct_bytes);
        out.extend_from_slice(&acu_row.object_digest);
        out.extend_from_slice(&(acu_row.row_index as u32).to_be_bytes());
        lp64_str(&mut out, &acu_row.seat_id);
        out.extend_from_slice(&acu_row.row_locator);
        out.extend_from_slice(&acu_row.oblivious_hint);
        out.extend_from_slice(&(acu_row.matrix_row.len() as u32).to_be_bytes());
        for s in &acu_row.matrix_row {
            out.extend_from_slice(&s.to_bytes());
        }
        out.extend_from_slice(&G1Affine::from(acu_row.c1).to_compressed());
        out.extend_from_slice(&G1Affine::from(acu_row.c2).to_compressed());
        out.extend_from_slice(&acu_row.row_pok.to_bytes());
        match policy_signature {
            Some(ps) => {
                out.push(1);
                lp64_str(&mut out, &ps.signer_seat_id);
                out.extend_from_slice(&ps.signature);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&timestamp_ms.to_be_bytes());
        out
    }
}

/// Audit decision recorded by the CISO's `chinwag` fat client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcuAuditDecision {
    /// Partial decryption share $S_{\text{ACU}} \in \mathbb{G}_1$ was issued to the requesting live agent/human.
    Granted,
    /// Partial decryption share $S_{\text{ACU}} \in \mathbb{G}_1$ was issued to the Message Archive Unit (`archive:vault`)
    /// for a CISO-authorized forensic investigation.
    GrantedArchiveInvestigation,
    /// Request was denied (e.g., seat revoked, policy mismatch, replay conflict, or invalid proof/signature).
    Denied,
}

impl AcuAuditDecision {
    const fn canonical_tag(self) -> u8 {
        match self {
            Self::Granted => 0x01,
            Self::GrantedArchiveInvestigation => 0x02,
            Self::Denied => 0x03,
        }
    }
}

/// Tamper-evident audit log record persisted by the CISO's `chinwag` fat client for every
/// ACU partial decryption request over `iroh` (`chinwag-mesh`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Request identifier.
    pub request_id: String,
    /// Requesting agent seat ID.
    pub requester_seat_id: String,
    /// CISO ACU seat ID.
    pub acu_seat_id: String,
    /// Repository identifier.
    pub repo_id: String,
    /// Task identifier.
    pub task_id: String,
    /// Policy epoch.
    pub policy_epoch: u64,
    /// Grant or deny outcome.
    pub decision: AcuAuditDecision,
    /// Human-readable reason for the audit record.
    pub reason: String,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// SHA-256 digest of the canonical audit entry (`0` `Debug` formatting).
    pub entry_sha256: [u8; 32],
}

impl AuditLogEntry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_entry_sha256(
        request_id: &str,
        requester_seat_id: &str,
        acu_seat_id: &str,
        repo_id: &str,
        task_id: &str,
        policy_epoch: u64,
        decision: AcuAuditDecision,
        reason: &str,
        timestamp_ms: u64,
    ) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(256);
        preimage.extend_from_slice(ACU_AUDIT_DOMAIN);
        lp64_str(&mut preimage, request_id);
        lp64_str(&mut preimage, requester_seat_id);
        lp64_str(&mut preimage, acu_seat_id);
        lp64_str(&mut preimage, repo_id);
        lp64_str(&mut preimage, task_id);
        preimage.extend_from_slice(&policy_epoch.to_be_bytes());
        preimage.push(decision.canonical_tag());
        lp64_str(&mut preimage, reason);
        preimage.extend_from_slice(&timestamp_ms.to_be_bytes());
        Sha256::digest(&preimage).into()
    }
}

/// Signed response sent over `iroh` (`chinwag-mesh`) from the CISO's `chinwag` fat client
/// back to the waking agent or archive unit, carrying the `48`-byte pure-$\mathbb{G}_1$
/// partial share $S_{\text{ACU}}$, its Chaum–Pedersen DLEQ proof, and the [`AuditLogEntry`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcuShareResponse {
    /// Request identifier matching [`AcuShareRequest::request_id`].
    pub request_id: String,
    /// CISO ACU seat identifier (`"acu:98939834"`).
    pub acu_seat_id: String,
    /// Requesting agent or archive seat identifier (`"branch:8687872"` or `"archive:vault"`).
    pub requester_seat_id: String,
    /// Policy epoch at which $S_{\text{ACU}}$ was computed.
    pub policy_epoch: u64,
    /// The ACU's `48`-byte pure-$\mathbb{G}_1$ partial decryption share + DLEQ proof (`CHWGSHR2`).
    pub partial_share: PartialDecryptionShare,
    /// Audit log entry generated for this transaction.
    pub audit_entry: AuditLogEntry,
    /// Ed25519 signature by the CISO ACU fat client over the canonical response bytes.
    pub acu_signature: [u8; 64],
}

impl AcuShareResponse {
    /// Verify the CISO ACU's Ed25519 signature, constant-time audit-entry SHA-256 integrity, AND that
    /// `partial_share` ($S_{\text{ACU}} \in \mathbb{G}_1$) matches `policy_epoch` and satisfies the
    /// pure-$\mathbb{G}_1$ Chaum–Pedersen DLEQ proof (`0` pairings!) against `acu_row` and `acu_pk`.
    pub fn verify_by_agent(
        &self,
        acu_row: &CiphertextRow,
        registry: &AllowedSignersRegistry,
    ) -> Result<(), AcuError> {
        if self.policy_epoch == 0 || self.partial_share.policy_epoch != self.policy_epoch {
            return Err(AcuError::EpochMismatch {
                expected: self.policy_epoch,
                actual: self.partial_share.policy_epoch,
            });
        }
        if acu_row.seat_id != self.acu_seat_id {
            return Err(AcuError::InvalidPartialShare {
                row_index: acu_row.row_index,
                seat_id: acu_row.seat_id.clone(),
            });
        }
        if self.audit_entry.request_id != self.request_id
            || self.audit_entry.acu_seat_id != self.acu_seat_id
            || self.audit_entry.requester_seat_id != self.requester_seat_id
            || self.audit_entry.policy_epoch != self.policy_epoch
        {
            return Err(AcuError::SignatureVerificationFailed("audit_entry"));
        }
        let expected_audit_sha256 = AuditLogEntry::compute_entry_sha256(
            &self.audit_entry.request_id,
            &self.audit_entry.requester_seat_id,
            &self.audit_entry.acu_seat_id,
            &self.audit_entry.repo_id,
            &self.audit_entry.task_id,
            self.audit_entry.policy_epoch,
            self.audit_entry.decision,
            &self.audit_entry.reason,
            self.audit_entry.timestamp_ms,
        );
        if !bool::from(self.audit_entry.entry_sha256.ct_eq(&expected_audit_sha256)) {
            return Err(AcuError::SignatureVerificationFailed("audit_entry"));
        }
        let acu_rec = registry.get_active(&self.acu_seat_id)?;
        let preimage = Self::canonical_preimage(
            &self.request_id,
            &self.acu_seat_id,
            &self.requester_seat_id,
            self.policy_epoch,
            &self.partial_share,
            &self.audit_entry.entry_sha256,
        );
        let sig = Signature::from_bytes(&self.acu_signature);
        acu_rec
            .ed25519_verifying_key
            .verify_strict(&preimage, &sig)
            .map_err(|_| AcuError::SignatureVerificationFailed("acu_share_response"))?;

        if !acu_verify_partial_share(acu_row, &acu_rec.acu_public_key, &self.partial_share) {
            return Err(AcuError::InvalidPartialShare {
                row_index: self.partial_share.row_index,
                seat_id: self.acu_seat_id.clone(),
            });
        }
        Ok(())
    }

    fn canonical_preimage(
        request_id: &str,
        acu_seat_id: &str,
        requester_seat_id: &str,
        policy_epoch: u64,
        partial_share: &PartialDecryptionShare,
        audit_sha256: &[u8; 32],
    ) -> Vec<u8> {
        let share_bytes = partial_share.to_bytes();
        let mut out = Vec::with_capacity(share_bytes.len() + 256);
        out.extend_from_slice(ACU_SHARE_RESP_DOMAIN);
        lp64_str(&mut out, request_id);
        lp64_str(&mut out, acu_seat_id);
        lp64_str(&mut out, requester_seat_id);
        out.extend_from_slice(&policy_epoch.to_be_bytes());
        lp64_bytes(&mut out, &share_bytes);
        out.extend_from_slice(audit_sha256);
        out
    }
}

/// CISO `chinwag` Fat Client hosting the ACU secret key (`sk_ACU`, e.g., `"acu:98939834"`)
/// on the `iroh` P2P mesh (`chinwag-mesh`).
pub struct CisoAcuFatClient {
    acu_sk: SeatSecretKey,
    acu_pk: SeatPublicKey,
    acu_ed25519_sk: SigningKey,
    revoked_seats: BTreeSet<String>,
    archive_seats: BTreeSet<String>,
    replay_fence: BTreeMap<String, ([u8; 32], AcuShareResponse)>,
    audit_log: Vec<AuditLogEntry>,
}

impl CisoAcuFatClient {
    /// Initialize a new CISO ACU fat client with its BLS12-381 + `0x647A` keypair and Ed25519 signing key.
    #[must_use]
    pub fn new(acu_sk: SeatSecretKey, acu_pk: SeatPublicKey, acu_ed25519_sk: SigningKey) -> Self {
        let mut archive_seats = BTreeSet::new();
        archive_seats.insert(DEFAULT_MESSAGE_ARCHIVE_ID.to_string());
        Self {
            acu_sk,
            acu_pk,
            acu_ed25519_sk,
            revoked_seats: BTreeSet::new(),
            archive_seats,
            replay_fence: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }

    /// Register an Archive Unit seat identifier that is restricted exclusively to
    /// [`CisoAcuFatClient::authorize_archive_investigation`] (requiring a forensic ticket)
    /// and blocked from live [`CisoAcuFatClient::handle_iroh_share_request`].
    pub fn register_archive_seat(&mut self, seat_id: impl Into<String>) {
        self.archive_seats.insert(seat_id.into());
    }

    /// Borrow the ACU operator's secret key for authorized policy evolution (`CHWG-0283`).
    #[must_use]
    pub fn acu_secret_key(&self) -> &SeatSecretKey {
        &self.acu_sk
    }

    /// Borrow the ACU operator's public key.
    #[must_use]
    pub fn acu_public_key(&self) -> &SeatPublicKey {
        &self.acu_pk
    }

    /// Instant CISO revocation on the fat client: immediately blocks any future partial
    /// decryption share issuance for `seat_id` over `iroh` (`chinwag-mesh`).
    pub fn instant_revoke(&mut self, seat_id: impl Into<String>) {
        self.revoked_seats.insert(seat_id.into());
    }

    /// Return the append-only audit log of all granted and denied `iroh` ACU share requests.
    #[must_use]
    pub fn audit_log(&self) -> &[AuditLogEntry] {
        &self.audit_log
    }

    /// Coalition-authorized general seat insertion (`ePrint v2` §6.3 Op 3): reconstructs $V_0^{(E)}$
    /// live in $\mathbb{G}_1$ from verified coalition shares (`0` pairings, never recovering $K_{\mathbb{G}_T}$),
    /// enforces non-ACU span exclusion, inserts `(new_seat_id, new_row)`, and compacts `sbc_slots`.
    pub fn insert_authorized_seat(
        &self,
        ct: &mut AcuCiphertext,
        new_seat_id: impl Into<String>,
        new_row: Vec<Scalar>,
        coalition: &[CoalitionInsertionRowShare],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<usize, AcuError> {
        insert_authorized_seat(
            ct,
            &self.acu_sk,
            new_seat_id,
            new_row,
            coalition,
            seat_keys,
            rng,
        )
    }

    /// Attach a `Shadow-KV` warm-fork `OR` sibling leaf verified jointly by `self.acu_sk` and a
    /// custodian-issued [`WarmForkRequest`] (preserving strict `ACU`-blindness).
    pub fn insert_sibling_key(
        &self,
        ct: &mut AcuCiphertext,
        warm_fork: &WarmForkRequest,
        seat_keys: &BTreeMap<String, SeatPublicKey>,
    ) -> Result<usize, AcuError> {
        insert_sibling_key(ct, &self.acu_sk, warm_fork, seat_keys)
    }

    /// Homomorphically escalate a gate threshold by `delta_t` with subtree-consistent Vandermonde
    /// evaluation points $x_{g,c}$ AND simultaneous $\Delta v$ rerandomization (`0` $V_0$ unsealing).
    pub fn escalate_threshold(
        &self,
        ct: &mut AcuCiphertext,
        affected_row_indices: &[usize],
        delta_t: usize,
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), AcuError> {
        escalate_threshold(
            ct,
            &self.acu_sk,
            affected_row_indices,
            delta_t,
            seat_keys,
            rng,
        )
    }

    /// Homomorphically prune `revoked_seat_ids` and rerandomize `c0_g1`, `sbc_slots`, and all surviving
    /// rows at `policy_epoch + 1`, refusing `2-of-2` self-lockout (`AcuError::PolicyUnsatisfiableAfterRevocation`).
    pub fn revoke_and_rerandomize(
        &self,
        ct: &mut AcuCiphertext,
        revoked_seat_ids: &[&str],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), AcuError> {
        revoke_and_rerandomize(ct, &self.acu_sk, revoked_seat_ids, seat_keys, rng)
    }

    /// Explicit CISO kill-switch lockout & rerandomization on a `2-of-2` split-key ciphertext.
    pub fn emergency_lock_and_rerandomize(
        &self,
        ct: &mut AcuCiphertext,
        revoked_seat_ids: &[&str],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(), AcuError> {
        emergency_lock_and_rerandomize(ct, &self.acu_sk, revoked_seat_ids, seat_keys, rng)
    }

    /// Process an inbound live [`AcuShareRequest`] over the `iroh` P2P bus (`chinwag-mesh`).
    pub fn handle_iroh_share_request(
        &mut self,
        req: &AcuShareRequest,
        registry: &AllowedSignersRegistry,
    ) -> Result<AcuShareResponse, AcuError> {
        if self.archive_seats.contains(&req.requester_seat_id) {
            self.record_audit(
                req,
                AcuAuditDecision::Denied,
                "archive_seat_requires_investigation_ticket",
            );
            return Err(AcuError::InvalidMetadata);
        }
        self.process_share_request_internal(req, registry, AcuAuditDecision::Granted, "ok")
    }

    /// Authorize a forensic archive investigation (`ACU + Archive Unit`) over `iroh` (`chinwag-mesh`).
    pub fn authorize_archive_investigation(
        &mut self,
        req: &AcuShareRequest,
        expected_archive_seat_id: &str,
        investigation_ticket: &str,
        registry: &AllowedSignersRegistry,
    ) -> Result<AcuShareResponse, AcuError> {
        if !is_valid_metadata_token(investigation_ticket) {
            self.record_audit(
                req,
                AcuAuditDecision::Denied,
                "missing_investigation_ticket",
            );
            return Err(AcuError::InvalidMetadata);
        }
        if req.requester_seat_id != expected_archive_seat_id
            || !self.archive_seats.contains(&req.requester_seat_id)
        {
            self.record_audit(req, AcuAuditDecision::Denied, "requester_not_archive_unit");
            return Err(AcuError::UnknownSeat(req.requester_seat_id.clone()));
        }
        let mut reason = String::from("forensic_investigation:");
        reason.push_str(investigation_ticket);
        self.process_share_request_internal(
            req,
            registry,
            AcuAuditDecision::GrantedArchiveInvestigation,
            &reason,
        )
    }

    fn process_share_request_internal(
        &mut self,
        req: &AcuShareRequest,
        registry: &AllowedSignersRegistry,
        grant_decision: AcuAuditDecision,
        grant_reason: &str,
    ) -> Result<AcuShareResponse, AcuError> {
        if req.iroh_topic != CHINWAG_MESH_TOPIC
            || req.policy_epoch == 0
            || !is_valid_metadata_token(&req.request_id)
            || !is_valid_metadata_token(&req.repo_id)
            || !is_valid_metadata_token(&req.task_id)
        {
            self.record_audit(req, AcuAuditDecision::Denied, "invalid_iroh_metadata");
            return Err(AcuError::InvalidMetadata);
        }
        if req.acu_seat_id != self.acu_pk.seat_id || req.acu_row.seat_id != self.acu_pk.seat_id {
            self.record_audit(req, AcuAuditDecision::Denied, "acu_seat_mismatch");
            return Err(AcuError::UnknownSeat(req.acu_seat_id.clone()));
        }

        // 1. Check local fat-client revocation list FIRST (before replay_fence!).
        if self.revoked_seats.contains(&req.requester_seat_id) {
            self.record_audit(req, AcuAuditDecision::Denied, "revoked_by_ciso_fat_client");
            return Err(AcuError::SeatRevoked(req.requester_seat_id.clone()));
        }

        // 2. Check .chinwag/allowed_signers registry status and requester Ed25519 signature.
        let requester_rec = match registry.get_active(&req.requester_seat_id) {
            Ok(rec) => rec,
            Err(err) => {
                self.record_audit(
                    req,
                    AcuAuditDecision::Denied,
                    "revoked_or_unknown_in_allowed_signers",
                );
                return Err(err);
            }
        };

        let preimage = AcuShareRequest::canonical_preimage(
            &req.request_id,
            &req.iroh_topic,
            &req.requester_seat_id,
            &req.acu_seat_id,
            &req.repo_id,
            &req.task_id,
            req.policy_epoch,
            &req.acu_ciphertext,
            &req.acu_row,
            req.policy_signature.as_ref(),
            req.timestamp_ms,
        );
        let req_sig = Signature::from_bytes(&req.requester_signature);
        if requester_rec
            .ed25519_verifying_key
            .verify_strict(&preimage, &req_sig)
            .is_err()
        {
            self.record_audit(
                req,
                AcuAuditDecision::Denied,
                "invalid_requester_ed25519_signature",
            );
            return Err(AcuError::SignatureVerificationFailed("acu_share_request"));
        }

        // 3. Enforce detached `AcuPolicySign` header verification (`ePrint v2` §6.2).
        let Some(ref policy_sig) = req.policy_signature else {
            self.record_audit(
                req,
                AcuAuditDecision::Denied,
                "missing_acu_policy_signature",
            );
            return Err(AcuError::SignatureVerificationFailed(
                "acu_policy_signature",
            ));
        };
        if let Err(err) = policy_sig.verify(&req.acu_ciphertext, registry) {
            self.record_audit(
                req,
                AcuAuditDecision::Denied,
                "invalid_acu_policy_signature",
            );
            return Err(err);
        }

        // 4. Verify pure-G1 row-randomness PoK chain (`RowPok` + `RowUpdateProof`) on `req.acu_row`
        // BEFORE applying `self.acu_sk` (blocks cross-object `c2` copy oracle attacks!).
        if !verify_row_randomness_witness(&req.acu_row, &self.acu_pk) {
            self.record_audit(req, AcuAuditDecision::Denied, "invalid_acu_row_witness");
            return Err(AcuError::InvalidRowPok);
        }

        // 5. Authenticate full `CHWGACU3` header, `init_matrix_digest` / `acu_epoch_auth`, and all
        // policy/SBC row randomness proofs (blocks same-epoch cut-and-paste row splicing!).
        if req.acu_ciphertext.policy_epoch != req.policy_epoch
            || req.acu_ciphertext.rows.get(req.acu_row.row_index) != Some(&req.acu_row)
        {
            self.record_audit(
                req,
                AcuAuditDecision::Denied,
                "unauthenticated_or_tampered_acu_ciphertext",
            );
            return Err(AcuError::BasisUnsealFailed);
        }
        if let Err(err) = req
            .acu_ciphertext
            .verify_authenticity(&self.acu_pk, |seat_id| {
                registry
                    .get_any(seat_id)
                    .ok()
                    .map(|rec| &rec.acu_public_key)
            })
        {
            match err {
                AcuError::InvalidRowPok => {
                    self.record_audit(req, AcuAuditDecision::Denied, "invalid_acu_row_witness");
                    return Err(AcuError::InvalidRowPok);
                }
                _ => {
                    self.record_audit(
                        req,
                        AcuAuditDecision::Denied,
                        "unauthenticated_or_tampered_acu_ciphertext",
                    );
                    return Err(AcuError::BasisUnsealFailed);
                }
            }
        }

        // 6. Require requester_seat_id to be an explicit non-ACU member of the authenticated LSSS policy.
        let requester_in_policy = req
            .acu_ciphertext
            .rows
            .iter()
            .any(|r| r.seat_id == req.requester_seat_id && r.seat_id != self.acu_pk.seat_id);
        if !requester_in_policy {
            self.record_audit(
                req,
                AcuAuditDecision::Denied,
                "requester_not_in_ciphertext_policy",
            );
            return Err(AcuError::PolicyNotSatisfied);
        }

        // 7. On live requests, refuse share issuance if ANY policy row belongs to an unpruned revoked seat.
        if grant_decision == AcuAuditDecision::Granted {
            for row in &req.acu_ciphertext.rows {
                let registry_revoked = registry.get_any(&row.seat_id).is_ok_and(|rec| rec.revoked);
                if self.revoked_seats.contains(&row.seat_id) || registry_revoked {
                    self.record_audit(
                        req,
                        AcuAuditDecision::Denied,
                        "ciphertext_contains_unpruned_revoked_seat",
                    );
                    return Err(AcuError::SeatRevoked(row.seat_id.clone()));
                }
            }
        }

        // 8. Enforce durable `request_id` replay fence AFTER revocation checks (`tombstone-acu-replay-fence-before-revocation-v1`).
        let req_digest: [u8; 32] = Sha256::digest(&preimage).into();
        if let Some((seen_digest, cached_resp)) = self.replay_fence.get(&req.request_id) {
            if !bool::from(seen_digest.ct_eq(&req_digest)) {
                self.record_audit(req, AcuAuditDecision::Denied, "request_id_replay_conflict");
                return Err(AcuError::ReplayConflict);
            }
            return Ok(cached_resp.clone());
        }

        // 9. Emit `48`-byte pure-G1 partial decryption share + Mode-A Chaum-Pedersen DLEQ proof (`0` pairings!).
        let partial_share =
            acu_partial_decrypt_at_epoch(&req.acu_row, &self.acu_sk, req.policy_epoch);
        let audit_entry = self.record_audit(req, grant_decision, grant_reason);

        let resp_preimage = AcuShareResponse::canonical_preimage(
            &req.request_id,
            &self.acu_pk.seat_id,
            &req.requester_seat_id,
            req.policy_epoch,
            &partial_share,
            &audit_entry.entry_sha256,
        );
        let acu_sig: Signature = self.acu_ed25519_sk.sign(&resp_preimage);

        let response = AcuShareResponse {
            request_id: req.request_id.clone(),
            acu_seat_id: self.acu_pk.seat_id.clone(),
            requester_seat_id: req.requester_seat_id.clone(),
            policy_epoch: req.policy_epoch,
            partial_share,
            audit_entry,
            acu_signature: acu_sig.to_bytes(),
        };
        self.replay_fence
            .insert(req.request_id.clone(), (req_digest, response.clone()));
        Ok(response)
    }

    fn record_audit(
        &mut self,
        req: &AcuShareRequest,
        decision: AcuAuditDecision,
        reason: &str,
    ) -> AuditLogEntry {
        let entry_sha256 = AuditLogEntry::compute_entry_sha256(
            &req.request_id,
            &req.requester_seat_id,
            &req.acu_seat_id,
            &req.repo_id,
            &req.task_id,
            req.policy_epoch,
            decision,
            reason,
            req.timestamp_ms,
        );

        let entry = AuditLogEntry {
            request_id: req.request_id.clone(),
            requester_seat_id: req.requester_seat_id.clone(),
            acu_seat_id: req.acu_seat_id.clone(),
            repo_id: req.repo_id.clone(),
            task_id: req.task_id.clone(),
            policy_epoch: req.policy_epoch,
            decision,
            reason: reason.to_string(),
            timestamp_ms: req.timestamp_ms,
            entry_sha256,
        };
        self.audit_log.push(entry.clone());
        entry
    }
}
