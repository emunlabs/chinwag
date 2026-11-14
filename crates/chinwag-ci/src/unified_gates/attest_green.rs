// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Cryptographic green-build attestation (`chinwag-ci attest-green` -> `CiGreenReceiptV1`).

use super::EphemeralRunnerSigner;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signed green-build receipt (`CiGreenReceiptV1`).
///
/// A runner-signed observation records that a suite exited `0` at `commit_sha`;
/// downstream gates still verify required suite coverage and signer enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiGreenReceiptV1 {
    pub schema: String,
    pub org_id_hash: String,
    pub run_id: String,
    pub commit_sha: String,
    pub suite: String,
    pub target_triple: String,
    pub artifacts_git_ref: String,
    pub transcript_sha256: String,
    pub pk_ci_k1_hex: String,
    pub k1_signature_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k2_signature_hex: Option<String>,
}

impl CiGreenReceiptV1 {
    #[must_use]
    pub fn canonical_transcript_bytes(
        org_id_hash: &str,
        run_id: &str,
        commit_sha: &str,
        suite: &str,
        target_triple: &str,
        artifacts_git_ref: &str,
        pk_ci_k1_hex: &str,
    ) -> Vec<u8> {
        let mut out = b"chinwag-ci-green-receipt-v2\0".to_vec();
        for field in [
            org_id_hash,
            run_id,
            commit_sha,
            suite,
            target_triple,
            artifacts_git_ref,
            pk_ci_k1_hex,
        ] {
            let bytes = field.as_bytes();
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    pub fn build_signed(
        runner_signer: &EphemeralRunnerSigner,
        org_id_hash: &str,
        run_id: &str,
        commit_sha: &str,
        suite: &str,
        target_triple: &str,
        k2_coordinator_sk: Option<&SigningKey>,
    ) -> Result<Self, String> {
        let artifacts_git_ref = format!("refs/chinwag/ci/{run_id}");
        let pk_ci_k1_hex = runner_signer.public_key_hex();
        let transcript = Self::canonical_transcript_bytes(
            org_id_hash,
            run_id,
            commit_sha,
            suite,
            target_triple,
            &artifacts_git_ref,
            &pk_ci_k1_hex,
        );
        let transcript_sha256 = hex::encode(Sha256::digest(&transcript));
        let k1_sig = runner_signer.sign(&transcript);
        let k2_signature_hex =
            k2_coordinator_sk.map(|sk| hex::encode(sk.sign(&transcript).to_bytes()));

        let receipt = Self {
            schema: "CiGreenReceiptV1".to_string(),
            org_id_hash: org_id_hash.to_string(),
            run_id: run_id.to_string(),
            commit_sha: commit_sha.to_string(),
            suite: suite.to_string(),
            target_triple: target_triple.to_string(),
            artifacts_git_ref,
            transcript_sha256,
            pk_ci_k1_hex,
            k1_signature_hex: hex::encode(k1_sig.to_bytes()),
            k2_signature_hex,
        };
        receipt.verify_k1()?;
        Ok(receipt)
    }

    pub fn verify_k1(&self) -> Result<(), String> {
        let pk_bytes: [u8; 32] = hex::decode(&self.pk_ci_k1_hex)
            .map_err(|e| format!("invalid pk_ci_k1_hex: {e}"))?
            .try_into()
            .map_err(|_| "pk_ci_k1_hex must be 32 bytes".to_string())?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| e.to_string())?;
        let sig_bytes: [u8; 64] = hex::decode(&self.k1_signature_hex)
            .map_err(|e| format!("invalid k1_signature_hex: {e}"))?
            .try_into()
            .map_err(|_| "k1_signature_hex must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_bytes);
        let transcript = Self::canonical_transcript_bytes(
            &self.org_id_hash,
            &self.run_id,
            &self.commit_sha,
            &self.suite,
            &self.target_triple,
            &self.artifacts_git_ref,
            &self.pk_ci_k1_hex,
        );
        let expected_sha256 = hex::encode(Sha256::digest(&transcript));
        if self.transcript_sha256 != expected_sha256 {
            return Err("CiGreenReceiptV1 transcript_sha256 mismatch".to_string());
        }
        vk.verify_strict(&transcript, &sig)
            .map_err(|e| format!("CiGreenReceiptV1 K1 verify_strict failed: {e}"))
    }
}
