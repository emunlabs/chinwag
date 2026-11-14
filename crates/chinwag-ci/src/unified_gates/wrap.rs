// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Unified subprocess execution wrapper (`chinwag-ci wrap`).
//!
//! Runs an explicit `argv` command without shell interpolation, streams stdout/stderr
//! verbatim to the runner console, scrubs secrets + strips ANSI/injections before
//! `CHWG-0278` deterministic triage, routes `InfraTransientOrAuth` faults to
//! `OperatorOwnedIncidentV1` (`0` coding-agent wakes), and builds a wire-compatible
//! `ReviewPacketV2.test_evidence` `AssertedSuiteRun` (`<= 400`-token `failure_header`).

use super::EphemeralRunnerSigner;
use super::scrubber::{scrub_ci_secrets, strip_ansi_and_prompt_injections};
use crate::diagnostics_triage::{
    CodegraphSymbolIndex, FaultClassification, OperatorOwnedIncidentV1, ShardDiagnosticInput,
    build_asserted_suite_run, coalesce_and_triage_shards,
};
use crate::packet::{AssertedSuiteRun, jcs_from_serializable};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

/// Signed execution receipt emitted by `chinwag-ci wrap`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapReceiptV1 {
    pub ok: bool,
    pub schema: String,
    pub command: String,
    pub org_id_hash: String,
    pub suite_id: String,
    pub toolchain: String,
    pub argv: Vec<String>,
    pub argv_sha256: String,
    pub exit_code: i32,
    pub elapsed_ms: u64,
    pub classification: FaultClassification,
    pub asserted_suite_run: Option<AssertedSuiteRun>,
    pub operator_incident: Option<OperatorOwnedIncidentV1>,
    pub payload_sha256_hex: String,
    pub pk_ci_k1_hex: String,
    pub k1_signature_hex: String,
}

impl WrapReceiptV1 {
    #[must_use]
    pub fn compute_argv_sha256(argv: &[String]) -> String {
        let mut h = Sha256::new();
        h.update(b"chinwag-ci-argv-v2\0");
        h.update((argv.len() as u64).to_be_bytes());
        for arg in argv {
            let b = arg.as_bytes();
            h.update((b.len() as u64).to_be_bytes());
            h.update(b);
        }
        hex::encode(h.finalize())
    }

    pub fn compute_evidence_digests(
        classification: &FaultClassification,
        asserted_suite_run: &Option<AssertedSuiteRun>,
        operator_incident: &Option<OperatorOwnedIncidentV1>,
    ) -> Result<(String, String, String), String> {
        let class_jcs = jcs_from_serializable(classification)
            .map_err(|e| format!("classification JCS: {e}"))?;
        let suite_jcs = jcs_from_serializable(asserted_suite_run)
            .map_err(|e| format!("asserted_suite_run JCS: {e}"))?;
        let incident_jcs = jcs_from_serializable(operator_incident)
            .map_err(|e| format!("operator_incident JCS: {e}"))?;
        Ok((
            hex::encode(Sha256::digest(&class_jcs)),
            hex::encode(Sha256::digest(&suite_jcs)),
            hex::encode(Sha256::digest(&incident_jcs)),
        ))
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_transcript_bytes(
        org_id_hash: &str,
        suite_id: &str,
        toolchain: &str,
        argv_sha256: &str,
        exit_code: i32,
        classification_jcs_sha256: &str,
        suite_run_jcs_sha256: &str,
        incident_jcs_sha256: &str,
        pk_ci_k1_hex: &str,
    ) -> Vec<u8> {
        let mut out = b"chinwag-ci-wrap-receipt-v2\0".to_vec();
        let exit_str = exit_code.to_string();
        for f in [
            org_id_hash,
            suite_id,
            toolchain,
            argv_sha256,
            exit_str.as_str(),
            classification_jcs_sha256,
            suite_run_jcs_sha256,
            incident_jcs_sha256,
            pk_ci_k1_hex,
        ] {
            let b = f.as_bytes();
            out.extend_from_slice(&(b.len() as u64).to_be_bytes());
            out.extend_from_slice(b);
        }
        out
    }

    pub fn verify_k1(&self) -> Result<(), String> {
        let expected_argv_sha = Self::compute_argv_sha256(&self.argv);
        if self.argv_sha256 != expected_argv_sha {
            return Err("WrapReceiptV1 argv_sha256 mismatch".to_string());
        }
        let (class_sha, suite_sha, inc_sha) = Self::compute_evidence_digests(
            &self.classification,
            &self.asserted_suite_run,
            &self.operator_incident,
        )?;
        let expected_transcript = Self::canonical_transcript_bytes(
            &self.org_id_hash,
            &self.suite_id,
            &self.toolchain,
            &self.argv_sha256,
            self.exit_code,
            &class_sha,
            &suite_sha,
            &inc_sha,
            &self.pk_ci_k1_hex,
        );
        let expected_sha = hex::encode(Sha256::digest(&expected_transcript));
        if self.payload_sha256_hex != expected_sha {
            return Err("WrapReceiptV1 payload_sha256_hex mismatch".to_string());
        }
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
        vk.verify_strict(&expected_transcript, &sig)
            .map_err(|e| format!("WrapReceiptV1 verify_strict failed: {e}"))
    }
}

/// Executes `argv` directly, echoes output, builds `WrapReceiptV1`, and returns `(exit_code, WrapReceiptV1)`.
pub fn execute_wrap(
    signer: &EphemeralRunnerSigner,
    org_id_hash: &str,
    suite_id: &str,
    toolchain: &str,
    argv: &[String],
    receipt_out: Option<&Path>,
) -> Result<(u8, WrapReceiptV1), String> {
    if argv.is_empty() || argv[0].trim().is_empty() {
        return Err("wrap requires a non-empty command after `--`".to_string());
    }

    let start = Instant::now();
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| format!("failed to spawn `{}`: {e}", argv[0]))?;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    if !output.stdout.is_empty() {
        let _ = std::io::stdout().write_all(&output.stdout);
        let _ = std::io::stdout().flush();
    }
    if !output.stderr.is_empty() {
        let _ = std::io::stderr().write_all(&output.stderr);
        let _ = std::io::stderr().flush();
    }

    let exit_code = output.status.code().unwrap_or(1);
    let mut combined_raw = Vec::with_capacity(output.stdout.len() + output.stderr.len() + 1);
    combined_raw.extend_from_slice(&output.stdout);
    if !combined_raw.is_empty() && !combined_raw.ends_with(b"\n") && !output.stderr.is_empty() {
        combined_raw.push(b'\n');
    }
    combined_raw.extend_from_slice(&output.stderr);

    let env_snapshot: Vec<(String, String)> = std::env::vars().collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let cg_index = CodegraphSymbolIndex::load_from_repo(&cwd);

    let triage = coalesce_and_triage_shards(
        &[ShardDiagnosticInput {
            shard_id: "wrap-01".to_string(),
            suite_id: suite_id.to_string(),
            raw_log: combined_raw.clone(),
            exit_code,
        }],
        &env_snapshot,
        cg_index.as_ref(),
    );

    let lossy = String::from_utf8_lossy(&combined_raw);
    let (deansied, _, _) = strip_ansi_and_prompt_injections(&lossy);
    let scrubbed = scrub_ci_secrets(&deansied, &env_snapshot);
    let clean_full_log = scrubbed.scrubbed_text;

    let asserted_suite_run = match &triage.classification {
        FaultClassification::CandidateCodeFailure => Some(build_asserted_suite_run(
            suite_id,
            argv.to_vec(),
            toolchain,
            exit_code,
            clean_full_log.as_bytes(),
            &triage,
        )?),
        FaultClassification::InfraTransientOrAuth { .. } => None,
    };

    let argv_sha256 = WrapReceiptV1::compute_argv_sha256(argv);
    let (class_sha, suite_sha, inc_sha) = WrapReceiptV1::compute_evidence_digests(
        &triage.classification,
        &asserted_suite_run,
        &triage.operator_incident,
    )?;
    let pk_ci_k1_hex = signer.public_key_hex();
    let transcript = WrapReceiptV1::canonical_transcript_bytes(
        org_id_hash,
        suite_id,
        toolchain,
        &argv_sha256,
        exit_code,
        &class_sha,
        &suite_sha,
        &inc_sha,
        &pk_ci_k1_hex,
    );
    let payload_sha256_hex = hex::encode(Sha256::digest(&transcript));
    let sig = signer.sign(&transcript);

    let receipt = WrapReceiptV1 {
        ok: exit_code == 0,
        schema: "ChinwagCiWrapReceiptV1".to_string(),
        command: "chinwag-ci wrap".to_string(),
        org_id_hash: org_id_hash.to_string(),
        suite_id: suite_id.to_string(),
        toolchain: toolchain.to_string(),
        argv: argv.to_vec(),
        argv_sha256,
        exit_code,
        elapsed_ms,
        classification: triage.classification,
        asserted_suite_run,
        operator_incident: triage.operator_incident,
        payload_sha256_hex,
        pk_ci_k1_hex,
        k1_signature_hex: hex::encode(sig.to_bytes()),
    };
    receipt.verify_k1()?;

    if let Some(path) = receipt_out {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| format!("unable to create dir: {e}"))?;
        }
        let encoded = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
        fs::write(path, encoded).map_err(|e| format!("unable to write receipt: {e}"))?;
    }

    let u8_code = u8::try_from(exit_code.clamp(0, 255)).unwrap_or(1);
    Ok((if exit_code == 0 { 0 } else { u8_code.max(1) }, receipt))
}
