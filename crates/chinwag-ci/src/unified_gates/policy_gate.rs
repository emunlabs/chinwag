// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Out-of-LLM deterministic workflow policy evaluator (`chinwag-ci policy-gate`).
//!
//! Enforces `WP-01`..`WP-06` (`file_scope`, `forbidden_paths`, `max_checkpoint_loc`,
//! raw environment secret read block + pre-encryption scrubbing, `allowed_signers`
//! presence, and required gate declarations) with fail-closed exit code `78`
//! (`EXIT_FAIL_CLOSED_HOLD`) and zero parallel `.cwcard` schemas
//! (`INV-SINGLE-CWCARD-SCHEMA-01`).

use super::EphemeralRunnerSigner;
use super::scrubber::{scrub_secrets, strip_ansi_and_prompt_injections};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Fail-closed hold exit code (`EX_CONFIG` / `78`) returned on policy violations.
pub const EXIT_FAIL_CLOSED_HOLD: u8 = 78;

/// Declarative repository/task workflow policy configuration (`WorkflowPolicyConfigV1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowPolicyConfigV1 {
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(default)]
    pub file_scope: Vec<String>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
    #[serde(default = "default_max_checkpoint_loc")]
    pub max_checkpoint_loc: usize,
    #[serde(default = "default_true")]
    pub block_raw_env_secret_reads: bool,
    #[serde(default)]
    pub required_gates: Vec<String>,
}

fn default_schema() -> String {
    "WorkflowPolicyConfigV1".to_string()
}

fn default_max_checkpoint_loc() -> usize {
    2_500
}

fn default_true() -> bool {
    true
}

impl Default for WorkflowPolicyConfigV1 {
    fn default() -> Self {
        Self {
            schema: default_schema(),
            file_scope: Vec::new(),
            forbidden_paths: vec![
                ".env".to_string(),
                ".chinwag/signing/".to_string(),
                "secrets/".to_string(),
            ],
            max_checkpoint_loc: default_max_checkpoint_loc(),
            block_raw_env_secret_reads: true,
            required_gates: vec!["verify-signer".to_string(), "test-regressions".to_string()],
        }
    }
}

/// Individual deterministic policy violation (`WP-01`..`WP-06`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule_id: String,
    pub path: Option<String>,
    pub detail: String,
}

/// Evaluation result produced by `evaluate_workflow_policy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub passed: bool,
    pub exit_code: u8,
    pub changed_files_checked: usize,
    pub added_loc: usize,
    pub scrubbed_diff_sha256: String,
    pub redacted_secret_count: usize,
    pub stripped_control_sequences: usize,
    pub neutralized_injections: usize,
    pub violations: Vec<PolicyViolation>,
}

/// Cryptographically signed policy evaluation receipt (`PolicyGateReceiptV1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGateReceiptV1 {
    pub ok: bool,
    pub schema: String,
    pub command: String,
    pub org_id_hash: String,
    pub run_id: String,
    pub base_ref: String,
    pub head_ref: String,
    pub evaluation: PolicyEvaluationResult,
    pub payload_sha256_hex: String,
    pub pk_ci_k1_hex: String,
    pub k1_signature_hex: String,
}

impl PolicyGateReceiptV1 {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_transcript_bytes(
        org_id_hash: &str,
        run_id: &str,
        base_ref: &str,
        head_ref: &str,
        passed: bool,
        scrubbed_diff_sha256: &str,
        violation_count: usize,
        pk_ci_k1_hex: &str,
    ) -> Vec<u8> {
        let mut out = b"chinwag-ci-policy-gate-v2\0".to_vec();
        let passed_str = if passed { "1" } else { "0" };
        let vcount_str = violation_count.to_string();
        for field in [
            org_id_hash,
            run_id,
            base_ref,
            head_ref,
            passed_str,
            scrubbed_diff_sha256,
            vcount_str.as_str(),
            pk_ci_k1_hex,
        ] {
            let bytes = field.as_bytes();
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    pub fn build_signed(
        signer: &EphemeralRunnerSigner,
        org_id_hash: &str,
        run_id: &str,
        base_ref: &str,
        head_ref: &str,
        evaluation: PolicyEvaluationResult,
    ) -> Result<Self, String> {
        let pk_ci_k1_hex = signer.public_key_hex();
        let transcript = Self::canonical_transcript_bytes(
            org_id_hash,
            run_id,
            base_ref,
            head_ref,
            evaluation.passed,
            &evaluation.scrubbed_diff_sha256,
            evaluation.violations.len(),
            &pk_ci_k1_hex,
        );
        let payload_sha256_hex = hex::encode(Sha256::digest(&transcript));
        let sig = signer.sign(&transcript);
        let receipt = Self {
            ok: evaluation.passed,
            schema: "PolicyGateReceiptV1".to_string(),
            command: "chinwag-ci policy-gate".to_string(),
            org_id_hash: org_id_hash.to_string(),
            run_id: run_id.to_string(),
            base_ref: base_ref.to_string(),
            head_ref: head_ref.to_string(),
            evaluation,
            payload_sha256_hex,
            pk_ci_k1_hex,
            k1_signature_hex: hex::encode(sig.to_bytes()),
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
            &self.base_ref,
            &self.head_ref,
            self.evaluation.passed,
            &self.evaluation.scrubbed_diff_sha256,
            self.evaluation.violations.len(),
            &self.pk_ci_k1_hex,
        );
        let expected_sha = hex::encode(Sha256::digest(&transcript));
        if self.payload_sha256_hex != expected_sha {
            return Err("PolicyGateReceiptV1 payload_sha256_hex mismatch".to_string());
        }
        vk.verify_strict(&transcript, &sig)
            .map_err(|e| format!("PolicyGateReceiptV1 verify_strict failed: {e}"))
    }
}

fn path_matches_scope_entry(path: &str, scope_entry: &str) -> bool {
    let norm_path = path.trim_start_matches("./");
    let norm_scope = scope_entry
        .trim_start_matches("./")
        .trim_end_matches("/**")
        .trim_end_matches("/*");
    if norm_scope == "*" || norm_scope.is_empty() {
        return true;
    }
    if norm_scope.ends_with('/') {
        norm_path.starts_with(norm_scope)
    } else {
        norm_path == norm_scope || norm_path.starts_with(&format!("{norm_scope}/"))
    }
}

fn added_line_reads_raw_secret_env(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start_matches('+').trim();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return None;
    }
    let env_calls = [
        "std::env::var(",
        "env::var(",
        "process.env.",
        "process.env[",
        "os.environ[",
        "os.getenv(",
    ];
    if !env_calls.iter().any(|c| trimmed.contains(c)) {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    [
        "API_KEY",
        "SECRET",
        "PRIVATE_KEY",
        "SIGNING_KEY",
        "BEARER_TOKEN",
        "ACCESS_TOKEN",
        "STRIPE_",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "DATABASE_URL",
    ]
    .into_iter()
    .find(|secret_marker| upper.contains(secret_marker))
}

/// Evaluates `WP-01`..`WP-06` deterministically in pure Rust (`$0` LLM spend).
/// Scrubs any secret material before hashing or storing evaluation output (`0` plaintext secret bytes retained).
#[must_use]
pub fn evaluate_workflow_policy(
    config: &WorkflowPolicyConfigV1,
    changed_paths: &[String],
    raw_unified_diff: &str,
    allowed_signers_present: bool,
    env_snapshot: &[(String, String)],
) -> PolicyEvaluationResult {
    let mut violations = Vec::new();

    // WP-01: file_scope enforcement (when non-empty)
    if !config.file_scope.is_empty() {
        for path in changed_paths {
            if !config
                .file_scope
                .iter()
                .any(|entry| path_matches_scope_entry(path, entry))
            {
                violations.push(PolicyViolation {
                    rule_id: "WP-01".to_string(),
                    path: Some(path.clone()),
                    detail: format!("changed path `{path}` is outside declared file_scope"),
                });
            }
        }
    }

    // WP-02: forbidden_paths enforcement
    for path in changed_paths {
        if config
            .forbidden_paths
            .iter()
            .any(|forb| path_matches_scope_entry(path, forb))
        {
            violations.push(PolicyViolation {
                rule_id: "WP-02".to_string(),
                path: Some(path.clone()),
                detail: format!("changed path `{path}` touches forbidden policy surface"),
            });
        }
    }

    // WP-03 & WP-04: checkpoint LOC ceiling & raw env secret read check on added diff lines
    let mut current_diff_file: Option<String> = None;
    let mut added_loc = 0usize;
    for raw_line in raw_unified_diff.lines() {
        if let Some(rest) = raw_line.strip_prefix("+++ b/") {
            current_diff_file = Some(rest.trim().to_string());
            continue;
        }
        if raw_line.starts_with("+++") || raw_line.starts_with("---") {
            continue;
        }
        if raw_line.starts_with('+') {
            added_loc += 1;
            if config.block_raw_env_secret_reads
                && let Some(marker) = added_line_reads_raw_secret_env(raw_line)
            {
                violations.push(PolicyViolation {
                    rule_id: "WP-04".to_string(),
                    path: current_diff_file.clone(),
                    detail: format!(
                        "added diff line reads sensitive environment secret `{marker}` directly outside capability broker"
                    ),
                });
            }
        }
    }

    if added_loc > config.max_checkpoint_loc {
        violations.push(PolicyViolation {
            rule_id: "WP-03".to_string(),
            path: None,
            detail: format!(
                "added LOC ({added_loc}) exceeds max_checkpoint_loc ({})",
                config.max_checkpoint_loc
            ),
        });
    }

    // WP-05: allowed_signers presence
    if !allowed_signers_present {
        violations.push(PolicyViolation {
            rule_id: "WP-05".to_string(),
            path: None,
            detail: "allowed_signers registry missing or unreadable".to_string(),
        });
    }

    // WP-06: required_gates non-empty
    if config.required_gates.is_empty() {
        violations.push(PolicyViolation {
            rule_id: "WP-06".to_string(),
            path: None,
            detail: "workflow policy must declare at least one required gate".to_string(),
        });
    }

    // Strip ANSI/prompt-injection markers first, then scrub secrets before hashing (`0` plaintext secret bytes retained)
    let (deansied_diff, stripped_control_sequences, neutralized_injections) =
        strip_ansi_and_prompt_injections(raw_unified_diff);
    let scrub_report = scrub_secrets(&deansied_diff, env_snapshot);
    let quarantined_diff = scrub_report.scrubbed_text;
    let scrubbed_diff_sha256 = hex::encode(Sha256::digest(quarantined_diff.as_bytes()));

    let passed = violations.is_empty();
    let exit_code = if passed { 0 } else { EXIT_FAIL_CLOSED_HOLD };

    PolicyEvaluationResult {
        passed,
        exit_code,
        changed_files_checked: changed_paths.len(),
        added_loc,
        scrubbed_diff_sha256,
        redacted_secret_count: scrub_report.total_redactions,
        stripped_control_sequences,
        neutralized_injections,
        violations,
    }
}

/// Loads policy config JSON (or defaults if omitted) and evaluates `git diff` between `base_ref` and `head_ref`.
pub fn execute_policy_gate(
    signer: &EphemeralRunnerSigner,
    config_path: Option<&Path>,
    allowed_signers_path: &Path,
    base_ref: &str,
    head_ref: &str,
    org_id_hash: &str,
    run_id: &str,
) -> Result<PolicyGateReceiptV1, String> {
    let config = if let Some(path) = config_path {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("unable to read policy config `{}`: {e}", path.display()))?;
        serde_json::from_str::<WorkflowPolicyConfigV1>(&raw)
            .map_err(|e| format!("invalid WorkflowPolicyConfigV1 `{}`: {e}", path.display()))?
    } else {
        WorkflowPolicyConfigV1::default()
    };

    let base_trimmed = base_ref.trim();
    let head_trimmed = head_ref.trim();
    if base_trimmed.is_empty()
        || head_trimmed.is_empty()
        || base_trimmed.starts_with('-')
        || head_trimmed.starts_with('-')
    {
        return Err(
            "invalid `--base` or `--head` revision: empty or leading `-` option injection is forbidden"
                .to_string(),
        );
    }

    let names_out = Command::new("git")
        .args(["diff", "--name-only", base_trimmed, head_trimmed, "--"])
        .output()
        .map_err(|e| format!("failed to spawn `git diff --name-only`: {e}"))?;
    if !names_out.status.success() {
        return Err(format!(
            "`git diff --name-only {base_trimmed} {head_trimmed}` failed with status {}",
            names_out.status
        ));
    }
    let changed_paths: Vec<String> = String::from_utf8_lossy(&names_out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    let diff_out = Command::new("git")
        .args(["diff", "--unified=0", base_trimmed, head_trimmed, "--"])
        .output()
        .map_err(|e| format!("failed to spawn `git diff --unified=0`: {e}"))?;
    if !diff_out.status.success() {
        return Err(format!(
            "`git diff --unified=0 {base_trimmed} {head_trimmed}` failed with status {}",
            diff_out.status
        ));
    }
    let raw_diff = String::from_utf8_lossy(&diff_out.stdout).into_owned();

    let signers_ok = fs::symlink_metadata(allowed_signers_path)
        .map(|m| m.is_file() && !m.file_type().is_symlink())
        .unwrap_or(false);
    let env_snapshot: Vec<(String, String)> = std::env::vars().collect();

    let eval = evaluate_workflow_policy(
        &config,
        &changed_paths,
        &raw_diff,
        signers_ok,
        &env_snapshot,
    );
    PolicyGateReceiptV1::build_signed(signer, org_id_hash, run_id, base_ref, head_ref, eval)
}
