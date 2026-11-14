// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `CHWG-0279`: `$0`-LLM Verified `RED -> GREEN` Intelligence Flywheel,
//! Automatic `.chinwag/regressions/<fingerprint>.json` RFC-8785 JCS Cassette Minter,
//! Configurable Memory-Bank Fix Ledger, and Bounded `EXACT_PATH` `AssertedTombstone`
//! Promoter (`<= 512` UTF-8 bytes, enforcing `8,000`-token / `32,768`-byte overhead guard).

use crate::diagnostics_triage::{
    FaultClassification, NormalizedDiagnosticSpan, TriageReportV1, estimate_conservative_tokens,
};
use crate::packet::{
    Artifact, AssertedTombstone, MANDATORY_OVERHEAD_MAX_BYTES, MANDATORY_OVERHEAD_MAX_TOKENS,
    RepoPath, RequiredSuite, Sha256Digest, TombstoneScope, UnverifiedPinnedPolicy,
    UnverifiedTestEvidence, jcs_from_serializable,
};
use crate::unified_gates::cassette_replay::{
    CassetteExpectationV1, RecordedStepV1, StepKindV1, TombstoneCassetteV1, jcs_sha256_hex,
};
use crate::unified_gates::scrubber::{scrub_secrets, strip_ansi_and_prompt_injections};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Hard ceiling (`<= 512` UTF-8 bytes) per promoted `EXACT_PATH` tombstone body (`CHWG-0279`).
pub const MAX_TOMBSTONE_BODY_BYTES: usize = 512;

/// Default maximum active `EXACT_PATH` tombstones permitted on any single `RepoPath`.
pub const DEFAULT_MAX_ACTIVE_TOMBSTONES_PER_PATH: usize = 4;

/// Default recurrence threshold before a candidate fix promotes to an `EXACT_PATH` tombstone.
pub const DEFAULT_PROMOTION_RECURRENCE_THRESHOLD: usize = 2;

/// Default safety reserve kept inside the `32,768`-byte / `8,000`-token mandatory overhead budget
/// for pinned workflow/policy framing when no `UnverifiedPinnedPolicy` artifact is supplied, so
/// tombstones can never trigger `UNAVAILABLE_SYSTEM_OVERHEAD_EXCEEDED` (`design-v2` §5.1).
pub const DEFAULT_BASE_POLICY_OVERHEAD_BYTES_RESERVE: u64 = 16_384;
pub const DEFAULT_BASE_POLICY_OVERHEAD_TOKENS_RESERVE: u64 = 4_000;

/// Structural packet envelope framing reserve (`2,048` bytes / `512` tokens) added on top of a
/// measured `UnverifiedPinnedPolicy` artifact when computing live mandatory overhead.
pub const PACKET_ENVELOPE_FRAMING_BYTES_RESERVE: u64 = 2_048;
pub const PACKET_ENVELOPE_FRAMING_TOKENS_RESERVE: u64 = 512;

/// Flywheel validation or budget enforcement error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FlywheelError {
    #[error("RED capture is not a CandidateCodeFailure (infra faults cannot seed flywheel)")]
    RedCaptureNotCandidateFailure,
    #[error("RED capture contains zero failure assertions or commit IDs match")]
    InvalidRedToGreenPair(&'static str),
    #[error("GREEN evidence failed clean-snapshot or required-suite verification: {0}")]
    UnverifiedGreenEvidence(String),
    #[error("touching zero valid repository-relative exact paths")]
    EmptyTouchedPaths,
    #[error("tombstone body ({actual_bytes} bytes) exceeds 512-byte ceiling")]
    TombstoneBodyTooLarge { actual_bytes: usize },
    #[error("GLOBAL tombstone auto-promotion is forbidden; must use EXACT_PATH")]
    GlobalScopeForbidden,
    #[error(
        "mandatory overhead budget exceeded (projected_tokens={projected_tokens}/{max_tokens}, projected_bytes={projected_bytes}/{max_bytes}) — refusing tombstone bloat before UNAVAILABLE_SYSTEM_OVERHEAD_EXCEEDED"
    )]
    OverheadBudgetExceeded {
        projected_tokens: u64,
        max_tokens: u64,
        projected_bytes: u64,
        max_bytes: u64,
    },
    #[error("per-path active tombstone cap ({max_per_path}) reached for `{repo_path}`")]
    PerPathCapReached {
        repo_path: String,
        max_per_path: usize,
    },
    #[error("I/O or serialization failure: {0}")]
    Io(String),
}

/// Deterministic AST / structural diff shape extracted from a `RED -> GREEN` patch without LLM calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstDiffShapeSummary {
    pub files_touched: usize,
    pub hunks_count: usize,
    pub added_lines: usize,
    pub removed_lines: usize,
    pub touched_symbols: Vec<String>,
}

/// Captured failing (`RED`) run input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedCaptureEvidence {
    pub ticket_id: String,
    pub failed_commit_id: String,
    pub triage: TriageReportV1,
}

/// Verified passing (`GREEN`) run input on the subsequent fix commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GreenVerificationEvidence {
    pub green_commit_id: String,
    pub required_suites: Vec<RequiredSuite>,
    pub test_evidence: UnverifiedTestEvidence,
    pub touched_paths: Vec<String>,
    pub unified_diff: String,
}

/// Verified `RED -> GREEN` transition record (`$0` LLM spend).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedRedToGreenTransitionV1 {
    pub schema: String,
    pub ticket_id: String,
    pub failed_commit_id: String,
    pub green_commit_id: String,
    pub normalized_failure_fingerprint: Sha256Digest,
    pub primary_error_code: String,
    pub primary_tool: String,
    pub touched_exact_paths: Vec<RepoPath>,
    pub verified_suite_ids: Vec<String>,
    pub ast_diff_shape: AstDiffShapeSummary,
    pub minimal_fix_summary: String,
}

/// Candidate fix memory record stored under the repository's configured memory bank.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFixMemoryEntryV1 {
    pub schema: String,
    pub bank: String,
    pub ticket_id: String,
    pub failure_fingerprint_sha256: String,
    pub primary_error_code: String,
    pub failed_commit_id: String,
    pub green_commit_id: String,
    pub exact_paths: Vec<String>,
    pub minimal_fix_summary: String,
}

/// Mandatory overhead budget guard (`design-v2` §5.1: `<= 8,000` tokens AND `<= 32,768` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverheadBudgetGuard {
    pub existing_policy_overhead_tokens: u64,
    pub existing_policy_overhead_bytes: u64,
    pub max_total_overhead_tokens: u64,
    pub max_total_overhead_bytes: u64,
    pub max_active_per_path: usize,
}

impl Default for OverheadBudgetGuard {
    fn default() -> Self {
        Self {
            existing_policy_overhead_tokens: DEFAULT_BASE_POLICY_OVERHEAD_TOKENS_RESERVE,
            existing_policy_overhead_bytes: DEFAULT_BASE_POLICY_OVERHEAD_BYTES_RESERVE,
            max_total_overhead_tokens: MANDATORY_OVERHEAD_MAX_TOKENS,
            max_total_overhead_bytes: MANDATORY_OVERHEAD_MAX_BYTES,
            max_active_per_path: DEFAULT_MAX_ACTIVE_TOMBSTONES_PER_PATH,
        }
    }
}

impl OverheadBudgetGuard {
    /// Measures exact canonical RFC-8785 JCS bytes and conservative tokens of a real
    /// `UnverifiedPinnedPolicy` plus packet envelope framing (`2,048`B / `512`t), ensuring large
    /// repository policies (>= 16KB / >= 4,000t) accurately constrain or block tombstone promotion
    /// before `UNAVAILABLE_SYSTEM_OVERHEAD_EXCEEDED` can ever trigger.
    pub fn from_pinned_policy(
        policy: &UnverifiedPinnedPolicy,
        max_active_per_path: usize,
    ) -> Result<Self, FlywheelError> {
        let canonical = jcs_from_serializable(policy)
            .map_err(|e| FlywheelError::Io(format!("failed to JCS-encode pinned policy: {e}")))?;
        let canonical_str = std::str::from_utf8(&canonical)
            .map_err(|_| FlywheelError::Io("non-UTF-8 JCS pinned policy".to_string()))?;
        let measured_bytes =
            (canonical.len() as u64).saturating_add(PACKET_ENVELOPE_FRAMING_BYTES_RESERVE);
        let measured_tokens = estimate_conservative_tokens(canonical_str)
            .saturating_add(PACKET_ENVELOPE_FRAMING_TOKENS_RESERVE);
        Ok(Self {
            existing_policy_overhead_tokens: measured_tokens,
            existing_policy_overhead_bytes: measured_bytes,
            max_total_overhead_tokens: MANDATORY_OVERHEAD_MAX_TOKENS,
            max_total_overhead_bytes: MANDATORY_OVERHEAD_MAX_BYTES,
            max_active_per_path,
        })
    }

    /// Measures mandatory policy overhead from a policy file (`UnverifiedPinnedPolicy` JSON or raw
    /// policy/workflow artifact), failing closed if the file cannot be read.
    pub fn from_policy_file(
        path: &Path,
        max_active_per_path: usize,
    ) -> Result<Self, FlywheelError> {
        let raw = fs::read(path).map_err(|e| {
            FlywheelError::Io(format!(
                "unable to read policy overhead file `{}`: {e}",
                path.display()
            ))
        })?;
        if let Ok(pinned) = serde_json::from_slice::<UnverifiedPinnedPolicy>(&raw) {
            return Self::from_pinned_policy(&pinned, max_active_per_path);
        }
        let lossy = String::from_utf8_lossy(&raw);
        let measured_bytes =
            (raw.len() as u64).saturating_add(PACKET_ENVELOPE_FRAMING_BYTES_RESERVE);
        let measured_tokens = estimate_conservative_tokens(&lossy)
            .saturating_add(PACKET_ENVELOPE_FRAMING_TOKENS_RESERVE);
        Ok(Self {
            existing_policy_overhead_tokens: measured_tokens,
            existing_policy_overhead_bytes: measured_bytes,
            max_total_overhead_tokens: MANDATORY_OVERHEAD_MAX_TOKENS,
            max_total_overhead_bytes: MANDATORY_OVERHEAD_MAX_BYTES,
            max_active_per_path,
        })
    }

    /// Resolves the live `OverheadBudgetGuard` from explicit overrides -> `--policy-file` ->
    /// `CHINWAG_PINNED_POLICY_FILE` -> `<repo_root>/.chinwag/pinned-policy.json` -> conservative default.
    pub fn resolve_from_inputs(
        policy_file: Option<&Path>,
        explicit_bytes: Option<u64>,
        explicit_tokens: Option<u64>,
        repo_root: Option<&Path>,
        max_active_per_path: usize,
    ) -> Result<Self, FlywheelError> {
        if explicit_bytes.is_some() || explicit_tokens.is_some() {
            return Ok(Self {
                existing_policy_overhead_bytes: explicit_bytes
                    .unwrap_or(DEFAULT_BASE_POLICY_OVERHEAD_BYTES_RESERVE),
                existing_policy_overhead_tokens: explicit_tokens
                    .unwrap_or(DEFAULT_BASE_POLICY_OVERHEAD_TOKENS_RESERVE),
                max_total_overhead_tokens: MANDATORY_OVERHEAD_MAX_TOKENS,
                max_total_overhead_bytes: MANDATORY_OVERHEAD_MAX_BYTES,
                max_active_per_path,
            });
        }
        if let Some(p) = policy_file {
            return Self::from_policy_file(p, max_active_per_path);
        }
        if let Ok(env_path) = std::env::var("CHINWAG_PINNED_POLICY_FILE") {
            let trimmed = env_path.trim();
            if !trimmed.is_empty() {
                return Self::from_policy_file(Path::new(trimmed), max_active_per_path);
            }
        }
        if let Some(root) = repo_root {
            let default_policy_path = root.join(".chinwag/pinned-policy.json");
            if default_policy_path.is_file() {
                return Self::from_policy_file(&default_policy_path, max_active_per_path);
            }
        }
        Ok(Self {
            max_active_per_path,
            ..Self::default()
        })
    }
}

/// Resolves the target memory bank strictly from `--bank` -> `CHINWAG_MEMORY_BANK` ->
/// `.chinwag/fleet.toml` `memory_bank = "..."` -> `"default"` (`0` hardcoded customer bank names).
#[must_use]
pub fn resolve_memory_bank(explicit_flag: Option<&str>, repo_root: Option<&Path>) -> String {
    if let Some(flag) = explicit_flag.map(str::trim).filter(|s| !s.is_empty()) {
        return flag.to_string();
    }
    if let Ok(env_val) = std::env::var("CHINWAG_MEMORY_BANK") {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(root) = repo_root {
        let manifest_path = root.join(".chinwag/fleet.toml");
        if let Ok(raw) = fs::read_to_string(manifest_path) {
            for line in raw.lines() {
                let t = line.trim();
                if t.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = t.split_once('=')
                    && k.trim() == "memory_bank"
                {
                    let unquoted = v.trim().trim_matches('"').trim_matches('\'').trim();
                    if !unquoted.is_empty() {
                        return unquoted.to_string();
                    }
                }
            }
        }
    }
    "default".to_string()
}

/// Summarizes unified diff structural metrics and touched Rust/TS/Python/Go symbol headers in pure Rust.
#[must_use]
pub fn summarize_ast_diff_shape(
    unified_diff: &str,
    touched_files_count: usize,
) -> AstDiffShapeSummary {
    let mut hunks_count = 0usize;
    let mut added_lines = 0usize;
    let mut removed_lines = 0usize;
    let mut symbols = Vec::new();

    for line in unified_diff.lines() {
        if let Some(after_hunk) = line.strip_prefix("@@") {
            hunks_count += 1;
            if let Some((_, ctx)) = after_hunk.split_once("@@")
                && let Some(sym) = extract_symbol_from_line(ctx.trim())
                && !symbols.contains(&sym)
                && symbols.len() < 8
            {
                symbols.push(sym);
            }
            continue;
        }
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            added_lines += 1;
            if let Some(sym) = extract_symbol_from_line(added.trim())
                && !symbols.contains(&sym)
                && symbols.len() < 8
            {
                symbols.push(sym);
            }
        } else if line.starts_with('-') {
            removed_lines += 1;
        }
    }

    AstDiffShapeSummary {
        files_touched: touched_files_count,
        hunks_count,
        added_lines,
        removed_lines,
        touched_symbols: symbols,
    }
}

fn extract_symbol_from_line(trimmed: &str) -> Option<String> {
    for kw in [
        "pub async fn ",
        "pub fn ",
        "async fn ",
        "fn ",
        "pub struct ",
        "struct ",
        "pub enum ",
        "enum ",
        "export function ",
        "function ",
        "def ",
        "func ",
    ] {
        if let Some(rest) = trimmed.strip_prefix(kw) {
            let ident: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() {
                return Some(ident);
            }
        }
    }
    None
}

/// Verifies a `RED -> GREEN` transition and computes `(normalized_failure_fingerprint,
/// touched_exact_paths, ast_diff_shape, minimal_fix_summary)` in `$0` pure Rust.
pub fn detect_red_to_green_transition(
    red: &RedCaptureEvidence,
    green: &GreenVerificationEvidence,
    env_snapshot: &[(String, String)],
) -> Result<VerifiedRedToGreenTransitionV1, FlywheelError> {
    if !matches!(
        red.triage.classification,
        FaultClassification::CandidateCodeFailure
    ) {
        return Err(FlywheelError::RedCaptureNotCandidateFailure);
    }
    if red.failed_commit_id.trim().is_empty() || green.green_commit_id.trim().is_empty() {
        return Err(FlywheelError::InvalidRedToGreenPair(
            "failed_commit_id and green_commit_id must be non-empty",
        ));
    }
    if red.failed_commit_id == green.green_commit_id {
        return Err(FlywheelError::InvalidRedToGreenPair(
            "failed_commit_id and green_commit_id must be distinct commits",
        ));
    }
    if red.triage.counts.failed == 0 && red.triage.root_diagnostics.is_empty() {
        return Err(FlywheelError::InvalidRedToGreenPair(
            "RED capture has zero failed assertions and zero root diagnostics",
        ));
    }

    // Strictly verify GREEN evidence (`asserted_clean_snapshot`, commit match, all required suites exit 0)
    if !green.test_evidence.asserted_clean_snapshot
        || green.test_evidence.tested_commit_id != green.green_commit_id
        || green.test_evidence.execution_snapshot_commit_id != green.green_commit_id
    {
        return Err(FlywheelError::UnverifiedGreenEvidence(
            "GREEN test_evidence must assert clean snapshot matching green_commit_id".to_string(),
        ));
    }
    if green.required_suites.is_empty() {
        return Err(FlywheelError::UnverifiedGreenEvidence(
            "GREEN required_suites plan cannot be empty".to_string(),
        ));
    }

    let mut verified_suite_ids = Vec::new();
    for req in &green.required_suites {
        let Some(run) = green
            .test_evidence
            .runs
            .iter()
            .find(|r| r.suite_id == req.id)
        else {
            return Err(FlywheelError::UnverifiedGreenEvidence(format!(
                "missing required suite `{}` in GREEN runs",
                req.id
            )));
        };
        if run.argv != req.argv {
            return Err(FlywheelError::UnverifiedGreenEvidence(format!(
                "suite `{}` argv does not match required plan",
                req.id
            )));
        }
        if run.exit_code != 0 || run.counts.failed > 0 || run.failure_header.is_some() {
            return Err(FlywheelError::UnverifiedGreenEvidence(format!(
                "suite `{}` is not clean green (exit_code={}, failed={})",
                req.id, run.exit_code, run.counts.failed
            )));
        }
        verified_suite_ids.push(req.id.clone());
    }
    verified_suite_ids.sort();

    let mut exact_path_strs = BTreeSet::new();
    for raw_p in &green.touched_paths {
        let norm = raw_p.trim().trim_start_matches("./");
        if !norm.is_empty() {
            exact_path_strs.insert(norm.to_string());
        }
    }
    if exact_path_strs.is_empty() {
        return Err(FlywheelError::EmptyTouchedPaths);
    }

    let mut touched_exact_paths = Vec::with_capacity(exact_path_strs.len());
    for p in &exact_path_strs {
        let rp = RepoPath::from_str_path(p)
            .map_err(|e| FlywheelError::Io(format!("invalid RepoPath `{p}`: {e}")))?;
        touched_exact_paths.push(rp);
    }

    let (deansied_diff, _, _) = strip_ansi_and_prompt_injections(&green.unified_diff);
    let scrubbed_diff = scrub_secrets(&deansied_diff, env_snapshot);
    let clean_diff = scrubbed_diff.scrubbed_text;
    let ast_diff_shape = summarize_ast_diff_shape(&clean_diff, touched_exact_paths.len());

    let (primary_tool, primary_error_code, primary_msg) = if let Some(PrimarySpan {
        tool,
        code,
        msg,
    }) =
        extract_primary(&red.triage.root_diagnostics)
    {
        (tool, code, msg)
    } else {
        (
            "generic-ci".to_string(),
            "CI_EXIT_NONZERO".to_string(),
            "failing suite resolved".to_string(),
        )
    };

    let sym_note = if ast_diff_shape.touched_symbols.is_empty() {
        "updated implementation".to_string()
    } else {
        format!("symbols [{}]", ast_diff_shape.touched_symbols.join(", "))
    };
    let raw_summary = format!(
        "Resolved {primary_tool} [{primary_error_code}] ({primary_msg}) across {} file(s) (+{}/-{} lines, {sym_note})",
        ast_diff_shape.files_touched, ast_diff_shape.added_lines, ast_diff_shape.removed_lines
    );
    let minimal_fix_summary: String = raw_summary.chars().take(280).collect();

    Ok(VerifiedRedToGreenTransitionV1 {
        schema: "chinwag.red-to-green-transition.v1".to_string(),
        ticket_id: red.ticket_id.clone(),
        failed_commit_id: red.failed_commit_id.clone(),
        green_commit_id: green.green_commit_id.clone(),
        normalized_failure_fingerprint: red.triage.failure_fingerprint_sha256.clone(),
        primary_error_code,
        primary_tool,
        touched_exact_paths,
        verified_suite_ids,
        ast_diff_shape,
        minimal_fix_summary,
    })
}

struct PrimarySpan {
    tool: String,
    code: String,
    msg: String,
}

fn extract_primary(roots: &[NormalizedDiagnosticSpan]) -> Option<PrimarySpan> {
    let first = roots.first()?;
    Some(PrimarySpan {
        tool: first.tool.as_str().to_string(),
        code: first.error_code.clone(),
        msg: first.primary_message.chars().take(120).collect(),
    })
}

/// Automatically mints a deterministic RFC-8785 JCS regression cassette under
/// `<regressions_dir>/reg-<16hex>.json` replayable in `<50ms` via `chinwag-ci test-regressions`.
pub fn mint_regression_cassette(
    transition: &VerifiedRedToGreenTransitionV1,
    regressions_dir: &Path,
) -> Result<(PathBuf, TombstoneCassetteV1), FlywheelError> {
    fs::create_dir_all(regressions_dir).map_err(|e| {
        FlywheelError::Io(format!(
            "unable to create regressions dir `{}`: {e}",
            regressions_dir.display()
        ))
    })?;

    let fp_hex = transition.normalized_failure_fingerprint.as_str();
    let short_fp = &fp_hex[..16];
    let exact_paths: Vec<String> = transition
        .touched_exact_paths
        .iter()
        .filter_map(|p| p.as_utf8_str().ok())
        .collect();

    let request_json = json!({
        "check": "red_to_green_regression_guard",
        "failure_fingerprint_sha256": fp_hex,
        "primary_error_code": transition.primary_error_code,
        "primary_tool": transition.primary_tool,
        "touched_exact_paths": exact_paths,
    });
    let request_jcs_sha256 = jcs_sha256_hex(&request_json);
    let response_json = json!({
        "ok": true,
        "status": "GREEN_VERIFIED",
        "primary_error_code": transition.primary_error_code,
        "verified_suite_ids": transition.verified_suite_ids,
        "minimal_fix_summary": transition.minimal_fix_summary,
    });

    let cassette = TombstoneCassetteV1 {
        tombstone_id: format!("tombstone-reg-{short_fp}-v1"),
        source_run_id: format!("{}-red-to-green-{short_fp}", transition.ticket_id),
        fork_at_step: 1,
        steps: vec![RecordedStepV1 {
            step_index: 0,
            kind: StepKindV1::Tool,
            request_jcs_sha256,
            request_json,
            response_json,
            simulated_clock_ms: 0,
            simulated_uuid: Some(format!("00000000-0000-4000-8000-{}", &fp_hex[..12])),
            tokens_in: 0,
            tokens_out: 0,
            cost_micro_usd: 0,
            shadow_kv_prefix_hash: None,
        }],
        expectations: vec![
            CassetteExpectationV1::JsonPathEquals {
                step_index: 0,
                json_path: "$.ok".to_string(),
                expected: json!(true),
            },
            CassetteExpectationV1::JsonPathEquals {
                step_index: 0,
                json_path: "$.status".to_string(),
                expected: json!("GREEN_VERIFIED"),
            },
            CassetteExpectationV1::MaxToolCalls { max_calls: 1 },
        ],
        ticket_id: Some(transition.ticket_id.clone()),
        failure_fingerprint_sha256: Some(fp_hex.to_string()),
        failed_commit_id: Some(transition.failed_commit_id.clone()),
        green_commit_id: Some(transition.green_commit_id.clone()),
        touched_exact_paths: exact_paths,
        pinned_suite_ids: transition.verified_suite_ids.clone(),
    };

    let mut canonical_bytes = jcs_from_serializable(&cassette)
        .map_err(|e| FlywheelError::Io(format!("JCS canonicalization failed: {e}")))?;
    canonical_bytes.push(b'\n');

    let out_path = regressions_dir.join(format!("reg-{short_fp}.json"));
    fs::write(&out_path, &canonical_bytes).map_err(|e| {
        FlywheelError::Io(format!(
            "failed to write cassette `{}`: {e}",
            out_path.display()
        ))
    })?;
    Ok((out_path, cassette))
}

/// Retains a verified `RED -> GREEN` candidate fix into the configured memory bank ledger
/// (`<flywheel_dir>/fix-ledger-<bank>.jsonl`) and returns the cumulative recurrence count
/// for `(exact_path, primary_error_code)`.
pub fn retain_candidate_fix_entry(
    transition: &VerifiedRedToGreenTransitionV1,
    flywheel_dir: &Path,
    explicit_bank: Option<&str>,
    repo_root: Option<&Path>,
) -> Result<(CandidateFixMemoryEntryV1, BTreeMap<String, usize>), FlywheelError> {
    fs::create_dir_all(flywheel_dir)
        .map_err(|e| FlywheelError::Io(format!("unable to create flywheel dir: {e}")))?;
    let bank = resolve_memory_bank(explicit_bank, repo_root);
    let sanitized_bank: String = bank
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let ledger_path = flywheel_dir.join(format!("fix-ledger-{sanitized_bank}.jsonl"));

    let exact_paths: Vec<String> = transition
        .touched_exact_paths
        .iter()
        .filter_map(|p| p.as_utf8_str().ok())
        .collect();

    let entry = CandidateFixMemoryEntryV1 {
        schema: "chinwag.candidate-fix-memory.v1".to_string(),
        bank,
        ticket_id: transition.ticket_id.clone(),
        failure_fingerprint_sha256: transition
            .normalized_failure_fingerprint
            .as_str()
            .to_string(),
        primary_error_code: transition.primary_error_code.clone(),
        failed_commit_id: transition.failed_commit_id.clone(),
        green_commit_id: transition.green_commit_id.clone(),
        exact_paths: exact_paths.clone(),
        minimal_fix_summary: transition.minimal_fix_summary.clone(),
    };

    let mut existing_entries: Vec<CandidateFixMemoryEntryV1> = if ledger_path.is_file() {
        fs::read_to_string(&ledger_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<CandidateFixMemoryEntryV1>(l).ok())
            .collect()
    } else {
        Vec::new()
    };

    let already_recorded = existing_entries.iter().any(|e| {
        e.failed_commit_id == entry.failed_commit_id && e.green_commit_id == entry.green_commit_id
    });
    if !already_recorded {
        let mut line = jcs_from_serializable(&entry)
            .map_err(|e| FlywheelError::Io(format!("JCS ledger serialize failed: {e}")))?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ledger_path)
            .map_err(|e| FlywheelError::Io(format!("ledger open failed: {e}")))?;
        file.write_all(&line)
            .map_err(|e| FlywheelError::Io(format!("ledger write failed: {e}")))?;
        existing_entries.push(entry.clone());
    }

    let mut path_recurrence = BTreeMap::new();
    for p in &exact_paths {
        let count = existing_entries
            .iter()
            .filter(|e| {
                e.primary_error_code == entry.primary_error_code && e.exact_paths.contains(p)
            })
            .count();
        path_recurrence.insert(p.clone(), count);
    }

    Ok((entry, path_recurrence))
}

/// Builds a single bounded `EXACT_PATH` `AssertedTombstone` (`<= 512` UTF-8 bytes) and validates
/// it against `existing_tombstones` and `OverheadBudgetGuard` (`<= 8,000` tokens / `<= 32,768` bytes).
pub fn mint_bounded_exact_path_tombstone(
    tombstone_id: &str,
    exact_repo_path: &str,
    concise_body: &str,
    existing_tombstones: &[AssertedTombstone],
    guard: &OverheadBudgetGuard,
) -> Result<AssertedTombstone, FlywheelError> {
    if existing_tombstones
        .iter()
        .any(|t| matches!(t.scope, TombstoneScope::Global))
    {
        return Err(FlywheelError::GlobalScopeForbidden);
    }

    let raw_trimmed = concise_body.trim();
    if raw_trimmed.is_empty() {
        return Err(FlywheelError::Io(
            "tombstone body cannot be empty".to_string(),
        ));
    }
    let env_snapshot: Vec<(String, String)> = std::env::vars().collect();
    let (deansied, _, _) = strip_ansi_and_prompt_injections(raw_trimmed);
    let scrubbed = scrub_secrets(&deansied, &env_snapshot);
    let trimmed_body = scrubbed.scrubbed_text.trim();
    if trimmed_body.is_empty() {
        return Err(FlywheelError::Io(
            "tombstone body cannot be empty after quarantine".to_string(),
        ));
    }
    if trimmed_body.len() > MAX_TOMBSTONE_BODY_BYTES {
        return Err(FlywheelError::TombstoneBodyTooLarge {
            actual_bytes: trimmed_body.len(),
        });
    }

    let repo_path = RepoPath::from_str_path(exact_repo_path)
        .map_err(|e| FlywheelError::Io(format!("invalid exact path `{exact_repo_path}`: {e}")))?;

    let candidate = AssertedTombstone {
        id: tombstone_id.to_string(),
        active: true,
        scope: TombstoneScope::ExactPath(repo_path.clone()),
        body: Artifact::from_bytes(trimmed_body.as_bytes()),
    };

    // Check per-path active tombstone cap (idempotent replacement if same ID already exists)
    let active_on_same_path = existing_tombstones
        .iter()
        .filter(|t| t.active && t.id != tombstone_id)
        .filter(|t| matches!(&t.scope, TombstoneScope::ExactPath(p) if p == &repo_path))
        .count();
    if active_on_same_path >= guard.max_active_per_path {
        return Err(FlywheelError::PerPathCapReached {
            repo_path: exact_repo_path.to_string(),
            max_per_path: guard.max_active_per_path,
        });
    }

    // Compute projected mandatory overhead across active tombstones + base policy reserve
    let mut simulated: Vec<AssertedTombstone> = existing_tombstones
        .iter()
        .filter(|t| t.active && t.id != tombstone_id)
        .cloned()
        .collect();
    simulated.push(candidate.clone());

    let serialized = jcs_from_serializable(&simulated)
        .map_err(|e| FlywheelError::Io(format!("JCS tombstone check failed: {e}")))?;
    let serialized_str = std::str::from_utf8(&serialized)
        .map_err(|_| FlywheelError::Io("non-UTF-8 JCS tombstones".to_string()))?;

    let tombstone_bytes = serialized.len() as u64;
    let tombstone_tokens = estimate_conservative_tokens(serialized_str);

    let projected_bytes = guard
        .existing_policy_overhead_bytes
        .saturating_add(tombstone_bytes);
    let projected_tokens = guard
        .existing_policy_overhead_tokens
        .saturating_add(tombstone_tokens);

    if projected_bytes > guard.max_total_overhead_bytes
        || projected_tokens > guard.max_total_overhead_tokens
    {
        return Err(FlywheelError::OverheadBudgetExceeded {
            projected_tokens,
            max_tokens: guard.max_total_overhead_tokens,
            projected_bytes,
            max_bytes: guard.max_total_overhead_bytes,
        });
    }

    Ok(candidate)
}

/// Promotes recurring `RED -> GREEN` failure classes (`recurrence >= min_recurrence`) into
/// `EXACT_PATH` `AssertedTombstone` entries persisted in `<flywheel_dir>/tombstones.json`.
pub fn promote_recurring_exact_path_tombstones(
    transition: &VerifiedRedToGreenTransitionV1,
    recurrence_by_path: &BTreeMap<String, usize>,
    min_recurrence: usize,
    flywheel_dir: &Path,
    guard: &OverheadBudgetGuard,
) -> Result<Vec<AssertedTombstone>, FlywheelError> {
    fs::create_dir_all(flywheel_dir)
        .map_err(|e| FlywheelError::Io(format!("unable to create flywheel dir: {e}")))?;
    let store_path = flywheel_dir.join("tombstones.json");
    let mut snapshot: Vec<AssertedTombstone> = match fs::symlink_metadata(&store_path) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(FlywheelError::Io(format!(
                    "tombstones store `{}` must be a regular non-symlink file",
                    store_path.display()
                )));
            }
            let raw = fs::read(&store_path)
                .map_err(|e| FlywheelError::Io(format!("unable to read tombstones.json: {e}")))?;
            serde_json::from_slice(&raw)
                .map_err(|e| FlywheelError::Io(format!("malformed tombstones.json: {e}")))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(FlywheelError::Io(format!(
                "unable to stat tombstones.json: {e}"
            )));
        }
    };

    let mut newly_promoted = Vec::new();
    let short_fp = &transition.normalized_failure_fingerprint.as_str()[..12];

    for (path_str, &count) in recurrence_by_path {
        if count < min_recurrence {
            continue;
        }
        let path_hash = Sha256Digest::of(path_str.as_bytes());
        let id = format!(
            "tombstone-{}-{}-v1",
            transition.primary_error_code.to_ascii_lowercase(),
            &path_hash.as_str()[..8]
        );
        let raw_body = format!(
            "[AVOID:{}@{short_fp}] Do not reintroduce {} failure on `{path_str}`: {}",
            transition.primary_tool, transition.primary_error_code, transition.minimal_fix_summary
        );
        let bounded_body: String = raw_body
            .chars()
            .take(MAX_TOMBSTONE_BODY_BYTES - 16)
            .collect();
        let tombstone =
            mint_bounded_exact_path_tombstone(&id, path_str, &bounded_body, &snapshot, guard)?;
        snapshot.retain(|t| t.id != tombstone.id);
        snapshot.push(tombstone.clone());
        newly_promoted.push(tombstone);
    }

    snapshot.sort_by(|a, b| a.id.cmp(&b.id));
    let mut jcs = jcs_from_serializable(&snapshot)
        .map_err(|e| FlywheelError::Io(format!("tombstones JCS encode failed: {e}")))?;
    jcs.push(b'\n');
    fs::write(&store_path, &jcs)
        .map_err(|e| FlywheelError::Io(format!("unable to write tombstones.json: {e}")))?;

    Ok(newly_promoted)
}
