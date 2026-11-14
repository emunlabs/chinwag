// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `<50ms` `$0`-LLM RFC-8785 JCS Cassette Replay (`test-regressions`),
//! Weighted-LCS Trajectory Alignment (`diff-run`), and Shadow-KV Prefix Replay (`fork-run`).

use crate::packet::canonicalize_jcs_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKindV1 {
    Llm,
    Tool,
    Clock,
    Uuid,
    ShadowKvCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedStepV1 {
    pub step_index: u32,
    pub kind: StepKindV1,
    pub request_jcs_sha256: String,
    #[serde(default)]
    pub request_json: Value,
    pub response_json: Value,
    pub simulated_clock_ms: u64,
    #[serde(default)]
    pub simulated_uuid: Option<String>,
    pub tokens_in: u32,
    pub tokens_out: u32,
    pub cost_micro_usd: u64,
    #[serde(default)]
    pub shadow_kv_prefix_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CassetteExpectationV1 {
    JsonPathEquals {
        step_index: u32,
        json_path: String,
        expected: Value,
    },
    MaxToolCalls {
        max_calls: u32,
    },
    ForbiddenPattern {
        pattern: String,
    },
    MustMatchPrefixHash {
        step_index: u32,
        expected_prefix_hash: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TombstoneCassetteV1 {
    pub tombstone_id: String,
    pub source_run_id: String,
    pub fork_at_step: u32,
    pub steps: Vec<RecordedStepV1>,
    pub expectations: Vec<CassetteExpectationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_fingerprint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_commit_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub green_commit_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub touched_exact_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_suite_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepDivergenceV1 {
    pub step_index: u32,
    pub kind: StepKindV1,
    pub expected_request_jcs_sha256: String,
    pub actual_request_jcs_sha256: String,
    pub changed_json_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectationCheckResultV1 {
    pub description: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassetteReplayReportV1 {
    pub tombstone_id: String,
    pub source_run_id: String,
    pub passed: bool,
    pub served_steps: usize,
    pub elapsed_us: u64,
    pub zero_llm_spend: bool,
    pub zero_network_calls: bool,
    pub first_divergence: Option<StepDivergenceV1>,
    pub expectation_results: Vec<ExpectationCheckResultV1>,
    pub tap_line: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlignmentStatusV1 {
    Equal,
    RequestChanged,
    ResponseChanged,
    Inserted,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlignedStepRowV1 {
    pub step_a: Option<u32>,
    pub step_b: Option<u32>,
    pub kind: StepKindV1,
    pub status: AlignmentStatusV1,
    pub changed_json_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryDivergenceV1 {
    pub step_a: Option<u32>,
    pub step_b: Option<u32>,
    pub kind: StepKindV1,
    pub status: AlignmentStatusV1,
    pub changed_json_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrajectoryDiffReportV1 {
    pub identical: bool,
    pub total_weight: u32,
    pub first_divergence: Option<TrajectoryDivergenceV1>,
    pub alignment: Vec<AlignedStepRowV1>,
    pub steps_delta: i64,
    pub llm_calls_delta: i64,
    pub tool_calls_delta: i64,
    pub tokens_in_delta: i64,
    pub tokens_out_delta: i64,
    pub cost_micro_usd_delta: i64,
    pub latency_ms_delta: i64,
    pub shadow_kv_reused_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowKvWarmBranchTicketV1 {
    pub ticket_id: String,
    pub fork_at_step: u32,
    pub variant_agent: String,
    pub warm_shadow_kv_prefix_hash: String,
    pub replayed_prefix_steps: usize,
    pub replayed_tokens_saved: u32,
    pub replayed_cost_saved_micro_usd: u64,
    pub prefix_replay_latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkRunPlanV1 {
    pub ok: bool,
    pub fork_at_step: u32,
    pub variant_agent: String,
    pub replayed_steps: Vec<u32>,
    pub warm_branch_ticket: ShadowKvWarmBranchTicketV1,
}

/// Canonicalizes a `serde_json::Value` according to RFC 8785 (JCS) UTF-16 key ordering.
#[must_use]
pub fn canonicalize_jcs_value(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut sorted_keys: Vec<&String> = map.keys().collect();
            sorted_keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut out = Map::with_capacity(map.len());
            for k in sorted_keys {
                if let Some(v) = map.get(k) {
                    out.insert(k.clone(), canonicalize_jcs_value(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_jcs_value).collect()),
        other => other.clone(),
    }
}

/// Computes the canonical RFC 8785 JCS SHA-256 hex digest of a JSON value.
#[must_use]
pub fn jcs_sha256_hex(val: &Value) -> String {
    if let Ok(raw) = serde_json::to_vec(val)
        && let Ok(jcs) = canonicalize_jcs_bytes(&raw)
    {
        return hex::encode(Sha256::digest(&jcs));
    }
    let canonical = canonicalize_jcs_value(val);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

#[must_use]
pub fn diff_json_paths(a: &Value, b: &Value) -> Vec<String> {
    let mut out = Vec::new();
    diff_json_paths_recursive("$", a, b, &mut out);
    out
}

fn diff_json_paths_recursive(prefix: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    if a == b {
        return;
    }
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            let mut keys: Vec<&String> = ma.keys().chain(mb.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let child_path = format!("{prefix}.{k}");
                match (ma.get(k), mb.get(k)) {
                    (Some(va), Some(vb)) => diff_json_paths_recursive(&child_path, va, vb, out),
                    _ => out.push(child_path),
                }
            }
        }
        (Value::Array(aa), Value::Array(ab)) => {
            let max_len = aa.len().max(ab.len());
            for idx in 0..max_len {
                let child_path = format!("{prefix}[{idx}]");
                match (aa.get(idx), ab.get(idx)) {
                    (Some(va), Some(vb)) => diff_json_paths_recursive(&child_path, va, vb, out),
                    _ => out.push(child_path),
                }
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

#[must_use]
pub fn resolve_json_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let trimmed = path.strip_prefix('$').unwrap_or(path);
    let mut current = root;
    for segment in trimmed.split('.').filter(|s| !s.is_empty()) {
        if let Some((key, rest)) = segment.split_once('[') {
            if !key.is_empty() {
                current = current.get(key)?;
            }
            let idx_str = rest.strip_suffix(']')?;
            let idx = idx_str.parse::<usize>().ok()?;
            current = current.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(current)
}

/// Replays a `TombstoneCassetteV1` against `candidate_steps` in microseconds at `$0` LLM spend.
#[must_use]
pub fn replay_tombstone_cassette(
    cassette: &TombstoneCassetteV1,
    candidate_steps: &[RecordedStepV1],
) -> CassetteReplayReportV1 {
    let start = std::time::Instant::now();
    let mut first_divergence: Option<StepDivergenceV1> = None;
    let mut served_steps = 0usize;

    for expected_step in cassette
        .steps
        .iter()
        .filter(|s| s.step_index < cassette.fork_at_step)
    {
        let Some(actual_step) = candidate_steps
            .iter()
            .find(|s| s.step_index == expected_step.step_index)
        else {
            first_divergence = Some(StepDivergenceV1 {
                step_index: expected_step.step_index,
                kind: expected_step.kind,
                expected_request_jcs_sha256: expected_step.request_jcs_sha256.clone(),
                actual_request_jcs_sha256: "<missing-step>".to_string(),
                changed_json_paths: vec!["$".to_string()],
            });
            break;
        };

        let computed_actual_hash = if !actual_step.request_json.is_null() {
            jcs_sha256_hex(&actual_step.request_json)
        } else {
            actual_step.request_jcs_sha256.clone()
        };

        if actual_step.kind != expected_step.kind
            || computed_actual_hash != expected_step.request_jcs_sha256
        {
            let mut changed_paths =
                diff_json_paths(&expected_step.request_json, &actual_step.request_json);
            if changed_paths.is_empty() {
                changed_paths.push("$.request_jcs_sha256".to_string());
            }
            first_divergence = Some(StepDivergenceV1 {
                step_index: expected_step.step_index,
                kind: actual_step.kind,
                expected_request_jcs_sha256: expected_step.request_jcs_sha256.clone(),
                actual_request_jcs_sha256: computed_actual_hash,
                changed_json_paths: changed_paths,
            });
            break;
        }
        served_steps += 1;
    }

    let mut expectation_results = Vec::with_capacity(cassette.expectations.len());
    for exp in &cassette.expectations {
        match exp {
            CassetteExpectationV1::JsonPathEquals {
                step_index,
                json_path,
                expected,
            } => {
                let actual_val = candidate_steps
                    .iter()
                    .find(|s| s.step_index == *step_index)
                    .and_then(|s| resolve_json_path(&s.response_json, json_path));
                let passed = actual_val == Some(expected);
                expectation_results.push(ExpectationCheckResultV1 {
                    description: format!("step[{step_index}] {json_path} == {expected}"),
                    passed,
                    detail: match actual_val {
                        Some(v) => format!("actual={v}"),
                        None => "path not found".to_string(),
                    },
                });
            }
            CassetteExpectationV1::MaxToolCalls { max_calls } => {
                let tool_calls = candidate_steps
                    .iter()
                    .filter(|s| s.kind == StepKindV1::Tool)
                    .count() as u32;
                let passed = tool_calls <= *max_calls;
                expectation_results.push(ExpectationCheckResultV1 {
                    description: format!("tool_calls <= {max_calls}"),
                    passed,
                    detail: format!("actual_tool_calls={tool_calls}"),
                });
            }
            CassetteExpectationV1::ForbiddenPattern { pattern } => {
                let violated = candidate_steps.iter().any(|s| {
                    s.request_json.to_string().contains(pattern)
                        || s.response_json.to_string().contains(pattern)
                });
                expectation_results.push(ExpectationCheckResultV1 {
                    description: format!("forbidden_pattern !contains `{pattern}`"),
                    passed: !violated,
                    detail: if violated {
                        format!("found forbidden pattern `{pattern}`")
                    } else {
                        "clean".to_string()
                    },
                });
            }
            CassetteExpectationV1::MustMatchPrefixHash {
                step_index,
                expected_prefix_hash,
            } => {
                let actual_prefix = candidate_steps
                    .iter()
                    .find(|s| s.step_index == *step_index)
                    .and_then(|s| s.shadow_kv_prefix_hash.as_ref());
                let passed = actual_prefix == Some(expected_prefix_hash);
                expectation_results.push(ExpectationCheckResultV1 {
                    description: format!(
                        "step[{step_index}] shadow_kv_prefix_hash == {expected_prefix_hash}"
                    ),
                    passed,
                    detail: match actual_prefix {
                        Some(h) => format!("actual={h}"),
                        None => "no shadow_kv_prefix_hash on step".to_string(),
                    },
                });
            }
        }
    }

    let all_expectations_ok = expectation_results.iter().all(|r| r.passed);
    let passed = first_divergence.is_none() && all_expectations_ok;
    let elapsed_us = start.elapsed().as_micros() as u64;
    let tap_line = if passed {
        format!(
            "ok - {} (source={}, served_steps={}, cost=$0.00)",
            cassette.tombstone_id, cassette.source_run_id, served_steps
        )
    } else {
        format!(
            "not ok - {} (source={}, served_steps={})",
            cassette.tombstone_id, cassette.source_run_id, served_steps
        )
    };

    CassetteReplayReportV1 {
        tombstone_id: cassette.tombstone_id.clone(),
        source_run_id: cassette.source_run_id.clone(),
        passed,
        served_steps,
        elapsed_us,
        zero_llm_spend: true,
        zero_network_calls: true,
        first_divergence,
        expectation_results,
        tap_line,
    }
}

/// Executes all `.json` cassettes inside `dir` sorted lexicographically for determinism.
pub fn replay_regression_dir(dir: &Path) -> Result<(bool, Vec<CassetteReplayReportV1>), String> {
    if !dir.exists() {
        return Ok((true, Vec::new()));
    }
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("failed to read regressions dir `{}`: {e}", dir.display()))?;
    let mut json_paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    json_paths.sort();

    let mut reports = Vec::with_capacity(json_paths.len());
    let mut all_passed = true;
    for path in json_paths {
        let raw = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read cassette `{}`: {e}", path.display()))?;
        let cassette: TombstoneCassetteV1 = serde_json::from_str(&raw)
            .map_err(|e| format!("malformed cassette JSON `{}`: {e}", path.display()))?;
        let report = replay_tombstone_cassette(&cassette, &cassette.steps);
        if !report.passed {
            all_passed = false;
        }
        reports.push(report);
    }
    Ok((all_passed, reports))
}

fn pair_weight(a: &RecordedStepV1, b: &RecordedStepV1) -> Option<(u32, AlignmentStatusV1)> {
    if a.kind != b.kind {
        return None;
    }
    if a.request_jcs_sha256 == b.request_jcs_sha256 && a.response_json == b.response_json {
        Some((3, AlignmentStatusV1::Equal))
    } else if a.request_jcs_sha256 != b.request_jcs_sha256 {
        Some((1, AlignmentStatusV1::RequestChanged))
    } else {
        Some((1, AlignmentStatusV1::ResponseChanged))
    }
}

/// Aligns two agent trajectories using Weighted-LCS (`equal` = 3, same-kind change = 1, insert/delete = 0).
#[must_use]
pub fn diff_runs_weighted_lcs(
    run_a: &[RecordedStepV1],
    run_b: &[RecordedStepV1],
) -> TrajectoryDiffReportV1 {
    let n = run_a.len();
    let m = run_b.len();
    let mut dp = vec![vec![0u32; m + 1]; n + 1];

    for i in (0..n).rev() {
        for j in (0..m).rev() {
            let mut best = dp[i + 1][j].max(dp[i][j + 1]);
            if let Some((w, _)) = pair_weight(&run_a[i], &run_b[j]) {
                let candidate = w + dp[i + 1][j + 1];
                if candidate >= best {
                    best = candidate;
                }
            }
            dp[i][j] = best;
        }
    }

    let mut i = 0;
    let mut j = 0;
    let mut alignment = Vec::with_capacity(n + m);
    let mut first_divergence: Option<TrajectoryDivergenceV1> = None;
    let mut shadow_kv_reused_tokens = 0u32;

    while i < n || j < m {
        if i < n
            && j < m
            && let Some((w, status)) = pair_weight(&run_a[i], &run_b[j])
            && dp[i][j] == w + dp[i + 1][j + 1]
        {
            let changed_json_paths = match status {
                AlignmentStatusV1::Equal => {
                    if run_a[i].shadow_kv_prefix_hash.is_some()
                        && run_a[i].shadow_kv_prefix_hash == run_b[j].shadow_kv_prefix_hash
                    {
                        shadow_kv_reused_tokens =
                            shadow_kv_reused_tokens.saturating_add(run_b[j].tokens_in);
                    }
                    Vec::new()
                }
                AlignmentStatusV1::RequestChanged => {
                    let mut p = diff_json_paths(&run_a[i].request_json, &run_b[j].request_json);
                    if p.is_empty() {
                        p.push("$.request_jcs_sha256".to_string());
                    }
                    p
                }
                AlignmentStatusV1::ResponseChanged => {
                    let mut p = diff_json_paths(&run_a[i].response_json, &run_b[j].response_json);
                    if p.is_empty() {
                        p.push("$.response_json".to_string());
                    }
                    p
                }
                AlignmentStatusV1::Inserted | AlignmentStatusV1::Deleted => Vec::new(),
            };

            if status != AlignmentStatusV1::Equal && first_divergence.is_none() {
                first_divergence = Some(TrajectoryDivergenceV1 {
                    step_a: Some(run_a[i].step_index),
                    step_b: Some(run_b[j].step_index),
                    kind: run_a[i].kind,
                    status,
                    changed_json_paths: changed_json_paths.clone(),
                });
            }

            alignment.push(AlignedStepRowV1 {
                step_a: Some(run_a[i].step_index),
                step_b: Some(run_b[j].step_index),
                kind: run_a[i].kind,
                status,
                changed_json_paths,
            });
            i += 1;
            j += 1;
            continue;
        }

        if i < n && (j == m || dp[i + 1][j] >= dp[i][j + 1]) {
            if first_divergence.is_none() {
                first_divergence = Some(TrajectoryDivergenceV1 {
                    step_a: Some(run_a[i].step_index),
                    step_b: None,
                    kind: run_a[i].kind,
                    status: AlignmentStatusV1::Deleted,
                    changed_json_paths: vec!["$".to_string()],
                });
            }
            alignment.push(AlignedStepRowV1 {
                step_a: Some(run_a[i].step_index),
                step_b: None,
                kind: run_a[i].kind,
                status: AlignmentStatusV1::Deleted,
                changed_json_paths: vec!["$".to_string()],
            });
            i += 1;
        } else if j < m {
            if first_divergence.is_none() {
                first_divergence = Some(TrajectoryDivergenceV1 {
                    step_a: None,
                    step_b: Some(run_b[j].step_index),
                    kind: run_b[j].kind,
                    status: AlignmentStatusV1::Inserted,
                    changed_json_paths: vec!["$".to_string()],
                });
            }
            alignment.push(AlignedStepRowV1 {
                step_a: None,
                step_b: Some(run_b[j].step_index),
                kind: run_b[j].kind,
                status: AlignmentStatusV1::Inserted,
                changed_json_paths: vec!["$".to_string()],
            });
            j += 1;
        }
    }

    let llm_a = run_a.iter().filter(|s| s.kind == StepKindV1::Llm).count() as i64;
    let llm_b = run_b.iter().filter(|s| s.kind == StepKindV1::Llm).count() as i64;
    let tool_a = run_a.iter().filter(|s| s.kind == StepKindV1::Tool).count() as i64;
    let tool_b = run_b.iter().filter(|s| s.kind == StepKindV1::Tool).count() as i64;
    let tok_in_a: i64 = run_a.iter().map(|s| s.tokens_in as i64).sum();
    let tok_in_b: i64 = run_b.iter().map(|s| s.tokens_in as i64).sum();
    let tok_out_a: i64 = run_a.iter().map(|s| s.tokens_out as i64).sum();
    let tok_out_b: i64 = run_b.iter().map(|s| s.tokens_out as i64).sum();
    let cost_a: i64 = run_a.iter().map(|s| s.cost_micro_usd as i64).sum();
    let cost_b: i64 = run_b.iter().map(|s| s.cost_micro_usd as i64).sum();

    let dur_a = match (run_a.first(), run_a.last()) {
        (Some(f), Some(l)) => l.simulated_clock_ms.saturating_sub(f.simulated_clock_ms) as i64,
        _ => 0,
    };
    let dur_b = match (run_b.first(), run_b.last()) {
        (Some(f), Some(l)) => l.simulated_clock_ms.saturating_sub(f.simulated_clock_ms) as i64,
        _ => 0,
    };

    TrajectoryDiffReportV1 {
        identical: first_divergence.is_none(),
        total_weight: dp[0][0],
        first_divergence,
        alignment,
        steps_delta: (m as i64) - (n as i64),
        llm_calls_delta: llm_b - llm_a,
        tool_calls_delta: tool_b - tool_a,
        tokens_in_delta: tok_in_b - tok_in_a,
        tokens_out_delta: tok_out_b - tok_out_a,
        cost_micro_usd_delta: cost_b - cost_a,
        latency_ms_delta: dur_b - dur_a,
        shadow_kv_reused_tokens,
    }
}

/// Replays prefix steps `0..at_step` in `0 ms` at `$0` spend and mints a warm Shadow-KV branch ticket.
pub fn fork_run_with_shadow_kv(
    parent_run: &[RecordedStepV1],
    at_step: u32,
    variant_agent: &str,
) -> Result<ForkRunPlanV1, String> {
    if at_step == 0 {
        return Err("fork-run requires --at-step >= 1".to_string());
    }
    let prefix_steps: Vec<&RecordedStepV1> = parent_run
        .iter()
        .filter(|s| s.step_index < at_step)
        .collect();
    if prefix_steps.is_empty() {
        return Err(format!("no steps found before step {at_step}"));
    }

    let mut replayed_steps = Vec::with_capacity(prefix_steps.len());
    let mut replayed_tokens_saved = 0u32;
    let mut replayed_cost_saved_micro_usd = 0u64;
    let mut warm_prefix_hash: Option<String> = None;

    for step in &prefix_steps {
        if !step.request_json.is_null() {
            let computed = jcs_sha256_hex(&step.request_json);
            if !step.request_jcs_sha256.is_empty() && computed != step.request_jcs_sha256 {
                return Err(format!(
                    "canonical JCS SHA-256 mismatch at prefix step {}: expected {}, got {}",
                    step.step_index, step.request_jcs_sha256, computed
                ));
            }
        }
        replayed_steps.push(step.step_index);
        replayed_tokens_saved = replayed_tokens_saved
            .saturating_add(step.tokens_in)
            .saturating_add(step.tokens_out);
        replayed_cost_saved_micro_usd =
            replayed_cost_saved_micro_usd.saturating_add(step.cost_micro_usd);
        if let Some(h) = &step.shadow_kv_prefix_hash {
            warm_prefix_hash = Some(h.clone());
        }
    }

    let warm_shadow_kv_prefix_hash = warm_prefix_hash.unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"chinwag-shadow-kv-prefix-v1\0");
        for s in &prefix_steps {
            hasher.update(s.request_jcs_sha256.as_bytes());
        }
        format!("cw-kv-{}", &hex::encode(hasher.finalize())[..16])
    });

    let mut ticket_hasher = Sha256::new();
    ticket_hasher
        .update(format!("{warm_shadow_kv_prefix_hash}:{at_step}:{variant_agent}").as_bytes());
    let ticket_id = format!("fork-kv-{}", &hex::encode(ticket_hasher.finalize())[..12]);

    Ok(ForkRunPlanV1 {
        ok: true,
        fork_at_step: at_step,
        variant_agent: variant_agent.to_string(),
        replayed_steps: replayed_steps.clone(),
        warm_branch_ticket: ShadowKvWarmBranchTicketV1 {
            ticket_id,
            fork_at_step: at_step,
            variant_agent: variant_agent.to_string(),
            warm_shadow_kv_prefix_hash,
            replayed_prefix_steps: replayed_steps.len(),
            replayed_tokens_saved,
            replayed_cost_saved_micro_usd,
            prefix_replay_latency_ms: 0,
        },
    })
}
