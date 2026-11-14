// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `CHWG-0278`: Pure-Rust `$0`-LLM Multi-Language Diagnostic Parser, Multi-Shard
//! Cascade Coalescer, Pre-Wake Infra Fault Filter, and `<= 400`-Token
//! `ReviewPacketV2.test_evidence` `AssertedFailureHeader` Builder.
//!
//! Normalizes `cargo`/`rustc --message-format=json`, `cargo-nextest`, TypeScript
//! external subprocesses (`tsc`, `tsgo`, `tsrs --noEmit`, and
//! `oxlint --type-aware --type-check`), `pytest`, and `go test -json` with zero
//! `tsrs_*` Cargo dependencies.

use crate::packet::{
    Artifact, AssertedFailureHeader, AssertedSuiteRun, MAX_FAILURE_HEADER_BYTES,
    MAX_FAILURE_HEADER_TOKENS, Sha256Digest, TestCounts,
};
use crate::unified_gates::scrubber::{scrub_ci_secrets, strip_ansi_and_prompt_injections};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Maximum `.codegraph` symbol-neighborhood pointers attached per diagnostic report.
pub const MAX_CODEGRAPH_POINTERS: usize = 5;

/// Canonical normalized tool family (`tsc`, `tsgo`, `tsrs`, and `oxlint --type-aware`
/// all map to `TypeScript` so identical errors produce byte-identical headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticToolKind {
    RustcCargo,
    CargoNextest,
    TypeScript,
    Pytest,
    GoTest,
    GenericCi,
}

impl DiagnosticToolKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RustcCargo => "rustc",
            Self::CargoNextest => "nextest",
            Self::TypeScript => "typescript",
            Self::Pytest => "pytest",
            Self::GoTest => "go-test",
            Self::GenericCi => "generic-ci",
        }
    }
}

/// External TypeScript typecheck subprocess backend (`0` `tsrs_*` Cargo crate linkage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TypeScriptBackendKind {
    Tsc,
    Tsgo,
    Tsrs,
    OxlintTypeAware,
}

/// Subprocess invocation contract for external TypeScript checkers, including
/// `--maxMemory` OOM bounding for `tsc`/`tsgo`/`tsrs` (`CHWG-0278`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeScriptSubprocessConfig {
    pub backend: TypeScriptBackendKind,
    pub tsconfig_path: Option<String>,
    pub max_memory_mb: Option<u32>,
}

impl TypeScriptSubprocessConfig {
    /// Builds deterministic external subprocess `argv` without linking any TS crate.
    #[must_use]
    pub fn build_argv(&self) -> Vec<String> {
        let mut argv = match self.backend {
            TypeScriptBackendKind::Tsc => {
                vec![
                    "tsc".to_string(),
                    "--noEmit".to_string(),
                    "--pretty".to_string(),
                    "false".to_string(),
                ]
            }
            TypeScriptBackendKind::Tsgo => vec!["tsgo".to_string(), "--noEmit".to_string()],
            TypeScriptBackendKind::Tsrs => vec!["tsrs".to_string(), "--noEmit".to_string()],
            TypeScriptBackendKind::OxlintTypeAware => vec![
                "oxlint".to_string(),
                "--type-aware".to_string(),
                "--type-check".to_string(),
            ],
        };
        if let Some(tsconfig) = &self.tsconfig_path
            && !tsconfig.trim().is_empty()
        {
            match self.backend {
                TypeScriptBackendKind::OxlintTypeAware => {
                    argv.push("--tsconfig".to_string());
                    argv.push(tsconfig.clone());
                }
                _ => {
                    argv.push("--project".to_string());
                    argv.push(tsconfig.clone());
                }
            }
        }
        if let Some(mem_mb) = self.max_memory_mb
            && matches!(
                self.backend,
                TypeScriptBackendKind::Tsc
                    | TypeScriptBackendKind::Tsgo
                    | TypeScriptBackendKind::Tsrs
            )
        {
            argv.push("--maxMemory".to_string());
            argv.push(mem_mb.to_string());
        }
        argv
    }
}

/// Normalized root-cause diagnostic span across all supported languages/runners.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NormalizedDiagnosticSpan {
    pub tool: DiagnosticToolKind,
    pub repo_path: String,
    pub line_start: u32,
    pub col_start: u32,
    pub error_code: String,
    pub root_symbol: String,
    pub primary_message: String,
}

impl NormalizedDiagnosticSpan {
    /// Deterministic SHA-256 fingerprint independent of timestamps, PIDs, or ANSI escapes.
    #[must_use]
    pub fn fingerprint_sha256(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"chinwag-diag-span-v1\0");
        for part in [
            self.tool.as_str().as_bytes(),
            self.repo_path.as_bytes(),
            &self.line_start.to_be_bytes(),
            &self.col_start.to_be_bytes(),
            self.error_code.as_bytes(),
            self.root_symbol.as_bytes(),
            self.primary_message.as_bytes(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Sha256Digest::parse(&hex::encode(hasher.finalize()))
            .unwrap_or_else(|_| Sha256Digest::of(b"fallback"))
    }
}

/// Operator-owned infrastructure / auth fault reason codes (`0` coding-agent wakes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfraFaultReasonCode {
    HttpAuthInterstitial401Or403,
    OidcTokenExchangeTimeout,
    RunnerDiskFullEnospc,
    PreTestTlsOrDnsFault,
    RegistryUpstream5xx,
}

/// Pre-wake classification routing candidate code defects vs operator-owned infra faults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FaultClassification {
    CandidateCodeFailure,
    InfraTransientOrAuth {
        reason_code: InfraFaultReasonCode,
        summary: String,
    },
}

/// Operator incident artifact emitted when `FaultClassification::InfraTransientOrAuth` matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorOwnedIncidentV1 {
    pub schema: String,
    pub suite_id: String,
    pub reason_code: InfraFaultReasonCode,
    pub summary: String,
    pub full_log_sha256: Sha256Digest,
    pub full_log_bytes: u64,
    pub coding_agent_wakes_invoked: u32,
    pub route_target: String,
}

/// Optional `.codegraph` symbol neighborhood lookup (`<= 5` `repo_path:line` pointers).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodegraphSymbolIndex {
    pub symbol_to_locations: BTreeMap<String, Vec<String>>,
}

impl CodegraphSymbolIndex {
    pub fn load_from_repo(repo_root: &Path) -> Option<Self> {
        let candidate = repo_root.join(".codegraph/symbols.json");
        let raw = fs::read_to_string(candidate).ok()?;
        serde_json::from_str::<Self>(&raw).ok()
    }

    #[must_use]
    pub fn lookup_bounded(&self, symbols: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for sym in symbols {
            if let Some(locs) = self.symbol_to_locations.get(sym) {
                for loc in locs {
                    if !out.contains(loc) {
                        out.push(loc.clone());
                        if out.len() >= MAX_CODEGRAPH_POINTERS {
                            return out;
                        }
                    }
                }
            }
        }
        out
    }
}

/// Single shard input supplied to `coalesce_and_triage_shards`.
#[derive(Debug, Clone)]
pub struct ShardDiagnosticInput {
    pub shard_id: String,
    pub suite_id: String,
    pub raw_log: Vec<u8>,
    pub exit_code: i32,
}

/// Complete `$0`-LLM triage report across one or more matrix shards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageReportV1 {
    pub classification: FaultClassification,
    pub root_diagnostics: Vec<NormalizedDiagnosticSpan>,
    pub suppressed_cascade_count: usize,
    pub coalesced_shard_count: usize,
    pub failure_fingerprint_sha256: Sha256Digest,
    pub codegraph_pointers: Vec<String>,
    pub counts: TestCounts,
    pub failure_header_text: String,
    pub failure_header_tokens: u64,
    pub full_log_sha256: Sha256Digest,
    pub full_log_bytes: u64,
    pub operator_incident: Option<OperatorOwnedIncidentV1>,
}

/// Conservative BPE upper-bound token estimator (`<= 400`-token `ReviewPacketV2` contract).
///
/// Guarantees `estimated >= ceil(utf8_bytes / 3)` AND `>= punctuation_and_word_chunks`,
/// so `ReviewPacketV2` `asserted_tokens` never undercounts real tokenizer consumption.
#[must_use]
pub fn estimate_conservative_tokens(text: &str) -> u64 {
    if text.is_empty() {
        return 0;
    }
    let byte_bound = (text.len() as u64).div_ceil(3);
    let mut chunk_count = 0u64;
    let mut in_alnum = false;
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            if !in_alnum {
                chunk_count += 1;
                in_alnum = true;
            }
        } else {
            in_alnum = false;
            if !ch.is_whitespace() {
                chunk_count += 1;
            }
        }
    }
    byte_bound.max(chunk_count).max(1)
}

fn normalize_repo_rel_path(raw: &str) -> String {
    let slash = raw.trim().replace('\\', "/");
    let stripped = slash.trim_start_matches("./").trim_start_matches('/');
    if stripped.is_empty() {
        "unknown".to_string()
    } else {
        stripped.to_string()
    }
}

fn normalize_message(msg: &str) -> String {
    let collapsed: String = msg.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(220).collect()
}

/// Parses structured and human diagnostics across Rust (`cargo`/`rustc`, `nextest`),
/// TypeScript (`tsc`, `tsgo`, `tsrs --noEmit`, `oxlint --type-aware --type-check`),
/// Python (`pytest`), and Go (`go test -json`).
#[must_use]
pub fn parse_multilang_diagnostics(
    scrubbed_clean_log: &str,
) -> (Vec<NormalizedDiagnosticSpan>, TestCounts) {
    let mut spans: Vec<NormalizedDiagnosticSpan> = Vec::new();
    let mut counts = TestCounts {
        passed: 0,
        failed: 0,
        ignored: 0,
        filtered: 0,
    };

    // Check if entire payload is a single JSON document (e.g., oxlint --format json or pytest json)
    let trimmed_whole = scrubbed_clean_log.trim();
    if (trimmed_whole.starts_with('{') || trimmed_whole.starts_with('['))
        && (!trimmed_whole.contains('\n') || serde_json::from_str::<Value>(trimmed_whole).is_ok())
    {
        parse_single_json_payload(trimmed_whole, &mut spans, &mut counts);
    }

    let lines: Vec<&str> = scrubbed_clean_log.lines().collect();
    let mut idx = 0usize;
    let mut go_last_loc: BTreeMap<String, (String, u32, String)> = BTreeMap::new();
    let mut pending_rust_err: Option<(String, String)> = None;
    let mut pending_nextest_name: Option<String> = None;
    let mut pending_oxlint_header: Option<(String, String)> = None;

    while idx < lines.len() {
        let line = lines[idx].trim();
        if line.is_empty() {
            idx += 1;
            continue;
        }

        // 1. NDJSON lines: cargo/rustc --message-format=json, nextest libtest json, go test -json, oxlint json line
        if line.starts_with('{')
            && let Ok(val) = serde_json::from_str::<Value>(line)
            && parse_json_line(&val, &mut spans, &mut counts, &mut go_last_loc)
        {
            idx += 1;
            continue;
        }

        // 2. JUnit XML <testcase ...><failure ...> (nextest / pytest junit)
        if line.contains("<testcase") && line.contains("name=\"") {
            let test_name =
                extract_xml_attr(line, "name").unwrap_or_else(|| "junit_test".to_string());
            let file_attr = extract_xml_attr(line, "file")
                .or_else(|| extract_xml_attr(line, "classname"))
                .unwrap_or_else(|| "unknown".to_string());
            if idx + 1 < lines.len() && lines[idx + 1].contains("<failure") {
                let fail_line = lines[idx + 1];
                let msg = extract_xml_attr(fail_line, "message")
                    .unwrap_or_else(|| "test assertion failed".to_string());
                counts.failed += 1;
                spans.push(NormalizedDiagnosticSpan {
                    tool: DiagnosticToolKind::CargoNextest,
                    repo_path: normalize_repo_rel_path(&file_attr),
                    line_start: 1,
                    col_start: 1,
                    error_code: "TEST_FAILURE".to_string(),
                    root_symbol: test_name,
                    primary_message: normalize_message(&msg),
                });
                idx += 2;
                continue;
            }
        }

        // 3. Human rustc / clippy header: `error[E0308]: mismatched types` or `error: ...`
        if let Some(rest) = line.strip_prefix("error") {
            if let Some(after_bracket) = rest.strip_prefix('[')
                && let Some((code, msg_rest)) = after_bracket.split_once("]:")
            {
                pending_rust_err = Some((code.trim().to_string(), normalize_message(msg_rest)));
                idx += 1;
                continue;
            } else if let Some(msg_rest) = rest.strip_prefix(':') {
                let msg_clean = normalize_message(msg_rest);
                if !msg_clean.starts_with("aborting due to")
                    && !msg_clean.starts_with("could not compile")
                {
                    pending_rust_err = Some(("RUSTC_ERR".to_string(), msg_clean));
                    idx += 1;
                    continue;
                }
            }
        }
        if let Some((code, msg)) = pending_rust_err.as_ref()
            && let Some(arrow) = line.strip_prefix("-->")
            && let Some((path, ln, col)) = parse_path_line_col(arrow.trim())
        {
            spans.push(NormalizedDiagnosticSpan {
                tool: DiagnosticToolKind::RustcCargo,
                repo_path: normalize_repo_rel_path(&path),
                line_start: ln,
                col_start: col,
                error_code: code.clone(),
                root_symbol: "compile_unit".to_string(),
                primary_message: msg.clone(),
            });
            pending_rust_err = None;
            idx += 1;
            continue;
        }

        // 4. Human nextest / cargo test panic output
        if let Some(rest) = line.strip_prefix("---- ")
            && let Some(test_sym) = rest.strip_suffix(" stdout ----")
        {
            pending_nextest_name = Some(test_sym.trim().to_string());
            idx += 1;
            continue;
        }
        if line.contains("panicked at ")
            && let Some((_, after_panic)) = line.split_once("panicked at ")
        {
            let loc_candidate = after_panic.trim_end_matches(':');
            if let Some((path, ln, col)) = parse_path_line_col(loc_candidate) {
                let msg = if idx + 1 < lines.len() && !lines[idx + 1].trim().is_empty() {
                    normalize_message(lines[idx + 1])
                } else {
                    normalize_message(after_panic)
                };
                let sym = pending_nextest_name
                    .take()
                    .or_else(|| extract_rust_thread_name(line))
                    .unwrap_or_else(|| "rust_test".to_string());
                counts.failed += 1;
                spans.push(NormalizedDiagnosticSpan {
                    tool: DiagnosticToolKind::CargoNextest,
                    repo_path: normalize_repo_rel_path(&path),
                    line_start: ln,
                    col_start: col,
                    error_code: "TEST_PANIC".to_string(),
                    root_symbol: sym,
                    primary_message: msg,
                });
                idx += 1;
                continue;
            }
        }

        // 5. TypeScript (`tsc`, `tsgo`, `tsrs --noEmit`, `oxlint --type-aware --type-check`)
        if let Some(ts_span) = try_parse_typescript_line(line) {
            spans.push(ts_span);
            idx += 1;
            continue;
        }
        // oxlint graphical header: `x typescript(TS2322): Type 'number' is not assignable to type 'string'`
        // or `× typescript(TS2322): ...` followed by `,-[src/auth.ts:42:10]`
        if let Some(ox_hdr) = try_parse_oxlint_header(line) {
            pending_oxlint_header = Some(ox_hdr);
            idx += 1;
            continue;
        }
        if let Some((code, msg)) = pending_oxlint_header.as_ref()
            && let Some((path, ln, col)) = try_parse_oxlint_span_bracket(line)
        {
            let (base_msg, sym) = split_trailing_symbol_tag(msg);
            spans.push(NormalizedDiagnosticSpan {
                tool: DiagnosticToolKind::TypeScript,
                repo_path: normalize_repo_rel_path(&path),
                line_start: ln,
                col_start: col,
                error_code: code.clone(),
                root_symbol: sym,
                primary_message: base_msg,
            });
            pending_oxlint_header = None;
            idx += 1;
            continue;
        }

        // 6. Pytest summary line: `FAILED tests/test_auth.py::test_token_expiry - AssertionError: token expired`
        if let Some(rest) = line.strip_prefix("FAILED ")
            && let Some((nodeid, reason)) = rest.split_once(" - ")
            && let Some((file_part, test_sym)) = nodeid.trim().split_once("::")
        {
            let (err_code, msg) = reason
                .split_once(':')
                .map(|(k, m)| (k.trim().to_string(), normalize_message(m)))
                .unwrap_or_else(|| ("PYTEST_FAIL".to_string(), normalize_message(reason)));
            let line_no = find_pytest_line_number(&lines, file_part.trim()).unwrap_or(1);
            counts.failed += 1;
            spans.push(NormalizedDiagnosticSpan {
                tool: DiagnosticToolKind::Pytest,
                repo_path: normalize_repo_rel_path(file_part),
                line_start: line_no,
                col_start: 1,
                error_code: err_code,
                root_symbol: test_sym.trim().to_string(),
                primary_message: msg,
            });
            idx += 1;
            continue;
        }

        // 7. Human `go test` output: `--- FAIL: TestVerifyToken (0.01s)`
        if let Some(rest) = line.strip_prefix("--- FAIL: ") {
            let test_sym = rest
                .split_whitespace()
                .next()
                .unwrap_or("GoTest")
                .to_string();
            let mut file_path = "unknown.go".to_string();
            let mut line_no = 1u32;
            let mut msg = "go test failed".to_string();
            if idx + 1 < lines.len() {
                let next_trimmed = lines[idx + 1].trim();
                if let Some((p, l, m)) = parse_go_test_location_line(next_trimmed) {
                    file_path = p;
                    line_no = l;
                    msg = m;
                }
            }
            counts.failed += 1;
            spans.push(NormalizedDiagnosticSpan {
                tool: DiagnosticToolKind::GoTest,
                repo_path: normalize_repo_rel_path(&file_path),
                line_start: line_no,
                col_start: 1,
                error_code: "GO_TEST_FAIL".to_string(),
                root_symbol: test_sym,
                primary_message: msg,
            });
            idx += 1;
            continue;
        }

        // Libtest summary counts: `test result: FAILED. 12 passed; 2 failed; 1 ignored; 0 measured; 0 filtered out`
        if line.starts_with("test result:") {
            parse_libtest_summary_counts(line, &mut counts);
        }

        idx += 1;
    }

    (spans, counts)
}

fn parse_single_json_payload(
    raw_json: &str,
    spans: &mut Vec<NormalizedDiagnosticSpan>,
    counts: &mut TestCounts,
) {
    let Ok(val) = serde_json::from_str::<Value>(raw_json) else {
        return;
    };
    if let Some(diags) = val
        .get("diagnostics")
        .and_then(|v| v.as_array())
        .or_else(|| val.as_array())
    {
        for d in diags {
            if let Some(ts_span) = parse_typescript_or_oxlint_json_diag(d) {
                spans.push(ts_span);
            }
        }
    }
    if let Some(tests) = val.get("tests").and_then(|v| v.as_array()) {
        for t in tests {
            let outcome = t.get("outcome").and_then(|v| v.as_str()).unwrap_or("");
            match outcome {
                "passed" => counts.passed += 1,
                "skipped" => counts.ignored += 1,
                "failed" | "error" => {
                    counts.failed += 1;
                    let nodeid = t
                        .get("nodeid")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown.py::test");
                    let (file_part, sym) = nodeid.split_once("::").unwrap_or((nodeid, "pytest"));
                    let line_no = t.get("lineno").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
                    let msg = t
                        .pointer("/call/crash/message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("pytest assertion failed");
                    spans.push(NormalizedDiagnosticSpan {
                        tool: DiagnosticToolKind::Pytest,
                        repo_path: normalize_repo_rel_path(file_part),
                        line_start: line_no.max(1),
                        col_start: 1,
                        error_code: "PYTEST_FAIL".to_string(),
                        root_symbol: sym.to_string(),
                        primary_message: normalize_message(msg),
                    });
                }
                _ => {}
            }
        }
    }
}

fn parse_json_line(
    val: &Value,
    spans: &mut Vec<NormalizedDiagnosticSpan>,
    counts: &mut TestCounts,
    go_last_loc: &mut BTreeMap<String, (String, u32, String)>,
) -> bool {
    // A. cargo / rustc --message-format=json
    if val.get("reason").and_then(|v| v.as_str()) == Some("compiler-message") {
        if let Some(msg_obj) = val.get("message")
            && msg_obj.get("level").and_then(|v| v.as_str()) == Some("error")
        {
            let raw_msg = msg_obj
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("compiler error");
            if raw_msg.starts_with("aborting due to") || raw_msg.starts_with("could not compile") {
                return true;
            }
            let code = msg_obj
                .pointer("/code/code")
                .and_then(|v| v.as_str())
                .unwrap_or("RUSTC_ERR")
                .to_string();
            let target_sym = val
                .pointer("/target/name")
                .and_then(|v| v.as_str())
                .unwrap_or("compile_unit")
                .to_string();
            if let Some(span_arr) = msg_obj.get("spans").and_then(|v| v.as_array()) {
                let chosen = span_arr
                    .iter()
                    .find(|s| s.get("is_primary").and_then(|b| b.as_bool()) == Some(true))
                    .or_else(|| span_arr.first());
                if let Some(sp) = chosen {
                    let file_name = sp
                        .get("file_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown.rs");
                    let line_start =
                        sp.get("line_start").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
                    let col_start =
                        sp.get("column_start").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
                    spans.push(NormalizedDiagnosticSpan {
                        tool: DiagnosticToolKind::RustcCargo,
                        repo_path: normalize_repo_rel_path(file_name),
                        line_start: line_start.max(1),
                        col_start: col_start.max(1),
                        error_code: code,
                        root_symbol: target_sym,
                        primary_message: normalize_message(raw_msg),
                    });
                }
            }
        }
        return true;
    }

    // B. cargo-nextest / libtest JSON (`{"type":"test","event":"failed","name":"...","stdout":"..."}`)
    if val.get("type").and_then(|v| v.as_str()) == Some("test")
        && let Some(event) = val.get("event").and_then(|v| v.as_str())
    {
        match event {
            "ok" => counts.passed += 1,
            "ignored" => counts.ignored += 1,
            "failed" => {
                counts.failed += 1;
                let name = val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("rust_test")
                    .to_string();
                let stdout = val.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
                let (path, ln, col, msg) = extract_panic_from_stdout(stdout);
                spans.push(NormalizedDiagnosticSpan {
                    tool: DiagnosticToolKind::CargoNextest,
                    repo_path: normalize_repo_rel_path(&path),
                    line_start: ln,
                    col_start: col,
                    error_code: "TEST_FAILURE".to_string(),
                    root_symbol: name,
                    primary_message: msg,
                });
            }
            _ => {}
        }
        return true;
    }

    // C. go test -json (`{"Action":"output"|"fail"|"pass","Package":"...","Test":"...","Output":"..."}`)
    if let Some(action) = val.get("Action").and_then(|v| v.as_str())
        && val.get("Package").is_some()
    {
        let pkg = val.get("Package").and_then(|v| v.as_str()).unwrap_or("pkg");
        if let Some(test_name) = val.get("Test").and_then(|v| v.as_str()) {
            let key = format!("{pkg}::{test_name}");
            match action {
                "output" => {
                    if let Some(out) = val.get("Output").and_then(|v| v.as_str())
                        && let Some((f, l, m)) = parse_go_test_location_line(out.trim())
                    {
                        let joined = if f.contains('/') {
                            f
                        } else {
                            format!("{}/{f}", pkg.trim_end_matches('/'))
                        };
                        go_last_loc.insert(key, (joined, l, m));
                    }
                }
                "pass" => counts.passed += 1,
                "skip" => counts.ignored += 1,
                "fail" => {
                    counts.failed += 1;
                    let (f, l, m) = go_last_loc.remove(&key).unwrap_or_else(|| {
                        (
                            format!("{pkg}/unknown_test.go"),
                            1,
                            "go test failed".to_string(),
                        )
                    });
                    spans.push(NormalizedDiagnosticSpan {
                        tool: DiagnosticToolKind::GoTest,
                        repo_path: normalize_repo_rel_path(&f),
                        line_start: l,
                        col_start: 1,
                        error_code: "GO_TEST_FAIL".to_string(),
                        root_symbol: test_name.to_string(),
                        primary_message: m,
                    });
                }
                _ => {}
            }
        }
        return true;
    }

    // D. Single-line TypeScript / oxlint JSON diagnostic object
    if let Some(ts_span) = parse_typescript_or_oxlint_json_diag(val) {
        spans.push(ts_span);
        return true;
    }

    false
}

fn normalize_ts_code(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed
        .strip_prefix("typescript(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return inner.trim().to_string();
    }
    if let Some(inner) = trimmed
        .strip_prefix("ts(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return inner.trim().to_string();
    }
    trimmed.to_string()
}

fn split_trailing_symbol_tag(msg: &str) -> (String, String) {
    let norm = normalize_message(msg);
    if let Some((before, bracket)) = norm.rsplit_once(" [symbol:")
        && let Some(sym) = bracket.strip_suffix(']')
    {
        return (before.trim().to_string(), sym.trim().to_string());
    }
    (norm, "typecheck".to_string())
}

fn parse_typescript_or_oxlint_json_diag(val: &Value) -> Option<NormalizedDiagnosticSpan> {
    let file = val
        .get("filename")
        .or_else(|| val.get("file"))
        .and_then(|v| v.as_str())?;
    let raw_code = val.get("code").and_then(|v| v.as_str())?;
    let code = normalize_ts_code(raw_code);
    if !code.starts_with("TS") && !raw_code.contains("typescript(") {
        return None;
    }
    let msg = val.get("message").and_then(|v| v.as_str())?;
    let line = val
        .get("line")
        .and_then(|v| v.as_u64())
        .or_else(|| val.pointer("/labels/0/span/line").and_then(|v| v.as_u64()))
        .unwrap_or(1) as u32;
    let col = val
        .get("column")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            val.pointer("/labels/0/span/column")
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(1) as u32;
    let (base_msg, parsed_sym) = split_trailing_symbol_tag(msg);
    let sym = val
        .get("symbol")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or(parsed_sym);
    Some(NormalizedDiagnosticSpan {
        tool: DiagnosticToolKind::TypeScript,
        repo_path: normalize_repo_rel_path(file),
        line_start: line.max(1),
        col_start: col.max(1),
        error_code: code,
        root_symbol: sym,
        primary_message: base_msg,
    })
}

fn try_parse_typescript_line(line: &str) -> Option<NormalizedDiagnosticSpan> {
    // Format 1: `src/auth.ts(42,10): error TS2322: Type 'number' is not assignable to type 'string'.`
    if let Some((lhs, rhs)) = line.split_once("): error TS")
        && let Some((file_part, coords)) = lhs.rsplit_once('(')
        && let Some((l_str, c_str)) = coords.split_once(',')
        && let (Ok(ln), Ok(col)) = (l_str.trim().parse::<u32>(), c_str.trim().parse::<u32>())
        && let Some((digits, msg)) = rhs.split_once(':')
        && digits.chars().all(|c| c.is_ascii_digit())
    {
        let (base_msg, sym) = split_trailing_symbol_tag(msg.trim().trim_end_matches('.'));
        return Some(NormalizedDiagnosticSpan {
            tool: DiagnosticToolKind::TypeScript,
            repo_path: normalize_repo_rel_path(file_part),
            line_start: ln,
            col_start: col,
            error_code: format!("TS{digits}"),
            root_symbol: sym,
            primary_message: base_msg,
        });
    }

    // Format 2: `src/auth.ts:42:10 - error TS2322: Type 'number' is not assignable to type 'string'.`
    // or `src/auth.ts:42:10: error TS2322: ...` (tsc --pretty, tsgo, tsrs, oxlint unix format)
    for sep in [
        " - error TS",
        ": error TS",
        " - error typescript(TS",
        ": error typescript(TS",
    ] {
        if let Some((lhs, rhs)) = line.split_once(sep)
            && let Some((path, ln, col)) = parse_path_line_col(lhs.trim())
            && let Some((code_part, msg)) = rhs.split_once(':')
        {
            let digits = code_part.trim().trim_end_matches(')');
            if digits.chars().all(|c| c.is_ascii_digit()) {
                let (base_msg, sym) = split_trailing_symbol_tag(msg.trim().trim_end_matches('.'));
                return Some(NormalizedDiagnosticSpan {
                    tool: DiagnosticToolKind::TypeScript,
                    repo_path: normalize_repo_rel_path(&path),
                    line_start: ln,
                    col_start: col,
                    error_code: format!("TS{digits}"),
                    root_symbol: sym,
                    primary_message: base_msg,
                });
            }
        }
    }
    None
}

fn try_parse_oxlint_header(line: &str) -> Option<(String, String)> {
    for marker in ["typescript(TS", "ts(TS"] {
        if let Some(pos) = line.find(marker) {
            let after = &line[pos + marker.len()..];
            if let Some((digits, msg_rest)) = after.split_once("):")
                && digits.chars().all(|c| c.is_ascii_digit())
            {
                let cleaned_msg = msg_rest.trim().trim_end_matches('.').to_string();
                return Some((format!("TS{digits}"), cleaned_msg));
            }
        }
    }
    None
}

fn try_parse_oxlint_span_bracket(line: &str) -> Option<(String, u32, u32)> {
    let start = line.find('[')?;
    let end = line[start + 1..].find(']')?;
    let inside = &line[start + 1..start + 1 + end];
    parse_path_line_col(inside)
}

fn parse_path_line_col(raw: &str) -> Option<(String, u32, u32)> {
    let parts: Vec<&str> = raw.rsplitn(3, ':').collect();
    if parts.len() == 3
        && let (Ok(col), Ok(ln)) = (
            parts[0].trim().parse::<u32>(),
            parts[1].trim().parse::<u32>(),
        )
    {
        return Some((parts[2].trim().to_string(), ln.max(1), col.max(1)));
    }
    None
}

fn extract_panic_from_stdout(stdout: &str) -> (String, u32, u32, String) {
    let lines: Vec<&str> = stdout.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if let Some((_, after)) = line.split_once("panicked at ") {
            let loc = after.trim().trim_end_matches(':');
            if let Some((p, ln, col)) = parse_path_line_col(loc) {
                let msg = lines
                    .get(i + 1)
                    .map(|s| normalize_message(s))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "test panicked".to_string());
                return (p, ln, col, msg);
            }
        }
    }
    (
        "unknown.rs".to_string(),
        1,
        1,
        normalize_message(stdout.lines().next().unwrap_or("test failed")),
    )
}

fn extract_rust_thread_name(line: &str) -> Option<String> {
    let (_, after) = line.split_once("thread '")?;
    let (name, _) = after.split_once('\'')?;
    if name == "main" {
        None
    } else {
        Some(name.to_string())
    }
}

fn extract_xml_attr(line: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let pos = line.find(&needle)?;
    let rest = &line[pos + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn find_pytest_line_number(lines: &[&str], file_part: &str) -> Option<u32> {
    let prefix = format!("{file_part}:");
    for line in lines {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(&prefix)
            && let Some((num_s, _)) = rest.split_once(':')
            && let Ok(n) = num_s.trim().parse::<u32>()
        {
            return Some(n.max(1));
        }
    }
    None
}

fn parse_go_test_location_line(line: &str) -> Option<(String, u32, String)> {
    let (lhs, rhs) = line.split_once(".go:")?;
    let file_name = lhs
        .split_whitespace()
        .next_back()
        .map(|s| format!("{s}.go"))?;
    let (ln_str, msg) = rhs.split_once(':')?;
    let ln = ln_str.trim().parse::<u32>().ok()?;
    Some((file_name, ln.max(1), normalize_message(msg)))
}

fn parse_libtest_summary_counts(line: &str, counts: &mut TestCounts) {
    for chunk in line.split([';', '.']) {
        let words: Vec<&str> = chunk.split_whitespace().collect();
        if words.len() >= 2
            && let Ok(n) = words[0].parse::<u64>()
        {
            match words[1] {
                "passed" => counts.passed = counts.passed.max(n),
                "failed" => counts.failed = counts.failed.max(n),
                "ignored" => counts.ignored = counts.ignored.max(n),
                "filtered" => counts.filtered = counts.filtered.max(n),
                _ => {}
            }
        }
    }
}

/// Classifies whether a failure log represents an infrastructure/auth transient fault
/// (`0` coding-agent wakes) or a candidate code defect (`INV-PRE-WAKE-INFRA-FILTER-01`).
///
/// Anti-spoofing invariant: when structured compiler/test diagnostic spans exist
/// (and no OS-level `ENOSPC` write abort prevented compilation), string literals inside
/// failing test output cannot spoof `InfraTransientOrAuth`.
/// Detects genuine test-runner execution framing across Rust `libtest`/`nextest`, Go `go test`,
/// Python `pytest`, and JS/TS Vitest/Jest so `Result`-returning or custom test failures that emit
/// HTML `401`/`403`, OIDC, or DNS strings cannot spoof `InfraTransientOrAuth` (`[AF-03]`).
#[must_use]
pub fn has_test_runner_framing(scrubbed_clean_log: &str) -> bool {
    for line in scrubbed_clean_log.lines() {
        let t = line.trim();
        if (t.starts_with("running ") && (t.ends_with(" test") || t.ends_with(" tests")))
            || (t.starts_with("---- ") && t.ends_with(" stdout ----"))
            || t.starts_with("test result: FAILED.")
            || t.starts_with("test result: ok.")
            || t.starts_with("=== RUN   ")
            || t.starts_with("--- FAIL: ")
            || line.starts_with("FAIL\t")
            || (t.starts_with("===") && t.contains("test session starts"))
            || (t.starts_with("===") && t.contains("FAILURES ==="))
            || t.starts_with("Test Suites:")
        {
            return true;
        }
    }
    false
}

/// Hardened pre-wake fault classifier: if structured compiler/test spans OR test-runner framing
/// exist (and no OS-level `ENOSPC` write abort prevented execution), string literals inside
/// failing test output cannot spoof `InfraTransientOrAuth`.
#[must_use]
pub fn classify_pre_wake_fault(
    scrubbed_clean_log: &str,
    parsed_spans: &[NormalizedDiagnosticSpan],
    counts: &TestCounts,
    any_nonzero_exit: bool,
) -> FaultClassification {
    if !any_nonzero_exit && parsed_spans.is_empty() && counts.failed == 0 {
        return FaultClassification::CandidateCodeFailure;
    }
    let lower = scrubbed_clean_log.to_ascii_lowercase();
    let framed_test_run =
        has_test_runner_framing(scrubbed_clean_log) || counts.failed > 0 || counts.passed > 0;

    // True runner disk exhaustion (`ENOSPC`) is always an operator host incident even mid-build
    // unless a candidate test span explicitly ran and panicked without host write errors.
    let has_test_span = parsed_spans.iter().any(|s| {
        matches!(
            s.tool,
            DiagnosticToolKind::CargoNextest
                | DiagnosticToolKind::Pytest
                | DiagnosticToolKind::GoTest
        )
    });
    if !has_test_span
        && (lower.contains("no space left on device (os error 28)")
            || lower.contains("enospc: no space left on device")
            || lower.contains("write failed: no space left on device"))
    {
        return FaultClassification::InfraTransientOrAuth {
            reason_code: InfraFaultReasonCode::RunnerDiskFullEnospc,
            summary: "runner filesystem exhausted (ENOSPC); route to operator incident queue"
                .to_string(),
        };
    }

    // If structured candidate compiler/test spans OR test-runner framing exist, never let test payload strings spoof infra!
    if !parsed_spans.is_empty() || framed_test_run {
        return FaultClassification::CandidateCodeFailure;
    }

    // Zero structured code/test spans — inspect pre-test transport/auth/OIDC/HTML interstitials
    let has_html_envelope = lower.contains("<!doctype html") || lower.contains("<html");
    if has_html_envelope
        && (lower.contains("401 unauthorized")
            || lower.contains("403 forbidden")
            || lower.contains("cloudflare")
            || lower.contains("access denied"))
    {
        return FaultClassification::InfraTransientOrAuth {
            reason_code: InfraFaultReasonCode::HttpAuthInterstitial401Or403,
            summary: "upstream HTTP 401/403 HTML interstitial encountered before suite execution"
                .to_string(),
        };
    }

    if lower.contains("oidc token exchange")
        || lower.contains("actions_id_token_request_url")
        || lower.contains("failed to get actions oidc token")
        || (lower.contains("oidc") && lower.contains("timed out"))
    {
        return FaultClassification::InfraTransientOrAuth {
            reason_code: InfraFaultReasonCode::OidcTokenExchangeTimeout,
            summary: "OIDC token exchange failed or timed out prior to candidate execution"
                .to_string(),
        };
    }

    if lower.contains("enospc") || lower.contains("no space left on device") {
        return FaultClassification::InfraTransientOrAuth {
            reason_code: InfraFaultReasonCode::RunnerDiskFullEnospc,
            summary: "runner disk exhausted (ENOSPC) prior to candidate execution".to_string(),
        };
    }

    if lower.contains("could not resolve host")
        || lower.contains("getaddrinfo eai_again")
        || lower.contains("temporary failure in name resolution")
        || lower.contains("tls handshake eof")
        || lower.contains("ssl routines")
    {
        return FaultClassification::InfraTransientOrAuth {
            reason_code: InfraFaultReasonCode::PreTestTlsOrDnsFault,
            summary: "pre-test DNS or TLS transport fault prevented runner bootstrap".to_string(),
        };
    }

    if has_html_envelope
        && (lower.contains("502 bad gateway")
            || lower.contains("503 service unavailable")
            || lower.contains("504 gateway time-out"))
    {
        return FaultClassification::InfraTransientOrAuth {
            reason_code: InfraFaultReasonCode::RegistryUpstream5xx,
            summary: "upstream package/artifact gateway returned 502/503/504 HTML interstitial"
                .to_string(),
        };
    }

    FaultClassification::CandidateCodeFailure
}

/// Deduplicates identical spans across shards and collapses secondary follow-on cascades
/// within the same file (such as unresolved-type fallout lines) to root-cause spans.
#[must_use]
pub fn deduplicate_and_collapse_cascades(
    raw_spans: Vec<NormalizedDiagnosticSpan>,
) -> (Vec<NormalizedDiagnosticSpan>, usize) {
    let total_input = raw_spans.len();
    let mut unique = BTreeSet::new();
    for s in raw_spans {
        unique.insert(s);
    }

    let mut sorted: Vec<NormalizedDiagnosticSpan> = unique.into_iter().collect();
    sorted.sort_by(|a, b| {
        a.repo_path
            .cmp(&b.repo_path)
            .then_with(|| a.line_start.cmp(&b.line_start))
            .then_with(|| a.col_start.cmp(&b.col_start))
            .then_with(|| a.error_code.cmp(&b.error_code))
    });

    let mut roots: Vec<NormalizedDiagnosticSpan> = Vec::new();
    let mut anchored_files: BTreeMap<String, u32> = BTreeMap::new();

    for span in sorted {
        let is_secondary_cascade = if let Some(&first_line) = anchored_files.get(&span.repo_path) {
            let msg_lower = span.primary_message.to_ascii_lowercase();
            span.line_start >= first_line
                && (span.error_code == "E0282"
                    || span.error_code == "TS7006"
                    || msg_lower.contains("type annotations needed")
                    || msg_lower.contains("cannot infer type")
                    || msg_lower.contains("implicitly has an 'any' type"))
        } else {
            false
        };

        if !is_secondary_cascade {
            anchored_files
                .entry(span.repo_path.clone())
                .or_insert(span.line_start);
            roots.push(span);
        }
    }

    let suppressed = total_input.saturating_sub(roots.len());
    (roots, suppressed)
}

/// Formats root-cause diagnostics into a strict `<= 400`-token (`<= 1,600`-byte) UTF-8
/// `failure_header` string marked as untrusted advisory diagnostic data.
#[must_use]
pub fn format_bounded_failure_header(
    roots: &[NormalizedDiagnosticSpan],
    suppressed_cascade_count: usize,
    coalesced_shard_count: usize,
    codegraph_pointers: &[String],
    fallback_excerpt: &str,
) -> (String, u64) {
    let mut lines = Vec::new();
    lines.push(format!(
        "[UNTRUSTED_DIAGNOSTIC_DATA] roots={} suppressed={} shards={}",
        roots.len(),
        suppressed_cascade_count,
        coalesced_shard_count
    ));

    if roots.is_empty() {
        let excerpt = normalize_message(fallback_excerpt);
        let clipped: String = excerpt.chars().take(360).collect();
        lines.push(format!(
            "generic-ci [CI_EXIT_NONZERO] unknown:1:1 :: {}",
            if clipped.is_empty() {
                "command exited non-zero"
            } else {
                clipped.as_str()
            }
        ));
    } else {
        for root in roots.iter().take(8) {
            lines.push(format!(
                "{} [{}] {}:{}:{} ({}) :: {}",
                root.tool.as_str(),
                root.error_code,
                root.repo_path,
                root.line_start,
                root.col_start,
                root.root_symbol,
                root.primary_message
            ));
        }
        if roots.len() > 8 {
            lines.push(format!(
                "... +{} additional root diagnostics",
                roots.len() - 8
            ));
        }
    }

    if !codegraph_pointers.is_empty() {
        lines.push(format!(
            "codegraph_refs: {}",
            codegraph_pointers
                .iter()
                .take(MAX_CODEGRAPH_POINTERS)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // Incrementally admit lines while guaranteeing <= 1,600 UTF-8 bytes AND <= 400 tokens
    let mut accepted = String::new();
    for line in lines {
        let candidate = if accepted.is_empty() {
            line
        } else {
            format!("{accepted}\n{line}")
        };
        if candidate.len() <= MAX_FAILURE_HEADER_BYTES
            && estimate_conservative_tokens(&candidate) <= MAX_FAILURE_HEADER_TOKENS
        {
            accepted = candidate;
        } else {
            break;
        }
    }

    if accepted.is_empty() {
        accepted = "[UNTRUSTED_DIAGNOSTIC_DATA] CI_EXIT_NONZERO".to_string();
    }
    let tokens = estimate_conservative_tokens(&accepted).clamp(1, MAX_FAILURE_HEADER_TOKENS);
    (accepted, tokens)
}

/// Coalesces one or more shard logs into a single `$0`-LLM `TriageReportV1`.
#[must_use]
pub fn coalesce_and_triage_shards(
    shards: &[ShardDiagnosticInput],
    env_snapshot: &[(String, String)],
    codegraph_index: Option<&CodegraphSymbolIndex>,
) -> TriageReportV1 {
    let mut combined_scrubbed = String::new();
    let mut raw_spans = Vec::new();
    let mut total_counts = TestCounts {
        passed: 0,
        failed: 0,
        ignored: 0,
        filtered: 0,
    };
    let mut any_nonzero_exit = false;

    for (idx, shard) in shards.iter().enumerate() {
        if shard.exit_code != 0 {
            any_nonzero_exit = true;
        }
        let lossy = String::from_utf8_lossy(&shard.raw_log);
        let (deansied, _, _) = strip_ansi_and_prompt_injections(&lossy);
        let scrubbed = scrub_ci_secrets(&deansied, env_snapshot);
        let clean = scrubbed.scrubbed_text;
        if idx > 0 && !combined_scrubbed.ends_with('\n') {
            combined_scrubbed.push('\n');
        }
        combined_scrubbed.push_str(&clean);

        let (shard_spans, shard_counts) = parse_multilang_diagnostics(&clean);
        raw_spans.extend(shard_spans);
        total_counts.passed += shard_counts.passed;
        total_counts.failed += shard_counts.failed;
        total_counts.ignored += shard_counts.ignored;
        total_counts.filtered += shard_counts.filtered;
    }

    let full_log_bytes_vec = combined_scrubbed.as_bytes();
    let full_log_sha256 = Sha256Digest::of(full_log_bytes_vec);
    let full_log_bytes = full_log_bytes_vec.len() as u64;

    let (roots, suppressed_cascade_count) = deduplicate_and_collapse_cascades(raw_spans);
    let classification =
        classify_pre_wake_fault(&combined_scrubbed, &roots, &total_counts, any_nonzero_exit);

    if any_nonzero_exit
        && total_counts.failed == 0
        && matches!(classification, FaultClassification::CandidateCodeFailure)
    {
        total_counts.failed = roots.len().max(1) as u64;
    }

    let failure_fingerprint_sha256 = if let Some(primary) = roots.first() {
        let mut h = Sha256::new();
        h.update(b"chinwag-failure-set-v1\0");
        for r in &roots {
            h.update(r.fingerprint_sha256().as_str().as_bytes());
        }
        Sha256Digest::parse(&hex::encode(h.finalize()))
            .unwrap_or_else(|_| primary.fingerprint_sha256())
    } else {
        full_log_sha256.clone()
    };

    let symbols: Vec<String> = roots.iter().map(|r| r.root_symbol.clone()).collect();
    let codegraph_pointers = codegraph_index
        .map(|idx| idx.lookup_bounded(&symbols))
        .unwrap_or_default();

    let coalesced_shard_count = shards.len().max(1);
    let (failure_header_text, failure_header_tokens) = format_bounded_failure_header(
        &roots,
        suppressed_cascade_count,
        coalesced_shard_count,
        &codegraph_pointers,
        &combined_scrubbed,
    );

    let suite_id = shards
        .first()
        .map(|s| s.suite_id.clone())
        .unwrap_or_else(|| "default".to_string());
    let operator_incident = match &classification {
        FaultClassification::InfraTransientOrAuth {
            reason_code,
            summary,
        } => Some(OperatorOwnedIncidentV1 {
            schema: "chinwag.operator-incident.v1".to_string(),
            suite_id,
            reason_code: *reason_code,
            summary: summary.clone(),
            full_log_sha256: full_log_sha256.clone(),
            full_log_bytes,
            coding_agent_wakes_invoked: 0,
            route_target: "OPERATOR_INCIDENT_QUEUE".to_string(),
        }),
        FaultClassification::CandidateCodeFailure => None,
    };

    TriageReportV1 {
        classification,
        root_diagnostics: roots,
        suppressed_cascade_count,
        coalesced_shard_count,
        failure_fingerprint_sha256,
        codegraph_pointers,
        counts: total_counts,
        failure_header_text,
        failure_header_tokens,
        full_log_sha256,
        full_log_bytes,
        operator_incident,
    }
}

/// Converts a `CandidateCodeFailure` `TriageReportV1` (or passing run) directly into
/// a wire-compatible `ReviewPacketV2.test_evidence` `AssertedSuiteRun`.
///
/// Refuses to convert `InfraTransientOrAuth` into a coding-agent `AssertedSuiteRun`
/// (`INV-PRE-WAKE-INFRA-FILTER-01`).
pub fn build_asserted_suite_run(
    suite_id: &str,
    argv: Vec<String>,
    toolchain: &str,
    exit_code: i32,
    scrubbed_full_log_bytes: &[u8],
    report: &TriageReportV1,
) -> Result<AssertedSuiteRun, String> {
    if let FaultClassification::InfraTransientOrAuth {
        reason_code,
        summary,
    } = &report.classification
    {
        return Err(format!(
            "INFRA_TRANSIENT_OR_AUTH ({reason_code:?}): {summary} — route to OperatorOwnedIncidentV1 with 0 coding-agent wakes"
        ));
    }

    let full_log = Artifact::from_bytes(scrubbed_full_log_bytes);
    let (counts, failure_header) = if exit_code == 0 && report.counts.failed == 0 {
        (
            TestCounts {
                passed: report.counts.passed,
                failed: 0,
                ignored: report.counts.ignored,
                filtered: report.counts.filtered,
            },
            None,
        )
    } else {
        let nonzero_exit = if exit_code == 0 { 1 } else { exit_code };
        let _ = nonzero_exit;
        let failed = report.counts.failed.max(1);
        (
            TestCounts {
                passed: report.counts.passed,
                failed,
                ignored: report.counts.ignored,
                filtered: report.counts.filtered,
            },
            Some(AssertedFailureHeader {
                body: Artifact::from_bytes(report.failure_header_text.as_bytes()),
                asserted_tokens: report.failure_header_tokens,
            }),
        )
    };

    Ok(AssertedSuiteRun {
        suite_id: suite_id.to_string(),
        argv,
        toolchain: toolchain.to_string(),
        exit_code: if counts.failed > 0 && exit_code == 0 {
            1
        } else {
            exit_code
        },
        counts,
        full_log,
        failure_header,
    })
}
