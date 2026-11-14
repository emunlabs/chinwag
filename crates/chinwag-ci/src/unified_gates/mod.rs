// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! `CHWG-0277`: Unified `chinwag-ci` Gate Suite (`wrap`, `verify-signer`,
//! `test-regressions`, `diff-run`, `fork-run`, `coalesce`, `policy-gate`,
//! `surface-gate`, `ui-gate`, `attest-green`, `triage`, `flywheel`, `memory`,
//! and `selftest`) parameterized via CLI flags, environment variables, and
//! `.chinwag/fleet.toml` with zero hardcoded organization constants
//! (`INV-CUSTOMER-CONFIGURABLE-NO-HARDCODING-01`).

pub mod attest_green;
pub mod cassette_replay;
pub mod coalesce;
pub mod policy_gate;
pub mod scrubber;
pub mod selftest;
pub mod surface_gate;
pub mod ui_gate;
pub mod verify_signer;
pub mod wrap;

use crate::diagnostics_triage::{
    CodegraphSymbolIndex, ShardDiagnosticInput, coalesce_and_triage_shards,
};
use crate::flywheel::{
    DEFAULT_MAX_ACTIVE_TOMBSTONES_PER_PATH, DEFAULT_PROMOTION_RECURRENCE_THRESHOLD,
    GreenVerificationEvidence, OverheadBudgetGuard, RedCaptureEvidence,
    detect_red_to_green_transition, mint_bounded_exact_path_tombstone, mint_regression_cassette,
    promote_recurring_exact_path_tombstones, retain_candidate_fix_entry,
};
use crate::packet::{AssertedTombstone, jcs_from_serializable};
use attest_green::CiGreenReceiptV1;
use cassette_replay::{
    RecordedStepV1, TombstoneCassetteV1, diff_runs_weighted_lcs, fork_run_with_shadow_kv,
    replay_regression_dir,
};
use coalesce::coalesce_shard_records;
use ed25519_dalek::{Signature, Signer, SigningKey};
use policy_gate::{EXIT_FAIL_CLOSED_HOLD, execute_policy_gate};
use selftest::run_selftest;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use surface_gate::{
    SurfaceGatePolicyOptions, execute_surface_gate_with_policy, parse_surface_manifest_file,
};
use ui_gate::{UiGateSurface, execute_ui_gate};
use verify_signer::execute_verify_signer;
use wrap::execute_wrap;
use zeroize::Zeroizing;

/// Ephemeral per-invocation `Ed25519` runner signer generated from the OS CSPRNG
/// (`getrandom::fill` into `Zeroizing<[u8; 32]>`).
pub struct EphemeralRunnerSigner {
    signing_key: SigningKey,
}

impl EphemeralRunnerSigner {
    pub fn generate() -> Result<Self, String> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed).map_err(|e| format!("OS CSPRNG failure: {e}"))?;
        if bool::from(seed.ct_eq(&[0u8; 32])) {
            return Err("OS CSPRNG produced all-zero seed".to_string());
        }
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

/// Resolves the caller's organization identifier without any hardcoded organization default
/// (`--org` -> `CHINWAG_ORG` -> `.chinwag/fleet.toml` `org = "..."` -> `"default"`),
/// returning `(org_slug, org_id_hash_sha256)`.
#[must_use]
pub fn resolve_org_id_hash(
    explicit_org: Option<&str>,
    repo_root: Option<&Path>,
) -> (String, String) {
    let org_slug = explicit_org
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            std::env::var("CHINWAG_ORG")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            let root = repo_root?;
            let raw = fs::read_to_string(root.join(".chinwag/fleet.toml")).ok()?;
            for line in raw.lines() {
                let t = line.trim();
                if t.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = t.split_once('=')
                    && k.trim() == "org"
                {
                    let unquoted = v.trim().trim_matches('"').trim_matches('\'').trim();
                    if !unquoted.is_empty() {
                        return Some(unquoted.to_string());
                    }
                }
            }
            None
        })
        .unwrap_or_else(|| "default".to_string());

    let mut h = Sha256::new();
    h.update(b"chinwag-org-id-v2:");
    h.update(org_slug.as_bytes());
    (org_slug, hex::encode(h.finalize()))
}

#[must_use]
pub fn unified_help_text() -> &'static str {
    "\
chinwag-ci — Unified Cryptographic CI Runner, Diagnostics Triage & RED->GREEN Flywheel

USAGE:
  chinwag-ci <SUBCOMMAND> [OPTIONS]

UNIFIED GATE & FLYWHEEL SUBCOMMANDS:
  wrap               Execute a command, scrub secrets, triage diagnostics, and sign WrapReceiptV1
  verify-signer      Validate .chinwag/allowed_signers 1-to-1 Ed25519 bijection and commit signer
  test-regressions   Replay .chinwag/regressions RFC-8785 JCS cassettes in <50ms at $0 LLM spend
  diff-run           Align two recorded trajectories via deterministic Weighted-LCS
  fork-run           Compute Shadow-KV prefix replay warm branch ticket
  coalesce           Deduplicate parallel matrix shard failures within the 1,400ms storm window
  policy-gate        Evaluate out-of-LLM WP-01..WP-06 workflow policy (fail-closed exit 78)
  surface-gate       Enforce 6-surface sync, 60m PR TTL, and monotonic cassette ratchet
  ui-gate            Enforce pricing, Markdown, RFC-6598 CGNAT zero-leak, and Playwright geometry
  attest-green       Mint Ed25519-signed CiGreenReceiptV1 for a verified green suite
  triage             Parse rustc/nextest/tsc/tsgo/tsrs/oxlint/pytest/go-test logs into <=400t header
  flywheel           Verify RED->GREEN transition, mint JCS cassette, and update configured bank
  memory             Promote bounded <=512B EXACT_PATH tombstones with 8k-token/32KB overhead guard
  selftest           Execute offline deterministic self-verification across all gates

DAEMON & OWNER SUBCOMMANDS:
  owner-init         Enroll hardware/owner root or studio public key
  owner-verify       Verify enrolled owner root or studio state
  policy-sign        Sign pinned repository policy artifact
  serve-root         Run root owner supervisor
  serve-studio       Run studio owner supervisor
  runner             Execute hosted runner admission capture
  agent-init         Enroll idle agent wake keypair
  agent-read         Read unsealed wake capture from local agent socket
"
}

/// Dispatches unified `CHWG-0277`/`CHWG-0278`/`CHWG-0279` subcommands if `args[1]` matches.
/// Returns `Some(exit_code)` when handled, or `None` so `main.rs` falls through to existing
/// owner/daemon subcommands untouched.
pub fn dispatch_unified_subcommand(args: &[OsString]) -> Option<u8> {
    let sub = args.get(1)?.to_str()?;
    let tail: Vec<String> = args[2..]
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();

    match sub {
        "--help" | "-h" | "help" => {
            print!("{}", unified_help_text());
            Some(0)
        }
        "selftest" => Some(cmd_selftest(&tail)),
        "verify-signer" => Some(cmd_verify_signer(&tail)),
        "test-regressions" => Some(cmd_test_regressions(&tail)),
        "diff-run" => Some(cmd_diff_run(&tail)),
        "fork-run" => Some(cmd_fork_run(&tail)),
        "coalesce" => Some(cmd_coalesce(&tail)),
        "policy-gate" => Some(cmd_policy_gate(&tail)),
        "ui-gate" => Some(cmd_ui_gate(&tail)),
        "surface-gate" => Some(cmd_surface_gate(&tail)),
        "attest-green" => Some(cmd_attest_green(&tail)),
        "wrap" => Some(cmd_wrap(&tail)),
        "triage" | "diagnostics-triage" => Some(cmd_triage(&tail)),
        "flywheel" => Some(cmd_flywheel(&tail)),
        "memory" => Some(cmd_memory(&tail)),
        _ => None,
    }
}

fn flag_val<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).map(String::as_str);
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{name}=")) {
            return Some(rest);
        }
        i += 1;
    }
    None
}

fn flag_vals(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
            continue;
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{name}=")) {
            out.push(rest.to_string());
        }
        i += 1;
    }
    out
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn cmd_selftest(args: &[String]) -> u8 {
    match run_selftest() {
        Ok(report) => {
            if has_flag(args, "--json") || !has_flag(args, "--quiet") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
            }
            if report.ok { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("CI_SELFTEST_FAILED: {e}");
            1
        }
    }
}

fn cmd_verify_signer(args: &[String]) -> u8 {
    let signers = flag_val(args, "--allowed-signers").unwrap_or(".chinwag/allowed_signers");
    let commit = flag_val(args, "--commit").unwrap_or("HEAD");
    let require_sig = !has_flag(args, "--allow-unsigned-commit");
    match execute_verify_signer(Path::new(signers), commit, require_sig) {
        Ok(rep) => {
            println!("{}", serde_json::to_string_pretty(&rep).unwrap_or_default());
            0
        }
        Err(e) => {
            eprintln!("CI_VERIFY_SIGNER_FAILED: {e}");
            1
        }
    }
}

fn cmd_test_regressions(args: &[String]) -> u8 {
    let dir = flag_val(args, "--dir").unwrap_or(".chinwag/regressions");
    match replay_regression_dir(Path::new(dir)) {
        Ok((passed, reports)) => {
            if has_flag(args, "--json") {
                let payload = json!({
                    "ok": passed,
                    "command": "chinwag-ci test-regressions",
                    "dir": dir,
                    "cassettes_replayed": reports.len(),
                    "reports": reports,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                for r in &reports {
                    println!("{}", r.tap_line);
                }
            }
            if passed { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("CI_TEST_REGRESSIONS_FAILED: {e}");
            1
        }
    }
}

fn load_steps_from_cassette_or_array(path: &Path) -> Result<Vec<RecordedStepV1>, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("unable to read `{}`: {e}", path.display()))?;
    if let Ok(cassette) = serde_json::from_str::<TombstoneCassetteV1>(&raw) {
        return Ok(cassette.steps);
    }
    serde_json::from_str::<Vec<RecordedStepV1>>(&raw)
        .map_err(|e| format!("invalid trajectory JSON `{}`: {e}", path.display()))
}

fn cmd_diff_run(args: &[String]) -> u8 {
    let Some(run_a) = flag_val(args, "--run-a").or_else(|| args.first().map(String::as_str)) else {
        eprintln!("CI_DIFF_RUN_USAGE: chinwag-ci diff-run --run-a <path> --run-b <path>");
        return 2;
    };
    let Some(run_b) = flag_val(args, "--run-b").or_else(|| args.get(1).map(String::as_str)) else {
        eprintln!("CI_DIFF_RUN_USAGE: chinwag-ci diff-run --run-a <path> --run-b <path>");
        return 2;
    };
    match (
        load_steps_from_cassette_or_array(Path::new(run_a)),
        load_steps_from_cassette_or_array(Path::new(run_b)),
    ) {
        (Ok(a), Ok(b)) => {
            let report = diff_runs_weighted_lcs(&a, &b);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            if has_flag(args, "--fail-on-diff") && !report.identical {
                1
            } else {
                0
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("CI_DIFF_RUN_FAILED: {e}");
            1
        }
    }
}

fn cmd_fork_run(args: &[String]) -> u8 {
    let Some(src) = flag_val(args, "--source") else {
        eprintln!("CI_FORK_RUN_USAGE: chinwag-ci fork-run --source <path> [--at-step <n>]");
        return 2;
    };
    let at_step = flag_val(args, "--at-step")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);
    let agent = flag_val(args, "--agent").unwrap_or("default-worker");
    match load_steps_from_cassette_or_array(Path::new(src))
        .and_then(|steps| fork_run_with_shadow_kv(&steps, at_step, agent))
    {
        Ok(plan) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&plan).unwrap_or_default()
            );
            0
        }
        Err(e) => {
            eprintln!("CI_FORK_RUN_FAILED: {e}");
            1
        }
    }
}

fn cmd_coalesce(args: &[String]) -> u8 {
    let commit = flag_val(args, "--commit").unwrap_or("HEAD");
    let shard_files = flag_vals(args, "--log");
    if shard_files.is_empty() {
        eprintln!("CI_COALESCE_USAGE: chinwag-ci coalesce --commit <sha> --log <path>...");
        return 2;
    }
    let mut inputs = Vec::with_capacity(shard_files.len());
    for (idx, file_path) in shard_files.iter().enumerate() {
        let Ok(raw) = fs::read_to_string(file_path) else {
            eprintln!("CI_COALESCE_READ_FAILED: `{file_path}`");
            return 1;
        };
        inputs.push((
            format!("shard-{:02}", idx + 1),
            raw,
            1_000 + (idx as u64) * 50,
        ));
    }
    let storms = coalesce_shard_records(commit, &inputs);
    let payload = json!({
        "ok": true,
        "command": "chinwag-ci coalesce",
        "commit_sha": commit,
        "input_shards": inputs.len(),
        "storm_groups": storms.len(),
        "storms": storms,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );
    0
}

fn cmd_policy_gate(args: &[String]) -> u8 {
    let Ok(signer) = EphemeralRunnerSigner::generate() else {
        eprintln!("CI_CSPRNG_INIT_FAILED");
        return 1;
    };
    let config_path = flag_val(args, "--config").map(Path::new);
    let signers =
        Path::new(flag_val(args, "--allowed-signers").unwrap_or(".chinwag/allowed_signers"));
    let base_ref = flag_val(args, "--base").unwrap_or("HEAD");
    let head_ref = flag_val(args, "--head").unwrap_or("HEAD");
    let run_id = flag_val(args, "--run-id").unwrap_or("local-run");
    let (_, org_hash) = resolve_org_id_hash(flag_val(args, "--org"), Some(Path::new(".")));

    match execute_policy_gate(
        &signer,
        config_path,
        signers,
        base_ref,
        head_ref,
        &org_hash,
        run_id,
    ) {
        Ok(receipt) => {
            if let Some(out) = flag_val(args, "--out") {
                let _ = fs::write(out, serde_json::to_vec_pretty(&receipt).unwrap_or_default());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt).unwrap_or_default()
            );
            if receipt.ok { 0 } else { EXIT_FAIL_CLOSED_HOLD }
        }
        Err(e) => {
            eprintln!("CI_POLICY_GATE_FAILED: {e}");
            EXIT_FAIL_CLOSED_HOLD
        }
    }
}

fn cmd_ui_gate(args: &[String]) -> u8 {
    let Ok(signer) = EphemeralRunnerSigner::generate() else {
        eprintln!("CI_CSPRNG_INIT_FAILED");
        return 1;
    };
    let surface_raw = flag_val(args, "--surface").unwrap_or("all");
    let surface = match UiGateSurface::parse(surface_raw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("CI_UI_GATE_FAILED: {e}");
            return 2;
        }
    };
    let repo_dir = flag_val(args, "--repo").map(Path::new);
    let audit_paths: Vec<PathBuf> = flag_vals(args, "--audit-json")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let forbidden_terms = flag_vals(args, "--forbidden-term");
    let ticket_id = flag_val(args, "--ticket").unwrap_or("CHWG-UI-GATE");
    let commit_sha = flag_val(args, "--commit").unwrap_or("HEAD");
    let (_, org_hash) = resolve_org_id_hash(flag_val(args, "--org"), repo_dir);

    match execute_ui_gate(
        &signer,
        surface,
        repo_dir,
        &audit_paths,
        &forbidden_terms,
        ticket_id,
        commit_sha,
        &org_hash,
    ) {
        Ok(receipt) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt).unwrap_or_default()
            );
            if receipt.passed { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("CI_UI_GATE_FAILED: {e}");
            1
        }
    }
}

fn cmd_surface_gate(args: &[String]) -> u8 {
    let Ok(signer) = EphemeralRunnerSigner::generate() else {
        eprintln!("CI_CSPRNG_INIT_FAILED");
        return 1;
    };
    let manifest_opt = flag_val(args, "--manifest").map(Path::new);
    let parsed_manifest = match manifest_opt {
        Some(p) => match parse_surface_manifest_file(p) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("CI_SURFACE_GATE_FAILED: {e}");
                return 1;
            }
        },
        None => Default::default(),
    };

    let ticket_id = flag_val(args, "--ticket")
        .map(ToOwned::to_owned)
        .or(parsed_manifest.ticket_id)
        .unwrap_or_else(|| "CHWG-SURFACE-GATE".to_string());
    let ws_root = flag_val(args, "--workspace-root").map(Path::new);
    let commit_sha = flag_val(args, "--commit").unwrap_or("HEAD");
    let (_, org_hash) = resolve_org_id_hash(flag_val(args, "--org"), ws_root);

    let changed_paths: Vec<String> = flag_vals(args, "--changed")
        .into_iter()
        .flat_map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect();

    let mut explicit_surfaces: Vec<String> = flag_vals(args, "--surfaces")
        .into_iter()
        .flat_map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect();
    if explicit_surfaces.is_empty() && !parsed_manifest.required_surfaces.is_empty() {
        explicit_surfaces = parsed_manifest.required_surfaces;
    }

    let mut layout = parsed_manifest.layout;
    if let Some(cd) = flag_val(args, "--code-dir") {
        layout.code_dir = Some(PathBuf::from(cd));
    }
    if let Some(dd) = flag_val(args, "--docs-dir") {
        layout.docs_dir = Some(PathBuf::from(dd));
    }
    if let Some(sd) = flag_val(args, "--site-dir") {
        layout.site_dir = Some(PathBuf::from(sd));
    }
    if let Some(pd) = flag_val(args, "--proxy-dir") {
        layout.proxy_dir = Some(PathBuf::from(pd));
    }
    if let Some(owner) = flag_val(args, "--adr-owner") {
        layout.adr_owner = Some(owner.to_string());
    }

    let policy = SurfaceGatePolicyOptions {
        pr_created_at_epoch: flag_val(args, "--pr-created-at").and_then(|v| v.parse().ok()),
        now_epoch_override: flag_val(args, "--now-epoch").and_then(|v| v.parse().ok()),
        max_pr_age_secs: flag_val(args, "--max-pr-age-secs")
            .and_then(|v| v.parse().ok())
            .or(parsed_manifest.max_pr_age_secs),
        expected_behaviors: parsed_manifest.expected_behaviors,
        min_cassettes_count: flag_val(args, "--min-cassettes")
            .and_then(|v| v.parse().ok())
            .or(parsed_manifest.min_cassettes_count),
        layout,
    };

    match execute_surface_gate_with_policy(
        &signer,
        &ticket_id,
        ws_root,
        &changed_paths,
        &explicit_surfaces,
        commit_sha,
        &org_hash,
        &policy,
    ) {
        Ok(receipt) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt).unwrap_or_default()
            );
            if receipt.passed { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("CI_SURFACE_GATE_FAILED: {e}");
            1
        }
    }
}

fn cmd_attest_green(args: &[String]) -> u8 {
    let Ok(signer) = EphemeralRunnerSigner::generate() else {
        eprintln!("CI_CSPRNG_INIT_FAILED");
        return 1;
    };
    let (_, org_hash) = resolve_org_id_hash(flag_val(args, "--org"), Some(Path::new(".")));
    let suite = flag_val(args, "--suite").unwrap_or("default-suite");
    let commit = flag_val(args, "--commit").unwrap_or("HEAD");
    let run_id = flag_val(args, "--run-id").unwrap_or("ci-run");
    let target = flag_val(args, "--target").unwrap_or(std::env::consts::ARCH);

    match CiGreenReceiptV1::build_signed(&signer, &org_hash, run_id, commit, suite, target, None) {
        Ok(receipt) => {
            if let Some(out) = flag_val(args, "--out") {
                let _ = fs::write(out, serde_json::to_vec_pretty(&receipt).unwrap_or_default());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt).unwrap_or_default()
            );
            0
        }
        Err(e) => {
            eprintln!("CI_ATTEST_GREEN_FAILED: {e}");
            1
        }
    }
}

fn cmd_wrap(args: &[String]) -> u8 {
    let Some(sep_pos) = args.iter().position(|a| a == "--") else {
        eprintln!("CI_WRAP_USAGE: chinwag-ci wrap [--org <org>] [--suite-id <id>] -- <cmd...>");
        return 2;
    };
    let opts = &args[..sep_pos];
    let cmd_argv = &args[sep_pos + 1..];
    if cmd_argv.is_empty() {
        eprintln!("CI_WRAP_USAGE: missing command after `--`");
        return 2;
    }

    let Ok(signer) = EphemeralRunnerSigner::generate() else {
        eprintln!("CI_CSPRNG_INIT_FAILED");
        return 1;
    };
    let (_, org_hash) = resolve_org_id_hash(flag_val(opts, "--org"), Some(Path::new(".")));
    let suite_id = flag_val(opts, "--suite-id").unwrap_or("wrapped-suite");
    let toolchain = flag_val(opts, "--toolchain").unwrap_or("host-toolchain");
    let receipt_out = flag_val(opts, "--receipt-out").map(Path::new);

    match execute_wrap(
        &signer,
        &org_hash,
        suite_id,
        toolchain,
        cmd_argv,
        receipt_out,
    ) {
        Ok((code, _receipt)) => code,
        Err(e) => {
            eprintln!("CI_WRAP_FAILED: {e}");
            1
        }
    }
}

fn cmd_triage(args: &[String]) -> u8 {
    let log_paths = flag_vals(args, "--log");
    if log_paths.is_empty() {
        eprintln!("CI_TRIAGE_USAGE: chinwag-ci triage --log <path>... [--suite-id <id>]");
        return 2;
    }
    let suite_id = flag_val(args, "--suite-id").unwrap_or("default");
    let exit_code = flag_val(args, "--exit-code")
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(1);
    let mut shards = Vec::with_capacity(log_paths.len());
    for (idx, p) in log_paths.iter().enumerate() {
        let Ok(raw) = fs::read(p) else {
            eprintln!("CI_TRIAGE_READ_FAILED: `{p}`");
            return 1;
        };
        shards.push(ShardDiagnosticInput {
            shard_id: format!("shard-{:02}", idx + 1),
            suite_id: suite_id.to_string(),
            raw_log: raw,
            exit_code,
        });
    }
    let env_snapshot: Vec<(String, String)> = std::env::vars().collect();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cg = CodegraphSymbolIndex::load_from_repo(&cwd);
    let report = coalesce_and_triage_shards(&shards, &env_snapshot, cg.as_ref());
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
    0
}

fn cmd_flywheel(args: &[String]) -> u8 {
    let Some(red_path) = flag_val(args, "--red") else {
        eprintln!(
            "CI_FLYWHEEL_USAGE: chinwag-ci flywheel --red <red.json> --green <green.json> [--regressions-dir <dir>] [--flywheel-dir <dir>] [--bank <bank>]"
        );
        return 2;
    };
    let Some(green_path) = flag_val(args, "--green") else {
        eprintln!("CI_FLYWHEEL_USAGE: missing --green <green.json>");
        return 2;
    };
    let regressions_dir =
        Path::new(flag_val(args, "--regressions-dir").unwrap_or(".chinwag/regressions"));
    let flywheel_dir = Path::new(flag_val(args, "--flywheel-dir").unwrap_or(".chinwag/flywheel"));
    let explicit_bank = flag_val(args, "--bank");
    let min_recurrence = flag_val(args, "--min-recurrence")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PROMOTION_RECURRENCE_THRESHOLD);

    let Ok(red_raw) = fs::read_to_string(red_path) else {
        eprintln!("CI_FLYWHEEL_READ_FAILED: `{red_path}`");
        return 1;
    };
    let Ok(green_raw) = fs::read_to_string(green_path) else {
        eprintln!("CI_FLYWHEEL_READ_FAILED: `{green_path}`");
        return 1;
    };
    let Ok(red) = serde_json::from_str::<RedCaptureEvidence>(&red_raw) else {
        eprintln!("CI_FLYWHEEL_PARSE_FAILED: invalid RedCaptureEvidence JSON");
        return 1;
    };
    let Ok(green) = serde_json::from_str::<GreenVerificationEvidence>(&green_raw) else {
        eprintln!("CI_FLYWHEEL_PARSE_FAILED: invalid GreenVerificationEvidence JSON");
        return 1;
    };

    let env_snapshot: Vec<(String, String)> = std::env::vars().collect();
    let transition = match detect_red_to_green_transition(&red, &green, &env_snapshot) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("CI_FLYWHEEL_REJECTED: {e}");
            return 1;
        }
    };

    let (cassette_path, _) = match mint_regression_cassette(&transition, regressions_dir) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("CI_FLYWHEEL_CASSETTE_FAILED: {e}");
            return 1;
        }
    };

    let (fix_entry, recurrence) = match retain_candidate_fix_entry(
        &transition,
        flywheel_dir,
        explicit_bank,
        Some(Path::new(".")),
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("CI_FLYWHEEL_MEMORY_FAILED: {e}");
            return 1;
        }
    };

    let policy_file = flag_val(args, "--policy-file").map(Path::new);
    let explicit_bytes = flag_val(args, "--existing-overhead-bytes").and_then(|v| v.parse().ok());
    let explicit_tokens = flag_val(args, "--existing-overhead-tokens").and_then(|v| v.parse().ok());
    let max_per_path = flag_val(args, "--max-per-path")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_ACTIVE_TOMBSTONES_PER_PATH);
    let guard = match OverheadBudgetGuard::resolve_from_inputs(
        policy_file,
        explicit_bytes,
        explicit_tokens,
        Some(Path::new(".")),
        max_per_path,
    ) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("CI_FLYWHEEL_OVERHEAD_GUARD_FAILED: {e}");
            return 1;
        }
    };

    let promoted = match promote_recurring_exact_path_tombstones(
        &transition,
        &recurrence,
        min_recurrence,
        flywheel_dir,
        &guard,
    ) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("CI_FLYWHEEL_PROMOTE_FAILED: {e}");
            return 1;
        }
    };

    let out = json!({
        "ok": true,
        "command": "chinwag-ci flywheel",
        "bank": fix_entry.bank,
        "cassette_path": cassette_path.display().to_string(),
        "transition": transition,
        "promoted_tombstones": promoted,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    0
}

fn cmd_memory(args: &[String]) -> u8 {
    let sub = args.first().map(String::as_str).unwrap_or("");
    if sub != "promote-tombstone" {
        eprintln!(
            "CI_MEMORY_USAGE: chinwag-ci memory promote-tombstone --id <id> --exact-path <repo_path> --body <text> [--store <tombstones.json>]"
        );
        return 2;
    }
    let tail = &args[1..];
    let (Some(id), Some(exact_path), Some(body)) = (
        flag_val(tail, "--id"),
        flag_val(tail, "--exact-path"),
        flag_val(tail, "--body"),
    ) else {
        eprintln!("CI_MEMORY_USAGE: --id, --exact-path, and --body are required");
        return 2;
    };
    if let Some(scope_arg) = flag_val(tail, "--scope")
        && !scope_arg.eq_ignore_ascii_case("exact_path")
    {
        eprintln!(
            "CI_TOMBSTONE_PROMOTE_REFUSED: {}",
            crate::flywheel::FlywheelError::GlobalScopeForbidden
        );
        return 1;
    }
    let store_path =
        Path::new(flag_val(tail, "--store").unwrap_or(".chinwag/flywheel/tombstones.json"));
    let mut existing: Vec<AssertedTombstone> = match fs::symlink_metadata(store_path) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() {
                eprintln!(
                    "CI_TOMBSTONE_STORE_INVALID: `{}` must be a regular non-symlink file",
                    store_path.display()
                );
                return 1;
            }
            let raw = match fs::read(store_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!(
                        "CI_TOMBSTONE_STORE_READ_FAILED: unable to read `{}`: {e}",
                        store_path.display()
                    );
                    return 1;
                }
            };
            match serde_json::from_slice::<Vec<AssertedTombstone>>(&raw) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!(
                        "CI_TOMBSTONE_STORE_CORRUPT: malformed tombstone store `{}`: {e}",
                        store_path.display()
                    );
                    return 1;
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            eprintln!(
                "CI_TOMBSTONE_STORE_STAT_FAILED: unable to stat `{}`: {e}",
                store_path.display()
            );
            return 1;
        }
    };

    let policy_file = flag_val(tail, "--policy-file").map(Path::new);
    let explicit_bytes = flag_val(tail, "--existing-overhead-bytes").and_then(|v| v.parse().ok());
    let explicit_tokens = flag_val(tail, "--existing-overhead-tokens").and_then(|v| v.parse().ok());
    let max_per_path = flag_val(tail, "--max-per-path")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_ACTIVE_TOMBSTONES_PER_PATH);
    let guard = match OverheadBudgetGuard::resolve_from_inputs(
        policy_file,
        explicit_bytes,
        explicit_tokens,
        Some(Path::new(".")),
        max_per_path,
    ) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("CI_TOMBSTONE_OVERHEAD_GUARD_FAILED: {e}");
            return 1;
        }
    };

    let minted = match mint_bounded_exact_path_tombstone(id, exact_path, body, &existing, &guard) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("CI_TOMBSTONE_PROMOTE_REFUSED: {e}");
            return 1;
        }
    };
    existing.retain(|t| t.id != minted.id);
    existing.push(minted.clone());
    existing.sort_by(|a, b| a.id.cmp(&b.id));
    if let Some(parent) = store_path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut jcs) = jcs_from_serializable(&existing) {
        jcs.push(b'\n');
        if let Err(e) = fs::write(store_path, &jcs) {
            eprintln!("CI_TOMBSTONE_STORE_WRITE_FAILED: {e}");
            return 1;
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&minted).unwrap_or_default()
    );
    0
}
