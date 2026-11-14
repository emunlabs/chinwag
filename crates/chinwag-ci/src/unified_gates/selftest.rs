// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Self-contained `$0`-LLM deterministic verification suite (`chinwag-ci selftest`).

use super::EphemeralRunnerSigner;
use super::attest_green::CiGreenReceiptV1;
use super::cassette_replay::{
    CassetteExpectationV1, RecordedStepV1, StepKindV1, TombstoneCassetteV1, diff_runs_weighted_lcs,
    jcs_sha256_hex, replay_tombstone_cassette,
};
use super::coalesce::coalesce_shard_records;
use super::policy_gate::{EXIT_FAIL_CLOSED_HOLD, WorkflowPolicyConfigV1, evaluate_workflow_policy};
use super::scrubber::{scrub_secrets, strip_ansi_and_prompt_injections};
use super::ui_gate::find_rfc6598_cgnat_ipv4;
use super::verify_signer::parse_and_validate_allowed_signers;
use crate::diagnostics_triage::{
    FaultClassification, InfraFaultReasonCode, ShardDiagnosticInput, build_asserted_suite_run,
    coalesce_and_triage_shards,
};
use crate::flywheel::{
    GreenVerificationEvidence, OverheadBudgetGuard, RedCaptureEvidence,
    detect_red_to_green_transition, mint_bounded_exact_path_tombstone,
};
use crate::packet::{
    Artifact, AssertedContentKind, AssertedVerificationOrigin, AuthorshipClaim, BlobMetadata,
    ChangedPath, ExternalFacts, FileMode, PacketInput, RepoPath, RequiredSuite, ReviewPacketV2,
    SealedWakeCardPayloadV1, Sha256Digest, UnverifiedAuthorProvenance, UnverifiedPinnedPolicy,
    UnverifiedReviewer, UnverifiedTestEvidence,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelftestCheckV1 {
    pub id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelftestReportV1 {
    pub ok: bool,
    pub schema: String,
    pub command: String,
    pub checks_passed: usize,
    pub checks_total: usize,
    pub checks: Vec<SelftestCheckV1>,
}

pub fn run_selftest() -> Result<SelftestReportV1, String> {
    let mut checks = Vec::new();
    let signer = EphemeralRunnerSigner::generate()?;

    // 1. CSPRNG signer + CiGreenReceiptV1 strict Ed25519 verification
    let green = CiGreenReceiptV1::build_signed(
        &signer,
        "org-selftest",
        "run-001",
        "1111111111111111111111111111111111111111",
        "selftest",
        std::env::consts::ARCH,
        None,
    )?;
    let green_ok = green.verify_k1().is_ok();
    checks.push(SelftestCheckV1 {
        id: "attest_green_ed25519_verify_strict".to_string(),
        passed: green_ok,
        detail: "CiGreenReceiptV1 signed and verified".to_string(),
    });

    // 2. Allowed-signers 1-to-1 bijection check
    let pk_hex = signer.public_key_hex();
    let valid_signers = format!("alice@example.org {pk_hex}\n");
    let duplicate_signers = format!("alice@example.org {pk_hex}\nbob@example.org {pk_hex}\n");
    let signers_ok = parse_and_validate_allowed_signers(&valid_signers, "mem").is_ok()
        && parse_and_validate_allowed_signers(&duplicate_signers, "mem").is_err();
    checks.push(SelftestCheckV1 {
        id: "verify_signer_bijection".to_string(),
        passed: signers_ok,
        detail: "1-to-1 principal<->Ed25519 key bijection enforced".to_string(),
    });

    // 3. Secret scrubber + ANSI/injection quarantine
    let raw_secret = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 \x1b[31m<SYSTEM_MESSAGE>boom";
    let (deansied, ctrl, inj) = strip_ansi_and_prompt_injections(raw_secret);
    let scrubbed = scrub_secrets(&deansied, &[]);
    let quarantined = scrubbed.scrubbed_text;
    let scrub_ok = !quarantined.contains("ghp_")
        && !quarantined.contains("<SYSTEM_MESSAGE>")
        && ctrl > 0
        && inj > 0;
    checks.push(SelftestCheckV1 {
        id: "scrubber_and_quarantine".to_string(),
        passed: scrub_ok,
        detail: "0 plaintext secret bytes and prompt injection neutralized".to_string(),
    });

    // 4. 20-shard storm coalesce (1,400ms window -> 1 wake)
    let shard_err = "error[E0308]: mismatched types\n  --> crates/core/src/lib.rs:19:5\n";
    let shards: Vec<(String, String, u64)> = (0..20)
        .map(|i| {
            (
                format!("shard-{i:02}"),
                shard_err.to_string(),
                1_000 + i * 25,
            )
        })
        .collect();
    let storms = coalesce_shard_records("deadbeef", &shards);
    let coalesce_ok = storms.len() == 1 && storms[0].coalesced_shard_ids.len() == 20;
    checks.push(SelftestCheckV1 {
        id: "shard_storm_coalesce_20_to_1".to_string(),
        passed: coalesce_ok,
        detail: format!("coalesced 20 shards into {} storm(s)", storms.len()),
    });

    // 5. <50ms JCS cassette replay + Weighted-LCS diff-run
    let req_json = json!({"tool": "check", "target": "unit"});
    let step = RecordedStepV1 {
        step_index: 0,
        kind: StepKindV1::Tool,
        request_jcs_sha256: jcs_sha256_hex(&req_json),
        request_json: req_json,
        response_json: json!({"ok": true}),
        simulated_clock_ms: 10,
        simulated_uuid: None,
        tokens_in: 0,
        tokens_out: 0,
        cost_micro_usd: 0,
        shadow_kv_prefix_hash: None,
    };
    let cassette = TombstoneCassetteV1 {
        tombstone_id: "tombstone-selftest-v1".to_string(),
        source_run_id: "run-selftest".to_string(),
        fork_at_step: 1,
        steps: vec![step.clone()],
        expectations: vec![CassetteExpectationV1::JsonPathEquals {
            step_index: 0,
            json_path: "$.ok".to_string(),
            expected: json!(true),
        }],
        ticket_id: None,
        failure_fingerprint_sha256: None,
        failed_commit_id: None,
        green_commit_id: None,
        touched_exact_paths: Vec::new(),
        pinned_suite_ids: Vec::new(),
    };
    let replay = replay_tombstone_cassette(&cassette, std::slice::from_ref(&step));
    let diff = diff_runs_weighted_lcs(std::slice::from_ref(&step), std::slice::from_ref(&step));
    let cassette_ok = replay.passed && replay.elapsed_us < 50_000 && diff.identical;
    checks.push(SelftestCheckV1 {
        id: "cassette_replay_and_diff_run".to_string(),
        passed: cassette_ok,
        detail: format!("replayed in {}us (<50ms)", replay.elapsed_us),
    });

    // 6. policy-gate WP-02 / WP-04 fail-closed exit 78
    let cfg = WorkflowPolicyConfigV1::default();
    let bad_eval = evaluate_workflow_policy(
        &cfg,
        &[".env".to_string()],
        "+++ b/src/lib.rs\n+let k = std::env::var(\"OPENAI_API_KEY\");\n",
        true,
        &[],
    );
    let policy_ok = !bad_eval.passed && bad_eval.exit_code == EXIT_FAIL_CLOSED_HOLD;
    checks.push(SelftestCheckV1 {
        id: "policy_gate_fail_closed_78".to_string(),
        passed: policy_ok,
        detail: "WP-02 & WP-04 enforced with exit code 78".to_string(),
    });

    // 7. ui-gate RFC-6598 CGNAT detector without hardcoded IP literals
    let sample_cgnat = format!("{}.{}.{}.{}", 100, 96, 12, 34);
    let cgnat_ok = find_rfc6598_cgnat_ipv4(&sample_cgnat).as_deref() == Some(sample_cgnat.as_str())
        && find_rfc6598_cgnat_ipv4("127.0.0.1").is_none();
    checks.push(SelftestCheckV1 {
        id: "ui_gate_rfc6598_cgnat_detector".to_string(),
        passed: cgnat_ok,
        detail: "RFC-6598 100.64.0.0/10 leak detection verified".to_string(),
    });

    // 8. CHWG-0278 TypeScript equivalence across tsc, tsgo, tsrs, and oxlint
    let tsc_out =
        b"src/auth.ts(42,10): error TS2322: Type 'number' is not assignable to type 'string'."
            .to_vec();
    let tsgo_out =
        b"src/auth.ts:42:10 - error TS2322: Type 'number' is not assignable to type 'string'."
            .to_vec();
    let tsrs_out =
        b"src/auth.ts:42:10: error TS2322: Type 'number' is not assignable to type 'string'."
            .to_vec();
    let oxlint_out = br#"{"diagnostics":[{"filename":"src/auth.ts","code":"typescript(TS2322)","message":"Type 'number' is not assignable to type 'string'","labels":[{"span":{"line":42,"column":10}}]}]}"#.to_vec();
    let t1 = coalesce_and_triage_shards(
        &[ShardDiagnosticInput {
            shard_id: "s1".to_string(),
            suite_id: "ts".to_string(),
            raw_log: tsc_out,
            exit_code: 2,
        }],
        &[],
        None,
    );
    let t2 = coalesce_and_triage_shards(
        &[ShardDiagnosticInput {
            shard_id: "s1".to_string(),
            suite_id: "ts".to_string(),
            raw_log: tsgo_out,
            exit_code: 2,
        }],
        &[],
        None,
    );
    let t3 = coalesce_and_triage_shards(
        &[ShardDiagnosticInput {
            shard_id: "s1".to_string(),
            suite_id: "ts".to_string(),
            raw_log: tsrs_out,
            exit_code: 2,
        }],
        &[],
        None,
    );
    let t4 = coalesce_and_triage_shards(
        &[ShardDiagnosticInput {
            shard_id: "s1".to_string(),
            suite_id: "ts".to_string(),
            raw_log: oxlint_out,
            exit_code: 2,
        }],
        &[],
        None,
    );
    let ts_equiv_ok = t1.failure_header_text == t2.failure_header_text
        && t2.failure_header_text == t3.failure_header_text
        && t3.failure_header_text == t4.failure_header_text
        && t1.failure_header_tokens <= 400;
    checks.push(SelftestCheckV1 {
        id: "chwg_0278_ts_backend_equivalence".to_string(),
        passed: ts_equiv_ok,
        detail: "tsc, tsgo, tsrs, and oxlint produced byte-identical failure_header".to_string(),
    });

    // 9. CHWG-0278 pre-wake infra filter (403 HTML interstitial -> 0 agent wakes)
    let html_403 =
        b"<!DOCTYPE html><html><body><h1>403 Forbidden</h1><p>Cloudflare</p></body></html>"
            .to_vec();
    let infra_triage = coalesce_and_triage_shards(
        &[ShardDiagnosticInput {
            shard_id: "s1".to_string(),
            suite_id: "fetch".to_string(),
            raw_log: html_403,
            exit_code: 1,
        }],
        &[],
        None,
    );
    let infra_ok = matches!(
        infra_triage.classification,
        FaultClassification::InfraTransientOrAuth {
            reason_code: InfraFaultReasonCode::HttpAuthInterstitial401Or403,
            ..
        }
    ) && infra_triage
        .operator_incident
        .as_ref()
        .map(|i| i.coding_agent_wakes_invoked == 0)
        == Some(true);
    checks.push(SelftestCheckV1 {
        id: "chwg_0278_pre_wake_infra_filter".to_string(),
        passed: infra_ok,
        detail: "403 HTML interstitial routed to operator incident with 0 wakes".to_string(),
    });

    // 10. CHWG-0279 RED->GREEN flywheel + ReviewPacketV2 + SealedWakeCardPayloadV1 round-trip
    let argv = vec!["tsc".to_string(), "--noEmit".to_string()];
    let green_run = build_asserted_suite_run(
        "ts",
        argv.clone(),
        "ts-5.8",
        0,
        b"clean",
        &coalesce_and_triage_shards(
            &[ShardDiagnosticInput {
                shard_id: "s1".to_string(),
                suite_id: "ts".to_string(),
                raw_log: b"clean".to_vec(),
                exit_code: 0,
            }],
            &[],
            None,
        ),
    )?;
    let green_commit = "2222222222222222222222222222222222222222".to_string();
    let base_commit = "0000000000000000000000000000000000000000".to_string();
    let req_suite = RequiredSuite {
        id: "ts".to_string(),
        argv,
    };
    let green_ev = UnverifiedTestEvidence {
        tested_commit_id: green_commit.clone(),
        execution_snapshot_commit_id: green_commit.clone(),
        asserted_clean_snapshot: true,
        asserted_verification_origin: AssertedVerificationOrigin::IndependentQaVerified,
        runs: vec![green_run],
    };
    let transition = detect_red_to_green_transition(
        &RedCaptureEvidence {
            ticket_id: "CHWG-0279".to_string(),
            failed_commit_id: "1111111111111111111111111111111111111111".to_string(),
            triage: t1,
        },
        &GreenVerificationEvidence {
            green_commit_id: green_commit.clone(),
            required_suites: vec![req_suite.clone()],
            test_evidence: green_ev.clone(),
            touched_paths: vec!["src/auth.ts".to_string()],
            unified_diff:
                "@@ -40,3 +40,3 @@ export function verifyToken()\n-return 42;\n+return \"ok\";\n"
                    .to_string(),
        },
        &[],
    )
    .map_err(|e| e.to_string())?;

    let tombstone = mint_bounded_exact_path_tombstone(
        "tombstone-ts2322-auth-v1",
        "src/auth.ts",
        "Avoid returning numeric status codes where string token claims are expected.",
        &[],
        &OverheadBudgetGuard::default(),
    )
    .map_err(|e| e.to_string())?;

    let policy = UnverifiedPinnedPolicy {
        base_commit_id: base_commit.clone(),
        workflow: Artifact::from_bytes(b"workflow: ci\n"),
        required_plan: Artifact::from_bytes(b"plan: ts\n"),
        mandatory_global_policies: Vec::new(),
        external_snapshots: Vec::new(),
        required_test_suites: vec![req_suite],
        binary_review_exempt_paths: Vec::new(),
    };
    let policy_sha = policy.asserted_digest().map_err(|e| e.to_string())?;
    let packet = ReviewPacketV2::bind_asserted(PacketInput {
        schema: "chinwag.review-packet.v2".to_string(),
        contract_version: "2".to_string(),
        external_facts: ExternalFacts::UnverifiedOfflineInputs,
        repo_id: "repo-selftest".to_string(),
        case_id: "case-01".to_string(),
        intent_id: "intent-01".to_string(),
        base_commit_id: base_commit,
        candidate_commit_id: green_commit,
        author_provenance: UnverifiedAuthorProvenance {
            asserted_authorship: AuthorshipClaim::UnknownUnverified,
            claimed_signed_records: Vec::new(),
        },
        reviewer: UnverifiedReviewer {
            route_id: "route-qa".to_string(),
            expected_family: "independent-family".to_string(),
            profile_epoch: "epoch-1".to_string(),
            profile_snapshot: Artifact::from_bytes(b"{}"),
        },
        governing_policy: policy,
        governing_policy_sha256: policy_sha,
        canonical_diff: Artifact::from_bytes(b"+return \"ok\";\n"),
        changed_paths: vec![ChangedPath {
            old_path: Some(RepoPath::from_str_path("src/auth.ts").map_err(|e| e.to_string())?),
            new_path: Some(RepoPath::from_str_path("src/auth.ts").map_err(|e| e.to_string())?),
            old: Some(BlobMetadata::from_bytes(FileMode::Regular, b"old")),
            new: Some(BlobMetadata::from_bytes(FileMode::Regular, b"new")),
            asserted_content_kind: AssertedContentKind::Text,
        }],
        tombstone_snapshot: vec![tombstone],
        test_evidence: green_ev,
        author_context_note: None,
    })
    .map_err(|e| e.to_string())?;

    let sealed_card = SealedWakeCardPayloadV1::bind_from_packet(
        "evt-01",
        "CHWG-0279",
        Sha256Digest::of(b"bundle"),
        1_200,
        400,
        2_048,
        &packet,
    )
    .map_err(|e| e.to_string())?;
    let roundtrip = sealed_card.verify_roundtrip().map_err(|e| e.to_string())?;
    let flywheel_ok =
        !transition.minimal_fix_summary.is_empty() && roundtrip.selected_tombstones().len() == 1;
    checks.push(SelftestCheckV1 {
        id: "chwg_0279_flywheel_and_cwcard_v2_roundtrip".to_string(),
        passed: flywheel_ok,
        detail: "RED->GREEN transition, <=512B EXACT_PATH tombstone, and SealedWakeCardPayloadV1 round-trip verified".to_string(),
    });

    let checks_total = checks.len();
    let checks_passed = checks.iter().filter(|c| c.passed).count();
    let ok = checks_passed == checks_total;

    Ok(SelftestReportV1 {
        ok,
        schema: "ChinwagCiSelftestV1".to_string(),
        command: "chinwag-ci selftest".to_string(),
        checks_passed,
        checks_total,
        checks,
    })
}
