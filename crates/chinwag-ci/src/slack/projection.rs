// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Zero-source CI boundary -> `BlindSlackBeatV1` projection (`CHWG-0253.04`).
//! Raw stdout, stderr, source code, diffs, and environment variables NEVER enter any field.

use chinwag_slack_contract::{
    AuthorizationRef, BeatSourceV1, BlindEvidenceV1, BlindSlackBeatV1, BlindSummaryV1,
    CanonicalU64, CiProviderV1, CiRemediationStepV1, Digest32, EventId, HpkeSuiteV1,
    KeyFingerprint, OpaqueOperationId, OpaqueOrgId, OpaqueRef, PolicyHoldStepV1, QueueStatusV1,
    SCHEMA_VERSION_V1, SceneProgressV1, SlackMetadataV1,
};

#[derive(Clone, Debug)]
pub struct CiBeatContext {
    pub org_id: OpaqueOrgId,
    pub operation_id: OpaqueOperationId,
    pub provider: CiProviderV1,
    pub runner_lease_ref: OpaqueRef,
    pub run_ref: OpaqueRef,
    pub shard_ref: Option<OpaqueRef>,
    pub authorization_ref: AuthorizationRef,
    pub k1_key_id: KeyFingerprint,
}

#[derive(Clone, Debug)]
pub struct CiTransitionSpec {
    pub event_id: EventId,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub progress: SceneProgressV1,
    pub queue_status: QueueStatusV1,
    pub cwcard_digest: Digest32,
    pub policy_gate_id: Option<OpaqueRef>,
    pub attestation_count: u8,
    pub specs_passed: u32,
    pub specs_total: u32,
    pub gates_passed: u8,
    pub gates_total: u8,
    pub loc_added: u32,
    pub loc_removed: u32,
    pub command_exit_code: Option<i32>,
    pub duration_ms: u64,
    pub est_minutes_saved: u32,
    pub credits_charged: u64,
}

pub fn project_ci_blind_beat(
    ctx: &CiBeatContext,
    spec: CiTransitionSpec,
) -> Result<BlindSlackBeatV1, String> {
    let beat = BlindSlackBeatV1 {
        schema_version: SCHEMA_VERSION_V1,
        event_id: spec.event_id,
        org_id: ctx.org_id.clone(),
        operation_id: ctx.operation_id.clone(),
        source: BeatSourceV1::Ci {
            provider: ctx.provider,
            runner_lease_ref: ctx.runner_lease_ref.clone(),
            run_ref: ctx.run_ref.clone(),
            shard_ref: ctx.shard_ref.clone(),
        },
        source_sequence: CanonicalU64::new(spec.sequence),
        attempt: 1,
        occurred_at_ms: CanonicalU64::new(spec.occurred_at_ms),
        progress: spec.progress,
        evidence: BlindEvidenceV1 {
            cwcard_digest: spec.cwcard_digest,
            hpke_suite: HpkeSuiteV1::X25519MlKem768HkdfSha256ChaCha20Poly1305,
            sealed_locator_ref: None,
            policy_gate_id: spec.policy_gate_id,
            tombstone_id: None,
            ed25519_attestation_count: spec.attestation_count,
            plaintext_source_bytes: 0,
        },
        metadata: SlackMetadataV1::StrictZk {
            summary: BlindSummaryV1 {
                queue_status: spec.queue_status,
                specs_passed: spec.specs_passed,
                specs_total: spec.specs_total,
                gates_passed: spec.gates_passed,
                gates_total: spec.gates_total,
                loc_added: spec.loc_added,
                loc_removed: spec.loc_removed,
                command_exit_code: spec.command_exit_code,
                duration_ms: CanonicalU64::new(spec.duration_ms),
                est_minutes_saved: spec.est_minutes_saved,
                credits_charged: CanonicalU64::new(spec.credits_charged),
                credit_receipt_ref: None,
            },
        },
        authorization_ref: ctx.authorization_ref.clone(),
        k1_key_id: ctx.k1_key_id.clone(),
    };
    beat.validate_semantics().map_err(|e| e.to_string())?;
    Ok(beat)
}

#[must_use]
pub const fn ci_build_progress() -> SceneProgressV1 {
    SceneProgressV1::CiRemediation {
        step: CiRemediationStepV1::Building,
    }
}

#[must_use]
pub const fn ci_failed_progress() -> SceneProgressV1 {
    SceneProgressV1::CiRemediation {
        step: CiRemediationStepV1::Failed,
    }
}

#[must_use]
pub const fn ci_verifying_candidate_progress() -> SceneProgressV1 {
    SceneProgressV1::CiRemediation {
        step: CiRemediationStepV1::VerifyingCandidate,
    }
}

#[must_use]
pub const fn ci_passed_progress() -> SceneProgressV1 {
    SceneProgressV1::CiRemediation {
        step: CiRemediationStepV1::Passed,
    }
}

#[must_use]
pub const fn ci_wp04_held_progress() -> SceneProgressV1 {
    SceneProgressV1::PolicyHold {
        step: PolicyHoldStepV1::Held,
    }
}

#[must_use]
pub const fn ci_wp04_scrub_packaging_progress() -> SceneProgressV1 {
    SceneProgressV1::PolicyHold {
        step: PolicyHoldStepV1::Packaging,
    }
}
