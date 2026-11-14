// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Blind `BlindSlackBeatV1` projection for `chinwag slack test` / daemon emissions,
//! plus the post-first-verified-function one-line CLI expansion nudge.

use crate::slack::authorization::{RequestedMetadataMode, SlackBindingState};
use crate::slack::outbox::{OutboxError, SqliteSlackOutbox};
use chinwag_slack_contract::{
    ApprovedSymbolsV1, AuthorizationRef, BeatSourceV1, BlindEvidenceV1, BlindSlackBeatV1,
    BlindSummaryV1, CanonicalU64, CiRemediationStepV1, Digest32, EventId, HpkeSuiteV1,
    KeyFingerprint, OpaqueOperationId, OpaqueOrgId, OpaqueRef, OrgAdminPasskeyAttestationV1,
    QueueStatusV1, SCHEMA_VERSION_V1, SceneProgressV1, SlackMetadataV1,
};

pub const FIRST_VERIFIED_RUN_NUDGE_KEY: &str = "post_first_verified_function_v1";

pub struct DaemonProbeParams<'a> {
    pub event_id: EventId,
    pub org_id: OpaqueOrgId,
    pub operation_id: OpaqueOperationId,
    pub device_ref: OpaqueRef,
    pub session_ref: OpaqueRef,
    pub authorization_ref: AuthorizationRef,
    pub k1_key_id: KeyFingerprint,
    pub metadata_mode: RequestedMetadataMode,
    pub passkey_attestation: Option<&'a OrgAdminPasskeyAttestationV1>,
    pub now_ms: u64,
}

/// Constructs a zero-source `BlindSlackBeatV1` health/connectivity probe beat.
pub fn build_daemon_probe_beat(params: DaemonProbeParams<'_>) -> Result<BlindSlackBeatV1, String> {
    let summary = BlindSummaryV1 {
        queue_status: QueueStatusV1::TerminalGreen,
        specs_passed: 1,
        specs_total: 1,
        gates_passed: 1,
        gates_total: 1,
        loc_added: 0,
        loc_removed: 0,
        command_exit_code: Some(0),
        duration_ms: CanonicalU64::new(12),
        est_minutes_saved: 0,
        credits_charged: CanonicalU64::new(0),
        credit_receipt_ref: None,
    };

    let metadata = match (params.metadata_mode, params.passkey_attestation) {
        (RequestedMetadataMode::RichSymbols, Some(att)) => SlackMetadataV1::RichSymbols {
            summary,
            symbols: Box::new(ApprovedSymbolsV1 {
                repo_label: None,
                branch_label: None,
                symbol_label: Some("slack_connectivity_probe".to_owned()),
                pr_number: None,
                approved_pr_url: None,
                short_revision: None,
                gate_display_name: Some("Visual Geometry & Copy Gate".to_owned()),
            }),
            passkey_attestation: Box::new(att.clone()),
        },
        _ => SlackMetadataV1::StrictZk { summary },
    };

    let probe_tag = format!(
        "probe:{}:{}",
        params.org_id.as_str(),
        params.event_id.as_str()
    );
    let cwcard_digest = Digest32::from_bytes(*blake3::hash(probe_tag.as_bytes()).as_bytes());

    let beat = BlindSlackBeatV1 {
        schema_version: SCHEMA_VERSION_V1,
        event_id: params.event_id,
        org_id: params.org_id,
        operation_id: params.operation_id,
        source: BeatSourceV1::Daemon {
            device_ref: params.device_ref,
            session_ref: params.session_ref,
        },
        source_sequence: CanonicalU64::new(1),
        attempt: 1,
        occurred_at_ms: CanonicalU64::new(params.now_ms),
        progress: SceneProgressV1::CiRemediation {
            step: CiRemediationStepV1::Passed,
        },
        evidence: BlindEvidenceV1 {
            cwcard_digest,
            hpke_suite: HpkeSuiteV1::X25519MlKem768HkdfSha256ChaCha20Poly1305,
            sealed_locator_ref: None,
            policy_gate_id: None,
            tombstone_id: None,
            ed25519_attestation_count: 1,
            plaintext_source_bytes: 0,
        },
        metadata,
        authorization_ref: params.authorization_ref,
        k1_key_id: params.k1_key_id,
    };
    beat.validate_semantics().map_err(|e| e.to_string())?;
    Ok(beat)
}

/// Evaluates whether to emit the post-first-verified-function CLI expansion nudge.
/// Emits ONLY when:
/// 1. `queue_status == TerminalGreen` (value has already been delivered),
/// 2. Slack is NOT yet connected (`SlackBindingState::NotConnected`), and
/// 3. The nudge has never been displayed before in `slack_nudge_state`.
pub fn maybe_format_post_verify_slack_nudge(
    binding_state: &SlackBindingState,
    outbox: &SqliteSlackOutbox,
    queue_status: QueueStatusV1,
    operation_id: &str,
    est_minutes_saved: u32,
    credits_charged: u64,
    now_ms: u64,
) -> Result<Option<String>, OutboxError> {
    if !matches!(queue_status, QueueStatusV1::TerminalGreen) {
        return Ok(None);
    }
    if !matches!(binding_state, SlackBindingState::NotConnected) {
        return Ok(None);
    }
    if est_minutes_saved == 0 {
        return Ok(None);
    }
    if !outbox.try_claim_one_time_nudge(FIRST_VERIFIED_RUN_NUDGE_KEY, operation_id, now_ms)? {
        return Ok(None);
    }
    Ok(Some(format!(
        "{est_minutes_saved} dev mins saved on this run. {credits_charged} credits.\n\
         Share the next one in #ci-builds:\n  \
         chinwag slack connect"
    )))
}
