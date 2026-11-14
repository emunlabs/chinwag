// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Multi-shard failure deduplication & `1,400ms` storm coalescing (`INV-CI-SHARD-COALESCE-01`).
//! Bridges multi-shard CI runner output into `CHWG-0278` deterministic root-cause triage.

use crate::diagnostics_triage::{ShardDiagnosticInput, coalesce_and_triage_shards};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical `1,400 ms` (`1.4s`) coalescing window for parallel matrix shards.
pub const COALESCE_WINDOW_MS: u64 = 1_400;

/// Canonical 5-tuple extracted from compiler/test runner output (`INV-CI-SHARD-COALESCE-01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalFailureTuple {
    pub tool: String,
    pub error_code: String,
    pub file_path: String,
    pub line_number: u32,
    pub failing_test_symbol: String,
}

impl CanonicalFailureTuple {
    /// Computes the deterministic SHA-256 hex digest over the canonical 5-tuple.
    #[must_use]
    pub fn signature_sha256(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"chinwag-ci-fail-sig-v2\0");
        for part in [
            self.tool.as_bytes(),
            self.error_code.as_bytes(),
            self.file_path.as_bytes(),
            &self.line_number.to_be_bytes(),
            self.failing_test_symbol.as_bytes(),
        ] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        hex::encode(digest.finalize())
    }
}

/// Extracts the primary canonical failure 5-tuple via `diagnostics_triage`.
#[must_use]
pub fn extract_failure_tuple(raw_output: &str) -> CanonicalFailureTuple {
    let report = coalesce_and_triage_shards(
        &[ShardDiagnosticInput {
            shard_id: "shard-01".to_string(),
            suite_id: "default".to_string(),
            raw_log: raw_output.as_bytes().to_vec(),
            exit_code: 1,
        }],
        &[],
        None,
    );
    if let Some(root) = report.root_diagnostics.first() {
        CanonicalFailureTuple {
            tool: root.tool.as_str().to_string(),
            error_code: root.error_code.clone(),
            file_path: root.repo_path.clone(),
            line_number: root.line_start,
            failing_test_symbol: root.root_symbol.clone(),
        }
    } else {
        CanonicalFailureTuple {
            tool: "generic-ci".to_string(),
            error_code: "CI_EXIT_NONZERO".to_string(),
            file_path: "unknown".to_string(),
            line_number: 0,
            failing_test_symbol: "unknown_symbol".to_string(),
        }
    }
}

/// Coalesced multi-shard storm record maintained across the `1,400 ms` window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescedShardStormRecordV1 {
    pub schema: String,
    pub commit_sha: String,
    pub failure_signature_sha256: String,
    pub tuple: CanonicalFailureTuple,
    pub first_seen_at_ms: u64,
    pub window_closes_at_ms: u64,
    pub primary_shard_id: String,
    pub coalesced_shard_ids: Vec<String>,
    pub total_credits_charged: u32,
    pub single_wakeup_dispatched: bool,
}

impl CoalescedShardStormRecordV1 {
    #[must_use]
    pub fn new_first_shard(
        commit_sha: &str,
        shard_id: &str,
        tuple: CanonicalFailureTuple,
        now_ms: u64,
    ) -> Self {
        let failure_signature_sha256 = tuple.signature_sha256();
        Self {
            schema: "CoalescedShardStormRecordV1".to_string(),
            commit_sha: commit_sha.to_string(),
            failure_signature_sha256,
            tuple,
            first_seen_at_ms: now_ms,
            window_closes_at_ms: now_ms.saturating_add(COALESCE_WINDOW_MS),
            primary_shard_id: shard_id.to_string(),
            coalesced_shard_ids: vec![shard_id.to_string()],
            total_credits_charged: 1,
            single_wakeup_dispatched: true,
        }
    }

    pub fn try_coalesce_shard(
        &mut self,
        commit_sha: &str,
        shard_id: &str,
        signature_sha256: &str,
        arrived_at_ms: u64,
    ) -> bool {
        if self.commit_sha == commit_sha
            && self.failure_signature_sha256 == signature_sha256
            && arrived_at_ms >= self.first_seen_at_ms
            && arrived_at_ms <= self.window_closes_at_ms
        {
            if !self.coalesced_shard_ids.iter().any(|s| s == shard_id) {
                self.coalesced_shard_ids.push(shard_id.to_string());
            }
            true
        } else {
            false
        }
    }
}

/// Coalesces multiple shard log files/records across a matrix run into deduplicated storm groups.
#[must_use]
pub fn coalesce_shard_records(
    commit_sha: &str,
    shards: &[(String, String, u64)],
) -> Vec<CoalescedShardStormRecordV1> {
    let mut storms: Vec<CoalescedShardStormRecordV1> = Vec::new();
    for (shard_id, raw_log, arrived_at_ms) in shards {
        let tuple = extract_failure_tuple(raw_log);
        let sig = tuple.signature_sha256();
        let mut merged = false;
        for storm in &mut storms {
            if storm.try_coalesce_shard(commit_sha, shard_id, &sig, *arrived_at_ms) {
                merged = true;
                break;
            }
        }
        if !merged {
            storms.push(CoalescedShardStormRecordV1::new_first_shard(
                commit_sha,
                shard_id,
                tuple,
                *arrived_at_ms,
            ));
        }
    }
    storms
}
