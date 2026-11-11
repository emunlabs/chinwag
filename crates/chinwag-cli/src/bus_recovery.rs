//! Read-only recovery observations and the same typed steps used by the SOP.
//! Input records select checks; they do not grant runtime operator authority.
#![forbid(unsafe_code)]

use crate::bus_network::NetworkSelection;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

pub const SCHEMA: &str = "chinwag.native-recovery-deployment.v1";
pub const MAX_RECORD_BYTES: u64 = 65_536;
pub const OBSERVATION_TTL_SECONDS: u64 = 30;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRecord {
    pub schema: String,
    pub deployment_id: String,
    pub revision: u64,
    pub captured_at_unix: u64,
    pub expires_at_unix: u64,
    pub node_role: NodeRole,
    pub host_binding: String,
    pub repository: String,
    pub service_domain: String,
    pub service_label: String,
    pub service_plist: String,
    pub binary_path: String,
    pub binary_sha256: String,
    pub source_commit: String,
    pub local_endpoint_id: String,
    pub peer_endpoint_id: String,
    pub coordinator_endpoint_id: String,
    pub coordinator_origin: String,
    pub selected_relay_origin: String,
    pub expected_relay_origin: String,
    pub configuration_id: String,
    pub generation: u64,
    pub route_lifecycle: RouteLifecycle,
    pub cloud_account_reference: String,
    pub required_cloud_capability: String,
    pub captured_failure: Option<CapturedFailure>,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    BusNode,
    Coordinator,
    BlindRelay,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLifecycle {
    Durable,
    Temporary,
    Unknown,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedFailure {
    pub category: String,
    pub observed_at_unix: u64,
    pub evidence_sha256: String,
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}
pub(crate) fn absolute_path(value: &str) -> bool {
    value.len() <= 4096
        && value.starts_with('/')
        && !value.ends_with('/')
        && value.is_ascii()
        && !value.contains("//")
        && !value.bytes().any(|b| b.is_ascii_control() || b == b'\\')
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !value.split('/').any(|c| c == "." || c == "..")
        && value.split('/').count() <= 65
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl DeploymentRecord {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != SCHEMA
            || !identifier(&self.deployment_id)
            || self.revision == 0
            || self.captured_at_unix >= self.expires_at_unix
            || self.expires_at_unix - self.captured_at_unix > 86_400
            || !identifier(&self.host_binding)
            || !identifier(&self.service_label)
            || !identifier(&self.cloud_account_reference)
            || !identifier(&self.required_cloud_capability)
            || !absolute_path(&self.repository)
            || !absolute_path(&self.binary_path)
            || !absolute_path(&self.service_plist)
            || !hex(&self.binary_sha256, 64)
            || !hex(&self.source_commit, 40)
            || Path::new(&self.binary_path)
                .file_name()
                .and_then(|s| s.to_str())
                != Some("chinwag")
            || Path::new(&self.service_plist)
                .file_name()
                .and_then(|s| s.to_str())
                != Some(&format!("{}.plist", self.service_label))
        {
            return Err("invalid_deployment_binding");
        }
        let gui = format!("gui/{}", rustix::process::geteuid().as_raw());
        if self.service_domain != gui && self.service_domain != "system" {
            return Err("unrelated_service_domain");
        }
        let local: iroh::EndpointId = self
            .local_endpoint_id
            .parse()
            .map_err(|_| "invalid_local_endpoint")?;
        let peer: iroh::EndpointId = self
            .peer_endpoint_id
            .parse()
            .map_err(|_| "invalid_peer_endpoint")?;
        let coordinator: iroh::EndpointId = self
            .coordinator_endpoint_id
            .parse()
            .map_err(|_| "invalid_coordinator_endpoint")?;
        if local == peer || local == coordinator || peer == coordinator {
            return Err("endpoint_identity_collision");
        }
        NetworkSelection::try_new(
            self.coordinator_origin.clone(),
            &self.coordinator_endpoint_id,
            &self.peer_endpoint_id,
            &self.selected_relay_origin,
            &self.expected_relay_origin,
            self.configuration_id.clone(),
            self.generation,
            true,
        )
        .map_err(|_| "invalid_native_route")?;
        if let Some(capture) = &self.captured_failure
            && (!identifier(&capture.category)
                || !hex(&capture.evidence_sha256, 64)
                || capture.observed_at_unix > self.captured_at_unix)
        {
            return Err("invalid_historical_capture");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Conclusion {
    Observed,
    Refused,
    Unknown,
    Unsupported,
}
#[derive(Debug, Serialize)]
pub struct Check {
    pub check: &'static str,
    pub conclusion: Conclusion,
    pub reason: String,
    pub observed_at_unix: u64,
    pub expires_at_unix: u64,
    pub evidence_sha256: Option<String>,
    pub next_read_only_check: &'static str,
}
impl Check {
    pub(crate) fn new(
        check: &'static str,
        conclusion: Conclusion,
        reason: impl Into<String>,
        now: u64,
        hash: Option<String>,
        next: &'static str,
    ) -> Self {
        Self {
            check,
            conclusion,
            reason: reason.into(),
            observed_at_unix: now,
            expires_at_unix: now.saturating_add(OBSERVATION_TTL_SECONDS),
            evidence_sha256: hash,
            next_read_only_check: next,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Diagnosis {
    pub schema: &'static str,
    pub side_effects: &'static str,
    pub offline: bool,
    pub record_sha256: Option<String>,
    pub record_claims_authenticated: bool,
    pub selected_deployment: Option<DeploymentRecord>,
    pub checks: Vec<Check>,
    pub transport_recovery: &'static str,
    pub processing_or_task_start: &'static str,
    pub effectful_recovery: &'static str,
}
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStep {
    Diagnose,
    Prepare,
    PairedCompareAndSwap,
    ActivateOnce,
    Reconcile,
    Rollback,
    Verify,
}
#[derive(Debug, Serialize)]
pub struct SopStep {
    pub step: RecoveryStep,
    pub command: Option<&'static str>,
    pub state: &'static str,
    pub requirement: &'static str,
}
pub fn sop_steps() -> Vec<SopStep> {
    use RecoveryStep::*;
    vec![
        SopStep {
            step: Diagnose,
            command: Some(
                "chinwag bus recovery diagnose --deployment ABSOLUTE_RECORD_JSON [--offline] --json",
            ),
            state: "IMPLEMENTED_READ_ONLY",
            requirement: "Explicit bounded public deployment record; inputs are claims, observations expire, missing proof remains UNKNOWN",
        },
        SopStep {
            step: Prepare,
            command: None,
            state: "HELD_NO_EFFECTFUL_ADAPTER",
            requirement: "Real finite operator grant bound to operation, exact deployment preimages, candidate hashes, host roles, scope and deadline; durable intent and hash-verified backups before effects",
        },
        SopStep {
            step: PairedCompareAndSwap,
            command: None,
            state: "HELD_NO_EFFECTFUL_ADAPTER",
            requirement: "Both exact nodes must independently compare current configuration and generation; reject one-sided, stale or mismatched transitions",
        },
        SopStep {
            step: ActivateOnce,
            command: None,
            state: "HELD_NO_EFFECTFUL_ADAPTER",
            requirement: "Durable one-use activation reservation, generation fencing and separately admitted owned service adapter; no replay of a message or activation",
        },
        SopStep {
            step: Reconcile,
            command: None,
            state: "HELD_NO_EFFECTFUL_ADAPTER",
            requirement: "Partial writes and crash windows remain UNKNOWN until exact durable intent, actual service handles and readback agree; never infer failure permits another activation",
        },
        SopStep {
            step: Rollback,
            command: None,
            state: "HELD_NO_EFFECTFUL_ADAPTER",
            requirement: "Separate current rollback authority and exact backup/preimage CAS; preserve uncertain states and original message IDs",
        },
        SopStep {
            step: Verify,
            command: None,
            state: "HELD_NO_SIGNED_ROUND_TRIP_ADAPTER",
            requirement: "Fresh authenticated same-ID/digest selected-native-relay readback on both nodes; distinguish journal ACK, processing, task start and independent acceptance",
        },
    ]
}
#[cfg(test)]
#[path = "bus_recovery_tests.rs"]
mod tests;
