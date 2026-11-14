// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Two-Tier Cleanroom Runner Trust Gate (`chinwag-ephemeral-public` vs
//! `chinwag-ephemeral-release` · `INV-CLEANROOM-TRUST-SPLIT-01`), AC/Thermal/HID/CPU
//! Multi-Mac Pool Admission, `0700` User-Owned Runtime Slot Leases with Dead-PID Reaping,
//! and Hybrid Post-Quantum HPKE (`X25519-MLKEM768`) Failure Diagnostic Bundle Sealing (`Hook H4`).

use crate::env_lock::read_non_symlink;
use crate::seatbelt::{
    DEFAULT_NIX_DAEMON_SOCKET_DIR, DEFAULT_NIX_DAEMON_SOCKET_PATH, DEFAULT_NIX_STORE_SUBPATH,
};
use core::convert::Infallible;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::XWing,
    rand_core::{TryCryptoRng, TryRng},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Apple `Virtualization.framework` & macOS EULA limit per physical Apple Silicon host.
pub const MAX_VMS_PER_MAC_HOST: u8 = 2;

/// Maximum latency budget (ms) to drain opportunistic laptop runner slots upon user input / AC unplug.
pub const MAX_DRAIN_BUDGET_MS: u64 = 500;

/// Default minimum host CPU idle percentage required for opportunistic laptop admission.
pub const DEFAULT_MIN_CPU_IDLE_PERCENT: u8 = 70;

/// HID idle threshold (nanoseconds): keyboard/mouse input within 30s pauses opportunistic admission.
const USER_HID_ACTIVE_THRESHOLD_NS: u64 = 30_000_000_000;

pub const DEFAULT_CLEANROOM_BASE_IMAGE: &str = "chinwag-macos-sequoia-base";
pub const DEFAULT_HOST_SCCACHE_DIR: &str = "/private/var/tmp/chinwag-sccache";
pub const DEFAULT_GUEST_SCRATCH_ROOT: &str = "/private/tmp";

pub const FAILURE_BUNDLE_SCHEMA: &str = "chinwag.cleanroom.failure-bundle.v1";
pub const FAILURE_BUNDLE_CIPHERSUITE: &str = "X25519-MLKEM768-HKDF-SHA256-ChaCha20Poly1305";
const FAILURE_HPKE_INFO_PREFIX: &[u8] = b"chinwag-cleanroom-h4-failure-bundle/v1\0";
const FAILURE_SIG_DOMAIN: &[u8] = b"chinwag-cleanroom-h4-origin-sig/v1\0";
const RELEASE_ADMISSION_DOMAIN: &[u8] = b"chinwag-cleanroom-release-admission/v1\0";
const MAX_DIAGNOSTIC_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_COMPRESSED_BYTES: usize = MAX_DIAGNOSTIC_PLAINTEXT_BYTES + 64 * 1024;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustPoolError {
    #[error("release profile `chinwag-ephemeral-release` refused: {0}")]
    ReleaseRefused(&'static str),
    #[error(
        "unknown runner profile `{0}` (expected `public`/`chinwag-ephemeral-public` or `release`/`chinwag-ephemeral-release`)"
    )]
    UnknownProfile(String),
    #[error("cleanroom host capacity refused: {0}")]
    PoolAdmissionRefused(&'static str),
    #[error("diagnostic bundle sealing or verification failed: {0}")]
    DiagnosticBundle(&'static str),
    #[error("OS CSPRNG entropy unavailable")]
    Entropy,
}

/// Two-tier cleanroom runner trust profile (`INV-CLEANROOM-TRUST-SPLIT-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunnerTrustProfile {
    /// Untrusted fork PRs, external contributor branches, and unmerged worktrees.
    #[serde(rename = "chinwag-ephemeral-public")]
    Public,
    /// Protected branches (`refs/heads/main`) or signed `refs/tags/v*` release tags
    /// with verified `Ed25519` commit signer proof.
    #[serde(rename = "chinwag-ephemeral-release")]
    Release,
}

impl RunnerTrustProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "chinwag-ephemeral-public",
            Self::Release => "chinwag-ephemeral-release",
        }
    }

    pub fn parse_label(raw: &str) -> Result<Self, TrustPoolError> {
        match raw.trim() {
            "public" | "chinwag-ephemeral-public" => Ok(Self::Public),
            "release" | "chinwag-ephemeral-release" => Ok(Self::Release),
            other => Err(TrustPoolError::UnknownProfile(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkEgressPolicy {
    /// Zero external network egress (`--offline`).
    Offline,
    /// Locked strictly to declared package registries and peer-to-peer binary cache.
    RegistriesAndBinaryCacheOnly,
    /// Scoped release artifact upload + Apple notarization endpoints.
    ScopedReleaseUploadAndNotarization,
}

/// Cryptographic proof that a commit on a protected branch or release tag was
/// verified by an enrolled `Ed25519` release signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSignerAttestation {
    pub git_ref: String,
    pub commit_oid: String,
    pub signer_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

impl ReleaseSignerAttestation {
    pub fn sign(git_ref: &str, commit_oid: &str, signing_key: &SigningKey) -> Self {
        let vk = signing_key.verifying_key().to_bytes();
        let msg = release_admission_preimage(git_ref, commit_oid);
        let sig = signing_key.sign(&msg);
        Self {
            git_ref: git_ref.to_owned(),
            commit_oid: commit_oid.to_owned(),
            signer_public_key: vk,
            signature: sig.to_bytes().to_vec(),
        }
    }

    pub fn verify(&self, pinned_signers: &[[u8; 32]]) -> Result<(), TrustPoolError> {
        if pinned_signers.is_empty() {
            return Err(TrustPoolError::ReleaseRefused(
                "no pinned release signers configured",
            ));
        }
        let mut matched = false;
        for pin in pinned_signers {
            if bool::from(self.signer_public_key.ct_eq(pin)) {
                matched = true;
            }
        }
        if !matched {
            return Err(TrustPoolError::ReleaseRefused(
                "commit signer is not in pinned release allowlist",
            ));
        }
        let vk = VerifyingKey::from_bytes(&self.signer_public_key)
            .map_err(|_| TrustPoolError::ReleaseRefused("invalid release signer public key"))?;
        if vk.is_weak() {
            return Err(TrustPoolError::ReleaseRefused(
                "weak small-order release signer public key",
            ));
        }
        let sig_arr: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| TrustPoolError::ReleaseRefused("invalid release signature length"))?;
        let msg = release_admission_preimage(&self.git_ref, &self.commit_oid);
        vk.verify_strict(&msg, &Signature::from_bytes(&sig_arr))
            .map_err(|_| TrustPoolError::ReleaseRefused("release Ed25519 signature invalid"))
    }
}

fn release_admission_preimage(git_ref: &str, commit_oid: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(RELEASE_ADMISSION_DOMAIN);
    out.extend_from_slice(&(git_ref.len() as u32).to_be_bytes());
    out.extend_from_slice(git_ref.as_bytes());
    out.extend_from_slice(&(commit_oid.len() as u32).to_be_bytes());
    out.extend_from_slice(commit_oid.as_bytes());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobTriggerContext {
    pub requested_profile: RunnerTrustProfile,
    pub git_ref: String,
    pub commit_oid: String,
    pub is_fork_pr: bool,
    pub is_untrusted_pr_event: bool,
    pub release_attestation: Option<ReleaseSignerAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerTrustDecision {
    pub profile: RunnerTrustProfile,
    pub allow_release_keys: bool,
    pub phantom_vault_enabled: bool,
    pub allow_apple_notarization: bool,
    pub network_policy: NetworkEgressPolicy,
    pub sanitized_env: BTreeMap<String, String>,
}

/// Customer-configurable cleanroom runner policy (`.chinwag/cleanroom-policy.toml`) covering
/// protected Git refs, base VM image, Nix daemon socket paths, scratch/sccache/signing/slot
/// directories, Softnet egress CIDRs, and scoped release lease environment variable names
/// (`INV-CLEANROOM-TRUST-SPLIT-01` & `INV-CUSTOMER-CONFIGURABLE-NO-HARDCODING-01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRefPolicy {
    #[serde(default = "default_exact_release_refs")]
    pub allowed_exact_refs: Vec<String>,
    #[serde(default = "default_prefix_release_refs")]
    pub allowed_ref_prefixes: Vec<String>,
    #[serde(default = "default_base_image")]
    pub base_image: String,
    #[serde(default = "default_nix_store_path")]
    pub nix_store_path: PathBuf,
    #[serde(default = "default_nix_daemon_socket_dir")]
    pub nix_daemon_socket_dir: PathBuf,
    #[serde(default = "default_nix_daemon_socket_path")]
    pub nix_daemon_socket_path: PathBuf,
    #[serde(default = "default_sccache_dir")]
    pub sccache_dir: PathBuf,
    #[serde(default = "default_guest_scratch_root")]
    pub guest_scratch_root: PathBuf,
    #[serde(default)]
    pub release_signing_dir: Option<PathBuf>,
    #[serde(default)]
    pub slot_dir: Option<PathBuf>,
    #[serde(default = "default_release_lease_env_keys")]
    pub release_lease_env_keys: Vec<String>,
    #[serde(default)]
    pub allowed_egress_cidrs: Vec<String>,
}

/// Alias emphasizing full cleanroom policy parameterization alongside release-ref gating.
pub type CleanroomPolicyConfig = ReleaseRefPolicy;

fn default_exact_release_refs() -> Vec<String> {
    vec!["refs/heads/main".to_owned()]
}

fn default_prefix_release_refs() -> Vec<String> {
    vec!["refs/tags/v".to_owned()]
}

fn default_base_image() -> String {
    DEFAULT_CLEANROOM_BASE_IMAGE.to_owned()
}

fn default_nix_store_path() -> PathBuf {
    PathBuf::from(DEFAULT_NIX_STORE_SUBPATH)
}

fn default_nix_daemon_socket_dir() -> PathBuf {
    PathBuf::from(DEFAULT_NIX_DAEMON_SOCKET_DIR)
}

fn default_nix_daemon_socket_path() -> PathBuf {
    PathBuf::from(DEFAULT_NIX_DAEMON_SOCKET_PATH)
}

fn default_sccache_dir() -> PathBuf {
    PathBuf::from(DEFAULT_HOST_SCCACHE_DIR)
}

fn default_guest_scratch_root() -> PathBuf {
    PathBuf::from(DEFAULT_GUEST_SCRATCH_ROOT)
}

fn default_release_lease_env_keys() -> Vec<String> {
    vec![
        "APPLE_DEVELOPER_ID_LEASE".to_owned(),
        "NOTARYTOOL_PROFILE_LEASE".to_owned(),
        "RELEASE_UPLOAD_LEASE".to_owned(),
    ]
}

impl Default for ReleaseRefPolicy {
    fn default() -> Self {
        Self {
            allowed_exact_refs: default_exact_release_refs(),
            allowed_ref_prefixes: default_prefix_release_refs(),
            base_image: default_base_image(),
            nix_store_path: default_nix_store_path(),
            nix_daemon_socket_dir: default_nix_daemon_socket_dir(),
            nix_daemon_socket_path: default_nix_daemon_socket_path(),
            sccache_dir: default_sccache_dir(),
            guest_scratch_root: default_guest_scratch_root(),
            release_signing_dir: None,
            slot_dir: None,
            release_lease_env_keys: default_release_lease_env_keys(),
            allowed_egress_cidrs: Vec::new(),
        }
    }
}

impl ReleaseRefPolicy {
    /// Loads a customer cleanroom policy from `.chinwag/cleanroom-policy.toml` (`O_NOFOLLOW`, `nlink == 1`).
    pub fn from_toml_file(path: &Path) -> Result<Self, TrustPoolError> {
        let bytes = read_non_symlink(path)
            .map_err(|_| TrustPoolError::ReleaseRefused("failed to read cleanroom-policy.toml"))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| TrustPoolError::ReleaseRefused("cleanroom-policy.toml must be UTF-8"))?;
        let policy: Self = toml::from_str(text)
            .map_err(|_| TrustPoolError::ReleaseRefused("malformed cleanroom-policy.toml"))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), TrustPoolError> {
        if self.allowed_exact_refs.is_empty() && self.allowed_ref_prefixes.is_empty() {
            return Err(TrustPoolError::ReleaseRefused(
                "release ref policy must declare at least one allowed ref or prefix",
            ));
        }
        for r in self
            .allowed_exact_refs
            .iter()
            .chain(self.allowed_ref_prefixes.iter())
        {
            if !r.starts_with("refs/") || r.contains("..") || r.chars().any(char::is_control) {
                return Err(TrustPoolError::ReleaseRefused(
                    "release ref policy patterns must start with `refs/` and contain no `..`",
                ));
            }
        }
        if self.base_image.trim().is_empty() || self.base_image.starts_with('-') {
            return Err(TrustPoolError::ReleaseRefused(
                "cleanroom base_image must be a non-empty VM identifier",
            ));
        }
        for env_key in &self.release_lease_env_keys {
            if !is_valid_env_ident(env_key) || !env_key.ends_with("_LEASE") {
                return Err(TrustPoolError::ReleaseRefused(
                    "release_lease_env_keys must be valid `*_LEASE` identifiers",
                ));
            }
        }
        Ok(())
    }

    pub fn allows_ref(&self, git_ref: &str) -> bool {
        if !git_ref.starts_with("refs/")
            || git_ref.contains("..")
            || git_ref.chars().any(char::is_control)
        {
            return false;
        }
        if self.allowed_exact_refs.iter().any(|exact| exact == git_ref) {
            return true;
        }
        for prefix in &self.allowed_ref_prefixes {
            if let Some(rest) = git_ref.strip_prefix(prefix.as_str())
                && !rest.is_empty()
                && rest.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'/' | b'_')
                })
            {
                return true;
            }
        }
        false
    }
}

fn is_valid_env_ident(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Evaluates the 2-tier cleanroom trust split (`INV-CLEANROOM-TRUST-SPLIT-01`)
/// using the default `ReleaseRefPolicy` (`refs/heads/main` + `refs/tags/v*`).
pub fn evaluate_trust_gate(
    ctx: &JobTriggerContext,
    host_env: &BTreeMap<String, String>,
    pinned_release_signers: &[[u8; 32]],
) -> Result<RunnerTrustDecision, TrustPoolError> {
    evaluate_trust_gate_with_policy(
        ctx,
        host_env,
        pinned_release_signers,
        &ReleaseRefPolicy::default(),
    )
}

/// Evaluates the 2-tier cleanroom trust split (`INV-CLEANROOM-TRUST-SPLIT-01`)
/// against a customer-configurable `ReleaseRefPolicy`.
pub fn evaluate_trust_gate_with_policy(
    ctx: &JobTriggerContext,
    host_env: &BTreeMap<String, String>,
    pinned_release_signers: &[[u8; 32]],
    ref_policy: &ReleaseRefPolicy,
) -> Result<RunnerTrustDecision, TrustPoolError> {
    ref_policy.validate()?;
    if !is_valid_git_oid(&ctx.commit_oid) {
        return Err(TrustPoolError::ReleaseRefused("malformed commit OID"));
    }

    match ctx.requested_profile {
        RunnerTrustProfile::Public => Ok(RunnerTrustDecision {
            profile: RunnerTrustProfile::Public,
            allow_release_keys: false,
            phantom_vault_enabled: false,
            allow_apple_notarization: false,
            network_policy: NetworkEgressPolicy::RegistriesAndBinaryCacheOnly,
            sanitized_env: scrub_public_runner_env(host_env),
        }),
        RunnerTrustProfile::Release => {
            if ctx.is_fork_pr || ctx.is_untrusted_pr_event {
                return Err(TrustPoolError::ReleaseRefused(
                    "fork PRs and untrusted pull_request triggers cannot enter release profile",
                ));
            }
            if !ref_policy.allows_ref(&ctx.git_ref) {
                return Err(TrustPoolError::ReleaseRefused(
                    "git ref is not permitted by configured ReleaseRefPolicy",
                ));
            }
            let attestation =
                ctx.release_attestation
                    .as_ref()
                    .ok_or(TrustPoolError::ReleaseRefused(
                        "missing Ed25519 release signer attestation",
                    ))?;
            if attestation.git_ref != ctx.git_ref || attestation.commit_oid != ctx.commit_oid {
                return Err(TrustPoolError::ReleaseRefused(
                    "release attestation ref/commit does not match job trigger",
                ));
            }
            attestation.verify(pinned_release_signers)?;

            Ok(RunnerTrustDecision {
                profile: RunnerTrustProfile::Release,
                allow_release_keys: true,
                phantom_vault_enabled: true,
                allow_apple_notarization: true,
                network_policy: NetworkEgressPolicy::ScopedReleaseUploadAndNotarization,
                sanitized_env: filter_release_runner_env(
                    host_env,
                    &ref_policy.release_lease_env_keys,
                ),
            })
        }
    }
}

fn is_valid_git_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.trim().to_ascii_uppercase();
    upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("PASSWORD")
        || upper.contains("PASSWD")
        || upper.contains("PRIVATE")
        || upper.contains("CREDENTIAL")
        || upper.contains("API_KEY")
        || upper.contains("APIKEY")
        || upper.contains("API-KEY")
        || upper == "AUTHORIZATION"
        || upper.ends_with("_KEY")
        || upper.starts_with("APPLE_")
        || upper.starts_with("NOTARY_")
        || upper.starts_with("AWS_")
        || upper.starts_with("CLOUDFLARE_")
        || upper.starts_with("SIGNING_")
        || upper.starts_with("ANTHROPIC_")
        || upper.starts_with("OPENAI_")
        || upper.starts_with("GEMINI_")
        || upper.starts_with("VERCEL_")
        || upper == "GITHUB_TOKEN"
        || upper == "GH_TOKEN"
}

fn scrub_public_runner_env(host_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let safe_allowlist = [
        "CI",
        "LANG",
        "LC_ALL",
        "RUSTUP_TOOLCHAIN",
        "SCCACHE_RECACHE",
        "TERM",
    ];
    let mut out = BTreeMap::new();
    for (k, v) in host_env {
        if safe_allowlist.contains(&k.as_str())
            && !is_sensitive_env_key(k)
            && !v.contains('\0')
            && scrub_diagnostic_secrets(v) == *v
        {
            out.insert(k.clone(), v.clone());
        }
    }
    out.insert(
        "PATH".to_owned(),
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_owned(),
    );
    out.insert("CHINWAG_CLEANROOM_TIER".to_owned(), "public".to_owned());
    out.insert("SCCACHE_READ_ONLY".to_owned(), "1".to_owned());
    out
}

fn filter_release_runner_env(
    host_env: &BTreeMap<String, String>,
    release_lease_keys: &[String],
) -> BTreeMap<String, String> {
    let mut out = scrub_public_runner_env(host_env);
    out.insert("CHINWAG_CLEANROOM_TIER".to_owned(), "release".to_owned());
    for scoped_key in release_lease_keys {
        if is_valid_env_ident(scoped_key)
            && scoped_key.ends_with("_LEASE")
            && let Some(val) = host_env.get(scoped_key.as_str())
            && !val.contains('\0')
        {
            out.insert(scoped_key.clone(), val.clone());
        }
    }
    out
}

// ============================================================================
// Multi-Mac Pool Policy, Darwin Hardware Probes & `0700` Runtime Slot Leases
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerPoolMode {
    /// Always-on workstation / build server (`slot-1`, `slot-2`).
    Dedicated,
    /// Opportunistic developer laptop (`chinwag runner start --ephemeral --opportunistic`).
    Opportunistic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalPressure {
    Nominal,
    Fair,
    Serious,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostHardwareTelemetry {
    pub ac_power_connected: bool,
    pub thermal_pressure: ThermalPressure,
    pub cpu_idle_percent: u8,
    pub active_vm_count: u8,
    pub user_hid_active: bool,
}

/// Per-sensor Darwin hardware probe report enabling strict fail-closed rejection
/// when `--opportunistic` is active and any un-overridden sensor probe fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareProbeReport {
    pub ac_power_connected: Result<bool, &'static str>,
    pub thermal_pressure: Result<ThermalPressure, &'static str>,
    pub cpu_idle_percent: Result<u8, &'static str>,
    pub user_hid_active: Result<bool, &'static str>,
    pub active_vm_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolAdmissionPolicy {
    pub mode: RunnerPoolMode,
    pub max_vms_per_host: u8,
    pub min_cpu_idle_percent: u8,
    pub drain_budget_ms: u64,
}

impl PoolAdmissionPolicy {
    pub fn dedicated() -> Self {
        Self {
            mode: RunnerPoolMode::Dedicated,
            max_vms_per_host: MAX_VMS_PER_MAC_HOST,
            min_cpu_idle_percent: 10,
            drain_budget_ms: MAX_DRAIN_BUDGET_MS,
        }
    }

    pub fn opportunistic() -> Self {
        Self {
            mode: RunnerPoolMode::Opportunistic,
            max_vms_per_host: MAX_VMS_PER_MAC_HOST,
            min_cpu_idle_percent: DEFAULT_MIN_CPU_IDLE_PERCENT,
            drain_budget_ms: MAX_DRAIN_BUDGET_MS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolAdmissionDecision {
    pub admitted: bool,
    pub allocated_slot: Option<u8>,
    pub drain_required: bool,
    pub drain_budget_ms: u64,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct RunnerPoolController {
    policy: PoolAdmissionPolicy,
}

impl RunnerPoolController {
    pub fn new(policy: PoolAdmissionPolicy) -> Result<Self, TrustPoolError> {
        if policy.max_vms_per_host == 0 || policy.max_vms_per_host > MAX_VMS_PER_MAC_HOST {
            return Err(TrustPoolError::PoolAdmissionRefused(
                "Apple Virtualization.framework caps macOS VMs at 1..=2 per physical host",
            ));
        }
        Ok(Self { policy })
    }

    pub fn evaluate_admission(&self, telemetry: &HostHardwareTelemetry) -> PoolAdmissionDecision {
        if telemetry.active_vm_count >= self.policy.max_vms_per_host {
            return PoolAdmissionDecision {
                admitted: false,
                allocated_slot: None,
                drain_required: false,
                drain_budget_ms: self.policy.drain_budget_ms,
                reason: "host_two_vm_hypervisor_cap_reached",
            };
        }

        match self.policy.mode {
            RunnerPoolMode::Dedicated => {
                if matches!(
                    telemetry.thermal_pressure,
                    ThermalPressure::Serious | ThermalPressure::Critical
                ) {
                    return PoolAdmissionDecision {
                        admitted: false,
                        allocated_slot: None,
                        drain_required: false,
                        drain_budget_ms: self.policy.drain_budget_ms,
                        reason: "dedicated_host_thermal_throttling",
                    };
                }
                PoolAdmissionDecision {
                    admitted: true,
                    allocated_slot: Some(telemetry.active_vm_count + 1),
                    drain_required: false,
                    drain_budget_ms: self.policy.drain_budget_ms,
                    reason: "admitted_dedicated_slot",
                }
            }
            RunnerPoolMode::Opportunistic => {
                if !telemetry.ac_power_connected {
                    return PoolAdmissionDecision {
                        admitted: false,
                        allocated_slot: None,
                        drain_required: telemetry.active_vm_count > 0,
                        drain_budget_ms: self.policy.drain_budget_ms,
                        reason: "opportunistic_requires_ac_wall_power",
                    };
                }
                if telemetry.user_hid_active {
                    return PoolAdmissionDecision {
                        admitted: false,
                        allocated_slot: None,
                        drain_required: telemetry.active_vm_count > 0,
                        drain_budget_ms: self.policy.drain_budget_ms,
                        reason: "opportunistic_paused_on_user_input",
                    };
                }
                if telemetry.thermal_pressure != ThermalPressure::Nominal {
                    return PoolAdmissionDecision {
                        admitted: false,
                        allocated_slot: None,
                        drain_required: telemetry.active_vm_count > 0,
                        drain_budget_ms: self.policy.drain_budget_ms,
                        reason: "opportunistic_requires_nominal_thermal_pressure",
                    };
                }
                if telemetry.cpu_idle_percent < self.policy.min_cpu_idle_percent {
                    return PoolAdmissionDecision {
                        admitted: false,
                        allocated_slot: None,
                        drain_required: false,
                        drain_budget_ms: self.policy.drain_budget_ms,
                        reason: "opportunistic_insufficient_cpu_idle_headroom",
                    };
                }
                PoolAdmissionDecision {
                    admitted: true,
                    allocated_slot: Some(telemetry.active_vm_count + 1),
                    drain_required: false,
                    drain_budget_ms: self.policy.drain_budget_ms,
                    reason: "admitted_opportunistic_slot",
                }
            }
        }
    }
}

/// Resolves and initializes the default `0700` user-owned runtime slot directory
/// (`~/.chinwag/run/cleanroom-slots`), verifying `uid == geteuid()` and non-symlink hierarchy.
pub fn default_runtime_slot_dir() -> Result<PathBuf, TrustPoolError> {
    let home =
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(TrustPoolError::PoolAdmissionRefused(
                "HOME environment variable is required to anchor ~/.chinwag/run/cleanroom-slots",
            ))?;
    if !home.is_absolute()
        || home
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(TrustPoolError::PoolAdmissionRefused(
            "HOME must be a normalized absolute path",
        ));
    }
    let dot_chinwag = home.join(".chinwag");
    let run_dir = dot_chinwag.join("run");
    let slots = run_dir.join("cleanroom-slots");
    ensure_user_owned_dir_0700_step(&dot_chinwag, false)?;
    ensure_user_owned_dir_0700_step(&run_dir, true)?;
    ensure_user_owned_dir_0700_step(&slots, true)?;
    Ok(slots)
}

fn ensure_user_owned_dir_0700_step(dir: &Path, enforce_0700: bool) -> Result<(), TrustPoolError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        let euid = rustix::process::geteuid().as_raw();
        if !dir.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            if let Err(e) = builder.create(dir)
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(TrustPoolError::PoolAdmissionRefused(
                    "failed to create 0700 runtime directory",
                ));
            }
        }
        let meta = fs::symlink_metadata(dir)
            .map_err(|_| TrustPoolError::PoolAdmissionRefused("slot_dir metadata unreadable"))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(TrustPoolError::PoolAdmissionRefused(
                "slot_dir and runtime ancestors must be non-symlink directories",
            ));
        }
        if meta.uid() != euid {
            return Err(TrustPoolError::PoolAdmissionRefused(
                "slot_dir uid does not match current effective user (geteuid)",
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if enforce_0700 && (mode & 0o077) != 0 {
            return Err(TrustPoolError::PoolAdmissionRefused(
                "slot_dir must enforce 0700 owner-only permissions",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = enforce_0700;
        fs::create_dir_all(dir)
            .map_err(|_| TrustPoolError::PoolAdmissionRefused("failed to create slot_dir"))
    }
}

fn ensure_secure_slot_dir(slot_dir: &Path) -> Result<(), TrustPoolError> {
    if slot_dir
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(TrustPoolError::PoolAdmissionRefused(
            "slot_dir cannot contain relative `.` or `..` segments",
        ));
    }
    if let Some(parent) = slot_dir.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut b = fs::DirBuilder::new();
            b.recursive(true).mode(0o700);
            b.create(parent).map_err(|_| {
                TrustPoolError::PoolAdmissionRefused("failed to create slot parent")
            })?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent).map_err(|_| {
                TrustPoolError::PoolAdmissionRefused("failed to create slot parent")
            })?;
        }
    }
    ensure_user_owned_dir_0700_step(slot_dir, true)
}

fn is_pid_alive(pid_u32: u32) -> bool {
    #[cfg(unix)]
    {
        if pid_u32 == 0 {
            return true;
        }
        let Ok(raw_pid) = i32::try_from(pid_u32) else {
            return false;
        };
        let Some(pid) = rustix::process::Pid::from_raw(raw_pid) else {
            return false;
        };
        match rustix::process::test_kill_process(pid) {
            Ok(()) => true,
            Err(e) => e != rustix::io::Errno::SRCH,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid_u32;
        true
    }
}

/// Reaps stale `slot-*.lease` files owned by `geteuid()` whose recorded PID is dead (`ESRCH`).
pub fn reap_dead_slot_leases(slot_dir: &Path, max_vms: u8) -> Result<u8, TrustPoolError> {
    ensure_secure_slot_dir(slot_dir)?;
    let mut reaped = 0u8;
    for slot in 1..=max_vms.min(MAX_VMS_PER_MAC_HOST) {
        let lease_path = slot_dir.join(format!("slot-{slot}.lease"));
        let Ok(meta) = fs::symlink_metadata(&lease_path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(TrustPoolError::PoolAdmissionRefused(
                "slot lease entry cannot be a symlink or special file",
            ));
        }
        #[cfg(unix)]
        {
            use rustix::fs::{CWD, Mode, OFlags, fstat, openat};
            let euid = rustix::process::geteuid().as_raw();
            let fd = openat(
                CWD,
                &lease_path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| TrustPoolError::PoolAdmissionRefused("failed to inspect slot lease"))?;
            let stat = fstat(&fd)
                .map_err(|_| TrustPoolError::PoolAdmissionRefused("slot fstat failed"))?;
            if stat.st_uid != euid {
                return Err(TrustPoolError::PoolAdmissionRefused(
                    "slot lease owned by foreign uid",
                ));
            }
            let mut text = String::new();
            let _ = File::from(fd).take(256).read_to_string(&mut text);
            let parsed_pid = text
                .lines()
                .find_map(|l| l.strip_prefix("pid="))
                .and_then(|v| v.trim().parse::<u32>().ok());
            if let Some(pid) = parsed_pid
                && !is_pid_alive(pid)
                && fs::remove_file(&lease_path).is_ok()
            {
                reaped = reaped.saturating_add(1);
            }
        }
    }
    Ok(reaped)
}

/// RAII host-wide hypervisor slot lease (`slot-1.lease`..`slot-2.lease`) enforcing
/// Apple `Virtualization.framework`'s 2-VM cap across concurrent `chinwag runner` processes.
#[derive(Debug)]
pub struct HostVmSlotLease {
    slot_index: u8,
    lease_path: PathBuf,
}

impl HostVmSlotLease {
    pub const fn slot_index(&self) -> u8 {
        self.slot_index
    }

    pub fn lease_path(&self) -> &Path {
        &self.lease_path
    }
}

impl Drop for HostVmSlotLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lease_path);
    }
}

/// Verifies `slot_dir` is `0700` + owned by `geteuid()`, reaps dead-PID leases, and atomically
/// claims the lowest free hypervisor slot (`1..=max_vms`) via `O_CREAT | O_EXCL | O_NOFOLLOW` (`0600`).
pub fn acquire_host_vm_slot(
    slot_dir: &Path,
    max_vms: u8,
) -> Result<HostVmSlotLease, TrustPoolError> {
    if max_vms == 0 || max_vms > MAX_VMS_PER_MAC_HOST {
        return Err(TrustPoolError::PoolAdmissionRefused(
            "Apple Virtualization.framework caps macOS VMs at 1..=2 per physical host",
        ));
    }
    let _ = reap_dead_slot_leases(slot_dir, max_vms)?;

    for slot in 1..=max_vms {
        let lease_path = slot_dir.join(format!("slot-{slot}.lease"));
        #[cfg(unix)]
        {
            use rustix::fs::{CWD, Mode, OFlags, openat};
            match openat(
                CWD,
                &lease_path,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    let mut f = File::from(fd);
                    let body = format!("pid={}\nslot={slot}\n", std::process::id());
                    let _ = f.write_all(body.as_bytes()).and_then(|()| f.sync_all());
                    return Ok(HostVmSlotLease {
                        slot_index: slot,
                        lease_path,
                    });
                }
                Err(e) if e == rustix::io::Errno::EXIST => continue,
                Err(_) => {
                    return Err(TrustPoolError::PoolAdmissionRefused(
                        "failed to open host hypervisor slot lease",
                    ));
                }
            }
        }
        #[cfg(not(unix))]
        {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lease_path)
            {
                Ok(mut f) => {
                    let body = format!("pid={}\nslot={slot}\n", std::process::id());
                    let _ = f.write_all(body.as_bytes()).and_then(|()| f.sync_all());
                    return Ok(HostVmSlotLease {
                        slot_index: slot,
                        lease_path,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => {
                    return Err(TrustPoolError::PoolAdmissionRefused(
                        "failed to open host hypervisor slot lease",
                    ));
                }
            }
        }
    }

    Err(TrustPoolError::PoolAdmissionRefused(
        "host_two_vm_hypervisor_cap_reached",
    ))
}

/// Counts live `slot-*.lease` files in `slot_dir` after reaping any dead-PID leases.
pub fn count_active_slot_leases(slot_dir: &Path, max_vms: u8) -> u8 {
    if slot_dir.exists() {
        let _ = reap_dead_slot_leases(slot_dir, max_vms);
    }
    let mut active = 0u8;
    for slot in 1..=max_vms.min(MAX_VMS_PER_MAC_HOST) {
        let p = slot_dir.join(format!("slot-{slot}.lease"));
        if fs::symlink_metadata(&p).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink()) {
            active = active.saturating_add(1);
        }
    }
    active
}

fn probe_darwin_ac_power() -> Result<bool, &'static str> {
    let out = Command::new("/usr/bin/pmset")
        .args(["-g", "batt"])
        .env_clear()
        .output()
        .map_err(|_| "opportunistic_ac_power_probe_failed")?;
    if !out.status.success() {
        return Err("opportunistic_ac_power_probe_failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("Battery Power") {
        Ok(false)
    } else if text.contains("AC Power") {
        Ok(true)
    } else {
        Err("opportunistic_ac_power_probe_failed")
    }
}

/// Parses `pmset -g therm` output into `ThermalPressure` (unit-testable parser).
pub fn parse_darwin_pmset_therm(text: &str) -> ThermalPressure {
    let lower = text.to_ascii_lowercase();
    if lower.contains("critical") || lower.contains("sleeping") {
        return ThermalPressure::Critical;
    }
    if lower.contains("serious") || lower.contains("heavy") || lower.contains("trapping") {
        return ThermalPressure::Serious;
    }
    if lower.contains("moderate") || lower.contains("fair") {
        return ThermalPressure::Fair;
    }
    for line in text.lines() {
        if let Some((_, rhs)) = line.split_once("CPU_Speed_Limit")
            && let Some(num) = rhs
                .trim_start_matches(|c: char| !c.is_ascii_digit())
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|s| s.parse::<u32>().ok())
        {
            return match num {
                100.. => ThermalPressure::Nominal,
                80..=99 => ThermalPressure::Fair,
                50..=79 => ThermalPressure::Serious,
                _ => ThermalPressure::Critical,
            };
        }
    }
    ThermalPressure::Nominal
}

fn probe_darwin_thermal_pressure() -> Result<ThermalPressure, &'static str> {
    let out = Command::new("/usr/bin/pmset")
        .args(["-g", "therm"])
        .env_clear()
        .output()
        .map_err(|_| "opportunistic_thermal_probe_failed")?;
    if !out.status.success() {
        return Err("opportunistic_thermal_probe_failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return Err("opportunistic_thermal_probe_failed");
    }
    Ok(parse_darwin_pmset_therm(&text))
}

/// Parses `ioreg -c IOHIDSystem` output for `"HIDIdleTime" = <ns>` (`< 30s` -> active).
pub fn parse_darwin_ioreg_hid_active(text: &str) -> Result<bool, &'static str> {
    for line in text.lines() {
        if let Some((_, rhs)) = line.split_once("\"HIDIdleTime\"")
            && let Some((_, val_part)) = rhs.split_once('=')
            && let Ok(idle_ns) = val_part.trim().parse::<u64>()
        {
            return Ok(idle_ns < USER_HID_ACTIVE_THRESHOLD_NS);
        }
    }
    Err("opportunistic_hid_idle_probe_failed")
}

fn probe_darwin_hid_active() -> Result<bool, &'static str> {
    let out = Command::new("/usr/sbin/ioreg")
        .args(["-c", "IOHIDSystem", "-d", "4"])
        .env_clear()
        .output()
        .map_err(|_| "opportunistic_hid_idle_probe_failed")?;
    if !out.status.success() {
        return Err("opportunistic_hid_idle_probe_failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_darwin_ioreg_hid_active(&text)
}

/// Parses `top -l 1 -n 0` output for `CPU usage: ... <float>% idle`.
pub fn parse_darwin_top_cpu_idle(text: &str) -> Result<u8, &'static str> {
    for line in text.lines() {
        if let Some((_, after_header)) = line.split_once("CPU usage:") {
            for part in after_header.split(',') {
                let trimmed = part.trim();
                if let Some(pct_str) = trimmed.strip_suffix("idle") {
                    let num_str = pct_str.trim().trim_end_matches('%').trim();
                    if let Ok(val) = num_str.parse::<f64>()
                        && val.is_finite()
                        && (0.0..=100.0).contains(&val)
                    {
                        return Ok(val.floor() as u8);
                    }
                }
            }
        }
    }
    Err("opportunistic_cpu_idle_probe_failed")
}

fn probe_darwin_cpu_idle_percent() -> Result<u8, &'static str> {
    let out = Command::new("/usr/bin/top")
        .args(["-l", "1", "-n", "0", "-s", "0"])
        .env_clear()
        .output()
        .map_err(|_| "opportunistic_cpu_idle_probe_failed")?;
    if !out.status.success() {
        return Err("opportunistic_cpu_idle_probe_failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_darwin_top_cpu_idle(&text)
}

/// Probes individual Darwin power, thermal, HID-idle, CPU-idle, and active slot sensors.
pub fn probe_host_hardware_report(slot_dir: &Path) -> HardwareProbeReport {
    let active_vm_count = count_active_slot_leases(slot_dir, MAX_VMS_PER_MAC_HOST);
    HardwareProbeReport {
        ac_power_connected: probe_darwin_ac_power(),
        thermal_pressure: probe_darwin_thermal_pressure(),
        cpu_idle_percent: probe_darwin_cpu_idle_percent(),
        user_hid_active: probe_darwin_hid_active(),
        active_vm_count,
    }
}

/// Strictly probes all live Darwin hardware sensors, failing closed if any sensor cannot be read.
pub fn try_probe_host_hardware_telemetry(
    slot_dir: &Path,
) -> Result<HostHardwareTelemetry, TrustPoolError> {
    let r = probe_host_hardware_report(slot_dir);
    Ok(HostHardwareTelemetry {
        ac_power_connected: r
            .ac_power_connected
            .map_err(TrustPoolError::PoolAdmissionRefused)?,
        thermal_pressure: r
            .thermal_pressure
            .map_err(TrustPoolError::PoolAdmissionRefused)?,
        cpu_idle_percent: r
            .cpu_idle_percent
            .map_err(TrustPoolError::PoolAdmissionRefused)?,
        active_vm_count: r.active_vm_count,
        user_hid_active: r
            .user_hid_active
            .map_err(TrustPoolError::PoolAdmissionRefused)?,
    })
}

/// Probes live macOS power, thermal, HID, CPU, and slot state; any failed sensor
/// defaults to fail-closed conservative telemetry (`ac=false`, `Critical`, `idle=0`, `hid=true`).
pub fn probe_host_hardware_telemetry(slot_dir: &Path) -> HostHardwareTelemetry {
    let r = probe_host_hardware_report(slot_dir);
    HostHardwareTelemetry {
        ac_power_connected: r.ac_power_connected.unwrap_or(false),
        thermal_pressure: r.thermal_pressure.unwrap_or(ThermalPressure::Critical),
        cpu_idle_percent: r.cpu_idle_percent.unwrap_or(0),
        active_vm_count: r.active_vm_count,
        user_hid_active: r.user_hid_active.unwrap_or(true),
    }
}

// ============================================================================
// Hook H4: Sealed Failure Diagnostic Bundle Contract (X25519-MLKEM768 + Ed25519)
// ============================================================================

struct PreSampledEntropy<const N: usize> {
    buf: Zeroizing<[u8; N]>,
    offset: usize,
    overflowed: bool,
}

impl<const N: usize> PreSampledEntropy<N> {
    fn sample() -> Result<Self, TrustPoolError> {
        let mut buf = Zeroizing::new([0u8; N]);
        getrandom::fill(&mut buf[..]).map_err(|_| TrustPoolError::Entropy)?;
        if bool::from(buf[..].ct_eq(&[0u8; N])) {
            return Err(TrustPoolError::Entropy);
        }
        Ok(Self {
            buf,
            offset: 0,
            overflowed: false,
        })
    }

    fn finish(self) -> Result<(), TrustPoolError> {
        if self.overflowed || self.offset != N {
            return Err(TrustPoolError::Entropy);
        }
        Ok(())
    }
}

impl<const N: usize> TryRng for PreSampledEntropy<N> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut out = [0u8; 4];
        self.try_fill_bytes(&mut out)?;
        Ok(u32::from_le_bytes(out))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut out = [0u8; 8];
        self.try_fill_bytes(&mut out)?;
        Ok(u64::from_le_bytes(out))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let avail = N.saturating_sub(self.offset);
        if self.overflowed || dst.len() > avail {
            self.overflowed = true;
            dst.fill(0);
            return Ok(());
        }
        let end = self.offset + dst.len();
        dst.copy_from_slice(&self.buf[self.offset..end]);
        self.buf[self.offset..end].fill(0);
        self.offset = end;
        Ok(())
    }
}

impl<const N: usize> TryCryptoRng for PreSampledEntropy<N> {}

/// Generates a fresh `X25519-MLKEM768` (`0x647a`) recipient keypair (`32 B` secret seed, `1216 B` public key).
pub fn generate_recipient_kem_keypair() -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), TrustPoolError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| TrustPoolError::Entropy)?;
    if bool::from(seed[..].ct_eq(&[0u8; 32])) {
        return Err(TrustPoolError::Entropy);
    }
    let (sk, pk) = XWing::derive_keypair(&seed[..]);
    let mut sk_arr = Zeroizing::new([0u8; 32]);
    sk_arr.copy_from_slice(sk.to_bytes().as_slice());
    Ok((sk_arr, pk.to_bytes().to_vec()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanroomDiagnosticInput {
    pub job_id: String,
    pub run_vm_name: String,
    pub trust_profile: RunnerTrustProfile,
    pub exit_code: i32,
    pub flake_lock_sha256: String,
    pub stderr_tail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedFailureBundleV1 {
    pub schema: String,
    pub ciphersuite: String,
    pub job_id: String,
    pub run_vm_name: String,
    pub trust_profile: RunnerTrustProfile,
    pub flake_lock_sha256: String,
    pub recipient_key_id_hex: String,
    pub runner_signer_pubkey_hex: String,
    pub plaintext_len: u32,
    pub encapsulated_key_hex: String,
    pub ciphertext_hex: String,
    pub origin_signature_hex: String,
}

/// Scrubs bearer tokens, Chinwag/GitHub/GitLab/Slack/AWS/OpenAI/Anthropic/Gemini/Vercel keys,
/// JWTs (`eyJ*`), sensitive env/JSON/URL assignments, and PEM private keys from failure logs
/// across whitespace, JSON, URL, and quote delimiters BEFORE failure emission or HPKE sealing (`Hook H4`).
pub fn scrub_diagnostic_secrets(raw: &str) -> String {
    let mut scrubbed = String::with_capacity(raw.len());
    let mut in_pem = false;
    for line in raw.lines() {
        let upper_line = line.to_ascii_uppercase();
        if upper_line.contains("BEGIN ") && upper_line.contains("PRIVATE KEY") {
            in_pem = true;
            scrubbed.push_str("[REDACTED_PRIVATE_KEY_BLOCK]\n");
            continue;
        }
        if in_pem {
            if upper_line.contains("END ") && upper_line.contains("PRIVATE KEY") {
                in_pem = false;
            }
            continue;
        }
        let step1 = redact_all_bearer_spans(line);
        let step2 = redact_sensitive_key_value_spans(&step1);
        let step3 = redact_secret_shaped_spans(&step2);
        scrubbed.push_str(&step3);
        scrubbed.push('\n');
    }
    if !raw.ends_with('\n') && scrubbed.ends_with('\n') {
        scrubbed.pop();
    }
    scrubbed
}

fn is_bearer_value_terminator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}' | '&' | '>')
}

fn redact_all_bearer_spans(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while !rest.is_empty() {
        let lower = rest.to_ascii_lowercase();
        let Some(pos) = lower.find("bearer") else {
            out.push_str(rest);
            break;
        };
        // Ensure `bearer` is not the tail of an identifier (e.g. `foobearer`)
        let boundary_before = pos == 0
            || !rest[..pos]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        let after_kw = &rest[pos + 6..];
        let ws_len: usize = after_kw
            .chars()
            .take_while(|c| matches!(*c, ' ' | '\t'))
            .map(char::len_utf8)
            .sum();
        if !boundary_before || ws_len == 0 {
            out.push_str(&rest[..pos + 6]);
            rest = after_kw;
            continue;
        }
        out.push_str(&rest[..pos + 6]);
        out.push(' ');
        let val_start = &after_kw[ws_len..];
        let tok_len: usize = val_start
            .chars()
            .take_while(|c| !is_bearer_value_terminator(*c))
            .map(char::len_utf8)
            .sum();
        if tok_len == 0 {
            rest = val_start;
            continue;
        }
        out.push_str("[REDACTED_BEARER]");
        rest = &val_start[tok_len..];
    }
    out
}

fn redact_sensitive_key_value_spans(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Scan an identifier `[A-Za-z_][A-Za-z0-9_-]*`
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-'))
            {
                i += 1;
            }
            let ident = &line[start..i];
            out.push_str(ident);

            if is_sensitive_env_key(ident) {
                // Allow optional closing quote + optional horizontal whitespace + (`=` or `:`)
                let mut j = i;
                if j < bytes.len() && matches!(bytes[j], b'"' | b'\'') {
                    j += 1;
                }
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                if j < bytes.len() && matches!(bytes[j], b'=' | b':') {
                    j += 1;
                    while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                        j += 1;
                    }
                    // Copy separator punctuation (`": "` or `=`) verbatim
                    out.push_str(&line[i..j]);
                    if j < bytes.len() && matches!(bytes[j], b'"' | b'\'') {
                        let quote = bytes[j];
                        out.push(quote as char);
                        j += 1;
                        let val_start = j;
                        while j < bytes.len() && bytes[j] != quote {
                            if bytes[j] == b'\\' && j + 1 < bytes.len() {
                                j += 2;
                            } else {
                                j += 1;
                            }
                        }
                        if j > val_start {
                            out.push_str("[REDACTED]");
                        }
                        if j < bytes.len() && bytes[j] == quote {
                            out.push(quote as char);
                            j += 1;
                        }
                        i = j;
                        continue;
                    } else {
                        let rest_str = &line[j..];
                        let val_len: usize = rest_str
                            .chars()
                            .take_while(|c| !is_bearer_value_terminator(*c))
                            .map(char::len_utf8)
                            .sum();
                        if val_len > 0 {
                            out.push_str("[REDACTED]");
                            i = j + val_len;
                            continue;
                        }
                    }
                }
            }
        } else {
            let ch = line[i..].chars().next().expect("i < bytes.len()");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn is_token_delimiter(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\''
                | ','
                | ';'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '&'
                | '?'
                | '='
                | ':'
                | '|'
                | '<'
                | '>'
                | '`'
                | '@'
        )
}

fn is_secret_token_shape(tok: &str) -> bool {
    if tok.starts_with("[REDACTED") {
        return false;
    }
    tok.starts_with("chwg_live_")
        || tok.starts_with("chwg_agent_")
        || (tok.starts_with("rk-") && tok.len() >= 8)
        || tok.starts_with("xoxb-")
        || tok.starts_with("xoxa-")
        || tok.starts_with("xoxp-")
        || tok.starts_with("xoxr-")
        || tok.starts_with("xoxs-")
        || tok.starts_with("glpat-")
        || tok.starts_with("ghp_")
        || tok.starts_with("gho_")
        || tok.starts_with("ghu_")
        || tok.starts_with("ghs_")
        || tok.starts_with("ghr_")
        || tok.starts_with("github_pat_")
        || ((tok.starts_with("AKIA") || tok.starts_with("ASIA"))
            && tok.len() >= 16
            && tok
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
        || (tok.starts_with("eyJ") && tok.len() >= 20 && tok.contains('.'))
        || (tok.starts_with("sk-") && tok.len() >= 8)
        || (tok.starts_with("AIza") && tok.len() >= 20)
        || ((tok.starts_with("vck_") || tok.starts_with("vcp_")) && tok.len() >= 12)
}

fn redact_secret_shaped_spans(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut idx = 0usize;
    while idx < line.len() {
        let ch = line[idx..].chars().next().expect("idx < line.len()");
        if is_token_delimiter(ch) {
            out.push(ch);
            idx += ch.len_utf8();
            continue;
        }
        let span_len: usize = line[idx..]
            .chars()
            .take_while(|c| !is_token_delimiter(*c))
            .map(char::len_utf8)
            .sum();
        let tok = &line[idx..idx + span_len];
        if is_secret_token_shape(tok) {
            out.push_str("[REDACTED_TOKEN]");
        } else {
            out.push_str(tok);
        }
        idx += span_len;
    }
    out
}

fn bundle_aad_and_info(
    job_id: &str,
    run_vm_name: &str,
    profile: RunnerTrustProfile,
    flake_lock_sha256: &str,
    recipient_key_id: &[u8; 32],
    runner_pubkey: &[u8; 32],
    plaintext_len: u32,
) -> (Vec<u8>, Vec<u8>) {
    let mut info = Vec::with_capacity(192);
    info.extend_from_slice(FAILURE_HPKE_INFO_PREFIX);
    info.extend_from_slice(job_id.as_bytes());
    info.push(0);
    info.extend_from_slice(run_vm_name.as_bytes());
    info.push(0);
    info.extend_from_slice(profile.as_str().as_bytes());
    info.push(0);
    info.extend_from_slice(flake_lock_sha256.as_bytes());

    let mut aad = info.clone();
    aad.extend_from_slice(recipient_key_id);
    aad.extend_from_slice(runner_pubkey);
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    (info, aad)
}

fn bundle_signature_preimage(aad: &[u8], enc_bytes: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(aad.len() + 96);
    msg.extend_from_slice(FAILURE_SIG_DOMAIN);
    msg.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    msg.extend_from_slice(aad);
    msg.extend_from_slice(blake3::hash(enc_bytes).as_bytes());
    msg.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    msg.extend_from_slice(blake3::hash(ciphertext).as_bytes());
    msg
}

/// Scrubs, compresses (`zstd`), seals (`X25519-MLKEM768`), and signs (`Ed25519`) a
/// cleanroom diagnostic failure bundle (`Hook H4`).
pub fn seal_failure_diagnostic_bundle(
    mut diagnostic: CleanroomDiagnosticInput,
    recipient_kem_public: &[u8],
    runner_signing_key: &SigningKey,
) -> Result<SealedFailureBundleV1, TrustPoolError> {
    if diagnostic.job_id.is_empty() || diagnostic.run_vm_name.is_empty() {
        return Err(TrustPoolError::DiagnosticBundle(
            "empty job_id or run_vm_name",
        ));
    }
    let pk = <XWing as KemTrait>::PublicKey::from_bytes(recipient_kem_public)
        .map_err(|_| TrustPoolError::DiagnosticBundle("invalid X25519-MLKEM768 recipient key"))?;
    let runner_vk = runner_signing_key.verifying_key();
    if runner_vk.is_weak() {
        return Err(TrustPoolError::DiagnosticBundle("weak runner Ed25519 key"));
    }

    diagnostic.stderr_tail = scrub_diagnostic_secrets(&diagnostic.stderr_tail);
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&diagnostic)
            .map_err(|_| TrustPoolError::DiagnosticBundle("diagnostic serialization failed"))?,
    );
    if plaintext.len() > MAX_DIAGNOSTIC_PLAINTEXT_BYTES {
        return Err(TrustPoolError::DiagnosticBundle(
            "diagnostic plaintext exceeds 8 MiB bound",
        ));
    }
    let plaintext_len = u32::try_from(plaintext.len())
        .map_err(|_| TrustPoolError::DiagnosticBundle("plaintext length overflow"))?;

    let compressed = Zeroizing::new(
        zstd::stream::encode_all(Cursor::new(plaintext.as_slice()), 3)
            .map_err(|_| TrustPoolError::DiagnosticBundle("zstd compression failed"))?,
    );
    if compressed.len() > MAX_DIAGNOSTIC_COMPRESSED_BYTES {
        return Err(TrustPoolError::DiagnosticBundle(
            "compressed diagnostic exceeds size bound",
        ));
    }

    let recipient_key_id = *blake3::hash(recipient_kem_public).as_bytes();
    let runner_pub_bytes = runner_vk.to_bytes();
    let (info, aad) = bundle_aad_and_info(
        &diagnostic.job_id,
        &diagnostic.run_vm_name,
        diagnostic.trust_profile,
        &diagnostic.flake_lock_sha256,
        &recipient_key_id,
        &runner_pub_bytes,
        plaintext_len,
    );

    let mut rng = PreSampledEntropy::<64>::sample()?;
    let (enc, mut sender) = hpke::setup_sender_with_rng::<HpkeChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        &info,
        &mut rng,
    )
    .map_err(|_| TrustPoolError::DiagnosticBundle("HPKE sender setup failed"))?;
    rng.finish()?;

    let ciphertext = sender
        .seal(compressed.as_slice(), &aad)
        .map_err(|_| TrustPoolError::DiagnosticBundle("HPKE AEAD seal failed"))?;
    let enc_bytes = enc.to_bytes();
    let sig_preimage = bundle_signature_preimage(&aad, enc_bytes.as_slice(), &ciphertext);
    let sig = runner_signing_key.sign(&sig_preimage);

    Ok(SealedFailureBundleV1 {
        schema: FAILURE_BUNDLE_SCHEMA.to_owned(),
        ciphersuite: FAILURE_BUNDLE_CIPHERSUITE.to_owned(),
        job_id: diagnostic.job_id,
        run_vm_name: diagnostic.run_vm_name,
        trust_profile: diagnostic.trust_profile,
        flake_lock_sha256: diagnostic.flake_lock_sha256,
        recipient_key_id_hex: hex::encode(recipient_key_id),
        runner_signer_pubkey_hex: hex::encode(runner_pub_bytes),
        plaintext_len,
        encapsulated_key_hex: hex::encode(enc_bytes),
        ciphertext_hex: hex::encode(ciphertext),
        origin_signature_hex: hex::encode(sig.to_bytes()),
    })
}

/// Verifies the runner `Ed25519` signature strictly BEFORE `X25519-MLKEM768`
/// decapsulation and bounded `zstd` single-frame decompression.
pub fn open_failure_diagnostic_bundle(
    bundle: &SealedFailureBundleV1,
    recipient_kem_secret: &[u8; 32],
    expected_runner_pubkey: &[u8; 32],
) -> Result<CleanroomDiagnosticInput, TrustPoolError> {
    if bundle.schema != FAILURE_BUNDLE_SCHEMA
        || bundle.ciphersuite != FAILURE_BUNDLE_CIPHERSUITE
        || (bundle.plaintext_len as usize) > MAX_DIAGNOSTIC_PLAINTEXT_BYTES
    {
        return Err(TrustPoolError::DiagnosticBundle(
            "invalid bundle schema, ciphersuite, or length",
        ));
    }

    let claimed_runner_pub = hex::decode(&bundle.runner_signer_pubkey_hex)
        .map_err(|_| TrustPoolError::DiagnosticBundle("malformed runner pubkey hex"))?;
    let runner_pub_arr: [u8; 32] = claimed_runner_pub
        .try_into()
        .map_err(|_| TrustPoolError::DiagnosticBundle("invalid runner pubkey length"))?;
    if !bool::from(runner_pub_arr.ct_eq(expected_runner_pubkey)) {
        return Err(TrustPoolError::DiagnosticBundle(
            "runner pubkey mismatch against pinned runner identity",
        ));
    }
    let vk = VerifyingKey::from_bytes(&runner_pub_arr)
        .map_err(|_| TrustPoolError::DiagnosticBundle("invalid runner Ed25519 key"))?;
    if vk.is_weak() {
        return Err(TrustPoolError::DiagnosticBundle("weak runner Ed25519 key"));
    }

    let recipient_id_raw = hex::decode(&bundle.recipient_key_id_hex)
        .map_err(|_| TrustPoolError::DiagnosticBundle("malformed recipient key id"))?;
    let recipient_id_arr: [u8; 32] = recipient_id_raw
        .try_into()
        .map_err(|_| TrustPoolError::DiagnosticBundle("invalid recipient key id length"))?;

    let enc_raw = hex::decode(&bundle.encapsulated_key_hex)
        .map_err(|_| TrustPoolError::DiagnosticBundle("malformed encapsulated key hex"))?;
    let ciphertext = hex::decode(&bundle.ciphertext_hex)
        .map_err(|_| TrustPoolError::DiagnosticBundle("malformed ciphertext hex"))?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_DIAGNOSTIC_COMPRESSED_BYTES + 16 {
        return Err(TrustPoolError::DiagnosticBundle("invalid ciphertext size"));
    }
    let sig_raw = hex::decode(&bundle.origin_signature_hex)
        .map_err(|_| TrustPoolError::DiagnosticBundle("malformed origin signature hex"))?;
    let sig_arr: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| TrustPoolError::DiagnosticBundle("invalid origin signature length"))?;

    let (info, aad) = bundle_aad_and_info(
        &bundle.job_id,
        &bundle.run_vm_name,
        bundle.trust_profile,
        &bundle.flake_lock_sha256,
        &recipient_id_arr,
        &runner_pub_arr,
        bundle.plaintext_len,
    );

    // Mandatory Verify-Before-Decrypt (`INV-VERIFY-BEFORE-DECRYPT-01`)
    let sig_preimage = bundle_signature_preimage(&aad, &enc_raw, &ciphertext);
    vk.verify_strict(&sig_preimage, &Signature::from_bytes(&sig_arr))
        .map_err(|_| {
            TrustPoolError::DiagnosticBundle(
                "Ed25519 verify_strict rejected unauthenticated bundle",
            )
        })?;

    let sk = <XWing as KemTrait>::PrivateKey::from_bytes(recipient_kem_secret)
        .map_err(|_| TrustPoolError::DiagnosticBundle("invalid recipient secret key"))?;
    let derived_pk = XWing::sk_to_pk(&sk).to_bytes();
    let expected_recipient_id = *blake3::hash(derived_pk.as_slice()).as_bytes();
    if !bool::from(recipient_id_arr.ct_eq(&expected_recipient_id)) {
        return Err(TrustPoolError::DiagnosticBundle(
            "recipient key fingerprint mismatch",
        ));
    }

    let enc = <XWing as KemTrait>::EncappedKey::from_bytes(&enc_raw)
        .map_err(|_| TrustPoolError::DiagnosticBundle("invalid X25519-MLKEM768 encapped key"))?;
    let mut receiver = hpke::setup_receiver::<HpkeChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk,
        &enc,
        &info,
    )
    .map_err(|_| TrustPoolError::DiagnosticBundle("HPKE receiver setup failed"))?;
    let compressed = Zeroizing::new(
        receiver
            .open(&ciphertext, &aad)
            .map_err(|_| TrustPoolError::DiagnosticBundle("HPKE AEAD open failed"))?,
    );

    let expected_len = bundle.plaintext_len as usize;
    let mut decoder = zstd::stream::read::Decoder::with_buffer(Cursor::new(compressed.as_slice()))
        .map_err(|_| TrustPoolError::DiagnosticBundle("zstd decoder init failed"))?
        .single_frame();
    let mut plain = Zeroizing::new(Vec::with_capacity(expected_len));
    decoder
        .by_ref()
        .take((expected_len + 1) as u64)
        .read_to_end(&mut plain)
        .map_err(|_| TrustPoolError::DiagnosticBundle("zstd decompression failed"))?;
    if plain.len() != expected_len || decoder.finish().position() != compressed.len() as u64 {
        return Err(TrustPoolError::DiagnosticBundle(
            "decompressed length mismatch or trailing frame bytes",
        ));
    }

    serde_json::from_slice(&plain)
        .map_err(|_| TrustPoolError::DiagnosticBundle("decrypted diagnostic JSON invalid"))
}
