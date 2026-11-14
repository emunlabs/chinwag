// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Two-Tier Cleanroom Runner Trust Gate (`chinwag-ephemeral-public` vs
//! `chinwag-ephemeral-release` · `INV-CLEANROOM-TRUST-SPLIT-01`), AC/Thermal
//! Multi-Mac Pool Admission, and Hybrid Post-Quantum HPKE (`X25519-MLKEM768`)
//! Failure Diagnostic Bundle Sealing (`Hook H4`).

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
use std::io::{Cursor, Read};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Apple `Virtualization.framework` & macOS EULA limit per physical Apple Silicon host.
pub const MAX_VMS_PER_MAC_HOST: u8 = 2;

/// Maximum latency budget (ms) to drain opportunistic laptop runner slots upon user input / AC unplug.
pub const MAX_DRAIN_BUDGET_MS: u64 = 500;

/// Default minimum host CPU idle percentage required for opportunistic laptop admission.
pub const DEFAULT_MIN_CPU_IDLE_PERCENT: u8 = 70;

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

/// Evaluates the 2-tier cleanroom trust split (`INV-CLEANROOM-TRUST-SPLIT-01`).
/// Untrusted fork PRs or unverified branches NEVER gain access to `chinwag-ephemeral-release`
/// or host signing/deployment secrets.
pub fn evaluate_trust_gate(
    ctx: &JobTriggerContext,
    host_env: &BTreeMap<String, String>,
    pinned_release_signers: &[[u8; 32]],
) -> Result<RunnerTrustDecision, TrustPoolError> {
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
            if !is_protected_release_ref(&ctx.git_ref) {
                return Err(TrustPoolError::ReleaseRefused(
                    "git ref is not `refs/heads/main` or a protected `refs/tags/v*` release tag",
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
                sanitized_env: filter_release_runner_env(host_env),
            })
        }
    }
}

fn is_protected_release_ref(git_ref: &str) -> bool {
    if git_ref == "refs/heads/main" {
        return true;
    }
    if let Some(tag) = git_ref.strip_prefix("refs/tags/v") {
        return !tag.is_empty()
            && !tag.contains("..")
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
    }
    false
}

fn is_valid_git_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("PASSWORD")
        || upper.contains("PRIVATE")
        || upper.ends_with("_KEY")
        || upper.starts_with("APPLE_")
        || upper.starts_with("NOTARY_")
        || upper.starts_with("AWS_")
        || upper.starts_with("CLOUDFLARE_")
        || upper.starts_with("SIGNING_")
        || upper == "GITHUB_TOKEN"
        || upper == "GH_TOKEN"
}

fn scrub_public_runner_env(host_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let safe_allowlist = [
        "CI",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "RUSTUP_TOOLCHAIN",
        "SCCACHE_DIR",
        "SCCACHE_RECACHE",
        "TERM",
        "TMPDIR",
    ];
    let mut out = BTreeMap::new();
    for (k, v) in host_env {
        if safe_allowlist.contains(&k.as_str()) && !is_sensitive_env_key(k) {
            out.insert(k.clone(), v.clone());
        }
    }
    out.insert("CHINWAG_CLEANROOM_TIER".to_owned(), "public".to_owned());
    out.insert("SCCACHE_READ_ONLY".to_owned(), "1".to_owned());
    out
}

fn filter_release_runner_env(host_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = scrub_public_runner_env(host_env);
    out.insert("CHINWAG_CLEANROOM_TIER".to_owned(), "release".to_owned());
    for scoped_key in [
        "APPLE_DEVELOPER_ID_LEASE",
        "NOTARYTOOL_PROFILE_LEASE",
        "RELEASE_UPLOAD_LEASE",
    ] {
        if let Some(val) = host_env.get(scoped_key) {
            out.insert(scoped_key.to_owned(), val.clone());
        }
    }
    out
}

// ============================================================================
// Multi-Mac Pool Policy & Hardware Admission (AC Power & Thermal Pressure)
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

/// Scrubs bearer tokens, GitHub PATs, OpenAI/Anthropic/AWS keys, and PEM private keys
/// from failure logs BEFORE zstd compression and HPKE sealing (`Hook H4`).
pub fn scrub_diagnostic_secrets(raw: &str) -> String {
    let mut scrubbed = String::with_capacity(raw.len());
    let mut in_pem = false;
    for line in raw.lines() {
        if line.contains("BEGIN ") && line.contains("PRIVATE KEY") {
            in_pem = true;
            scrubbed.push_str("[REDACTED_PRIVATE_KEY_BLOCK]\n");
            continue;
        }
        if in_pem {
            if line.contains("END ") && line.contains("PRIVATE KEY") {
                in_pem = false;
            }
            continue;
        }
        let tokens: Vec<String> = line
            .split(' ')
            .map(|word| {
                let trimmed = word.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';'));
                if trimmed.starts_with("ghp_")
                    || trimmed.starts_with("ghs_")
                    || trimmed.starts_with("github_pat_")
                    || trimmed.starts_with("sk-")
                    || trimmed.starts_with("AKIA")
                    || trimmed.starts_with("xoxb-")
                {
                    "[REDACTED_TOKEN]".to_owned()
                } else if let Some((lhs, _)) = word.split_once('=')
                    && is_sensitive_env_key(lhs.trim())
                {
                    format!("{}=[REDACTED]", lhs.trim())
                } else {
                    word.to_owned()
                }
            })
            .collect();
        let mut joined = tokens.join(" ");
        if let Some(idx) = joined.to_ascii_lowercase().find("bearer ") {
            let prefix = &joined[..idx + 7];
            let rest = &joined[idx + 7..];
            let after = rest
                .find(char::is_whitespace)
                .map_or("", |end| &rest[end..]);
            joined = format!("{prefix}[REDACTED_BEARER]{after}");
        }
        scrubbed.push_str(&joined);
        scrubbed.push('\n');
    }
    if !raw.ends_with('\n') && scrubbed.ends_with('\n') {
        scrubbed.pop();
    }
    scrubbed
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
