// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Normative `BlindSlackBeatV1`, `OrgAdminPasskeyAttestationV1`, and `CoordinatorDispatchReceiptBodyV1`
//! types with `#[serde(deny_unknown_fields)]` at every object boundary and zero source/diff/secret fields.

use crate::ContractError;
use crate::mrkdwn::{is_forbidden_control_or_bidi, validate_safe_display_token};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use url::Url;

pub const MAX_SLACK_BEAT_BYTES: usize = 32_768;
pub const SCHEMA_VERSION_V1: u16 = 1;

/// Decimal-string wire representation of `u64` (`"0"` or `^[1-9][0-9]{0,19}$`).
/// Rejects raw JSON numbers, leading zeroes, whitespace, and overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalU64(u64);

impl CanonicalU64 {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn parse_decimal(raw: &str) -> Result<Self, ContractError> {
        if raw.is_empty() || raw.len() > 20 {
            return Err(ContractError::InvalidCanonicalU64);
        }
        if raw != "0" && raw.starts_with('0') {
            return Err(ContractError::InvalidCanonicalU64);
        }
        if !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ContractError::InvalidCanonicalU64);
        }
        let parsed = raw
            .parse::<u64>()
            .map_err(|_| ContractError::InvalidCanonicalU64)?;
        if parsed.to_string() != raw {
            return Err(ContractError::InvalidCanonicalU64);
        }
        Ok(Self(parsed))
    }
}

impl fmt::Display for CanonicalU64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for CanonicalU64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalU64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse_decimal(&s).map_err(serde::de::Error::custom)
    }
}

fn validate_opaque_ascii_id(
    raw: &str,
    max_len: usize,
    field: &'static str,
) -> Result<(), ContractError> {
    if raw.is_empty() || raw.len() > max_len {
        return Err(ContractError::InvalidField(field));
    }
    if raw.starts_with('.') || raw.ends_with('.') || raw.contains("..") {
        return Err(ContractError::InvalidField(field));
    }
    if raw.contains('/') || raw.contains('\\') || raw.contains("${") {
        return Err(ContractError::InvalidField(field));
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
    {
        return Err(ContractError::InvalidField(field));
    }
    validate_safe_display_token(raw, max_len)
}

macro_rules! define_opaque_id {
    ($name:ident, $max_len:expr, $field:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn parse(raw: impl Into<String>) -> Result<Self, ContractError> {
                let s = raw.into();
                validate_opaque_ascii_id(&s, $max_len, $field)?;
                Ok(Self(s))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::parse(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_opaque_id!(EventId, 96, "event_id");
define_opaque_id!(OpaqueOrgId, 64, "org_id");
define_opaque_id!(OpaqueOperationId, 96, "operation_id");
define_opaque_id!(OpaqueRef, 96, "opaque_ref");
define_opaque_id!(AuthorizationRef, 96, "authorization_ref");

/// `blake3:<64-lowercase-hex>` 32-byte digest.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse_prefixed(raw: &str) -> Result<Self, ContractError> {
        let hex_part = raw
            .strip_prefix("blake3:")
            .ok_or(ContractError::InvalidDigest)?;
        if hex_part.len() != 64
            || !hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ContractError::InvalidDigest);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_part, &mut out).map_err(|_| ContractError::InvalidDigest)?;
        Ok(Self(out))
    }

    #[must_use]
    pub fn to_prefixed_string(&self) -> String {
        format!("blake3:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32({})", self.to_prefixed_string())
    }
}

impl Serialize for Digest32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_prefixed_string())
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse_prefixed(&s).map_err(serde::de::Error::custom)
    }
}

/// `ed25519:<64-lowercase-hex>` 32-byte Ed25519 verifying key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyFingerprint([u8; 32]);

impl KeyFingerprint {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse_prefixed(raw: &str) -> Result<Self, ContractError> {
        let hex_part = raw
            .strip_prefix("ed25519:")
            .ok_or(ContractError::InvalidPublicKey)?;
        if hex_part.len() != 64
            || !hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ContractError::InvalidPublicKey);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_part, &mut out).map_err(|_| ContractError::InvalidPublicKey)?;
        Ok(Self(out))
    }

    #[must_use]
    pub fn to_prefixed_string(&self) -> String {
        format!("ed25519:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyFingerprint({})", self.to_prefixed_string())
    }
}

impl Serialize for KeyFingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_prefixed_string())
    }
}

impl<'de> Deserialize<'de> for KeyFingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse_prefixed(&s).map_err(serde::de::Error::custom)
    }
}

/// `ed25519:<128-lowercase-hex>` 64-byte Ed25519 detached signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature64([u8; 64]);

impl Signature64 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn parse_prefixed(raw: &str) -> Result<Self, ContractError> {
        let hex_part = raw
            .strip_prefix("ed25519:")
            .ok_or(ContractError::InvalidSignature)?;
        if hex_part.len() != 128
            || !hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ContractError::InvalidSignature);
        }
        let mut out = [0u8; 64];
        hex::decode_to_slice(hex_part, &mut out).map_err(|_| ContractError::InvalidSignature)?;
        Ok(Self(out))
    }

    #[must_use]
    pub fn to_prefixed_string(&self) -> String {
        format!("ed25519:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Signature64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature64(ed25519:{}...)", hex::encode(&self.0[..8]))
    }
}

impl Serialize for Signature64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_prefixed_string())
    }
}

impl<'de> Deserialize<'de> for Signature64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse_prefixed(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated HTTPS URL with zero embedded credentials and zero fragments unless explicitly local-open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedHttpsUrl(String);

impl ApprovedHttpsUrl {
    pub fn parse(raw: impl Into<String>) -> Result<Self, ContractError> {
        let s = raw.into();
        if s.len() > 512 || s.chars().any(is_forbidden_control_or_bidi) || s.contains("${") {
            return Err(ContractError::InvalidUrl);
        }
        let parsed = Url::parse(&s).map_err(|_| ContractError::InvalidUrl)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.host_str().is_none()
        {
            return Err(ContractError::InvalidUrl);
        }
        Ok(Self(s))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn host(&self) -> Option<String> {
        Url::parse(&self.0)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
    }
}

impl Serialize for ApprovedHttpsUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ApprovedHttpsUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(s).map_err(serde::de::Error::custom)
    }
}

fn deserialize_disallow_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiProviderV1 {
    GithubActions,
    GitlabCi,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BeatSourceV1 {
    Ci {
        provider: CiProviderV1,
        runner_lease_ref: OpaqueRef,
        run_ref: OpaqueRef,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_disallow_null"
        )]
        shard_ref: Option<OpaqueRef>,
    },
    Daemon {
        device_ref: OpaqueRef,
        session_ref: OpaqueRef,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiRemediationStepV1 {
    Pushing,
    Verifying,
    Building,
    Failed,
    Packaging,
    Routing,
    Waking,
    Fixing,
    PushingCandidate,
    VerifyingCandidate,
    BuildingCandidate,
    Passed,
}

impl CiRemediationStepV1 {
    #[must_use]
    pub const fn step_number(self) -> u8 {
        match self {
            Self::Pushing => 1,
            Self::Verifying => 2,
            Self::Building => 3,
            Self::Failed => 4,
            Self::Packaging => 5,
            Self::Routing => 6,
            Self::Waking => 7,
            Self::Fixing => 8,
            Self::PushingCandidate => 9,
            Self::VerifyingCandidate => 10,
            Self::BuildingCandidate => 11,
            Self::Passed => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairSessionStepV1 {
    Leasing,
    Drafting,
    Packaging,
    Routing,
    Auditing,
    Sealing,
    Returning,
    Waking,
    Fixing,
    Signing,
    Verifying,
    Passed,
}

impl PairSessionStepV1 {
    #[must_use]
    pub const fn step_number(self) -> u8 {
        match self {
            Self::Leasing => 1,
            Self::Drafting => 2,
            Self::Packaging => 3,
            Self::Routing => 4,
            Self::Auditing => 5,
            Self::Sealing => 6,
            Self::Returning => 7,
            Self::Waking => 8,
            Self::Fixing => 9,
            Self::Signing => 10,
            Self::Verifying => 11,
            Self::Passed => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHoldStepV1 {
    Pushing,
    Verifying,
    Checking,
    Held,
    Packaging,
    Routing,
    Waking,
    Fixing,
    Signing,
    PushingCandidate,
    VerifyingCandidate,
    Passed,
}

impl PolicyHoldStepV1 {
    #[must_use]
    pub const fn step_number(self) -> u8 {
        match self {
            Self::Pushing => 1,
            Self::Verifying => 2,
            Self::Checking => 3,
            Self::Held => 4,
            Self::Packaging => 5,
            Self::Routing => 6,
            Self::Waking => 7,
            Self::Fixing => 8,
            Self::Signing => 9,
            Self::PushingCandidate => 10,
            Self::VerifyingCandidate => 11,
            Self::Passed => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStepV1 {
    Moving,
    Scoping,
    Splitting,
    Claiming,
    FanOut,
    Gating,
    SnapBack,
    Waking,
    Patching,
    ReGating,
    Merging,
    Shipped,
}

impl DeliveryStepV1 {
    #[must_use]
    pub const fn step_number(self) -> u8 {
        match self {
            Self::Moving => 1,
            Self::Scoping => 2,
            Self::Splitting => 3,
            Self::Claiming => 4,
            Self::FanOut => 5,
            Self::Gating => 6,
            Self::SnapBack => 7,
            Self::Waking => 8,
            Self::Patching => 9,
            Self::ReGating => 10,
            Self::Merging => 11,
            Self::Shipped => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scene", rename_all = "snake_case", deny_unknown_fields)]
pub enum SceneProgressV1 {
    CiRemediation { step: CiRemediationStepV1 },
    PairSession { step: PairSessionStepV1 },
    PolicyHold { step: PolicyHoldStepV1 },
    Delivery { step: DeliveryStepV1 },
}

impl SceneProgressV1 {
    #[must_use]
    pub const fn step_number(self) -> u8 {
        match self {
            Self::CiRemediation { step } => step.step_number(),
            Self::PairSession { step } => step.step_number(),
            Self::PolicyHold { step } => step.step_number(),
            Self::Delivery { step } => step.step_number(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HpkeSuiteV1 {
    #[serde(rename = "X25519-MLKEM768-HKDF-SHA256-ChaCha20Poly1305")]
    X25519MlKem768HkdfSha256ChaCha20Poly1305,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindEvidenceV1 {
    pub cwcard_digest: Digest32,
    pub hpke_suite: HpkeSuiteV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub sealed_locator_ref: Option<OpaqueRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub policy_gate_id: Option<OpaqueRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub tombstone_id: Option<OpaqueRef>,
    pub ed25519_attestation_count: u8,
    pub plaintext_source_bytes: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatusV1 {
    Active,
    QueuedLaptopAsleep,
    PolicyHoldFailClosed,
    TerminalGreen,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindSummaryV1 {
    pub queue_status: QueueStatusV1,
    pub specs_passed: u32,
    pub specs_total: u32,
    pub gates_passed: u8,
    pub gates_total: u8,
    pub loc_added: u32,
    pub loc_removed: u32,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub command_exit_code: Option<i32>,
    pub duration_ms: CanonicalU64,
    pub est_minutes_saved: u32,
    pub credits_charged: CanonicalU64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub credit_receipt_ref: Option<OpaqueRef>,
}

/// Safe bounded symbolic metadata permitted ONLY under a verified `OrgAdminPasskeyAttestationV1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedSymbolsV1 {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub repo_label: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub branch_label: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub symbol_label: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub pr_number: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub approved_pr_url: Option<ApprovedHttpsUrl>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub short_revision: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_disallow_null"
    )]
    pub gate_display_name: Option<String>,
}

impl ApprovedSymbolsV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if let Some(repo) = &self.repo_label {
            validate_safe_display_token(repo, 64)?;
            if repo.contains("..") || repo.starts_with('/') {
                return Err(ContractError::InvalidField("repo_label"));
            }
        }
        if let Some(branch) = &self.branch_label {
            validate_safe_display_token(branch, 64)?;
            if branch.contains("..") {
                return Err(ContractError::InvalidField("branch_label"));
            }
        }
        if let Some(sym) = &self.symbol_label {
            validate_safe_display_token(sym, 64)?;
            if sym.contains('/') || sym.contains('\\') || sym.contains("..") {
                return Err(ContractError::InvalidField("symbol_label"));
            }
        }
        if let Some(pr) = self.pr_number
            && pr == 0
        {
            return Err(ContractError::InvalidField("pr_number"));
        }
        if let Some(rev) = &self.short_revision
            && (rev.len() < 7 || rev.len() > 40 || !rev.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ContractError::InvalidField("short_revision"));
        }
        if let Some(gate_name) = &self.gate_display_name {
            validate_safe_display_token(gate_name, 64)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPasskeyAttestationV1 {
    pub schema_version: u16,
    pub org_id: OpaqueOrgId,
    pub disclosure_grant_ref: OpaqueRef,
    pub config_digest: Digest32,
    pub webauthn_credential_id: OpaqueRef,
    pub authorization_epoch: CanonicalU64,
    pub expires_at_ms: CanonicalU64,
    pub admin_k1_pubkey: KeyFingerprint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgAdminPasskeyAttestationV1 {
    pub grant: UnsignedPasskeyAttestationV1,
    pub admin_k1_signature: Signature64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SlackMetadataV1 {
    StrictZk {
        summary: BlindSummaryV1,
    },
    RichSymbols {
        summary: BlindSummaryV1,
        symbols: Box<ApprovedSymbolsV1>,
        passkey_attestation: Box<OrgAdminPasskeyAttestationV1>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindSlackBeatV1 {
    pub schema_version: u16,
    pub event_id: EventId,
    pub org_id: OpaqueOrgId,
    pub operation_id: OpaqueOperationId,
    pub source: BeatSourceV1,
    pub source_sequence: CanonicalU64,
    pub attempt: u32,
    pub occurred_at_ms: CanonicalU64,
    pub progress: SceneProgressV1,
    pub evidence: BlindEvidenceV1,
    pub metadata: SlackMetadataV1,
    pub authorization_ref: AuthorizationRef,
    pub k1_key_id: KeyFingerprint,
}

impl BlindSlackBeatV1 {
    pub fn validate_semantics(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION_V1 {
            return Err(ContractError::UnsupportedSchemaVersion(self.schema_version));
        }
        if self.attempt == 0 {
            return Err(ContractError::InvalidField("attempt"));
        }
        if self.evidence.plaintext_source_bytes != 0 {
            return Err(ContractError::NonZeroPlaintextBytes);
        }
        if self.evidence.ed25519_attestation_count == 0
            || self.evidence.ed25519_attestation_count > 4
        {
            return Err(ContractError::InvalidField("ed25519_attestation_count"));
        }

        let summary = match &self.metadata {
            SlackMetadataV1::StrictZk { summary } => summary,
            SlackMetadataV1::RichSymbols {
                summary,
                symbols,
                passkey_attestation,
            } => {
                symbols.validate()?;
                if passkey_attestation.grant.schema_version != SCHEMA_VERSION_V1 {
                    return Err(ContractError::UnsupportedSchemaVersion(
                        passkey_attestation.grant.schema_version,
                    ));
                }
                if passkey_attestation.grant.org_id != self.org_id {
                    return Err(ContractError::PasskeyGrantOrgMismatch);
                }
                if passkey_attestation.grant.expires_at_ms.get() <= self.occurred_at_ms.get() {
                    return Err(ContractError::PasskeyGrantExpired);
                }
                summary
            }
        };

        if summary.specs_passed > summary.specs_total || summary.gates_passed > summary.gates_total
        {
            return Err(ContractError::InvalidField("summary_counts"));
        }
        if matches!(summary.queue_status, QueueStatusV1::QueuedLaptopAsleep)
            && summary.credits_charged.get() != 0
        {
            return Err(ContractError::NonZeroCreditsDuringLaptopSleep);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBlindSlackBeatV1 {
    pub beat: BlindSlackBeatV1,
    pub k1_signature: Signature64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerActionV1 {
    Quote,
    Reserve,
    LaptopSleepHold,
    Commit,
    Void,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorDispatchReceiptBodyV1 {
    pub schema_version: u16,
    pub dispatch_id: OpaqueRef,
    pub beat_digest: Digest32,
    pub org_id: OpaqueOrgId,
    pub event_id: EventId,
    pub coordinator_sequence: CanonicalU64,
    pub ledger_receipt_ref: OpaqueRef,
    pub ledger_action: LedgerActionV1,
    pub credits_charged: CanonicalU64,
    pub remaining_credits: CanonicalU64,
    pub authorization_epoch: CanonicalU64,
    pub destination_binding_ref: OpaqueRef,
    pub dispatch_audience: ApprovedHttpsUrl,
    pub dispatched_at_ms: CanonicalU64,
    pub k2_key_id: KeyFingerprint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSlackDispatchEnvelopeV1 {
    pub signed_beat: SignedBlindSlackBeatV1,
    pub receipt: CoordinatorDispatchReceiptBodyV1,
    pub k2_signature: Signature64,
}
