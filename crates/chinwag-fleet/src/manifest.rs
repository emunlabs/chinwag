// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Versioned policy manifests with canonical digest and optional Ed25519 pinning.
#![forbid(unsafe_code)]

use crate::{
    CredentialIsolation, DriverSpec, ExecutionTarget, FleetPolicyError, FleetResult, IsolationSpec,
    KeyBijectionValidator, NodeDescriptor, SkillConfig, SkillPolicyRef,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SeatId(String);

impl SeatId {
    pub fn new(value: &str) -> FleetResult<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(FleetPolicyError::InvalidManifest(format!(
                "invalid seat identifier: {value}"
            )));
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for SeatId {
    type Error = FleetPolicyError;
    fn try_from(value: String) -> FleetResult<Self> {
        Self::new(&value)
    }
}
impl From<SeatId> for String {
    fn from(value: SeatId) -> Self {
        value.0
    }
}
impl fmt::Display for SeatId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub nodes: Vec<NodeDescriptor>,
    #[serde(default)]
    pub seats: Vec<SeatDefinition>,
    #[serde(default)]
    pub policy: OrgFleetPolicy,
    #[serde(default)]
    pub skills: SkillConfig,
    #[serde(default)]
    pub pubkey_map: BTreeMap<SeatId, String>,
    #[serde(default)]
    pub allowed_signers: BTreeMap<SeatId, String>,
    #[serde(default)]
    pub private_key_paths: BTreeMap<SeatId, PathBuf>,
    #[serde(default)]
    pub pin: Option<ManifestPin>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
    #[serde(default)]
    pub task_profiles: BTreeMap<String, TaskProfile>,
    /// Runtime origin is excluded from the signed policy representation.
    #[serde(skip)]
    pub source_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPin {
    pub digest_sha256: String,
    #[serde(default)]
    pub signer_public_key: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatDefinition {
    pub id: SeatId,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub lifecycle: SeatLifecycle,
    #[serde(default)]
    pub target_selector: ExecutionTarget,
    pub driver: DriverSpec,
    pub model: ModelBinding,
    #[serde(default)]
    pub write_mode: WriteMode,
    #[serde(default)]
    pub isolation: IsolationSpec,
    #[serde(default)]
    pub allowed_write_roots: Vec<String>,
    #[serde(default)]
    pub allowed_rooms: Option<Vec<RoomPattern>>,
    #[serde(default)]
    pub skills: SkillPolicyRef,
    #[serde(default)]
    pub boot_files: Vec<PathTemplate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SeatLifecycle {
    #[default]
    ActiveStanding,
    EphemeralPool {
        min_idle: u32,
        max_concurrency: u32,
    },
    Paused,
    Retired,
}
impl SeatLifecycle {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::ActiveStanding | Self::EphemeralPool { .. })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBinding {
    pub provider: String,
    pub model_id: String,
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
    #[serde(default)]
    pub failover_policy: Option<FailoverPolicy>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverPolicy {
    #[default]
    Forbid,
    ExplicitOnly,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode {
    #[default]
    ReadOnly,
    Isolated,
}
pub type RoomPattern = String;
pub type PathTemplate = String;

/// A named request scope; profiles cannot replace the seat's model or driver.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskProfile {
    #[serde(default)]
    pub requested_skills: Vec<String>,
    #[serde(default)]
    pub requested_write_globs: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgFleetPolicy {
    #[serde(default)]
    pub failover_policy: FailoverPolicy,
    #[serde(default)]
    pub allow_seat_failover_override: bool,
    #[serde(default)]
    pub deny_providers: Vec<String>,
    #[serde(default)]
    pub egress_policy: EgressPolicy,
    #[serde(default)]
    pub room_acls: BTreeMap<RoomPattern, Vec<SeatId>>,
    #[serde(default)]
    pub repo_holds: Vec<RepoHoldRule>,
    #[serde(default)]
    pub release_signers: Vec<String>,
    /// Exact qualified actors authorized to sign consumer/operator bindings.
    #[serde(default)]
    pub operator_signers: Vec<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EgressPolicy {
    #[default]
    Unrestricted,
    DenyAll,
    AllowList {
        endpoints: Vec<String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoHoldRule {
    pub repo_pattern: String,
    #[serde(default = "yes")]
    pub active: bool,
    #[serde(default)]
    pub reason: String,
}
fn yes() -> bool {
    true
}

impl FleetManifest {
    pub fn discover_path(explicit: Option<&Path>, cwd: &Path) -> PathBuf {
        explicit
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("CHINWAG_FLEET_MANIFEST").map(PathBuf::from))
            .unwrap_or_else(|| cwd.join(".chinwag/fleet.toml"))
    }
    pub fn load(path: &Path) -> FleetResult<Self> {
        let bytes = std::fs::read(path)?;
        let mut manifest: Self = if path.extension().is_some_and(|x| x == "json") {
            serde_json::from_slice(&bytes)
                .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?
        } else {
            toml::from_str(
                std::str::from_utf8(&bytes)
                    .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?,
            )
            .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?
        };
        manifest.source_dir = Some(
            path.canonicalize()?
                .parent()
                .ok_or_else(|| FleetPolicyError::InvalidManifest("manifest has no parent".into()))?
                .to_path_buf(),
        );
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn from_toml(text: &str) -> FleetResult<Self> {
        let manifest: Self =
            toml::from_str(text).map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn from_json(bytes: &[u8]) -> FleetResult<Self> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn to_toml(&self) -> FleetResult<String> {
        toml::to_string_pretty(self).map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))
    }
    pub fn to_canonical_json(&self) -> FleetResult<Vec<u8>> {
        serde_jcs::to_vec(self).map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))
    }
    pub fn digest(&self) -> FleetResult<String> {
        let mut unsigned = self.clone();
        unsigned.pin = None;
        Ok(chinwag_claim::encode_hex(&chinwag_claim::sha256(
            &unsigned.to_canonical_json()?,
        )))
    }
    pub fn seat(&self, id: &str) -> Option<&SeatDefinition> {
        self.seats.iter().find(|s| s.id.as_str() == id)
    }
    pub fn resolve_path(&self, path: &Path, cwd: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.source_dir.as_deref().unwrap_or(cwd).join(path)
        }
    }
    pub fn validate(&self) -> FleetResult<()> {
        if self.schema_version != 1 {
            return Err(FleetPolicyError::InvalidManifest(
                "schema_version must equal 1".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for seat in &self.seats {
            SeatId::new(seat.id.as_str())?;
            if !ids.insert(&seat.id) {
                return Err(FleetPolicyError::InvalidManifest(format!(
                    "duplicate seat {}",
                    seat.id
                )));
            }
            if seat.model.provider.is_empty() || seat.model.model_id.is_empty() {
                return Err(FleetPolicyError::InvalidManifest(format!(
                    "seat {} lacks provider/model",
                    seat.id
                )));
            }
            if let SeatLifecycle::EphemeralPool {
                min_idle,
                max_concurrency,
            } = seat.lifecycle
                && (max_concurrency == 0 || min_idle > max_concurrency)
            {
                return Err(FleetPolicyError::InvalidManifest(
                    "invalid ephemeral pool capacity".into(),
                ));
            }
            if let Some(failover) = seat.model.failover_policy
                && failover != self.policy.failover_policy
                && !self.policy.allow_seat_failover_override
            {
                return Err(FleetPolicyError::InvalidManifest(
                    "seat failover override is forbidden".into(),
                ));
            }
            for root in &seat.allowed_write_roots {
                crate::isolation::validate_write_pattern(root)?;
            }
            if seat.write_mode == WriteMode::ReadOnly && !seat.allowed_write_roots.is_empty() {
                return Err(FleetPolicyError::InvalidManifest(
                    "read-only seat cannot declare write roots".into(),
                ));
            }
            if seat.write_mode == WriteMode::ReadOnly && seat.isolation != IsolationSpec::ReadOnly {
                return Err(FleetPolicyError::InvalidManifest(
                    "read-only seats require read-only isolation".into(),
                ));
            }
            if seat
                .boot_files
                .iter()
                .any(|p| p.contains(['\0', '\n']) || p.contains("..") || Path::new(p).is_absolute())
            {
                return Err(FleetPolicyError::InvalidManifest(
                    "boot files must be workspace relative".into(),
                ));
            }
            if let Some(profile_dir) = &seat.profile_dir {
                let raw = profile_dir.to_string_lossy();
                if profile_dir.as_os_str().is_empty()
                    || raw.contains(['\0', '\n'])
                    || profile_dir
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(FleetPolicyError::InvalidManifest(
                        "invalid seat profile_dir".into(),
                    ));
                }
            }
            match &seat.driver {
                DriverSpec::OpenAiCompatibleHttp {
                    stream_mode,
                    transport,
                    ..
                } => {
                    crate::http_driver::OpenAiStreamMode::parse(stream_mode)?;
                    crate::http_driver::validate_transport_policy(transport.as_ref())?;
                }
                DriverSpec::GoogleGenAiHttp { transport, .. }
                | DriverSpec::AnthropicMessagesHttp { transport, .. } => {
                    crate::http_driver::validate_transport_policy(transport.as_ref())?;
                }
                DriverSpec::CliSubprocess { .. } => {}
            }
        }
        let mut nodes = BTreeSet::new();
        for node in &self.nodes {
            if node.node_id.is_empty() || !nodes.insert(&node.node_id) {
                return Err(FleetPolicyError::InvalidManifest(
                    "duplicate or empty node id".into(),
                ));
            }
        }
        for seats in self.policy.room_acls.values() {
            for seat in seats {
                if !ids.contains(seat) {
                    return Err(FleetPolicyError::UnknownSeat(seat.to_string()));
                }
            }
        }
        for actor in &self.policy.operator_signers {
            let (seat, _) = actor
                .split_once('#')
                .ok_or_else(|| FleetPolicyError::BareSeatAddressRejected(actor.clone()))?;
            let seat = self
                .seat(seat)
                .ok_or_else(|| FleetPolicyError::UnknownSeat(seat.into()))?;
            crate::validate_actor(&seat.id, actor)?;
        }
        for (name, profile) in &self.task_profiles {
            SeatId::new(name)?;
            for root in &profile.requested_write_globs {
                crate::isolation::validate_write_pattern(root)?;
            }
        }
        KeyBijectionValidator::validate(self, false)?;
        if let Some(pin) = &self.pin {
            let digest = self.digest()?;
            if digest != pin.digest_sha256 {
                return Err(FleetPolicyError::InvalidManifest(
                    "manifest digest pin mismatch".into(),
                ));
            }
            match (&pin.signer_public_key, &pin.signature) {
                (None, None) => {}
                (Some(key), Some(signature)) => {
                    let key = chinwag_claim::decode_hex_exact::<32>(key)
                        .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?;
                    let sig = chinwag_claim::decode_hex_exact::<64>(signature)
                        .map_err(|e| FleetPolicyError::InvalidManifest(e.to_string()))?;
                    VerifyingKey::from_bytes(&key)
                        .and_then(|key| {
                            key.verify_strict(digest.as_bytes(), &Signature::from_bytes(&sig))
                        })
                        .map_err(|e| {
                            FleetPolicyError::InvalidManifest(format!("manifest signature: {e}"))
                        })?;
                }
                _ => {
                    return Err(FleetPolicyError::InvalidManifest(
                        "signature and signer must both be supplied".into(),
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn starter_profile(profile: &str) -> FleetResult<Self> {
        if !["solo", "mesh", "airgapped", "cloud-pool"].contains(&profile) {
            return Err(FleetPolicyError::InvalidManifest(format!(
                "unknown profile {profile}"
            )));
        }
        let mut manifest = Self {
            schema_version: 1,
            nodes: Vec::new(),
            seats: Vec::new(),
            policy: OrgFleetPolicy::default(),
            skills: SkillConfig::default(),
            pubkey_map: BTreeMap::new(),
            allowed_signers: BTreeMap::new(),
            private_key_paths: BTreeMap::new(),
            pin: None,
            extensions: BTreeMap::new(),
            task_profiles: BTreeMap::new(),
            source_dir: None,
        };
        if profile == "airgapped" {
            manifest.policy.egress_policy = EgressPolicy::DenyAll;
        }
        let target_selector = match profile {
            "mesh" => ExecutionTarget::MeshPeerSelector {
                required_labels: BTreeMap::from([("pool".into(), "default".into())]),
                preferred_labels: BTreeMap::new(),
            },
            "cloud-pool" => ExecutionTarget::CloudSandbox {
                provider: "configure-provider".into(),
                region_or_pool: "configure-pool".into(),
                profile: "configure-profile".into(),
            },
            _ => ExecutionTarget::LocalProcess,
        };
        manifest.seats.push(SeatDefinition {
            id: SeatId::new("default")?,
            display_name: None,
            lifecycle: SeatLifecycle::Paused,
            target_selector,
            driver: DriverSpec::CliSubprocess {
                executable: "configure-driver".into(),
                argv_template: vec![],
                auth_isolation: CredentialIsolation::NoneLocal,
                env_allowlist: vec![],
                env_overrides: BTreeMap::new(),
                framing: "stdin".into(),
                timeout_secs: 300,
            },
            model: ModelBinding {
                provider: "configure-provider".into(),
                model_id: "configure-model".into(),
                params: BTreeMap::new(),
                failover_policy: None,
            },
            write_mode: WriteMode::ReadOnly,
            isolation: IsolationSpec::ReadOnly,
            allowed_write_roots: vec![],
            allowed_rooms: None,
            skills: SkillPolicyRef::default(),
            boot_files: vec![],
            profile_dir: None,
        });
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Patterns use exact matches or one trailing `*`, never shell expansion.
pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == value, |prefix| value.starts_with(prefix))
}
