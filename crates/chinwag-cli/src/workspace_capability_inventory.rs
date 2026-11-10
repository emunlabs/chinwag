#![forbid(unsafe_code)]

//! Continuously maintained JJ workspace-isolation and capability-provenance
//! inventory (`CHWG-JJ-WORKSPACE-REGISTRY-01`, Slice 1).
//!
//! Invariants enforced by this module:
//! - Every source-bound agent mutation requires an exclusive physical JJ
//!   workspace directory `(dev, ino)` and an exclusive mutable JJ working-copy
//!   change ID (`jj_working_copy_change_id`), distinct from the operational
//!   checkout while sharing the backing Git object store.
//! - Path aliases, symlinks, duplicate physical `(dev, ino)` claims, shared
//!   mutable JJ changes, bare/unresolved actors, and mismatched `TaskRefV1`
//!   bindings fail closed and place conflicting claims into a scoped hold.
//! - Capability records keep `Implemented`, `Tested`, `AcceptedSource`,
//!   `Installed`, `Operational`, `Authorized`, `Unknown`, and `Held` distinct;
//!   dirty/uncommitted builds or mismatched binary digests invalidate
//!   `AcceptedSource`/`Installed`/`Operational`/`Authorized` claims.
//! - Inventory observations are never execution or production authority.
//! - Updates use an append-only, fsync-checked intent/result journal with
//!   idempotent `(operation_id, intent_digest)` replay handling, crash-recovery
//!   holds for incomplete intents, and non-mutating discovery snapshots.

use crate::agent_instance::ActorAddress;
use crate::task_ref::{GitOid, Sha256Digest, TaskRefV1, validate_id};
use crate::task_store::StoredObservation;
use rustix::fs::{AtFlags, Mode, OFlags, openat, statat};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub const MAX_INVENTORY_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_INVENTORY_RECORDS: usize = 2048;
pub const MAX_SCOPE_PATHS: usize = 64;

mod git_oid_serde {
    use super::*;
    pub fn serialize<S: Serializer>(oid: &GitOid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&oid.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<GitOid, D::Error> {
        let raw = String::deserialize(deserializer)?;
        GitOid::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

mod opt_git_oid_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        oid: &Option<GitOid>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match oid {
            Some(v) => serializer.serialize_some(&v.to_string()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<GitOid>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|s| GitOid::from_hex(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

mod sha256_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        digest: &Sha256Digest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&digest.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Sha256Digest, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Sha256Digest::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

mod opt_sha256_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        digest: &Option<Sha256Digest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match digest {
            Some(v) => serializer.serialize_some(&v.to_string()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Sha256Digest>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|s| Sha256Digest::from_hex(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn decode_lower_hex(raw: &str) -> Result<Vec<u8>, &'static str> {
    if !raw.len().is_multiple_of(2) {
        return Err("odd hex length");
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks_exact(2) {
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err("invalid lowercase hex character"),
        };
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

mod task_ref_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        task_ref: &TaskRefV1,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = task_ref.encode().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&encode_lower_hex(&bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<TaskRefV1, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = decode_lower_hex(&raw).map_err(serde::de::Error::custom)?;
        TaskRefV1::decode(&bytes).map_err(serde::de::Error::custom)
    }
}

mod opt_task_ref_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        task_ref: &Option<TaskRefV1>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match task_ref {
            Some(v) => {
                let bytes = v.encode().map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&encode_lower_hex(&bytes))
            }
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<TaskRefV1>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|s| {
            let bytes = decode_lower_hex(&s).map_err(serde::de::Error::custom)?;
            TaskRefV1::decode(&bytes).map_err(serde::de::Error::custom)
        })
        .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    InvalidIdentifier(String),
    InvalidPath(String),
    SymlinkOrNonDirectory(String),
    UnownedOrWritableDirectory(String),
    OperationalCheckoutForbidden(String),
    SharedGitStoreMismatch(String),
    DuplicatePhysicalWorkspace(String),
    DuplicateWorkspaceName(String),
    SharedMutableJjChange(String),
    UnresolvedOrMismatchedOwner(String),
    WorkspaceIdentityDrift(String),
    WorkspaceHeld(String),
    UnprovenCapabilityClaim(String),
    DirtyOrMismatchedBuildProvenance(String),
    InventoryNotExecutionAuthority,
    ConflictingReplay(String),
    JournalCorruptOrBounded(String),
    Io(String),
}

impl std::fmt::Display for InventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "workspace/capability inventory refused: {self:?}")
    }
}

impl std::error::Error for InventoryError {}

pub type InventoryResult<T> = Result<T, InventoryError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsEntryIdentityV1 {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl FsEntryIdentityV1 {
    pub fn same_inode(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }
}

/// Walk an absolute canonical path component-by-component with `OFlags::NOFOLLOW`
/// and return its physical `(dev, ino, uid, gid, mode)` identity. Rejects any
/// symlink segment, relative path, `.` or `..` component, or non-directory leaf.
pub fn verify_private_directory_identity(
    path: &Path,
    require_private_mode: bool,
) -> InventoryResult<FsEntryIdentityV1> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(InventoryError::InvalidPath(
            "path must be non-empty and absolute".to_owned(),
        ));
    }
    let mut current = File::open("/").map_err(|e| InventoryError::Io(e.to_string()))?;
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                saw_normal = true;
                let st = statat(&current, part, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| InventoryError::Io(format!("{path:?}: {e}")))?;
                if (st.st_mode as u32) & 0o170000 != 0o040000 {
                    return Err(InventoryError::SymlinkOrNonDirectory(format!(
                        "{path:?} component {part:?} is not a real directory"
                    )));
                }
                current = File::from(
                    openat(
                        &current,
                        part,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|e| InventoryError::Io(format!("{path:?}: {e}")))?,
                );
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(InventoryError::InvalidPath(format!(
                    "non-canonical path component in {path:?}"
                )));
            }
        }
    }
    if !saw_normal {
        return Err(InventoryError::InvalidPath(
            "root directory '/' cannot be a workspace or store root".to_owned(),
        ));
    }
    let meta = current
        .metadata()
        .map_err(|e| InventoryError::Io(e.to_string()))?;
    let euid = rustix::process::geteuid().as_raw();
    let mode = meta.mode() & 0o7777;
    if meta.uid() != euid {
        return Err(InventoryError::UnownedOrWritableDirectory(format!(
            "directory {path:?} uid {} != euid {euid}",
            meta.uid()
        )));
    }
    if require_private_mode && (mode & 0o077 != 0) {
        return Err(InventoryError::UnownedOrWritableDirectory(format!(
            "directory {path:?} mode {mode:#o} must not grant group/other access"
        )));
    }
    if !require_private_mode && (mode & 0o022 != 0) {
        return Err(InventoryError::UnownedOrWritableDirectory(format!(
            "directory {path:?} mode {mode:#o} is group/world writable"
        )));
    }
    Ok(FsEntryIdentityV1 {
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOwnershipStatusV1 {
    Active,
    HeldConflict,
    HeldStaleOrUnknown,
    Released,
    Retired,
    Abandoned,
}

impl WorkspaceOwnershipStatusV1 {
    pub fn blocks_exclusive_claim(self) -> bool {
        matches!(
            self,
            Self::Active | Self::HeldConflict | Self::HeldStaleOrUnknown
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceOwnershipRecordV1 {
    pub record_id: String,
    pub repo_id: String,
    pub operational_checkout_path: String,
    pub operational_checkout_identity: FsEntryIdentityV1,
    pub shared_git_store_path: String,
    pub shared_git_store_identity: FsEntryIdentityV1,
    pub workspace_name: String,
    pub workspace_path: String,
    pub workspace_identity: FsEntryIdentityV1,
    pub jj_working_copy_change_id: String,
    #[serde(with = "git_oid_serde")]
    pub jj_working_copy_commit_id: GitOid,
    #[serde(with = "git_oid_serde")]
    pub base_commit_id: GitOid,
    #[serde(with = "git_oid_serde")]
    pub base_tree_id: GitOid,
    pub owner_actor: String,
    #[serde(with = "task_ref_serde")]
    pub task_ref: TaskRefV1,
    #[serde(with = "sha256_serde")]
    pub admission_digest: Sha256Digest,
    pub scope_paths: Vec<String>,
    pub review_branch: String,
    pub issued_unix_ms: u64,
    pub lease_expires_unix_ms: u64,
    pub pid_birth_binding: Option<(u32, u64)>,
    pub status: WorkspaceOwnershipStatusV1,
    pub hold_reason: Option<String>,
}

impl WorkspaceOwnershipRecordV1 {
    pub fn validate_structural(&self) -> InventoryResult<()> {
        validate_id(&self.record_id, "record_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.repo_id, "repo_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.workspace_name, "workspace_name")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.jj_working_copy_change_id, "jj_working_copy_change_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.review_branch, "review_branch")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        self.task_ref
            .validate()
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        if self.scope_paths.is_empty() || self.scope_paths.len() > MAX_SCOPE_PATHS {
            return Err(InventoryError::InvalidIdentifier(
                "scope_paths must contain 1..=64 relative paths".to_owned(),
            ));
        }
        for scope in &self.scope_paths {
            if scope.is_empty()
                || scope.starts_with('/')
                || scope.contains("..")
                || scope.contains('\0')
            {
                return Err(InventoryError::InvalidPath(format!(
                    "invalid relative scope path: {scope:?}"
                )));
            }
        }
        let parsed_actor = ActorAddress::parse(&self.owner_actor).map_err(|e| {
            InventoryError::UnresolvedOrMismatchedOwner(format!(
                "owner_actor {:?} failed ActorAddress validation: {e}",
                self.owner_actor
            ))
        })?;
        if parsed_actor.instance().is_none() {
            return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                "owner_actor {:?} must carry a complete conversation/worker instance ID",
                self.owner_actor
            )));
        }
        if self.lease_expires_unix_ms <= self.issued_unix_ms {
            return Err(InventoryError::InvalidIdentifier(
                "lease_expires_unix_ms must be strictly greater than issued_unix_ms".to_owned(),
            ));
        }
        if self.workspace_path == self.operational_checkout_path
            || self
                .workspace_identity
                .same_inode(&self.operational_checkout_identity)
        {
            return Err(InventoryError::OperationalCheckoutForbidden(format!(
                "workspace {:?} aliases operational checkout {:?}",
                self.workspace_path, self.operational_checkout_path
            )));
        }
        if self
            .workspace_identity
            .same_inode(&self.shared_git_store_identity)
        {
            return Err(InventoryError::InvalidPath(
                "workspace directory cannot be identical to the shared Git object store".to_owned(),
            ));
        }
        if self.jj_working_copy_commit_id == self.base_commit_id {
            return Err(InventoryError::SharedMutableJjChange(
                "working-copy commit ID must be a dedicated child commit, not the immutable base commit".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClassificationV1 {
    Implemented,
    Tested,
    AcceptedSource,
    Installed,
    Operational,
    Authorized,
    Unknown,
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProvenanceRecordV1 {
    pub capability_id: String,
    pub handler_symbol: String,
    pub source_module_path: String,
    pub claimed_classification: CapabilityClassificationV1,
    pub handler_wired: bool,
    pub unit_tests_passed: bool,
    #[serde(with = "git_oid_serde")]
    pub source_commit: GitOid,
    #[serde(with = "git_oid_serde")]
    pub source_tree: GitOid,
    pub source_tree_clean: bool,
    #[serde(with = "opt_git_oid_serde")]
    pub accepted_source_commit: Option<GitOid>,
    #[serde(with = "opt_sha256_serde")]
    pub compiled_artifact_sha256: Option<Sha256Digest>,
    pub installed_binary_path: Option<String>,
    #[serde(with = "opt_sha256_serde")]
    pub installed_binary_sha256: Option<Sha256Digest>,
    pub runtime_health_verified: bool,
    #[serde(with = "opt_sha256_serde")]
    pub admission_authority_digest: Option<Sha256Digest>,
    #[serde(with = "opt_task_ref_serde")]
    pub task_ref: Option<TaskRefV1>,
    pub observed_unix_ms: u64,
    pub effective_classification: CapabilityClassificationV1,
    pub hold_or_downgrade_reason: Option<String>,
}

impl CapabilityProvenanceRecordV1 {
    /// Evaluate and verify provenance so that `Implemented`, `Tested`,
    /// `AcceptedSource`, `Installed`, `Operational`, and `Authorized` are never
    /// conflated, and dirty/uncommitted builds or mismatched binaries fail
    /// closed.
    pub fn verify_and_classify(&mut self) -> InventoryResult<CapabilityClassificationV1> {
        validate_id(&self.capability_id, "capability_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.handler_symbol, "handler_symbol")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        if self.source_module_path.is_empty()
            || self.source_module_path.starts_with('/')
            || self.source_module_path.contains("..")
        {
            return Err(InventoryError::InvalidPath(format!(
                "invalid source_module_path {:?}",
                self.source_module_path
            )));
        }

        // Dirty source tree invalidates any claim above Tested.
        if !self.source_tree_clean
            && matches!(
                self.claimed_classification,
                CapabilityClassificationV1::AcceptedSource
                    | CapabilityClassificationV1::Installed
                    | CapabilityClassificationV1::Operational
                    | CapabilityClassificationV1::Authorized
            )
        {
            self.effective_classification = CapabilityClassificationV1::Held;
            let reason = format!(
                "capability {:?} claims {:?} on dirty/uncommitted source tree",
                self.capability_id, self.claimed_classification
            );
            self.hold_or_downgrade_reason = Some(reason.clone());
            return Err(InventoryError::DirtyOrMismatchedBuildProvenance(reason));
        }

        match self.claimed_classification {
            CapabilityClassificationV1::Unknown => {
                self.effective_classification = CapabilityClassificationV1::Unknown;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Held => {
                self.effective_classification = CapabilityClassificationV1::Held;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Implemented => {
                if !self.handler_wired {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    let reason = format!(
                        "capability {:?} claims Implemented without wired handler",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Implemented;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Tested => {
                if !self.handler_wired || !self.unit_tests_passed {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    let reason = format!(
                        "capability {:?} claims Tested without handler_wired && unit_tests_passed",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Tested;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::AcceptedSource => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    let reason = format!(
                        "capability {:?} claims AcceptedSource without matching accepted_source_commit",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::AcceptedSource;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Installed => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    let reason = format!(
                        "capability {:?} claims Installed without AcceptedSource provenance",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                match (
                    &self.compiled_artifact_sha256,
                    &self.installed_binary_sha256,
                    &self.installed_binary_path,
                ) {
                    (Some(compiled), Some(installed), Some(path))
                        if compiled == installed && path.starts_with('/') =>
                    {
                        self.effective_classification = CapabilityClassificationV1::Installed;
                        self.hold_or_downgrade_reason = None;
                        Ok(self.effective_classification)
                    }
                    _ => {
                        self.effective_classification = CapabilityClassificationV1::Held;
                        let reason = format!(
                            "capability {:?} claims Installed with missing or mismatched binary digest",
                            self.capability_id
                        );
                        self.hold_or_downgrade_reason = Some(reason.clone());
                        Err(InventoryError::DirtyOrMismatchedBuildProvenance(reason))
                    }
                }
            }
            CapabilityClassificationV1::Operational => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                    || !self.runtime_health_verified
                    || self.compiled_artifact_sha256.is_none()
                    || self.compiled_artifact_sha256 != self.installed_binary_sha256
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    let reason = format!(
                        "capability {:?} claims Operational without verified installed binary and runtime health",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Operational;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Authorized => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                    || !self.runtime_health_verified
                    || self.compiled_artifact_sha256.is_none()
                    || self.compiled_artifact_sha256 != self.installed_binary_sha256
                    || self.admission_authority_digest.is_none()
                    || self.task_ref.is_none()
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    let reason = format!(
                        "capability {:?} claims Authorized without full operational + admission + TaskRef provenance",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Authorized;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
        }
    }

    /// Inventory records are descriptive/supervisory and never grant production
    /// execution authority on their own.
    pub fn require_execution_authority(&self) -> InventoryResult<()> {
        Err(InventoryError::InventoryNotExecutionAuthority)
    }
}

/// Verify that a `StoredObservation` from `task_store` also refuses production
/// authority promotion through the inventory layer.
pub fn require_stored_observation_not_authority(
    observation: &StoredObservation,
) -> InventoryResult<()> {
    let _ = observation.require_production_authority();
    Err(InventoryError::InventoryNotExecutionAuthority)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum InventoryPayloadV1 {
    RegisterWorkspace {
        record: Box<WorkspaceOwnershipRecordV1>,
    },
    ReleaseWorkspace {
        record_id: String,
        actor: String,
        released_unix_ms: u64,
    },
    UpsertCapability {
        record: Box<CapabilityProvenanceRecordV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_kind", rename_all = "snake_case", deny_unknown_fields)]
enum JournalEntryV1 {
    Intent {
        operation_id: String,
        intent_digest: String,
        recorded_unix_ms: u64,
        payload: InventoryPayloadV1,
    },
    Result {
        operation_id: String,
        intent_digest: String,
        completed_unix_ms: u64,
        committed: bool,
        hold_reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySubmissionOutcomeV1 {
    Applied,
    IdempotentReplay,
    ConflictingReplayHeld,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySnapshotV1 {
    pub shared_git_store_identity: FsEntryIdentityV1,
    pub operational_checkout_identity: FsEntryIdentityV1,
    pub workspaces: Vec<WorkspaceOwnershipRecordV1>,
    pub capabilities: Vec<CapabilityProvenanceRecordV1>,
    pub incomplete_operations_held: Vec<String>,
}

pub struct ContinuousInventoryRegistryV1 {
    shared_git_store_identity: FsEntryIdentityV1,
    operational_checkout_identity: FsEntryIdentityV1,
    workspaces: BTreeMap<String, WorkspaceOwnershipRecordV1>,
    capabilities: BTreeMap<String, CapabilityProvenanceRecordV1>,
    committed_ops: BTreeMap<String, String>,
    incomplete_ops_held: BTreeMap<String, String>,
}

impl ContinuousInventoryRegistryV1 {
    pub fn new(
        shared_git_store_identity: FsEntryIdentityV1,
        operational_checkout_identity: FsEntryIdentityV1,
    ) -> InventoryResult<Self> {
        if shared_git_store_identity.same_inode(&operational_checkout_identity) {
            return Err(InventoryError::InvalidPath(
                "shared_git_store_identity and operational_checkout_identity must be distinct"
                    .to_owned(),
            ));
        }
        Ok(Self {
            shared_git_store_identity,
            operational_checkout_identity,
            workspaces: BTreeMap::new(),
            capabilities: BTreeMap::new(),
            committed_ops: BTreeMap::new(),
            incomplete_ops_held: BTreeMap::new(),
        })
    }

    fn payload_digest(payload: &InventoryPayloadV1) -> InventoryResult<String> {
        let bytes = serde_json::to_vec(payload).map_err(|e| InventoryError::Io(e.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(&bytes)))
    }

    fn append_journal_entry(journal_path: &Path, entry: &JournalEntryV1) -> InventoryResult<()> {
        let parent = journal_path.parent().ok_or_else(|| {
            InventoryError::InvalidPath("journal_path must have a parent directory".to_owned())
        })?;
        verify_private_directory_identity(parent, true)?;
        let mut line = serde_json::to_vec(entry).map_err(|e| InventoryError::Io(e.to_string()))?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal_path)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        let len_before = file
            .metadata()
            .map_err(|e| InventoryError::Io(e.to_string()))?
            .len();
        if len_before.saturating_add(line.len() as u64) > MAX_INVENTORY_JOURNAL_BYTES {
            return Err(InventoryError::JournalCorruptOrBounded(
                "inventory journal byte ceiling exceeded".to_owned(),
            ));
        }
        file.write_all(&line)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        let dir = File::open(parent).map_err(|e| InventoryError::Io(e.to_string()))?;
        dir.sync_all()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        Ok(())
    }

    /// Submit a durable intent + result atomically to the registry and journal.
    /// Idempotent replay of the exact `(operation_id, intent_digest)` returns
    /// `IdempotentReplay` without duplicate side effects; conflicting reuse of
    /// `operation_id` with a different payload fails closed.
    pub fn submit_durable(
        &mut self,
        journal_path: &Path,
        operation_id: &str,
        now_unix_ms: u64,
        payload: InventoryPayloadV1,
    ) -> InventoryResult<InventorySubmissionOutcomeV1> {
        validate_id(operation_id, "operation_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        let digest = Self::payload_digest(&payload)?;
        if let Some(existing_digest) = self.committed_ops.get(operation_id) {
            if existing_digest == &digest {
                return Ok(InventorySubmissionOutcomeV1::IdempotentReplay);
            }
            return Err(InventoryError::ConflictingReplay(format!(
                "operation_id {operation_id:?} replayed with different payload digest"
            )));
        }
        if self.incomplete_ops_held.contains_key(operation_id) {
            return Err(InventoryError::ConflictingReplay(format!(
                "operation_id {operation_id:?} is held due to prior incomplete execution"
            )));
        }

        let intent = JournalEntryV1::Intent {
            operation_id: operation_id.to_owned(),
            intent_digest: digest.clone(),
            recorded_unix_ms: now_unix_ms,
            payload: payload.clone(),
        };
        Self::append_journal_entry(journal_path, &intent)?;

        match self.apply_payload(payload) {
            Ok(()) => {
                let result = JournalEntryV1::Result {
                    operation_id: operation_id.to_owned(),
                    intent_digest: digest.clone(),
                    completed_unix_ms: now_unix_ms,
                    committed: true,
                    hold_reason: None,
                };
                Self::append_journal_entry(journal_path, &result)?;
                self.committed_ops.insert(operation_id.to_owned(), digest);
                Ok(InventorySubmissionOutcomeV1::Applied)
            }
            Err(err) => {
                let result = JournalEntryV1::Result {
                    operation_id: operation_id.to_owned(),
                    intent_digest: digest,
                    completed_unix_ms: now_unix_ms,
                    committed: false,
                    hold_reason: Some(err.to_string()),
                };
                let _ = Self::append_journal_entry(journal_path, &result);
                Err(err)
            }
        }
    }

    fn apply_payload(&mut self, payload: InventoryPayloadV1) -> InventoryResult<()> {
        match payload {
            InventoryPayloadV1::RegisterWorkspace { mut record } => {
                record.validate_structural()?;
                if !record
                    .shared_git_store_identity
                    .same_inode(&self.shared_git_store_identity)
                {
                    return Err(InventoryError::SharedGitStoreMismatch(format!(
                        "workspace {:?} does not share the enrolled Git object store",
                        record.workspace_name
                    )));
                }
                if !record
                    .operational_checkout_identity
                    .same_inode(&self.operational_checkout_identity)
                {
                    return Err(InventoryError::OperationalCheckoutForbidden(
                        "operational_checkout_identity mismatch".to_owned(),
                    ));
                }
                let actual_ws_identity =
                    verify_private_directory_identity(Path::new(&record.workspace_path), true)?;
                if actual_ws_identity != record.workspace_identity {
                    return Err(InventoryError::WorkspaceIdentityDrift(format!(
                        "workspace {:?} physical identity {:?} != claimed {:?}",
                        record.workspace_path, actual_ws_identity, record.workspace_identity
                    )));
                }

                // Check against all existing active/held workspaces for physical
                // inode collision, name collision, or shared mutable JJ change.
                for existing in self.workspaces.values() {
                    if !existing.status.blocks_exclusive_claim() {
                        continue;
                    }
                    if existing.record_id == record.record_id {
                        return Err(InventoryError::DuplicateWorkspaceName(format!(
                            "record_id {:?} already active or held",
                            record.record_id
                        )));
                    }
                    if existing.workspace_name == record.workspace_name {
                        return Err(InventoryError::DuplicateWorkspaceName(format!(
                            "workspace_name {:?} already claimed by {:?}",
                            record.workspace_name, existing.owner_actor
                        )));
                    }
                    if existing
                        .workspace_identity
                        .same_inode(&record.workspace_identity)
                    {
                        return Err(InventoryError::DuplicatePhysicalWorkspace(format!(
                            "physical directory (dev={}, ino={}) already claimed by {:?}",
                            record.workspace_identity.dev,
                            record.workspace_identity.ino,
                            existing.owner_actor
                        )));
                    }
                    if existing.jj_working_copy_change_id == record.jj_working_copy_change_id
                        || existing.jj_working_copy_commit_id == record.jj_working_copy_commit_id
                    {
                        return Err(InventoryError::SharedMutableJjChange(format!(
                            "JJ working-copy change {:?} already claimed by {:?}",
                            record.jj_working_copy_change_id, existing.owner_actor
                        )));
                    }
                }

                record.status = WorkspaceOwnershipStatusV1::Active;
                record.hold_reason = None;
                self.workspaces.insert(record.record_id.clone(), *record);
                Ok(())
            }
            InventoryPayloadV1::ReleaseWorkspace {
                record_id,
                actor,
                released_unix_ms,
            } => {
                let Some(existing) = self.workspaces.get_mut(&record_id) else {
                    return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                        "unknown workspace record_id {record_id:?}"
                    )));
                };
                if existing.owner_actor != actor {
                    return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                        "actor {actor:?} cannot release workspace owned by {:?}",
                        existing.owner_actor
                    )));
                }
                if released_unix_ms < existing.issued_unix_ms {
                    return Err(InventoryError::InvalidIdentifier(
                        "released_unix_ms precedes issued_unix_ms".to_owned(),
                    ));
                }
                existing.status = WorkspaceOwnershipStatusV1::Released;
                existing.hold_reason = None;
                Ok(())
            }
            InventoryPayloadV1::UpsertCapability { mut record } => {
                record.verify_and_classify()?;
                self.capabilities
                    .insert(record.capability_id.clone(), *record);
                Ok(())
            }
        }
    }

    /// Guard a source-mutating operation before execution: verifies that the
    /// workspace record is `Active`, owned by `caller_actor`, bound to
    /// `expected_task_ref`, within its lease window, and that its physical
    /// directory `(dev, ino, uid, mode)` has not drifted since admission.
    pub fn verify_workspace_for_mutation(
        &mut self,
        record_id: &str,
        caller_actor: &str,
        expected_task_ref: &TaskRefV1,
        now_unix_ms: u64,
    ) -> InventoryResult<&WorkspaceOwnershipRecordV1> {
        let Some(record) = self.workspaces.get_mut(record_id) else {
            return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                "workspace record {record_id:?} is not registered"
            )));
        };
        if record.status != WorkspaceOwnershipStatusV1::Active {
            return Err(InventoryError::WorkspaceHeld(format!(
                "workspace {record_id:?} is not Active (status={:?}, reason={:?})",
                record.status, record.hold_reason
            )));
        }
        if record.owner_actor != caller_actor || &record.task_ref != expected_task_ref {
            return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                "workspace {record_id:?} owner/task mismatch for caller {caller_actor:?}"
            )));
        }
        if now_unix_ms >= record.lease_expires_unix_ms {
            record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
            let reason = format!(
                "workspace {record_id:?} lease expired at {}",
                record.lease_expires_unix_ms
            );
            record.hold_reason = Some(reason.clone());
            return Err(InventoryError::WorkspaceHeld(reason));
        }
        match verify_private_directory_identity(Path::new(&record.workspace_path), true) {
            Ok(current_id) if current_id == record.workspace_identity => Ok(record),
            Ok(current_id) => {
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                let reason = format!(
                    "workspace {record_id:?} physical identity drifted from {:?} to {:?}",
                    record.workspace_identity, current_id
                );
                record.hold_reason = Some(reason.clone());
                Err(InventoryError::WorkspaceIdentityDrift(reason))
            }
            Err(err) => {
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                let reason = format!("workspace {record_id:?} verification failed: {err}");
                record.hold_reason = Some(reason.clone());
                Err(err)
            }
        }
    }

    /// Startup / pre-use / bounded runtime reconciliation. Places any expired,
    /// dead-PID, or physically drifted workspace into `HeldStaleOrUnknown`
    /// without silently deleting or stealing ownership.
    pub fn reconcile_workspaces<F>(
        &mut self,
        now_unix_ms: u64,
        is_pid_birth_alive: F,
    ) -> Vec<String>
    where
        F: Fn(u32, u64) -> bool,
    {
        let mut newly_held = Vec::new();
        for (id, record) in &mut self.workspaces {
            if record.status != WorkspaceOwnershipStatusV1::Active {
                continue;
            }
            if now_unix_ms >= record.lease_expires_unix_ms {
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                record.hold_reason = Some("lease expired during reconciliation".to_owned());
                newly_held.push(id.clone());
                continue;
            }
            if let Some((pid, birth)) = record.pid_birth_binding
                && !is_pid_birth_alive(pid, birth)
            {
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                record.hold_reason = Some(format!(
                    "bound process pid={pid} birth={birth} is not alive"
                ));
                newly_held.push(id.clone());
                continue;
            }
            match verify_private_directory_identity(Path::new(&record.workspace_path), true) {
                Ok(actual) if actual == record.workspace_identity => {}
                Ok(_) | Err(_) => {
                    record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                    record.hold_reason =
                        Some("physical workspace directory missing or identity drifted".to_owned());
                    newly_held.push(id.clone());
                }
            }
        }
        newly_held
    }

    /// Replay a durable journal from disk and place any intent lacking a
    /// matching result record into a conservative hold (`incomplete_ops_held`
    /// + `HeldStaleOrUnknown` on the target workspace).
    pub fn load_and_reconcile(
        shared_git_store_identity: FsEntryIdentityV1,
        operational_checkout_identity: FsEntryIdentityV1,
        journal_path: &Path,
    ) -> InventoryResult<Self> {
        let mut registry = Self::new(shared_git_store_identity, operational_checkout_identity)?;
        if !journal_path.exists() {
            return Ok(registry);
        }
        let file = File::open(journal_path).map_err(|e| InventoryError::Io(e.to_string()))?;
        let meta = file
            .metadata()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        if meta.len() > MAX_INVENTORY_JOURNAL_BYTES {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal exceeds MAX_INVENTORY_JOURNAL_BYTES".to_owned(),
            ));
        }
        let reader = BufReader::new(file);
        let mut pending_intents: BTreeMap<String, (String, InventoryPayloadV1)> = BTreeMap::new();
        let mut count = 0usize;
        for line in reader.lines() {
            count += 1;
            if count > MAX_INVENTORY_RECORDS {
                return Err(InventoryError::JournalCorruptOrBounded(
                    "journal record count exceeds MAX_INVENTORY_RECORDS".to_owned(),
                ));
            }
            let raw = line.map_err(|e| InventoryError::Io(e.to_string()))?;
            if raw.trim().is_empty() {
                continue;
            }
            let entry: JournalEntryV1 = serde_json::from_str(&raw)
                .map_err(|e| InventoryError::JournalCorruptOrBounded(e.to_string()))?;
            match entry {
                JournalEntryV1::Intent {
                    operation_id,
                    intent_digest,
                    payload,
                    ..
                } => {
                    if registry.committed_ops.contains_key(&operation_id)
                        || pending_intents.contains_key(&operation_id)
                    {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "duplicate intent for operation_id {operation_id:?}"
                        )));
                    }
                    pending_intents.insert(operation_id, (intent_digest, payload));
                }
                JournalEntryV1::Result {
                    operation_id,
                    intent_digest,
                    committed,
                    ..
                } => {
                    let Some((expected_digest, payload)) = pending_intents.remove(&operation_id)
                    else {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "result without preceding intent for operation_id {operation_id:?}"
                        )));
                    };
                    if expected_digest != intent_digest {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "intent/result digest mismatch for operation_id {operation_id:?}"
                        )));
                    }
                    if committed {
                        registry.apply_payload(payload)?;
                        registry.committed_ops.insert(operation_id, intent_digest);
                    }
                }
            }
        }

        // Any intent without a matching result is held conservatively across restart.
        for (op_id, (digest, payload)) in pending_intents {
            registry.incomplete_ops_held.insert(op_id.clone(), digest);
            if let InventoryPayloadV1::RegisterWorkspace { mut record } = payload {
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                record.hold_reason = Some(format!(
                    "incomplete intent {op_id} held across crash/restart recovery"
                ));
                registry
                    .workspaces
                    .insert(record.record_id.clone(), *record);
            }
        }
        Ok(registry)
    }

    /// Non-mutating discovery snapshot for agents and humans. Performs zero
    /// disk writes or state mutations.
    pub fn inspect_discovery_snapshot(&self) -> DiscoverySnapshotV1 {
        DiscoverySnapshotV1 {
            shared_git_store_identity: self.shared_git_store_identity,
            operational_checkout_identity: self.operational_checkout_identity,
            workspaces: self.workspaces.values().cloned().collect(),
            capabilities: self.capabilities.values().cloned().collect(),
            incomplete_operations_held: self.incomplete_ops_held.keys().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_writer::CanonicalTaskDocumentV1;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn sample_task_ref(task_id: &str) -> TaskRefV1 {
        let tref = TaskRefV1 {
            workspace_id: "chinwag".to_owned(),
            repo_id: "emunlabs/chinwag".to_owned(),
            task_source_id: "05a1b2c3d4e54f608192a3b4c5d6e806".to_owned(),
            source_generation: 1,
            canonical_task_path: "TASKS.md".to_owned(),
            task_id: task_id.to_owned(),
            task_spec_digest: Sha256Digest::from_hex(
                "d220229601d9a92042ff570206905bcb8faf3049d45251b145993dedb3fdd2f4",
            )
            .unwrap(),
            task_status_rev: 1,
            file_cas_rev: 1,
            baseline_commit: GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35").unwrap(),
        };
        tref.validate().unwrap();
        tref
    }

    struct EnvFixture {
        _tmp: TempDir,
        store_dir: std::path::PathBuf,
        op_dir: std::path::PathBuf,
        ws1_dir: std::path::PathBuf,
        ws2_dir: std::path::PathBuf,
        journal_path: std::path::PathBuf,
        store_id: FsEntryIdentityV1,
        op_id: FsEntryIdentityV1,
        ws1_id: FsEntryIdentityV1,
        ws2_id: FsEntryIdentityV1,
    }

    impl EnvFixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir_in("/private/tmp").unwrap();
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let store_dir = tmp.path().join("store-repo");
            let op_dir = tmp.path().join("operational-checkout");
            let ws1_dir = tmp.path().join("ws-agent-1");
            let ws2_dir = tmp.path().join("ws-agent-2");
            let journal_dir = tmp.path().join("journal");
            for dir in [&store_dir, &op_dir, &ws1_dir, &ws2_dir, &journal_dir] {
                fs::create_dir(dir).unwrap();
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let store_id = verify_private_directory_identity(&store_dir, true).unwrap();
            let op_id = verify_private_directory_identity(&op_dir, true).unwrap();
            let ws1_id = verify_private_directory_identity(&ws1_dir, true).unwrap();
            let ws2_id = verify_private_directory_identity(&ws2_dir, true).unwrap();
            let journal_path = journal_dir.join("inventory-journal.jsonl");
            Self {
                _tmp: tmp,
                store_dir,
                op_dir,
                ws1_dir,
                ws2_dir,
                journal_path,
                store_id,
                op_id,
                ws1_id,
                ws2_id,
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn make_ws_record(
            &self,
            record_id: &str,
            ws_name: &str,
            ws_path: &Path,
            ws_id: FsEntryIdentityV1,
            change_id: &str,
            commit_hex: &str,
            actor: &str,
            task_id: &str,
        ) -> WorkspaceOwnershipRecordV1 {
            WorkspaceOwnershipRecordV1 {
                record_id: record_id.to_owned(),
                repo_id: "emunlabs/chinwag".to_owned(),
                operational_checkout_path: self.op_dir.to_str().unwrap().to_owned(),
                operational_checkout_identity: self.op_id,
                shared_git_store_path: self.store_dir.to_str().unwrap().to_owned(),
                shared_git_store_identity: self.store_id,
                workspace_name: ws_name.to_owned(),
                workspace_path: ws_path.to_str().unwrap().to_owned(),
                workspace_identity: ws_id,
                jj_working_copy_change_id: change_id.to_owned(),
                jj_working_copy_commit_id: GitOid::from_hex(commit_hex).unwrap(),
                base_commit_id: GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35")
                    .unwrap(),
                base_tree_id: GitOid::from_hex("69c3b294b10a74190b894e2be486138c61772d83").unwrap(),
                owner_actor: actor.to_owned(),
                task_ref: sample_task_ref(task_id),
                admission_digest: Sha256Digest::from_hex(
                    "47db4ba1d53b605e82275e1994d6a591a2569aef7af7dea4749c8b410c145ed3",
                )
                .unwrap(),
                scope_paths: vec![
                    "crates/chinwag-cli/src/workspace_capability_inventory.rs".to_owned(),
                ],
                review_branch: "refs/heads/review/chwg-jj-workspace-registry-01-s1-20261109"
                    .to_owned(),
                issued_unix_ms: 1_000,
                lease_expires_unix_ms: 60_000,
                pid_birth_binding: Some((12345, 999)),
                status: WorkspaceOwnershipStatusV1::Active,
                hold_reason: None,
            }
        }
    }

    #[test]
    fn acceptance_1_to_4_and_8_exclusive_workspace_change_alias_and_operational_checkout_guards() {
        let f = EnvFixture::new();
        let mut reg = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();

        // 1. Operational checkout is rejected as an agent workspace.
        let op_claim = f.make_ws_record(
            "rec-op",
            "ws-op",
            &f.op_dir,
            f.op_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-reject-1",
                1_500,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(op_claim),
                },
            ),
            Err(InventoryError::OperationalCheckoutForbidden(_))
        ));

        // 2. Bare/unresolved actor without #<instance> is rejected.
        let bare_actor_claim = f.make_ws_record(
            "rec-bare",
            "ws-bare",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-reject-bare",
                1_500,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(bare_actor_claim),
                },
            ),
            Err(InventoryError::UnresolvedOrMismatchedOwner(_))
        ));

        // 3. Valid registration of Workspace 1 succeeds and shares the Git store.
        let ws1_claim = f.make_ws_record(
            "rec-ws1",
            "ws-chwg-jj-workspace-registry-01-s1",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert_eq!(
            reg.submit_durable(
                &f.journal_path,
                "op-reg-ws1",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(ws1_claim.clone()),
                },
            )
            .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );

        // 4. Duplicate physical directory (same dev/ino) by another actor is rejected.
        let dup_phys = f.make_ws_record(
            "rec-dup-phys",
            "ws-other-name",
            &f.ws1_dir,
            f.ws1_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-dup-phys",
                2_100,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(dup_phys),
                },
            ),
            Err(InventoryError::DuplicatePhysicalWorkspace(_))
        ));

        // 5. Symlink alias to ws1_dir is rejected by NOFOLLOW directory walk.
        let alias_path = f._tmp.path().join("ws-symlink-alias");
        symlink(&f.ws1_dir, &alias_path).unwrap();
        let symlink_claim = f.make_ws_record(
            "rec-symlink",
            "ws-symlink",
            &alias_path,
            f.ws1_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-symlink",
                2_200,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(symlink_claim),
                },
            ),
            Err(InventoryError::SymlinkOrNonDirectory(_))
        ));

        // 6. Second distinct physical workspace sharing the same mutable JJ change is rejected.
        let shared_change = f.make_ws_record(
            "rec-ws2-shared-change",
            "ws-agent-2",
            &f.ws2_dir,
            f.ws2_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-shared-change",
                2_300,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(shared_change),
                },
            ),
            Err(InventoryError::SharedMutableJjChange(_))
        ));

        // 7. Second distinct physical workspace with its own JJ change sharing the Git store succeeds.
        let ws2_claim = f.make_ws_record(
            "rec-ws2",
            "ws-task-publish-reg-v1",
            &f.ws2_dir,
            f.ws2_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "GEMINI-PM#ef045f9c-8ad4-42a7-836e-eea718e3d198",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert_eq!(
            reg.submit_durable(
                &f.journal_path,
                "op-reg-ws2",
                2_400,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(ws2_claim),
                },
            )
            .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
    }

    #[test]
    fn acceptance_5_6_9_and_10_capability_provenance_dirty_build_and_non_authority() {
        let f = EnvFixture::new();
        let mut reg = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();

        let base_oid = GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35").unwrap();
        let tree_oid = GitOid::from_hex("69c3b294b10a74190b894e2be486138c61772d83").unwrap();
        let bin_sha = Sha256Digest::from_hex(
            "142c504a5f85210670c78e3671b453f0a5866383764a4b8306c4f5eac416e528",
        )
        .unwrap();

        // Dirty tree claiming Installed must fail closed.
        let dirty_installed = CapabilityProvenanceRecordV1 {
            capability_id: "cap.workspace_inventory.v1".to_owned(),
            handler_symbol: "verify_workspace_for_mutation".to_owned(),
            source_module_path: "crates/chinwag-cli/src/workspace_capability_inventory.rs"
                .to_owned(),
            claimed_classification: CapabilityClassificationV1::Installed,
            handler_wired: true,
            unit_tests_passed: true,
            source_commit: base_oid,
            source_tree: tree_oid,
            source_tree_clean: false,
            accepted_source_commit: Some(base_oid),
            compiled_artifact_sha256: Some(bin_sha),
            installed_binary_path: Some("/Users/brianspector/.local/bin/chinwag".to_owned()),
            installed_binary_sha256: Some(bin_sha),
            runtime_health_verified: false,
            admission_authority_digest: None,
            task_ref: None,
            observed_unix_ms: 3_000,
            effective_classification: CapabilityClassificationV1::Unknown,
            hold_or_downgrade_reason: None,
        };
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-cap-dirty",
                3_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(dirty_installed.clone()),
                },
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));

        // Tested capability on uncommitted/dirty workspace is valid ONLY as Tested, never Operational/Authorized.
        let mut tested_only = dirty_installed;
        tested_only.claimed_classification = CapabilityClassificationV1::Tested;
        assert_eq!(
            reg.submit_durable(
                &f.journal_path,
                "op-cap-tested",
                3_100,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(tested_only.clone()),
                },
            )
            .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
        // Inventory record never grants execution authority.
        assert_eq!(
            tested_only.require_execution_authority(),
            Err(InventoryError::InventoryNotExecutionAuthority)
        );
    }

    #[test]
    fn acceptance_7_8_and_9_idempotent_replay_crash_recovery_reconcile_and_readonly_discovery() {
        let f = EnvFixture::new();
        let mut reg = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();

        let ws1 = f.make_ws_record(
            "rec-ws1",
            "ws-chwg-jj-workspace-registry-01-s1",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(ws1.clone()),
        };
        assert_eq!(
            reg.submit_durable(&f.journal_path, "op-1", 2_000, payload.clone())
                .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
        // Exact replay is idempotent.
        assert_eq!(
            reg.submit_durable(&f.journal_path, "op-1", 2_005, payload)
                .unwrap(),
            InventorySubmissionOutcomeV1::IdempotentReplay
        );

        // Simulate a crash after writing an Intent for ws2 without a Result record.
        let ws2 = f.make_ws_record(
            "rec-ws2-crash",
            "ws-crash",
            &f.ws2_dir,
            f.ws2_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let crash_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(ws2),
        };
        let crash_intent = JournalEntryV1::Intent {
            operation_id: "op-crash-incomplete".to_owned(),
            intent_digest: ContinuousInventoryRegistryV1::payload_digest(&crash_payload).unwrap(),
            recorded_unix_ms: 2_500,
            payload: crash_payload,
        };
        ContinuousInventoryRegistryV1::append_journal_entry(&f.journal_path, &crash_intent)
            .unwrap();

        // Reload and reconcile: ws1 is Active, ws2 is HeldStaleOrUnknown, op-crash-incomplete is held.
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        let journal_bytes_before = fs::read(&f.journal_path).unwrap();
        let snap = recovered.inspect_discovery_snapshot();
        let journal_bytes_after = fs::read(&f.journal_path).unwrap();
        assert_eq!(journal_bytes_before, journal_bytes_after);
        assert_eq!(
            snap.incomplete_operations_held,
            vec!["op-crash-incomplete".to_owned()]
        );
        let ws2_rec = snap
            .workspaces
            .iter()
            .find(|w| w.record_id == "rec-ws2-crash")
            .unwrap();
        assert_eq!(
            ws2_rec.status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );

        // Reconcile dead PID / expired lease places ws1 into HeldStaleOrUnknown.
        let newly_held = recovered.reconcile_workspaces(70_000, |_pid, _birth| false);
        assert_eq!(newly_held, vec!["rec-ws1".to_owned()]);
        assert!(matches!(
            recovered.verify_workspace_for_mutation(
                "rec-ws1",
                "RUST#efffddad3cb4321cb1308b089f76c206",
                &ws1.task_ref,
                70_001,
            ),
            Err(InventoryError::WorkspaceHeld(_))
        ));
    }

    #[test]
    fn canonical_task_document_v1_parses_registered_chwg_jj_workspace_registry_01_task_ref() {
        let markdown = concat!(
            "# Tasks\n\n",
            "<!-- chinwag-task-source-meta-v1 {\"workspace_id\":\"chinwag\",\"repo_id\":\"emunlabs/chinwag\",\"task_source_id\":\"05a1b2c3d4e54f608192a3b4c5d6e806\",\"source_generation\":1,\"file_cas_rev\":1,\"last_operation_id\":\"05a1b2c3d4e54f608192a3b4c5d6e806\"} -->\n",
            "### `[NEXT]` CHWG-JJ-WORKSPACE-REGISTRY-01 — Enforce isolated JJ workspaces and maintain canonical live ownership and capability inventories\n",
            "<!-- chinwag-task-begin-v1 task_id=\"CHWG-JJ-WORKSPACE-REGISTRY-01\" -->\n",
            "- [ ] **CHWG-JJ-WORKSPACE-REGISTRY-01** (`in-progress`) — Enforce isolated JJ workspaces and maintain canonical live ownership and capability inventories\n",
            "<!-- chinwag-task-entry-v1 {\"task_id\":\"CHWG-JJ-WORKSPACE-REGISTRY-01\",\"status\":\"in-progress\",\"task_status_rev\":1,\"task_spec_digest\":\"d220229601d9a92042ff570206905bcb8faf3049d45251b145993dedb3fdd2f4\",\"task_control_digest\":\"d7432f6df63ec14682feafa27e6d02bea1d0076d74e58c0242b1965286ff1ed7\",\"completion_policy_digest\":\"9324dbba9729965789cd1e148903dfb35d17cbe749defd27751b7f9f01988af3\",\"owner_actor\":\"RUST#efffddad3cb4321cb1308b089f76c206\",\"reviewer_role\":\"ARCHITECT\",\"baseline_commit\":\"d326c7129979ca43499547842daac076d80fac35\",\"candidate_commit\":null,\"overlay_digest\":null,\"execution_flags\":[\"priority:next\",\"slice:s1-admitted\"],\"dependencies\":[]} -->\n",
            "<!-- chinwag-task-end-v1 task_id=\"CHWG-JJ-WORKSPACE-REGISTRY-01\" -->\n",
        );
        let doc = CanonicalTaskDocumentV1::from_bytes(markdown.as_bytes()).unwrap();
        assert_eq!(doc.tasks.len(), 1);
        let task_ref = doc.task_ref(&doc.tasks[0], "TASKS.md");
        let encoded = task_ref.encode().unwrap();
        let digest_hex = format!("{:x}", Sha256::digest(&encoded));
        assert_eq!(
            digest_hex,
            "e880883b5510f0981cb05cc9a9db0f58697a54a373e921f2ec6a120c2638a104"
        );
    }
}
