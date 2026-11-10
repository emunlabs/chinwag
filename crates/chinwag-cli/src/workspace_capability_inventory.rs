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
use crate::task_write_journal::strict_json_object;
use rustix::fs::{
    AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, openat, statat,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

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
    IncompleteIntentHeld(String),
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
            self.installed_binary_sha256 = None;
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
                self.installed_binary_sha256 = None;
                if self
                    .hold_or_downgrade_reason
                    .as_ref()
                    .is_none_or(|reason| reason.trim().is_empty())
                {
                    self.hold_or_downgrade_reason =
                        Some("explicit Held capability observation".to_owned());
                }
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Implemented => {
                if !self.handler_wired {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    self.installed_binary_sha256 = None;
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
                    self.installed_binary_sha256 = None;
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
                    self.installed_binary_sha256 = None;
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
                    self.installed_binary_sha256 = None;
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
                        self.installed_binary_sha256 = None;
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
                    self.installed_binary_sha256 = None;
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
                    self.installed_binary_sha256 = None;
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
    HoldWorkspace {
        record_id: String,
        hold_reason: String,
        updated_unix_ms: u64,
    },
    HoldCapability {
        capability_id: String,
        hold_reason: String,
        updated_unix_ms: u64,
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
    pub corrupt_or_ambiguous_tail_reason: Option<String>,
}

/// Independently opened descriptors retain both locks for the whole transaction.
struct LockedInventoryJournal {
    dir_fd: File,
    file_fd: File,
    file_name: std::ffi::OsString,
    parent_identity: FsEntryIdentityV1,
    file_identity: (u64, u64),
    file_bytes: u64,
}

impl LockedInventoryJournal {
    fn open(journal_path: &Path, create: bool) -> InventoryResult<Option<Self>> {
        let parent = journal_path.parent().ok_or_else(|| {
            InventoryError::InvalidPath("journal_path must have a parent directory".to_owned())
        })?;
        let parent_identity = verify_private_directory_identity(parent, true)?;
        let file_name = journal_path.file_name().ok_or_else(|| {
            InventoryError::InvalidPath("journal_path must name a file".to_owned())
        })?;
        let dir_fd = File::from(
            openat(
                CWD,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| InventoryError::Io(e.to_string()))?,
        );
        Self::verify_directory(&dir_fd, parent_identity)?;
        flock(&dir_fd, FlockOperation::LockExclusive)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        Self::verify_directory(&dir_fd, parent_identity)?;
        match statat(&dir_fd, file_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                Self::file_snapshot(&stat)?;
            }
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {}
            Err(err) => return Err(InventoryError::Io(err.to_string())),
        }
        let flags = if create {
            OFlags::RDWR | OFlags::CREATE | OFlags::APPEND
        } else {
            OFlags::RDONLY
        };
        let file_fd = File::from(
            openat(
                &dir_fd,
                file_name,
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|e| InventoryError::Io(e.to_string()))?,
        );
        flock(&file_fd, FlockOperation::LockExclusive)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        let (dev, ino, file_bytes) =
            Self::file_snapshot(&fstat(&file_fd).map_err(|e| InventoryError::Io(e.to_string()))?)?;
        let journal = Self {
            dir_fd,
            file_fd,
            file_name: file_name.to_owned(),
            parent_identity,
            file_identity: (dev, ino),
            file_bytes,
        };
        journal.verify_binding(file_bytes)?;
        Ok(Some(journal))
    }

    fn verify_directory(file: &File, identity: FsEntryIdentityV1) -> InventoryResult<()> {
        let stat = fstat(file).map_err(|e| InventoryError::Io(e.to_string()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || (stat.st_dev as u64, stat.st_ino as u64) != (identity.dev, identity.ino)
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o700
            || stat.st_nlink == 0
        {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal directory identity or private metadata changed".to_owned(),
            ));
        }
        Ok(())
    }

    fn file_snapshot(stat: &Stat) -> InventoryResult<(u64, u64, u64)> {
        let size = u64::try_from(stat.st_size).map_err(|_| {
            InventoryError::JournalCorruptOrBounded("negative journal size".to_owned())
        })?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || size > MAX_INVENTORY_JOURNAL_BYTES
        {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal must be a private, singly linked, bounded regular file".to_owned(),
            ));
        }
        Ok((stat.st_dev as u64, stat.st_ino, size))
    }

    fn verify_binding(&self, expected_size: u64) -> InventoryResult<()> {
        Self::verify_directory(&self.dir_fd, self.parent_identity)?;
        let opened = Self::file_snapshot(
            &fstat(&self.file_fd).map_err(|e| InventoryError::Io(e.to_string()))?,
        )?;
        let named = Self::file_snapshot(
            &statat(&self.dir_fd, &self.file_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| InventoryError::Io(e.to_string()))?,
        )?;
        if opened != named || opened != (self.file_identity.0, self.file_identity.1, expected_size)
        {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal inode binding or size changed".to_owned(),
            ));
        }
        Ok(())
    }

    fn read_from_start(&mut self) -> InventoryResult<Vec<u8>> {
        self.file_fd
            .rewind()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        let mut bytes = Vec::new();
        (&mut self.file_fd)
            .take(MAX_INVENTORY_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        if bytes.len() as u64 != self.file_bytes {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal size changed during replay".to_owned(),
            ));
        }
        self.verify_binding(self.file_bytes)?;
        Ok(bytes)
    }

    fn append_line(&mut self, line: &[u8]) -> InventoryResult<()> {
        let expected_size = self
            .file_bytes
            .checked_add(line.len() as u64)
            .filter(|size| *size <= MAX_INVENTORY_JOURNAL_BYTES)
            .ok_or_else(|| {
                InventoryError::JournalCorruptOrBounded(
                    "inventory journal byte ceiling exceeded".to_owned(),
                )
            })?;
        self.verify_binding(self.file_bytes)?;
        self.file_fd
            .write_all(line)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        self.file_fd
            .sync_all()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        self.dir_fd
            .sync_all()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        self.verify_binding(expected_size)?;
        self.file_bytes = expected_size;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ContinuousInventoryRegistryV1 {
    shared_git_store_identity: FsEntryIdentityV1,
    operational_checkout_identity: FsEntryIdentityV1,
    workspaces: BTreeMap<String, WorkspaceOwnershipRecordV1>,
    capabilities: BTreeMap<String, CapabilityProvenanceRecordV1>,
    committed_ops: BTreeMap<String, String>,
    rejected_ops: BTreeMap<String, (String, Option<String>)>,
    incomplete_ops_held: BTreeMap<String, String>,
    journal_path: Option<PathBuf>,
    bound_journal_identity: Option<(FsEntryIdentityV1, std::ffi::OsString, (u64, u64))>,
    corrupt_or_ambiguous_tail_reason: Option<String>,
    #[cfg(test)]
    fail_next_result_append: bool,
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
            rejected_ops: BTreeMap::new(),
            incomplete_ops_held: BTreeMap::new(),
            journal_path: None,
            bound_journal_identity: None,
            corrupt_or_ambiguous_tail_reason: None,
            #[cfg(test)]
            fail_next_result_append: false,
        })
    }

    fn verify_or_bind_journal_identity(
        &mut self,
        journal: &LockedInventoryJournal,
    ) -> InventoryResult<()> {
        if let Some((expected_parent, expected_name, expected_file_id)) =
            &self.bound_journal_identity
        {
            if expected_parent.dev != journal.parent_identity.dev
                || expected_parent.ino != journal.parent_identity.ino
                || expected_name != &journal.file_name
                || *expected_file_id != journal.file_identity
            {
                return Err(InventoryError::InvalidPath(
                    "registry instance is already bound to a different authoritative journal identity"
                        .to_owned(),
                ));
            }
        } else {
            self.bound_journal_identity = Some((
                journal.parent_identity,
                journal.file_name.clone(),
                journal.file_identity,
            ));
        }
        Ok(())
    }

    pub fn corrupt_or_ambiguous_tail_reason(&self) -> Option<&str> {
        self.corrupt_or_ambiguous_tail_reason.as_deref()
    }

    fn payload_digest(payload: &InventoryPayloadV1) -> InventoryResult<String> {
        let bytes = serde_json::to_vec(payload).map_err(|e| InventoryError::Io(e.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(&bytes)))
    }

    fn journal_line(entry: &JournalEntryV1) -> InventoryResult<Vec<u8>> {
        let mut line = serde_json::to_vec(entry).map_err(|e| InventoryError::Io(e.to_string()))?;
        strict_json_object(&line, MAX_INVENTORY_JOURNAL_BYTES as usize)
            .map_err(|e| InventoryError::JournalCorruptOrBounded(e.to_string()))?;
        line.push(b'\n');
        Ok(line)
    }

    #[cfg(test)]
    fn append_journal_entry(journal_path: &Path, entry: &JournalEntryV1) -> InventoryResult<()> {
        let mut journal = LockedInventoryJournal::open(journal_path, true)?
            .ok_or_else(|| InventoryError::Io("created journal is missing".to_owned()))?;
        journal.append_line(&Self::journal_line(entry)?)
    }

    /// Submit an intent/result pair under shared-journal exclusion, installing
    /// the candidate registry only after both records are durable.
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
        let mut journal = LockedInventoryJournal::open(journal_path, true)?
            .ok_or_else(|| InventoryError::Io("created journal is missing".to_owned()))?;
        self.verify_or_bind_journal_identity(&journal)?;
        let existing_record_count = self.refresh_from_journal_locked(journal_path, &mut journal)?;
        if let Some(reason) = &self.corrupt_or_ambiguous_tail_reason {
            return Err(InventoryError::JournalCorruptOrBounded(reason.clone()));
        }
        if let Some(existing_digest) = self.committed_ops.get(operation_id) {
            if existing_digest == &digest {
                return Ok(InventorySubmissionOutcomeV1::IdempotentReplay);
            }
            return Err(InventoryError::ConflictingReplay(format!(
                "operation_id {operation_id:?} replayed with different payload digest"
            )));
        }
        if let Some((existing_digest, hold_reason)) = self.rejected_ops.get(operation_id) {
            return Err(InventoryError::ConflictingReplay(format!(
                "operation_id {operation_id} was already durably rejected/held (digest_match={}): {}",
                existing_digest == &digest,
                hold_reason.as_deref().unwrap_or("rejected")
            )));
        }
        if self.incomplete_ops_held.contains_key(operation_id) {
            return Err(InventoryError::IncompleteIntentHeld(
                operation_id.to_owned(),
            ));
        }

        // A rejected new capability has no journal effect. An existing capability
        // must retain a durable negative observation before reporting the error.
        if let InventoryPayloadV1::UpsertCapability { record } = &payload {
            let mut observation = record.clone();
            if let Err(err) = observation.verify_and_classify() {
                if self.capabilities.contains_key(&record.capability_id)
                    && matches!(
                        err,
                        InventoryError::UnprovenCapabilityClaim(_)
                            | InventoryError::DirtyOrMismatchedBuildProvenance(_)
                    )
                {
                    return self.commit_payload(
                        &mut journal,
                        existing_record_count,
                        operation_id,
                        now_unix_ms,
                        payload,
                    );
                }
                return Err(err);
            }
        }
        self.commit_payload(
            &mut journal,
            existing_record_count,
            operation_id,
            now_unix_ms,
            payload,
        )
    }

    /// Refresh discovery state from the bound authoritative journal without
    /// appending records. An ambiguous append remains held on this handle.
    pub fn refresh_from_journal(&mut self, journal_path: &Path) -> InventoryResult<()> {
        let mut journal = LockedInventoryJournal::open(journal_path, false)?
            .ok_or_else(|| InventoryError::Io("authoritative journal is missing".to_owned()))?;
        self.refresh_from_journal_locked(journal_path, &mut journal)?;
        Ok(())
    }

    fn refresh_from_journal_locked(
        &mut self,
        journal_path: &Path,
        journal: &mut LockedInventoryJournal,
    ) -> InventoryResult<usize> {
        self.verify_or_bind_journal_identity(journal)?;
        let (mut staging, existing_record_count) = Self::replay_journal(
            self.shared_git_store_identity,
            self.operational_checkout_identity,
            journal,
        )?;
        // Local reconciliation holds remain conservative across shared-journal refreshes.
        for (id, record) in &self.workspaces {
            if record.status == WorkspaceOwnershipStatusV1::HeldStaleOrUnknown {
                if self.corrupt_or_ambiguous_tail_reason.is_some() {
                    staging.workspaces.insert(id.clone(), record.clone());
                    continue;
                }
                staging
                    .workspaces
                    .entry(id.clone())
                    .and_modify(|existing| {
                        if existing.status.blocks_exclusive_claim() {
                            existing.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                            existing.hold_reason.clone_from(&record.hold_reason);
                            existing.pid_birth_binding = None;
                        }
                    })
                    .or_insert_with(|| record.clone());
            }
        }
        staging
            .incomplete_ops_held
            .extend(self.incomplete_ops_held.clone());
        staging.rejected_ops.extend(self.rejected_ops.clone());
        if self.corrupt_or_ambiguous_tail_reason.is_some() {
            for (id, record) in &self.capabilities {
                if record.effective_classification == CapabilityClassificationV1::Held {
                    staging.capabilities.insert(id.clone(), record.clone());
                }
            }
            if staging.corrupt_or_ambiguous_tail_reason.is_none() {
                staging.corrupt_or_ambiguous_tail_reason =
                    self.corrupt_or_ambiguous_tail_reason.clone();
            }
        }
        staging.bound_journal_identity = self.bound_journal_identity.clone();
        staging.journal_path = Some(journal_path.to_owned());
        #[cfg(test)]
        {
            staging.fail_next_result_append = self.fail_next_result_append;
        }
        *self = staging;
        Ok(existing_record_count)
    }

    fn commit_payload(
        &mut self,
        journal: &mut LockedInventoryJournal,
        existing_record_count: usize,
        operation_id: &str,
        now_unix_ms: u64,
        payload: InventoryPayloadV1,
    ) -> InventoryResult<InventorySubmissionOutcomeV1> {
        let digest = Self::payload_digest(&payload)?;
        let mut candidate = self.clone();
        let apply_outcome = candidate.apply_payload(payload.clone(), false);
        let hold_reason = apply_outcome.as_ref().err().map(ToString::to_string);
        let intent_line = Self::journal_line(&JournalEntryV1::Intent {
            operation_id: operation_id.to_owned(),
            intent_digest: digest.clone(),
            recorded_unix_ms: now_unix_ms,
            payload: payload.clone(),
        })?;
        let result_line = Self::journal_line(&JournalEntryV1::Result {
            operation_id: operation_id.to_owned(),
            intent_digest: digest.clone(),
            completed_unix_ms: now_unix_ms,
            committed: apply_outcome.is_ok(),
            hold_reason: hold_reason.clone(),
        })?;
        if existing_record_count
            .checked_add(2)
            .is_none_or(|count| count > MAX_INVENTORY_RECORDS)
            || journal
                .file_bytes
                .checked_add((intent_line.len() + result_line.len()) as u64)
                .is_none_or(|size| size > MAX_INVENTORY_JOURNAL_BYTES)
        {
            return Err(InventoryError::JournalCorruptOrBounded(
                "inventory journal cannot reserve both Intent and Result".to_owned(),
            ));
        }
        if let Err(err) = journal.append_line(&intent_line) {
            self.hold_incomplete(operation_id.to_owned(), digest, payload);
            self.corrupt_or_ambiguous_tail_reason =
                Some(format!("ambiguous_intent_append:{operation_id}:{err}"));
            return Err(err);
        }
        #[cfg(test)]
        let result_persistence = if std::mem::take(&mut self.fail_next_result_append) {
            Err(InventoryError::Io(
                "injected failure before durable Result".to_owned(),
            ))
        } else {
            journal.append_line(&result_line)
        };
        #[cfg(not(test))]
        let result_persistence = journal.append_line(&result_line);
        if let Err(err) = result_persistence {
            self.hold_incomplete(operation_id.to_owned(), digest, payload);
            self.corrupt_or_ambiguous_tail_reason =
                Some(format!("ambiguous_result_append:{operation_id}:{err}"));
            return Err(err);
        }
        match apply_outcome {
            Ok(()) => {
                candidate
                    .committed_ops
                    .insert(operation_id.to_owned(), digest);
                *self = candidate;
                Ok(InventorySubmissionOutcomeV1::Applied)
            }
            Err(err) => {
                candidate
                    .rejected_ops
                    .insert(operation_id.to_owned(), (digest, hold_reason));
                *self = candidate;
                Err(err)
            }
        }
    }

    fn commit_automatic_hold(
        &mut self,
        journal: &mut LockedInventoryJournal,
        record_count: usize,
        now_unix_ms: u64,
        payload: InventoryPayloadV1,
    ) -> InventoryResult<()> {
        let mut sequence = record_count;
        let operation_id = loop {
            let id = format!("auto-hold-seq-{sequence}");
            if !self.committed_ops.contains_key(&id)
                && !self.rejected_ops.contains_key(&id)
                && !self.incomplete_ops_held.contains_key(&id)
            {
                break id;
            }
            sequence += 1;
        };
        if let Err(err) = self.commit_payload(
            journal,
            record_count,
            &operation_id,
            now_unix_ms,
            payload.clone(),
        ) {
            // A persistence failure must never leave a known-bad observation ready.
            self.apply_payload(payload, false)?;
            return Err(err);
        }
        Ok(())
    }

    fn hold_workspace(
        &mut self,
        record_id: &str,
        reason: String,
        now_unix_ms: u64,
    ) -> InventoryResult<()> {
        let payload = InventoryPayloadV1::HoldWorkspace {
            record_id: record_id.to_owned(),
            hold_reason: reason,
            updated_unix_ms: now_unix_ms,
        };
        let Some(path) = self.journal_path.clone() else {
            return self.apply_payload(payload, false);
        };
        let opened = LockedInventoryJournal::open(&path, true).and_then(|journal| {
            journal.ok_or_else(|| InventoryError::Io("created journal is missing".to_owned()))
        });
        let mut journal = match opened {
            Ok(journal) => journal,
            Err(err) => {
                self.apply_payload(payload, false)?;
                return Err(err);
            }
        };
        // A foreign journal must be rejected before even a local hold changes
        // the state belonging to this handle's authoritative journal.
        self.verify_or_bind_journal_identity(&journal)?;
        let count = match self.refresh_from_journal_locked(&path, &mut journal) {
            Ok(count) => count,
            Err(err) => {
                self.apply_payload(payload, false)?;
                return Err(err);
            }
        };
        if let Some(reason) = &self.corrupt_or_ambiguous_tail_reason {
            return Err(InventoryError::JournalCorruptOrBounded(reason.clone()));
        }
        if !self
            .workspaces
            .get(record_id)
            .is_some_and(|record| record.status == WorkspaceOwnershipStatusV1::Active)
        {
            return Ok(());
        }
        self.commit_automatic_hold(&mut journal, count, now_unix_ms, payload)
    }

    fn apply_payload(
        &mut self,
        payload: InventoryPayloadV1,
        is_replay: bool,
    ) -> InventoryResult<()> {
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
                // Historical admission is a fact about the journal, independent of
                // today's directory. Verify only live admissions against the disk.
                if !is_replay {
                    let actual_ws_identity =
                        verify_private_directory_identity(Path::new(&record.workspace_path), true)?;
                    if actual_ws_identity != record.workspace_identity {
                        return Err(InventoryError::WorkspaceIdentityDrift(format!(
                            "workspace {:?} physical identity {:?} != claimed {:?}",
                            record.workspace_path, actual_ws_identity, record.workspace_identity
                        )));
                    }
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
                if let Err(err) = record.verify_and_classify() {
                    if matches!(
                        err,
                        InventoryError::UnprovenCapabilityClaim(_)
                            | InventoryError::DirtyOrMismatchedBuildProvenance(_)
                    ) && self.capabilities.contains_key(&record.capability_id)
                    {
                        self.capabilities
                            .insert(record.capability_id.clone(), *record);
                    }
                    return Err(err);
                }
                self.capabilities
                    .insert(record.capability_id.clone(), *record);
                Ok(())
            }
            InventoryPayloadV1::HoldWorkspace {
                record_id,
                hold_reason,
                ..
            } => {
                let record = self.workspaces.get_mut(&record_id).ok_or_else(|| {
                    InventoryError::WorkspaceHeld(format!("unknown workspace record {record_id:?}"))
                })?;
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                record.hold_reason = Some(hold_reason);
                record.pid_birth_binding = None;
                Ok(())
            }
            InventoryPayloadV1::HoldCapability {
                capability_id,
                hold_reason,
                updated_unix_ms,
            } => {
                let record = self.capabilities.get_mut(&capability_id).ok_or_else(|| {
                    InventoryError::UnprovenCapabilityClaim(format!(
                        "unknown capability {capability_id:?}"
                    ))
                })?;
                record.effective_classification = CapabilityClassificationV1::Held;
                record.hold_or_downgrade_reason = Some(hold_reason);
                record.installed_binary_sha256 = None;
                record.observed_unix_ms = updated_unix_ms;
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
        let Some(record) = self.workspaces.get(record_id) else {
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
        let failure = if now_unix_ms >= record.lease_expires_unix_ms {
            let reason = format!(
                "workspace {record_id:?} lease expired at {}",
                record.lease_expires_unix_ms
            );
            Some((InventoryError::WorkspaceHeld(reason.clone()), reason))
        } else {
            match verify_private_directory_identity(Path::new(&record.workspace_path), true) {
                Ok(current_id) if current_id == record.workspace_identity => None,
                Ok(current_id) => {
                    let reason = format!(
                        "workspace {record_id:?} physical identity drifted from {:?} to {:?}",
                        record.workspace_identity, current_id
                    );
                    Some((
                        InventoryError::WorkspaceIdentityDrift(reason.clone()),
                        reason,
                    ))
                }
                Err(err) => {
                    let reason = format!("workspace {record_id:?} verification failed: {err}");
                    Some((err, reason))
                }
            }
        };
        if let Some((err, reason)) = failure {
            self.hold_workspace(record_id, reason, now_unix_ms)?;
            return Err(err);
        }
        Ok(&self.workspaces[record_id])
    }

    /// Startup / pre-use / bounded runtime reconciliation. Places any expired,
    /// dead-PID, or physically drifted workspace into `HeldStaleOrUnknown`
    /// without silently deleting or stealing ownership. Persistence failures
    /// remain visible in the held record's reason and never restore readiness.
    pub fn reconcile_workspaces<F>(
        &mut self,
        now_unix_ms: u64,
        is_pid_birth_alive: F,
    ) -> Vec<String>
    where
        F: Fn(u32, u64) -> bool,
    {
        let mut holds = Vec::new();
        for (id, record) in &self.workspaces {
            if record.status != WorkspaceOwnershipStatusV1::Active {
                continue;
            }
            let reason = if now_unix_ms >= record.lease_expires_unix_ms {
                Some("lease expired during reconciliation".to_owned())
            } else if let Some((pid, birth)) = record.pid_birth_binding
                && !is_pid_birth_alive(pid, birth)
            {
                Some(format!(
                    "bound process pid={pid} birth={birth} is not alive"
                ))
            } else {
                match verify_private_directory_identity(Path::new(&record.workspace_path), true) {
                    Ok(actual) if actual == record.workspace_identity => None,
                    Ok(_) | Err(_) => {
                        Some("physical workspace directory missing or identity drifted".to_owned())
                    }
                }
            };
            if let Some(reason) = reason {
                holds.push((id.clone(), reason));
            }
        }
        let mut newly_held = Vec::new();
        for (id, reason) in holds {
            if let Err(err) = self.hold_workspace(&id, reason.clone(), now_unix_ms)
                && let Some(record) = self.workspaces.get_mut(&id)
            {
                record.hold_reason = Some(format!("{reason}; durable hold failed: {err}"));
            }
            newly_held.push(id);
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
        let Some(mut journal) = LockedInventoryJournal::open(journal_path, false)? else {
            let mut registry = Self::new(shared_git_store_identity, operational_checkout_identity)?;
            registry.journal_path = Some(journal_path.to_owned());
            return Ok(registry);
        };
        let (mut registry, _) = Self::replay_journal(
            shared_git_store_identity,
            operational_checkout_identity,
            &mut journal,
        )?;
        registry.verify_or_bind_journal_identity(&journal)?;
        registry.journal_path = Some(journal_path.to_owned());
        if registry.corrupt_or_ambiguous_tail_reason.is_some() {
            return Ok(registry);
        }
        // Release the replay lock before automatic hold transactions reopen it.
        drop(journal);
        registry.reconcile_workspaces(0, |_, _| true);
        Ok(registry)
    }

    fn replay_journal(
        shared_git_store_identity: FsEntryIdentityV1,
        operational_checkout_identity: FsEntryIdentityV1,
        journal: &mut LockedInventoryJournal,
    ) -> InventoryResult<(Self, usize)> {
        let mut registry = Self::new(shared_git_store_identity, operational_checkout_identity)?;
        let bytes = journal.read_from_start()?;
        if bytes.is_empty() {
            return Ok((registry, 0));
        }
        let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
        let mut pending_intents: BTreeMap<String, (String, InventoryPayloadV1)> = BTreeMap::new();
        let mut count = 0usize;
        for (idx, raw_line) in lines.iter().enumerate() {
            count += 1;
            if count > MAX_INVENTORY_RECORDS {
                return Err(InventoryError::JournalCorruptOrBounded(
                    "journal record count exceeds MAX_INVENTORY_RECORDS".to_owned(),
                ));
            }
            let parsed = (|| {
                let line = raw_line.strip_suffix(b"\n").ok_or_else(|| {
                    InventoryError::JournalCorruptOrBounded(
                        "unterminated journal record".to_owned(),
                    )
                })?;
                strict_json_object(line, MAX_INVENTORY_JOURNAL_BYTES as usize)
                    .map_err(|e| InventoryError::JournalCorruptOrBounded(e.to_string()))?;
                serde_json::from_slice::<JournalEntryV1>(line)
                    .map_err(|e| InventoryError::JournalCorruptOrBounded(e.to_string()))
            })();
            let entry = match parsed {
                Ok(entry) => entry,
                Err(_) if idx + 1 == lines.len() => {
                    for (op_id, (digest, payload)) in pending_intents {
                        registry.hold_incomplete(op_id, digest, payload);
                    }
                    let reason = format!("torn_or_corrupt_journal_tail_at_line_{}", idx + 1);
                    registry.corrupt_or_ambiguous_tail_reason = Some(reason.clone());
                    registry.incomplete_ops_held.insert(
                        format!("torn-journal-tail-line-{}", idx + 1),
                        reason.clone(),
                    );
                    for record in registry.workspaces.values_mut() {
                        if record.status == WorkspaceOwnershipStatusV1::Active {
                            record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                            record.hold_reason = Some(format!("fenced_by_{reason}"));
                            record.pid_birth_binding = None;
                        }
                    }
                    // Every positive classification in this schema is evidence
                    // of readiness; none survives an untrustworthy journal tail.
                    for record in registry.capabilities.values_mut() {
                        if !matches!(
                            record.effective_classification,
                            CapabilityClassificationV1::Unknown | CapabilityClassificationV1::Held
                        ) {
                            record.effective_classification = CapabilityClassificationV1::Held;
                            record.hold_or_downgrade_reason = Some(format!("fenced_by_{reason}"));
                            record.installed_binary_sha256 = None;
                        }
                    }
                    return Ok((registry, count));
                }
                Err(err) => return Err(err),
            };
            match entry {
                JournalEntryV1::Intent {
                    operation_id,
                    intent_digest,
                    payload,
                    ..
                } => {
                    if intent_digest != Self::payload_digest(&payload)? {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "intent payload digest mismatch for operation_id {operation_id:?}"
                        )));
                    }
                    if registry.committed_ops.contains_key(&operation_id)
                        || registry.rejected_ops.contains_key(&operation_id)
                        || pending_intents.contains_key(&operation_id)
                    {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "duplicate journal intent for operation_id {operation_id}"
                        )));
                    }
                    pending_intents.insert(operation_id, (intent_digest, payload));
                }
                JournalEntryV1::Result {
                    operation_id,
                    intent_digest,
                    committed,
                    hold_reason,
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
                        registry.apply_payload(payload, true)?;
                        registry.committed_ops.insert(operation_id, intent_digest);
                    } else {
                        if let InventoryPayloadV1::UpsertCapability { mut record } = payload
                            && registry.capabilities.contains_key(&record.capability_id)
                        {
                            let _ = record.verify_and_classify();
                            registry
                                .capabilities
                                .insert(record.capability_id.clone(), *record);
                        }
                        registry
                            .rejected_ops
                            .insert(operation_id, (intent_digest, hold_reason));
                    }
                }
            }
        }

        // Any intent without a matching result is held conservatively across restart.
        for (op_id, (digest, payload)) in pending_intents {
            registry.hold_incomplete(op_id, digest, payload);
        }
        journal.verify_binding(journal.file_bytes)?;
        Ok((registry, count))
    }

    fn hold_incomplete(&mut self, op_id: String, digest: String, payload: InventoryPayloadV1) {
        self.incomplete_ops_held.insert(op_id.clone(), digest);
        match payload {
            InventoryPayloadV1::RegisterWorkspace { mut record } => {
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                record.hold_reason = Some(format!(
                    "incomplete_journal_intent:{op_id}:register_workspace_unconfirmed"
                ));
                record.pid_birth_binding = None;
                if self
                    .workspaces
                    .get(&record.record_id)
                    .is_some_and(|existing| existing.status.blocks_exclusive_claim())
                {
                    let footprint_id = format!("{}#incomplete:{op_id}", record.record_id);
                    record.record_id = footprint_id;
                }
                self.workspaces.insert(record.record_id.clone(), *record);
            }
            InventoryPayloadV1::ReleaseWorkspace {
                record_id,
                released_unix_ms,
                ..
            } => {
                let _ = self.apply_payload(
                    InventoryPayloadV1::HoldWorkspace {
                        record_id,
                        hold_reason: format!(
                            "incomplete_journal_intent:{op_id}:release_workspace_unconfirmed"
                        ),
                        updated_unix_ms: released_unix_ms,
                    },
                    true,
                );
            }
            InventoryPayloadV1::UpsertCapability { mut record } => {
                let reason =
                    format!("incomplete_journal_intent:{op_id}:upsert_capability_unconfirmed");
                let existing = self
                    .capabilities
                    .entry(record.capability_id.clone())
                    .or_insert_with(|| {
                        record.effective_classification = CapabilityClassificationV1::Held;
                        *record
                    });
                existing.effective_classification = CapabilityClassificationV1::Held;
                existing.hold_or_downgrade_reason = Some(reason);
                existing.installed_binary_sha256 = None;
            }
            hold @ (InventoryPayloadV1::HoldWorkspace { .. }
            | InventoryPayloadV1::HoldCapability { .. }) => {
                let _ = self.apply_payload(hold, true);
            }
        }
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
            corrupt_or_ambiguous_tail_reason: self.corrupt_or_ambiguous_tail_reason.clone(),
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
            let tmp = tempfile::tempdir().unwrap();
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
    fn s2a_cross_instance_and_concurrent_shared_journal_exclusive_ownership_serialization() {
        // Exercise physical identity and mutable change collisions independently.
        for shared_change in [false, true] {
            let f = EnvFixture::new();
            let first = f.make_ws_record(
                "sequential-first",
                "sequential-first",
                &f.ws1_dir,
                f.ws1_id,
                "pvonlxyolzsyqopzqrmtopulwnmmvmur",
                "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
                "RUST#efffddad3cb4321cb1308b089f76c206",
                "CHWG-JJ-WORKSPACE-REGISTRY-01",
            );
            let mut second = first.clone();
            second.record_id = "sequential-second".to_owned();
            second.workspace_name = "sequential-second".to_owned();
            second.jj_working_copy_commit_id =
                GitOid::from_hex("9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2").unwrap();
            if shared_change {
                second.workspace_path = f.ws2_dir.to_str().unwrap().to_owned();
                second.workspace_identity = f.ws2_id;
            } else {
                second.jj_working_copy_change_id = "xnslnrmrotuspxtltrpqrzpzrzmtyyok".to_owned();
            }
            let mut owner = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            let mut stale = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            assert_eq!(
                owner
                    .submit_durable(
                        &f.journal_path,
                        "sequential-owner",
                        2_000,
                        InventoryPayloadV1::RegisterWorkspace {
                            record: Box::new(first.clone())
                        }
                    )
                    .unwrap(),
                InventorySubmissionOutcomeV1::Applied
            );
            let collision = stale.submit_durable(
                &f.journal_path,
                "sequential-collision",
                2_001,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(second),
                },
            );
            if shared_change {
                assert!(matches!(
                    collision,
                    Err(InventoryError::SharedMutableJjChange(_))
                ));
            } else {
                assert!(matches!(
                    collision,
                    Err(InventoryError::DuplicatePhysicalWorkspace(_))
                ));
            }
            assert_eq!(stale.workspaces.len(), 1);
            assert_eq!(stale.workspaces.get(&first.record_id), Some(&first));
            let loaded = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            assert_eq!(loaded.workspaces.len(), 1);
            assert_eq!(loaded.workspaces.get(&first.record_id), Some(&first));
            assert!(loaded.incomplete_ops_held.is_empty());

            let racing = EnvFixture::new();
            let mut claims = Vec::new();
            for index in 0..4 {
                let path = if shared_change {
                    let path = racing._tmp.path().join(format!("race-workspace-{index}"));
                    fs::create_dir(&path).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    path
                } else {
                    racing.ws1_dir.clone()
                };
                let identity = verify_private_directory_identity(&path, true).unwrap();
                let mut claim = racing.make_ws_record(
                    &format!("race-record-{index}"),
                    &format!("race-name-{index}"),
                    &path,
                    identity,
                    "pvonlxyolzsyqopzqrmtopulwnmmvmur",
                    "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
                    "RUST#efffddad3cb4321cb1308b089f76c206",
                    "CHWG-JJ-WORKSPACE-REGISTRY-01",
                );
                if !shared_change {
                    claim.jj_working_copy_change_id = format!("distinct-race-change-{index}");
                }
                claim.jj_working_copy_commit_id =
                    GitOid::from_hex(&format!("{:040x}", index + 1)).unwrap();
                claims.push(claim);
            }
            let barrier = std::sync::Barrier::new(4);
            let outcomes = std::thread::scope(|scope| {
                let mut threads = Vec::new();
                for (index, claim) in claims.into_iter().enumerate() {
                    let barrier = &barrier;
                    let journal_path = &racing.journal_path;
                    let store_id = racing.store_id;
                    let op_id = racing.op_id;
                    threads.push(scope.spawn(move || {
                        let mut registry =
                            ContinuousInventoryRegistryV1::new(store_id, op_id).unwrap();
                        barrier.wait();
                        registry.submit_durable(
                            journal_path,
                            &format!("race-operation-{index}"),
                            3_000,
                            InventoryPayloadV1::RegisterWorkspace {
                                record: Box::new(claim),
                            },
                        )
                    }));
                }
                threads
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .collect::<Vec<_>>()
            });
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| matches!(outcome, Ok(InventorySubmissionOutcomeV1::Applied)))
                    .count(),
                1
            );
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| if shared_change {
                        matches!(outcome, Err(InventoryError::SharedMutableJjChange(_)))
                    } else {
                        matches!(outcome, Err(InventoryError::DuplicatePhysicalWorkspace(_)))
                    })
                    .count(),
                3
            );
            let loaded = ContinuousInventoryRegistryV1::load_and_reconcile(
                racing.store_id,
                racing.op_id,
                &racing.journal_path,
            )
            .unwrap();
            assert_eq!(loaded.workspaces.len(), 1);
            assert_eq!(
                loaded.workspaces.values().next().unwrap().status,
                WorkspaceOwnershipStatusV1::Active
            );
            assert!(loaded.incomplete_ops_held.is_empty());
            assert_eq!(loaded.committed_ops.len(), 1);
        }
    }

    #[test]
    fn s2a_no_in_memory_ownership_effect_before_durable_result_and_prewrite_reservation() {
        let f = EnvFixture::new();
        let first = f.make_ws_record(
            "failed-registration",
            "failed-registration",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry.fail_next_result_append = true;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "failed-register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(first.clone())
                }
            ),
            Err(InventoryError::Io(_))
        ));
        assert!(!registry.fail_next_result_append);
        assert_eq!(
            registry.workspaces[&first.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(registry.incomplete_ops_held.contains_key("failed-register"));
        assert!(registry.committed_ops.is_empty());
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            loaded.workspaces[&first.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(loaded.incomplete_ops_held.contains_key("failed-register"));

        let f = EnvFixture::new();
        let owner = f.make_ws_record(
            "active-owner",
            "active-owner",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let owner_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(owner.clone()),
        };
        registry
            .submit_durable(
                &f.journal_path,
                "active-registration",
                2_000,
                owner_payload.clone(),
            )
            .unwrap();
        let mut collision = owner.clone();
        collision.workspace_name = "crashed-collision".to_owned();
        collision.workspace_path = f.ws2_dir.to_str().unwrap().to_owned();
        collision.workspace_identity = f.ws2_id;
        registry.fail_next_result_append = true;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "failed-collision",
                2_001,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(collision)
                }
            ),
            Err(InventoryError::Io(_))
        ));
        assert_eq!(registry.workspaces.get(&owner.record_id), Some(&owner));
        assert!(
            registry
                .incomplete_ops_held
                .contains_key("failed-collision")
        );
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(loaded.workspaces.get(&owner.record_id), Some(&owner));
        assert!(loaded.incomplete_ops_held.contains_key("failed-collision"));
        assert!(registry.corrupt_or_ambiguous_tail_reason().is_some());
        // A handle with an ambiguous append cannot attempt another mutation.
        // Explicit recovery creates a new handle from the complete prefix.
        registry = loaded;
        registry.fail_next_result_append = true;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "failed-release",
                2_002,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: owner.record_id.clone(),
                    actor: owner.owner_actor.clone(),
                    released_unix_ms: 2_002
                }
            ),
            Err(InventoryError::Io(_))
        ));
        assert_eq!(
            registry.workspaces[&owner.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(registry.incomplete_ops_held.contains_key("failed-release"));
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            loaded.workspaces[&owner.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(loaded.incomplete_ops_held.contains_key("failed-release"));
        assert!(registry.corrupt_or_ambiguous_tail_reason().is_some());
        registry = loaded;

        // A local reconciliation hold must survive an authoritative replay.
        assert_eq!(
            registry.reconcile_workspaces(70_000, |_, _| true),
            Vec::<String>::new()
        );
        assert_eq!(
            registry
                .submit_durable(
                    &f.journal_path,
                    "active-registration",
                    70_001,
                    owner_payload
                )
                .unwrap(),
            InventorySubmissionOutcomeV1::IdempotentReplay
        );
        assert_eq!(
            registry.workspaces[&owner.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );

        let f = EnvFixture::new();
        let owner = f.make_ws_record(
            "reservation-owner",
            "reservation-owner",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "reservation-owner",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(owner),
                },
            )
            .unwrap();
        let second = f.make_ws_record(
            "reservation-second",
            "reservation-second",
            &f.ws2_dir,
            f.ws2_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(second),
        };
        let digest = ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap();
        let intent = JournalEntryV1::Intent {
            operation_id: "byte-reserved".to_owned(),
            intent_digest: digest.clone(),
            recorded_unix_ms: 4_000,
            payload: payload.clone(),
        };
        let result = JournalEntryV1::Result {
            operation_id: "byte-reserved".to_owned(),
            intent_digest: digest,
            completed_unix_ms: 4_000,
            committed: true,
            hold_reason: None,
        };
        let intent_bytes = serde_json::to_vec(&intent).unwrap().len() as u64 + 1;
        let result_bytes = serde_json::to_vec(&result).unwrap().len() as u64 + 1;
        let target_bytes = MAX_INVENTORY_JOURNAL_BYTES - intent_bytes - result_bytes + 1;
        assert!(target_bytes + intent_bytes < MAX_INVENTORY_JOURNAL_BYTES);
        assert!(target_bytes + intent_bytes + result_bytes > MAX_INVENTORY_JOURNAL_BYTES);
        let mut padded = fs::read(&f.journal_path).unwrap();
        assert_eq!(padded.pop(), Some(b'\n'));
        assert!(padded.len() < target_bytes as usize - 1);
        padded.resize(target_bytes as usize - 1, b' ');
        padded.push(b'\n');
        fs::write(&f.journal_path, &padded).unwrap();
        fs::set_permissions(&f.journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = registry.inspect_discovery_snapshot();
        let committed_before = registry.committed_ops.clone();
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(loaded.inspect_discovery_snapshot(), before);
        assert_eq!(loaded.committed_ops, committed_before);
        assert!(matches!(
            registry.submit_durable(&f.journal_path, "byte-reserved", 4_000, payload),
            Err(InventoryError::JournalCorruptOrBounded(_))
        ));
        assert_eq!(fs::metadata(&f.journal_path).unwrap().len(), target_bytes);
        assert_eq!(fs::read(&f.journal_path).unwrap(), padded);
        assert_eq!(registry.inspect_discovery_snapshot(), before);
        assert_eq!(registry.committed_ops, committed_before);
    }

    fn s2b_workspace(f: &EnvFixture, second: bool) -> WorkspaceOwnershipRecordV1 {
        let (id, path, identity, change, commit) = if second {
            (
                "s2b-second",
                &f.ws2_dir,
                f.ws2_id,
                "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
                "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            )
        } else {
            (
                "s2b-first",
                &f.ws1_dir,
                f.ws1_id,
                "pvonlxyolzsyqopzqrmtopulwnmmvmur",
                "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            )
        };
        f.make_ws_record(
            id,
            id,
            path,
            identity,
            change,
            commit,
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        )
    }

    fn s2b_capability(id: &str) -> CapabilityProvenanceRecordV1 {
        let source = GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35").unwrap();
        let binary = Sha256Digest::from_hex(
            "142c504a5f85210670c78e3671b453f0a5866383764a4b8306c4f5eac416e528",
        )
        .unwrap();
        CapabilityProvenanceRecordV1 {
            capability_id: id.to_owned(),
            handler_symbol: "verify_workspace_for_mutation".to_owned(),
            source_module_path: "crates/chinwag-cli/src/workspace_capability_inventory.rs"
                .to_owned(),
            claimed_classification: CapabilityClassificationV1::Operational,
            handler_wired: true,
            unit_tests_passed: true,
            source_commit: source,
            source_tree: GitOid::from_hex("69c3b294b10a74190b894e2be486138c61772d83").unwrap(),
            source_tree_clean: true,
            accepted_source_commit: Some(source),
            compiled_artifact_sha256: Some(binary),
            installed_binary_path: Some("/test/chinwag".to_owned()),
            installed_binary_sha256: Some(binary),
            runtime_health_verified: true,
            admission_authority_digest: Some(binary),
            task_ref: Some(sample_task_ref("CHWG-JJ-WORKSPACE-REGISTRY-01")),
            observed_unix_ms: 2_000,
            effective_classification: CapabilityClassificationV1::Unknown,
            hold_or_downgrade_reason: None,
        }
    }

    fn read_journal_entries(path: &Path) -> Vec<JournalEntryV1> {
        fs::read(path)
            .unwrap()
            .split_inclusive(|byte| *byte == b'\n')
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    #[test]
    fn s2b_replay_survives_deleted_released_workspace_and_holds_moved_active_workspace() {
        let f = EnvFixture::new();
        let released = s2b_workspace(&f, false);
        let active = s2b_workspace(&f, true);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        for (op, record) in [
            ("register-released", &released),
            ("register-active", &active),
        ] {
            registry
                .submit_durable(
                    &f.journal_path,
                    op,
                    2_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(record.clone()),
                    },
                )
                .unwrap();
        }
        registry
            .submit_durable(
                &f.journal_path,
                "release-first",
                3_000,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: released.record_id.clone(),
                    actor: released.owner_actor.clone(),
                    released_unix_ms: 3_000,
                },
            )
            .unwrap();
        fs::remove_dir(&f.ws1_dir).unwrap();
        fs::rename(&f.ws2_dir, f._tmp.path().join("moved-active")).unwrap();
        // Raw replay remains independent of both missing directories.
        let mut journal = LockedInventoryJournal::open(&f.journal_path, false)
            .unwrap()
            .unwrap();
        let (replayed, _) =
            ContinuousInventoryRegistryV1::replay_journal(f.store_id, f.op_id, &mut journal)
                .unwrap();
        assert_eq!(
            replayed.workspaces[&active.record_id].status,
            WorkspaceOwnershipStatusV1::Active
        );
        drop(journal);
        let recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            recovered.workspaces[&released.record_id].status,
            WorkspaceOwnershipStatusV1::Released
        );
        assert_eq!(
            recovered.workspaces[&active.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(
            recovered.workspaces[&active.record_id]
                .hold_reason
                .as_ref()
                .unwrap()
                .contains("directory missing")
        );
        let bytes = fs::read(&f.journal_path).unwrap();
        let again =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            again.inspect_discovery_snapshot(),
            recovered.inspect_discovery_snapshot()
        );
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("\"op\":\"hold_workspace\"")
        );
        // A new live admission still rejects the missing path.
        let mut missing = active;
        missing.record_id = "missing-live-admission".to_owned();
        assert!(
            registry
                .submit_durable(
                    &f.journal_path,
                    "missing-live",
                    4_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(missing)
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn s2b_durable_workspace_hold_from_verify_workspace_for_mutation_survives_restart() {
        // Cover lease, inode drift, and missing-directory failures separately.
        for failure in 0..3 {
            let f = EnvFixture::new();
            let record = s2b_workspace(&f, false);
            let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            registry
                .submit_durable(
                    &f.journal_path,
                    "register",
                    2_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(record.clone()),
                    },
                )
                .unwrap();
            let now = match failure {
                0 => 70_000,
                1 => {
                    fs::rename(&f.ws1_dir, f._tmp.path().join("old-inode")).unwrap();
                    fs::create_dir(&f.ws1_dir).unwrap();
                    fs::set_permissions(&f.ws1_dir, fs::Permissions::from_mode(0o700)).unwrap();
                    3_000
                }
                _ => {
                    fs::remove_dir(&f.ws1_dir).unwrap();
                    3_000
                }
            };
            assert!(
                registry
                    .verify_workspace_for_mutation(
                        &record.record_id,
                        &record.owner_actor,
                        &record.task_ref,
                        now
                    )
                    .is_err()
            );
            let held = registry.workspaces[&record.record_id].clone();
            assert_eq!(held.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
            assert_eq!(held.pid_birth_binding, None);
            // Restore a valid directory binding before restart: only the journal
            // can now explain the hold (especially the expired synthetic lease).
            if failure == 1 {
                fs::remove_dir(&f.ws1_dir).unwrap();
                fs::rename(f._tmp.path().join("old-inode"), &f.ws1_dir).unwrap();
            }
            let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            assert_eq!(recovered.workspaces[&record.record_id], held);
            let bytes = fs::read(&f.journal_path).unwrap();
            assert_eq!(
                bytes
                    .split(|b| *b == b'\n')
                    .filter(|line| !line.is_empty())
                    .count(),
                4
            );
            let again = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            assert_eq!(again.workspaces[&record.record_id], held);
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        }
        // The same transition works without a journal for an in-memory registry.
        let f = EnvFixture::new();
        let record = s2b_workspace(&f, false);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .apply_payload(
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(record.clone()),
                },
                false,
            )
            .unwrap();
        assert!(
            registry
                .verify_workspace_for_mutation(
                    &record.record_id,
                    &record.owner_actor,
                    &record.task_ref,
                    70_000
                )
                .is_err()
        );
        assert_eq!(
            registry.workspaces[&record.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(!f.journal_path.exists());
    }

    #[test]
    fn s2b_incomplete_release_and_upsert_intents_place_targets_in_conservative_hold_on_recovery() {
        let f = EnvFixture::new();
        let record = s2b_workspace(&f, false);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(record.clone()),
                },
            )
            .unwrap();
        let ready = s2b_capability("cap-existing");
        let unaffected = s2b_capability("cap-unaffected");
        for cap in [&ready, &unaffected] {
            registry
                .submit_durable(
                    &f.journal_path,
                    &format!("register-{}", cap.capability_id),
                    2_000,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(cap.clone()),
                    },
                )
                .unwrap();
        }
        let mut replacement = ready.clone();
        replacement.handler_symbol = "unconfirmed_replacement".to_owned();
        let pending = [
            (
                "pending-release",
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: record.record_id.clone(),
                    actor: record.owner_actor.clone(),
                    released_unix_ms: 3_000,
                },
            ),
            (
                "pending-existing",
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(replacement),
                },
            ),
            (
                "pending-new",
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(s2b_capability("cap-new")),
                },
            ),
            (
                "pending-register",
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(s2b_workspace(&f, true)),
                },
            ),
        ];
        for (operation_id, payload) in pending {
            let intent = JournalEntryV1::Intent {
                operation_id: operation_id.to_owned(),
                intent_digest: ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap(),
                recorded_unix_ms: 3_000,
                payload,
            };
            ContinuousInventoryRegistryV1::append_journal_entry(&f.journal_path, &intent).unwrap();
        }
        let bytes = fs::read(&f.journal_path).unwrap();
        for _ in 0..2 {
            let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            let held = &recovered.workspaces[&record.record_id];
            assert_eq!(held.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
            assert_eq!(held.pid_birth_binding, None);
            assert_eq!(
                held.hold_reason.as_deref(),
                Some("incomplete_journal_intent:pending-release:release_workspace_unconfirmed")
            );
            for (id, op) in [
                ("cap-existing", "pending-existing"),
                ("cap-new", "pending-new"),
            ] {
                let cap = &recovered.capabilities[id];
                assert_eq!(
                    cap.effective_classification,
                    CapabilityClassificationV1::Held
                );
                assert_eq!(cap.installed_binary_sha256, None);
                assert_eq!(
                    cap.hold_or_downgrade_reason,
                    Some(format!(
                        "incomplete_journal_intent:{op}:upsert_capability_unconfirmed"
                    ))
                );
            }
            assert_eq!(
                recovered.capabilities["cap-existing"].handler_symbol,
                ready.handler_symbol
            );
            assert_eq!(
                recovered.capabilities["cap-unaffected"].effective_classification,
                CapabilityClassificationV1::Operational
            );
            assert!(
                recovered.workspaces["s2b-second"]
                    .hold_reason
                    .as_ref()
                    .unwrap()
                    .contains("pending-register")
            );
            assert_eq!(recovered.incomplete_ops_held.len(), 4);
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        }
    }

    #[test]
    fn s2b_negative_capability_observation_downgrades_prior_ready_classification_durably() {
        for classification in [
            CapabilityClassificationV1::Implemented,
            CapabilityClassificationV1::Installed,
            CapabilityClassificationV1::Operational,
            CapabilityClassificationV1::Authorized,
        ] {
            for failure in 0..3 {
                let f = EnvFixture::new();
                let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                let mut cap = s2b_capability("cap-1");
                cap.claimed_classification = classification;
                registry
                    .submit_durable(
                        &f.journal_path,
                        "prior-ready",
                        2_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(cap.clone()),
                        },
                    )
                    .unwrap();
                let mut negative = cap.clone();
                negative.claimed_classification = CapabilityClassificationV1::Operational;
                match failure {
                    0 => negative.source_tree_clean = false,
                    1 => negative.installed_binary_sha256 = None,
                    _ => negative.handler_wired = false,
                }
                let error = registry
                    .submit_durable(
                        &f.journal_path,
                        "negative-observation",
                        3_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(negative.clone()),
                        },
                    )
                    .unwrap_err();
                let held = registry.capabilities["cap-1"].clone();
                assert_eq!(
                    held.effective_classification,
                    CapabilityClassificationV1::Held
                );
                let mut expected = negative.clone();
                assert_eq!(expected.verify_and_classify(), Err(error));
                assert_eq!(held, expected);
                assert_eq!(held.installed_binary_sha256, None);
                let bytes = fs::read(&f.journal_path).unwrap();
                let entries = read_journal_entries(&f.journal_path);
                assert_eq!(entries.len(), 4);
                assert!(matches!(
                    &entries[3],
                    JournalEntryV1::Result { operation_id, committed: false, hold_reason: Some(_), .. }
                        if operation_id == "negative-observation"
                ));
                assert!(!registry.committed_ops.contains_key("negative-observation"));
                assert!(registry.rejected_ops.contains_key("negative-observation"));
                for _ in 0..2 {
                    let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                        f.store_id,
                        f.op_id,
                        &f.journal_path,
                    )
                    .unwrap();
                    assert_eq!(recovered.capabilities["cap-1"], held);
                    assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
                }
                // Explicit Held observations remain admissible with dirty source
                // and invalid binaries, and provide a reason even if omitted.
                negative.claimed_classification = CapabilityClassificationV1::Held;
                negative.source_tree_clean = false;
                negative.installed_binary_sha256 = None;
                negative.hold_or_downgrade_reason = None;
                registry
                    .submit_durable(
                        &f.journal_path,
                        "explicit-held",
                        4_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(negative),
                        },
                    )
                    .unwrap();
                let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                    f.store_id,
                    f.op_id,
                    &f.journal_path,
                )
                .unwrap();
                assert_eq!(
                    recovered.capabilities["cap-1"].effective_classification,
                    CapabilityClassificationV1::Held
                );
                assert!(
                    recovered.capabilities["cap-1"]
                        .hold_or_downgrade_reason
                        .as_ref()
                        .is_some_and(|reason| !reason.is_empty())
                );
                // Direct in-memory updates also retain negative observations.
                let mut memory = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                memory
                    .apply_payload(
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(cap.clone()),
                        },
                        false,
                    )
                    .unwrap();
                cap.handler_wired = false;
                assert!(
                    memory
                        .apply_payload(
                            InventoryPayloadV1::UpsertCapability {
                                record: Box::new(cap)
                            },
                            false
                        )
                        .is_err()
                );
                assert_eq!(
                    memory.capabilities["cap-1"].effective_classification,
                    CapabilityClassificationV1::Held
                );
                assert_eq!(memory.capabilities["cap-1"].installed_binary_sha256, None);
            }
        }
    }

    #[test]
    fn s2a_rejects_pre_intent_without_poisoning_sequence_or_writing_pending() {
        let f = EnvFixture::new();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let mut cap = s2b_capability("cap-dirty-s2a");
        cap.source_tree_clean = false;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "reusable-operation",
                2_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(cap.clone())
                }
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        assert!(registry.capabilities.is_empty());
        assert!(registry.committed_ops.is_empty());
        assert!(registry.incomplete_ops_held.is_empty());
        assert!(fs::read(&f.journal_path).unwrap().is_empty());
        cap.source_tree_clean = true;
        assert_eq!(
            registry
                .submit_durable(
                    &f.journal_path,
                    "reusable-operation",
                    2_001,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(cap)
                    }
                )
                .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
    }

    #[test]
    fn registry_rejects_cross_journal_path_mutation_and_refresh() {
        let f = EnvFixture::new();
        let owner = s2b_workspace(&f, false);
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(owner.clone()),
        };
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(&f.journal_path, "op-bind", 2_000, payload.clone())
            .unwrap();
        let before = registry.inspect_discovery_snapshot();
        let binding = registry.bound_journal_identity.clone();
        let committed = registry.committed_ops.clone();
        let journal_a_bytes = fs::read(&f.journal_path).unwrap();

        // Exercise both a different leaf name and a different parent identity.
        // Invalid foreign contents prove identity rejection precedes replay.
        for journal_b in [
            f.journal_path.with_file_name("journal-b.jsonl"),
            f.ws2_dir.join(f.journal_path.file_name().unwrap()),
        ] {
            let journal_b_bytes = b"foreign journal must never be replayed\n";
            fs::write(&journal_b, journal_b_bytes).unwrap();
            fs::set_permissions(&journal_b, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                registry.submit_durable(&journal_b, "op-foreign", 3_000, payload.clone()),
                Err(InventoryError::InvalidPath(_))
            ));
            assert!(matches!(
                registry.refresh_from_journal(&journal_b),
                Err(InventoryError::InvalidPath(_))
            ));
            let mut holding = registry.clone();
            holding.journal_path = Some(journal_b.clone());
            assert!(matches!(
                holding.hold_workspace(&owner.record_id, "foreign hold".to_owned(), 3_000),
                Err(InventoryError::InvalidPath(_))
            ));
            assert_eq!(holding.inspect_discovery_snapshot(), before);
            assert_eq!(registry.inspect_discovery_snapshot(), before);
            assert_eq!(registry.bound_journal_identity, binding);
            assert_eq!(registry.committed_ops, committed);
            assert_eq!(fs::read(&f.journal_path).unwrap(), journal_a_bytes);
            assert_eq!(fs::read(&journal_b).unwrap(), journal_b_bytes);
        }

        registry.refresh_from_journal(&f.journal_path).unwrap();
        assert_eq!(registry.bound_journal_identity, binding);
        // The same pathname with a replacement inode is also a foreign journal.
        fs::rename(&f.journal_path, f.journal_path.with_extension("original")).unwrap();
        fs::write(&f.journal_path, &journal_a_bytes).unwrap();
        fs::set_permissions(&f.journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            registry.refresh_from_journal(&f.journal_path),
            Err(InventoryError::InvalidPath(_))
        ));
        assert_eq!(registry.inspect_discovery_snapshot(), before);
        assert_eq!(registry.bound_journal_identity, binding);
        assert_eq!(fs::read(&f.journal_path).unwrap(), journal_a_bytes);
    }

    #[test]
    fn rejected_operation_id_cannot_be_reused_with_same_or_different_payload_and_pre_admission_leaves_no_footprint()
     {
        let f = EnvFixture::new();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let ready = s2b_capability("cap-1");
        let mut dirty = ready.clone();
        dirty.source_tree_clean = false;
        let dirty_payload = InventoryPayloadV1::UpsertCapability {
            record: Box::new(dirty.clone()),
        };
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-pre-reject",
                2_000,
                dirty_payload.clone()
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        assert!(fs::read(&f.journal_path).unwrap().is_empty());
        assert!(!registry.rejected_ops.contains_key("op-pre-reject"));
        assert!(registry.capabilities.is_empty());
        assert!(registry.incomplete_ops_held.is_empty());
        let ready_payload = InventoryPayloadV1::UpsertCapability {
            record: Box::new(ready.clone()),
        };
        // Pre-admission rejection does not consume the operation ID.
        registry
            .submit_durable(
                &f.journal_path,
                "op-pre-reject",
                2_001,
                ready_payload.clone(),
            )
            .unwrap();
        let before_invalid = fs::read(&f.journal_path).unwrap();
        let mut invalid = ready.clone();
        invalid.handler_symbol.clear();
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-invalid-field",
                2_002,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(invalid)
                }
            ),
            Err(InventoryError::InvalidIdentifier(_))
        ));
        assert_eq!(fs::read(&f.journal_path).unwrap(), before_invalid);
        assert!(!registry.rejected_ops.contains_key("op-invalid-field"));
        assert_eq!(
            registry.capabilities["cap-1"].effective_classification,
            CapabilityClassificationV1::Operational
        );

        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-cap-dirty",
                3_000,
                dirty_payload.clone()
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        let entries = read_journal_entries(&f.journal_path);
        assert_eq!(entries.len(), 4);
        assert!(matches!(
            &entries[2],
            JournalEntryV1::Intent { operation_id, payload, .. }
                if operation_id == "op-cap-dirty" && payload == &dirty_payload
        ));
        assert!(matches!(
            &entries[3],
            JournalEntryV1::Result { operation_id, committed: false, hold_reason: Some(_), .. }
                if operation_id == "op-cap-dirty"
        ));
        let held = registry.capabilities["cap-1"].clone();
        assert_eq!(
            held.effective_classification,
            CapabilityClassificationV1::Held
        );
        assert_eq!(held.installed_binary_sha256, None);
        assert!(!held.source_tree_clean);
        assert!(registry.rejected_ops.contains_key("op-cap-dirty"));
        let rejected_bytes = fs::read(&f.journal_path).unwrap();
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(recovered.capabilities["cap-1"], held);
        assert_eq!(recovered.rejected_ops, registry.rejected_ops);
        for handle in [&mut registry, &mut recovered] {
            for (payload, digest_matches) in [
                (dirty_payload.clone(), true),
                (ready_payload.clone(), false),
            ] {
                let error = handle
                    .submit_durable(&f.journal_path, "op-cap-dirty", 3_001, payload)
                    .unwrap_err();
                assert!(
                    matches!(error, InventoryError::ConflictingReplay(ref reason)
                    if reason.contains(&format!("digest_match={digest_matches}")))
                );
                assert_eq!(handle.capabilities["cap-1"], held);
                assert_eq!(fs::read(&f.journal_path).unwrap(), rejected_bytes);
            }
        }

        let owner = s2b_workspace(&f, false);
        registry
            .submit_durable(
                &f.journal_path,
                "op-ws-owner",
                4_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(owner.clone()),
                },
            )
            .unwrap();
        let mut conflict = owner;
        conflict.record_id = "ws-conflict".to_owned();
        conflict.workspace_name = "ws-conflict".to_owned();
        let conflict_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(conflict),
        };
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-ws-conflict",
                4_001,
                conflict_payload.clone()
            ),
            Err(InventoryError::DuplicatePhysicalWorkspace(_))
        ));
        let entries = read_journal_entries(&f.journal_path);
        assert_eq!(entries.len(), 8);
        assert!(matches!(
            &entries[6],
            JournalEntryV1::Intent { operation_id, .. } if operation_id == "op-ws-conflict"
        ));
        assert!(matches!(
            &entries[7],
            JournalEntryV1::Result { operation_id, committed: false, hold_reason: Some(_), .. }
                if operation_id == "op-ws-conflict"
        ));
        let rejected_bytes = fs::read(&f.journal_path).unwrap();
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        let different_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(s2b_workspace(&f, true)),
        };
        for handle in [&mut registry, &mut recovered] {
            assert!(handle.rejected_ops.contains_key("op-ws-conflict"));
            for payload in [conflict_payload.clone(), different_payload.clone()] {
                assert!(matches!(
                    handle.submit_durable(&f.journal_path, "op-ws-conflict", 4_002, payload),
                    Err(InventoryError::ConflictingReplay(_))
                ));
                assert_eq!(fs::read(&f.journal_path).unwrap(), rejected_bytes);
            }
        }
    }

    #[test]
    fn incomplete_register_workspace_colliding_record_id_and_released_record_id_preserve_both_footprints()
     {
        let f = EnvFixture::new();
        let mut owner = s2b_workspace(&f, false);
        owner.record_id = "ws-1".to_owned();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "op-owner",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(owner.clone()),
                },
            )
            .unwrap();
        let mut collision = s2b_workspace(&f, true);
        collision.record_id = owner.record_id.clone();
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(collision.clone()),
        };
        ContinuousInventoryRegistryV1::append_journal_entry(
            &f.journal_path,
            &JournalEntryV1::Intent {
                operation_id: "op-incomplete-collision".to_owned(),
                intent_digest: ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap(),
                recorded_unix_ms: 3_000,
                payload,
            },
        )
        .unwrap();
        let bytes = fs::read(&f.journal_path).unwrap();
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(recovered.workspaces["ws-1"], owner);
        let footprint_id = "ws-1#incomplete:op-incomplete-collision";
        let footprint = &recovered.workspaces[footprint_id];
        assert_eq!(
            footprint.status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert_eq!(footprint.workspace_identity, collision.workspace_identity);
        assert_eq!(footprint.workspace_name, collision.workspace_name);
        assert_eq!(
            footprint.jj_working_copy_change_id,
            collision.jj_working_copy_change_id
        );
        assert_eq!(
            footprint.jj_working_copy_commit_id,
            collision.jj_working_copy_commit_id
        );
        assert_eq!(footprint.pid_birth_binding, None);
        assert_eq!(recovered.workspaces.len(), 2);
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        let third_path = f._tmp.path().join("ws-third");
        fs::create_dir(&third_path).unwrap();
        fs::set_permissions(&third_path, fs::Permissions::from_mode(0o700)).unwrap();
        let third_identity = verify_private_directory_identity(&third_path, true).unwrap();

        // Independently collide with the held inode, name, change, and commit.
        for conflict in 0..4 {
            let mut claim = collision.clone();
            claim.record_id = "ws-2".to_owned();
            claim.workspace_path = third_path.to_str().unwrap().to_owned();
            claim.workspace_identity = third_identity;
            claim.workspace_name = "ws-2".to_owned();
            claim.jj_working_copy_change_id = "unique-third-change".to_owned();
            claim.jj_working_copy_commit_id =
                GitOid::from_hex("1111111111111111111111111111111111111111").unwrap();
            match conflict {
                0 => {
                    claim.workspace_path.clone_from(&collision.workspace_path);
                    claim.workspace_identity = collision.workspace_identity;
                }
                1 => claim.workspace_name.clone_from(&collision.workspace_name),
                2 => claim
                    .jj_working_copy_change_id
                    .clone_from(&collision.jj_working_copy_change_id),
                _ => claim.jj_working_copy_commit_id = collision.jj_working_copy_commit_id,
            }
            let error = recovered
                .submit_durable(
                    &f.journal_path,
                    &format!("op-claim-{conflict}"),
                    4_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(claim),
                    },
                )
                .unwrap_err();
            match conflict {
                0 => assert!(matches!(
                    error,
                    InventoryError::DuplicatePhysicalWorkspace(_)
                )),
                1 => assert!(matches!(error, InventoryError::DuplicateWorkspaceName(_))),
                _ => assert!(matches!(error, InventoryError::SharedMutableJjChange(_))),
            }
            assert_eq!(recovered.workspaces["ws-1"], owner);
            assert_eq!(recovered.workspaces.len(), 2);
        }
        let before = fs::read(&f.journal_path).unwrap();
        assert!(matches!(
            recovered.submit_durable(
                &f.journal_path,
                "op-incomplete-collision",
                4_001,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(collision)
                }
            ),
            Err(InventoryError::IncompleteIntentHeld(_))
        ));
        assert_eq!(fs::read(&f.journal_path).unwrap(), before);

        let f = EnvFixture::new();
        let mut released = s2b_workspace(&f, false);
        released.record_id = "ws-rel".to_owned();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "op-register-released",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(released.clone()),
                },
            )
            .unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "op-release",
                3_000,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: released.record_id,
                    actor: released.owner_actor,
                    released_unix_ms: 3_000,
                },
            )
            .unwrap();
        let mut replacement = s2b_workspace(&f, true);
        replacement.record_id = "ws-rel".to_owned();
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(replacement.clone()),
        };
        ContinuousInventoryRegistryV1::append_journal_entry(
            &f.journal_path,
            &JournalEntryV1::Intent {
                operation_id: "op-incomplete-reregister".to_owned(),
                intent_digest: ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap(),
                recorded_unix_ms: 4_000,
                payload,
            },
        )
        .unwrap();
        let bytes = fs::read(&f.journal_path).unwrap();
        let recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        let held = &recovered.workspaces["ws-rel"];
        assert_eq!(held.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
        assert_eq!(held.workspace_identity, replacement.workspace_identity);
        assert_eq!(held.workspace_name, replacement.workspace_name);
        assert_eq!(
            held.jj_working_copy_change_id,
            replacement.jj_working_copy_change_id
        );
        assert_eq!(
            held.jj_working_copy_commit_id,
            replacement.jj_working_copy_commit_id
        );
        assert_eq!(held.pid_birth_binding, None);
        assert_eq!(
            held.hold_reason.as_deref(),
            Some(
                "incomplete_journal_intent:op-incomplete-reregister:register_workspace_unconfirmed"
            )
        );
        assert_eq!(recovered.workspaces.len(), 1);
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
    }

    #[test]
    fn torn_journal_tail_preserves_valid_prefix_for_discovery_fences_active_entries_and_blocks_mutations_without_truncating()
     {
        for tail in [
            b"{\"record_kind\":\"intent\"".as_slice(),
            b"not JSON\n".as_slice(),
            b"{\"record_kind\":\"intent\"}\n".as_slice(),
            b"{\"record_kind\":\"intent\",\"record_kind\":\"result\"}\n".as_slice(),
        ] {
            let f = EnvFixture::new();
            let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            let mut owner = s2b_workspace(&f, false);
            owner.record_id = "ws-1".to_owned();
            registry
                .submit_durable(
                    &f.journal_path,
                    "op-owner",
                    2_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(owner),
                    },
                )
                .unwrap();
            registry
                .submit_durable(
                    &f.journal_path,
                    "op-ready",
                    2_000,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(s2b_capability("cap-1")),
                    },
                )
                .unwrap();
            let pending = InventoryPayloadV1::RegisterWorkspace {
                record: Box::new(s2b_workspace(&f, true)),
            };
            ContinuousInventoryRegistryV1::append_journal_entry(
                &f.journal_path,
                &JournalEntryV1::Intent {
                    operation_id: "op-pending-prefix".to_owned(),
                    intent_digest: ContinuousInventoryRegistryV1::payload_digest(&pending).unwrap(),
                    recorded_unix_ms: 3_000,
                    payload: pending,
                },
            )
            .unwrap();
            let mut bytes = fs::read(&f.journal_path).unwrap();
            bytes.extend_from_slice(tail);
            fs::write(&f.journal_path, &bytes).unwrap();
            let size = fs::metadata(&f.journal_path).unwrap().len();
            // Reconciliation would ordinarily persist a hold for this missing
            // path. Torn-tail recovery must remain a discovery-only operation.
            fs::remove_dir(&f.ws1_dir).unwrap();
            let mut recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            let snapshot = recovered.inspect_discovery_snapshot();
            let reason = "torn_or_corrupt_journal_tail_at_line_6";
            assert_eq!(
                snapshot.corrupt_or_ambiguous_tail_reason.as_deref(),
                Some(reason)
            );
            assert_eq!(recovered.corrupt_or_ambiguous_tail_reason(), Some(reason));
            let owner = snapshot
                .workspaces
                .iter()
                .find(|w| w.record_id == "ws-1")
                .unwrap();
            assert_eq!(owner.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
            assert_eq!(owner.pid_birth_binding, None);
            assert_eq!(owner.hold_reason, Some(format!("fenced_by_{reason}")));
            let capability = snapshot
                .capabilities
                .iter()
                .find(|c| c.capability_id == "cap-1")
                .unwrap();
            assert_eq!(
                capability.effective_classification,
                CapabilityClassificationV1::Held
            );
            assert_eq!(capability.installed_binary_sha256, None);
            assert_eq!(
                capability.hold_or_downgrade_reason,
                Some(format!("fenced_by_{reason}"))
            );
            assert_eq!(
                snapshot.incomplete_operations_held,
                vec![
                    "op-pending-prefix".to_owned(),
                    "torn-journal-tail-line-6".to_owned()
                ]
            );
            assert_eq!(snapshot.workspaces.len(), 2);
            assert_eq!(
                recovered.workspaces["s2b-second"].status,
                WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
            );
            assert_eq!(fs::metadata(&f.journal_path).unwrap().len(), size);
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);

            // Both a freshly loaded handle and a stale live handle fail closed.
            for handle in [&mut recovered, &mut registry] {
                assert!(matches!(
                    handle.submit_durable(
                        &f.journal_path,
                        "op-after-tail",
                        4_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(s2b_capability("cap-after-tail"))
                        }
                    ),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                assert!(matches!(
                    handle.hold_workspace("ws-1", "after tail".to_owned(), 4_001),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                handle.refresh_from_journal(&f.journal_path).unwrap();
                assert_eq!(handle.inspect_discovery_snapshot(), snapshot);
                assert_eq!(fs::metadata(&f.journal_path).unwrap().len(), size);
                assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
            }
            let mut journal = LockedInventoryJournal::open(&f.journal_path, false)
                .unwrap()
                .unwrap();
            let (_, physical_record_count) =
                ContinuousInventoryRegistryV1::replay_journal(f.store_id, f.op_id, &mut journal)
                    .unwrap();
            assert_eq!(physical_record_count, 6);
        }
    }

    #[test]
    fn ambiguous_append_failures_preserve_holds_and_disposition_across_refresh() {
        for fail_result in [false, true] {
            for upsert_capability in [false, true] {
                let f = EnvFixture::new();
                let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                let owner = s2b_workspace(&f, false);
                let ready = s2b_capability("cap-1");
                registry
                    .submit_durable(
                        &f.journal_path,
                        "op-owner",
                        2_000,
                        InventoryPayloadV1::RegisterWorkspace {
                            record: Box::new(owner.clone()),
                        },
                    )
                    .unwrap();
                registry
                    .submit_durable(
                        &f.journal_path,
                        "op-ready",
                        2_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(ready.clone()),
                        },
                    )
                    .unwrap();
                let mut collision = owner;
                collision.record_id = "ws-conflict".to_owned();
                collision.workspace_name = "ws-conflict".to_owned();
                assert!(matches!(
                    registry.submit_durable(
                        &f.journal_path,
                        "op-rejected",
                        3_000,
                        InventoryPayloadV1::RegisterWorkspace {
                            record: Box::new(collision)
                        }
                    ),
                    Err(InventoryError::DuplicatePhysicalWorkspace(_))
                ));
                let payload = if upsert_capability {
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(ready),
                    }
                } else {
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(s2b_workspace(&f, true)),
                    }
                };
                let before_failure = fs::read(&f.journal_path).unwrap();
                let error = if fail_result {
                    registry.fail_next_result_append = true;
                    registry
                        .submit_durable(&f.journal_path, "op-ambiguous", 4_000, payload.clone())
                        .unwrap_err()
                } else {
                    // An actual read-only descriptor makes Intent append fail
                    // without changing any bytes on disk.
                    let mut journal = LockedInventoryJournal::open(&f.journal_path, false)
                        .unwrap()
                        .unwrap();
                    registry
                        .commit_payload(&mut journal, 6, "op-ambiguous", 4_000, payload.clone())
                        .unwrap_err()
                };
                assert!(matches!(error, InventoryError::Io(_)));
                let reason_prefix = if fail_result {
                    "ambiguous_result_append:op-ambiguous:"
                } else {
                    "ambiguous_intent_append:op-ambiguous:"
                };
                assert!(
                    registry
                        .corrupt_or_ambiguous_tail_reason()
                        .is_some_and(|reason| reason.starts_with(reason_prefix))
                );
                assert!(registry.incomplete_ops_held.contains_key("op-ambiguous"));
                if upsert_capability {
                    assert_eq!(
                        registry.capabilities["cap-1"].effective_classification,
                        CapabilityClassificationV1::Held
                    );
                    assert_eq!(registry.capabilities["cap-1"].installed_binary_sha256, None);
                } else {
                    assert_eq!(
                        registry.workspaces["s2b-second"].status,
                        WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
                    );
                    assert_eq!(registry.workspaces["s2b-second"].pid_birth_binding, None);
                }
                let after_failure = fs::read(&f.journal_path).unwrap();
                if fail_result {
                    assert_eq!(read_journal_entries(&f.journal_path).len(), 7);
                } else {
                    assert_eq!(after_failure, before_failure);
                }
                let snapshot = registry.inspect_discovery_snapshot();
                let rejected = registry.rejected_ops.clone();
                registry.refresh_from_journal(&f.journal_path).unwrap();
                assert_eq!(registry.inspect_discovery_snapshot(), snapshot);
                assert_eq!(registry.rejected_ops, rejected);
                assert!(matches!(
                    registry.submit_durable(&f.journal_path, "op-ambiguous", 4_001, payload),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                assert!(matches!(
                    registry.hold_workspace("s2b-first", "blocked hold".to_owned(), 4_001),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                assert_eq!(registry.inspect_discovery_snapshot(), snapshot);
                assert_eq!(fs::read(&f.journal_path).unwrap(), after_failure);
            }
        }
    }

    #[test]
    fn journal_semantic_corruption_and_nonfinal_syntax_errors_fail_closed() {
        let f = EnvFixture::new();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let mut capability = s2b_capability("cap-1");
        registry
            .submit_durable(
                &f.journal_path,
                "op-ready",
                2_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(capability.clone()),
                },
            )
            .unwrap();
        capability.source_tree_clean = false;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-rejected",
                3_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(capability)
                }
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        let entries = read_journal_entries(&f.journal_path);
        let prefix = fs::read(&f.journal_path).unwrap();
        let payload = InventoryPayloadV1::UpsertCapability {
            record: Box::new(s2b_capability("cap-new")),
        };
        let digest = ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap();
        let pending = JournalEntryV1::Intent {
            operation_id: "op-pending".to_owned(),
            intent_digest: digest.clone(),
            recorded_unix_ms: 4_000,
            payload: payload.clone(),
        };
        let orphan = JournalEntryV1::Result {
            operation_id: "op-orphan".to_owned(),
            intent_digest: digest,
            completed_unix_ms: 4_000,
            committed: false,
            hold_reason: Some("orphan result".to_owned()),
        };
        let bad_digest = JournalEntryV1::Intent {
            operation_id: "op-bad-digest".to_owned(),
            intent_digest: "invalid digest".to_owned(),
            recorded_unix_ms: 4_000,
            payload,
        };
        let mismatched_result = JournalEntryV1::Result {
            operation_id: "op-pending".to_owned(),
            intent_digest: "mismatched result digest".to_owned(),
            completed_unix_ms: 4_000,
            committed: false,
            hold_reason: Some("invalid digest".to_owned()),
        };
        let line = |entry| ContinuousInventoryRegistryV1::journal_line(entry).unwrap();
        let duplicate_pending = [line(&pending), line(&pending)].concat();
        let nonfinal_syntax = [b"not JSON\n".to_vec(), line(&pending)].concat();
        let mismatched_result = [line(&pending), line(&mismatched_result)].concat();
        for suffix in [
            line(&entries[0]), // Duplicate committed Intent.
            line(&entries[2]), // Duplicate durably rejected Intent.
            duplicate_pending,
            line(&orphan),
            line(&bad_digest),
            mismatched_result,
            nonfinal_syntax,
        ] {
            let bytes = [prefix.clone(), suffix].concat();
            fs::write(&f.journal_path, &bytes).unwrap();
            assert!(matches!(
                ContinuousInventoryRegistryV1::load_and_reconcile(
                    f.store_id,
                    f.op_id,
                    &f.journal_path
                ),
                Err(InventoryError::JournalCorruptOrBounded(_))
            ));
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        }
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
