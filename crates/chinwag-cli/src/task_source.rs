#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Source enrollment decisions for the controlled Phase 0 profile.
//!
//! The caller supplies an already authorized workspace configuration and writer
//! migration. These in-memory records do not authenticate that authorization,
//! publish configuration, persist operation outcomes, or invoke executors.

use crate::task_source_path::{
    ResolvedTaskSourceFile, SourcePathHoldReason, WorkspaceRootPin,
    resolve_enrolled_source_under_root, validate_enrolled_relative_path,
};
use serde::{Deserialize, Serialize};

pub const MAX_ENROLLED_SOURCES: usize = 16;
pub const MAX_SOURCE_FILE_BYTES: u64 = 1_048_576;
pub const MAX_ID_UTF8_BYTES: usize = 256;
pub const MAX_CANONICAL_PATH_BYTES: usize = 4096;
pub const MAX_REV_COUNTER: u64 = i64::MAX as u64;
pub const SUPPORTED_NORMALIZATION_VERSION: u32 = 1;
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// A visible refusal to enroll or admit a new effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeldReason {
    InvalidWorkspaceId,
    InvalidIdentifier,
    InvalidSourceId,
    InvalidRevision,
    UnsupportedVersion,
    InvalidSourceLimit,
    PolicyBindingMismatch,
    ContradictoryOrMissingControls,
    DispatchNotAuthorized,
    DeploymentNotAuthorized,
    AutomaticDispatchNotAuthorized,
    AmbiguousOrAliasSource,
    SourceLimitExceeded,
    SourceNotFound,
    InvalidStateTransition,
    ExplicitConflictResolutionRequired,
    SourceNotEnrolled,
    RetiredSource,
    InterruptedMigration,
    MigrationAuthorizationMismatch,
    MalformedRollup,
    SourcePath(SourcePathHoldReason),
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_UTF8_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Validate an opaque bounded workspace ID: 1..=256 UTF-8 bytes, no whitespace
/// or control characters, no filesystem path separators `/` or `\`, no leading
/// `~`, and neither `.` nor `..`. Workspace enrollment authority is enforced by
/// `record.workspace_id == policy.workspace_id`, not by lexical validation.
pub fn validate_workspace_id(value: &str) -> Result<(), HeldReason> {
    if !identifier(value)
        || value.chars().any(char::is_whitespace)
        || value == "."
        || value == ".."
        || value.starts_with('~')
        || value.contains(['/', '\\'])
    {
        return Err(HeldReason::InvalidWorkspaceId);
    }
    Ok(())
}

pub fn validate_task_source_id(value: &str) -> Result<(), HeldReason> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(HeldReason::InvalidSourceId);
    }
    Ok(())
}

/// Mint 128 random bits; labels and path spelling never participate in identity.
pub fn new_task_source_id() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in rand::random::<[u8; 16]>() {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 15)]));
    }
    value
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceTaskPolicy {
    pub workspace_id: String,
    pub repo_id: String,
    pub config_revision: u64,
    pub authority_epoch: u64,
    pub scheduler_owner: String,
    pub max_sources: usize,
    /// External commitment; never computed from a self-containing artifact.
    pub config_digest: [u8; 32],
}

impl WorkspaceTaskPolicy {
    pub fn validate(&self) -> Result<(), HeldReason> {
        validate_workspace_id(&self.workspace_id)?;
        if !identifier(&self.repo_id) || !identifier(&self.scheduler_owner) {
            return Err(HeldReason::InvalidIdentifier);
        }
        if self.config_revision > MAX_REV_COUNTER || self.authority_epoch > MAX_REV_COUNTER {
            return Err(HeldReason::InvalidRevision);
        }
        if !(1..=MAX_ENROLLED_SOURCES).contains(&self.max_sources) {
            return Err(HeldReason::InvalidSourceLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SourceExecutionMode {
    #[serde(rename = "REVIEW_ONLY")]
    ReviewOnly,
    #[serde(rename = "IMPLEMENTATION")]
    Implementation,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDispatchControls {
    pub mode: SourceExecutionMode,
    pub implementation_authorized: bool,
    pub deployment_authorized: bool,
    pub automatic_dispatch: bool,
    pub allowed_actions: Vec<String>,
}

impl SourceDispatchControls {
    pub fn validate(&self) -> Result<(), HeldReason> {
        if self.allowed_actions.is_empty()
            || self.allowed_actions.len() > MAX_ID_UTF8_BYTES
            || self
                .allowed_actions
                .iter()
                .any(|action| !identifier(action))
            || self
                .allowed_actions
                .iter()
                .enumerate()
                .any(|(i, action)| self.allowed_actions[..i].contains(action))
            || (self.mode == SourceExecutionMode::ReviewOnly
                && (self.implementation_authorized
                    || self.deployment_authorized
                    || self.automatic_dispatch))
            || (!self.implementation_authorized
                && (self.deployment_authorized || self.automatic_dispatch))
        {
            return Err(HeldReason::ContradictoryOrMissingControls);
        }
        Ok(())
    }

    /// Engineering admission; document review must use its separate entry point.
    /// Automatic callers must also use `check_automatic_dispatch_admission`.
    pub fn check_dispatch_admission(&self, requested_action: &str) -> Result<(), HeldReason> {
        self.validate()?;
        if self.mode != SourceExecutionMode::Implementation
            || !self.implementation_authorized
            || !self
                .allowed_actions
                .iter()
                .any(|action| action == requested_action)
        {
            return Err(HeldReason::DispatchNotAuthorized);
        }
        if is_deployment_action(requested_action) && !self.deployment_authorized {
            return Err(HeldReason::DeploymentNotAuthorized);
        }
        Ok(())
    }

    /// Only the literal bounded review action is admitted by this review gate.
    pub fn check_review_admission(&self, requested_action: &str) -> Result<(), HeldReason> {
        self.validate()?;
        if requested_action != "document-review"
            || !self
                .allowed_actions
                .iter()
                .any(|action| action == requested_action)
        {
            return Err(HeldReason::DispatchNotAuthorized);
        }
        Ok(())
    }

    pub fn check_automatic_dispatch_admission(&self, action: &str) -> Result<(), HeldReason> {
        self.check_dispatch_admission(action)?;
        if !self.automatic_dispatch {
            return Err(HeldReason::AutomaticDispatchNotAuthorized);
        }
        Ok(())
    }

    /// Call for every deployment, including actions with application-specific names.
    pub fn check_deployment_admission(&self, action: &str) -> Result<(), HeldReason> {
        self.check_dispatch_admission(action)?;
        if !self.deployment_authorized {
            return Err(HeldReason::DeploymentNotAuthorized);
        }
        Ok(())
    }
}

fn is_deployment_action(action: &str) -> bool {
    matches!(action, "deploy" | "deployment")
        || action.starts_with("deploy:")
        || action.starts_with("deploy/")
        || action.starts_with("deploy-")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskSourceState {
    Proposed,
    Enrolled,
    Held(HeldReason),
    Suspended,
    Retired,
}

impl TaskSourceState {
    /// `conflict_resolved` attests explicit resolution plus fresh validation by
    /// the authority. The registry additionally prevents clearing migration fences.
    pub fn transition_to(&mut self, next: Self, conflict_resolved: bool) -> Result<(), HeldReason> {
        if *self == Self::Retired {
            return Err(HeldReason::RetiredSource);
        }
        if matches!(self, Self::Held(_)) && next == Self::Enrolled && !conflict_resolved {
            return Err(HeldReason::ExplicitConflictResolutionRequired);
        }
        if !matches!(
            (*self, next),
            (Self::Proposed, Self::Held(_) | Self::Enrolled)
                | (
                    Self::Enrolled,
                    Self::Held(_) | Self::Suspended | Self::Retired
                )
                | (Self::Suspended | Self::Held(_), Self::Enrolled)
        ) {
            return Err(HeldReason::InvalidStateTransition);
        }
        *self = next;
        Ok(())
    }

    pub fn check_new_admission(&self) -> Result<(), HeldReason> {
        match self {
            Self::Enrolled => Ok(()),
            Self::Held(reason) => Err(*reason),
            Self::Retired => Err(HeldReason::RetiredSource),
            Self::Proposed | Self::Suspended => Err(HeldReason::SourceNotEnrolled),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskSourceRecord {
    pub workspace_id: String,
    pub repo_id: String,
    pub source_worktree_id: String,
    pub task_source_id: String,
    pub display_name: String,
    pub canonical_relative_path: String,
    /// Checked nonnegative signed-64-bit revision, independent of root generation.
    pub source_generation: u64,
    pub normalization_version: u32,
    pub schema_version: u32,
    pub writer_principal: String,
    pub writer_epoch: u64,
    pub config_digest: [u8; 32],
    pub state: TaskSourceState,
    pub controls: SourceDispatchControls,
}

impl TaskSourceRecord {
    pub fn validate(&self, policy: &WorkspaceTaskPolicy) -> Result<(), HeldReason> {
        policy.validate()?;
        if self.normalization_version != SUPPORTED_NORMALIZATION_VERSION
            || self.schema_version != SUPPORTED_SCHEMA_VERSION
        {
            return Err(HeldReason::UnsupportedVersion);
        }
        validate_workspace_id(&self.workspace_id)?;
        validate_task_source_id(&self.task_source_id)?;
        if !identifier(&self.repo_id)
            || !identifier(&self.source_worktree_id)
            || !identifier(&self.writer_principal)
            || !identifier(&self.display_name)
        {
            return Err(HeldReason::InvalidIdentifier);
        }
        if self.source_generation > MAX_REV_COUNTER || self.writer_epoch > MAX_REV_COUNTER {
            return Err(HeldReason::InvalidRevision);
        }
        if self.workspace_id != policy.workspace_id
            || self.repo_id != policy.repo_id
            || self.config_digest != policy.config_digest
        {
            return Err(HeldReason::PolicyBindingMismatch);
        }
        validate_enrolled_relative_path(&self.canonical_relative_path)
            .map_err(HeldReason::SourcePath)?;
        self.controls.validate()
    }

    pub fn rename_display(&mut self, display_name: String) -> Result<(), HeldReason> {
        if !identifier(&display_name) {
            return Err(HeldReason::InvalidIdentifier);
        }
        self.display_name = display_name;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceFilesystemIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl From<&ResolvedTaskSourceFile> for SourceFilesystemIdentity {
    fn from(file: &ResolvedTaskSourceFile) -> Self {
        Self {
            dev: file.dev,
            ino: file.ino,
        }
    }
}

/// Historical bindings never authorize new admissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalSourceBinding {
    pub canonical_relative_path: String,
    pub source_generation: u64,
    pub filesystem_identity: SourceFilesystemIdentity,
}

/// Supplied only after the caller authorizes this exact writer operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMigrationAuthorization {
    pub operation_id: String,
    pub workspace_id: String,
    pub task_source_id: String,
    pub writer_principal: String,
    pub expected_writer_epoch: u64,
    pub expected_source_generation: u64,
    pub expected_config_revision: u64,
    pub expected_authority_epoch: u64,
    pub config_digest: [u8; 32],
    pub new_relative_path: String,
}

#[derive(Clone, Debug)]
struct PendingMigration {
    authorization: SourceMigrationAuthorization,
    old_binding: HistoricalSourceBinding,
    old_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
struct RegisteredSource {
    record: TaskSourceRecord,
    filesystem_identity: Option<SourceFilesystemIdentity>,
    history: Vec<HistoricalSourceBinding>,
    pending: Option<PendingMigration>,
}

/// A bounded model of the existing workspace configuration, not a second store.
/// Sources are exposed immutably; all actionable decisions revalidate bindings.
#[derive(Debug)]
pub struct WorkspaceSourceRegistry {
    policy: WorkspaceTaskPolicy,
    root: WorkspaceRootPin,
    sources: Vec<RegisteredSource>,
}

impl WorkspaceSourceRegistry {
    pub fn new(policy: WorkspaceTaskPolicy, root: WorkspaceRootPin) -> Result<Self, HeldReason> {
        policy.validate()?;
        root.verify().map_err(HeldReason::SourcePath)?;
        Ok(Self {
            policy,
            root,
            sources: Vec::new(),
        })
    }

    pub fn policy(&self) -> &WorkspaceTaskPolicy {
        &self.policy
    }

    pub fn source(&self, source_id: &str) -> Option<&TaskSourceRecord> {
        self.sources
            .iter()
            .find(|entry| entry.record.task_source_id == source_id)
            .map(|entry| &entry.record)
    }

    pub fn sources(&self) -> impl Iterator<Item = &TaskSourceRecord> {
        self.sources.iter().map(|entry| &entry.record)
    }

    pub fn binding_history(&self, source_id: &str) -> Option<&[HistoricalSourceBinding]> {
        self.sources
            .iter()
            .find(|entry| entry.record.task_source_id == source_id)
            .map(|entry| entry.history.as_slice())
    }

    fn index(&self, source_id: &str) -> Result<usize, HeldReason> {
        self.sources
            .iter()
            .position(|entry| entry.record.task_source_id == source_id)
            .ok_or(HeldReason::SourceNotFound)
    }

    /// A failed filesystem enrollment remains visibly Held and consumes a slot.
    /// Duplicate identities cannot overwrite the original source record.
    pub fn enroll(&mut self, mut record: TaskSourceRecord) -> Result<(), HeldReason> {
        record.validate(&self.policy)?;
        if record.state != TaskSourceState::Proposed {
            return Err(HeldReason::InvalidStateTransition);
        }
        if self.source(&record.task_source_id).is_some() {
            return Err(HeldReason::AmbiguousOrAliasSource);
        }
        if self.sources.len() >= self.policy.max_sources {
            return Err(HeldReason::SourceLimitExceeded);
        }
        let file = resolve_enrolled_source_under_root(&self.root, &record.canonical_relative_path);
        let mut held = file.as_ref().err().copied().map(HeldReason::SourcePath);
        for entry in &mut self.sources {
            let same_file = file.as_ref().ok().is_some_and(|resolved| {
                entry.filesystem_identity == Some(SourceFilesystemIdentity::from(resolved))
            });
            if entry.record.canonical_relative_path == record.canonical_relative_path
                || entry.pending.as_ref().is_some_and(|pending| {
                    pending.authorization.new_relative_path == record.canonical_relative_path
                })
                || same_file
            {
                held = Some(HeldReason::AmbiguousOrAliasSource);
                if entry.record.state == TaskSourceState::Enrolled {
                    entry.record.state = TaskSourceState::Held(HeldReason::AmbiguousOrAliasSource);
                }
            }
        }
        record.state = held.map_or(TaskSourceState::Enrolled, TaskSourceState::Held);
        self.sources.push(RegisteredSource {
            record,
            filesystem_identity: file.as_ref().ok().map(SourceFilesystemIdentity::from),
            history: Vec::new(),
            pending: None,
        });
        held.map_or(Ok(()), Err)
    }

    /// Suspend/retire only; enrolling again requires fresh descriptor validation.
    pub fn transition_source(
        &mut self,
        source_id: &str,
        next: TaskSourceState,
    ) -> Result<(), HeldReason> {
        let index = self.index(source_id)?;
        if self.sources[index].pending.is_some() {
            return Err(HeldReason::InterruptedMigration);
        }
        if !matches!(
            next,
            TaskSourceState::Suspended | TaskSourceState::Retired | TaskSourceState::Held(_)
        ) {
            return Err(HeldReason::InvalidStateTransition);
        }
        self.sources[index].record.state.transition_to(next, false)
    }

    /// Explicit conflict resolution or resume, always with fresh path validation.
    /// Choosing one held alias leaves all competing held proposals fenced.
    pub fn revalidate_source(
        &mut self,
        source_id: &str,
        conflict_resolved: bool,
    ) -> Result<(), HeldReason> {
        let index = self.index(source_id)?;
        let entry = &self.sources[index];
        if entry.pending.is_some()
            || entry.record.state == TaskSourceState::Held(HeldReason::InterruptedMigration)
        {
            return Err(HeldReason::InterruptedMigration);
        }
        let mut next = entry.record.state;
        next.transition_to(TaskSourceState::Enrolled, conflict_resolved)?;
        let file =
            resolve_enrolled_source_under_root(&self.root, &entry.record.canonical_relative_path)
                .map_err(HeldReason::SourcePath)?;
        if entry
            .filesystem_identity
            .is_some_and(|identity| identity != SourceFilesystemIdentity::from(&file))
        {
            return Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceReplacedOrDrifted,
            ));
        }
        self.check_alias(index, &file)?;
        self.sources[index].filesystem_identity = Some(SourceFilesystemIdentity::from(&file));
        self.sources[index].record.state = next;
        Ok(())
    }

    fn check_alias(&self, index: usize, file: &ResolvedTaskSourceFile) -> Result<(), HeldReason> {
        if self.sources.iter().enumerate().any(|(other, entry)| {
            other != index
                && ((matches!(
                    entry.record.state,
                    TaskSourceState::Enrolled
                        | TaskSourceState::Suspended
                        | TaskSourceState::Held(HeldReason::InterruptedMigration)
                ) && (entry.record.canonical_relative_path == file.canonical_relative_path
                    || entry.filesystem_identity == Some(SourceFilesystemIdentity::from(file))))
                    || entry.pending.as_ref().is_some_and(|pending| {
                        pending.authorization.new_relative_path == file.canonical_relative_path
                            || pending.old_binding.canonical_relative_path
                                == file.canonical_relative_path
                            || pending.old_binding.filesystem_identity
                                == SourceFilesystemIdentity::from(file)
                    }))
        }) {
            return Err(HeldReason::AmbiguousOrAliasSource);
        }
        Ok(())
    }

    fn validate_bound_source(&self, source_id: &str) -> Result<&TaskSourceRecord, HeldReason> {
        let index = self.index(source_id)?;
        let entry = &self.sources[index];
        entry.record.state.check_new_admission()?;
        entry.record.validate(&self.policy)?;
        let file =
            resolve_enrolled_source_under_root(&self.root, &entry.record.canonical_relative_path)
                .map_err(HeldReason::SourcePath)?;
        if entry.filesystem_identity != Some(SourceFilesystemIdentity::from(&file)) {
            return Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceReplacedOrDrifted,
            ));
        }
        self.check_alias(index, &file)?;
        Ok(&entry.record)
    }

    /// Adopt the exact same-path replacement produced by the fenced writer.
    /// Migration, enrollment state and source generation retain their bindings.
    pub fn adopt_writer_commit(
        &mut self,
        proof: &crate::task_writer::WriterCommitProof,
    ) -> Result<(), HeldReason> {
        let index = self.index(proof.task_source_id())?;
        let entry = &self.sources[index];
        if entry.pending.is_some() {
            return Err(HeldReason::InterruptedMigration);
        }
        entry.record.validate(&self.policy)?;
        entry.record.state.check_new_admission()?;
        let committed_identity = proof.verify_for_source_record(
            &self.policy,
            &entry.record,
            entry.filesystem_identity,
        )?;
        let file =
            resolve_enrolled_source_under_root(&self.root, &entry.record.canonical_relative_path)
                .map_err(HeldReason::SourcePath)?;
        if SourceFilesystemIdentity::from(&file) != committed_identity
            || &file.sha256 != proof.committed_postimage_sha256()
            || file.bytes.len() as u64 != proof.committed_postimage_bytes()
        {
            return Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceReplacedOrDrifted,
            ));
        }
        self.check_alias(index, &file)?;
        self.sources[index].filesystem_identity = Some(committed_identity);
        Ok(())
    }

    pub fn check_dispatch_admission(
        &self,
        source_id: &str,
        action: &str,
    ) -> Result<(), HeldReason> {
        self.validate_bound_source(source_id)?
            .controls
            .check_dispatch_admission(action)
    }

    pub fn check_review_admission(&self, source_id: &str, action: &str) -> Result<(), HeldReason> {
        self.validate_bound_source(source_id)?
            .controls
            .check_review_admission(action)
    }

    pub fn check_automatic_dispatch_admission(
        &self,
        source_id: &str,
        action: &str,
    ) -> Result<(), HeldReason> {
        self.validate_bound_source(source_id)?
            .controls
            .check_automatic_dispatch_admission(action)
    }

    pub fn check_deployment_admission(
        &self,
        source_id: &str,
        action: &str,
    ) -> Result<(), HeldReason> {
        self.validate_bound_source(source_id)?
            .controls
            .check_deployment_admission(action)
    }

    fn validate_migration_authorization(
        &self,
        index: usize,
        authorization: &SourceMigrationAuthorization,
    ) -> Result<(), HeldReason> {
        let record = &self.sources[index].record;
        if !identifier(&authorization.operation_id)
            || authorization.workspace_id != self.policy.workspace_id
            || authorization.task_source_id != record.task_source_id
            || authorization.writer_principal != record.writer_principal
            || authorization.expected_writer_epoch != record.writer_epoch
            || authorization.expected_source_generation != record.source_generation
            || authorization.expected_config_revision != self.policy.config_revision
            || authorization.expected_authority_epoch != self.policy.authority_epoch
            || authorization.config_digest != self.policy.config_digest
        {
            return Err(HeldReason::MigrationAuthorizationMismatch);
        }
        validate_enrolled_relative_path(&authorization.new_relative_path)
            .map_err(HeldReason::SourcePath)?;
        if record.source_generation >= MAX_REV_COUNTER {
            return Err(HeldReason::InvalidRevision);
        }
        Ok(())
    }

    /// Fence admissions before handing any filesystem effect to the designated writer.
    pub fn begin_source_path_migration(
        &mut self,
        authorization: SourceMigrationAuthorization,
    ) -> Result<(), HeldReason> {
        let index = self.index(&authorization.task_source_id)?;
        self.validate_migration_authorization(index, &authorization)?;
        self.sources[index].record.state.check_new_admission()?;
        if authorization.new_relative_path == self.sources[index].record.canonical_relative_path
            || self.sources.iter().enumerate().any(|(other, entry)| {
                other != index
                    && (entry.record.canonical_relative_path == authorization.new_relative_path
                        || entry.pending.as_ref().is_some_and(|pending| {
                            pending.authorization.new_relative_path
                                == authorization.new_relative_path
                        }))
            })
        {
            return Err(HeldReason::AmbiguousOrAliasSource);
        }
        let entry = &mut self.sources[index];
        entry.record.state = TaskSourceState::Held(HeldReason::InterruptedMigration);
        let old =
            resolve_enrolled_source_under_root(&self.root, &entry.record.canonical_relative_path)
                .map_err(HeldReason::SourcePath)?;
        if entry.filesystem_identity != Some(SourceFilesystemIdentity::from(&old)) {
            return Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceReplacedOrDrifted,
            ));
        }
        match resolve_enrolled_source_under_root(&self.root, &authorization.new_relative_path) {
            Err(SourcePathHoldReason::HeldSourceMissing) => {}
            Ok(_) => return Err(HeldReason::AmbiguousOrAliasSource),
            Err(reason) => return Err(HeldReason::SourcePath(reason)),
        }
        entry.pending = Some(PendingMigration {
            old_binding: HistoricalSourceBinding {
                canonical_relative_path: entry.record.canonical_relative_path.clone(),
                source_generation: entry.record.source_generation,
                filesystem_identity: SourceFilesystemIdentity::from(&old),
            },
            old_sha256: old.sha256,
            authorization,
        });
        Ok(())
    }

    /// Commit only the exact authorized move after the old binding is absent.
    /// Any failure retains the migration fence and original binding.
    pub fn complete_source_path_migration(
        &mut self,
        authorization: &SourceMigrationAuthorization,
    ) -> Result<(), HeldReason> {
        let index = self.index(&authorization.task_source_id)?;
        self.validate_migration_authorization(index, authorization)?;
        let pending = self.sources[index]
            .pending
            .as_ref()
            .ok_or(HeldReason::InterruptedMigration)?;
        if &pending.authorization != authorization {
            return Err(HeldReason::MigrationAuthorizationMismatch);
        }
        let new = resolve_enrolled_source_under_root(&self.root, &authorization.new_relative_path)
            .map_err(HeldReason::SourcePath)?;
        if new.sha256 != pending.old_sha256 {
            return Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceReplacedOrDrifted,
            ));
        }
        match resolve_enrolled_source_under_root(
            &self.root,
            &pending.old_binding.canonical_relative_path,
        ) {
            Err(SourcePathHoldReason::HeldSourceMissing) => {}
            Ok(_) => return Err(HeldReason::AmbiguousOrAliasSource),
            Err(reason) => return Err(HeldReason::SourcePath(reason)),
        }
        self.check_alias(index, &new)?;
        let entry = &mut self.sources[index];
        let pending = entry
            .pending
            .take()
            .ok_or(HeldReason::InterruptedMigration)?;
        entry.history.push(pending.old_binding);
        entry.record.source_generation += 1;
        entry
            .record
            .canonical_relative_path
            .clone_from(&authorization.new_relative_path);
        entry.filesystem_identity = Some(SourceFilesystemIdentity::from(&new));
        entry.record.state = TaskSourceState::Enrolled;
        Ok(())
    }

    /// Run an already authorized writer, then validate its exact postcondition.
    /// This model performs no rename itself and cannot replace durable writer CAS.
    pub fn migrate_source_path<F>(
        &mut self,
        authorization: SourceMigrationAuthorization,
        writer: F,
    ) -> Result<(), HeldReason>
    where
        F: FnOnce() -> Result<(), HeldReason>,
    {
        self.begin_source_path_migration(authorization.clone())?;
        writer()?;
        self.complete_source_path_migration(&authorization)
    }
}

fn heading(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let level = trimmed.bytes().take_while(|byte| *byte == b'#').count();
    if !(1..=6).contains(&level)
        || !trimmed
            .as_bytes()
            .get(level)
            .is_some_and(u8::is_ascii_whitespace)
    {
        return None;
    }
    Some((
        level,
        trimmed[level..].trim().trim_end_matches('#').trim_end(),
    ))
}

fn fence(line: &str) -> Option<(u8, usize, bool)> {
    let trimmed = line.trim_start_matches(' ');
    if line.len() - trimmed.len() > 3 {
        return None;
    }
    let marker = *trimmed.as_bytes().first()?;
    if !matches!(marker, b'`' | b'~') {
        return None;
    }
    let count = trimmed.bytes().take_while(|byte| *byte == marker).count();
    (count >= 3).then(|| (marker, count, trimmed[count..].trim().is_empty()))
}

/// Remove projection sections while preserving every remaining line's bytes.
/// Unterminated, nested, or mismatched markers hold discovery rather than expose
/// partially parsed executable headings. A Rollup heading ends at its peer/parent.
pub fn strip_marked_rollup_sections(markdown: &str) -> Result<String, HeldReason> {
    if markdown.len() as u64 > MAX_SOURCE_FILE_BYTES {
        return Err(HeldReason::MalformedRollup);
    }
    let mut output = String::with_capacity(markdown.len());
    let mut block: Option<&str> = None;
    let mut rollup_level = None;
    let mut code_fence: Option<(u8, usize)> = None;
    for line in markdown.split_inclusive('\n') {
        let trimmed = line.trim();
        if code_fence.is_none() {
            let marker = match trimmed {
                "<!-- chinwag:rollup:start -->" => Some(("rollup", true)),
                "<!-- chinwag:rollup:end -->" => Some(("rollup", false)),
                "<!-- chinwag:projection:start -->" => Some(("projection", true)),
                "<!-- chinwag:projection:end -->" => Some(("projection", false)),
                _ => None,
            };
            if let Some((kind, start)) = marker {
                if start {
                    if block.is_some() {
                        return Err(HeldReason::MalformedRollup);
                    }
                    block = Some(kind);
                } else if block != Some(kind) {
                    return Err(HeldReason::MalformedRollup);
                } else {
                    block = None;
                }
                continue;
            }
            if trimmed.contains("<!-- chinwag:rollup:")
                || trimmed.contains("<!-- chinwag:projection:")
            {
                return Err(HeldReason::MalformedRollup);
            }
            if let Some((level, title)) = heading(line).filter(|_| block.is_none()) {
                if rollup_level.is_some_and(|old| level <= old) {
                    rollup_level = None;
                }
                if title.eq_ignore_ascii_case("rollup") {
                    rollup_level = Some(level);
                }
            }
        }
        if let Some((marker, count, closing)) = fence(line) {
            match code_fence {
                Some((old, minimum)) if marker == old && count >= minimum && closing => {
                    code_fence = None
                }
                None => code_fence = Some((marker, count)),
                _ => {}
            }
        }
        if block.is_none() && rollup_level.is_none() {
            output.push_str(line);
        }
    }
    if block.is_some() {
        return Err(HeldReason::MalformedRollup);
    }
    Ok(output)
}

/// Candidate task headings/checklist entries for a subsequent task-schema parser.
/// Code examples and projections never contribute canonical candidates.
pub fn extract_canonical_task_lines(markdown: &str) -> Result<Vec<String>, HeldReason> {
    let canonical = strip_marked_rollup_sections(markdown)?;
    let mut code_fence: Option<(u8, usize)> = None;
    let mut lines = Vec::new();
    for line in canonical.lines() {
        if let Some((marker, count, closing)) = fence(line) {
            match code_fence {
                Some((old, minimum)) if marker == old && count >= minimum && closing => {
                    code_fence = None
                }
                None => code_fence = Some((marker, count)),
                _ => {}
            }
            continue;
        }
        let trimmed = line.trim_start_matches(' ');
        if code_fence.is_none()
            && line.len() - trimmed.len() <= 3
            && (heading(line).is_some_and(|(level, _)| level == 3)
                || ["- [ ] ", "- [x] ", "- [X] "]
                    .iter()
                    .any(|prefix| trimmed.starts_with(prefix)))
        {
            lines.push(line.to_owned());
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    fn policy() -> WorkspaceTaskPolicy {
        WorkspaceTaskPolicy {
            workspace_id: "workspace-fixture".into(),
            repo_id: "repository-fixture".into(),
            config_revision: 4,
            authority_epoch: 2,
            scheduler_owner: "scheduler-fixture".into(),
            max_sources: MAX_ENROLLED_SOURCES,
            config_digest: [7; 32],
        }
    }

    fn controls() -> SourceDispatchControls {
        SourceDispatchControls {
            mode: SourceExecutionMode::Implementation,
            implementation_authorized: true,
            deployment_authorized: false,
            automatic_dispatch: false,
            allowed_actions: vec![
                "implement".into(),
                "deploy".into(),
                "document-review".into(),
            ],
        }
    }

    fn source(number: usize, path: &str) -> TaskSourceRecord {
        TaskSourceRecord {
            workspace_id: policy().workspace_id,
            repo_id: policy().repo_id,
            source_worktree_id: "worktree-fixture".into(),
            task_source_id: format!("{number:032x}"),
            display_name: "Display label".into(),
            canonical_relative_path: path.into(),
            source_generation: 1,
            normalization_version: 1,
            schema_version: 1,
            writer_principal: "writer-fixture".into(),
            writer_epoch: 3,
            config_digest: policy().config_digest,
            state: TaskSourceState::Proposed,
            controls: controls(),
        }
    }

    fn registry(directory: &TempDir) -> WorkspaceSourceRegistry {
        let metadata = fs::metadata(directory.path()).expect("root metadata");
        let root = WorkspaceRootPin {
            path: directory.path().to_owned(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            generation: 1,
        };
        WorkspaceSourceRegistry::new(policy(), root).expect("valid registry")
    }

    fn migration(
        registry: &WorkspaceSourceRegistry,
        new_path: &str,
    ) -> SourceMigrationAuthorization {
        let record = registry.sources().next().expect("source");
        SourceMigrationAuthorization {
            operation_id: "migration-original-operation".into(),
            workspace_id: record.workspace_id.clone(),
            task_source_id: record.task_source_id.clone(),
            writer_principal: record.writer_principal.clone(),
            expected_writer_epoch: record.writer_epoch,
            expected_source_generation: record.source_generation,
            expected_config_revision: registry.policy.config_revision,
            expected_authority_epoch: registry.policy.authority_epoch,
            config_digest: registry.policy.config_digest,
            new_relative_path: new_path.into(),
        }
    }

    #[test]
    fn p0_source_workspace_id_is_opaque_bounded_and_not_a_path() {
        for invalid in [
            "",
            ".",
            "..",
            "~workspace",
            "~/ws",
            "a/b",
            "a\\b",
            "/workspace",
            "C:\\workspace",
            "https://host/repo",
            "ws with space",
            " ws",
            "ws\n",
            "ws\nforged",
            "ws\0",
            "ws\u{a0}id",
        ] {
            assert_eq!(
                validate_workspace_id(invalid),
                Err(HeldReason::InvalidWorkspaceId),
                "{invalid:?}"
            );
        }
        for valid in [
            "workspace-enrolled-01",
            "workspace.v1",
            "workspace.local",
            "urn:workspace",
            "urn:workspace:fixture",
            "host.example",
            "...",
            "state.crdb",
            "state.db",
            "localhost",
            "localhostlocaldomain",
            "@?#",
        ] {
            assert_eq!(validate_workspace_id(valid), Ok(()), "{valid:?}");
        }
        assert_eq!(
            validate_workspace_id(&"a".repeat(MAX_ID_UTF8_BYTES)),
            Ok(())
        );
        assert_eq!(validate_workspace_id(&"é".repeat(128)), Ok(()));
        for invalid in ["a".repeat(MAX_ID_UTF8_BYTES + 1), "é".repeat(129)] {
            assert_eq!(
                validate_workspace_id(&invalid),
                Err(HeldReason::InvalidWorkspaceId)
            );
        }
    }

    #[test]
    fn p0_source_opaque_workspace_id_requires_exact_policy_binding() {
        for workspace_id in ["workspace.v1", "urn:workspace:fixture"] {
            let mut record = source(1, "TASKS.md");
            record.workspace_id = workspace_id.into();
            assert_eq!(
                record.validate(&policy()),
                Err(HeldReason::PolicyBindingMismatch)
            );
            let mut enrolled_policy = policy();
            enrolled_policy.workspace_id = workspace_id.into();
            assert_eq!(record.validate(&enrolled_policy), Ok(()));
        }
    }

    #[test]
    fn p0_source_unsupported_versions_rejected_by_record_and_enrollment() {
        let directory = TempDir::new().expect("temporary root");
        let mut registry = registry(&directory);
        for unsupported in [0, 2, u32::MAX] {
            for normalization in [true, false] {
                let mut record = source(1, "TASKS.md");
                if normalization {
                    record.normalization_version = unsupported;
                } else {
                    record.schema_version = unsupported;
                }
                assert_eq!(
                    record.validate(&policy()),
                    Err(HeldReason::UnsupportedVersion)
                );
                assert_eq!(registry.enroll(record), Err(HeldReason::UnsupportedVersion));
                assert_eq!(registry.sources().count(), 0);
            }
        }
    }

    #[test]
    fn p0_source_unsupported_versions_rejected_by_all_admission_gates() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("TASKS.md"), b"source").expect("source");
        let mut registry = registry(&directory);
        let mut record = source(1, "TASKS.md");
        record.controls.deployment_authorized = true;
        record.controls.automatic_dispatch = true;
        let id = record.task_source_id.clone();
        registry.enroll(record).expect("supported versions enroll");
        assert_eq!(registry.check_dispatch_admission(&id, "implement"), Ok(()));
        assert_eq!(registry.check_deployment_admission(&id, "deploy"), Ok(()));
        assert_eq!(
            registry.check_automatic_dispatch_admission(&id, "implement"),
            Ok(())
        );
        assert_eq!(
            registry.check_review_admission(&id, "document-review"),
            Ok(())
        );
        for unsupported in [0, 2, u32::MAX] {
            for normalization in [true, false] {
                // Model stale stored metadata after a valid enrollment. Public
                // accessors are immutable; each admission must still revalidate.
                let record = &mut registry.sources[0].record;
                record.normalization_version = SUPPORTED_NORMALIZATION_VERSION;
                record.schema_version = SUPPORTED_SCHEMA_VERSION;
                if normalization {
                    record.normalization_version = unsupported;
                } else {
                    record.schema_version = unsupported;
                }
                assert_eq!(
                    registry.check_dispatch_admission(&id, "implement"),
                    Err(HeldReason::UnsupportedVersion)
                );
                assert_eq!(
                    registry.check_deployment_admission(&id, "deploy"),
                    Err(HeldReason::UnsupportedVersion)
                );
                assert_eq!(
                    registry.check_automatic_dispatch_admission(&id, "implement"),
                    Err(HeldReason::UnsupportedVersion)
                );
                assert_eq!(
                    registry.check_review_admission(&id, "document-review"),
                    Err(HeldReason::UnsupportedVersion)
                );
            }
        }
    }

    #[test]
    fn p0_source_policy_and_record_revision_and_limit_bounds() {
        for limit in [0, 17, usize::MAX] {
            let mut candidate = policy();
            candidate.max_sources = limit;
            assert_eq!(candidate.validate(), Err(HeldReason::InvalidSourceLimit));
        }
        let mut candidate = policy();
        candidate.config_revision = MAX_REV_COUNTER + 1;
        assert_eq!(candidate.validate(), Err(HeldReason::InvalidRevision));
        candidate.config_revision = MAX_REV_COUNTER;
        candidate.authority_epoch = MAX_REV_COUNTER;
        assert!(candidate.validate().is_ok());
        candidate.authority_epoch += 1;
        assert_eq!(candidate.validate(), Err(HeldReason::InvalidRevision));
        let mut record = source(1, "TASKS.md");
        record.source_generation = 0;
        assert_eq!(record.validate(&policy()), Ok(()));
        record.source_generation = MAX_REV_COUNTER + 1;
        assert_eq!(record.validate(&policy()), Err(HeldReason::InvalidRevision));
        record.source_generation = MAX_REV_COUNTER;
        record.writer_epoch = MAX_REV_COUNTER;
        assert!(record.validate(&policy()).is_ok());
        record.writer_epoch += 1;
        assert_eq!(record.validate(&policy()), Err(HeldReason::InvalidRevision));
    }

    #[test]
    fn p0_source_id_requires_32_lowerhex_and_survives_display_rename() {
        assert!(validate_task_source_id(&new_task_source_id()).is_ok());
        for invalid in [
            "",
            "abc",
            "ABCDEF0123456789abcdef0123456789",
            "gggggggggggggggggggggggggggggggg",
            "0123456789abcdef0123456789abcdef0",
        ] {
            assert_eq!(
                validate_task_source_id(invalid),
                Err(HeldReason::InvalidSourceId)
            );
        }
        let mut record = source(15, "tasks.md");
        let identity = record.task_source_id.clone();
        record
            .rename_display("A new stream label".into())
            .expect("rename");
        assert_eq!(identity, record.task_source_id);
        assert_eq!(record.canonical_relative_path, "tasks.md");
        assert_eq!(
            record.rename_display("label\n### injected".into()),
            Err(HeldReason::InvalidIdentifier)
        );
    }

    #[test]
    fn p0_source_state_machine_transitions_and_retired_fencing() {
        let mut state = TaskSourceState::Proposed;
        assert_eq!(
            state.transition_to(TaskSourceState::Suspended, false),
            Err(HeldReason::InvalidStateTransition)
        );
        state
            .transition_to(
                TaskSourceState::Held(HeldReason::AmbiguousOrAliasSource),
                false,
            )
            .expect("hold proposal");
        assert_eq!(
            state.transition_to(TaskSourceState::Enrolled, false),
            Err(HeldReason::ExplicitConflictResolutionRequired)
        );
        state
            .transition_to(TaskSourceState::Enrolled, true)
            .expect("explicit resolution");
        state
            .transition_to(TaskSourceState::Suspended, false)
            .expect("suspend");
        assert_eq!(
            state.check_new_admission(),
            Err(HeldReason::SourceNotEnrolled)
        );
        state
            .transition_to(TaskSourceState::Enrolled, false)
            .expect("fresh validation supplied by caller");
        state
            .transition_to(TaskSourceState::Retired, false)
            .expect("retire");
        for next in [
            TaskSourceState::Proposed,
            TaskSourceState::Enrolled,
            TaskSourceState::Retired,
        ] {
            assert_eq!(
                state.transition_to(next, true),
                Err(HeldReason::RetiredSource)
            );
        }
        assert_eq!(state.check_new_admission(), Err(HeldReason::RetiredSource));
    }

    #[test]
    fn p0_source_review_only_mode_blocks_implementation_and_auto_dispatch() {
        let mut review = controls();
        review.mode = SourceExecutionMode::ReviewOnly;
        review.implementation_authorized = false;
        assert_eq!(
            review.check_dispatch_admission("implement"),
            Err(HeldReason::DispatchNotAuthorized)
        );
        assert_eq!(
            review.check_deployment_admission("deploy"),
            Err(HeldReason::DispatchNotAuthorized)
        );
        assert!(review.check_review_admission("document-review").is_ok());
        assert!(review.check_review_admission("implement").is_err());
        review.automatic_dispatch = true;
        assert_eq!(
            review.check_dispatch_admission("implement"),
            Err(HeldReason::ContradictoryOrMissingControls)
        );
        review.automatic_dispatch = false;
        review.deployment_authorized = true;
        assert_eq!(
            review.validate(),
            Err(HeldReason::ContradictoryOrMissingControls)
        );
        review.deployment_authorized = false;
        review.implementation_authorized = true;
        assert_eq!(
            review.validate(),
            Err(HeldReason::ContradictoryOrMissingControls)
        );
    }

    #[test]
    fn p0_source_dispatch_requires_explicit_actions_deployment_and_automatic_policy() {
        let mut dispatch = controls();
        assert!(dispatch.check_dispatch_admission("implement").is_ok());
        assert_eq!(
            dispatch.check_dispatch_admission("Implement"),
            Err(HeldReason::DispatchNotAuthorized)
        );
        assert_eq!(
            dispatch.check_dispatch_admission("deploy"),
            Err(HeldReason::DeploymentNotAuthorized)
        );
        assert_eq!(
            dispatch.check_automatic_dispatch_admission("implement"),
            Err(HeldReason::AutomaticDispatchNotAuthorized)
        );
        dispatch.deployment_authorized = true;
        dispatch.automatic_dispatch = true;
        assert!(dispatch.check_deployment_admission("deploy").is_ok());
        assert!(
            dispatch
                .check_automatic_dispatch_admission("implement")
                .is_ok()
        );
        dispatch.allowed_actions.clear();
        assert_eq!(
            dispatch.validate(),
            Err(HeldReason::ContradictoryOrMissingControls)
        );
        dispatch.allowed_actions = vec!["implement".into(), "implement".into()];
        assert_eq!(
            dispatch.validate(),
            Err(HeldReason::ContradictoryOrMissingControls)
        );
        assert_eq!(
            serde_json::to_string(&SourceExecutionMode::ReviewOnly).expect("serialize"),
            "\"REVIEW_ONLY\""
        );
        assert!(serde_json::from_str::<SourceDispatchControls>("{}").is_err());
    }

    #[test]
    fn p0_source_registry_max_16_and_duplicate_alias_held() {
        let directory = TempDir::new().expect("temporary root");
        let mut registry = registry(&directory);
        for number in 0..16 {
            let path = format!("tasks-{number}.md");
            fs::write(directory.path().join(&path), b"### task").expect("write source");
            registry
                .enroll(source(number, &path))
                .expect("enroll within bound");
        }
        assert_eq!(registry.sources().count(), 16);
        assert_eq!(
            registry.enroll(source(16, "extra.md")),
            Err(HeldReason::SourceLimitExceeded)
        );
        assert_eq!(
            registry.enroll(source(0, "tasks-0.md")),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        let mut separate = super::WorkspaceSourceRegistry::new(policy(), registry.root.clone())
            .expect("separate model");
        separate
            .enroll(source(1, "tasks-0.md"))
            .expect("first source");
        assert_eq!(
            separate.enroll(source(2, "tasks-0.md")),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        assert!(separate.sources().all(
            |record| record.state == TaskSourceState::Held(HeldReason::AmbiguousOrAliasSource)
        ));
    }

    #[test]
    fn p0_source_explicit_alias_resolution_selects_only_one_admissible_source() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("tasks.md"), b"task").expect("source");
        let mut registry = registry(&directory);
        let first = source(1, "tasks.md");
        let second = source(2, "tasks.md");
        let first_id = first.task_source_id.clone();
        let second_id = second.task_source_id.clone();
        registry.enroll(first).expect("first source");
        assert_eq!(
            registry.enroll(second),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        assert_eq!(
            registry.revalidate_source(&first_id, false),
            Err(HeldReason::ExplicitConflictResolutionRequired)
        );
        registry
            .revalidate_source(&first_id, true)
            .expect("authorized choice");
        assert!(
            registry
                .check_dispatch_admission(&first_id, "implement")
                .is_ok()
        );
        assert_eq!(
            registry.revalidate_source(&second_id, true),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        assert!(
            registry
                .check_dispatch_admission(&second_id, "implement")
                .is_err()
        );
    }

    #[test]
    fn p0_source_registry_all_action_gates_fence_suspended_review_sources() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("tasks.md"), b"task").expect("source");
        let mut registry = registry(&directory);
        let mut review = source(1, "tasks.md");
        review.controls.mode = SourceExecutionMode::ReviewOnly;
        review.controls.implementation_authorized = false;
        let id = review.task_source_id.clone();
        registry.enroll(review).expect("review enrollment");
        assert!(
            registry
                .check_review_admission(&id, "document-review")
                .is_ok()
        );
        assert_eq!(
            registry.check_dispatch_admission(&id, "implement"),
            Err(HeldReason::DispatchNotAuthorized)
        );
        registry
            .transition_source(&id, TaskSourceState::Suspended)
            .expect("suspend");
        assert_eq!(
            registry.check_review_admission(&id, "document-review"),
            Err(HeldReason::SourceNotEnrolled)
        );
        assert_eq!(
            registry.check_automatic_dispatch_admission(&id, "implement"),
            Err(HeldReason::SourceNotEnrolled)
        );
        assert_eq!(
            registry.check_deployment_admission(&id, "deploy"),
            Err(HeldReason::SourceNotEnrolled)
        );
    }

    #[test]
    fn p0_source_registry_rejects_workspace_repo_and_digest_mismatch() {
        let directory = TempDir::new().expect("temporary root");
        let mut registry = registry(&directory);
        let mut wrong_workspace = source(1, "TASKS.md");
        wrong_workspace.workspace_id = "other-workspace".into();
        let mut wrong_repo = source(2, "TASKS.md");
        wrong_repo.repo_id = "other-repository".into();
        let mut wrong_digest = source(3, "TASKS.md");
        wrong_digest.config_digest = [8; 32];
        for record in [wrong_workspace, wrong_repo, wrong_digest] {
            assert_eq!(
                registry.enroll(record),
                Err(HeldReason::PolicyBindingMismatch)
            );
        }
        assert_eq!(registry.sources().count(), 0);
    }

    #[test]
    fn p0_source_registry_missing_source_retains_held_without_fallback() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("TASKS.md"), b"root source").expect("root source");
        let mut registry = registry(&directory);
        let record = source(1, "missing.md");
        let source_id = record.task_source_id.clone();
        assert_eq!(
            registry.enroll(record),
            Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceMissing
            ))
        );
        assert_eq!(
            registry
                .source(&source_id)
                .expect("retained source")
                .canonical_relative_path,
            "missing.md"
        );
        assert!(
            registry
                .check_dispatch_admission(&source_id, "implement")
                .is_err()
        );
    }

    #[test]
    fn p0_source_registry_dispatch_rechecks_inode_and_suspension() {
        let directory = TempDir::new().expect("temporary root");
        let path = directory.path().join("TASKS.md");
        fs::write(&path, b"source").expect("source");
        let mut registry = registry(&directory);
        let source = source(1, "TASKS.md");
        let id = source.task_source_id.clone();
        registry.enroll(source).expect("enroll");
        assert!(registry.check_dispatch_admission(&id, "implement").is_ok());
        registry
            .transition_source(&id, TaskSourceState::Suspended)
            .expect("suspend");
        assert_eq!(
            registry.check_dispatch_admission(&id, "implement"),
            Err(HeldReason::SourceNotEnrolled)
        );
        registry
            .revalidate_source(&id, false)
            .expect("resume after validation");
        fs::write(directory.path().join("replacement.md"), b"replacement").expect("replacement");
        fs::rename(directory.path().join("replacement.md"), &path).expect("replace inode");
        assert_eq!(
            registry.check_dispatch_admission(&id, "implement"),
            Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceReplacedOrDrifted
            ))
        );
    }

    #[test]
    fn p0_source_migration_increments_generation_and_holds_on_interrupt() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("old.md"), b"### canonical task\n").expect("source");
        let mut registry = registry(&directory);
        registry.enroll(source(1, "old.md")).expect("enroll");
        let authorization = migration(&registry, "new.md");
        let id = authorization.task_source_id.clone();
        registry
            .begin_source_path_migration(authorization.clone())
            .expect("fence");
        assert_eq!(
            registry.check_dispatch_admission(&id, "implement"),
            Err(HeldReason::InterruptedMigration)
        );
        assert_eq!(
            registry.revalidate_source(&id, true),
            Err(HeldReason::InterruptedMigration)
        );
        assert!(
            registry
                .complete_source_path_migration(&authorization)
                .is_err()
        );
        assert_eq!(
            registry.source(&id).expect("source").state,
            TaskSourceState::Held(HeldReason::InterruptedMigration)
        );
        fs::rename(
            directory.path().join("old.md"),
            directory.path().join("new.md"),
        )
        .expect("authorized writer move");
        registry
            .complete_source_path_migration(&authorization)
            .expect("commit exact move");
        let current = registry.source(&id).expect("source");
        assert_eq!(current.source_generation, 2);
        assert_eq!(current.canonical_relative_path, "new.md");
        assert_eq!(current.state, TaskSourceState::Enrolled);
        let history = registry.binding_history(&id).expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].canonical_relative_path, "old.md");
        assert_eq!(history[0].source_generation, 1);
        assert_eq!(
            registry.complete_source_path_migration(&authorization),
            Err(HeldReason::MigrationAuthorizationMismatch)
        );
    }

    #[test]
    fn p0_source_migration_rejects_two_canonical_files_and_changed_content() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("old.md"), b"original").expect("source");
        let mut registry = registry(&directory);
        registry.enroll(source(1, "old.md")).expect("enroll");
        let authorization = migration(&registry, "new.md");
        registry
            .begin_source_path_migration(authorization.clone())
            .expect("fence");
        fs::copy(
            directory.path().join("old.md"),
            directory.path().join("new.md"),
        )
        .expect("writer incorrectly copies");
        assert_eq!(
            registry.complete_source_path_migration(&authorization),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        fs::remove_file(directory.path().join("old.md")).expect("old binding retired");
        fs::write(directory.path().join("new.md"), b"changed").expect("wrong postimage");
        assert_eq!(
            registry.complete_source_path_migration(&authorization),
            Err(HeldReason::SourcePath(
                SourcePathHoldReason::HeldSourceReplacedOrDrifted
            ))
        );
        assert_eq!(
            registry.sources().next().expect("source").state,
            TaskSourceState::Held(HeldReason::InterruptedMigration)
        );
    }

    #[test]
    fn p0_source_migration_reserves_old_binding_against_alias_resolution() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("old.md"), b"original").expect("source");
        let mut registry = registry(&directory);
        registry.enroll(source(1, "old.md")).expect("enroll");
        let authorization = migration(&registry, "new.md");
        registry
            .begin_source_path_migration(authorization)
            .expect("migration fence");
        let competing = source(2, "old.md");
        let id = competing.task_source_id.clone();
        assert_eq!(
            registry.enroll(competing),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        assert_eq!(
            registry.revalidate_source(&id, true),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        assert!(registry.check_dispatch_admission(&id, "implement").is_err());
    }

    #[test]
    fn p0_source_migration_early_failure_cannot_release_original_binding() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("old.md"), b"original").expect("source");
        fs::write(directory.path().join("occupied.md"), b"occupied").expect("occupied destination");
        let mut registry = registry(&directory);
        registry.enroll(source(1, "old.md")).expect("enroll");
        let authorization = migration(&registry, "occupied.md");
        let original_id = authorization.task_source_id.clone();
        assert_eq!(
            registry.begin_source_path_migration(authorization),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        assert_eq!(
            registry.revalidate_source(&original_id, true),
            Err(HeldReason::InterruptedMigration)
        );
        let competing = source(2, "old.md");
        let competing_id = competing.task_source_id.clone();
        assert_eq!(
            registry.enroll(competing),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
        assert_eq!(
            registry.revalidate_source(&competing_id, true),
            Err(HeldReason::AmbiguousOrAliasSource)
        );
    }

    #[test]
    fn p0_source_migration_generation_bound_and_original_authorization_are_checked() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("old.md"), b"original").expect("source");
        let mut bounded = source(1, "old.md");
        bounded.source_generation = MAX_REV_COUNTER;
        let mut registry = registry(&directory);
        registry
            .enroll(bounded)
            .expect("maximum generation enrolls");
        let authorization = migration(&registry, "new.md");
        assert_eq!(
            registry.begin_source_path_migration(authorization),
            Err(HeldReason::InvalidRevision)
        );
        assert_eq!(
            registry.sources().next().expect("source").state,
            TaskSourceState::Enrolled
        );
    }

    #[test]
    fn p0_source_migration_checks_authority_and_writer_failure_retains_fence() {
        let directory = TempDir::new().expect("temporary root");
        fs::write(directory.path().join("old.md"), b"original").expect("source");
        let mut registry = registry(&directory);
        registry.enroll(source(1, "old.md")).expect("enroll");
        let authorization = migration(&registry, "new.md");
        let mut stale = authorization.clone();
        stale.expected_writer_epoch += 1;
        assert_eq!(
            registry.begin_source_path_migration(stale),
            Err(HeldReason::MigrationAuthorizationMismatch)
        );
        assert_eq!(
            registry.migrate_source_path(authorization, || Err(HeldReason::InterruptedMigration)),
            Err(HeldReason::InterruptedMigration)
        );
        assert_eq!(
            registry.sources().next().expect("source").state,
            TaskSourceState::Held(HeldReason::InterruptedMigration)
        );
        assert!(directory.path().join("old.md").exists());
        assert!(!directory.path().join("new.md").exists());
    }

    #[test]
    fn p0_source_rollup_section_excluded_from_canonical_discovery() {
        let markdown = "### TASK-A canonical\n<!-- chinwag:rollup:start -->\n### TASK-B projected\n- [ ] TASK-C projection\n<!-- chinwag:rollup:end -->\n## Rollup\n### TASK-D linked\n## Canonical\n### TASK-E canonical\n<!-- chinwag:projection:start -->\n### TASK-F projected\n<!-- chinwag:projection:end -->\n";
        assert_eq!(
            extract_canonical_task_lines(markdown).expect("canonical lines"),
            vec!["### TASK-A canonical", "### TASK-E canonical"]
        );
        let bytes = "### TASK-A\r\nbody without a final newline";
        assert_eq!(
            strip_marked_rollup_sections(bytes).expect("preserve bytes"),
            bytes
        );
    }

    #[test]
    fn p0_source_rollup_rejects_unbalanced_nested_and_mismatched_markers() {
        for markdown in [
            "<!-- chinwag:rollup:start -->\n### hidden",
            "<!-- chinwag:rollup:end -->\n### hidden",
            "<!-- chinwag:rollup:start -->\n<!-- chinwag:rollup:start -->\n",
            "<!-- chinwag:rollup:start -->\n<!-- chinwag:projection:end -->\n",
            "text <!-- chinwag:rollup:start -->\n### hidden",
        ] {
            assert_eq!(
                strip_marked_rollup_sections(markdown),
                Err(HeldReason::MalformedRollup)
            );
        }
    }

    #[test]
    fn p0_source_rollup_projection_heading_cannot_end_outer_rollup() {
        let markdown = "## Rollup\n<!-- chinwag:projection:start -->\n## Inside projection\n<!-- chinwag:projection:end -->\n### TASK-LEAK\n## Canonical\n### TASK-REAL\n    - [ ] TASK-INDENTED-EXAMPLE\n\t- [ ] TASK-TAB-EXAMPLE\n";
        assert_eq!(
            extract_canonical_task_lines(markdown).expect("canonical candidates"),
            vec!["### TASK-REAL"]
        );
    }

    #[test]
    fn p0_source_rollup_ignores_fenced_examples_and_preserves_task_body() {
        let markdown = "### TASK-A\n```markdown\n## Rollup\n### TASK-EXAMPLE\n<!-- chinwag:rollup:start -->\n```\n### TASK-B\n~~~\n### TASK-EXAMPLE-2\n~~~\n- [ ] TASK-C\n";
        assert_eq!(
            extract_canonical_task_lines(markdown).expect("candidates"),
            vec!["### TASK-A", "### TASK-B", "- [ ] TASK-C"]
        );
    }
}
