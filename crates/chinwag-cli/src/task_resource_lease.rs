#![forbid(unsafe_code)]
//! Local cooperative resource leases. No production authority adapter is
//! enabled. A lease is not OS containment, process retirement, or billing proof.
use crate::task_ref::validate_id;
use crate::task_resource_path::{FsIdentity, ScopeDescriptor, ScopeKind, resolve_scope};
use crate::task_scheduler::{InvocationOutcome, QualifiedLeaseAssignment, QualifiedLeaseBinding};
use crate::task_scheduler_journal::{
    MAX_SCHEDULER_FILE_BYTES, MAX_SCHEDULER_RECORD_BYTES, MAX_SCHEDULER_RECORDS, SchedulerJournal,
};
use crate::task_wire::HostClockState;
use crate::task_writer::ExecutionAdmissionV1;
use rustix::fs::{Mode, OFlags, fstat, openat};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs::File,
    io::Write,
    os::unix::fs::MetadataExt,
};

/// Matches the existing chinwag-claim MAX_TTL_SECONDS; no legacy wire changes.
pub const MAX_TTL_SECONDS: u64 = 120;
const MAX_SCOPES: usize = 32;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    Unsupported,
    Invalid,
    Authority,
    Clock,
    Expired,
    Conflict,
    ReplayConflict,
    Unknown,
    StaleGeneration,
    Identity,
    Journal(String),
    Io(String),
}
impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "resource lease refused: {self:?}")
    }
}
impl std::error::Error for LeaseError {}
type Result<T> = std::result::Result<T, LeaseError>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseStorePolicy {
    pub repo_id: String,
    pub common_git_identity: (u64, u64),
    pub authority_epoch: u64,
    pub config_digest: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceScope {
    File { path: String },
    Directory { path: String },
    Symbol { path: String, symbol: String },
    GitIndex,
    GitRef { reference: String },
    GitCommonDirectory,
    IntegrationTarget,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub scopes: Vec<ResourceScope>,
    pub ttl_seconds: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum GitScope {
    Index { scope: ScopeDescriptor },
    Ref { reference: String },
    CommonDirectory,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ResourceKey {
    Fs {
        scope: ScopeDescriptor,
        target: String,
    },
    Git {
        common: FsIdentity,
        scope: GitScope,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseStatus {
    Prepared,
    Committed,
    Bound,
    Unknown,
    Retired,
}
impl LeaseStatus {
    fn held(self) -> bool {
        self != Self::Retired
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseRow {
    id: String,
    generation: u64,
    binding: QualifiedLeaseBinding,
    keys: Vec<ResourceKey>,
    // Public write indices refer to request order; keys remain acquisition order.
    request_to_key: Vec<usize>,
    request: LeaseRequest,
    root_binding: FsIdentity,
    gitdir_binding: FsIdentity,
    integration_target: String,
    issued: u64,
    expires: u64,
    status: LeaseStatus,
    retirement: Option<String>,
    phase_revision: u64,
    retirement_phase_revision: Option<u64>,
}
impl LeaseRow {
    fn immutable(&self) -> Self {
        let mut r = self.clone();
        r.status = LeaseStatus::Prepared;
        r.retirement = None;
        r.phase_revision = 0;
        r.retirement_phase_revision = None;
        r
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Data {
    Header {
        purpose: String,
        policy: LeaseStorePolicy,
    },
    Lease {
        row: Box<LeaseRow>,
        observed: u64,
    },
    WriteChecked {
        id: String,
        generation: u64,
        observed: u64,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    revision: u64,
    data: Data,
}

pub struct PreparedLease {
    id: String,
    generation: u64,
    store: FsIdentity,
}
pub enum LeasePreparation {
    Prepared(PreparedLease),
    Existing(LeaseStatus),
}
pub struct CommittedWriteLease {
    id: String,
    generation: u64,
    store: FsIdentity,
}
/// Private trusted controlled profile. Public DTOs/flags cannot select it.
struct ControlledAuthority<'a> {
    policy: LeaseStorePolicy,
    store: FsIdentity,
    scheduler_store: (u64, u64),
    root: &'a File,
    roots: BTreeMap<FsIdentity, &'a File>,
    gitdir: &'a File,
    common: &'a File,
    target: String,
    owner: String,
    clock: &'a Cell<HostClockState>,
    retired: &'a RefCell<BTreeMap<String, RetirementWitness>>,
    current_bindings: &'a RefCell<BTreeMap<String, QualifiedLeaseBinding>>,
}
#[derive(Clone)]
struct RetirementWitness {
    binding: QualifiedLeaseBinding,
    generation: u64,
    receipt: String,
    phase_revision: u64,
}
pub struct CurrentLeaseAuthority<'a> {
    profile: Option<ControlledAuthority<'a>>,
}
impl CurrentLeaseAuthority<'_> {
    pub fn unsupported() -> Self {
        Self { profile: None }
    }
}
pub trait LeasedExecutor {
    fn invoke(
        &mut self,
        admission: &ExecutionAdmissionV1,
        writer: &mut ProtectedWriter<'_>,
    ) -> InvocationOutcome;
}

pub struct ResourceLeaseStore {
    journal: SchedulerJournal,
    identity: FsIdentity,
    policy: LeaseStorePolicy,
    next_revision: u64,
    next_generation: u64,
    max_time: u64,
    rows: BTreeMap<String, LeaseRow>,
}
fn identity(f: &File) -> Result<FsIdentity> {
    let m = f.metadata().map_err(|e| LeaseError::Io(e.to_string()))?;
    Ok(FsIdentity {
        dev: m.dev(),
        ino: m.ino(),
    })
}
fn journal_error(e: impl std::fmt::Display) -> LeaseError {
    LeaseError::Journal(e.to_string())
}
fn binding_valid(b: &QualifiedLeaseBinding) -> bool {
    b.task_ref.validate().is_ok()
        && b.workspace == b.task_ref.workspace_id
        && b.repo == b.task_ref.repo_id
        && crate::agent_instance::ActorAddress::parse(&b.owner)
            .and_then(|a| a.require_instance())
            .is_ok()
        && [&b.owner, &b.assignment, &b.operation, &b.write_scope_claim]
            .into_iter()
            .all(|x| validate_id(x, "lease binding").is_ok())
}
fn reference_valid(r: &str) -> bool {
    r.is_ascii()
        && r.len() <= 4096
        && !r
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        && !r.contains("..")
        && !r.contains("@{")
        && !r.ends_with('.')
        && r.starts_with("refs/")
        && !r.ends_with('/')
        && !r.contains(['\\', '\0', ' ', '~', '^', ':', '?', '*', '['])
        && r.split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && !p.ends_with(".lock"))
}
fn is_directory(s: &ScopeDescriptor) -> bool {
    matches!(s.kind, ScopeKind::Directory)
}
fn descendant(parent: &str, path: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|tail| tail.starts_with('/'))
}
fn valid_request_mapping(row: &LeaseRow, policy: &LeaseStorePolicy) -> bool {
    if row.request_to_key.len() != row.request.scopes.len()
        || row.keys.len() != row.request.scopes.len()
    {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    let encoded: Vec<_> = row
        .keys
        .iter()
        .map(|k| serde_json::to_vec(k).unwrap_or_default())
        .collect();
    if encoded.windows(2).any(|p| p[0] >= p[1]) {
        return false;
    }
    for (request, index) in row.request.scopes.iter().zip(&row.request_to_key) {
        if !seen.insert(*index) {
            return false;
        }
        let Some(key) = row.keys.get(*index) else {
            return false;
        };
        let common = FsIdentity {
            dev: policy.common_git_identity.0,
            ino: policy.common_git_identity.1,
        };
        let valid = match (request, key) {
            (ResourceScope::File { path }, ResourceKey::Fs { scope, target }) => {
                scope.path == *path
                    && scope.kind == ScopeKind::File
                    && scope.root == row.root_binding
                    && target == &row.integration_target
            }
            (ResourceScope::Directory { path }, ResourceKey::Fs { scope, target }) => {
                scope.path == *path
                    && scope.kind == ScopeKind::Directory
                    && scope.root == row.root_binding
                    && target == &row.integration_target
            }
            (ResourceScope::Symbol { path, symbol }, ResourceKey::Fs { scope, target }) => {
                scope.path == *path
                    && scope.kind
                        == (ScopeKind::Symbol {
                            symbol: symbol.clone(),
                        })
                    && scope.root == row.root_binding
                    && target == &row.integration_target
            }
            (
                ResourceScope::GitIndex,
                ResourceKey::Git {
                    common: c,
                    scope: GitScope::Index { scope },
                },
            ) => {
                *c == common
                    && scope.root == row.gitdir_binding
                    && scope.path == "index"
                    && scope.kind == ScopeKind::File
            }
            (
                ResourceScope::GitRef { reference },
                ResourceKey::Git {
                    common: c,
                    scope: GitScope::Ref { reference: r },
                },
            ) => *c == common && reference == r,
            (
                ResourceScope::IntegrationTarget,
                ResourceKey::Git {
                    common: c,
                    scope: GitScope::Ref { reference },
                },
            ) => *c == common && reference == &row.integration_target,
            (
                ResourceScope::GitCommonDirectory,
                ResourceKey::Git {
                    common: c,
                    scope: GitScope::CommonDirectory,
                },
            ) => *c == common,
            _ => false,
        };
        if !valid {
            return false;
        }
    }
    true
}
fn conflict(a: &ResourceKey, b: &ResourceKey) -> bool {
    fn physical(key: &ResourceKey) -> Option<&ScopeDescriptor> {
        match key {
            ResourceKey::Fs { scope, .. }
            | ResourceKey::Git {
                scope: GitScope::Index { scope },
                ..
            } => Some(scope),
            _ => None,
        }
    }
    if let (Some(a), Some(b)) = (physical(a), physical(b))
        && ((a.target.is_some() && a.target == b.target)
            || (a.parent == b.parent
                && a.folded_path.rsplit('/').next() == b.folded_path.rsplit('/').next())
            || (is_directory(a) && a.target.is_some_and(|id| b.ancestors.contains(&id)))
            || (is_directory(b) && b.target.is_some_and(|id| a.ancestors.contains(&id))))
    {
        return true;
    }
    match (a, b) {
        (
            ResourceKey::Fs {
                scope: a,
                target: ta,
            },
            ResourceKey::Fs {
                scope: b,
                target: tb,
            },
        ) => {
            (a.target.is_some() && a.target == b.target)
                || (a.parent == b.parent
                    && a.folded_path.rsplit('/').next() == b.folded_path.rsplit('/').next())
                || (is_directory(a) && a.target.is_some_and(|id| b.ancestors.contains(&id)))
                || (is_directory(b) && b.target.is_some_and(|id| a.ancestors.contains(&id)))
                || (ta.eq_ignore_ascii_case(tb)
                    && (a.folded_path == b.folded_path
                        || (is_directory(a) && descendant(&a.folded_path, &b.folded_path))
                        || (is_directory(b) && descendant(&b.folded_path, &a.folded_path))))
        }
        (
            ResourceKey::Git {
                common: a,
                scope: sa,
            },
            ResourceKey::Git {
                common: b,
                scope: sb,
            },
        ) => {
            a == b
                && (sa == sb
                    || matches!((sa, sb), (GitScope::Ref { .. }, GitScope::Ref { .. }))
                    || matches!(sa, GitScope::CommonDirectory)
                    || matches!(sb, GitScope::CommonDirectory))
        }
        (
            ResourceKey::Fs { target, .. },
            ResourceKey::Git {
                scope: GitScope::Ref { reference },
                ..
            },
        )
        | (
            ResourceKey::Git {
                scope: GitScope::Ref { reference },
                ..
            },
            ResourceKey::Fs { target, .. },
        ) => target.eq_ignore_ascii_case(reference),
        (
            ResourceKey::Fs { .. },
            ResourceKey::Git {
                scope: GitScope::CommonDirectory,
                ..
            },
        )
        | (
            ResourceKey::Git {
                scope: GitScope::CommonDirectory,
                ..
            },
            ResourceKey::Fs { .. },
        ) => true,
        _ => false,
    }
}
impl ResourceLeaseStore {
    pub fn open(directory: &File, policy: LeaseStorePolicy) -> Result<Self> {
        validate_id(&policy.repo_id, "repo").map_err(|_| LeaseError::Invalid)?;
        if policy.authority_epoch == 0 {
            return Err(LeaseError::Invalid);
        }
        let journal =
            SchedulerJournal::open_resource_leases(directory, rustix::process::geteuid().as_raw())
                .map_err(journal_error)?;
        let records = journal.records().to_vec();
        let mut s = Self {
            journal,
            identity: identity(directory)?,
            policy,
            next_revision: 1,
            next_generation: 0,
            max_time: 0,
            rows: BTreeMap::new(),
        };
        let mut bytes = 0;
        for (index, b) in records.into_iter().enumerate() {
            bytes += b.len() + 1;
            let r: Record = serde_json::from_slice(&b).map_err(|_| LeaseError::Invalid)?;
            s.apply(&r)?;
            let reserve = s.reserve();
            if index + 1 + reserve > MAX_SCHEDULER_RECORDS
                || bytes + reserve * MAX_SCHEDULER_RECORD_BYTES > MAX_SCHEDULER_FILE_BYTES as usize
            {
                return Err(LeaseError::Invalid);
            }
        }
        if s.next_revision == 1 {
            s.append(Data::Header {
                purpose: "repository-resource-leases-v1".into(),
                policy: s.policy.clone(),
            })?;
        }
        Ok(s)
    }
    fn reserve(&self) -> usize {
        self.rows
            .values()
            .map(|r| match r.status {
                LeaseStatus::Prepared => 4,
                LeaseStatus::Committed => 3,
                LeaseStatus::Bound => 2,
                LeaseStatus::Unknown => 1,
                LeaseStatus::Retired => 0,
            })
            .sum()
    }
    fn apply(&mut self, r: &Record) -> Result<()> {
        if r.revision != self.next_revision {
            return Err(LeaseError::Invalid);
        }
        match &r.data {
            Data::Header { purpose, policy } => {
                if r.revision != 1
                    || purpose != "repository-resource-leases-v1"
                    || policy != &self.policy
                {
                    return Err(LeaseError::Authority);
                }
            }
            Data::WriteChecked {
                id,
                generation,
                observed,
            } => {
                let row = self.rows.get_mut(id).ok_or(LeaseError::Invalid)?;
                if r.revision == 1
                    || row.status != LeaseStatus::Bound
                    || row.generation != *generation
                    || *observed < self.max_time
                    || *observed >= row.expires
                    || *observed >= row.binding.original_deadline
                {
                    return Err(LeaseError::Invalid);
                }
                self.max_time = *observed;
                row.phase_revision = r.revision;
            }
            Data::Lease { row, observed } => {
                if r.revision == 1
                    || row.phase_revision != r.revision
                    || !binding_valid(&row.binding)
                    || row.binding.repo != self.policy.repo_id
                    || row.binding.authority_epoch != self.policy.authority_epoch
                    || *observed < self.max_time
                    || row.keys.is_empty()
                    || row.keys.len() > MAX_SCOPES
                    || !valid_request_mapping(row, &self.policy)
                    || row.request.scopes.is_empty()
                    || row.request.scopes.len() > MAX_SCOPES
                    || row.request.ttl_seconds == 0
                    || row.request.ttl_seconds > MAX_TTL_SECONDS
                    || row.expires <= row.issued
                    || row.expires - row.issued > MAX_TTL_SECONDS
                    || row.expires - row.issued > row.request.ttl_seconds
                    || row.expires > row.binding.original_deadline
                {
                    return Err(LeaseError::Invalid);
                }
                if let Some(old) = self.rows.get(&row.id) {
                    if row.status == LeaseStatus::Retired
                        && row.retirement_phase_revision != Some(old.phase_revision)
                    {
                        return Err(LeaseError::Authority);
                    }
                    if old.immutable() != row.immutable()
                        || !matches!(
                            (old.status, row.status),
                            (
                                LeaseStatus::Prepared,
                                LeaseStatus::Committed | LeaseStatus::Unknown
                            ) | (
                                LeaseStatus::Committed,
                                LeaseStatus::Bound | LeaseStatus::Unknown
                            ) | (LeaseStatus::Bound, LeaseStatus::Unknown)
                                | (
                                    LeaseStatus::Prepared
                                        | LeaseStatus::Committed
                                        | LeaseStatus::Bound
                                        | LeaseStatus::Unknown,
                                    LeaseStatus::Retired
                                )
                        )
                    {
                        return Err(LeaseError::ReplayConflict);
                    }
                } else {
                    if row.id != row.binding.assignment
                        || row.status != LeaseStatus::Prepared
                        || row.generation != self.next_generation + 1
                        || row.issued != *observed
                        || row.retirement.is_some()
                        || self
                            .rows
                            .values()
                            .filter(|old| old.status.held())
                            .any(|old| {
                                old.keys
                                    .iter()
                                    .any(|a| row.keys.iter().any(|b| conflict(a, b)))
                            })
                    {
                        return Err(LeaseError::Conflict);
                    }
                    self.next_generation = row.generation;
                }
                if (row.status == LeaseStatus::Retired) != row.retirement.is_some() {
                    return Err(LeaseError::Invalid);
                }
                if (row.status == LeaseStatus::Retired) != row.retirement_phase_revision.is_some() {
                    return Err(LeaseError::Invalid);
                }
                self.rows.insert(row.id.clone(), row.as_ref().clone());
                self.max_time = *observed;
            }
        }
        self.next_revision = self
            .next_revision
            .checked_add(1)
            .ok_or(LeaseError::Invalid)?;
        Ok(())
    }
    fn append(&mut self, mut data: Data) -> Result<()> {
        if let Data::Lease { row, .. } = &mut data {
            row.phase_revision = self.next_revision;
        }
        let r = Record {
            revision: self.next_revision,
            data,
        };
        let bytes = serde_json::to_vec(&r).map_err(|_| LeaseError::Invalid)?;
        let before = (
            self.next_revision,
            self.next_generation,
            self.max_time,
            self.rows.clone(),
        );
        let result = self.apply(&r).and_then(|()| {
            let reserve = self.reserve();
            self.journal
                .append(&bytes, reserve, reserve * MAX_SCHEDULER_RECORD_BYTES)
                .map_err(journal_error)
        });
        if result.is_err() {
            (
                self.next_revision,
                self.next_generation,
                self.max_time,
                self.rows,
            ) = before;
        }
        result
    }
    fn current<'a>(
        &self,
        a: &'a CurrentLeaseAuthority<'a>,
    ) -> Result<(&'a ControlledAuthority<'a>, u64)> {
        self.journal.verify().map_err(journal_error)?;
        let p = a.profile.as_ref().ok_or(LeaseError::Unsupported)?;
        if p.policy != self.policy
            || p.store != self.identity
            || p.scheduler_store == (self.identity.dev, self.identity.ino)
            || !p.roots.contains_key(&identity(p.root)?)
            || identity(p.common)?
                != (FsIdentity {
                    dev: self.policy.common_git_identity.0,
                    ino: self.policy.common_git_identity.1,
                })
        {
            return Err(LeaseError::Authority);
        }
        for (pin, root) in &p.roots {
            if identity(root)? != *pin {
                return Err(LeaseError::Authority);
            }
        }
        let now = match p.clock.get() {
            HostClockState::Verified { now_unix } if now_unix >= self.max_time => now_unix,
            _ => return Err(LeaseError::Clock),
        };
        Ok((p, now))
    }
    fn keys(
        &self,
        request: &LeaseRequest,
        p: &ControlledAuthority<'_>,
    ) -> Result<(Vec<ResourceKey>, Vec<usize>)> {
        if request.scopes.is_empty()
            || request.scopes.len() > MAX_SCOPES
            || request.ttl_seconds == 0
            || request.ttl_seconds > MAX_TTL_SECONDS
            || !reference_valid(&p.target)
        {
            return Err(LeaseError::Invalid);
        }
        let mut keys = Vec::new();
        for scope in &request.scopes {
            let key = match scope {
                ResourceScope::File { path } => ResourceKey::Fs {
                    scope: resolve_scope(p.root, path, ScopeKind::File)
                        .map_err(|_| LeaseError::Identity)?
                        .descriptor,
                    target: p.target.clone(),
                },
                ResourceScope::Directory { path } => ResourceKey::Fs {
                    scope: resolve_scope(p.root, path, ScopeKind::Directory)
                        .map_err(|_| LeaseError::Identity)?
                        .descriptor,
                    target: p.target.clone(),
                },
                ResourceScope::Symbol { path, symbol } => ResourceKey::Fs {
                    scope: resolve_scope(
                        p.root,
                        path,
                        ScopeKind::Symbol {
                            symbol: symbol.clone(),
                        },
                    )
                    .map_err(|_| LeaseError::Identity)?
                    .descriptor,
                    target: p.target.clone(),
                },
                ResourceScope::GitIndex => ResourceKey::Git {
                    common: identity(p.common)?,
                    scope: GitScope::Index {
                        scope: resolve_scope(p.gitdir, "index", ScopeKind::File)
                            .map_err(|_| LeaseError::Identity)?
                            .descriptor,
                    },
                },
                ResourceScope::GitRef { reference } => {
                    if !reference_valid(reference) {
                        return Err(LeaseError::Invalid);
                    }
                    ResourceKey::Git {
                        common: identity(p.common)?,
                        scope: GitScope::Ref {
                            reference: reference.clone(),
                        },
                    }
                }
                ResourceScope::GitCommonDirectory => ResourceKey::Git {
                    common: identity(p.common)?,
                    scope: GitScope::CommonDirectory,
                },
                ResourceScope::IntegrationTarget => ResourceKey::Git {
                    common: identity(p.common)?,
                    scope: GitScope::Ref {
                        reference: p.target.clone(),
                    },
                },
            };
            keys.push(key);
        }
        let mut indexed: Vec<_> = keys.into_iter().enumerate().collect();
        indexed.sort_by_key(|(_, k)| serde_json::to_vec(k).unwrap_or_default());
        let mut request_to_key = vec![0; indexed.len()];
        let keys: Vec<_> = indexed
            .into_iter()
            .enumerate()
            .map(|(ordered, (request, key))| {
                request_to_key[request] = ordered;
                key
            })
            .collect();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LeaseError::Invalid);
        }
        Ok((keys, request_to_key))
    }
    fn validate_scopes(&self, row: &LeaseRow, p: &ControlledAuthority<'_>) -> Result<()> {
        for key in &row.keys {
            let scope = match key {
                ResourceKey::Fs { scope, .. }
                | ResourceKey::Git {
                    scope: GitScope::Index { scope },
                    ..
                } => scope,
                _ => continue,
            };
            let root = p.roots.get(&scope.root).ok_or(LeaseError::Identity)?;
            let current = resolve_scope(root, &scope.path, scope.kind.clone())
                .map_err(|_| LeaseError::Identity)?;
            if current.descriptor != *scope {
                return Err(LeaseError::Identity);
            }
            current.verify().map_err(|_| LeaseError::Identity)?;
        }
        Ok(())
    }
    fn binding_current(p: &ControlledAuthority<'_>, b: &QualifiedLeaseBinding) -> bool {
        b.scheduler_store == p.scheduler_store
            && b.owner == p.owner
            && p.current_bindings.borrow().get(&b.assignment) == Some(b)
    }
    fn refresh_conflicts(&self, keys: &[ResourceKey], p: &ControlledAuthority<'_>) -> Result<()> {
        for row in self.rows.values().filter(|r| r.status.held()) {
            for old in &row.keys {
                if keys.iter().any(|key| conflict(old, key)) {
                    return Err(LeaseError::Conflict);
                }
                let scope = match old {
                    ResourceKey::Fs { scope, .. }
                    | ResourceKey::Git {
                        scope: GitScope::Index { scope },
                        ..
                    } => Some(scope),
                    _ => None,
                };
                if let Some(scope) = scope {
                    // Retain old inode ownership AND refresh the reserved name:
                    // replacement must not create a hardlink-alias loophole.
                    if keys.iter().any(|k| {
                        matches!(
                            k,
                            ResourceKey::Fs { .. }
                                | ResourceKey::Git {
                                    scope: GitScope::Index { .. },
                                    ..
                                }
                        )
                    }) {
                        let root = p.roots.get(&scope.root).ok_or(LeaseError::Identity)?;
                        let current = resolve_scope(root, &scope.path, scope.kind.clone())
                            .map_err(|_| LeaseError::Identity)?;
                        let refreshed = match old {
                            ResourceKey::Fs { target, .. } => ResourceKey::Fs {
                                scope: current.descriptor,
                                target: target.clone(),
                            },
                            ResourceKey::Git { common, .. } => ResourceKey::Git {
                                common: *common,
                                scope: GitScope::Index {
                                    scope: current.descriptor,
                                },
                            },
                        };
                        if keys.iter().any(|key| conflict(&refreshed, key)) {
                            return Err(LeaseError::Conflict);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub fn prepare(
        &mut self,
        assignment: &QualifiedLeaseAssignment,
        request: LeaseRequest,
        a: &CurrentLeaseAuthority<'_>,
    ) -> Result<LeasePreparation> {
        let (p, now) = self.current(a)?;
        let b = assignment.binding();
        if b.scheduler_store != p.scheduler_store
            || b.repo != self.policy.repo_id
            || b.authority_epoch != self.policy.authority_epoch
            || !Self::binding_current(p, b)
            || !binding_valid(b)
        {
            return Err(LeaseError::Authority);
        }
        if let Some(old) = self.rows.get(&b.assignment) {
            return if old.binding == *b && old.request == request {
                Ok(LeasePreparation::Existing(old.status))
            } else {
                Err(LeaseError::ReplayConflict)
            };
        }
        let (keys, request_to_key) = self.keys(&request, p)?;
        self.refresh_conflicts(&keys, p)?;
        let expires = now
            .checked_add(request.ttl_seconds)
            .ok_or(LeaseError::Invalid)?
            .min(b.original_deadline);
        if expires <= now {
            return Err(LeaseError::Expired);
        }
        let row = LeaseRow {
            id: b.assignment.clone(),
            generation: self.next_generation + 1,
            binding: b.clone(),
            keys,
            request_to_key,
            request,
            root_binding: identity(p.root)?,
            gitdir_binding: identity(p.gitdir)?,
            integration_target: p.target.clone(),
            issued: now,
            expires,
            status: LeaseStatus::Prepared,
            retirement: None,
            phase_revision: 0,
            retirement_phase_revision: None,
        };
        let prepared = PreparedLease {
            id: row.id.clone(),
            generation: row.generation,
            store: self.identity,
        };
        self.append(Data::Lease {
            row: Box::new(row),
            observed: now,
        })?;
        Ok(LeasePreparation::Prepared(prepared))
    }
    pub fn commit(
        &mut self,
        prepared: PreparedLease,
        a: &CurrentLeaseAuthority<'_>,
    ) -> Result<CommittedWriteLease> {
        let (p, now) = self.current(a)?;
        if prepared.store != self.identity {
            return Err(LeaseError::Authority);
        }
        let mut row = self
            .rows
            .get(&prepared.id)
            .cloned()
            .ok_or(LeaseError::Invalid)?;
        if !Self::binding_current(p, &row.binding) {
            return Err(LeaseError::Authority);
        }
        if row.root_binding != identity(p.root)?
            || row.gitdir_binding != identity(p.gitdir)?
            || row.integration_target != p.target
        {
            return Err(LeaseError::Authority);
        }
        if row.generation != prepared.generation || row.status != LeaseStatus::Prepared {
            return Err(LeaseError::StaleGeneration);
        }
        if now >= row.expires {
            return Err(LeaseError::Expired);
        }
        self.validate_scopes(&row, p)?;
        row.status = LeaseStatus::Committed;
        self.append(Data::Lease {
            row: Box::new(row),
            observed: now,
        })?;
        Ok(CommittedWriteLease {
            id: prepared.id,
            generation: prepared.generation,
            store: self.identity,
        })
    }
    fn validate_cap(
        &self,
        cap: &CommittedWriteLease,
        binding: &QualifiedLeaseBinding,
        a: &CurrentLeaseAuthority<'_>,
    ) -> Result<u64> {
        let (p, now) = self.current(a)?;
        let row = self.rows.get(&cap.id).ok_or(LeaseError::Invalid)?;
        if cap.store != self.identity
            || cap.generation != row.generation
            || row.binding != *binding
            || binding.scheduler_store != p.scheduler_store
            || !Self::binding_current(p, binding)
            || row.root_binding != identity(p.root)?
            || row.gitdir_binding != identity(p.gitdir)?
            || row.integration_target != p.target
        {
            return Err(LeaseError::Authority);
        }
        if !matches!(row.status, LeaseStatus::Committed | LeaseStatus::Bound) {
            return Err(LeaseError::Unknown);
        }
        if now >= row.expires || now >= binding.original_deadline {
            return Err(LeaseError::Expired);
        }
        self.validate_scopes(row, p)?;
        Ok(now)
    }
    pub(crate) fn invoke(
        &mut self,
        cap: CommittedWriteLease,
        assignment: &QualifiedLeaseAssignment,
        a: &CurrentLeaseAuthority<'_>,
        invoke: impl FnOnce(&mut ProtectedWriter<'_>) -> InvocationOutcome,
    ) -> Result<InvocationOutcome> {
        let now = self.validate_cap(&cap, assignment.binding(), a)?;
        let mut row = self.rows[&cap.id].clone();
        row.status = LeaseStatus::Bound;
        self.append(Data::Lease {
            row: Box::new(row),
            observed: now,
        })?;
        let outcome = {
            let mut writer = ProtectedWriter {
                store: self,
                cap: &cap,
                binding: assignment.binding(),
                authority: a,
            };
            invoke(&mut writer)
        };
        let persistence = (|| -> Result<()> {
            let (_, now) = self.current(a)?;
            let mut row = self.rows[&cap.id].clone();
            row.status = LeaseStatus::Unknown;
            self.append(Data::Lease {
                row: Box::new(row),
                observed: now,
            })?;
            Ok(())
        })();
        Ok(if persistence.is_ok() {
            outcome
        } else {
            InvocationOutcome::Unknown {
                reason: "resource-lease-effect-or-disposition-held".into(),
            }
        })
    }
    pub fn reconcile_original(
        &mut self,
        id: &str,
        a: &CurrentLeaseAuthority<'_>,
    ) -> Result<LeaseStatus> {
        let (p, now) = self.current(a)?;
        let mut row = self.rows.get(id).cloned().ok_or(LeaseError::Invalid)?;
        if row.status == LeaseStatus::Retired {
            return Ok(row.status);
        }
        let evidence = p
            .retired
            .borrow()
            .get(&row.binding.operation)
            .cloned()
            .ok_or(LeaseError::Unknown)?;
        if evidence.binding != row.binding
            || evidence.generation != row.generation
            || evidence.phase_revision != row.phase_revision
            || validate_id(&evidence.receipt, "retirement receipt").is_err()
        {
            return Err(LeaseError::Authority);
        }
        row.status = LeaseStatus::Retired;
        row.retirement = Some(evidence.receipt);
        row.retirement_phase_revision = Some(evidence.phase_revision);
        self.append(Data::Lease {
            row: Box::new(row),
            observed: now,
        })?;
        Ok(LeaseStatus::Retired)
    }
    pub fn status(&self, id: &str) -> Option<LeaseStatus> {
        self.rows.get(id).map(|r| r.status)
    }
}

/// This object exposes operations, never writable descriptors or raw paths.
/// Checks guard this cooperative API; they are not OS-level containment and
/// cannot preempt an already-running kernel write or retire another writer.
pub struct ProtectedWriter<'a> {
    store: &'a mut ResourceLeaseStore,
    cap: &'a CommittedWriteLease,
    binding: &'a QualifiedLeaseBinding,
    authority: &'a CurrentLeaseAuthority<'a>,
}
impl ProtectedWriter<'_> {
    pub fn write_file(&mut self, scope_index: usize, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 65_536 {
            return Err(LeaseError::Invalid);
        }
        self.store
            .validate_cap(self.cap, self.binding, self.authority)?;
        let (profile, _) = self.store.current(self.authority)?;
        let row = &self.store.rows[&self.cap.id];
        let descriptor = match row
            .request_to_key
            .get(scope_index)
            .and_then(|index| row.keys.get(*index))
        {
            Some(ResourceKey::Fs { scope, .. }) if !is_directory(scope) => scope.clone(),
            _ => return Err(LeaseError::Unsupported),
        };
        let resolved = resolve_scope(profile.root, &descriptor.path, descriptor.kind.clone())
            .map_err(|_| LeaseError::Identity)?;
        if resolved.descriptor != descriptor || descriptor.target.is_none() {
            return Err(LeaseError::Identity);
        }
        resolved.verify().map_err(|_| LeaseError::Identity)?;
        let name = descriptor
            .path
            .rsplit('/')
            .next()
            .ok_or(LeaseError::Invalid)?;
        let mut file = File::from(
            openat(
                &resolved.parent,
                name,
                OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| LeaseError::Io(e.to_string()))?,
        );
        let stat = fstat(&file).map_err(|e| LeaseError::Io(e.to_string()))?;
        if Some(FsIdentity {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
        }) != descriptor.target
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_nlink != 1
        {
            return Err(LeaseError::Identity);
        }
        let observed = self
            .store
            .validate_cap(self.cap, self.binding, self.authority)?;
        self.store.append(Data::WriteChecked {
            id: self.cap.id.clone(),
            generation: self.cap.generation,
            observed,
        })?;
        file.set_len(0)
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.sync_all())
            .map_err(|e| LeaseError::Io(e.to_string()))?;
        // Observation after the effect reports drift; it cannot roll back the
        // write or establish an atomic namespace/write primitive.
        let post = resolve_scope(profile.root, &descriptor.path, descriptor.kind.clone())
            .map_err(|_| LeaseError::Identity)?;
        if post.descriptor != descriptor {
            return Err(LeaseError::Identity);
        }
        post.verify().map_err(|_| LeaseError::Identity)
    }
}

#[cfg(test)]
#[path = "task_resource_lease_tests.rs"]
pub(crate) mod tests;
