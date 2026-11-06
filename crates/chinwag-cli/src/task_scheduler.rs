#![forbid(unsafe_code)]
//! Shared, durable Phase 0 admission. Legacy CLI dispatch has no authority here.
//!
//! The public authority constructor is deliberately unsupported for execution:
//! approved lease/execution adapters arrive in P0-08/P0-09. Positive conformance
//! uses a private in-module profile, not caller booleans or a public `Done` DTO.
use crate::task_dependency::{
    DependencyNode, DependencySourceBinding, ResolvedDependency, TaskStatus,
    validate_dependency_graph, validate_dependency_satisfaction,
};
use crate::task_ref::{
    MAX_REV_COUNTER, Sha256Digest, TaskContractError, TaskKey, TaskRefV1, validate_id,
};
use crate::task_scheduler_journal::{
    MAX_SCHEDULER_FILE_BYTES, MAX_SCHEDULER_RECORD_BYTES, MAX_SCHEDULER_RECORDS, SchedulerJournal,
};
use crate::task_source::{
    TaskSourceRecord, TaskSourceState, WorkspaceSourceRegistry, WorkspaceTaskPolicy,
};
use crate::task_wire::{
    HostClockState, RatifiedPayloadProfile, TaskActionableBodyV1, TaskMessageKind,
    VerifiedTaskMessage,
};
use crate::task_writer::{
    CanonicalTaskDocumentV1, CanonicalTaskStatus, ExecutionAdmissionV1, TaskEntrySnapshotV1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt;

pub const QUALIFIED_ADMISSION_REQUIRED: &str = "HELD_QUALIFIED_SCHEDULER_ADMISSION_REQUIRED";
pub const ASSIGNMENT_PROFILE: &str = "chinwag-scheduler-assignment-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    Invalid,
    CorruptJournal,
    PolicyChanged,
    StaleTask,
    StaleGraph,
    StaleEpoch,
    Clock,
    Expired,
    UnsupportedAdapters,
    Grant,
    Dependency,
    DependencyBlocked(DependencyBlockReason),
    NoEligibleTask,
    NotFairTurn,
    Capacity,
    Budget,
    ReplayConflict,
    AlreadyActive,
    Journal(String),
    ResourceLeaseHeld(String),
}
impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "scheduler held: {self:?}")
    }
}
impl std::error::Error for SchedulerError {}

/// Observational diagnostics for one affected full TaskKey, never admission
/// authority. Structural closure errors are reported before completion checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyBlockReason {
    UnresolvedTarget {
        target: TaskKey,
    },
    SourceUnavailable {
        target: TaskKey,
        state: TaskSourceState,
    },
    Cycle,
    InvalidGraph(TaskContractError),
    UnacceptedCompletion {
        target: TaskKey,
    },
    UnsatisfiedCommitment {
        target: TaskKey,
    },
}

type Result<T> = std::result::Result<T, SchedulerError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionTrigger {
    Manual,
    Timer,
    Event,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionStatus {
    Claimed,
    Unknown,
    Completed,
    RejectedBeforeInvocation,
}
impl AdmissionStatus {
    fn active(self) -> bool {
        matches!(self, Self::Claimed | Self::Unknown)
    }
}

/// Request bytes are signed by the existing task/2 envelope, never authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentRequest {
    pub action: String,
    pub executor_actor: String,
    pub resource: String,
    pub grant_id: String,
    pub execution_binding_id: String,
    pub write_scope_claim_id: String,
    pub tokens: u64,
    pub micro_usd: u64,
    pub dag_revision: u64,
}
impl AssignmentRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        for x in [
            &self.action,
            &self.executor_actor,
            &self.resource,
            &self.grant_id,
            &self.execution_binding_id,
            &self.write_scope_claim_id,
        ] {
            validate_id(x, "scheduler assignment").map_err(|_| SchedulerError::Invalid)?;
        }
        crate::agent_instance::ActorAddress::parse(&self.executor_actor)
            .and_then(|a| a.require_instance())
            .map_err(|_| SchedulerError::Invalid)?;
        serde_json::to_vec(self).map_err(|_| SchedulerError::Invalid)
    }
}
fn valid_payload(b: &[u8]) -> bool {
    serde_json::from_slice::<AssignmentRequest>(b).is_ok_and(|r| r.encode().is_ok_and(|v| v == b))
}
pub fn assignment_profile() -> RatifiedPayloadProfile<'static> {
    RatifiedPayloadProfile {
        kind: TaskMessageKind::Assignment,
        name: ASSIGNMENT_PROFILE,
        validate_canonical_payload: valid_payload,
    }
}

#[derive(Clone)]
struct Grant {
    id: String,
    principal: String,
    action: String,
    executor: String,
    resource: String,
    spec: Sha256Digest,
    controls: Sha256Digest,
    expires: u64,
    max_tokens: u64,
    max_micro_usd: u64,
}
#[derive(Clone)]
struct ControlledProfile {
    store_identity: (u64, u64),
    grants: BTreeMap<TaskKey, Grant>,
    capacities: BTreeMap<String, u16>,
    execution_binding: String,
    write_claim: String,
    token_limit: u64,
    micro_usd_limit: u64,
    accepted_dependencies: BTreeMap<TaskKey, AcceptedCompletion>,
}
// Populated only by the private trusted fixture authority, which binds the
// verified acceptance commitment to the exact current source projection.
// A public parsed Done row or caller-supplied boolean cannot construct it.
#[derive(Clone)]
struct AcceptedCompletion {
    reference: TaskRefV1,
    controls: Sha256Digest,
    policy: Sha256Digest,
    verified_acceptance: Sha256Digest,
}
/// Trusted current-source access, not deserializable message data. Construction
/// cannot turn on execution. Real adapter proof must replace the explicit hold.
pub struct CurrentAuthority<'a> {
    registry: &'a WorkspaceSourceRegistry,
    clock: HostClockState,
    profile: Option<ControlledProfile>,
}
impl<'a> CurrentAuthority<'a> {
    pub fn unsupported(registry: &'a WorkspaceSourceRegistry, clock: HostClockState) -> Self {
        Self {
            registry,
            clock,
            profile: None,
        }
    }
}
#[derive(Clone)]
struct CatalogTask {
    reference: TaskRefV1,
    entry: TaskEntrySnapshotV1,
    source: TaskSourceRecord,
}
struct EligibleTask {
    request: AssignmentRequest,
    grant: Grant,
    reference: TaskRefV1,
    principal: String,
    digest: Sha256Digest,
    assignment: String,
    operation: String,
    deadline: u64,
    now: u64,
}
/// Consumed by value. No public constructor, deserializer, or Clone can mint an
/// invocation capability from an ACK, row, enum, or replayed record.
pub struct ClaimedAssignment {
    id: String,
    digest: Sha256Digest,
    message: Box<VerifiedTaskMessage>,
}
/// Only this module can qualify a currently durable once-only claim. Public
/// execution DTOs and string claim IDs cannot construct this capability.
pub struct QualifiedLeaseAssignment {
    binding: QualifiedLeaseBinding,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct QualifiedLeaseBinding {
    pub scheduler_store: (u64, u64),
    pub workspace: String,
    pub repo: String,
    pub authority_epoch: u64,
    pub owner: String,
    pub assignment: String,
    pub operation: String,
    pub write_scope_claim: String,
    pub original_deadline: u64,
    pub assignment_digest: [u8; 32],
    #[serde(with = "crate::task_acceptance::TaskRefJson")]
    pub task_ref: TaskRefV1,
}
impl QualifiedLeaseAssignment {
    pub(crate) fn binding(&self) -> &QualifiedLeaseBinding {
        &self.binding
    }
    #[cfg(test)]
    pub(crate) fn fixture(binding: QualifiedLeaseBinding) -> Self {
        Self { binding }
    }
}
pub enum AdmissionDisposition {
    Claimed(ClaimedAssignment),
    Existing(AdmissionStatus),
}
#[derive(Debug, Clone)]
pub struct SelectedTask {
    pub task_ref: TaskRefV1,
    pub dag_revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationOutcome {
    ConfirmedRetired {
        original_operation_id: String,
        receipt_id: String,
    },
    Unknown {
        reason: String,
    },
}
/// A future approved adapter must authenticate its original native evidence.
/// This trait does not enable production; CurrentAuthority remains held there.
pub trait ControlledExecutor {
    fn invoke(&mut self, admission: &ExecutionAdmissionV1) -> InvocationOutcome;
}
pub trait OriginalOutcomeLookup {
    fn lookup(&mut self, admission: &ExecutionAdmissionV1) -> InvocationOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    workspace: String,
    repo: String,
    revision: u64,
    epoch: u64,
    owner: String,
    config: [u8; 32],
}
impl From<&WorkspaceTaskPolicy> for Policy {
    fn from(p: &WorkspaceTaskPolicy) -> Self {
        Self {
            workspace: p.workspace_id.clone(),
            repo: p.repo_id.clone(),
            revision: p.config_revision,
            epoch: p.authority_epoch,
            owner: p.scheduler_owner.clone(),
            config: p.config_digest,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    id: String,
    operation: String,
    actor: String,
    principal: String,
    #[serde(with = "crate::task_acceptance::TaskRefJson")]
    reference: TaskRefV1,
    controls: Sha256Bytes,
    request: AssignmentRequest,
    digest: Sha256Bytes,
    deadline: u64,
    epoch: u64,
    trigger: AdmissionTrigger,
    status: AdmissionStatus,
    outcome: Option<String>,
}
// SHA bytes are local journal metadata, not a replacement signed wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Sha256Bytes([u8; 32]);
impl Assignment {
    fn immutable(&self) -> Self {
        let mut x = self.clone();
        x.status = AdmissionStatus::Claimed;
        x.outcome = None;
        x
    }
    fn execution(&self) -> ExecutionAdmissionV1 {
        ExecutionAdmissionV1 {
            actor: self.actor.clone(),
            authenticated_signer_principal: self.principal.clone(),
            executor_actor: self.request.executor_actor.clone(),
            task_ref: self.reference.clone(),
            task_control_digest: Sha256Digest(self.controls.0),
            admission_id: self.id.clone(),
            assignment_id: self.id.clone(),
            original_operation_id: self.operation.clone(),
            action: self.request.action.clone(),
            grant_id: self.request.grant_id.clone(),
            capacity_claim_id: self.id.clone(),
            write_scope_claim_id: self.request.write_scope_claim_id.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Data {
    Header {
        policy: Policy,
    },
    Enqueue {
        keys: Vec<Vec<u8>>,
    },
    Graph {
        digest: [u8; 32],
    },
    Assignment {
        assignment: Box<Assignment>,
        observed_at: u64,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    revision: u64,
    data: Data,
}

pub struct WorkspaceScheduler {
    journal: SchedulerJournal,
    store_identity: (u64, u64),
    policy: Policy,
    next_revision: u64,
    queued: BTreeMap<TaskKey, u64>,
    next_ordinal: u64,
    graph: Option<[u8; 32]>,
    dag_revision: u64,
    last_source: Option<String>,
    assignments: BTreeMap<String, Assignment>,
    max_time: u64,
    catalog: BTreeMap<TaskKey, CatalogTask>,
    unavailable_sources: BTreeMap<String, TaskSourceState>,
    blocked_dependencies: BTreeMap<TaskKey, DependencyBlockReason>,
}
impl WorkspaceScheduler {
    pub fn open(directory: &File, policy: &WorkspaceTaskPolicy) -> Result<Self> {
        policy
            .validate()
            .map_err(|_| SchedulerError::PolicyChanged)?;
        let journal = SchedulerJournal::open(directory, rustix::process::geteuid().as_raw())
            .map_err(|e| SchedulerError::Journal(e.to_string()))?;
        let store = directory
            .metadata()
            .map_err(|e| SchedulerError::Journal(e.to_string()))?;
        let records = journal.records().to_vec();
        let mut s = Self {
            journal,
            store_identity: (store.dev(), store.ino()),
            policy: policy.into(),
            next_revision: 1,
            queued: BTreeMap::new(),
            next_ordinal: 0,
            graph: None,
            dag_revision: 0,
            last_source: None,
            assignments: BTreeMap::new(),
            max_time: 0,
            catalog: BTreeMap::new(),
            unavailable_sources: BTreeMap::new(),
            blocked_dependencies: BTreeMap::new(),
        };
        let mut replay_bytes = 0usize;
        for (index, b) in records.into_iter().enumerate() {
            replay_bytes += b.len() + 1;
            let r: Record =
                serde_json::from_slice(&b).map_err(|_| SchedulerError::CorruptJournal)?;
            s.apply(&r)?;
            let reserve: usize = s
                .assignments
                .values()
                .map(|a| match a.status {
                    AdmissionStatus::Claimed => 2,
                    AdmissionStatus::Unknown => 1,
                    _ => 0,
                })
                .sum();
            if index + 1 + reserve > MAX_SCHEDULER_RECORDS
                || replay_bytes.saturating_add(reserve.saturating_mul(MAX_SCHEDULER_RECORD_BYTES))
                    > MAX_SCHEDULER_FILE_BYTES as usize
            {
                return Err(SchedulerError::CorruptJournal);
            }
        }
        if s.next_revision == 1 {
            s.append(Data::Header {
                policy: s.policy.clone(),
            })?;
        }
        Ok(s)
    }
    fn apply(&mut self, r: &Record) -> Result<()> {
        if r.revision != self.next_revision || r.revision > MAX_REV_COUNTER {
            return Err(SchedulerError::CorruptJournal);
        }
        match &r.data {
            Data::Header { policy } => {
                if r.revision != 1 || policy != &self.policy {
                    return Err(SchedulerError::PolicyChanged);
                }
            }
            Data::Enqueue { keys } => {
                if r.revision == 1 || keys.is_empty() || keys.len() > 32 {
                    return Err(SchedulerError::CorruptJournal);
                }
                for raw in keys {
                    let k = TaskKey::decode(raw).map_err(|_| SchedulerError::CorruptJournal)?;
                    if k.workspace_id != self.policy.workspace || self.queued.contains_key(&k) {
                        return Err(SchedulerError::CorruptJournal);
                    }
                    self.next_ordinal = self
                        .next_ordinal
                        .checked_add(1)
                        .filter(|n| *n <= MAX_REV_COUNTER)
                        .ok_or(SchedulerError::CorruptJournal)?;
                    self.queued.insert(k, self.next_ordinal);
                }
            }
            Data::Graph { digest } => {
                if r.revision == 1 || self.graph == Some(*digest) {
                    return Err(SchedulerError::CorruptJournal);
                }
                self.graph = Some(*digest);
                self.dag_revision = self
                    .dag_revision
                    .checked_add(1)
                    .filter(|n| *n <= MAX_REV_COUNTER)
                    .ok_or(SchedulerError::CorruptJournal)?;
            }
            Data::Assignment {
                assignment: a,
                observed_at,
            } => {
                if r.revision == 1
                    || a.epoch != self.policy.epoch
                    || a.reference.workspace_id != self.policy.workspace
                    || a.reference.repo_id != self.policy.repo
                    || *observed_at < self.max_time
                {
                    return Err(SchedulerError::CorruptJournal);
                }
                a.reference
                    .validate()
                    .map_err(|_| SchedulerError::CorruptJournal)?;
                a.request.encode()?;
                for id in [&a.id, &a.operation, &a.actor, &a.principal] {
                    validate_id(id, "scheduler journal identity")
                        .map_err(|_| SchedulerError::CorruptJournal)?;
                }
                if a.actor != self.policy.owner
                    || !self.queued.contains_key(&a.reference.task_key())
                    || (a.status == AdmissionStatus::Claimed) != a.outcome.is_none()
                {
                    return Err(SchedulerError::CorruptJournal);
                }
                if let Some(outcome) = &a.outcome {
                    validate_id(outcome, "scheduler outcome")
                        .map_err(|_| SchedulerError::CorruptJournal)?;
                }
                if let Some(old) = self.assignments.get(&a.id) {
                    if old.immutable() != a.immutable()
                        || !matches!(
                            (old.status, a.status),
                            (
                                AdmissionStatus::Claimed,
                                AdmissionStatus::Unknown
                                    | AdmissionStatus::Completed
                                    | AdmissionStatus::RejectedBeforeInvocation
                            ) | (AdmissionStatus::Unknown, AdmissionStatus::Completed)
                        )
                    {
                        return Err(SchedulerError::CorruptJournal);
                    }
                } else {
                    if a.status != AdmissionStatus::Claimed
                        || a.outcome.is_some()
                        || a.deadline < *observed_at
                        || a.request.dag_revision != self.dag_revision
                        || self.assignments.values().any(|old| {
                            old.status != AdmissionStatus::RejectedBeforeInvocation
                                && old.reference.task_key() == a.reference.task_key()
                        })
                    {
                        return Err(SchedulerError::CorruptJournal);
                    }
                    self.last_source = Some(a.reference.task_source_id.clone());
                }
                self.max_time = *observed_at;
                self.assignments.insert(a.id.clone(), a.as_ref().clone());
            }
        }
        self.next_revision += 1;
        Ok(())
    }
    fn append(&mut self, data: Data) -> Result<()> {
        let mut active = self.assignments.clone();
        if let Data::Assignment { assignment, .. } = &data {
            active.insert(assignment.id.clone(), assignment.as_ref().clone());
        }
        let reserve = active
            .values()
            .map(|a| match a.status {
                AdmissionStatus::Claimed => 2,
                AdmissionStatus::Unknown => 1,
                _ => 0,
            })
            .sum::<usize>();
        let r = Record {
            revision: self.next_revision,
            data,
        };
        let bytes = serde_json::to_vec(&r).map_err(|_| SchedulerError::Invalid)?;
        // Validate the whole semantic transition before its first persisted
        // byte. Restore the prestate on any error; the journal itself poisons
        // uncertain persistence and is never cloned or silently recovered.
        let before = (
            self.next_revision,
            self.queued.clone(),
            self.next_ordinal,
            self.graph,
            self.dag_revision,
            self.last_source.clone(),
            self.assignments.clone(),
            self.max_time,
        );
        let result = self.apply(&r).and_then(|()| {
            self.journal
                .append(
                    &bytes,
                    reserve,
                    reserve
                        .checked_mul(MAX_SCHEDULER_RECORD_BYTES)
                        .ok_or(SchedulerError::Invalid)?,
                )
                .map_err(|e| SchedulerError::Journal(e.to_string()))
        });
        if result.is_err() {
            (
                self.next_revision,
                self.queued,
                self.next_ordinal,
                self.graph,
                self.dag_revision,
                self.last_source,
                self.assignments,
                self.max_time,
            ) = before;
        }
        result
    }
    pub fn synchronize_sources(&mut self, registry: &WorkspaceSourceRegistry) -> Result<()> {
        self.blocked_dependencies.clear();
        if Policy::from(registry.policy()) != self.policy {
            return Err(SchedulerError::PolicyChanged);
        }
        self.journal
            .verify()
            .map_err(|e| SchedulerError::Journal(e.to_string()))?;
        let mut catalog = BTreeMap::new();
        let mut unavailable_sources: BTreeMap<_, _> = registry
            .sources()
            .map(|s| (s.task_source_id.clone(), s.state))
            .collect();
        for source in registry
            .sources()
            .filter(|r| r.state == TaskSourceState::Enrolled)
        {
            let Ok((source, file)) = registry.read_for_scheduler(&source.task_source_id) else {
                continue;
            };
            let Ok(doc) = CanonicalTaskDocumentV1::from_bytes(&file.bytes) else {
                continue;
            };
            if doc.workspace_id != source.workspace_id
                || doc.repo_id != source.repo_id
                || doc.task_source_id != source.task_source_id
                || doc.source_generation != source.source_generation
            {
                continue;
            }
            unavailable_sources.remove(&source.task_source_id);
            for entry in &doc.tasks {
                let reference = doc.task_ref(entry, &source.canonical_relative_path);
                catalog.insert(
                    reference.task_key(),
                    CatalogTask {
                        reference,
                        entry: entry.clone(),
                        source: source.clone(),
                    },
                );
            }
        }
        let fresh: Vec<_> = catalog
            .keys()
            .filter(|k| !self.queued.contains_key(*k))
            .cloned()
            .collect();
        for batch in fresh.chunks(32) {
            self.append(Data::Enqueue {
                keys: batch.iter().map(TaskKey::encode).collect(),
            })?;
        }
        let mut graph = Vec::new();
        for t in catalog.values() {
            graph.extend(t.reference.encode().map_err(|_| SchedulerError::Invalid)?);
            graph.extend(t.entry.task_control_digest.encode_typed());
            graph.extend(crate::task_ref::encode_bytes_field(
                t.entry.status.as_str().as_bytes(),
            ));
            graph.extend(t.entry.completion_policy_digest.encode_typed());
            for d in &t.entry.dependencies {
                graph.extend(d.encode());
            }
        }
        let digest = Sha256Digest::of(&graph).0;
        if self.graph != Some(digest) {
            self.append(Data::Graph { digest })?;
        }
        self.catalog = catalog;
        self.unavailable_sources = unavailable_sources;
        Ok(())
    }
    fn now(&self, a: &CurrentAuthority<'_>) -> Result<u64> {
        self.trusted_store(a)?;
        if Policy::from(a.registry.policy()) != self.policy {
            return Err(SchedulerError::StaleEpoch);
        }
        match a.clock {
            HostClockState::Verified { now_unix } if now_unix >= self.max_time => Ok(now_unix),
            _ => Err(SchedulerError::Clock),
        }
    }
    fn trusted_store(&self, a: &CurrentAuthority<'_>) -> Result<()> {
        let profile = a
            .profile
            .as_ref()
            .ok_or(SchedulerError::UnsupportedAdapters)?;
        if profile.store_identity != self.store_identity {
            return Err(SchedulerError::Grant);
        }
        Ok(())
    }
    fn dependencies(&self, t: &CatalogTask, p: &ControlledProfile) -> Result<()> {
        let mut pending = vec![t.reference.task_key()];
        let mut seen = BTreeSet::new();
        let mut nodes = Vec::new();
        while let Some(k) = pending.pop() {
            if !seen.insert(k.clone()) {
                continue;
            }
            let n = self
                .catalog
                .get(&k)
                .ok_or_else(|| self.missing_dependency(&k))?;
            nodes.push(DependencyNode {
                task_ref: n.reference.clone(),
                completion_policy_digest: n.entry.completion_policy_digest,
                dependencies: n.entry.dependencies.clone(),
            });
            for d in &n.entry.dependencies {
                if !self.catalog.contains_key(&d.target_key) {
                    return Err(self.missing_dependency(&d.target_key));
                }
                pending.push(d.target_key.clone());
            }
        }
        validate_dependency_graph(&nodes).map_err(|error| {
            SchedulerError::DependencyBlocked(
                if error == TaskContractError::DependencyCycleDetected {
                    DependencyBlockReason::Cycle
                } else {
                    DependencyBlockReason::InvalidGraph(error)
                },
            )
        })?;
        for n in &nodes {
            for d in &n.dependencies {
                let resolved = self
                    .catalog
                    .get(&d.target_key)
                    .ok_or_else(|| self.missing_dependency(&d.target_key))?;
                let status =
                    TaskStatus::parse(resolved.entry.status.as_str()).map_err(|error| {
                        SchedulerError::DependencyBlocked(DependencyBlockReason::InvalidGraph(
                            error,
                        ))
                    })?;
                let accepted = p.accepted_dependencies.get(&d.target_key).ok_or_else(|| {
                    SchedulerError::DependencyBlocked(DependencyBlockReason::UnacceptedCompletion {
                        target: d.target_key.clone(),
                    })
                })?;
                if accepted.reference != resolved.reference
                    || accepted.controls != resolved.entry.task_control_digest
                    || accepted.policy != resolved.entry.completion_policy_digest
                    || accepted.verified_acceptance == Sha256Digest([0; 32])
                {
                    return Err(SchedulerError::DependencyBlocked(
                        DependencyBlockReason::UnacceptedCompletion {
                            target: d.target_key.clone(),
                        },
                    ));
                }
                validate_dependency_satisfaction(
                    d,
                    &ResolvedDependency {
                        task_ref: resolved.reference.clone(),
                        completion_policy_digest: resolved.entry.completion_policy_digest,
                        status,
                    },
                    &DependencySourceBinding::from_task_ref(&resolved.reference).map_err(
                        |error| {
                            SchedulerError::DependencyBlocked(DependencyBlockReason::InvalidGraph(
                                error,
                            ))
                        },
                    )?,
                )
                .map_err(|_| {
                    SchedulerError::DependencyBlocked(
                        DependencyBlockReason::UnsatisfiedCommitment {
                            target: d.target_key.clone(),
                        },
                    )
                })?;
            }
        }
        Ok(())
    }
    fn missing_dependency(&self, target: &TaskKey) -> SchedulerError {
        SchedulerError::DependencyBlocked(
            match self.unavailable_sources.get(&target.task_source_id) {
                Some(state) => DependencyBlockReason::SourceUnavailable {
                    target: target.clone(),
                    state: *state,
                },
                None => DependencyBlockReason::UnresolvedTarget {
                    target: target.clone(),
                },
            },
        )
    }
    /// Latest selection's explicit dependency holds, keyed by the complete
    /// affected TaskKey. Refresh with select_next[_for_trigger] or admit; these
    /// diagnostics confer no grant and are cleared by source synchronization.
    pub fn dependency_blocked_reasons(&self) -> &BTreeMap<TaskKey, DependencyBlockReason> {
        &self.blocked_dependencies
    }
    fn available(&self, r: &AssignmentRequest, p: &ControlledProfile) -> Result<()> {
        self.available_except(r, p, None)
    }
    fn available_except(
        &self,
        r: &AssignmentRequest,
        p: &ControlledProfile,
        own: Option<&str>,
    ) -> Result<()> {
        let cap = p
            .capacities
            .get(&r.resource)
            .ok_or(SchedulerError::Capacity)?;
        let active: Vec<_> = self
            .assignments
            .values()
            .filter(|a| a.status.active() && Some(a.id.as_str()) != own)
            .collect();
        if active
            .iter()
            .filter(|a| a.request.resource == r.resource)
            .count()
            >= usize::from(*cap)
        {
            return Err(SchedulerError::Capacity);
        }
        // Confirmed retirement releases capacity, not already committed budget.
        // Until a supported usage adapter exists, charge the full reservation.
        let charged: Vec<_> = self
            .assignments
            .values()
            .filter(|a| {
                a.status != AdmissionStatus::RejectedBeforeInvocation && Some(a.id.as_str()) != own
            })
            .collect();
        let tokens = charged
            .iter()
            .try_fold(r.tokens, |n, a| n.checked_add(a.request.tokens))
            .ok_or(SchedulerError::Budget)?;
        let money = charged
            .iter()
            .try_fold(r.micro_usd, |n, a| n.checked_add(a.request.micro_usd))
            .ok_or(SchedulerError::Budget)?;
        if tokens > p.token_limit || money > p.micro_usd_limit {
            return Err(SchedulerError::Budget);
        }
        Ok(())
    }
    fn grant<'a>(&self, t: &CatalogTask, p: &'a ControlledProfile, now: u64) -> Result<&'a Grant> {
        if t.entry.status != CanonicalTaskStatus::Todo {
            return Err(SchedulerError::StaleTask);
        }
        self.dependencies(t, p)?;
        let g = p
            .grants
            .get(&t.reference.task_key())
            .ok_or(SchedulerError::Grant)?;
        t.source
            .controls
            .check_dispatch_admission(&g.action)
            .map_err(|_| SchedulerError::Grant)?;
        if g.spec != t.reference.task_spec_digest
            || g.controls != t.entry.task_control_digest
            || now >= g.expires
        {
            return Err(SchedulerError::Grant);
        }
        Ok(g)
    }
    pub fn select_next(&mut self, a: &CurrentAuthority<'_>) -> Result<SelectedTask> {
        self.select_next_for_trigger(AdmissionTrigger::Manual, a)
    }
    pub fn select_next_for_trigger(
        &mut self,
        trigger: AdmissionTrigger,
        a: &CurrentAuthority<'_>,
    ) -> Result<SelectedTask> {
        self.blocked_dependencies.clear();
        self.trusted_store(a)?;
        self.synchronize_sources(a.registry)?;
        let now = self.now(a)?;
        let p = a
            .profile
            .as_ref()
            .ok_or(SchedulerError::UnsupportedAdapters)?;
        let mut per_source: BTreeMap<String, Vec<(&TaskKey, &CatalogTask)>> = BTreeMap::new();
        for (k, t) in &self.catalog {
            if self.assignments.values().any(|r| {
                r.status != AdmissionStatus::RejectedBeforeInvocation
                    && r.reference.task_key() == *k
            }) {
                continue;
            }
            let g = match self.grant(t, p, now) {
                Ok(grant) => grant,
                Err(SchedulerError::DependencyBlocked(reason)) => {
                    self.blocked_dependencies.insert(k.clone(), reason);
                    continue;
                }
                Err(_) => continue,
            };
            if matches!(trigger, AdmissionTrigger::Timer | AdmissionTrigger::Event)
                && t.source
                    .controls
                    .check_automatic_dispatch_admission(&g.action)
                    .is_err()
            {
                continue;
            }
            let r = AssignmentRequest {
                action: g.action.clone(),
                executor_actor: g.executor.clone(),
                resource: g.resource.clone(),
                grant_id: g.id.clone(),
                execution_binding_id: p.execution_binding.clone(),
                write_scope_claim_id: p.write_claim.clone(),
                tokens: g.max_tokens,
                micro_usd: g.max_micro_usd,
                dag_revision: self.dag_revision,
            };
            if self.available(&r, p).is_ok() {
                per_source
                    .entry(k.task_source_id.clone())
                    .or_default()
                    .push((k, t));
            }
        }
        let source = per_source
            .keys()
            .find(|s| self.last_source.as_ref().is_none_or(|last| *s > last))
            .or_else(|| per_source.keys().next())
            .ok_or(SchedulerError::NoEligibleTask)?;
        let (_, t) = per_source[source]
            .iter()
            .min_by_key(|(k, _)| self.queued.get(*k).copied().unwrap_or(u64::MAX))
            .ok_or(SchedulerError::NoEligibleTask)?;
        Ok(SelectedTask {
            task_ref: t.reference.clone(),
            dag_revision: self.dag_revision,
        })
    }
    fn eligible(
        &self,
        m: &VerifiedTaskMessage,
        trigger: AdmissionTrigger,
        a: &CurrentAuthority<'_>,
    ) -> Result<EligibleTask> {
        let now = self.now(a)?;
        let p = a
            .profile
            .as_ref()
            .ok_or(SchedulerError::UnsupportedAdapters)?;
        let auth = m.authenticated();
        let tr = auth.transcript();
        if tr.message_kind != TaskMessageKind::Assignment
            || tr.sender_full_actor_address != self.policy.owner
            || tr.config_digest.0 != self.policy.config
            || tr.issued_at_unix > now
            || tr.expires_at_unix <= now
        {
            return Err(SchedulerError::Grant);
        }
        let body = TaskActionableBodyV1::parse(
            &tr.body_utf8,
            TaskMessageKind::Assignment,
            &[assignment_profile()],
        )
        .map_err(|_| SchedulerError::Invalid)?;
        let r: AssignmentRequest =
            serde_json::from_slice(&body.canonical_payload).map_err(|_| SchedulerError::Invalid)?;
        if r.dag_revision != self.dag_revision {
            return Err(SchedulerError::StaleGraph);
        }
        let t = self
            .catalog
            .get(&tr.task_ref.task_key())
            .ok_or(SchedulerError::StaleTask)?;
        if t.reference != tr.task_ref || t.entry.task_control_digest != tr.task_control_digest {
            return Err(SchedulerError::StaleTask);
        }
        if matches!(trigger, AdmissionTrigger::Timer | AdmissionTrigger::Event) {
            t.source
                .controls
                .check_automatic_dispatch_admission(&r.action)
                .map_err(|_| SchedulerError::Grant)?;
        }
        let g = self.grant(t, p, now)?;
        if g.principal != auth.signer_principal()
            || g.id != r.grant_id
            || g.action != r.action
            || g.executor != r.executor_actor
            || g.resource != r.resource
            || r.tokens > g.max_tokens
            || r.micro_usd > g.max_micro_usd
            || r.execution_binding_id != p.execution_binding
            || r.write_scope_claim_id != p.write_claim
            || !tr
                .recipient_full_actor_addresses
                .contains(&r.executor_actor)
        {
            return Err(SchedulerError::Grant);
        }
        Ok(EligibleTask {
            request: r,
            grant: g.clone(),
            reference: t.reference.clone(),
            principal: auth.signer_principal().into(),
            digest: auth.transcript_digest(),
            assignment: tr.assignment_id.clone().ok_or(SchedulerError::Invalid)?,
            operation: tr.operation_id.clone().ok_or(SchedulerError::Invalid)?,
            deadline: tr.expires_at_unix,
            now,
        })
    }
    pub fn admit(
        &mut self,
        m: &VerifiedTaskMessage,
        trigger: AdmissionTrigger,
        a: &CurrentAuthority<'_>,
    ) -> Result<AdmissionDisposition> {
        self.trusted_store(a)?;
        self.journal
            .verify()
            .map_err(|e| SchedulerError::Journal(e.to_string()))?;
        let tr = m.authenticated().transcript();
        let id = tr.assignment_id.as_ref().ok_or(SchedulerError::Invalid)?;
        if let Some(old) = self.assignments.get(id) {
            return if old.digest.0 == m.authenticated().transcript_digest().0 {
                Ok(AdmissionDisposition::Existing(old.status))
            } else {
                Err(SchedulerError::ReplayConflict)
            };
        }
        let selected = match self.select_next_for_trigger(trigger, a) {
            Ok(selected) => Some(selected),
            Err(SchedulerError::NoEligibleTask) => None,
            Err(error) => return Err(error),
        };
        // Preserve the submitted task's specific refusal even when its trigger
        // has no eligible fair turn. Only the ordinary no-turn case is deferred;
        // journal, clock and authority errors above are never masked.
        let e = self.eligible(m, trigger, a)?;
        let selected = selected.ok_or(SchedulerError::NoEligibleTask)?;
        if self
            .assignments
            .values()
            .any(|r| r.status.active() && r.reference.task_key() == e.reference.task_key())
        {
            return Err(SchedulerError::AlreadyActive);
        }
        if selected.task_ref.task_key() != e.reference.task_key() {
            return Err(SchedulerError::NotFairTurn);
        }
        self.available(
            &e.request,
            a.profile
                .as_ref()
                .ok_or(SchedulerError::UnsupportedAdapters)?,
        )?;
        let row = Assignment {
            id: e.assignment.clone(),
            operation: e.operation,
            actor: self.policy.owner.clone(),
            principal: e.principal,
            reference: e.reference,
            controls: Sha256Bytes(e.grant.controls.0),
            request: e.request,
            digest: Sha256Bytes(e.digest.0),
            deadline: e.deadline,
            epoch: self.policy.epoch,
            trigger,
            status: AdmissionStatus::Claimed,
            outcome: None,
        };
        self.append(Data::Assignment {
            assignment: Box::new(row),
            observed_at: e.now,
        })?;
        Ok(AdmissionDisposition::Claimed(ClaimedAssignment {
            id: e.assignment,
            digest: e.digest,
            message: Box::new(m.clone()),
        }))
    }
    fn finish(
        &mut self,
        id: &str,
        outcome: InvocationOutcome,
        now: u64,
    ) -> Result<AdmissionStatus> {
        let mut row = self
            .assignments
            .get(id)
            .cloned()
            .ok_or(SchedulerError::Invalid)?;
        match outcome {
            InvocationOutcome::ConfirmedRetired {
                original_operation_id,
                receipt_id,
            } if original_operation_id == row.operation => {
                validate_id(&receipt_id, "native receipt").map_err(|_| SchedulerError::Invalid)?;
                row.status = AdmissionStatus::Completed;
                row.outcome = Some(receipt_id);
            }
            InvocationOutcome::Unknown { reason } => {
                validate_id(&reason, "unknown reason").map_err(|_| SchedulerError::Invalid)?;
                if row.status == AdmissionStatus::Unknown {
                    return Ok(row.status);
                }
                row.status = AdmissionStatus::Unknown;
                row.outcome = Some(reason);
            }
            _ => return Err(SchedulerError::ReplayConflict),
        }
        let status = row.status;
        self.append(Data::Assignment {
            assignment: Box::new(row),
            observed_at: now,
        })?;
        Ok(status)
    }
    #[cfg(test)]
    fn invoke(
        &mut self,
        claim: ClaimedAssignment,
        a: &CurrentAuthority<'_>,
        executor: &mut impl ControlledExecutor,
    ) -> Result<AdmissionStatus> {
        self.invoke_checked(claim, a, |admission| Ok(executor.invoke(admission)))
    }
    pub fn qualify_for_lease(
        &mut self,
        claim: &ClaimedAssignment,
        a: &CurrentAuthority<'_>,
    ) -> Result<QualifiedLeaseAssignment> {
        self.trusted_store(a)?;
        self.journal
            .verify()
            .map_err(|e| SchedulerError::Journal(e.to_string()))?;
        let row = self
            .assignments
            .get(&claim.id)
            .cloned()
            .ok_or(SchedulerError::Invalid)?;
        self.synchronize_sources(a.registry)?;
        if row.status != AdmissionStatus::Claimed || row.digest.0 != claim.digest.0 {
            return Err(SchedulerError::ReplayConflict);
        }
        self.eligible(&claim.message, row.trigger, a)?;
        Ok(QualifiedLeaseAssignment {
            binding: QualifiedLeaseBinding {
                scheduler_store: self.store_identity,
                workspace: self.policy.workspace.clone(),
                repo: self.policy.repo.clone(),
                authority_epoch: self.policy.epoch,
                owner: row.request.executor_actor.clone(),
                assignment: row.id.clone(),
                operation: row.operation.clone(),
                write_scope_claim: row.request.write_scope_claim_id.clone(),
                original_deadline: row.deadline,
                assignment_digest: row.digest.0,
                task_ref: row.reference.clone(),
            },
        })
    }
    pub fn invoke_with_lease(
        &mut self,
        claim: ClaimedAssignment,
        a: &CurrentAuthority<'_>,
        leases: &mut crate::task_resource_lease::ResourceLeaseStore,
        capability: crate::task_resource_lease::CommittedWriteLease,
        lease_authority: &crate::task_resource_lease::CurrentLeaseAuthority<'_>,
        executor: &mut impl crate::task_resource_lease::LeasedExecutor,
    ) -> Result<AdmissionStatus> {
        let qualified = self.qualify_for_lease(&claim, a)?;
        self.invoke_checked(claim, a, |admission| {
            leases
                .invoke(capability, &qualified, lease_authority, |writer| {
                    executor.invoke(admission, writer)
                })
                .map_err(|error| SchedulerError::ResourceLeaseHeld(error.to_string()))
        })
    }
    fn invoke_checked(
        &mut self,
        claim: ClaimedAssignment,
        a: &CurrentAuthority<'_>,
        invoke: impl FnOnce(&ExecutionAdmissionV1) -> Result<InvocationOutcome>,
    ) -> Result<AdmissionStatus> {
        self.trusted_store(a)?;
        self.journal
            .verify()
            .map_err(|e| SchedulerError::Journal(e.to_string()))?;
        let row = self
            .assignments
            .get(&claim.id)
            .cloned()
            .ok_or(SchedulerError::Invalid)?;
        if row.status != AdmissionStatus::Claimed || row.digest.0 != claim.digest.0 {
            return Err(SchedulerError::ReplayConflict);
        }
        self.synchronize_sources(a.registry)?;
        let current = self
            .eligible(&claim.message, row.trigger, a)
            .and_then(|eligible| {
                self.available_except(
                    &eligible.request,
                    a.profile
                        .as_ref()
                        .ok_or(SchedulerError::UnsupportedAdapters)?,
                    Some(&row.id),
                )
            });
        if current.is_err() {
            let mut rejected = row;
            rejected.status = AdmissionStatus::RejectedBeforeInvocation;
            rejected.outcome = Some("current authority changed before invocation".into());
            self.append(Data::Assignment {
                assignment: Box::new(rejected),
                observed_at: self.now(a)?,
            })?;
            return Err(SchedulerError::Grant);
        }
        let outcome = match invoke(&row.execution()) {
            Ok(outcome) => outcome,
            Err(error) => {
                let mut rejected = row;
                rejected.status = AdmissionStatus::RejectedBeforeInvocation;
                rejected.outcome = Some("resource lease refused before callback".into());
                self.append(Data::Assignment {
                    assignment: Box::new(rejected),
                    observed_at: self.now(a)?,
                })?;
                return Err(error);
            }
        };
        self.finish(&claim.id, outcome, self.now(a)?)
    }
    pub fn resolve_original(
        &mut self,
        id: &str,
        a: &CurrentAuthority<'_>,
        lookup: &mut impl OriginalOutcomeLookup,
    ) -> Result<AdmissionStatus> {
        self.trusted_store(a)?;
        a.profile
            .as_ref()
            .ok_or(SchedulerError::UnsupportedAdapters)?;
        let now = self.now(a)?;
        self.journal
            .verify()
            .map_err(|e| SchedulerError::Journal(e.to_string()))?;
        let row = self
            .assignments
            .get(id)
            .cloned()
            .ok_or(SchedulerError::Invalid)?;
        if !row.status.active() {
            return Ok(row.status);
        }
        self.finish(id, lookup.lookup(&row.execution()), now)
    }
    pub fn status(&self, id: &str) -> Option<AdmissionStatus> {
        self.assignments.get(id).map(|r| r.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_dependency::DependencyCommitment;
    use crate::task_ref::GitOid;
    use crate::task_source::{SourceDispatchControls, SourceExecutionMode};
    use crate::task_source_path::WorkspaceRootPin;
    use crate::task_wire::{
        PublishTaskV1, SignerEnrollment, TASK_BUS_V2_ALPN, TaskTranscriptV3,
        TaskVerificationContext,
    };
    use iroh::SecretKey;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tempfile::TempDir;

    fn entry(id: &str) -> TaskEntrySnapshotV1 {
        TaskEntrySnapshotV1 {
            task_id: id.into(),
            status: CanonicalTaskStatus::Todo,
            task_status_rev: 0,
            task_spec_digest: Sha256Digest::of(id.as_bytes()),
            task_control_digest: Sha256Digest([2; 32]),
            completion_policy_digest: Sha256Digest([3; 32]),
            owner_actor: None,
            reviewer_role: "ARCHITECT".into(),
            baseline_commit: GitOid::from_hex("15ea881e96d43a8ffe87f7e24dd5e9f22311ff31").unwrap(),
            candidate_commit: None,
            overlay_digest: None,
            execution_flags: vec![],
            dependencies: vec![],
        }
    }
    struct Fixture {
        _root: TempDir,
        store: TempDir,
        registry: WorkspaceSourceRegistry,
        profile: ControlledProfile,
    }
    impl Fixture {
        fn new(sources: Vec<Vec<TaskEntrySnapshotV1>>) -> Self {
            Self::with_auto(sources, true)
        }
        fn with_auto(sources: Vec<Vec<TaskEntrySnapshotV1>>, automatic: bool) -> Self {
            let automatic = vec![automatic; sources.len()];
            Self::with_automatic_sources(sources, automatic)
        }
        fn with_automatic_sources(
            sources: Vec<Vec<TaskEntrySnapshotV1>>,
            automatic: Vec<bool>,
        ) -> Self {
            let root = TempDir::new().unwrap();
            let store = TempDir::new().unwrap();
            fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let meta = fs::metadata(root.path()).unwrap();
            let policy = WorkspaceTaskPolicy {
                workspace_id: "scheduler-fixture".into(),
                repo_id: "repository-fixture".into(),
                config_revision: 1,
                authority_epoch: 1,
                scheduler_owner: "DELIVERY#manager".into(),
                max_sources: 16,
                config_digest: [7; 32],
            };
            let mut registry = WorkspaceSourceRegistry::new(
                policy.clone(),
                WorkspaceRootPin {
                    path: root.path().into(),
                    dev: meta.dev(),
                    ino: meta.ino(),
                    uid: meta.uid(),
                    generation: 1,
                },
            )
            .unwrap();
            let mut profile = ControlledProfile {
                store_identity: {
                    let m = fs::metadata(store.path()).unwrap();
                    (m.dev(), m.ino())
                },
                grants: BTreeMap::new(),
                capacities: BTreeMap::from([("cpu".into(), 1), ("other".into(), 1)]),
                execution_binding: "fixture-worktree".into(),
                write_claim: "fixture-write-scope".into(),
                token_limit: 1000,
                micro_usd_limit: 1000,
                accepted_dependencies: BTreeMap::new(),
            };
            for (index, mut tasks) in sources.into_iter().enumerate() {
                tasks.sort_by(|a, b| a.task_id.cmp(&b.task_id));
                let id = format!("{:032x}", index + 1);
                let path = format!("source-{}.md", index + 1);
                let doc:CanonicalTaskDocumentV1=serde_json::from_value(serde_json::json!({"workspace_id":policy.workspace_id,"repo_id":policy.repo_id,"task_source_id":id,"source_generation":1,"file_cas_rev":0,"last_operation_id":null,"tasks":tasks})).unwrap();
                fs::write(root.path().join(&path), doc.to_canonical_bytes().unwrap()).unwrap();
                fs::set_permissions(root.path().join(&path), fs::Permissions::from_mode(0o400))
                    .unwrap();
                for task in &doc.tasks {
                    let r = doc.task_ref(task, &path);
                    profile.grants.insert(
                        r.task_key(),
                        Grant {
                            id: format!("grant-{}", task.task_id),
                            principal: "manager-principal".into(),
                            action: "implement".into(),
                            executor: "RUST#executor".into(),
                            resource: "cpu".into(),
                            spec: r.task_spec_digest,
                            controls: task.task_control_digest,
                            expires: 500,
                            max_tokens: 10,
                            max_micro_usd: 10,
                        },
                    );
                }
                registry
                    .enroll(TaskSourceRecord {
                        workspace_id: policy.workspace_id.clone(),
                        repo_id: policy.repo_id.clone(),
                        source_worktree_id: "fixture-worktree".into(),
                        task_source_id: id,
                        display_name: format!("source {}", index + 1),
                        canonical_relative_path: path,
                        source_generation: 1,
                        normalization_version: 1,
                        schema_version: 1,
                        writer_principal: "writer-principal".into(),
                        writer_epoch: 1,
                        config_digest: policy.config_digest,
                        state: TaskSourceState::Proposed,
                        controls: SourceDispatchControls {
                            mode: SourceExecutionMode::Implementation,
                            implementation_authorized: true,
                            deployment_authorized: false,
                            automatic_dispatch: automatic[index],
                            allowed_actions: vec!["implement".into()],
                        },
                    })
                    .unwrap();
            }
            Self {
                _root: root,
                store,
                registry,
                profile,
            }
        }
        fn authority(&self, now: u64) -> CurrentAuthority<'_> {
            CurrentAuthority {
                registry: &self.registry,
                clock: HostClockState::Verified { now_unix: now },
                profile: Some(self.profile.clone()),
            }
        }
        fn open(&self) -> WorkspaceScheduler {
            WorkspaceScheduler::open(
                &File::open(self.store.path()).unwrap(),
                self.registry.policy(),
            )
            .unwrap()
        }
    }
    fn message(
        s: &WorkspaceScheduler,
        f: &Fixture,
        key: &TaskKey,
        id: &str,
        change: impl FnOnce(&mut AssignmentRequest),
    ) -> VerifiedTaskMessage {
        let t = &s.catalog[key];
        let g = &f.profile.grants[key];
        let mut r = AssignmentRequest {
            action: g.action.clone(),
            executor_actor: g.executor.clone(),
            resource: g.resource.clone(),
            grant_id: g.id.clone(),
            execution_binding_id: f.profile.execution_binding.clone(),
            write_scope_claim_id: f.profile.write_claim.clone(),
            tokens: 10,
            micro_usd: 10,
            dag_revision: s.dag_revision,
        };
        change(&mut r);
        let payload = r.encode().unwrap();
        let secret = SecretKey::from_bytes(&[7; 32]);
        let payload_hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
        let tr=TaskTranscriptV3 {message_id:format!("message-{id}"),issued_at_unix:100,expires_at_unix:200,nonce:[9;32],sender_full_actor_address:f.registry.policy().scheduler_owner.clone(),parent_full_actor_address:Some("WORKHORSE#root".into()),recipient_full_actor_addresses:vec!["RUST#executor".into()],room:"#eng".into(),message_kind:TaskMessageKind::Assignment,receiver_authority_id:"fixture-authority".into(),task_ref:t.reference.clone(),assignment_id:Some(id.into()),operation_id:Some(format!("operation-{id}")),request_id:None,in_reply_to_message_id:None,config_digest:Sha256Digest(f.registry.policy().config_digest),task_control_digest:t.entry.task_control_digest,body_utf8:serde_json::json!({"payload_profile":ASSIGNMENT_PROFILE,"canonical_payload_hex":payload_hex,"payload_digest_sha256":Sha256Digest::of(&payload).to_string()}).to_string()};
        let profiles = [assignment_profile()];
        let frame = PublishTaskV1::sign(tr, &secret, &profiles).unwrap();
        let roster = [SignerEnrollment {
            workspace_id: t.reference.workspace_id.clone(),
            repo_id: t.reference.repo_id.clone(),
            seat: "DELIVERY".into(),
            authenticated_signer_principal: "manager-principal".into(),
            signer_pubkey: secret.public(),
            key_epoch: 1,
            config_digest: Sha256Digest(f.registry.policy().config_digest),
            allowed_actions: vec![TaskMessageKind::Assignment],
            active: true,
        }];
        frame
            .verify(
                TASK_BUS_V2_ALPN,
                &roster,
                &TaskVerificationContext {
                    receiver_authority_id: "fixture-authority",
                    recipient_full_actor_address: "RUST#executor",
                    current_task_ref: &t.reference,
                    config_digest: Sha256Digest(f.registry.policy().config_digest),
                    task_control_digest: t.entry.task_control_digest,
                    required_key_epoch: 1,
                    current_granted_actions: &[TaskMessageKind::Assignment],
                    ratified_profiles: &profiles,
                    host_clock: HostClockState::Verified { now_unix: 150 },
                },
            )
            .unwrap()
    }
    fn claim(
        s: &mut WorkspaceScheduler,
        m: &VerifiedTaskMessage,
        f: &Fixture,
        trigger: AdmissionTrigger,
    ) -> ClaimedAssignment {
        match s.admit(m, trigger, &f.authority(150)).unwrap() {
            AdmissionDisposition::Claimed(c) => c,
            _ => panic!("expected fresh durable claim"),
        }
    }
    #[derive(Default)]
    struct Executor {
        calls: usize,
        unknown: bool,
    }
    impl ControlledExecutor for Executor {
        fn invoke(&mut self, a: &ExecutionAdmissionV1) -> InvocationOutcome {
            self.calls += 1;
            if self.unknown {
                InvocationOutcome::Unknown {
                    reason: "operator-outcome-unknown".into(),
                }
            } else {
                InvocationOutcome::ConfirmedRetired {
                    original_operation_id: a.original_operation_id.clone(),
                    receipt_id: format!("receipt-{}", a.assignment_id),
                }
            }
        }
    }
    struct Lookup;
    impl OriginalOutcomeLookup for Lookup {
        fn lookup(&mut self, a: &ExecutionAdmissionV1) -> InvocationOutcome {
            InvocationOutcome::ConfirmedRetired {
                original_operation_id: a.original_operation_id.clone(),
                receipt_id: "original-retirement-receipt".into(),
            }
        }
    }

    #[test]
    fn p007_durable_claim_invokes_once_replay_and_restart_never_reinvoke() {
        let f = Fixture::new(vec![vec![entry("A1")]]);
        let mut s = f.open();
        let a = f.authority(150);
        let selected = s.select_next(&a).unwrap();
        let m = message(
            &s,
            &f,
            &selected.task_ref.task_key(),
            "assignment-1",
            |_| {},
        );
        let c = claim(&mut s, &m, &f, AdmissionTrigger::Manual);
        let mut exec = Executor::default();
        assert_eq!(
            s.invoke(c, &a, &mut exec).unwrap(),
            AdmissionStatus::Completed
        );
        assert_eq!(exec.calls, 1);
        assert!(matches!(
            s.admit(&m, AdmissionTrigger::Timer, &a).unwrap(),
            AdmissionDisposition::Existing(AdmissionStatus::Completed)
        ));
        let changed = message(&s, &f, &selected.task_ref.task_key(), "assignment-1", |r| {
            r.tokens = 9
        });
        assert!(matches!(
            s.admit(&changed, AdmissionTrigger::Event, &a),
            Err(SchedulerError::ReplayConflict)
        ));
        drop(s);
        let mut reopened = f.open();
        assert!(matches!(
            reopened.admit(&m, AdmissionTrigger::Event, &a).unwrap(),
            AdmissionDisposition::Existing(AdmissionStatus::Completed)
        ));
        assert_eq!(exec.calls, 1);
        assert_eq!(
            reopened.select_next(&a).unwrap_err(),
            SchedulerError::NoEligibleTask
        );
    }
    #[test]
    fn p007_persisted_round_robin_fifo_survives_every_reopen() {
        let f = Fixture::new(vec![
            vec![entry("A1"), entry("A2")],
            vec![entry("B1"), entry("B2")],
            vec![entry("C1"), entry("C2")],
        ]);
        let mut seen = Vec::new();
        for n in 0..6 {
            let mut s = f.open();
            let selected = s.select_next(&f.authority(150)).unwrap();
            seen.push(selected.task_ref.task_id.clone());
            let m = message(
                &s,
                &f,
                &selected.task_ref.task_key(),
                &format!("fair-{n}"),
                |_| {},
            );
            let c = claim(&mut s, &m, &f, AdmissionTrigger::Timer);
            s.invoke(c, &f.authority(150), &mut Executor::default())
                .unwrap();
        }
        assert_eq!(seen, ["A1", "B1", "C1", "A2", "B2", "C2"]);
    }
    #[test]
    fn p007_unknown_keeps_slot_task_and_budget_reserved_across_reopen() {
        let mut f = Fixture::new(vec![vec![entry("A1"), entry("A2")], vec![entry("B1")]]);
        let b = f
            .profile
            .grants
            .keys()
            .find(|k| k.task_id == "B1")
            .unwrap()
            .clone();
        f.profile.grants.get_mut(&b).unwrap().resource = "other".into();
        let mut s = f.open();
        let selected = s.select_next(&f.authority(150)).unwrap();
        let m = message(&s, &f, &selected.task_ref.task_key(), "unknown-1", |_| {});
        let c = claim(&mut s, &m, &f, AdmissionTrigger::Manual);
        let mut exec = Executor {
            calls: 0,
            unknown: true,
        };
        assert_eq!(
            s.invoke(c, &f.authority(150), &mut exec).unwrap(),
            AdmissionStatus::Unknown
        );
        drop(s);
        let mut s = f.open();
        assert!(matches!(
            s.admit(&m, AdmissionTrigger::Timer, &f.authority(150))
                .unwrap(),
            AdmissionDisposition::Existing(AdmissionStatus::Unknown)
        ));
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
            "B1"
        );
        assert_eq!(
            s.resolve_original("unknown-1", &f.authority(150), &mut Lookup)
                .unwrap(),
            AdmissionStatus::Completed
        );
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
            "B1"
        );
        assert_eq!(exec.calls, 1);
    }
    #[test]
    fn p007_manual_timer_compete_for_one_durable_slot_and_task_key() {
        let f = Fixture::new(vec![vec![entry("A1"), entry("A2")]]);
        let mut s = f.open();
        assert!(
            WorkspaceScheduler::open(&File::open(f.store.path()).unwrap(), f.registry.policy())
                .is_err()
        );
        let selected = s.select_next(&f.authority(150)).unwrap();
        let manual = message(&s, &f, &selected.task_ref.task_key(), "manual", |_| {});
        let timer = message(&s, &f, &selected.task_ref.task_key(), "timer", |_| {});
        let _c = claim(&mut s, &manual, &f, AdmissionTrigger::Manual);
        assert!(
            s.admit(&timer, AdmissionTrigger::Timer, &f.authority(150))
                .is_err()
        );
        assert_eq!(s.assignments.len(), 1);
        drop(s);
        let mut reopened = f.open();
        assert_eq!(reopened.status("manual"), Some(AdmissionStatus::Claimed));
        assert!(
            reopened
                .admit(&timer, AdmissionTrigger::Timer, &f.authority(150))
                .is_err()
        );
    }
    #[test]
    fn p007_production_unsupported_and_fresh_authority_checks_have_no_effect() {
        let mut f = Fixture::new(vec![vec![entry("A1")]]);
        let mut s = f.open();
        assert_eq!(
            s.select_next(&CurrentAuthority::unsupported(
                &f.registry,
                HostClockState::Verified { now_unix: 150 }
            ))
            .unwrap_err(),
            SchedulerError::UnsupportedAdapters
        );
        let selected = s.select_next(&f.authority(150)).unwrap();
        let m = message(&s, &f, &selected.task_ref.task_key(), "stale", |_| {});
        let bad = message(&s, &f, &selected.task_ref.task_key(), "bad-graph", |r| {
            r.dag_revision += 1
        });
        assert!(matches!(
            s.admit(&bad, AdmissionTrigger::Manual, &f.authority(150)),
            Err(SchedulerError::StaleGraph)
        ));
        let mut rollback = f.authority(150);
        rollback.clock = HostClockState::ClockRollback;
        assert!(matches!(
            s.admit(&m, AdmissionTrigger::Manual, &rollback),
            Err(SchedulerError::Clock)
        ));
        let mut expired = f.authority(201);
        assert!(s.admit(&m, AdmissionTrigger::Manual, &expired).is_err());
        expired.profile = None;
        f.profile.grants.values_mut().next().unwrap().controls = Sha256Digest([9; 32]);
        assert!(
            s.admit(&m, AdmissionTrigger::Manual, &f.authority(150))
                .is_err()
        );
        assert!(s.assignments.is_empty());
    }
    #[test]
    fn p007_invalid_transition_is_rejected_before_journal_bytes() {
        let f = Fixture::new(vec![vec![entry("A1")]]);
        let mut s = f.open();
        let selected = s.select_next(&f.authority(150)).unwrap();
        let m = message(&s, &f, &selected.task_ref.task_key(), "terminal", |_| {});
        let c = claim(&mut s, &m, &f, AdmissionTrigger::Event);
        s.invoke(c, &f.authority(150), &mut Executor::default())
            .unwrap();
        let path = f
            .store
            .path()
            .join(crate::task_scheduler_journal::SCHEDULER_JOURNAL_FILE_NAME);
        let before = fs::read(&path).unwrap();
        assert!(
            s.finish(
                "terminal",
                InvocationOutcome::Unknown {
                    reason: "invalid-after-terminal".into()
                },
                150
            )
            .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), before);
        drop(s);
        assert_eq!(
            f.open().status("terminal"),
            Some(AdmissionStatus::Completed)
        );
    }
    #[test]
    fn p007_done_file_without_exact_accepted_evidence_cannot_satisfy_dependency() {
        let mut done = entry("DONE");
        done.status = CanonicalTaskStatus::Done;
        done.task_status_rev = 1;
        let mut child = entry("NEXT");
        child.dependencies.push(DependencyCommitment {
            target_key: TaskKey::new("scheduler-fixture", format!("{:032x}", 1), "DONE").unwrap(),
            target_spec_digest: done.task_spec_digest,
            completion_policy_digest: done.completion_policy_digest,
        });
        let mut f = Fixture::new(vec![vec![done, child]]);
        let mut s = f.open();
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap_err(),
            SchedulerError::NoEligibleTask
        );
        let t = s
            .catalog
            .values()
            .find(|t| t.entry.task_id == "DONE")
            .unwrap();
        let key = t.reference.task_key();
        let proof = AcceptedCompletion {
            reference: t.reference.clone(),
            controls: t.entry.task_control_digest,
            policy: t.entry.completion_policy_digest,
            verified_acceptance: Sha256Digest::of(b"fixture verified paired acceptance"),
        };
        f.profile
            .accepted_dependencies
            .insert(key.clone(), proof.clone());
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
            "NEXT"
        );
        f.profile
            .accepted_dependencies
            .get_mut(&key)
            .unwrap()
            .reference
            .file_cas_rev += 1;
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap_err(),
            SchedulerError::NoEligibleTask
        );
    }
    #[test]
    fn p007_stale_spec_epoch_and_dependency_sources_do_not_authorize_execution() {
        let mut f = Fixture::new(vec![vec![entry("A1")], vec![entry("B1")]]);
        let mut s = f.open();
        let selected = s.select_next(&f.authority(150)).unwrap();
        let key = selected.task_ref.task_key();
        let m = message(&s, &f, &key, "recheck", |_| {});
        let c = claim(&mut s, &m, &f, AdmissionTrigger::Manual);
        f.profile.grants.get_mut(&key).unwrap().spec = Sha256Digest([8; 32]);
        let mut exec = Executor::default();
        assert!(s.invoke(c, &f.authority(150), &mut exec).is_err());
        assert_eq!(exec.calls, 0);
        assert_eq!(
            s.status("recheck"),
            Some(AdmissionStatus::RejectedBeforeInvocation)
        );
        let mut policy = f.registry.policy().clone();
        policy.authority_epoch += 1;
        drop(s);
        assert!(WorkspaceScheduler::open(&File::open(f.store.path()).unwrap(), &policy).is_err());
    }
    #[test]
    fn p007_completed_spend_stays_committed_and_blocks_budget_oversubscription() {
        let mut f = Fixture::new(vec![vec![entry("A1"), entry("A2")]]);
        f.profile.token_limit = 10;
        let mut s = f.open();
        let selected = s.select_next(&f.authority(150)).unwrap();
        let m = message(&s, &f, &selected.task_ref.task_key(), "budget", |_| {});
        let c = claim(&mut s, &m, &f, AdmissionTrigger::Manual);
        s.invoke(c, &f.authority(150), &mut Executor::default())
            .unwrap();
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap_err(),
            SchedulerError::NoEligibleTask
        );
    }
    #[test]
    fn p007_rechecks_capacity_budget_and_lease_before_consumed_claim_invokes() {
        for revoke in 0..3 {
            let mut f = Fixture::new(vec![vec![entry("A1")]]);
            let mut s = f.open();
            let task = s.select_next(&f.authority(150)).unwrap();
            let m = message(&s, &f, &task.task_ref.task_key(), "revoked", |_| {});
            let c = claim(&mut s, &m, &f, AdmissionTrigger::Manual);
            match revoke {
                0 => {
                    f.profile.capacities.insert("cpu".into(), 0);
                }
                1 => f.profile.token_limit = 0,
                _ => f.profile.write_claim = "different-current-lease".into(),
            };
            let mut exec = Executor::default();
            assert!(s.invoke(c, &f.authority(150), &mut exec).is_err());
            assert_eq!(exec.calls, 0);
            assert_eq!(
                s.status("revoked"),
                Some(AdmissionStatus::RejectedBeforeInvocation)
            );
        }
    }
    #[test]
    fn p007_event_and_timer_cannot_bypass_automatic_dispatch_controls() {
        let f = Fixture::with_auto(vec![vec![entry("A1")]], false);
        let mut s = f.open();
        let task = s.select_next(&f.authority(150)).unwrap();
        for trigger in [AdmissionTrigger::Timer, AdmissionTrigger::Event] {
            let m = message(&s, &f, &task.task_ref.task_key(), "automatic", |_| {});
            assert!(matches!(
                s.admit(&m, trigger, &f.authority(150)),
                Err(SchedulerError::Grant)
            ));
            assert!(s.assignments.is_empty());
        }
        let m = message(&s, &f, &task.task_ref.task_key(), "manual-only", |_| {});
        let c = claim(&mut s, &m, &f, AdmissionTrigger::Manual);
        let mut exec = Executor::default();
        assert_eq!(
            s.invoke(c, &f.authority(150), &mut exec).unwrap(),
            AdmissionStatus::Completed
        );
        assert_eq!(exec.calls, 1);
    }
    #[test]
    fn p007_authority_cannot_select_a_second_store_for_the_same_workspace() {
        struct NeverLookup;
        impl OriginalOutcomeLookup for NeverLookup {
            fn lookup(&mut self, _: &ExecutionAdmissionV1) -> InvocationOutcome {
                panic!("unadmitted store must not query an operator")
            }
        }
        let f = Fixture::new(vec![vec![entry("A1")]]);
        let mut admitted = f.open();
        let task = admitted.select_next(&f.authority(150)).unwrap();
        let m = message(
            &admitted,
            &f,
            &task.task_ref.task_key(),
            "one-workspace",
            |_| {},
        );
        let second = TempDir::new().unwrap();
        fs::set_permissions(second.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut foreign =
            WorkspaceScheduler::open(&File::open(second.path()).unwrap(), f.registry.policy())
                .unwrap();
        assert_eq!(
            foreign.select_next(&f.authority(150)).unwrap_err(),
            SchedulerError::Grant
        );
        assert!(matches!(
            foreign.admit(&m, AdmissionTrigger::Manual, &f.authority(150)),
            Err(SchedulerError::Grant)
        ));
        assert!(foreign.assignments.is_empty());
        assert!(foreign.catalog.is_empty());
        let c = claim(&mut admitted, &m, &f, AdmissionTrigger::Manual);
        let mut exec = Executor::default();
        assert_eq!(
            foreign.invoke(c, &f.authority(150), &mut exec),
            Err(SchedulerError::Grant)
        );
        assert_eq!(
            foreign.resolve_original("one-workspace", &f.authority(150), &mut NeverLookup),
            Err(SchedulerError::Grant)
        );
        assert_eq!(exec.calls, 0);
        assert_eq!(
            admitted.status("one-workspace"),
            Some(AdmissionStatus::Claimed)
        );
    }
    #[test]
    fn p007_qa_regression_automatic_turn_skips_manual_only_source_across_reopen() {
        for trigger in [AdmissionTrigger::Timer, AdmissionTrigger::Event] {
            let mut f = Fixture::with_automatic_sources(
                vec![vec![entry("A1")], vec![entry("B1")]],
                vec![false, true],
            );
            let b = f
                .profile
                .grants
                .keys()
                .find(|k| k.task_id == "B1")
                .unwrap()
                .clone();
            f.profile.grants.get_mut(&b).unwrap().resource = "other".into();
            let mut s = f.open();
            assert_eq!(
                s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
                "A1"
            );
            let m = message(&s, &f, &b, "automatic-B", |_| {});
            drop(s);
            let mut s = f.open();
            assert!(s.last_source.is_none());
            assert_eq!(
                s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
                "A1"
            );
            let result = s.admit(&m, trigger, &f.authority(150));
            assert!(
                matches!(result, Ok(AdmissionDisposition::Claimed(_))),
                "manual-only A must not block automatic B"
            );
        }
    }
    fn dependency_to(source: usize, id: &str) -> DependencyCommitment {
        DependencyCommitment {
            target_key: TaskKey::new("scheduler-fixture", format!("{source:032x}"), id).unwrap(),
            target_spec_digest: Sha256Digest::of(id.as_bytes()),
            completion_policy_digest: Sha256Digest([3; 32]),
        }
    }
    #[test]
    fn p007_qa_regression_unresolved_target_has_exact_reason_without_blocking_other_source() {
        let mut blocked = entry("A1");
        let dependency = dependency_to(3, "MISSING");
        blocked.dependencies.push(dependency.clone());
        let f = Fixture::new(vec![vec![blocked], vec![entry("B1")]]);
        let mut s = f.open();
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
            "B1"
        );
        let task = s
            .catalog
            .values()
            .find(|t| t.entry.task_id == "A1")
            .unwrap();
        let reason = format!("{:?}", s.dependencies(task, &f.profile));
        assert!(
            reason.contains("UnresolvedTarget")
                && reason.contains("MISSING")
                && reason.contains(&dependency.target_key.task_source_id),
            "exact target reason required: {reason}"
        );
        assert_eq!(
            s.dependency_blocked_reasons()
                .get(&task.reference.task_key()),
            Some(&DependencyBlockReason::UnresolvedTarget {
                target: dependency.target_key
            })
        );
        assert_eq!(s.dependency_blocked_reasons().len(), 1);
    }
    #[test]
    fn p007_qa_regression_removed_target_has_exact_reason_without_blocking_other_source() {
        let mut blocked = entry("A1");
        let dependency = dependency_to(2, "DONE");
        blocked.dependencies.push(dependency.clone());
        let mut done = entry("DONE");
        done.status = CanonicalTaskStatus::Done;
        let mut f = Fixture::new(vec![vec![blocked], vec![done], vec![entry("C1")]]);
        f.registry
            .transition_source(
                &dependency.target_key.task_source_id,
                TaskSourceState::Retired,
            )
            .unwrap();
        let mut s = f.open();
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
            "C1"
        );
        let task = s
            .catalog
            .values()
            .find(|t| t.entry.task_id == "A1")
            .unwrap();
        let reason = format!("{:?}", s.dependencies(task, &f.profile));
        assert!(
            reason.contains("SourceUnavailable")
                && reason.contains("Retired")
                && reason.contains("DONE")
                && reason.contains(&dependency.target_key.task_source_id),
            "removed source reason required: {reason}"
        );
        assert_eq!(
            s.dependency_blocked_reasons()
                .get(&task.reference.task_key()),
            Some(&DependencyBlockReason::SourceUnavailable {
                target: dependency.target_key,
                state: TaskSourceState::Retired
            })
        );
        assert_eq!(s.dependency_blocked_reasons().len(), 1);
    }
    #[test]
    fn p007_qa_regression_cycle_has_reason_without_blocking_other_source() {
        let mut a1 = entry("A1");
        let mut a2 = entry("A2");
        a1.dependencies.push(dependency_to(1, "A2"));
        a2.dependencies.push(dependency_to(1, "A1"));
        let f = Fixture::new(vec![vec![a1, a2], vec![entry("B1")]]);
        let mut s = f.open();
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap().task_ref.task_id,
            "B1"
        );
        let task = s
            .catalog
            .values()
            .find(|t| t.entry.task_id == "A1")
            .unwrap();
        let reason = format!("{:?}", s.dependencies(task, &f.profile));
        assert!(
            reason.contains("Cycle"),
            "cycle must not collapse into generic dependency failure: {reason}"
        );
        for id in ["A1", "A2"] {
            let key = TaskKey::new("scheduler-fixture", format!("{:032x}", 1), id).unwrap();
            assert_eq!(
                s.dependency_blocked_reasons().get(&key),
                Some(&DependencyBlockReason::Cycle)
            );
        }
        assert_eq!(s.dependency_blocked_reasons().len(), 2);
    }
    #[test]
    fn p008_real_scheduler_claim_requires_committed_lease_before_protected_write() {
        use crate::task_resource_lease::{
            LeaseRequest, LeaseStatus, LeasedExecutor, ProtectedWriter, ResourceScope,
        };
        struct Writer {
            calls: usize,
        }
        impl LeasedExecutor for Writer {
            fn invoke(
                &mut self,
                admission: &ExecutionAdmissionV1,
                writer: &mut ProtectedWriter<'_>,
            ) -> InvocationOutcome {
                self.calls += 1;
                writer.write_file(0, b"guarded actual bytes").unwrap();
                InvocationOutcome::ConfirmedRetired {
                    original_operation_id: admission.original_operation_id.clone(),
                    receipt_id: "controlled-original-retired".into(),
                }
            }
        }
        let f = Fixture::new(vec![vec![entry("A1")]]);
        let mut s = f.open();
        let task = s.select_next(&f.authority(150)).unwrap();
        let message = message(&s, &f, &task.task_ref.task_key(), "leased-real", |_| {});
        let claim = claim(&mut s, &message, &f, AdmissionTrigger::Manual);
        let qualified = s.qualify_for_lease(&claim, &f.authority(150)).unwrap();
        let fixture = crate::task_resource_lease::tests::Fixture::new(s.store_identity);
        fs::write(fixture.root.path().join("code.rs"), b"before").unwrap();
        let mut leases = fixture.open();
        let cap = fixture.acquire(
            &mut leases,
            &qualified,
            LeaseRequest {
                scopes: vec![ResourceScope::File {
                    path: "code.rs".into(),
                }],
                ttl_seconds: 120,
            },
        );
        let mut writer = Writer { calls: 0 };
        assert_eq!(
            s.invoke_with_lease(
                claim,
                &f.authority(150),
                &mut leases,
                cap,
                &fixture.authority(),
                &mut writer
            )
            .unwrap(),
            AdmissionStatus::Completed
        );
        assert_eq!(writer.calls, 1);
        assert_eq!(
            fs::read(fixture.root.path().join("code.rs")).unwrap(),
            b"guarded actual bytes"
        );
        assert_eq!(leases.status("leased-real"), Some(LeaseStatus::Unknown));
        assert!(matches!(
            s.admit(&message, AdmissionTrigger::Event, &f.authority(150))
                .unwrap(),
            AdmissionDisposition::Existing(AdmissionStatus::Completed)
        ));
    }
    #[test]
    fn p008_expired_lease_is_proved_precallback_refusal_not_unknown_invocation() {
        use crate::task_resource_lease::{
            LeaseRequest, LeasedExecutor, ProtectedWriter, ResourceScope,
        };
        struct Never {
            calls: usize,
        }
        impl LeasedExecutor for Never {
            fn invoke(
                &mut self,
                _: &ExecutionAdmissionV1,
                _: &mut ProtectedWriter<'_>,
            ) -> InvocationOutcome {
                self.calls += 1;
                panic!("expired lease must never invoke")
            }
        }
        let f = Fixture::new(vec![vec![entry("A1")]]);
        let mut s = f.open();
        let task = s.select_next(&f.authority(150)).unwrap();
        let message = message(&s, &f, &task.task_ref.task_key(), "lease-expired", |_| {});
        let claim = claim(&mut s, &message, &f, AdmissionTrigger::Manual);
        let qualified = s.qualify_for_lease(&claim, &f.authority(150)).unwrap();
        let fixture = crate::task_resource_lease::tests::Fixture::new(s.store_identity);
        fs::write(fixture.root.path().join("code.rs"), b"unchanged").unwrap();
        let mut leases = fixture.open();
        let cap = fixture.acquire(
            &mut leases,
            &qualified,
            LeaseRequest {
                scopes: vec![ResourceScope::File {
                    path: "code.rs".into(),
                }],
                ttl_seconds: 120,
            },
        );
        fixture
            .clock
            .set(HostClockState::Verified { now_unix: 200 });
        let mut never = Never { calls: 0 };
        assert!(matches!(
            s.invoke_with_lease(
                claim,
                &f.authority(150),
                &mut leases,
                cap,
                &fixture.authority(),
                &mut never
            ),
            Err(SchedulerError::ResourceLeaseHeld(_))
        ));
        assert_eq!(never.calls, 0);
        assert_eq!(
            s.status("lease-expired"),
            Some(AdmissionStatus::RejectedBeforeInvocation)
        );
        assert_eq!(
            fs::read(fixture.root.path().join("code.rs")).unwrap(),
            b"unchanged"
        );
    }
    #[test]
    fn p007_original_outcome_for_another_operation_cannot_release_unknown_claim() {
        struct Wrong;
        impl OriginalOutcomeLookup for Wrong {
            fn lookup(&mut self, _: &ExecutionAdmissionV1) -> InvocationOutcome {
                InvocationOutcome::ConfirmedRetired {
                    original_operation_id: "another-original-operation".into(),
                    receipt_id: "stale-receipt".into(),
                }
            }
        }
        let f = Fixture::new(vec![vec![entry("A1"), entry("A2")]]);
        let mut s = f.open();
        let task = s.select_next(&f.authority(150)).unwrap();
        let m = message(&s, &f, &task.task_ref.task_key(), "retained", |_| {});
        let c = claim(&mut s, &m, &f, AdmissionTrigger::Manual);
        let mut exec = Executor {
            calls: 0,
            unknown: true,
        };
        s.invoke(c, &f.authority(150), &mut exec).unwrap();
        assert_eq!(
            s.resolve_original("retained", &f.authority(150), &mut Wrong),
            Err(SchedulerError::ReplayConflict)
        );
        assert_eq!(s.status("retained"), Some(AdmissionStatus::Unknown));
        assert_eq!(
            s.select_next(&f.authority(150)).unwrap_err(),
            SchedulerError::NoEligibleTask
        );
        assert_eq!(exec.calls, 1);
    }
}
