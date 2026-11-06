//! Qualified dependency commitments and finite, nonrecursive DAG validation.

use crate::task_ref::{
    CanonicalDecoder, GitOid, MAX_DEPENDENCY_DEPTH, MAX_DEPENDENCY_EDGES, MAX_LIST_ITEMS,
    MAX_TASK_SOURCES, MAX_TASKS_PER_SOURCE, Sha256Digest, TaskContractError, TaskKey, TaskRefV1,
    encode_list,
};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyCommitment {
    pub target_key: TaskKey,
    pub target_spec_digest: Sha256Digest,
    pub completion_policy_digest: Sha256Digest,
}

impl DependencyCommitment {
    pub fn validate(&self) -> Result<(), TaskContractError> {
        self.target_key.validate()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = self.target_key.encode();
        encoded.extend(self.target_spec_digest.encode_typed());
        encoded.extend(self.completion_policy_digest.encode_typed());
        encoded
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TaskContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let value = Self {
            target_key: decoder.task_key()?,
            target_spec_digest: decoder.sha256_digest()?,
            completion_policy_digest: decoder.sha256_digest()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

pub fn canonicalize_dependencies(
    dependent_key: &TaskKey,
    mut dependencies: Vec<DependencyCommitment>,
) -> Result<Vec<DependencyCommitment>, TaskContractError> {
    dependent_key.validate()?;
    if dependencies.len() > MAX_LIST_ITEMS {
        return Err(TaskContractError::LimitExceeded("dependencies"));
    }
    for dependency in &dependencies {
        dependency.validate()?;
        if dependency.target_key.workspace_id != dependent_key.workspace_id {
            return Err(TaskContractError::CrossWorkspaceDependency);
        }
        if &dependency.target_key == dependent_key {
            return Err(TaskContractError::SelfDependency);
        }
    }
    dependencies.sort_by(|a, b| a.target_key.cmp(&b.target_key));
    if dependencies
        .windows(2)
        .any(|pair| pair[0].target_key == pair[1].target_key)
    {
        return Err(TaskContractError::DuplicateDependency);
    }
    Ok(dependencies)
}

pub fn encode_dependencies(
    dependent_key: &TaskKey,
    dependencies: &[DependencyCommitment],
) -> Result<Vec<u8>, TaskContractError> {
    if dependencies.len() > MAX_LIST_ITEMS {
        return Err(TaskContractError::LimitExceeded("dependencies"));
    }
    let canonical = canonicalize_dependencies(dependent_key, dependencies.to_vec())?;
    encode_list(&canonical, DependencyCommitment::encode)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Todo,
    InProgress,
    DonePendingReview,
    Done,
    Blocked,
}

impl TaskStatus {
    pub fn parse(value: &str) -> Result<Self, TaskContractError> {
        match value {
            "todo" => Ok(Self::Todo),
            "in-progress" => Ok(Self::InProgress),
            "done-pending-review" => Ok(Self::DonePendingReview),
            "done" => Ok(Self::Done),
            "blocked" => Ok(Self::Blocked),
            _ => Err(TaskContractError::InvalidField("task status")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Todo => "todo",
            Self::InProgress => "in-progress",
            Self::DonePendingReview => "done-pending-review",
            Self::Done => "done",
            Self::Blocked => "blocked",
        }
    }
}

/// Supplied by the enrolled source resolver, independently of target evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencySourceBinding {
    pub workspace_id: String,
    pub task_source_id: String,
    pub repo_id: String,
    pub source_generation: u64,
    pub canonical_task_path: String,
    pub baseline_commit: GitOid,
}

impl DependencySourceBinding {
    pub fn from_task_ref(task_ref: &TaskRefV1) -> Result<Self, TaskContractError> {
        task_ref.validate()?;
        Ok(Self {
            workspace_id: task_ref.workspace_id.clone(),
            task_source_id: task_ref.task_source_id.clone(),
            repo_id: task_ref.repo_id.clone(),
            source_generation: task_ref.source_generation,
            canonical_task_path: task_ref.canonical_task_path.clone(),
            baseline_commit: task_ref.baseline_commit,
        })
    }

    pub fn matches(&self, task_ref: &TaskRefV1) -> Result<(), TaskContractError> {
        task_ref.validate()?;
        if self != &Self::from_task_ref(task_ref)? {
            return Err(TaskContractError::AcceptanceInvalidated);
        }
        Ok(())
    }
}

/// Supplied by the authoritative enrolled source/index caller, which projects
/// only current enrolled-source tasks and enforces exact CAS commitment sets at
/// the index boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDependency {
    pub task_ref: TaskRefV1,
    pub completion_policy_digest: Sha256Digest,
    pub status: TaskStatus,
}

/// No prose or pending-review state can satisfy a qualified dependency.
/// `current_source` and `resolved` must come from the authoritative enrolled
/// source/index caller, which projects only current enrolled-source tasks and
/// enforces exact CAS commitment sets at the index boundary.
pub fn validate_dependency_satisfaction(
    required: &DependencyCommitment,
    resolved: &ResolvedDependency,
    current_source: &DependencySourceBinding,
) -> Result<(), TaskContractError> {
    required.validate()?;
    current_source.matches(&resolved.task_ref)?;
    if required.target_key != resolved.task_ref.task_key()
        || required.target_spec_digest != resolved.task_ref.task_spec_digest
        || required.completion_policy_digest != resolved.completion_policy_digest
        || resolved.status != TaskStatus::Done
    {
        return Err(TaskContractError::DependencyUnsatisfied);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyNode {
    pub task_ref: TaskRefV1,
    pub completion_policy_digest: Sha256Digest,
    pub dependencies: Vec<DependencyCommitment>,
}

/// Validates graph structure and commitments, independently of task completion.
/// Every referenced target must be present, including targets in other sources.
/// All nodes and edges must remain in one workspace and one repository.
/// The caller must resolve each source against its current enrolled binding.
pub fn validate_dependency_graph(nodes: &[DependencyNode]) -> Result<(), TaskContractError> {
    if nodes.len() > MAX_TASK_SOURCES * MAX_TASKS_PER_SOURCE {
        return Err(TaskContractError::LimitExceeded("graph tasks"));
    }
    let mut indices = BTreeMap::new();
    let mut sources: BTreeMap<(String, String), (usize, DependencySourceBinding)> = BTreeMap::new();
    let mut edge_count = 0usize;
    for (index, node) in nodes.iter().enumerate() {
        node.task_ref.validate()?;
        if let Some(first) = nodes.first() {
            if node.task_ref.workspace_id != first.task_ref.workspace_id {
                return Err(TaskContractError::CrossWorkspaceDependency);
            }
            if node.task_ref.repo_id != first.task_ref.repo_id {
                return Err(TaskContractError::CrossRepositoryDependency);
            }
        }
        let key = node.task_ref.task_key();
        if indices.insert(key.clone(), index).is_some() {
            return Err(TaskContractError::DuplicateDependency);
        }
        let source_key = (key.workspace_id, key.task_source_id);
        if !sources.contains_key(&source_key) && sources.len() == MAX_TASK_SOURCES {
            return Err(TaskContractError::LimitExceeded("task sources"));
        }
        let binding = DependencySourceBinding::from_task_ref(&node.task_ref)?;
        let source = sources.entry(source_key).or_insert((0, binding));
        source.0 += 1;
        if source.0 > MAX_TASKS_PER_SOURCE {
            return Err(TaskContractError::LimitExceeded("tasks per source"));
        }
        source.1.matches(&node.task_ref)?;
        if node.dependencies.len() > MAX_LIST_ITEMS {
            return Err(TaskContractError::LimitExceeded("dependencies"));
        }
        edge_count = edge_count
            .checked_add(node.dependencies.len())
            .ok_or(TaskContractError::LimitExceeded("dependency edges"))?;
        if edge_count > MAX_DEPENDENCY_EDGES {
            return Err(TaskContractError::LimitExceeded("dependency edges"));
        }
    }

    let mut edges = vec![Vec::new(); nodes.len()];
    let mut incoming = vec![0usize; nodes.len()];
    for (index, node) in nodes.iter().enumerate() {
        let canonical =
            canonicalize_dependencies(&node.task_ref.task_key(), node.dependencies.clone())?;
        for dependency in canonical {
            let target = *indices
                .get(&dependency.target_key)
                .ok_or(TaskContractError::DependencyTargetMissing)?;
            if nodes[target].task_ref.repo_id != node.task_ref.repo_id {
                return Err(TaskContractError::CrossRepositoryDependency);
            }
            if nodes[target].task_ref.task_spec_digest != dependency.target_spec_digest
                || nodes[target].completion_policy_digest != dependency.completion_policy_digest
            {
                return Err(TaskContractError::DependencyUnsatisfied);
            }
            edges[index].push(target);
            incoming[target] += 1;
        }
    }

    // Kahn's algorithm detects cycles without consuming the call stack. Longest
    // path propagation also catches depth hidden behind an earlier short path.
    let mut ready: VecDeque<usize> = incoming
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect();
    let mut depths = vec![0usize; nodes.len()];
    let mut visited = 0;
    while let Some(index) = ready.pop_front() {
        visited += 1;
        for &target in &edges[index] {
            depths[target] = depths[target].max(depths[index] + 1);
            incoming[target] -= 1;
            if incoming[target] == 0 {
                ready.push_back(target);
            }
        }
    }
    if visited != nodes.len() {
        return Err(TaskContractError::DependencyCycleDetected);
    }
    if depths.iter().any(|depth| *depth > MAX_DEPENDENCY_DEPTH) {
        return Err(TaskContractError::DependencyDepthExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(task_id: &str) -> TaskKey {
        TaskKey::new(
            "p0-fixture-workspace",
            "00000000000000000000000000000001",
            task_id,
        )
        .unwrap()
    }

    fn node(task_id: &str) -> DependencyNode {
        let key = key(task_id);
        DependencyNode {
            task_ref: TaskRefV1 {
                workspace_id: key.workspace_id,
                repo_id: "p0-fixture-repo".into(),
                task_source_id: key.task_source_id,
                source_generation: 1,
                canonical_task_path: "TASKS.md".into(),
                task_id: key.task_id,
                task_spec_digest: Sha256Digest([0x11; 32]),
                task_status_rev: 0,
                file_cas_rev: 0,
                baseline_commit: GitOid::Sha1([1; 20]),
            },
            completion_policy_digest: Sha256Digest([0x22; 32]),
            dependencies: vec![],
        }
    }

    fn commitment(target: &DependencyNode) -> DependencyCommitment {
        DependencyCommitment {
            target_key: target.task_ref.task_key(),
            target_spec_digest: target.task_ref.task_spec_digest,
            completion_policy_digest: target.completion_policy_digest,
        }
    }

    fn chain(edges: usize) -> Vec<DependencyNode> {
        let mut nodes: Vec<_> = (0..=edges).map(|i| node(&format!("N-{i}"))).collect();
        for i in 0..edges {
            let target = commitment(&nodes[i + 1]);
            nodes[i].dependencies.push(target);
        }
        nodes
    }

    #[test]
    fn p0_contract_dependency_golden_transcript_digest_and_roundtrip() {
        let dependency = commitment(&node("B"));
        let encoded = dependency.encode();
        assert_eq!(encoded.len(), 185);
        let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            concat!(
                "000000000000001470302d666978747572652d776f726b7370616365",
                "00000000000000203030303030303030303030303030303030303030303030303030303030303031",
                "00000000000000014200000000000000067368613235360000000000000020",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "00000000000000067368613235360000000000000020",
                "2222222222222222222222222222222222222222222222222222222222222222"
            )
        );
        assert_eq!(
            Sha256Digest::of(&encoded).to_string(),
            "2de60a32b3dc1e7d35c1389b572553834938aa72e0472d842107cc5a152f6772"
        );
        assert_eq!(DependencyCommitment::decode(&encoded).unwrap(), dependency);
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            DependencyCommitment::decode(&trailing),
            Err(TaskContractError::TrailingBytes)
        );
    }

    #[test]
    fn p0_contract_dependency_sort_and_duplicate_key_rejected() {
        let a = commitment(&node("z"));
        let b = commitment(&node("aa"));
        let sorted = canonicalize_dependencies(&key("A"), vec![b.clone(), a.clone()]).unwrap();
        assert_eq!(sorted, vec![a.clone(), b]);
        assert_eq!(
            canonicalize_dependencies(&key("A"), vec![a.clone(), a.clone()]),
            Err(TaskContractError::DuplicateDependency)
        );
        let mut changed = a.clone();
        changed.target_spec_digest = Sha256Digest([9; 32]);
        assert_eq!(
            canonicalize_dependencies(&key("A"), vec![changed, a.clone()]),
            Err(TaskContractError::DuplicateDependency)
        );
        let mut changed = a.clone();
        changed.completion_policy_digest = Sha256Digest([9; 32]);
        assert_eq!(
            canonicalize_dependencies(&key("A"), vec![a, changed]),
            Err(TaskContractError::DuplicateDependency)
        );
    }

    #[test]
    fn p0_contract_dependency_self_and_list_limit_rejected() {
        let target = node("A");
        assert_eq!(
            canonicalize_dependencies(&key("A"), vec![commitment(&target)]),
            Err(TaskContractError::SelfDependency)
        );
        let too_many = (0..=MAX_LIST_ITEMS)
            .map(|i| commitment(&node(&format!("B-{i}"))))
            .collect();
        assert!(matches!(
            canonicalize_dependencies(&key("A"), too_many),
            Err(TaskContractError::LimitExceeded("dependencies"))
        ));
        let exact = (0..MAX_LIST_ITEMS)
            .map(|i| commitment(&node(&format!("B-{i}"))))
            .collect();
        assert_eq!(
            canonicalize_dependencies(&key("A"), exact).unwrap().len(),
            MAX_LIST_ITEMS
        );
    }

    #[test]
    fn p0_contract_dependency_complete_keys_distinguish_sources_and_workspaces() {
        let first = commitment(&node("B"));
        let mut second = first.clone();
        second.target_key.task_source_id = "00000000000000000000000000000002".into();
        let mut third = first.clone();
        third.target_key.workspace_id = "other-workspace".into();
        assert_ne!(first.target_key, second.target_key);
        assert_ne!(first.target_key, third.target_key);
        assert_ne!(second.target_key, third.target_key);
        assert_eq!(
            canonicalize_dependencies(&key("A"), vec![first, second])
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            canonicalize_dependencies(&key("A"), vec![third]),
            Err(TaskContractError::CrossWorkspaceDependency)
        );
    }

    #[test]
    fn p0_contract_dependency_same_workspace_repository_cross_source_succeeds() {
        let mut dependent = node("same-id");
        let mut target = node("same-id");
        target.task_ref.task_source_id = "00000000000000000000000000000002".into();
        let required = commitment(&target);
        assert_eq!(
            canonicalize_dependencies(&dependent.task_ref.task_key(), vec![required.clone()]),
            Ok(vec![required.clone()])
        );
        dependent.dependencies.push(required);
        assert_eq!(validate_dependency_graph(&[dependent, target]), Ok(()));
    }

    #[test]
    fn p0_contract_dependency_cross_workspace_edge_rejected() {
        let mut dependent = node("A");
        let mut target = node("B");
        target.task_ref.workspace_id = "other-workspace".into();
        let required = commitment(&target);
        assert_eq!(
            canonicalize_dependencies(&dependent.task_ref.task_key(), vec![required.clone()]),
            Err(TaskContractError::CrossWorkspaceDependency)
        );
        dependent.dependencies.push(required);
        assert_eq!(
            validate_dependency_graph(&[dependent.clone(), target]),
            Err(TaskContractError::CrossWorkspaceDependency)
        );
        assert_eq!(
            validate_dependency_graph(&[dependent]),
            Err(TaskContractError::CrossWorkspaceDependency)
        );
    }

    #[test]
    fn p0_contract_dependency_cross_repository_edge_rejected() {
        let mut dependent = node("A");
        let mut target = node("B");
        target.task_ref.task_source_id = "00000000000000000000000000000002".into();
        target.task_ref.repo_id = "other-repo".into();
        dependent.dependencies.push(commitment(&target));
        assert_eq!(
            validate_dependency_graph(&[dependent, target]),
            Err(TaskContractError::CrossRepositoryDependency)
        );
    }

    #[test]
    fn p0_contract_dependency_disconnected_graph_domain_rejected() {
        let first = node("A");
        let mut other = node("B");
        other.task_ref.workspace_id = "other-workspace".into();
        assert_eq!(
            validate_dependency_graph(&[first.clone(), other.clone()]),
            Err(TaskContractError::CrossWorkspaceDependency)
        );
        other.task_ref.workspace_id = first.task_ref.workspace_id.clone();
        other.task_ref.repo_id = "other-repo".into();
        assert_eq!(
            validate_dependency_graph(&[first, other]),
            Err(TaskContractError::CrossRepositoryDependency)
        );
    }

    #[test]
    fn p0_contract_dependency_satisfaction_requires_done_and_matching_digests() {
        let target = node("B");
        let required = commitment(&target);
        let current = DependencySourceBinding::from_task_ref(&target.task_ref).unwrap();
        let mut resolved = ResolvedDependency {
            task_ref: target.task_ref,
            completion_policy_digest: target.completion_policy_digest,
            status: TaskStatus::Done,
        };
        validate_dependency_satisfaction(&required, &resolved, &current).unwrap();
        for status in [
            TaskStatus::Todo,
            TaskStatus::InProgress,
            TaskStatus::DonePendingReview,
            TaskStatus::Blocked,
        ] {
            resolved.status = status;
            assert_eq!(
                validate_dependency_satisfaction(&required, &resolved, &current),
                Err(TaskContractError::DependencyUnsatisfied)
            );
        }
        resolved.status = TaskStatus::Done;
        for field in 0..3 {
            let mut changed = resolved.clone();
            match field {
                0 => changed.task_ref.task_id = "C".into(),
                1 => changed.task_ref.task_spec_digest = Sha256Digest([9; 32]),
                _ => changed.completion_policy_digest = Sha256Digest([9; 32]),
            }
            assert_eq!(
                validate_dependency_satisfaction(&required, &changed, &current),
                Err(TaskContractError::DependencyUnsatisfied)
            );
        }
        for bad in ["COMPLETED", "DONE", "done ", "Completed successfully"] {
            assert!(TaskStatus::parse(bad).is_err());
        }
        assert_eq!(TaskStatus::parse("done").unwrap().as_str(), "done");
    }

    #[test]
    fn p0_contract_dependency_stale_generation_baseline_and_binding_held() {
        let target = node("B");
        let required = commitment(&target);
        let current = DependencySourceBinding::from_task_ref(&target.task_ref).unwrap();
        let resolved = ResolvedDependency {
            task_ref: target.task_ref,
            completion_policy_digest: target.completion_policy_digest,
            status: TaskStatus::Done,
        };
        for field in 0..5 {
            let mut stale = resolved.clone();
            match field {
                0 => stale.task_ref.source_generation += 1,
                1 => stale.task_ref.baseline_commit = GitOid::Sha1([2; 20]),
                2 => stale.task_ref.repo_id = "other-repo".into(),
                3 => stale.task_ref.canonical_task_path = "tasks/TASKS.md".into(),
                _ => stale.task_ref.task_source_id = "00000000000000000000000000000002".into(),
            }
            assert_eq!(
                validate_dependency_satisfaction(&required, &stale, &current),
                Err(TaskContractError::AcceptanceInvalidated)
            );
        }
    }

    #[test]
    fn p0_contract_dependency_cycle_and_depth_128_enforced() {
        assert!(validate_dependency_graph(&chain(MAX_DEPENDENCY_DEPTH)).is_ok());
        assert_eq!(
            validate_dependency_graph(&chain(MAX_DEPENDENCY_DEPTH + 1)),
            Err(TaskContractError::DependencyDepthExceeded)
        );
        let mut cycle = chain(2);
        let back = commitment(&cycle[0]);
        cycle[2].dependencies.push(back);
        assert_eq!(
            validate_dependency_graph(&cycle),
            Err(TaskContractError::DependencyCycleDetected)
        );
    }

    #[test]
    fn p0_contract_dependency_longest_path_independent_of_node_order() {
        let mut nodes = chain(MAX_DEPENDENCY_DEPTH + 1);
        let direct = commitment(nodes.last().unwrap());
        nodes[0].dependencies.push(direct);
        nodes.reverse();
        assert_eq!(
            validate_dependency_graph(&nodes),
            Err(TaskContractError::DependencyDepthExceeded)
        );
        assert!(validate_dependency_graph(&[]).is_ok());
    }

    #[test]
    fn p0_contract_dependency_graph_missing_duplicate_and_stale_commitments_held() {
        let original = chain(1);
        assert_eq!(
            validate_dependency_graph(&original[..1]),
            Err(TaskContractError::DependencyTargetMissing)
        );
        assert_eq!(
            validate_dependency_graph(&[original[0].clone(), original[0].clone()]),
            Err(TaskContractError::DuplicateDependency)
        );
        for field in 0..2 {
            let mut nodes = original.clone();
            if field == 0 {
                nodes[1].task_ref.task_spec_digest = Sha256Digest([9; 32]);
            } else {
                nodes[1].completion_policy_digest = Sha256Digest([9; 32]);
            }
            assert_eq!(
                validate_dependency_graph(&nodes),
                Err(TaskContractError::DependencyUnsatisfied)
            );
        }
        let mut nodes = original;
        nodes[1].task_ref.source_generation += 1;
        assert_eq!(
            validate_dependency_graph(&nodes),
            Err(TaskContractError::AcceptanceInvalidated)
        );
    }

    #[test]
    fn p0_contract_dependency_graph_tasks_per_source_bound() {
        let mut nodes: Vec<_> = (0..MAX_TASKS_PER_SOURCE)
            .map(|i| node(&format!("N-{i}")))
            .collect();
        assert!(validate_dependency_graph(&nodes).is_ok());
        nodes.push(node("overflow"));
        assert_eq!(
            validate_dependency_graph(&nodes),
            Err(TaskContractError::LimitExceeded("tasks per source"))
        );
        nodes.last_mut().unwrap().task_ref.task_source_id =
            "00000000000000000000000000000002".into();
        assert!(validate_dependency_graph(&nodes).is_ok());
    }

    #[test]
    fn p0_contract_dependency_graph_edge_limit() {
        let mut nodes: Vec<_> = (0..320).map(|i| node(&format!("N-{i}"))).collect();
        let targets: Vec<_> = nodes[64..].iter().map(commitment).collect();
        for node in &mut nodes[..64] {
            node.dependencies = targets.clone();
        }
        assert_eq!(64 * targets.len(), MAX_DEPENDENCY_EDGES);
        assert!(validate_dependency_graph(&nodes).is_ok());
        let additional = commitment(&nodes[65]);
        nodes[64].dependencies.push(additional);
        assert_eq!(
            validate_dependency_graph(&nodes),
            Err(TaskContractError::LimitExceeded("dependency edges"))
        );
    }

    #[test]
    fn p0_contract_dependency_graph_source_bound_and_cross_source_target() {
        let mut nodes: Vec<_> = (0..MAX_TASK_SOURCES)
            .map(|i| {
                let mut target = node("same-id");
                target.task_ref.task_source_id = format!("{i:032x}");
                target
            })
            .collect();
        let required = commitment(&nodes[1]);
        nodes[0].dependencies.push(required);
        assert!(validate_dependency_graph(&nodes).is_ok());
        let mut additional = node("same-id");
        additional.task_ref.task_source_id = format!("{:032x}", MAX_TASK_SOURCES);
        nodes.push(additional);
        assert_eq!(
            validate_dependency_graph(&nodes),
            Err(TaskContractError::LimitExceeded("task sources"))
        );
    }
}
