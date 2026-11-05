#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

//! Cross-module rejection cases for the controlled Phase 0 profile.
//! These are authored expectations, not execution or acceptance evidence.

use chinwag_cli::task_dependency::{
    DependencyCommitment, DependencyNode, validate_dependency_graph,
};
use chinwag_cli::task_ref::{GitOid, Sha256Digest, TaskKey, TaskRefV1};
use chinwag_cli::task_source::{
    SourceDispatchControls, SourceExecutionMode, TaskSourceRecord, TaskSourceState,
    WorkspaceTaskPolicy,
};
use chinwag_cli::task_source_path::validate_enrolled_relative_path;

fn policy(workspace: &str) -> WorkspaceTaskPolicy {
    WorkspaceTaskPolicy {
        workspace_id: workspace.into(),
        repo_id: "fixture-repository".into(),
        config_revision: 1,
        authority_epoch: 1,
        scheduler_owner: "fixture-scheduler".into(),
        max_sources: 16,
        config_digest: [7; 32],
    }
}

fn source(workspace: &str) -> TaskSourceRecord {
    TaskSourceRecord {
        workspace_id: workspace.into(),
        repo_id: "fixture-repository".into(),
        source_worktree_id: "fixture-worktree".into(),
        task_source_id: "00000000000000000000000000000001".into(),
        display_name: "Fixture source".into(),
        canonical_relative_path: "TASKS.md".into(),
        source_generation: 1,
        normalization_version: 1,
        schema_version: 1,
        writer_principal: "fixture-writer".into(),
        writer_epoch: 1,
        config_digest: [7; 32],
        state: TaskSourceState::Proposed,
        controls: SourceDispatchControls {
            mode: SourceExecutionMode::ReviewOnly,
            implementation_authorized: false,
            deployment_authorized: false,
            automatic_dispatch: false,
            allowed_actions: vec!["document-review".into()],
        },
    }
}

fn node(task: &str, source_id: &str) -> DependencyNode {
    DependencyNode {
        task_ref: TaskRefV1 {
            workspace_id: "fixture-workspace".into(),
            repo_id: "fixture-repository".into(),
            task_source_id: source_id.into(),
            source_generation: 1,
            canonical_task_path: format!("tasks/{source_id}.md"),
            task_id: task.into(),
            task_spec_digest: Sha256Digest([1; 32]),
            task_status_rev: 0,
            file_cas_rev: 0,
            baseline_commit: GitOid::Sha1([2; 20]),
        },
        completion_policy_digest: Sha256Digest([3; 32]),
        dependencies: vec![],
    }
}

fn graph_to(mut target: DependencyNode) -> Vec<DependencyNode> {
    let mut dependent = node("A", "00000000000000000000000000000001");
    dependent.dependencies.push(DependencyCommitment {
        target_key: target.task_ref.task_key(),
        target_spec_digest: target.task_ref.task_spec_digest,
        completion_policy_digest: target.completion_policy_digest,
    });
    target.dependencies.clear();
    vec![dependent, target]
}

#[test]
fn p0_adversarial_source_parser_versions_fail_closed() {
    let policy = policy("fixture-workspace");
    let original = source("fixture-workspace");
    original.validate(&policy).expect("supported source profile");
    for version in [0, u32::MAX] {
        let mut schema = original.clone();
        schema.schema_version = version;
        assert!(schema.validate(&policy).is_err(), "schema {version}");
        let mut normalization = original.clone();
        normalization.normalization_version = version;
        assert!(
            normalization.validate(&policy).is_err(),
            "normalization {version}"
        );
    }
}

#[test]
fn p0_adversarial_dependency_cross_workspace_is_held() {
    let mut target = node("B", "00000000000000000000000000000002");
    target.task_ref.workspace_id = "another-workspace".into();
    assert!(validate_dependency_graph(&graph_to(target)).is_err());
}

#[test]
fn p0_adversarial_dependency_cross_repository_without_policy_is_held() {
    let mut target = node("B", "00000000000000000000000000000002");
    target.task_ref.repo_id = "another-repository".into();
    assert!(validate_dependency_graph(&graph_to(target)).is_err());
}

#[test]
fn p0_adversarial_dependency_same_domain_cross_source_remains_valid() {
    let target = node("B", "00000000000000000000000000000002");
    validate_dependency_graph(&graph_to(target)).expect("same enrolled domain");
}

#[test]
fn p0_adversarial_opaque_workspace_ids_require_exact_policy_binding() {
    for workspace in ["workspace.v1", "urn:workspace:fixture"] {
        let policy = policy(workspace);
        let record = source(workspace);
        record.validate(&policy).expect("opaque enrolled identity");
        let key = TaskKey::new(workspace, &record.task_source_id, "A")
            .expect("the representation does not mint enrollment authority");
        assert_eq!(TaskKey::decode(&key.encode()).unwrap(), key);
        let mut wrong_policy = policy.clone();
        wrong_policy.workspace_id = "different-enrolled-identity".into();
        assert!(record.validate(&wrong_policy).is_err());
    }
}

#[test]
fn p0_adversarial_task_ref_preserves_enrolled_path_bytes_and_descent_bound() {
    let maximum_descent = ["a"; 64].join("/");
    for path in [
        " Tasks/task.md ",
        "Tasks/task:v1.md",
        maximum_descent.as_str(),
    ] {
        validate_enrolled_relative_path(path).expect("enrolled path spelling");
        let mut reference = node("A", "00000000000000000000000000000001").task_ref;
        reference.canonical_task_path = path.into();
        let encoded = reference.encode().expect("same path profile in TaskRef");
        let decoded = TaskRefV1::decode(&encoded).expect("canonical TaskRef");
        assert_eq!(decoded.canonical_task_path.as_bytes(), path.as_bytes());
    }
    let too_deep = ["a"; 65].join("/");
    assert!(validate_enrolled_relative_path(&too_deep).is_err());
    let mut reference = node("A", "00000000000000000000000000000001").task_ref;
    reference.canonical_task_path = too_deep;
    assert!(reference.encode().is_err());
}
