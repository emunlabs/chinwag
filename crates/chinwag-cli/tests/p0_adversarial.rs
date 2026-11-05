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
    original
        .validate(&policy)
        .expect("supported source profile");
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

fn signed_legacy_fixture(
    task_id: &str,
) -> (
    chinwag_cli::task_legacy::LegacyBusRecord,
    chinwag_cli::task_legacy::LegacySignerBinding,
) {
    use chinwag_cli::task_legacy::{
        LegacyBusRecord, LegacySignerBinding, canonical_signing_payload,
    };
    let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
    let mut record = LegacyBusRecord {
        id: "fixture-legacy-message".into(),
        seq: 1,
        ts_unix: 17,
        ts_iso: "display-only".into(),
        room: "#eng".into(),
        sender: "RUST#historical-case".into(),
        sender_cast: "display-only".into(),
        sender_endpoint_id: "display-only".into(),
        to: Some("WORKHORSE#historical-recipient".into()),
        task_id: Some(task_id.into()),
        body: "COMPLETED is historical prose, not acceptance".into(),
        digest_sha256: "untrusted transported metadata".into(),
        pubkey_ed25519: Some(secret.public().to_string()),
        signature_ed25519: None,
        sig_verified: false,
    };
    let signature = secret.sign(canonical_signing_payload(&record).as_bytes());
    record.signature_ed25519 = Some(
        signature
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let signer = LegacySignerBinding {
        sender: record.sender.clone(),
        public_key: secret.public(),
    };
    (record, signer)
}

#[test]
fn p0_adversarial_signed_opaque_legacy_ids_keep_history_without_task_authority() {
    use chinwag_cli::task_legacy::{
        LegacyError, LegacyQualification, admit_legacy_for_canonical_status_commit,
        admit_legacy_for_document_coordination, admit_legacy_for_historical_read,
        admit_legacy_for_task_dispatch, admit_legacy_for_task_lease, admit_legacy_mutation,
        verify_legacy_record,
    };
    for task_id in ["TASKS.md/Task-1", r"Task-1\substep"] {
        let (record, signer) = signed_legacy_fixture(task_id);
        let verified = verify_legacy_record(&record, &signer).expect("original signed opaque ID");
        assert_eq!(
            verified.qualification(),
            LegacyQualification::LegacyUnqualified
        );
        assert_eq!(
            admit_legacy_for_historical_read(&verified, true)
                .unwrap()
                .task_id
                .as_deref(),
            Some(task_id)
        );
        assert!(admit_legacy_for_document_coordination(&verified, true).is_ok());
        assert_eq!(
            admit_legacy_for_historical_read(&verified, false),
            Err(LegacyError::PermissionDenied)
        );
        assert!(admit_legacy_for_task_dispatch(&verified).is_err());
        assert!(admit_legacy_for_task_lease(&verified).is_err());
        assert!(admit_legacy_for_canonical_status_commit(&verified).is_err());
        assert!(admit_legacy_mutation(&verified).is_err());
    }
    let (mut record, signer) = signed_legacy_fixture("Task-1");
    record.task_id = Some("TASKS.md/Task-1".into());
    assert_eq!(
        verify_legacy_record(&record, &signer),
        Err(LegacyError::InvalidSignature)
    );
}

#[test]
fn p0_adversarial_explicit_source_selection_keeps_opaque_task_id_bytes() {
    use chinwag_cli::task_legacy::{LegacyError, resolve_interactive_task_selector};
    let mut enrolled = source("fixture-workspace");
    enrolled.state = TaskSourceState::Enrolled;
    for task_id in ["Task/substep", r"Task\substep", "Task-É"] {
        let selected = resolve_interactive_task_selector(
            std::slice::from_ref(&enrolled),
            Some(&enrolled.task_source_id),
            None,
            task_id,
        )
        .expect("explicit enrolled source plus opaque ID");
        assert_eq!(
            selected,
            TaskKey::new(&enrolled.workspace_id, &enrolled.task_source_id, task_id).unwrap()
        );
        assert_eq!(selected.task_id.as_bytes(), task_id.as_bytes());
    }
    let mut second = enrolled.clone();
    second.task_source_id = "00000000000000000000000000000002".into();
    second.canonical_relative_path = "second/TASKS.md".into();
    assert_eq!(
        resolve_interactive_task_selector(&[enrolled, second], None, None, "unique-now"),
        Err(LegacyError::ExplicitSourceSelectionRequired),
    );
}

#[test]
fn p0_adversarial_legacy_history_cannot_cross_new_wire_or_gain_adjacent_authority() {
    use chinwag_cli::task_legacy::{LegacyError, decode_legacy_record_json};
    use chinwag_cli::task_wire::{
        LEGACY_BUS_V1_ALPN, PublishTaskV1, TASK_BUS_V2_ALPN, TaskWireError,
    };
    let (record, _) = signed_legacy_fixture("Task-1");
    let bytes = serde_json::to_vec(&record).unwrap();
    assert_eq!(
        PublishTaskV1::decode_json(&bytes, LEGACY_BUS_V1_ALPN, &[]),
        Err(TaskWireError::ProtocolDowngradeForbidden),
    );
    assert!(PublishTaskV1::decode_json(&bytes, TASK_BUS_V2_ALPN, &[]).is_err());
    let mut adjacent = serde_json::to_value(&record).unwrap();
    adjacent["task_ref"] = serde_json::json!({"task_source_id": "forged-source"});
    assert_eq!(
        decode_legacy_record_json(&serde_json::to_vec(&adjacent).unwrap()),
        Err(LegacyError::MalformedLegacyRecord),
    );
}

#[test]
fn p0_adversarial_escaped_duplicate_profile_rejected_before_profile_admission() {
    use chinwag_cli::task_wire::{TaskActionableBodyV1, TaskMessageKind, TaskWireError};
    assert_eq!(
        TaskActionableBodyV1::parse(
            r#"{"payload_profile":"a","\u0070ayload_profile":"b"}"#,
            TaskMessageKind::Assignment,
            &[],
        ),
        Err(TaskWireError::DuplicateJsonKey),
    );
}
