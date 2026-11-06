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

fn writer_markdown_fixture() -> String {
    let metadata = serde_json::json!({
        "workspace_id": "fixture-workspace",
        "repo_id": "fixture-repository",
        "task_source_id": "00000000000000000000000000000001",
        "source_generation": 1,
        "file_cas_rev": 1,
        "last_operation_id": null,
    });
    let mut text = format!(
        "# Shared writer fixture\n\nUnrelated prose keeps  two spaces.  \n\n<!-- chinwag-task-source-meta-v1 {metadata} -->\n\n"
    );
    for id in ["A", "B"] {
        let entry = serde_json::json!({
            "task_id": id,
            "status": "todo",
            "task_status_rev": 0,
            "task_spec_digest": "11".repeat(32),
            "task_control_digest": "22".repeat(32),
            "completion_policy_digest": "33".repeat(32),
            "owner_actor": "RUST#00000000000000000000000000000011",
            "reviewer_role": "QA",
            "baseline_commit": "44".repeat(20),
            "candidate_commit": null,
            "overlay_digest": null,
            "execution_flags": [],
            "dependencies": [],
        });
        text.push_str(&format!(
            "<!-- chinwag-task-begin-v1 task_id=\"{id}\" -->\n- [ ] **{id}** (`todo`) — {id} summary\n<!-- chinwag-task-entry-v1 {entry} -->\n{id} body keeps  its spaces.\n<!-- chinwag-task-end-v1 task_id=\"{id}\" -->\n\n"
        ));
    }
    text.push_str("# Unrelated footer\nKeep this table: | a | b |\n");
    text
}

#[test]
fn p0_adversarial_writer_markdown_preserves_other_tasks_and_prose() {
    use chinwag_cli::task_writer::{CanonicalTaskDocumentV1, CanonicalTaskStatus};
    let original = writer_markdown_fixture();
    let mut document = CanonicalTaskDocumentV1::from_bytes(original.as_bytes())
        .expect("the admitted controlled Markdown profile");
    let begin = original
        .find("<!-- chinwag-task-begin-v1 task_id=\"B\" -->")
        .unwrap();
    let end_marker = "<!-- chinwag-task-end-v1 task_id=\"B\" -->";
    let end = original.find(end_marker).unwrap() + end_marker.len();
    let unrelated_block = &original[begin..end];
    document
        .tasks
        .iter_mut()
        .find(|task| task.task_id == "A")
        .unwrap()
        .status = CanonicalTaskStatus::InProgress;
    document.file_cas_rev = 2;
    document.last_operation_id = Some("000000000000000000000000000000ab".into());
    let rewritten = String::from_utf8(document.to_canonical_bytes().unwrap()).unwrap();
    assert!(
        rewritten
            .starts_with("# Shared writer fixture\n\nUnrelated prose keeps  two spaces.  \n\n")
    );
    assert!(rewritten.contains(unrelated_block));
    assert!(rewritten.contains("A body keeps  its spaces.\n"));
    assert!(rewritten.ends_with("# Unrelated footer\nKeep this table: | a | b |\n"));
    let reparsed = CanonicalTaskDocumentV1::from_bytes(rewritten.as_bytes()).unwrap();
    assert_eq!(reparsed.file_cas_rev, 2);
    assert_eq!(reparsed.tasks[0].status, CanonicalTaskStatus::InProgress);
    assert_eq!(reparsed.tasks[1].task_id, "B");
}

#[test]
fn p0_adversarial_writer_markdown_rejects_ambiguous_authority() {
    use chinwag_cli::task_writer::CanonicalTaskDocumentV1;
    let valid = writer_markdown_fixture();
    CanonicalTaskDocumentV1::from_bytes(valid.as_bytes()).expect("valid control fixture");
    let header = valid
        .lines()
        .find(|line| line.starts_with("<!-- chinwag-task-source-meta-v1 "))
        .unwrap();
    let malformed = [
        format!("{header}\n{valid}"),
        valid.replace(
            "\"file_cas_rev\":1",
            "\"file_cas_rev\":1,\"file_cas_rev\":1",
        ),
        valid.replace(
            "\"file_cas_rev\":1",
            "\"file_cas_rev\":1,\"sha256\":\"self-hash\"",
        ),
        valid.replacen("- [ ] **A**", "- [x] **A**", 1),
        valid.replacen(
            "chinwag-task-end-v1 task_id=\"A\"",
            "chinwag-task-end-v1 task_id=\"B\"",
            1,
        ),
        "{\"tasks\":[]}".into(),
    ];
    for text in malformed {
        assert!(CanonicalTaskDocumentV1::from_bytes(text.as_bytes()).is_err());
    }
}

#[test]
fn p0_adversarial_writer_rejects_unratified_task_statuses() {
    use chinwag_cli::task_writer::CanonicalTaskDocumentV1;
    let valid = writer_markdown_fixture();
    CanonicalTaskDocumentV1::from_bytes(valid.as_bytes()).expect("valid control fixture");
    for status in [
        "Open",
        "Claimed",
        "InReview",
        "Held",
        "Cancelled",
        "cancelled",
    ] {
        let text = valid
            .replace("\"status\":\"todo\"", &format!("\"status\":\"{status}\""))
            .replace("(`todo`)", &format!("(`{status}`)"));
        assert!(
            CanonicalTaskDocumentV1::from_bytes(text.as_bytes()).is_err(),
            "{status}"
        );
    }
}

#[test]
fn p0_adversarial_writer_completion_prose_never_becomes_acceptance() {
    use chinwag_cli::task_writer::{
        CanonicalTaskDocumentV1, CanonicalTaskStatus, TransitionAuthorization, authorize_transition,
    };
    let text = writer_markdown_fixture()
        .replace("\"status\":\"todo\"", "\"status\":\"done-pending-review\"")
        .replace("\"task_status_rev\":0", "\"task_status_rev\":1")
        .replace(
            "\"candidate_commit\":null",
            &format!("\"candidate_commit\":\"{}\"", "55".repeat(20)),
        )
        .replace("(`todo`)", "(`done-pending-review`)");
    let document = CanonicalTaskDocumentV1::from_bytes(text.as_bytes()).unwrap();
    let claimed =
        TransitionAuthorization::ProseClaim("COMPLETED; exit 0; all checks passed".into());
    assert!(
        authorize_transition(
            &document,
            &document.tasks[0],
            "TASKS.md",
            CanonicalTaskStatus::Done,
            &claimed,
            &[],
        )
        .is_err()
    );
}

struct WriterRegistryFixture {
    _temp: tempfile::TempDir,
    root: chinwag_cli::task_source_path::WorkspaceRootPin,
    policy: WorkspaceTaskPolicy,
    record: TaskSourceRecord,
    source_identity: chinwag_cli::task_source::SourceFilesystemIdentity,
    lease: chinwag_cli::task_writer::WriterLeaseV1,
    current: chinwag_cli::task_writer::WriterAuthoritySnapshot,
    request: chinwag_cli::task_writer::TaskWriteRequestV1,
}

impl WriterRegistryFixture {
    fn new(markdown: String) -> Self {
        use chinwag_cli::task_source::{SourceFilesystemIdentity, WorkspaceSourceRegistry};
        use chinwag_cli::task_source_path::WorkspaceRootPin;
        use chinwag_cli::task_wire::{
            HostClockState, PublishTaskV1, RatifiedPayloadProfile, SignerEnrollment,
            TASK_BUS_V2_ALPN, TaskMessageKind, TaskTranscriptV3, TaskVerificationContext,
        };
        use chinwag_cli::task_writer::{
            CanonicalTaskDocumentV1, CanonicalTaskStatus, ExecutionAdmissionV1, TaskWriteRequestV1,
            TransitionAuthorityV1, TransitionAuthorization, TransitionEvidenceV1,
            WriterAuthoritySnapshot, WriterLeaseV1,
        };
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let canonical = path.join("TASKS.md");
        std::fs::write(&canonical, &markdown).unwrap();
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir(path.join("journal")).unwrap();
        std::fs::set_permissions(path.join("journal"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let root_metadata = std::fs::metadata(&path).unwrap();
        let root = WorkspaceRootPin {
            path,
            dev: root_metadata.dev(),
            ino: root_metadata.ino(),
            uid: root_metadata.uid(),
            generation: 1,
        };
        let policy = policy("fixture-workspace");
        let mut proposed = source("fixture-workspace");
        proposed.controls = SourceDispatchControls {
            mode: SourceExecutionMode::Implementation,
            implementation_authorized: true,
            deployment_authorized: false,
            automatic_dispatch: false,
            allowed_actions: vec!["task-write".into()],
        };
        let mut enrolled = WorkspaceSourceRegistry::new(policy.clone(), root.clone()).unwrap();
        enrolled.enroll(proposed.clone()).unwrap();
        let record = enrolled.source(&proposed.task_source_id).unwrap().clone();
        let metadata = std::fs::metadata(&canonical).unwrap();
        let source_identity = SourceFilesystemIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        let document = CanonicalTaskDocumentV1::from_bytes(markdown.as_bytes()).unwrap();
        let reference = document.task_ref(&document.tasks[0], "TASKS.md");
        let control = document.tasks[0].task_control_digest;
        let executor = document.tasks[0].owner_actor.clone().unwrap();
        let operation = "000000000000000000000000000000ad";
        let sender = "WRITER#registry-fixture";
        let recipient = "WORKHORSE#registry-fixture";
        let evidence = TransitionEvidenceV1 {
            admission_id: Some("fixture-admission".into()),
            assignment_id: Some("fixture-assignment".into()),
            original_operation_id: Some(operation.into()),
            grant_id: Some("fixture-grant".into()),
            capacity_claim_id: Some("fixture-capacity".into()),
            write_scope_claim_id: Some("fixture-scope".into()),
            executor_actor: Some(executor.clone()),
            blocker: None,
            resolution: None,
        };
        let secret = iroh::SecretKey::from_bytes(&rand::random::<[u8; 32]>());
        let profiles = [RatifiedPayloadProfile {
            kind: TaskMessageKind::TaskProposal,
            name: "chinwag-writer-request-v1",
            validate_canonical_payload: |payload| payload.len() == 32,
        }];
        let actions = [TaskMessageKind::TaskProposal];
        let roster = [SignerEnrollment {
            workspace_id: policy.workspace_id.clone(),
            repo_id: policy.repo_id.clone(),
            seat: "WRITER".into(),
            authenticated_signer_principal: record.writer_principal.clone(),
            signer_pubkey: secret.public(),
            key_epoch: 1,
            config_digest: Sha256Digest(policy.config_digest),
            allowed_actions: actions.to_vec(),
            active: true,
        }];
        let authority_for = |digest: [u8; 32], message_id: &str, nonce: [u8; 32]| {
            let transcript = TaskTranscriptV3 {
                message_id: message_id.into(),
                issued_at_unix: 10,
                expires_at_unix: 20,
                nonce,
                sender_full_actor_address: sender.into(),
                parent_full_actor_address: None,
                recipient_full_actor_addresses: vec![recipient.into()],
                room: "#eng".into(),
                message_kind: TaskMessageKind::TaskProposal,
                receiver_authority_id: "fixture-registry-authority".into(),
                task_ref: reference.clone(),
                assignment_id: Some("fixture-assignment".into()),
                operation_id: Some(operation.into()),
                request_id: None,
                in_reply_to_message_id: None,
                config_digest: Sha256Digest(policy.config_digest),
                task_control_digest: control,
                body_utf8: serde_json::json!({
                    "payload_profile": "chinwag-writer-request-v1",
                    "canonical_payload_hex": Sha256Digest(digest).to_string(),
                    "payload_digest_sha256": Sha256Digest::of(&digest).to_string(),
                })
                .to_string(),
            };
            let signed = PublishTaskV1::sign(transcript, &secret, &profiles).unwrap();
            let verified = signed
                .verify(
                    TASK_BUS_V2_ALPN,
                    &roster,
                    &TaskVerificationContext {
                        receiver_authority_id: "fixture-registry-authority",
                        recipient_full_actor_address: recipient,
                        current_task_ref: &reference,
                        config_digest: Sha256Digest(policy.config_digest),
                        task_control_digest: control,
                        required_key_epoch: 1,
                        current_granted_actions: &actions,
                        ratified_profiles: &profiles,
                        host_clock: HostClockState::Verified { now_unix: 15 },
                    },
                )
                .unwrap();
            TransitionAuthorization::Standard(Box::new(
                TransitionAuthorityV1::from_verified(&verified)
                    .unwrap()
                    .with_evidence(evidence.clone()),
            ))
        };
        // Bootstrap only the public digest API; this distinct message/nonce never
        // enters the writer or a replay ledger. Only the final signed message does.
        let mut request = TaskWriteRequestV1 {
            operation_id: operation.into(),
            authenticated_signer_principal: record.writer_principal.clone(),
            request_message_id: "fixture-writer-proposal".into(),
            nonce: [9; 32],
            request_digest_sha256: [0; 32],
            admitted_task_ref: reference.clone(),
            expected_preimage_sha256: Sha256Digest::of(markdown.as_bytes()).0,
            admitted_document: document,
            next_status: CanonicalTaskStatus::InProgress,
            authorization: authority_for([0; 32], "fixture-digest-bootstrap", [8; 32]),
        };
        let digest = request.canonical_request_digest().unwrap();
        request.request_digest_sha256 = digest;
        request.authorization = authority_for(digest, "fixture-writer-proposal", [9; 32]);
        let lease = WriterLeaseV1 {
            workspace_id: policy.workspace_id.clone(),
            repo_id: policy.repo_id.clone(),
            source_worktree_id: record.source_worktree_id.clone(),
            task_source_id: record.task_source_id.clone(),
            canonical_relative_path: record.canonical_relative_path.clone(),
            source_generation: record.source_generation,
            writer_principal: record.writer_principal.clone(),
            writer_epoch: record.writer_epoch,
            config_revision: policy.config_revision,
            authority_epoch: policy.authority_epoch,
            config_digest: policy.config_digest,
            issued_at_unix: 10,
            expires_at_unix: 20,
        };
        let current = WriterAuthoritySnapshot {
            policy: policy.clone(),
            record: record.clone(),
            writer_principal: record.writer_principal.clone(),
            writer_epoch: record.writer_epoch,
            clock: HostClockState::Verified { now_unix: 15 },
            reviewer_role_grants: vec![],
            execution_admissions: vec![ExecutionAdmissionV1 {
                actor: sender.into(),
                authenticated_signer_principal: record.writer_principal.clone(),
                executor_actor: executor,
                task_ref: reference,
                task_control_digest: control,
                admission_id: "fixture-admission".into(),
                assignment_id: "fixture-assignment".into(),
                original_operation_id: operation.into(),
                action: "task-write".into(),
                grant_id: "fixture-grant".into(),
                capacity_claim_id: "fixture-capacity".into(),
                write_scope_claim_id: "fixture-scope".into(),
            }],
        };
        Self {
            _temp: temp,
            root,
            policy,
            record,
            source_identity,
            lease,
            current,
            request,
        }
    }

    fn registry(
        &self,
        policy: WorkspaceTaskPolicy,
    ) -> chinwag_cli::task_source::WorkspaceSourceRegistry {
        let mut registry =
            chinwag_cli::task_source::WorkspaceSourceRegistry::new(policy, self.root.clone())
                .unwrap();
        let mut proposed = self.record.clone();
        proposed.state = TaskSourceState::Proposed;
        registry.enroll(proposed).unwrap();
        registry
    }

    fn journal(&self) -> chinwag_cli::task_write_journal::Journal {
        chinwag_cli::task_write_journal::Journal::open(
            &std::fs::File::open(self.root.path.join("journal")).unwrap(),
            chinwag_cli::task_write_journal::AUTHORITATIVE_JOURNAL_FILE_NAME,
            self.root.uid,
        )
        .unwrap()
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.root.path.join("TASKS.md")).unwrap()
    }

    fn commit(
        &self,
        journal: &mut chinwag_cli::task_write_journal::Journal,
        current: &chinwag_cli::task_writer::WriterAuthoritySnapshot,
        projections: &std::cell::Cell<usize>,
    ) -> Result<chinwag_cli::task_writer::WriterWriteOutcome, chinwag_cli::task_writer::WriterError>
    {
        chinwag_cli::task_writer::commit_task_write(
            &chinwag_cli::task_writer::WriterContextV1 {
                root: &self.root,
                lease: &self.lease,
                source_identity: self.source_identity,
            },
            journal,
            &self.request,
            &[],
            || Ok(current.clone()),
            |_, _, _| Ok(()),
            |_| {
                projections.set(projections.get() + 1);
                Ok(())
            },
        )
    }
}

#[test]
fn p0_adversarial_writer_commit_requires_exact_registry_adoption() {
    use chinwag_cli::task_source::HeldReason;
    use chinwag_cli::task_source_path::SourcePathHoldReason;
    use chinwag_cli::task_writer::{
        CanonicalTaskDocumentV1, CanonicalTaskStatus, WriterWriteOutcome,
    };

    let fixture = WriterRegistryFixture::new(writer_markdown_fixture());
    let mut registry = fixture.registry(fixture.policy.clone());
    let mut other_policy = fixture.policy.clone();
    other_policy.authority_epoch += 1;
    let mut wrong_policy_registry = fixture.registry(other_policy);
    registry
        .check_dispatch_admission(&fixture.record.task_source_id, "task-write")
        .unwrap();
    let mut journal = fixture.journal();
    let projections = std::cell::Cell::new(0);
    let proof = match fixture
        .commit(&mut journal, &fixture.current, &projections)
        .unwrap()
    {
        WriterWriteOutcome::Committed(proof) => proof,
        other => panic!("expected original commit, got {other:?}"),
    };
    let committed = fixture.bytes();
    let document = CanonicalTaskDocumentV1::from_bytes(&committed).unwrap();
    assert_eq!(document.tasks[0].status, CanonicalTaskStatus::InProgress);
    assert_eq!(document.file_cas_rev, 2);
    assert_ne!(proof.previous_identity(), proof.committed_identity());
    let drift = HeldReason::SourcePath(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
    assert_eq!(
        registry.check_dispatch_admission(&fixture.record.task_source_id, "task-write"),
        Err(drift),
    );
    assert!(wrong_policy_registry.adopt_writer_commit(&proof).is_err());
    let mut altered = committed.clone();
    altered.extend_from_slice(b"\nUnadmitted postimage prose.\n");
    std::fs::write(fixture.root.path.join("TASKS.md"), &altered).unwrap();
    assert_eq!(registry.adopt_writer_commit(&proof), Err(drift));
    assert_eq!(fixture.bytes(), altered);
    std::fs::write(fixture.root.path.join("TASKS.md"), &committed).unwrap();
    registry.adopt_writer_commit(&proof).unwrap();
    registry
        .check_dispatch_admission(&fixture.record.task_source_id, "task-write")
        .unwrap();
    assert_eq!(fixture.bytes(), committed);
    assert_eq!(projections.get(), 1);
}

#[test]
fn p0_adversarial_writer_parseable_external_revision_never_supplies_commit_authority() {
    use chinwag_cli::task_write_journal::WriteOperationState;
    use chinwag_cli::task_writer::{CanonicalTaskDocumentV1, WriterError};
    use std::os::unix::fs::MetadataExt;

    let fixture = WriterRegistryFixture::new(writer_markdown_fixture());
    let before_inode = std::fs::metadata(fixture.root.path.join("TASKS.md"))
        .unwrap()
        .ino();
    let mut external = fixture.request.admitted_document.clone();
    external.file_cas_rev += 1;
    external.last_operation_id = Some("000000000000000000000000000000ae".into());
    external.tasks[1].task_status_rev += 1;
    let external_bytes = external.to_canonical_bytes().unwrap();
    CanonicalTaskDocumentV1::from_bytes(&external_bytes).unwrap();
    std::fs::write(fixture.root.path.join("TASKS.md"), &external_bytes).unwrap();
    let mut journal = fixture.journal();
    let projections = std::cell::Cell::new(0);
    assert!(matches!(
        fixture.commit(&mut journal, &fixture.current, &projections),
        Err(WriterError::SourceHeld),
    ));
    assert_eq!(fixture.bytes(), external_bytes);
    assert_eq!(
        std::fs::metadata(fixture.root.path.join("TASKS.md"))
            .unwrap()
            .ino(),
        before_inode
    );
    assert_eq!(projections.get(), 0);
    let held = journal
        .latest(
            &fixture.record.workspace_id,
            &fixture.record.task_source_id,
            &fixture.request.operation_id,
        )
        .unwrap();
    assert_eq!(held.state, WriteOperationState::Held);
    assert_eq!(
        held.request.signed_task_ref,
        fixture.request.admitted_task_ref.encode().unwrap()
    );
}

#[test]
fn p0_adversarial_writer_source_byte_limit_uses_valid_prose_and_precedes_replacement() {
    use chinwag_cli::task_source_path::MAX_SOURCE_FILE_BYTES;
    use chinwag_cli::task_writer::{
        CanonicalTaskDocumentV1, CanonicalTaskStatus, WriterError, WriterWriteOutcome,
    };
    use std::os::unix::fs::MetadataExt;

    let base = writer_markdown_fixture();
    let mut expected = CanonicalTaskDocumentV1::from_bytes(base.as_bytes()).unwrap();
    expected.file_cas_rev += 1;
    expected.last_operation_id = Some("000000000000000000000000000000ad".into());
    expected.tasks[0].status = CanonicalTaskStatus::InProgress;
    expected.tasks[0].task_status_rev += 1;
    let growth = expected.to_canonical_bytes().unwrap().len() - base.len();
    for overflow in [false, true] {
        let target = MAX_SOURCE_FILE_BYTES as usize + (if overflow { 1 } else { 0 });
        let padding = target - growth - base.len();
        let markdown = format!("{base}{}\n", "x".repeat(padding - 1));
        CanonicalTaskDocumentV1::from_bytes(markdown.as_bytes()).unwrap();
        let fixture = WriterRegistryFixture::new(markdown);
        let before = fixture.bytes();
        let before_inode = std::fs::metadata(fixture.root.path.join("TASKS.md"))
            .unwrap()
            .ino();
        let mut journal = fixture.journal();
        let projections = std::cell::Cell::new(0);
        let result = fixture.commit(&mut journal, &fixture.current, &projections);
        if overflow {
            assert!(matches!(result, Err(WriterError::FileTooLarge)));
            assert_eq!(fixture.bytes(), before);
            assert_eq!(
                std::fs::metadata(fixture.root.path.join("TASKS.md"))
                    .unwrap()
                    .ino(),
                before_inode
            );
            assert_eq!(projections.get(), 0);
            assert!(journal.records().all(|record| record.prepared.is_none()));
        } else {
            assert!(matches!(result, Ok(WriterWriteOutcome::Committed(_))));
            let committed = fixture.bytes();
            assert_eq!(committed.len(), MAX_SOURCE_FILE_BYTES as usize);
            CanonicalTaskDocumentV1::from_bytes(&committed).unwrap();
            assert_eq!(projections.get(), 1);
        }
    }
}

#[test]
fn p0_adversarial_writer_review_only_current_claims_cannot_authorize_implementation() {
    use chinwag_cli::task_writer::WriterError;
    use std::os::unix::fs::MetadataExt;

    let fixture = WriterRegistryFixture::new(writer_markdown_fixture());
    let mut review_only = fixture.current.clone();
    review_only.record.controls.mode = SourceExecutionMode::ReviewOnly;
    review_only.record.controls.implementation_authorized = false;
    review_only.record.validate(&review_only.policy).unwrap();
    assert_eq!(review_only.execution_admissions.len(), 1);
    let before = fixture.bytes();
    let before_inode = std::fs::metadata(fixture.root.path.join("TASKS.md"))
        .unwrap()
        .ino();
    let mut journal = fixture.journal();
    let projections = std::cell::Cell::new(0);
    assert!(matches!(
        fixture.commit(&mut journal, &review_only, &projections),
        Err(WriterError::AuthorityMismatch),
    ));
    assert_eq!(fixture.bytes(), before);
    assert_eq!(
        std::fs::metadata(fixture.root.path.join("TASKS.md"))
            .unwrap()
            .ino(),
        before_inode
    );
    assert_eq!(projections.get(), 0);
    assert!(journal.records().all(|record| record.prepared.is_none()));
}

#[test]
fn p0_adversarial_writer_nonprivate_target_mode_never_produces_a_commit() {
    use chinwag_cli::task_writer::WriterWriteOutcome;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = WriterRegistryFixture::new(writer_markdown_fixture());
    let path = fixture.root.path.join("TASKS.md");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let before = fixture.bytes();
    let before_metadata = std::fs::metadata(&path).unwrap();
    let mut journal = fixture.journal();
    let projections = std::cell::Cell::new(0);
    let result = fixture.commit(&mut journal, &fixture.current, &projections);
    assert!(
        !matches!(
            result,
            Ok(WriterWriteOutcome::Committed(_) | WriterWriteOutcome::DuplicateRecorded(_))
        ),
        "0644 target must not produce a commit: {result:?}",
    );
    assert_eq!(fixture.bytes(), before);
    let after_metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(after_metadata.ino(), before_metadata.ino());
    assert_eq!(after_metadata.permissions().mode() & 0o777, 0o644);
    assert_eq!(projections.get(), 0);
    assert!(journal.records().all(|record| record.prepared.is_none()));
}

#[test]
fn p0_adversarial_writer_received_and_validated_reopen_without_source_effects() {
    use chinwag_cli::task_write_journal::{
        JournalRequestV1, ReplayDispositionV1, WriteOperationState,
    };
    use chinwag_cli::task_writer::{
        WriterContextV1, WriterWriteOutcome, reject_unprepared_operation,
    };
    use std::os::unix::fs::MetadataExt;

    for phase in [
        WriteOperationState::Received,
        WriteOperationState::Validated,
    ] {
        let fixture = WriterRegistryFixture::new(writer_markdown_fixture());
        let canonical = fixture.root.path.join("TASKS.md");
        let before = fixture.bytes();
        let before_metadata = std::fs::metadata(&canonical).unwrap();
        let workspace = &fixture.record.workspace_id;
        let source = &fixture.record.task_source_id;
        let operation = &fixture.request.operation_id;
        let original_request = JournalRequestV1 {
            workspace_id: workspace.clone(),
            task_source_id: source.clone(),
            operation_id: operation.clone(),
            signer_principal: fixture.request.authenticated_signer_principal.clone(),
            request_id: fixture.request.request_message_id.clone(),
            request_digest: fixture.request.request_digest_sha256,
            nonce: fixture.request.nonce,
            writer_epoch: fixture.lease.writer_epoch,
            signed_task_ref: fixture.request.admitted_task_ref.encode().unwrap(),
            metadata: serde_json::to_value(&fixture.lease).unwrap(),
        };
        let mut journal = fixture.journal();
        let mut snapshot = match journal.reserve(original_request.clone()).unwrap() {
            ReplayDispositionV1::Fresh(record) => record,
            other => panic!("expected first reservation, got {other:?}"),
        };
        if phase == WriteOperationState::Validated {
            snapshot.state = WriteOperationState::Validated;
            journal.append(snapshot.clone()).unwrap();
        }
        assert_eq!(snapshot.state, phase);
        assert!(snapshot.prepared.is_none());
        drop(journal);

        let mut reopened = fixture.journal();
        assert_eq!(
            reopened.latest(workspace, source, operation),
            Some(&snapshot)
        );
        let context = WriterContextV1 {
            root: &fixture.root,
            lease: &fixture.lease,
            source_identity: fixture.source_identity,
        };
        reject_unprepared_operation(&context, &mut reopened, operation, &fixture.current).unwrap();
        let rejected = reopened
            .latest(workspace, source, operation)
            .unwrap()
            .clone();
        assert_eq!(rejected.state, WriteOperationState::Rejected);
        assert_eq!(rejected.request, original_request);
        assert!(rejected.prepared.is_none());
        drop(reopened);

        let mut rejected_reopen = fixture.journal();
        let projections = std::cell::Cell::new(0);
        assert_eq!(
            fixture
                .commit(&mut rejected_reopen, &fixture.current, &projections)
                .unwrap(),
            WriterWriteOutcome::Rejected,
        );
        assert_eq!(
            rejected_reopen.latest(workspace, source, operation),
            Some(&rejected),
        );
        assert_eq!(fixture.bytes(), before);
        let after_metadata = std::fs::metadata(&canonical).unwrap();
        assert_eq!(after_metadata.dev(), before_metadata.dev());
        assert_eq!(after_metadata.ino(), before_metadata.ino());
        assert_eq!(projections.get(), 0);
        assert!(rejected_reopen.records().all(|record| {
            matches!(
                record.state,
                WriteOperationState::Received
                    | WriteOperationState::Validated
                    | WriteOperationState::Rejected
            ) && record.prepared.is_none()
        }));
    }
}

#[test]
fn p0_adversarial_writer_recorded_before_ack_replays_original_without_effects() {
    use chinwag_cli::task_write_journal::{
        AUTHORITATIVE_JOURNAL_FILE_NAME, PreparedRecoveryDisposition, WriteOperationState,
        classify_and_recover_prepared_operation,
    };
    use chinwag_cli::task_writer::{
        WriterContextV1, WriterError, WriterStep, WriterWriteOutcome, commit_task_write,
    };
    use std::os::unix::fs::MetadataExt;

    let fixture = WriterRegistryFixture::new(writer_markdown_fixture());
    let canonical = fixture.root.path.join("TASKS.md");
    let before_metadata = std::fs::metadata(&canonical).unwrap();
    let context = WriterContextV1 {
        root: &fixture.root,
        lease: &fixture.lease,
        source_identity: fixture.source_identity,
    };
    let mut journal = fixture.journal();
    let replacements = std::cell::Cell::new(0);
    let interrupted = commit_task_write(
        &context,
        &mut journal,
        &fixture.request,
        &[],
        || Ok(fixture.current.clone()),
        |step, _, _| {
            if step == WriterStep::AfterRename {
                replacements.set(replacements.get() + 1);
                Err(WriterError::InjectedCrash)
            } else {
                Ok(())
            }
        },
        |_| panic!("projection must follow the injected AfterRename interruption"),
    );
    assert!(matches!(interrupted, Err(WriterError::InjectedCrash)));
    let successor = fixture.bytes();
    let successor_metadata = std::fs::metadata(&canonical).unwrap();
    assert_ne!(successor_metadata.ino(), before_metadata.ino());
    assert_eq!(replacements.get(), 1);
    let workspace = &fixture.record.workspace_id;
    let source = &fixture.record.task_source_id;
    let operation = &fixture.request.operation_id;
    let original = journal
        .latest(workspace, source, operation)
        .unwrap()
        .clone();
    assert_eq!(original.state, WriteOperationState::Prepared);
    let parent = std::fs::File::open(&fixture.root.path).unwrap();
    let projections = std::cell::Cell::new(0);
    let recovered = classify_and_recover_prepared_operation(
        &mut journal,
        &parent,
        workspace,
        source,
        operation,
        |record| {
            assert_eq!(record.request, original.request);
            assert_eq!(record.prepared, original.prepared);
            fixture.lease.verify(&fixture.current).unwrap();
            Ok(())
        },
        |record| {
            assert_eq!(record.request, original.request);
            assert_eq!(record.prepared, original.prepared);
            projections.set(projections.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    let recorded = match recovered {
        PreparedRecoveryDisposition::Recorded(record) => record,
        other => panic!("expected Recorded without ACK, got {other:?}"),
    };
    assert_eq!(recorded.state, WriteOperationState::Recorded);
    assert_eq!(recorded.request, original.request);
    assert_eq!(recorded.prepared, original.prepared);
    assert!(
        journal
            .records()
            .all(|record| record.state != WriteOperationState::Acknowledged)
    );
    let journal_directory = fixture.root.path.join("journal");
    let journal_path = journal_directory.join(AUTHORITATIVE_JOURNAL_FILE_NAME);
    let recorded_bytes = std::fs::read(&journal_path).unwrap();
    drop(journal);

    let mut reopened = fixture.journal();
    assert_eq!(
        reopened.latest(workspace, source, operation),
        Some(&recorded)
    );
    let replay = commit_task_write(
        &context,
        &mut reopened,
        &fixture.request,
        &[],
        || panic!("Recorded replay must not refresh authority"),
        |_, _, _| panic!("Recorded replay must not stage or replace again"),
        |_| panic!("Recorded replay must not project again"),
    )
    .unwrap();
    let proof = match replay {
        WriterWriteOutcome::DuplicateRecorded(proof) => proof,
        other => panic!("expected original duplicate result, got {other:?}"),
    };
    assert_eq!(proof.operation_id(), operation.as_str());
    assert_eq!(
        proof.expected_preimage_sha256(),
        &fixture.request.expected_preimage_sha256,
    );
    assert_eq!(
        proof.committed_postimage_sha256(),
        &Sha256Digest::of(&successor).0
    );
    assert_eq!(
        reopened.latest(workspace, source, operation),
        Some(&recorded)
    );
    assert_eq!(std::fs::read(&journal_path).unwrap(), recorded_bytes);
    assert_eq!(fixture.bytes(), successor);
    let replay_metadata = std::fs::metadata(&canonical).unwrap();
    assert_eq!(replay_metadata.dev(), successor_metadata.dev());
    assert_eq!(replay_metadata.ino(), successor_metadata.ino());
    assert_eq!(replacements.get(), 1);
    assert_eq!(projections.get(), 1);
}

#[test]
fn p0_adversarial_writer_stage_collision_preserves_evidence_and_original_rejection() {
    use chinwag_cli::task_write_journal::WriteOperationState;
    use chinwag_cli::task_writer::{
        WriterContextV1, WriterError, WriterWriteOutcome, reject_unprepared_operation,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = WriterRegistryFixture::new(writer_markdown_fixture());
    let canonical = fixture.root.path.join("TASKS.md");
    let before = fixture.bytes();
    let before_metadata = std::fs::metadata(&canonical).unwrap();
    let collision_name = format!(".chinwag-tmp-{}", fixture.request.operation_id);
    let collision = fixture.root.path.join(collision_name);
    let evidence = b"preexisting deterministic stage collision evidence";
    std::fs::write(&collision, evidence).unwrap();
    std::fs::set_permissions(&collision, std::fs::Permissions::from_mode(0o600)).unwrap();
    let collision_metadata = std::fs::metadata(&collision).unwrap();
    let mut journal = fixture.journal();
    let projections = std::cell::Cell::new(0);
    let result = fixture.commit(&mut journal, &fixture.current, &projections);
    assert!(matches!(
        result,
        Err(WriterError::Io(ref error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    let workspace = &fixture.record.workspace_id;
    let source = &fixture.record.task_source_id;
    let operation = &fixture.request.operation_id;
    let validated = journal
        .latest(workspace, source, operation)
        .unwrap()
        .clone();
    assert_eq!(validated.state, WriteOperationState::Validated);
    assert!(validated.prepared.is_none());
    assert_eq!(
        validated.request.signed_task_ref,
        fixture.request.admitted_task_ref.encode().unwrap(),
    );
    drop(journal);

    let mut reopened = fixture.journal();
    assert_eq!(
        reopened.latest(workspace, source, operation),
        Some(&validated)
    );
    let context = WriterContextV1 {
        root: &fixture.root,
        lease: &fixture.lease,
        source_identity: fixture.source_identity,
    };
    reject_unprepared_operation(&context, &mut reopened, operation, &fixture.current).unwrap();
    let rejected = reopened
        .latest(workspace, source, operation)
        .unwrap()
        .clone();
    assert_eq!(rejected.state, WriteOperationState::Rejected);
    assert_eq!(rejected.request, validated.request);
    assert_eq!(
        fixture
            .commit(&mut reopened, &fixture.current, &projections)
            .unwrap(),
        WriterWriteOutcome::Rejected,
    );
    assert_eq!(
        reopened.latest(workspace, source, operation),
        Some(&rejected)
    );
    assert_eq!(fixture.bytes(), before);
    let after_metadata = std::fs::metadata(&canonical).unwrap();
    assert_eq!(after_metadata.dev(), before_metadata.dev());
    assert_eq!(after_metadata.ino(), before_metadata.ino());
    assert_eq!(std::fs::read(&collision).unwrap(), evidence);
    let after_collision = std::fs::metadata(&collision).unwrap();
    assert_eq!(after_collision.dev(), collision_metadata.dev());
    assert_eq!(after_collision.ino(), collision_metadata.ino());
    assert_eq!(projections.get(), 0);
    assert!(reopened.records().all(|record| record.prepared.is_none()));
}
