//! Controlled native fixtures: no live database, provider or worker is used.

use crate::{
    task_dependency::{DependencyCommitment, DependencyNode},
    task_legacy::{
        LegacyBusRecord, LegacyMigrationPin, LegacySignerBinding, canonical_signing_payload,
        verify_legacy_record,
    },
    task_normalization::{ExecutionMode, NormalizedTaskSpecV1, RawSpecValue, TaskControlV1},
    task_projection::*,
    task_ref::{GitOid, Sha256Digest, TaskKey, TaskRefV1},
    task_source::{
        SourceDispatchControls, SourceExecutionMode, TaskSourceRecord, TaskSourceState,
        WorkspaceSourceRegistry, WorkspaceTaskPolicy,
    },
    task_source_path::WorkspaceRootPin,
    task_store::*,
    task_wire::{
        HostClockState, MAX_TASK_WIRE_FRAME_BYTES, PublishTaskV1, RatifiedPayloadProfile,
        SignerEnrollment, TASK_BUS_V2_ALPN, TaskMessageKind, TaskTranscriptV3,
        TaskVerificationContext,
    },
    task_write_journal::{AUTHORITATIVE_JOURNAL_FILE_NAME, Journal},
    task_writer::{CanonicalTaskDocumentV1, CanonicalTaskStatus, TaskEntrySnapshotV1},
};
use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    SnapshotSession,
    initial_create::fresh_empty_store_image_for_private_fixture,
    qualified::{
        LegacyAssociationBatch, LocalJournalMirrorBatch, LogicalKey, ObservationBatch,
        QualifiedRecord, RecordFamily, TaskRefEnvelope,
    },
    replacement::{AgentDispatchRecord, MigrationRequest, WriteOwner, WriteSession},
};
use iroh::SecretKey;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
use tempfile::TempDir;

const SOURCE: &str = "11111111111111111111111111111111";
const PROFILES: &[RatifiedPayloadProfile] = &[RatifiedPayloadProfile {
    kind: TaskMessageKind::Assignment,
    name: "p010-wire-fixture-v1",
    validate_canonical_payload: |bytes| bytes == b"abc",
}];
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct SourceFixture {
    _temporary: TempDir,
    root: PathBuf,
    policy: WorkspaceTaskPolicy,
    source: TaskSourceRecord,
    registry: WorkspaceSourceRegistry,
    journal: Journal,
    spec: NormalizedTaskSpecV1,
    control: TaskControlV1,
    entry: TaskEntrySnapshotV1,
    reference: TaskRefV1,
    source_bytes: Vec<u8>,
}
impl SourceFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let key = TaskKey::new("p010-workspace", SOURCE, "TASK-1").unwrap();
        let spec = NormalizedTaskSpecV1::from_fields(
            &key,
            vec![
                ("task_id".into(), RawSpecValue::Scalar("TASK-1".into())),
                (
                    "title".into(),
                    RawSpecValue::Scalar("Observe a qualified task".into()),
                ),
                (
                    "scope".into(),
                    RawSpecValue::Scalar("controlled fixture".into()),
                ),
                (
                    "promised_interfaces".into(),
                    RawSpecValue::List(vec!["typed snapshot".into()]),
                ),
                (
                    "acceptance_checks".into(),
                    RawSpecValue::List(vec!["exact bytes".into()]),
                ),
                ("dependencies".into(), RawSpecValue::Dependencies(vec![])),
                (
                    "reviewer_role".into(),
                    RawSpecValue::Scalar("independent-review".into()),
                ),
            ],
        )
        .unwrap();
        let control = TaskControlV1 {
            task_key: key,
            owner_principal: "fixture-worker".into(),
            reviewer_role: "independent-review".into(),
            execution_mode: ExecutionMode::Implementation,
            implementation_authorized: true,
            deployment_authorized: false,
            automatic_dispatch: false,
            allowed_action_names: vec!["implement".into()],
            review_policy_digest: Sha256Digest([4; 32]),
        };
        let entry = TaskEntrySnapshotV1 {
            task_id: "TASK-1".into(),
            status: CanonicalTaskStatus::Todo,
            task_status_rev: 0,
            task_spec_digest: spec.task_spec_digest(),
            task_control_digest: control.task_control_digest().unwrap(),
            completion_policy_digest: Sha256Digest([3; 32]),
            owner_actor: Some("DEV#fixture".into()),
            reviewer_role: "independent-review".into(),
            baseline_commit: GitOid::Sha1([1; 20]),
            candidate_commit: None,
            overlay_digest: None,
            execution_flags: vec!["implementation".into()],
            dependencies: vec![],
        };
        let document: CanonicalTaskDocumentV1 = serde_json::from_value(serde_json::json!({
            "workspace_id":"p010-workspace", "repo_id":"p010-repo", "task_source_id":SOURCE,
            "source_generation":1, "file_cas_rev":0, "last_operation_id":null, "tasks":[entry.clone()],
        })).unwrap();
        let source_bytes = document.to_canonical_bytes().unwrap();
        fs::write(root.join("Tasks.md"), &source_bytes).unwrap();
        fs::set_permissions(root.join("Tasks.md"), fs::Permissions::from_mode(0o600)).unwrap();
        let policy = WorkspaceTaskPolicy {
            workspace_id: "p010-workspace".into(),
            repo_id: "p010-repo".into(),
            config_revision: 1,
            authority_epoch: 1,
            scheduler_owner: "SCHEDULER#fixture".into(),
            max_sources: 16,
            config_digest: [7; 32],
        };
        let mut source = TaskSourceRecord {
            workspace_id: policy.workspace_id.clone(),
            repo_id: policy.repo_id.clone(),
            source_worktree_id: "fixture-tree".into(),
            task_source_id: SOURCE.into(),
            display_name: "Fixture tasks".into(),
            canonical_relative_path: "Tasks.md".into(),
            source_generation: 1,
            normalization_version: 1,
            schema_version: 1,
            writer_principal: "fixture-writer".into(),
            writer_epoch: 1,
            config_digest: policy.config_digest,
            state: TaskSourceState::Proposed,
            controls: SourceDispatchControls {
                mode: SourceExecutionMode::Implementation,
                implementation_authorized: true,
                deployment_authorized: false,
                automatic_dispatch: false,
                allowed_actions: vec!["task-write".into()],
            },
        };
        let metadata = fs::metadata(&root).unwrap();
        let pin = WorkspaceRootPin {
            path: root.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            generation: 1,
        };
        let mut registry = WorkspaceSourceRegistry::new(policy.clone(), pin).unwrap();
        registry.enroll(source.clone()).unwrap();
        source.state = TaskSourceState::Enrolled;
        fs::create_dir(root.join("journal")).unwrap();
        fs::set_permissions(root.join("journal"), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::open(root.join("journal")).unwrap();
        let journal =
            Journal::open(&directory, AUTHORITATIVE_JOURNAL_FILE_NAME, metadata.uid()).unwrap();
        let reference = document.task_ref(&entry, "Tasks.md");
        Self {
            _temporary: temporary,
            root,
            policy,
            source,
            registry,
            journal,
            spec,
            control,
            entry,
            reference,
            source_bytes,
        }
    }
    fn projection(&self, id: &str) -> QualifiedRecord {
        projection_observation(
            id.into(),
            &self.reference,
            &self.entry,
            &self.spec,
            &self.control,
            Sha256Digest::of(&self.source_bytes),
            None,
        )
        .unwrap()
    }
    fn source_record(&self, id: &str) -> QualifiedRecord {
        source_observation(
            id.into(),
            &self.source,
            &self.policy,
            1,
            Sha256Digest::of(&self.source_bytes),
            b"private enrollment observation".to_vec(),
        )
        .unwrap()
    }
    fn authority(&self) -> ProjectionAuthority<'_> {
        ProjectionAuthority::fixture(&self.registry, &self.journal)
    }
}

struct NativeFixture {
    _temporary: TempDir,
    root: PathBuf,
    authority: StoreMutationAuthority,
}
impl NativeFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap().join("repo");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join(".chinwag")).unwrap();
        fs::set_permissions(root.join(".chinwag"), fs::Permissions::from_mode(0o700)).unwrap();
        fresh_empty_store_image_for_private_fixture()
            .unwrap()
            .begin_private_fixture(&root)
            .unwrap()
            .finish()
            .unwrap();
        let authority = StoreMutationAuthority::fixture(&root).unwrap();
        Self {
            _temporary: temporary,
            root,
            authority,
        }
    }
    fn image(&self) -> Vec<u8> {
        fs::read(self.root.join(".chinwag/state.crdb")).unwrap()
    }
    fn snapshot(&self) -> TaskStoreSnapshot {
        TaskStoreSnapshot::from_v2_owner(
            ReadOwner::acquire_existing_private_fixture(&self.root).unwrap(),
        )
        .unwrap()
    }
    fn migration(&self, observations: Vec<QualifiedRecord>) -> MigrationRequest {
        MigrationRequest::try_new(
            "p010-workspace".into(),
            "migration-1".into(),
            Sha256Digest::of(&self.image()).0,
            ObservationBatch::try_new(observations).unwrap(),
            LocalJournalMirrorBatch::try_new(vec![]).unwrap(),
        )
        .unwrap()
    }
    fn seed_legacy(&self, body: &str) {
        let record = AgentDispatchRecord::try_new(
            "legacy-thread".into(),
            "p010-repo".into(),
            "fixture".into(),
            "Historical thread".into(),
            "legacy-message".into(),
            "DEV#legacy".into(),
            "user".into(),
            body.into(),
            "legacy-reply".into(),
            "ROOT#fixture".into(),
            "assistant".into(),
            "exact historical reply".into(),
            100,
        )
        .unwrap();
        let completion = WriteSession::from_owner(
            WriteOwner::acquire_existing_private_fixture(&self.root).unwrap(),
        )
        .unwrap()
        .prepare_agent_dispatch(record, || false)
        .unwrap()
        .commit(false)
        .unwrap();
        assert!(!completion.is_error());
    }
}

fn signed_frame(
    fixture: &SourceFixture,
    secret: &SecretKey,
    id: &str,
    large: bool,
) -> PublishTaskV1 {
    let mut transcript = TaskTranscriptV3 {
        message_id:id.into(), issued_at_unix:100, expires_at_unix:200, nonce:[9;32], sender_full_actor_address:"RUST#sender".into(),
        parent_full_actor_address:Some("DELIVERY#parent".into()), recipient_full_actor_addresses:vec!["FIXTURE-A#receiver".into()],
        room:"#eng".into(), message_kind:TaskMessageKind::Assignment, receiver_authority_id:"fixture-authority".into(),
        task_ref:fixture.reference.clone(), assignment_id:Some("assignment-1".into()), operation_id:Some("operation-1".into()),
        request_id:None, in_reply_to_message_id:None, config_digest:Sha256Digest([1;32]), task_control_digest:fixture.control.task_control_digest().unwrap(),
        body_utf8:serde_json::json!({"payload_profile":"p010-wire-fixture-v1","canonical_payload_hex":"616263","payload_digest_sha256":Sha256Digest::of(b"abc").to_string(),"display_text":""}).to_string(),
    };
    if large {
        let overhead = transcript.encode_transcript(PROFILES).unwrap().len();
        let padding = MAX_TASK_WIRE_FRAME_BYTES - 158 - overhead;
        let mut body: serde_json::Value = serde_json::from_str(&transcript.body_utf8).unwrap();
        body["display_text"] = serde_json::Value::String("x".repeat(padding));
        transcript.body_utf8 = body.to_string();
        assert_eq!(
            transcript.encode_transcript(PROFILES).unwrap().len(),
            130_914
        );
    }
    PublishTaskV1::sign(transcript, secret, PROFILES).unwrap()
}
fn roster(secret: &SecretKey) -> Vec<SignerEnrollment> {
    vec![SignerEnrollment {
        workspace_id: "p010-workspace".into(),
        repo_id: "p010-repo".into(),
        seat: "RUST".into(),
        authenticated_signer_principal: "fixture-signer".into(),
        signer_pubkey: secret.public(),
        key_epoch: 1,
        config_digest: Sha256Digest([1; 32]),
        allowed_actions: vec![TaskMessageKind::Assignment],
        active: true,
    }]
}
fn context(fixture: &SourceFixture) -> TaskVerificationContext<'_> {
    TaskVerificationContext {
        receiver_authority_id: "fixture-authority",
        recipient_full_actor_address: "FIXTURE-A#receiver",
        current_task_ref: &fixture.reference,
        config_digest: Sha256Digest([1; 32]),
        task_control_digest: fixture.control.task_control_digest().unwrap(),
        required_key_epoch: 1,
        current_granted_actions: &[TaskMessageKind::Assignment],
        ratified_profiles: PROFILES,
        host_clock: HostClockState::Verified { now_unix: 150 },
    }
}

#[test]
fn p010_taskref_all_ten_indexes_and_exact_codec_are_checked() {
    let fixture = SourceFixture::new();
    let reference = &fixture.reference;
    let envelope = task_ref_envelope(reference).unwrap();
    assert_eq!(decode_stored_reference(&envelope).unwrap(), *reference);
    for field in 0..10 {
        let mut changed = reference.clone();
        match field {
            0 => changed.workspace_id = "other-workspace".into(),
            1 => changed.repo_id = "other-repo".into(),
            2 => changed.task_source_id = "22222222222222222222222222222222".into(),
            3 => changed.source_generation += 1,
            4 => changed.canonical_task_path = "tasks.md".into(),
            5 => changed.task_id = "TASK-2".into(),
            6 => changed.task_spec_digest = Sha256Digest([3; 32]),
            7 => changed.task_status_rev += 1,
            8 => changed.file_cas_rev += 1,
            9 => changed.baseline_commit = GitOid::Sha256([2; 32]),
            _ => unreachable!(),
        }
        assert!(
            TaskRefEnvelope::try_new(
                reference.encode().unwrap(),
                reference.task_ref_digest().unwrap().0,
                task_ref_indexes(&changed).unwrap()
            )
            .is_err(),
            "index {field}"
        );
    }
    let mut canonical = reference.encode().unwrap();
    canonical.push(0);
    assert!(
        TaskRefEnvelope::try_new(
            canonical.clone(),
            Sha256Digest::of(&canonical).0,
            envelope.indexes().clone()
        )
        .is_err()
    );
    let mut wrong = reference.encode().unwrap();
    wrong[0] ^= 1;
    assert!(
        TaskRefEnvelope::try_new(
            wrong.clone(),
            Sha256Digest::of(&wrong).0,
            envelope.indexes().clone()
        )
        .is_err()
    );
    for counter in [0, i64::MAX as u64] {
        let mut boundary = reference.clone();
        boundary.source_generation = counter;
        boundary.task_status_rev = counter;
        boundary.file_cas_rev = counter;
        assert_eq!(
            decode_stored_reference(&task_ref_envelope(&boundary).unwrap()).unwrap(),
            boundary
        );
    }
    let mut overflow = reference.clone();
    overflow.file_cas_rev = i64::MAX as u64 + 1;
    assert!(task_ref_envelope(&overflow).is_err());
}

#[test]
fn p010_staged_sources_are_order_independent_and_conflicts_never_pick_a_winner() {
    let fixture = SourceFixture::new();
    let projection = fixture.projection("projection-1");
    let source = fixture.source_record("source-1");
    assert_eq!(
        classify_staged_relationships(std::slice::from_ref(&projection), &[]).unwrap()[0]
            .disposition(),
        ProjectionDisposition::DanglingObservation
    );
    for records in [
        vec![source.clone(), projection.clone()],
        vec![projection.clone(), source.clone()],
    ] {
        assert!(
            classify_staged_relationships(&records, &[])
                .unwrap()
                .iter()
                .all(|row| row.disposition() == ProjectionDisposition::LinkedObservation)
        );
    }
    let mut conflicting = fixture.source.clone();
    conflicting.canonical_relative_path = "Other.md".into();
    let conflict = source_observation(
        "source-conflict".into(),
        &conflicting,
        &fixture.policy,
        1,
        Sha256Digest::of(b"other"),
        vec![],
    )
    .unwrap();
    for sources in [
        vec![source.clone(), conflict.clone()],
        vec![conflict, source.clone()],
    ] {
        assert_eq!(
            classify_staged_relationships(std::slice::from_ref(&projection), &sources).unwrap()[0]
                .disposition(),
            ProjectionDisposition::Quarantined
        );
    }
    let phase = source_observation(
        "source-phase".into(),
        &fixture.source,
        &fixture.policy,
        2,
        Sha256Digest::of(b"changed canonical phase"),
        vec![],
    )
    .unwrap();
    assert_eq!(
        classify_staged_relationships(std::slice::from_ref(&projection), &[source, phase]).unwrap()
            [0]
        .disposition(),
        ProjectionDisposition::LinkedObservation
    );
}

#[test]
fn p010_genesis_projection_requires_current_source_and_original_empty_journal_snapshot() {
    let fixture = SourceFixture::new();
    let projection = fixture.projection("projection-1");
    let public = reconcile_current_projection(
        &projection,
        &ProjectionAuthority::unsupported(),
        &fixture.spec,
        &fixture.control,
    )
    .unwrap();
    assert_eq!(public.disposition(), ProjectionDisposition::HeldUnsupported);
    assert!(public.require_production_current().is_err());
    let current = reconcile_current_projection(
        &projection,
        &fixture.authority(),
        &fixture.spec,
        &fixture.control,
    )
    .unwrap();
    assert_eq!(
        current.disposition(),
        ProjectionDisposition::FixtureCurrentObservation
    );
    assert!(current.require_production_current().is_err());
    let mut file = OpenOptions::new()
        .append(true)
        .open(
            fixture
                .root
                .join("journal")
                .join(AUTHORITATIVE_JOURNAL_FILE_NAME),
        )
        .unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        reconcile_current_projection(
            &projection,
            &fixture.authority(),
            &fixture.spec,
            &fixture.control
        ),
        Err(ProjectionError::Journal(_))
    ));
}

#[test]
fn p010_replaced_original_journal_and_changed_source_are_held() {
    let fixture = SourceFixture::new();
    let projection = fixture.projection("projection-1");
    let path = fixture
        .root
        .join("journal")
        .join(AUTHORITATIVE_JOURNAL_FILE_NAME);
    fs::rename(&path, path.with_extension("old")).unwrap();
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        reconcile_current_projection(
            &projection,
            &fixture.authority(),
            &fixture.spec,
            &fixture.control
        ),
        Err(ProjectionError::Journal(_))
    ));
    let other = SourceFixture::new();
    let projection = other.projection("projection-1");
    let mut changed = other.source_bytes.clone();
    changed.extend(b"\n");
    fs::write(other.root.join("Tasks.md"), changed).unwrap();
    assert_ne!(
        reconcile_current_projection(&projection, &other.authority(), &other.spec, &other.control)
            .unwrap()
            .disposition(),
        ProjectionDisposition::FixtureCurrentObservation
    );
}

#[test]
fn p010_public_mutation_provider_refuses_before_marker_or_database_effects() {
    let native = NativeFixture::new();
    let before = native.image();
    let request = native.migration(vec![]);
    assert!(matches!(
        migrate_store(
            &native.root,
            request,
            &StoreMutationAuthority::unsupported()
        ),
        Err(ProjectionError::Unsupported)
    ));
    assert_eq!(native.image(), before);
    assert!(!native.root.join(".chinwag/state.crdb.lock").exists());
    assert!(matches!(
        append_observations(
            &native.root,
            ObservationBatch::try_new(vec![]).unwrap(),
            &StoreMutationAuthority::unsupported()
        ),
        Err(ProjectionError::Unsupported)
    ));
    assert_eq!(native.image(), before);
}

#[test]
fn p010_empty_journal_append_after_source_recheck_is_detected_before_current_result() {
    let fixture = SourceFixture::new();
    let projection = fixture.projection("projection-1");
    let result = reconcile_projection_with_private_cut(
        &projection,
        &fixture.authority(),
        &fixture.spec,
        &fixture.control,
        || {
            let mut file = OpenOptions::new()
                .append(true)
                .open(
                    fixture
                        .root
                        .join("journal")
                        .join(AUTHORITATIVE_JOURNAL_FILE_NAME),
                )
                .unwrap();
            file.write_all(b"\n").unwrap();
            file.sync_all().unwrap();
        },
    );
    assert!(matches!(result, Err(ProjectionError::Journal(_))));
}

#[test]
fn p010_same_path_fixture_root_replacement_cannot_reuse_mutation_authority() {
    let native = NativeFixture::new();
    let request = native.migration(vec![]);
    let displaced = native.root.with_file_name("displaced-repo");
    fs::rename(&native.root, &displaced).unwrap();
    fs::create_dir(&native.root).unwrap();
    fs::set_permissions(&native.root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(migrate_store(&native.root, request, &native.authority).is_err());
    assert!(!native.root.join(".chinwag").exists());
    assert!(!displaced.join(".chinwag/state.crdb.lock").exists());
}

#[test]
fn p010_reopened_source_binding_conflicts_hold_both_source_and_projection() {
    let source = SourceFixture::new();
    let native = NativeFixture::new();
    migrate_store(
        &native.root,
        native.migration(vec![
            source.source_record("source-1"),
            source.projection("projection-1"),
        ]),
        &native.authority,
    )
    .unwrap();
    let mut conflicting = source.source.clone();
    conflicting.canonical_relative_path = "Other.md".into();
    let conflict = source_observation(
        "source-conflict".into(),
        &conflicting,
        &source.policy,
        2,
        Sha256Digest::of(b"other"),
        vec![],
    )
    .unwrap();
    append_observations(
        &native.root,
        ObservationBatch::try_new(vec![conflict]).unwrap(),
        &native.authority,
    )
    .unwrap();
    let snapshot = native.snapshot();
    for (family, id) in [
        (RecordFamily::Source, "source-1"),
        (RecordFamily::Projection, "projection-1"),
    ] {
        let held = snapshot.record(family, "p010-workspace", id).unwrap();
        assert_eq!(held.disposition(), ProjectionDisposition::Quarantined);
        assert!(held.record().is_none());
    }
    snapshot.finish().unwrap();
}

#[test]
fn p010_actual_131072_signed_frame_migrates_serializes_reopens_and_verifies() {
    let source = SourceFixture::new();
    let native = NativeFixture::new();
    native.seed_legacy("exact original v2 body and signature text");
    let old_owner = ReadOwner::acquire_existing_private_fixture(&native.root).unwrap();
    let old = SnapshotSession::from_owner(old_owner).unwrap();
    let legacy_before = old.context("legacy-thread").unwrap();
    let site_before = old.site_id().unwrap();
    old.finish().unwrap();
    let secret = SecretKey::from_bytes(&[23; 32]);
    let frame = signed_frame(&source, &secret, "large-message", true);
    let binary = frame.encode_binary(PROFILES).unwrap();
    assert_eq!(binary.len(), MAX_TASK_WIRE_FRAME_BYTES);
    frame
        .verify(TASK_BUS_V2_ALPN, &roster(&secret), &context(&source))
        .unwrap();
    let message = message_observation(
        "large-observation".into(),
        frame.clone(),
        &roster(&secret),
        &context(&source),
        vec![b'p'; 65_536],
    )
    .unwrap();
    assert!(message.canonical_len() > 3 * 65_536 && message.canonical_len() <= 262_144);
    assert_eq!(message.original().unwrap().binding(), binary);
    assert_eq!(message.payload(), vec![b'p'; 65_536]);
    let request = native.migration(vec![
        source.source_record("source-1"),
        source.projection("projection-1"),
        message.clone(),
    ]);
    let expected_request = request.clone();
    let completion = migrate_store(&native.root, request, &native.authority).unwrap();
    assert!(!completion.is_error());
    assert_eq!(completion.observation().site_id(), site_before);
    let before_read = native.image();
    let snapshot = native.snapshot();
    assert_eq!(
        snapshot.legacy_context("legacy-thread").unwrap(),
        legacy_before
    );
    let observed = snapshot
        .record(RecordFamily::Message, "p010-workspace", "large-observation")
        .unwrap();
    assert_eq!(
        observed.disposition(),
        ProjectionDisposition::LinkedObservation
    );
    assert!(observed.require_production_authority().is_err());
    let reassembled = observed.record().unwrap();
    assert_eq!(reassembled, &message);
    let recovered = reassembled.original().unwrap().binding();
    assert_eq!(recovered, binary);
    assert_eq!(Sha256Digest::of(recovered), Sha256Digest::of(&binary));
    PublishTaskV1::decode_binary(recovered, TASK_BUS_V2_ALPN, PROFILES)
        .unwrap()
        .verify(TASK_BUS_V2_ALPN, &roster(&secret), &context(&source))
        .unwrap();
    let historical = snapshot.migration_replay(&expected_request).unwrap();
    assert_eq!(historical.request_digest(), expected_request.digest());
    assert!(historical.require_production_authority().is_err());
    let wrong = MigrationRequest::try_new(
        "p010-workspace".into(),
        "migration-1".into(),
        [0; 32],
        ObservationBatch::try_new(vec![]).unwrap(),
        LocalJournalMirrorBatch::try_new(vec![]).unwrap(),
    )
    .unwrap();
    assert!(snapshot.migration_replay(&wrong).is_err());
    let missing = MigrationRequest::try_new(
        "p010-workspace".into(),
        "not-original-operation".into(),
        expected_request.expected_v1_sha(),
        ObservationBatch::try_new(vec![]).unwrap(),
        LocalJournalMirrorBatch::try_new(vec![]).unwrap(),
    )
    .unwrap();
    assert!(snapshot.migration_replay(&missing).is_err());
    snapshot.finish().unwrap();
    assert_eq!(native.image(), before_read);
    assert!(!native.root.join(".chinwag/state.crdb.lock").exists());
    let mut too_large = frame.transcript.clone();
    let mut body: serde_json::Value = serde_json::from_str(&too_large.body_utf8).unwrap();
    let padded = format!("{}x", body["display_text"].as_str().unwrap());
    body["display_text"] = padded.into();
    too_large.body_utf8 = body.to_string();
    let beyond = PublishTaskV1::sign(too_large, &secret, PROFILES).unwrap();
    assert!(beyond.encode_binary(PROFILES).is_err());
    assert_eq!(native.image(), before_read);
}

#[test]
fn p010_immutable_original_conflict_quarantines_but_phase_history_and_exact_replay_append() {
    let source = SourceFixture::new();
    let native = NativeFixture::new();
    let secret = SecretKey::from_bytes(&[24; 32]);
    let frame = signed_frame(&source, &secret, "same-original", false);
    let first = message_observation(
        "phase-1".into(),
        frame.clone(),
        &roster(&secret),
        &context(&source),
        b"reserved".to_vec(),
    )
    .unwrap();
    let request = native.migration(vec![
        source.source_record("source-1"),
        source.projection("projection-1"),
        first.clone(),
    ]);
    migrate_store(&native.root, request, &native.authority).unwrap();
    let after_first = native.image();
    let exact = append_observations(
        &native.root,
        ObservationBatch::try_new(vec![first.clone()]).unwrap(),
        &native.authority,
    )
    .unwrap();
    assert!(!exact.is_error());
    assert_eq!(native.image(), after_first);
    let next = message_observation(
        "phase-2".into(),
        frame.clone(),
        &roster(&secret),
        &context(&source),
        b"consumed-observation".to_vec(),
    )
    .unwrap();
    assert!(
        !append_observations(
            &native.root,
            ObservationBatch::try_new(vec![next]).unwrap(),
            &native.authority
        )
        .unwrap()
        .is_error()
    );
    let snapshot = native.snapshot();
    let key = first.key();
    assert_eq!(snapshot.observation_ids(key, "", 64).unwrap().len(), 2);
    assert_eq!(
        snapshot
            .original(key)
            .unwrap()
            .record()
            .unwrap()
            .original()
            .unwrap()
            .binding(),
        frame.encode_binary(PROFILES).unwrap()
    );
    snapshot.finish().unwrap();
    let mut changed = frame.transcript.clone();
    changed.nonce = [3; 32];
    let conflict = PublishTaskV1::sign(changed, &secret, PROFILES).unwrap();
    let conflict = message_observation(
        "phase-conflict".into(),
        conflict,
        &roster(&secret),
        &context(&source),
        b"newer time cannot win".to_vec(),
    )
    .unwrap();
    append_observations(
        &native.root,
        ObservationBatch::try_new(vec![conflict]).unwrap(),
        &native.authority,
    )
    .unwrap();
    let snapshot = native.snapshot();
    assert_eq!(
        snapshot.original(key).unwrap().disposition(),
        ProjectionDisposition::Quarantined
    );
    snapshot.finish().unwrap();
}

#[test]
fn p010_local_journal_mirror_cannot_enter_replica_batch_or_change_original_journal() {
    let source = SourceFixture::new();
    let native = NativeFixture::new();
    migrate_store(&native.root, native.migration(vec![]), &native.authority).unwrap();
    let before = fs::read(
        source
            .root
            .join("journal")
            .join(AUTHORITATIVE_JOURNAL_FILE_NAME),
    )
    .unwrap();
    let payload = b"{\"state\":\"Consumed\",\"owner\":\"forged\"}".to_vec();
    let mirror = QualifiedRecord::try_new(
        "mirror-1".into(),
        LogicalKey::source_write_intent(
            "p010-workspace".into(),
            SOURCE.into(),
            "operation-1".into(),
        )
        .unwrap(),
        vec![task_ref_envelope(&source.reference).unwrap()],
        None,
        payload.clone(),
        Sha256Digest::of(&payload).0,
    )
    .unwrap();
    assert!(ObservationBatch::try_new(vec![mirror.clone()]).is_err());
    append_local_journal_mirrors(
        &native.root,
        LocalJournalMirrorBatch::try_new(vec![mirror]).unwrap(),
        &native.authority,
    )
    .unwrap();
    let snapshot = native.snapshot();
    let observation = snapshot
        .record(
            RecordFamily::SourceWriteIntent,
            "p010-workspace",
            "mirror-1",
        )
        .unwrap();
    assert!(observation.require_production_authority().is_err());
    snapshot.finish().unwrap();
    assert_eq!(
        fs::read(
            source
                .root
                .join("journal")
                .join(AUTHORITATIVE_JOURNAL_FILE_NAME)
        )
        .unwrap(),
        before
    );
    assert!(source.journal.records().next().is_none());
}

#[test]
fn p010_full_source_task_keys_and_dependency_cycles_stay_distinct() {
    let source = SourceFixture::new();
    let mut other = source.reference.clone();
    other.task_source_id = "22222222222222222222222222222222".into();
    let commitment = DependencyCommitment {
        target_key: other.task_key(),
        target_spec_digest: other.task_spec_digest,
        completion_policy_digest: Sha256Digest([3; 32]),
    };
    let dependency = dependency_observation(
        "dependency-1".into(),
        &source.reference,
        &other,
        &commitment,
        1,
    )
    .unwrap();
    assert_eq!(
        classify_staged_relationships(
            &[dependency],
            &[
                source.source_record("source-1"),
                source.projection("projection-1")
            ]
        )
        .unwrap()[0]
            .disposition(),
        ProjectionDisposition::DanglingObservation
    );
    let a = DependencyNode {
        task_ref: source.reference.clone(),
        completion_policy_digest: Sha256Digest([3; 32]),
        dependencies: vec![commitment],
    };
    let b = DependencyNode {
        task_ref: other,
        completion_policy_digest: Sha256Digest([3; 32]),
        dependencies: vec![DependencyCommitment {
            target_key: source.reference.task_key(),
            target_spec_digest: source.reference.task_spec_digest,
            completion_policy_digest: Sha256Digest([3; 32]),
        }],
    };
    assert!(validate_projection_dependency_graph(&[a, b]).is_err());
}

#[test]
fn p010_exact_pinned_legacy_inference_is_separate_and_never_sender_qualified() {
    let source = SourceFixture::new();
    let native = NativeFixture::new();
    let secret = SecretKey::from_bytes(&[25; 32]);
    let mut legacy = LegacyBusRecord {
        id: "legacy-message".into(),
        seq: 1,
        ts_unix: 100,
        ts_iso: "1970-01-01T00:01:40Z".into(),
        room: "#eng".into(),
        sender: "DEV#legacy".into(),
        sender_cast: "DEV".into(),
        sender_endpoint_id: secret.public().to_string(),
        to: Some("FIXTURE-A#receiver".into()),
        task_id: Some("TASK-1".into()),
        body: "Historical source-unqualified body".into(),
        digest_sha256: String::new(),
        pubkey_ed25519: Some(secret.public().to_string()),
        signature_ed25519: None,
        sig_verified: false,
    };
    let payload = canonical_signing_payload(&legacy);
    legacy.signature_ed25519 = Some(hex(&secret.sign(payload.as_bytes()).to_bytes()));
    let verified = verify_legacy_record(
        &legacy,
        &LegacySignerBinding {
            sender: legacy.sender.clone(),
            public_key: secret.public(),
        },
    )
    .unwrap();
    let raw = serde_json::to_vec(&legacy).unwrap();
    native.seed_legacy(std::str::from_utf8(&raw).unwrap());
    let pin = LegacyMigrationPin {
        workspace_id: source.reference.workspace_id.clone(),
        repo_id: source.reference.repo_id.clone(),
        canonical_task_path: source.reference.canonical_task_path.clone(),
        task_source_id: source.reference.task_source_id.clone(),
        source_generation: source.reference.source_generation,
        file_cas_rev: source.reference.file_cas_rev,
        preimage_digest: Sha256Digest::of(&source.source_bytes),
    };
    let association = legacy_association_observation(
        "inference-1".into(),
        "legacy-thread".into(),
        "migration-1".into(),
        &verified,
        raw.clone(),
        &pin,
        &source.source_bytes,
        std::slice::from_ref(&source.reference),
        &source.authority(),
    )
    .unwrap();
    assert!(association.inferred_legacy());
    assert!(!association.signed_by_original_sender());
    assert!(
        legacy_association_observation(
            "not-authorized".into(),
            "legacy-thread".into(),
            "migration-1".into(),
            &verified,
            raw.clone(),
            &pin,
            &source.source_bytes,
            std::slice::from_ref(&source.reference),
            &ProjectionAuthority::unsupported()
        )
        .is_err()
    );
    let mut wrong = pin.clone();
    wrong.canonical_task_path = "tasks.md".into();
    assert!(
        legacy_association_observation(
            "wrong-case".into(),
            "legacy-thread".into(),
            "migration-1".into(),
            &verified,
            raw.clone(),
            &wrong,
            &source.source_bytes,
            std::slice::from_ref(&source.reference),
            &source.authority()
        )
        .is_err()
    );
    let mut other = source.reference.clone();
    other.task_source_id = "22222222222222222222222222222222".into();
    assert!(
        legacy_association_observation(
            "ambiguous".into(),
            "legacy-thread".into(),
            "migration-1".into(),
            &verified,
            raw.clone(),
            &pin,
            &source.source_bytes,
            &[source.reference.clone(), other],
            &source.authority()
        )
        .is_err()
    );
    let request = MigrationRequest::try_new_with_legacy(
        "p010-workspace".into(),
        "migration-1".into(),
        Sha256Digest::of(&native.image()).0,
        ObservationBatch::try_new(vec![
            source.source_record("source-1"),
            source.projection("projection-1"),
        ])
        .unwrap(),
        LocalJournalMirrorBatch::try_new(vec![]).unwrap(),
        LegacyAssociationBatch::try_new(vec![association.clone()]).unwrap(),
    )
    .unwrap();
    migrate_store(&native.root, request, &native.authority).unwrap();
    let snapshot = native.snapshot();
    assert_eq!(
        snapshot
            .legacy_associations("p010-workspace", "legacy-thread", "legacy-message", "", 64)
            .unwrap(),
        vec!["inference-1"]
    );
    let stored = snapshot
        .legacy_association(
            "p010-workspace",
            "legacy-thread",
            "legacy-message",
            "inference-1",
        )
        .unwrap();
    assert_eq!(
        stored.classification(),
        chinwag_snapshot_session_private::qualified_read::RecordClassification::LegacyUnqualified
    );
    assert_eq!(stored.association(), Some(&association));
    assert!(stored.require_production_authority().is_err());
    let original_context = snapshot.legacy_context("legacy-thread").unwrap();
    assert!(original_context.messages.iter().any(|row|row.iter().any(|value|matches!(value,chinwag_snapshot_session_private::Value::Text(body) if body.as_bytes()==raw))));
    assert_eq!(
        snapshot
            .record(RecordFamily::Message, "p010-workspace", "inference-1")
            .unwrap()
            .record(),
        None
    );
    snapshot.finish().unwrap();
}
