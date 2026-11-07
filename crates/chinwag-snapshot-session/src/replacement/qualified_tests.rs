use super::*;
use crate::{
    qualified::{ImmutableOriginal, RecordFamily, StoredGitOid, TaskRefEnvelope, TaskRefIndexes},
    qualified_read::{QualifiedSnapshotSession, RecordClassification},
};
use chinwag_snapshot_read_owner_private::ReadOwner;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const SOURCE: &str = "0123456789abcdef0123456789abcdef";
static NEXT: AtomicU64 = AtomicU64::new(1);
fn reference() -> TaskRefEnvelope {
    let indexes = TaskRefIndexes::try_new(
        "workspace".into(),
        "repo".into(),
        SOURCE.into(),
        1,
        "spec/tasks.md".into(),
        "P0-10".into(),
        [8; 32],
        1,
        1,
        StoredGitOid::Sha1([7; 20]),
    )
    .unwrap();
    let bytes = indexes.canonical_bytes();
    TaskRefEnvelope::try_new(bytes.clone(), qualified::digest(&bytes), indexes).unwrap()
}
fn source_record() -> QualifiedRecord {
    QualifiedRecord::try_new(
        "source-observation".into(),
        LogicalKey::source("workspace".into(), SOURCE.into(), 1).unwrap(),
        vec![],
        None,
        b"enrollment observation".to_vec(),
        qualified::digest(b"enrollment observation"),
    )
    .unwrap()
}
fn projection(id: &str) -> QualifiedRecord {
    QualifiedRecord::try_new(
        id.into(),
        LogicalKey::projection("workspace".into(), SOURCE.into(), "P0-10".into()).unwrap(),
        vec![reference()],
        None,
        b"file+journal observational projection".to_vec(),
        qualified::digest(b"file+journal observational projection"),
    )
    .unwrap()
}
fn message(id: &str, binding: Vec<u8>, phase: &[u8]) -> QualifiedRecord {
    let key = LogicalKey::message(
        "workspace".into(),
        "original-signer".into(),
        "original-id".into(),
    )
    .unwrap();
    let original =
        ImmutableOriginal::try_new(key.clone(), binding.clone(), qualified::digest(&binding))
            .unwrap();
    QualifiedRecord::try_new(
        id.into(),
        key,
        vec![reference()],
        Some(original),
        phase.to_vec(),
        qualified::digest(phase),
    )
    .unwrap()
}
fn mirrors() -> LocalJournalMirrorBatch {
    LocalJournalMirrorBatch::try_new(vec![]).unwrap()
}
fn initial() -> ObservationBatch {
    ObservationBatch::try_new(vec![source_record(), projection("projection-observation")]).unwrap()
}
fn fixture() -> (PathBuf, Vec<u8>) {
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "p010-qualified-private-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
    fs::create_dir_all(&root).unwrap();
    let leaf = root.join(".chinwag");
    fs::create_dir(&leaf).unwrap();
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
    let native = Connection::open_template_memory().unwrap();
    let image=crate::initialize_schema(&native).and_then(|()| {
        crate::transaction(&native,|| {
            native.query(c"INSERT INTO threads(id,repo_id,branch_ref,title,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",&[Value::Text("legacy-thread".into()),Value::Text("legacy-repo".into()),Value::Text("refs/heads/legacy".into()),Value::Text("legacy preserved".into()),Value::Integer(17),Value::Integer(18)])?;
            native.query(c"INSERT INTO messages(id,thread_id,author_key_id,role,body,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",&[Value::Text("legacy-message".into()),Value::Text("legacy-thread".into()),Value::Text("legacy-author".into()),Value::Text("agent".into()),Value::Text("raw legacy \0 bytes and [DONE] stay unqualified".into()),Value::Integer(19)])?;
            Ok(())
        })?;
        native.export_image_for_original_writer()
    });
    let image = crate::finish(native, image).unwrap();
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(leaf.join("state.crdb"))
        .unwrap();
    file.write_all(&image).unwrap();
    file.sync_all().unwrap();
    drop(file);
    (root, image)
}
fn request(preimage: &[u8], records: ObservationBatch) -> MigrationRequest {
    MigrationRequest::try_new(
        "workspace".into(),
        "original-migration-operation".into(),
        qualified::digest(preimage),
        records,
        mirrors(),
    )
    .unwrap()
}
fn migrate(root: &std::path::Path, request: MigrationRequest) -> super::super::Completion {
    QualifiedMigrationSession::from_v1_owner(
        WriteOwner::acquire_existing_private_fixture(root).unwrap(),
    )
    .unwrap()
    .prepare(request, || false)
    .unwrap()
    .commit(false)
    .unwrap()
}
fn read(root: &std::path::Path) -> QualifiedSnapshotSession {
    QualifiedSnapshotSession::from_v2_owner(
        ReadOwner::acquire_existing_private_fixture(root).unwrap(),
    )
    .unwrap()
}
fn append_batch(root: &std::path::Path, records: Vec<QualifiedRecord>) -> super::super::Completion {
    QualifiedWriteSession::from_v2_owner(
        WriteOwner::acquire_existing_private_fixture(root).unwrap(),
    )
    .unwrap()
    .prepare_observations(ObservationBatch::try_new(records).unwrap(), || false)
    .unwrap()
    .commit(false)
    .unwrap()
}

#[test]
fn p010_real_original_migration_install_reopen_preserves_legacy_and_full_four_part_binding() {
    let (root, v1) = fixture();
    let large = message(
        "message-observation",
        vec![0xa5; 131072],
        &vec![0x5a; 65536],
    );
    let mut records = initial().records().to_vec();
    records.push(large.clone());
    let request = request(&v1, ObservationBatch::try_new(records).unwrap());
    let digest = request.digest();
    let completion = migrate(&root, request);
    assert!(!completion.is_error());
    assert_eq!(
        completion.observation().old_sha256(),
        qualified::digest(&v1)
    );
    assert_ne!(
        completion.observation().old_sha256(),
        completion.observation().new_sha256()
    );
    let session = read(&root);
    let stored = session
        .record(RecordFamily::Message, "workspace", "message-observation")
        .unwrap();
    assert_eq!(
        stored.classification(),
        RecordClassification::LinkedObservation
    );
    assert_eq!(stored.record(), Some(&large));
    let context = session.legacy_context("legacy-thread").unwrap();
    assert_eq!(
        context.messages[0][4],
        Value::Text("raw legacy \0 bytes and [DONE] stay unqualified".into())
    );
    let historical = session
        .migration_receipt("workspace", "original-migration-operation")
        .unwrap()
        .unwrap();
    assert_eq!(historical.request_digest(), digest);
    assert_eq!((historical.from_version(), historical.to_version()), (1, 2));
    assert_eq!(historical.outcome(), MIGRATION_OUTCOME);
    assert!(
        session
            .migration_receipt("workspace", "other-operation")
            .unwrap()
            .is_none()
    );
    session.finish().unwrap();
    assert!(!root.join(".chinwag/state.crdb.lock").exists());
    let actual = fs::read(root.join(".chinwag/state.crdb")).unwrap();
    assert_eq!(
        qualified::digest(&actual),
        completion.observation().new_sha256()
    );
    // Strict V1 admission remains unchanged; use detached validation to avoid
    // acquiring a failing read-owner marker just to prove the version refusal.
    assert!(crate::validate_detached_private_image(&actual).is_err());
}

#[test]
fn p010_exact_replay_uses_read_receipt_without_a_second_migration_write_owner() {
    let (root, v1) = fixture();
    let request = request(&v1, initial());
    let expected = request.clone();
    migrate(&root, request);
    let image = fs::read(root.join(".chinwag/state.crdb")).unwrap();
    let session = read(&root);
    let receipt = session
        .migration_receipt(expected.workspace(), expected.operation())
        .unwrap()
        .unwrap();
    assert_eq!(receipt.request_digest(), expected.digest());
    session.finish().unwrap();
    assert_eq!(fs::read(root.join(".chinwag/state.crdb")).unwrap(), image);
    assert!(!root.join(".chinwag/state.crdb.lock").exists());
    assert!(!root.join(".chinwag/state.crdb.next").exists());
    assert!(!root.join(".chinwag/state.crdb.intent").exists());
    let changed = MigrationRequest::try_new(
        "workspace".into(),
        expected.operation().into(),
        [0; 32],
        initial(),
        mirrors(),
    )
    .unwrap();
    assert_ne!(changed.digest(), receipt.request_digest());
}

#[test]
fn p010_observation_exact_replay_is_unchanged_without_duplicate_rows() {
    let (root, v1) = fixture();
    migrate(&root, request(&v1, initial()));
    let before = fs::read(root.join(".chinwag/state.crdb")).unwrap();
    let result = append_batch(&root, initial().records().to_vec());
    assert!(matches!(result, super::super::Completion::Unchanged(_)));
    assert_eq!(result.response()["classification"], "ExactReplay");
    assert_eq!(fs::read(root.join(".chinwag/state.crdb")).unwrap(), before);
    let session = read(&root);
    assert_eq!(
        session
            .observation_ids(projection("unused").key(), "", 64)
            .unwrap(),
        vec!["projection-observation"]
    );
    session.finish().unwrap();
}

#[test]
fn p010_phase_history_advances_but_changed_original_commits_only_quarantine() {
    let (root, v1) = fixture();
    let original = message(
        "message-phase-1",
        b"original immutable bytes".to_vec(),
        b"pending",
    );
    let mut records = initial().records().to_vec();
    records.push(original.clone());
    migrate(
        &root,
        request(&v1, ObservationBatch::try_new(records).unwrap()),
    );
    let advanced = message(
        "message-phase-2",
        b"original immutable bytes".to_vec(),
        b"processed",
    );
    let result = append_batch(&root, vec![advanced.clone()]);
    assert_eq!(result.response()["classification"], "ObservationsStored");
    let session = read(&root);
    assert_eq!(
        session
            .record(RecordFamily::Message, "workspace", "message-phase-2")
            .unwrap()
            .record(),
        Some(&advanced)
    );
    session.finish().unwrap();
    let incoming = message(
        "message-phase-conflict",
        b"CHANGED immutable bytes".to_vec(),
        b"processed",
    );
    let unrelated = projection("unrelated-observation");
    let result = append_batch(&root, vec![incoming.clone(), unrelated]);
    assert!(!result.is_error());
    assert_eq!(result.response()["classification"], "Quarantined");
    assert_eq!(result.response()["normal_insertions"], 0);
    let session = read(&root);
    assert_eq!(
        session
            .original(original.original().unwrap().key())
            .unwrap()
            .classification(),
        RecordClassification::Quarantined
    );
    assert_eq!(
        session
            .record(
                RecordFamily::Projection,
                "workspace",
                "unrelated-observation"
            )
            .unwrap()
            .classification(),
        RecordClassification::Missing
    );
    session.finish().unwrap();
    let before = fs::read(root.join(".chinwag/state.crdb")).unwrap();
    let result = append_batch(&root, vec![incoming]);
    assert_eq!(result.response()["classification"], "Quarantined");
    assert!(matches!(result, super::super::Completion::Unchanged(_)));
    assert_eq!(fs::read(root.join(".chinwag/state.crdb")).unwrap(), before);
}

#[test]
fn p010_conflicting_same_observation_variants_are_retained_without_choosing_first() {
    let (root, v1) = fixture();
    migrate(&root, request(&v1, initial()));
    let one = message("same-observation", b"one".to_vec(), b"phase");
    let two = message("same-observation", b"two".to_vec(), b"phase");
    let result = append_batch(&root, vec![one, two]);
    assert_eq!(result.response()["retained_conflicts"], 2);
    let session = read(&root);
    assert_eq!(
        session
            .record(RecordFamily::Message, "workspace", "same-observation")
            .unwrap()
            .classification(),
        RecordClassification::Quarantined
    );
    session.finish().unwrap();
}

#[test]
fn p010_dangling_projection_relinks_only_after_matching_source_observation_arrives() {
    let (root, v1) = fixture();
    let projected = projection("dangling-projection");
    migrate(
        &root,
        request(
            &v1,
            ObservationBatch::try_new(vec![projected.clone()]).unwrap(),
        ),
    );
    let session = read(&root);
    assert_eq!(
        session
            .record(RecordFamily::Projection, "workspace", "dangling-projection")
            .unwrap()
            .classification(),
        RecordClassification::Dangling
    );
    session.finish().unwrap();
    append_batch(&root, vec![source_record()]);
    let session = read(&root);
    assert_eq!(
        session
            .record(RecordFamily::Projection, "workspace", "dangling-projection")
            .unwrap()
            .classification(),
        RecordClassification::LinkedObservation
    );
    session.finish().unwrap();
}

#[test]
fn p010_cancelled_original_migration_keeps_v1_and_releases_only_its_own_lock() {
    let (root, v1) = fixture();
    let prepared = QualifiedMigrationSession::from_v1_owner(
        WriteOwner::acquire_existing_private_fixture(&root).unwrap(),
    )
    .unwrap()
    .prepare(request(&v1, initial()), || true)
    .unwrap();
    let completion = prepared.commit(false).unwrap();
    assert!(matches!(completion, super::super::Completion::Unchanged(_)));
    assert!(completion.is_error());
    assert_eq!(fs::read(root.join(".chinwag/state.crdb")).unwrap(), v1);
    assert!(!root.join(".chinwag/state.crdb.lock").exists());
}

#[test]
fn p010_local_journal_mirrors_never_advance_replicated_version_or_replace_authority() {
    let (root, v1) = fixture();
    migrate(&root, request(&v1, initial()));
    let make = |payload: &[u8]| {
        QualifiedRecord::try_new(
            "same-local-observation".into(),
            LogicalKey::scheduler_admission("workspace".into(), "original-admission".into())
                .unwrap(),
            vec![reference()],
            None,
            payload.to_vec(),
            qualified::digest(payload),
        )
        .unwrap()
    };
    let first = make(b"external committed journal mirror");
    let run = |record| {
        QualifiedWriteSession::from_v2_owner(
            WriteOwner::acquire_existing_private_fixture(&root).unwrap(),
        )
        .unwrap()
        .prepare_local_journal_mirrors(
            LocalJournalMirrorBatch::try_new(vec![record]).unwrap(),
            || false,
        )
        .unwrap()
        .commit(false)
        .unwrap()
    };
    let inserted = run(first.clone());
    assert_eq!(
        inserted.observation().old_db_version(),
        inserted.observation().new_db_version()
    );
    assert_eq!(inserted.response()["authority"], "NONE");
    let conflict = run(make(b"changed mirror under same observation"));
    assert_eq!(conflict.response()["classification"], "Quarantined");
    // The accepted local mirror already owns exact local parts. Quarantining
    // it after a conflict reuses only byte-equal complete parts, not INSERT OR
    // REPLACE and not a second authoritative journal.
    let replay = run(first);
    assert_eq!(replay.response()["classification"], "Quarantined");
    let session = read(&root);
    assert_eq!(
        session
            .record(
                RecordFamily::SchedulerAdmission,
                "workspace",
                "same-local-observation"
            )
            .unwrap()
            .classification(),
        RecordClassification::Quarantined
    );
    session.finish().unwrap();
}

#[test]
fn p010_explicit_legacy_association_is_separate_unqualified_and_conflicting_inference_is_held() {
    let (root, v1) = fixture();
    let raw = b"raw legacy \0 bytes and [DONE] stay unqualified";
    let make = |pin: &[u8]| {
        qualified::InferredLegacyAssociation::try_new(
            "association-1".into(),
            "workspace".into(),
            "legacy-thread".into(),
            "legacy-message".into(),
            qualified::digest(raw),
            "original-migration-operation".into(),
            reference(),
            pin.to_vec(),
            qualified::digest(pin),
        )
        .unwrap()
    };
    let association = make(b"exact controlled migration source/file pin");
    let request = MigrationRequest::try_new_with_legacy(
        "workspace".into(),
        "original-migration-operation".into(),
        qualified::digest(&v1),
        initial(),
        mirrors(),
        LegacyAssociationBatch::try_new(vec![association.clone()]).unwrap(),
    )
    .unwrap();
    migrate(&root, request);
    let session = read(&root);
    let stored = session
        .legacy_association(
            "workspace",
            "legacy-thread",
            "legacy-message",
            "association-1",
        )
        .unwrap();
    assert_eq!(
        stored.classification(),
        RecordClassification::LegacyUnqualified
    );
    assert_eq!(stored.association(), Some(&association));
    assert!(stored.association().unwrap().inferred_legacy());
    assert!(!stored.association().unwrap().signed_by_original_sender());
    assert_eq!(
        session
            .record(RecordFamily::Message, "workspace", "association-1")
            .unwrap()
            .classification(),
        RecordClassification::Missing
    );
    session.finish().unwrap();
    let replay = QualifiedWriteSession::from_v2_owner(
        WriteOwner::acquire_existing_private_fixture(&root).unwrap(),
    )
    .unwrap()
    .prepare_legacy_associations(
        LegacyAssociationBatch::try_new(vec![association]).unwrap(),
        || false,
    )
    .unwrap()
    .commit(false)
    .unwrap();
    assert!(matches!(replay, super::super::Completion::Unchanged(_)));
    QualifiedWriteSession::from_v2_owner(
        WriteOwner::acquire_existing_private_fixture(&root).unwrap(),
    )
    .unwrap()
    .prepare_legacy_associations(
        LegacyAssociationBatch::try_new(vec![make(b"different inference source/file pin")])
            .unwrap(),
        || false,
    )
    .unwrap()
    .commit(false)
    .unwrap();
    let session = read(&root);
    assert_eq!(
        session
            .legacy_association(
                "workspace",
                "legacy-thread",
                "legacy-message",
                "association-1"
            )
            .unwrap()
            .classification(),
        RecordClassification::Quarantined
    );
    assert_eq!(
        session.legacy_context("legacy-thread").unwrap().messages[0][4],
        Value::Text(String::from_utf8(raw.to_vec()).unwrap())
    );
    session.finish().unwrap();
}

#[test]
fn p010_wrong_legacy_preimage_refuses_without_installing_a_migration() {
    let (root, v1) = fixture();
    let association = qualified::InferredLegacyAssociation::try_new(
        "association".into(),
        "workspace".into(),
        "legacy-thread".into(),
        "legacy-message".into(),
        [0; 32],
        "original-migration-operation".into(),
        reference(),
        b"pin".to_vec(),
        qualified::digest(b"pin"),
    )
    .unwrap();
    let request = MigrationRequest::try_new_with_legacy(
        "workspace".into(),
        "original-migration-operation".into(),
        qualified::digest(&v1),
        initial(),
        mirrors(),
        LegacyAssociationBatch::try_new(vec![association]).unwrap(),
    )
    .unwrap();
    let result = QualifiedMigrationSession::from_v1_owner(
        WriteOwner::acquire_existing_private_fixture(&root).unwrap(),
    )
    .unwrap()
    .prepare(request, || false);
    assert!(result.is_err());
    assert_eq!(fs::read(root.join(".chinwag/state.crdb")).unwrap(), v1);
    assert!(root.join(".chinwag/state.crdb.lock").exists());
    assert!(ReadOwner::acquire_existing_private_fixture(&root).is_err());
}

#[cfg(feature = "private-probe")]
#[test]
fn p010_interrupted_original_migrations_reopen_held_without_resume_or_new_ddl() {
    for cut in [
        super::super::Cut::AfterNativeClose,
        super::super::Cut::AfterNextSync,
        super::super::Cut::AfterIntent,
        super::super::Cut::AfterRename,
    ] {
        let (root, v1) = fixture();
        let prepared = QualifiedMigrationSession::from_v1_owner(
            WriteOwner::acquire_existing_private_fixture(&root).unwrap(),
        )
        .unwrap()
        .prepare(request(&v1, initial()), || false)
        .unwrap();
        assert!(
            prepared
                .commit_with_controlled_cut_for_private_probe(cut)
                .is_err()
        );
        let held_image = fs::read(root.join(".chinwag/state.crdb")).unwrap();
        assert!(ReadOwner::acquire_existing_private_fixture(&root).is_err());
        assert!(WriteOwner::acquire_existing_private_fixture(&root).is_err());
        assert_eq!(
            fs::read(root.join(".chinwag/state.crdb")).unwrap(),
            held_image
        );
        assert!(root.join(".chinwag/state.crdb.lock").exists());
        if cut == super::super::Cut::AfterRename {
            assert_ne!(held_image, v1);
        } else {
            assert_eq!(held_image, v1);
        }
    }
}
