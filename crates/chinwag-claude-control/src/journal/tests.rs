use super::*;
use crate::{ActionKind, InputTiming, StartupRecord};
use std::{
    ffi::CString,
    fs,
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt, symlink},
};

fn private_root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new()
        .prefix("cw-journal-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().canonicalize().unwrap().join("journal");
    (directory, root)
}
fn id(n: usize) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn saved(n: usize) -> SavedInput {
    SavedInput {
        schema: "chinwag-claude-input/v1".into(),
        id: id(n),
        session_epoch: id(999),
        session_id: id(998),
        kind: ActionKind::Direction,
        timing: InputTiming::Now,
        text: format!("Explicit human input {n}"),
        startup: None,
    }
}
fn create(journal: &mut InputJournal, operation: SavedInput) -> Receipt {
    match journal.consume(operation).unwrap() {
        Consume::Created(receipt) => receipt,
        Consume::Existing(_) => panic!("new ID must be consumed once"),
    }
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn durable_intent_is_exact_cached_or_conflicting_and_restart_never_creates_it_again() {
    let (_dir, root) = private_root();
    let operation = saved(1);
    let original;
    {
        let mut journal = InputJournal::open(&root).unwrap();
        let receipt = create(&mut journal, operation.clone());
        assert_eq!(receipt.operation, operation);
        assert_eq!(receipt.evidence, InputEvidence::default());
        let path = root.join(filename(&operation.id));
        original = fs::read(&path).unwrap();
        assert!(original.ends_with(b"\n"));
        let line: Line = serde_json::from_slice(&original).unwrap();
        assert!(matches!(line,Line::Saved{operation:ref found}if found.as_ref()==&operation));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(matches!(
            journal.consume(operation.clone()).unwrap(),
            Consume::Existing(_)
        ));
        for changed in ["text", "timing", "epoch", "session"] {
            let mut conflict = operation.clone();
            match changed {
                "text" => conflict.text.push_str(" different"),
                "timing" => conflict.timing = InputTiming::AfterTurn,
                "epoch" => conflict.session_epoch = id(997),
                _ => conflict.session_id = id(996),
            }
            assert!(matches!(
                journal.consume(conflict),
                Err(ClaudeError::Conflict)
            ));
        }
        assert_eq!(fs::read(path).unwrap(), original);
    }
    let mut recovered = InputJournal::open(&root).unwrap();
    let found = recovered.lookup(&operation.id).unwrap().unwrap();
    assert!(found.recovered_after_restart);
    assert!(found.evidence.write_uncertain);
    assert!(matches!(
        recovered.consume(operation).unwrap(),
        Consume::Existing(_)
    ));
    assert_eq!(
        fs::read(root.join(filename(&id(1)))).unwrap(),
        original,
        "recovery does not append/replay"
    );
}

#[test]
fn start_record_retains_explicit_binary_digest_folder_and_policy() {
    let (_dir, root) = private_root();
    let mut operation = saved(2);
    operation.kind = ActionKind::Start;
    operation.startup = Some(StartupRecord {
        binary: PathBuf::from("/owner/bin/claude"),
        sha256: "a".repeat(64),
        workdir: PathBuf::from("/owner/work"),
        policy: "managed_policy_prose_only".into(),
    });
    let mut journal = InputJournal::open(&root).unwrap();
    let receipt = create(&mut journal, operation.clone());
    assert_eq!(receipt.operation, operation);
    let mut wrong = operation;
    wrong.id = id(3);
    wrong.startup.as_mut().unwrap().policy = "bypass".into();
    assert!(matches!(
        journal.consume(wrong),
        Err(ClaudeError::InvalidInput)
    ));
    assert!(!root.join(filename(&id(3))).exists());
}

#[test]
fn failed_append_never_publishes_positive_evidence_and_other_ids_stay_usable() {
    let (_dir, root) = private_root();
    let mut journal = InputJournal::open(&root).unwrap();
    create(&mut journal, saved(4));
    journal
        .apply(
            &id(4),
            InputEvidence {
                frame_written: true,
                ..InputEvidence::default()
            },
        )
        .unwrap();
    let before = fs::read(root.join(filename(&id(4)))).unwrap();
    journal.fail_next_append = true;
    assert!(matches!(
        journal.apply(
            &id(4),
            InputEvidence {
                user_replayed: true,
                ..InputEvidence::default()
            }
        ),
        Err(ClaudeError::Storage)
    ));
    let found = journal.lookup(&id(4)).unwrap().unwrap();
    assert!(found.persistence_failed);
    assert!(found.evidence.frame_written);
    assert!(found.evidence.write_uncertain);
    assert!(!found.evidence.user_replayed);
    assert_eq!(fs::read(root.join(filename(&id(4)))).unwrap(), before);
    create(&mut journal, saved(5));
    drop(journal);
    let recovered = InputJournal::open(&root).unwrap();
    let found = recovered.lookup(&id(4)).unwrap().unwrap();
    assert!(found.evidence.frame_written);
    assert!(!found.evidence.user_replayed);
    assert!(found.evidence.write_uncertain);
    assert!(recovered.lookup(&id(5)).unwrap().is_some());
}

#[test]
fn recovered_positive_evidence_requires_successful_resync_and_preserves_bytes_on_failure() {
    let (_dir, root) = private_root();
    let mut journal = InputJournal::open(&root).unwrap();
    create(&mut journal, saved(6));
    journal
        .apply(
            &id(6),
            InputEvidence {
                user_replayed: true,
                ..InputEvidence::default()
            },
        )
        .unwrap();
    let before = fs::read(root.join(filename(&id(6)))).unwrap();
    assert!(
        load_entry_with_sync(&journal.directory, &filename(&id(6)), &id(6), |_, _| Err(
            ClaudeError::Storage
        ))
        .is_err()
    );
    assert_eq!(fs::read(root.join(filename(&id(6)))).unwrap(), before);
    drop(journal);
    let recovered = InputJournal::open(&root).unwrap();
    assert!(
        recovered
            .lookup(&id(6))
            .unwrap()
            .unwrap()
            .evidence
            .user_replayed
    );
    assert_eq!(fs::read(root.join(filename(&id(6)))).unwrap(), before);
}

#[test]
fn full_capacity_retains_every_original_id_without_overwrite_or_eviction() {
    let (_dir, root) = private_root();
    let mut journal = InputJournal::open(&root).unwrap();
    for n in 0..MAX_OPERATIONS {
        create(&mut journal, saved(n));
    }
    let before = fs::read(root.join(filename(&id(0)))).unwrap();
    assert!(matches!(
        journal.consume(saved(MAX_OPERATIONS)),
        Err(ClaudeError::Capacity)
    ));
    assert!(!root.join(filename(&id(MAX_OPERATIONS))).exists());
    assert!(matches!(
        journal.consume(saved(0)).unwrap(),
        Consume::Existing(_)
    ));
    assert_eq!(fs::read(root.join(filename(&id(0)))).unwrap(), before);
    drop(journal);
    let recovered = InputJournal::open(&root).unwrap();
    assert_eq!(recovered.receipts().unwrap().len(), MAX_OPERATIONS);
    for n in 0..MAX_OPERATIONS {
        assert!(recovered.lookup(&id(n)).unwrap().is_some());
    }
}

#[test]
fn torn_or_orphaned_records_reserve_the_id_but_do_not_block_unrelated_input() {
    let (_dir, root) = private_root();
    drop(InputJournal::open(&root).unwrap());
    let torn = b"{\"type\":\"saved\"";
    private_file(&root.join(filename(&id(7))), torn);
    let orphan = root.join(format!(".{}-write.tmp", id(8)));
    private_file(&orphan, b"uncertain original bytes");
    let mut journal = InputJournal::open(&root).unwrap();
    assert!(journal.has_consumed());
    for n in [7, 8] {
        assert!(matches!(journal.lookup(&id(n)), Err(ClaudeError::Storage)));
        assert!(matches!(
            journal.consume(saved(n)),
            Err(ClaudeError::Storage)
        ));
    }
    create(&mut journal, saved(9));
    assert_eq!(fs::read(root.join(filename(&id(7)))).unwrap(), torn);
    assert_eq!(fs::read(orphan).unwrap(), b"uncertain original bytes");
}

#[test]
fn a_late_named_record_replacement_is_never_adopted_or_overwritten() {
    let (_dir, root) = private_root();
    let mut journal = InputJournal::open(&root).unwrap();
    create(&mut journal, saved(10));
    let path = root.join(filename(&id(10)));
    let held = root.join("preserved-original");
    fs::rename(&path, &held).unwrap();
    private_file(&path, b"foreign replacement\n");
    assert!(journal.lookup(&id(10)).is_err());
    assert!(journal.consume(saved(10)).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"foreign replacement\n");
    let preserved: Line = serde_json::from_slice(&fs::read(&held).unwrap()).unwrap();
    assert!(matches!(preserved,Line::Saved{operation}if *operation==saved(10)));
    create(&mut journal, saved(11));
    let late = root.join(filename(&id(17)));
    private_file(&late, b"late foreign canonical bytes\n");
    assert!(matches!(
        journal.consume(saved(17)),
        Err(ClaudeError::Storage)
    ));
    assert_eq!(fs::read(late).unwrap(), b"late foreign canonical bytes\n");
    create(&mut journal, saved(18));
}

#[test]
fn wrong_domain_unmarked_foreign_data_modes_and_symlink_roots_fail_without_repairs() {
    let (_dir, root) = private_root();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&root.join(DOMAIN), b"foreign domain\n");
    assert!(InputJournal::open(&root).is_err());
    assert_eq!(fs::read(root.join(DOMAIN)).unwrap(), b"foreign domain\n");
    let other = root.with_file_name("unmarked");
    fs::create_dir(&other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&other.join("keep"), b"unmarked bytes");
    assert!(InputJournal::open(&other).is_err());
    assert_eq!(fs::read(other.join("keep")).unwrap(), b"unmarked bytes");
    assert!(!other.join(DOMAIN).exists());
    let alias = root.with_file_name("alias");
    symlink(&root, &alias).unwrap();
    assert!(InputJournal::open(&alias).is_err());
    let exposed = root.with_file_name("exposed");
    fs::create_dir(&exposed).unwrap();
    fs::set_permissions(&exposed, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(InputJournal::open(&exposed).is_err());
    assert_eq!(fs::metadata(&exposed).unwrap().mode() & 0o7777, 0o755);
}

#[test]
fn fifo_socket_hardlink_and_symlink_records_are_preserved_reserved_and_nonblocking() {
    use std::os::unix::{ffi::OsStrExt as _, net::UnixListener};
    let (_dir, root) = private_root();
    drop(InputJournal::open(&root).unwrap());
    let fifo = root.join(filename(&id(12)));
    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // Controlled temporary path only; no process or external application.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let socket = root.join(filename(&id(13)));
    let _listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let external = root.with_file_name("preserved-data");
    private_file(&external, b"preserve me");
    symlink(&external, root.join(filename(&id(14)))).unwrap();
    fs::hard_link(&external, root.join(filename(&id(15)))).unwrap();
    let begin = std::time::Instant::now();
    let mut journal = InputJournal::open(&root).unwrap();
    assert!(begin.elapsed() < std::time::Duration::from_secs(3));
    for n in 12..=15 {
        assert!(matches!(
            journal.consume(saved(n)),
            Err(ClaudeError::Storage)
        ));
    }
    create(&mut journal, saved(16));
    assert_eq!(fs::read(external).unwrap(), b"preserve me");
    assert!(fs::symlink_metadata(fifo).unwrap().file_type().is_fifo());
}

#[test]
fn dropping_the_journal_unlocks_even_when_a_duplicate_lock_descriptor_survives() {
    let (_dir, root) = private_root();
    let journal = InputJournal::open(&root).unwrap();
    let held = journal.lock.0.try_clone().unwrap();
    assert!(matches!(
        InputJournal::open(&root),
        Err(ClaudeError::Unavailable)
    ));
    drop(journal);
    let reopened = InputJournal::open(&root).unwrap();
    drop(reopened);
    drop(held);
}
