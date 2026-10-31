use super::*;
use crate::{ActionKind, StartupRecord, StopReason};
use std::{
    ffi::CString,
    fs,
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt, symlink},
};

fn private_root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new()
        .prefix("cw-gemini-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path().canonicalize().unwrap().join("journal");
    (directory, root)
}
fn id(n: usize) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn saved(n: usize) -> SavedOperation {
    SavedOperation {
        schema: "chinwag-gemini-operation/v1".into(),
        id: id(n),
        kind: ActionKind::Prompt,
        text: format!("Human input {n}"),
        session_epoch: id(999),
        session_id: Some(id(998)),
        prompt_rpc_id: format!("prompt-{}", id(n)),
        prompt_generation: n as u64 + 1,
        startup: None,
    }
}
fn create(journal: &mut OperationJournal, operation: SavedOperation) -> Receipt {
    match journal.consume(operation).unwrap() {
        Consume::Created(receipt) => receipt,
        Consume::Existing(_) => panic!("new ID consumed once"),
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
fn durable_intent_is_exact_cached_or_conflicting_and_recovery_never_replays() {
    let (_dir, root) = private_root();
    let operation = saved(1);
    let original;
    {
        let mut journal = OperationJournal::open(&root).unwrap();
        assert_eq!(create(&mut journal, operation.clone()).operation, operation);
        let path = root.join(filename(&operation.id));
        original = fs::read(&path).unwrap();
        let line: Line = serde_json::from_slice(&original).unwrap();
        assert!(matches!(line,Line::Saved{operation:ref found}if found.as_ref()==&operation));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert!(matches!(
            journal.consume(operation.clone()).unwrap(),
            Consume::Existing(_)
        ));
        for changed in ["text", "generation", "epoch", "session"] {
            let mut conflict = operation.clone();
            match changed {
                "text" => conflict.text.push_str(" changed"),
                "generation" => conflict.prompt_generation += 1,
                "epoch" => conflict.session_epoch = id(997),
                _ => conflict.session_id = Some(id(996)),
            }
            assert!(matches!(
                journal.consume(conflict),
                Err(GeminiError::Conflict)
            ));
        }
        assert_eq!(fs::read(path).unwrap(), original);
    }
    let mut recovered = OperationJournal::open(&root).unwrap();
    let receipt = recovered.lookup(&operation.id).unwrap().unwrap();
    assert!(receipt.recovered_after_restart);
    assert!(receipt.evidence.write_uncertain);
    assert!(matches!(
        recovered.consume(operation).unwrap(),
        Consume::Existing(_)
    ));
    assert_eq!(
        fs::read(root.join(filename(&id(1)))).unwrap(),
        original,
        "lookup/recovery never append or replay"
    );
}

#[test]
fn startup_policy_and_cancel_target_are_immutable_distinct_actions() {
    let (_dir, root) = private_root();
    let mut journal = OperationJournal::open(&root).unwrap();
    let mut start = saved(2);
    start.kind = ActionKind::Start;
    start.session_id = None;
    start.startup = Some(StartupRecord {
        binary: "/owner/bin/gemini".into(),
        sha256: "a".repeat(64),
        workdir: "/owner/work".into(),
        policy: "configured_runtime_effects_manual_mode_extensions_disabled".into(),
    });
    assert_eq!(create(&mut journal, start.clone()).operation, start);
    let mut cancel = saved(3);
    cancel.kind = ActionKind::Cancel;
    cancel.text.clear();
    cancel.prompt_rpc_id = start.prompt_rpc_id;
    cancel.prompt_generation = start.prompt_generation;
    assert_eq!(create(&mut journal, cancel.clone()).operation, cancel);
    assert!(
        journal
            .apply(
                &cancel.id,
                Evidence {
                    terminal: Some(StopReason::Cancelled),
                    ..Evidence::default()
                }
            )
            .is_err(),
        "Cancel has no invented terminal ACK"
    );
    let mut wrong = saved(4);
    wrong.kind = ActionKind::Start;
    wrong.session_id = None;
    wrong.startup = Some(StartupRecord {
        binary: "/owner/bin/gemini".into(),
        sha256: "a".repeat(64),
        workdir: "/owner/work".into(),
        policy: "restricted-no-tools".into(),
    });
    assert!(matches!(
        journal.consume(wrong),
        Err(GeminiError::InvalidInput)
    ));
    assert!(!root.join(filename(&id(4))).exists());
}

#[test]
fn failed_append_keeps_prior_durable_facts_and_other_ids_usable() {
    let (_dir, root) = private_root();
    let mut journal = OperationJournal::open(&root).unwrap();
    create(&mut journal, saved(5));
    journal
        .apply(
            &id(5),
            Evidence {
                frame_written: true,
                ..Evidence::default()
            },
        )
        .unwrap();
    let before = fs::read(root.join(filename(&id(5)))).unwrap();
    journal.fail_next_append = true;
    assert!(matches!(
        journal.apply(
            &id(5),
            Evidence {
                terminal: Some(StopReason::EndTurn),
                ..Evidence::default()
            }
        ),
        Err(GeminiError::Storage)
    ));
    let found = journal.lookup(&id(5)).unwrap().unwrap();
    assert!(found.persistence_failed);
    assert!(found.evidence.frame_written);
    assert!(found.evidence.terminal.is_none());
    assert_eq!(fs::read(root.join(filename(&id(5)))).unwrap(), before);
    create(&mut journal, saved(6));
    drop(journal);
    let recovered = OperationJournal::open(&root).unwrap();
    let found = recovered.lookup(&id(5)).unwrap().unwrap();
    assert!(found.evidence.frame_written);
    assert!(found.evidence.terminal.is_none());
    assert!(found.evidence.terminal_unknown);
    assert!(
        !found.evidence.write_uncertain,
        "a known full write is not a partial write"
    );
    assert!(recovered.lookup(&id(6)).unwrap().is_some());
}

#[test]
fn written_cancel_with_original_cancelled_terminal_recovers_without_an_invented_ack() {
    let (_dir, root) = private_root();
    let mut journal = OperationJournal::open(&root).unwrap();
    let original = saved(19);
    create(&mut journal, original.clone());
    journal
        .apply(
            &original.id,
            Evidence {
                frame_written: true,
                terminal: Some(StopReason::Cancelled),
                ..Evidence::default()
            },
        )
        .unwrap();
    let mut cancel = saved(20);
    cancel.kind = ActionKind::Cancel;
    cancel.text.clear();
    cancel.prompt_rpc_id = original.prompt_rpc_id.clone();
    cancel.prompt_generation = original.prompt_generation;
    create(&mut journal, cancel.clone());
    journal
        .apply(
            &cancel.id,
            Evidence {
                frame_written: true,
                permission_cancel_responses_written: 1,
                ..Evidence::default()
            },
        )
        .unwrap();
    let original_bytes = fs::read(root.join(filename(&original.id))).unwrap();
    let cancel_bytes = fs::read(root.join(filename(&cancel.id))).unwrap();
    drop(journal);
    let mut recovered = OperationJournal::open(&root).unwrap();
    let found = recovered.lookup(&cancel.id).unwrap().unwrap();
    assert!(found.recovered_after_restart);
    assert!(found.evidence.frame_written);
    assert_eq!(found.evidence.permission_cancel_responses_written, 1);
    assert!(
        found.evidence.terminal.is_none(),
        "a notification has no terminal ACK"
    );
    assert!(!found.evidence.write_uncertain);
    assert!(!found.evidence.terminal_unknown);
    assert_eq!(
        recovered
            .lookup(&original.id)
            .unwrap()
            .unwrap()
            .evidence
            .terminal,
        Some(StopReason::Cancelled)
    );
    assert!(matches!(
        recovered.consume(cancel).unwrap(),
        Consume::Existing(_)
    ));
    assert_eq!(
        fs::read(root.join(filename(&id(19)))).unwrap(),
        original_bytes
    );
    assert_eq!(
        fs::read(root.join(filename(&id(20)))).unwrap(),
        cancel_bytes
    );
}

#[test]
fn known_written_prompt_and_start_recover_terminal_unknown_without_partial_write_or_replay() {
    let (_dir, root) = private_root();
    let mut journal = OperationJournal::open(&root).unwrap();
    let prompt = saved(21);
    let mut start = saved(22);
    start.kind = ActionKind::Start;
    start.session_id = None;
    start.startup = Some(StartupRecord {
        binary: "/owner/bin/gemini".into(),
        sha256: "a".repeat(64),
        workdir: "/owner/work".into(),
        policy: "configured_runtime_effects_manual_mode_extensions_disabled".into(),
    });
    let operations = [prompt, start];
    let mut originals = Vec::new();
    for operation in &operations {
        create(&mut journal, operation.clone());
        journal
            .apply(
                &operation.id,
                Evidence {
                    frame_written: true,
                    ..Evidence::default()
                },
            )
            .unwrap();
        originals.push(fs::read(root.join(filename(&operation.id))).unwrap());
    }
    create(&mut journal, saved(23));
    journal
        .apply(
            &id(23),
            Evidence {
                not_dispatched: true,
                ..Evidence::default()
            },
        )
        .unwrap();
    drop(journal);
    let mut recovered = OperationJournal::open(&root).unwrap();
    for (operation, before) in operations.into_iter().zip(originals) {
        let receipt = recovered.lookup(&operation.id).unwrap().unwrap();
        assert!(receipt.evidence.frame_written);
        assert!(receipt.evidence.terminal_unknown);
        assert!(
            !receipt.evidence.write_uncertain,
            "missing terminal does not erase a known full write"
        );
        assert!(receipt.evidence.terminal.is_none());
        let id = operation.id.clone();
        assert!(matches!(
            recovered.consume(operation).unwrap(),
            Consume::Existing(_)
        ));
        assert_eq!(
            fs::read(root.join(filename(&id))).unwrap(),
            before,
            "recovery never appends or replays"
        );
    }
    let not_dispatched = recovered.lookup(&id(23)).unwrap().unwrap();
    assert!(not_dispatched.evidence.not_dispatched);
    assert!(!not_dispatched.evidence.write_uncertain);
    assert!(!not_dispatched.evidence.terminal_unknown);
}

#[test]
fn recovered_positive_evidence_must_resync_without_rewriting_bytes() {
    let (_dir, root) = private_root();
    let mut journal = OperationJournal::open(&root).unwrap();
    create(&mut journal, saved(7));
    journal
        .apply(
            &id(7),
            Evidence {
                terminal: Some(StopReason::Refusal),
                ..Evidence::default()
            },
        )
        .unwrap();
    let before = fs::read(root.join(filename(&id(7)))).unwrap();
    assert!(
        load_entry_with_sync(&journal.directory, &filename(&id(7)), &id(7), |_, _| Err(
            GeminiError::Storage
        ))
        .is_err()
    );
    assert_eq!(fs::read(root.join(filename(&id(7)))).unwrap(), before);
    drop(journal);
    let recovered = OperationJournal::open(&root).unwrap();
    assert_eq!(
        recovered.lookup(&id(7)).unwrap().unwrap().evidence.terminal,
        Some(StopReason::Refusal)
    );
    assert_eq!(fs::read(root.join(filename(&id(7)))).unwrap(), before);
}

#[test]
fn capacity_preserves_all_128_originals_and_never_evicts_unresolved_work() {
    let (_dir, root) = private_root();
    let mut journal = OperationJournal::open(&root).unwrap();
    for n in 0..MAX_OPERATIONS {
        create(&mut journal, saved(n));
    }
    let before = fs::read(root.join(filename(&id(0)))).unwrap();
    assert!(matches!(
        journal.consume(saved(MAX_OPERATIONS)),
        Err(GeminiError::Capacity)
    ));
    assert!(!root.join(filename(&id(MAX_OPERATIONS))).exists());
    assert!(matches!(
        journal.consume(saved(0)).unwrap(),
        Consume::Existing(_)
    ));
    assert_eq!(fs::read(root.join(filename(&id(0)))).unwrap(), before);
    drop(journal);
    let recovered = OperationJournal::open(&root).unwrap();
    assert_eq!(recovered.receipts().unwrap().len(), MAX_OPERATIONS);
    for n in 0..MAX_OPERATIONS {
        assert!(recovered.lookup(&id(n)).unwrap().is_some());
    }
}

#[test]
fn torn_and_orphan_records_reserve_original_id_without_poisoning_unrelated_ids() {
    let (_dir, root) = private_root();
    drop(OperationJournal::open(&root).unwrap());
    let torn = b"{\"type\":\"saved\"";
    private_file(&root.join(filename(&id(8))), torn);
    let orphan = root.join(format!(".{}-write.tmp", id(9)));
    private_file(&orphan, b"original uncertain bytes");
    let mut journal = OperationJournal::open(&root).unwrap();
    assert!(journal.has_consumed());
    for n in [8, 9] {
        assert!(matches!(journal.lookup(&id(n)), Err(GeminiError::Storage)));
        assert!(matches!(
            journal.consume(saved(n)),
            Err(GeminiError::Storage)
        ));
    }
    create(&mut journal, saved(10));
    assert_eq!(fs::read(root.join(filename(&id(8)))).unwrap(), torn);
    assert_eq!(fs::read(orphan).unwrap(), b"original uncertain bytes");
}

#[test]
fn named_replacement_and_late_canonical_bytes_are_never_adopted_or_overwritten() {
    let (_dir, root) = private_root();
    let mut journal = OperationJournal::open(&root).unwrap();
    create(&mut journal, saved(11));
    let path = root.join(filename(&id(11)));
    let old = root.join("original-held");
    fs::rename(&path, &old).unwrap();
    private_file(&path, b"foreign replacement\n");
    assert!(journal.lookup(&id(11)).is_err());
    assert!(journal.consume(saved(11)).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"foreign replacement\n");
    let line: Line = serde_json::from_slice(&fs::read(old).unwrap()).unwrap();
    assert!(matches!(line,Line::Saved{operation}if *operation==saved(11)));
    let late = root.join(filename(&id(12)));
    private_file(&late, b"late foreign bytes\n");
    assert!(matches!(
        journal.consume(saved(12)),
        Err(GeminiError::Storage)
    ));
    assert_eq!(fs::read(late).unwrap(), b"late foreign bytes\n");
    create(&mut journal, saved(13));
}

#[test]
fn foreign_domain_modes_and_symlink_roots_fail_without_repair() {
    let (_dir, root) = private_root();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&root.join(DOMAIN), b"foreign domain\n");
    assert!(OperationJournal::open(&root).is_err());
    assert_eq!(fs::read(root.join(DOMAIN)).unwrap(), b"foreign domain\n");
    let unmarked = root.with_file_name("unmarked");
    fs::create_dir(&unmarked).unwrap();
    fs::set_permissions(&unmarked, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&unmarked.join("keep"), b"keep bytes");
    assert!(OperationJournal::open(&unmarked).is_err());
    assert!(!unmarked.join(DOMAIN).exists());
    let alias = root.with_file_name("alias");
    symlink(&root, &alias).unwrap();
    assert!(OperationJournal::open(&alias).is_err());
    let exposed = root.with_file_name("exposed");
    fs::create_dir(&exposed).unwrap();
    fs::set_permissions(&exposed, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(OperationJournal::open(&exposed).is_err());
    assert_eq!(fs::metadata(exposed).unwrap().mode() & 0o7777, 0o755);
}

#[test]
fn fifo_socket_hardlink_and_symlink_ids_stay_reserved_and_nonblocking() {
    use std::os::unix::{ffi::OsStrExt as _, net::UnixListener};
    let (_dir, root) = private_root();
    drop(OperationJournal::open(&root).unwrap());
    let fifo = root.join(filename(&id(14)));
    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // Only a controlled temporary FIFO; no child or application is executed.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let socket = root.join(filename(&id(15)));
    let _listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let external = root.with_file_name("preserved-data");
    private_file(&external, b"preserve me");
    symlink(&external, root.join(filename(&id(16)))).unwrap();
    fs::hard_link(&external, root.join(filename(&id(17)))).unwrap();
    let begin = std::time::Instant::now();
    let mut journal = OperationJournal::open(&root).unwrap();
    assert!(begin.elapsed() < std::time::Duration::from_secs(3));
    for n in 14..=17 {
        assert!(matches!(
            journal.consume(saved(n)),
            Err(GeminiError::Storage)
        ));
    }
    create(&mut journal, saved(18));
    assert_eq!(fs::read(external).unwrap(), b"preserve me");
    assert!(fs::symlink_metadata(fifo).unwrap().file_type().is_fifo());
}

#[test]
fn journal_lock_is_released_even_with_a_surviving_duplicate_descriptor() {
    let (_dir, root) = private_root();
    let journal = OperationJournal::open(&root).unwrap();
    let held = journal.lock.0.try_clone().unwrap();
    assert!(matches!(
        OperationJournal::open(&root),
        Err(GeminiError::Unavailable)
    ));
    drop(journal);
    drop(OperationJournal::open(&root).unwrap());
    drop(held);
}
