use super::*;
use std::{
    ffi::CString,
    fs::{self, OpenOptions},
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
        net::UnixListener,
    },
};

struct Directory {
    _temp: tempfile::TempDir,
    path: PathBuf,
}

impl Directory {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { _temp: temp, path }
    }
}

fn saved(index: usize) -> SavedSteer {
    SavedSteer {
        schema: crate::record::OPERATION_SCHEMA.into(),
        id: format!("steer-op-{index:08}"),
        transport_epoch: "a".repeat(32),
        thread_id: "thread_fixture".into(),
        expected_turn_id: "turn_fixture".into(),
        text: format!("Keep this exact human text {index}\nincluding spaces  "),
    }
}

fn create(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    file.write_all(bytes).unwrap();
}

fn initialized(directory: &Directory) {
    drop(SteerJournal::open(&directory.path).unwrap());
}

fn created(journal: &mut SteerJournal, value: SavedSteer) -> Receipt {
    match journal.consume(value).unwrap() {
        Consume::Created(receipt) => receipt,
        Consume::Existing(_) => panic!("expected newly committed pending record"),
    }
}

#[test]
fn pending_is_synced_before_created_and_exact_repeat_never_writes_again() {
    let directory = Directory::new();
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    let value = saved(1);
    let receipt = created(&mut journal, value.clone());
    assert_eq!(receipt.operation, value);
    assert_eq!(receipt.evidence, Evidence::default());
    assert!(!receipt.recovered_after_restart);
    assert!(!receipt.persistence_failed);
    let path = directory.path.join(filename(&value.id));
    assert_eq!(
        fs::read(&path).unwrap(),
        encode(&Line::Saved {
            operation: value.clone()
        })
        .unwrap()
    );
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        fs::metadata(directory.path.join(DOMAIN)).unwrap().mode() & 0o7777,
        0o600
    );
    let before = fs::read(&path).unwrap();
    match journal.consume(value.clone()).unwrap() {
        Consume::Existing(existing) => assert_eq!(existing, receipt),
        Consume::Created(_) => panic!("duplicate must not receive dispatch authority"),
    }
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(journal.lookup(&value.id).unwrap(), Some(receipt));
}

#[test]
fn every_immutable_target_or_text_conflict_preserves_original_bytes() {
    let directory = Directory::new();
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    let original = saved(1);
    created(&mut journal, original.clone());
    let path = directory.path.join(filename(&original.id));
    let before = fs::read(&path).unwrap();
    for field in 0..4 {
        let mut conflicting = original.clone();
        match field {
            0 => conflicting.transport_epoch = "b".repeat(32),
            1 => conflicting.thread_id = "another_thread".into(),
            2 => conflicting.expected_turn_id = "another_turn".into(),
            3 => conflicting.text.push(' '),
            _ => unreachable!(),
        }
        assert!(matches!(
            journal.consume(conflicting),
            Err(SteerError::Conflict)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn independent_out_of_order_evidence_is_append_only_and_idempotent() {
    let directory = Directory::new();
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    let value = saved(1);
    created(&mut journal, value.clone());
    let path = directory.path.join(filename(&value.id));
    let pending = fs::read(&path).unwrap();
    let recorded = Evidence {
        harness_recorded: true,
        ..Evidence::default()
    };
    let receipt = journal.apply(&value.id, recorded).unwrap();
    assert!(receipt.evidence.harness_recorded);
    assert!(!receipt.evidence.core_accepted);
    let first = fs::read(&path).unwrap();
    assert!(first.starts_with(&pending));
    journal.apply(&value.id, recorded).unwrap();
    assert_eq!(fs::read(&path).unwrap(), first);
    let receipt = journal
        .apply(
            &value.id,
            Evidence {
                core_accepted: true,
                ..Evidence::default()
            },
        )
        .unwrap();
    assert!(receipt.evidence.harness_recorded && receipt.evidence.core_accepted);
    assert!(fs::read(&path).unwrap().starts_with(&first));
    let durable = fs::read(&path).unwrap();
    assert!(matches!(
        journal.apply(
            &value.id,
            Evidence {
                not_dispatched: true,
                ..Evidence::default()
            }
        ),
        Err(SteerError::InvalidInput)
    ));
    assert_eq!(fs::read(&path).unwrap(), durable);
    assert!(
        !journal
            .lookup(&value.id)
            .unwrap()
            .unwrap()
            .persistence_failed
    );
}

#[test]
fn restart_projects_pending_as_unknown_without_replay_and_retains_positive_facts() {
    let directory = Directory::new();
    {
        let mut journal = SteerJournal::open(&directory.path).unwrap();
        created(&mut journal, saved(1));
        created(&mut journal, saved(2));
        journal
            .apply(
                &saved(2).id,
                Evidence {
                    core_accepted: true,
                    ..Evidence::default()
                },
            )
            .unwrap();
        created(&mut journal, saved(3));
        journal
            .apply(
                &saved(3).id,
                Evidence {
                    not_dispatched: true,
                    ..Evidence::default()
                },
            )
            .unwrap();
    }
    let path = directory.path.join(filename(&saved(1).id));
    let before = fs::read(&path).unwrap();
    let mut recovered = SteerJournal::open(&directory.path).unwrap();
    let unknown = recovered.lookup(&saved(1).id).unwrap().unwrap();
    assert!(unknown.recovered_after_restart && unknown.evidence.write_uncertain);
    assert!(!unknown.evidence.core_accepted && !unknown.evidence.harness_recorded);
    assert!(matches!(
        recovered.consume(saved(1)).unwrap(),
        Consume::Existing(_)
    ));
    assert_eq!(
        fs::read(&path).unwrap(),
        before,
        "recovery must not append or replay"
    );
    let accepted = recovered.lookup(&saved(2).id).unwrap().unwrap();
    assert!(accepted.recovered_after_restart && accepted.evidence.core_accepted);
    assert!(!accepted.evidence.write_uncertain);
    let rejected = recovered.lookup(&saved(3).id).unwrap().unwrap();
    assert!(rejected.evidence.not_dispatched && !rejected.evidence.write_uncertain);
}

#[test]
fn malformed_torn_oversized_and_nonmonotonic_records_reserve_only_their_ids() {
    for kind in 0..6 {
        let directory = Directory::new();
        initialized(&directory);
        let value = saved(1);
        let mut bytes = encode(&Line::Saved {
            operation: value.clone(),
        })
        .unwrap();
        match kind {
            0 => bytes = b"{malformed}\n".to_vec(),
            1 => {
                bytes.pop();
            }
            2 => bytes = vec![b' '; MAX_BYTES + 1],
            3 => bytes.extend_from_slice(
                &encode(&Line::Saved {
                    operation: value.clone(),
                })
                .unwrap(),
            ),
            4 => {
                bytes.extend_from_slice(
                    &encode(&Line::Evidence {
                        evidence: Evidence {
                            core_accepted: true,
                            ..Evidence::default()
                        },
                    })
                    .unwrap(),
                );
                bytes.extend_from_slice(
                    &encode(&Line::Evidence {
                        evidence: Evidence::default(),
                    })
                    .unwrap(),
                );
            }
            5 => {
                bytes = encode(&Line::Saved {
                    operation: saved(99),
                })
                .unwrap()
            }
            _ => unreachable!(),
        }
        let path = directory.path.join(filename(&value.id));
        create(&path, &bytes);
        let mut journal = SteerJournal::open(&directory.path).unwrap();
        assert_eq!(journal.lookup(&value.id), Err(SteerError::Storage));
        assert!(matches!(journal.consume(value), Err(SteerError::Storage)));
        created(&mut journal, saved(2));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn recognized_orphan_reserves_even_a_valid_canonical_id_without_deleting_either() {
    let directory = Directory::new();
    {
        let mut journal = SteerJournal::open(&directory.path).unwrap();
        created(&mut journal, saved(1));
    }
    let orphan = directory.path.join(format!(".{}-append.tmp", saved(1).id));
    create(&orphan, b"partial orphan");
    let canonical = directory.path.join(filename(&saved(1).id));
    let before = fs::read(&canonical).unwrap();
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    assert_eq!(journal.lookup(&saved(1).id), Err(SteerError::Storage));
    created(&mut journal, saved(2));
    assert_eq!(fs::read(canonical).unwrap(), before);
    assert_eq!(fs::read(orphan).unwrap(), b"partial orphan");
}

#[test]
fn capacity_counts_reserved_ids_and_never_evicts_or_overwrites_a_record() {
    let directory = Directory::new();
    initialized(&directory);
    create(&directory.path.join(filename(&saved(0).id)), b"torn");
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    for index in 1..MAX_OPERATIONS {
        created(&mut journal, saved(index));
    }
    assert!(matches!(
        journal.consume(saved(MAX_OPERATIONS)),
        Err(SteerError::Capacity)
    ));
    assert!(matches!(
        journal.consume(saved(1)).unwrap(),
        Consume::Existing(_)
    ));
    assert_eq!(
        fs::read(directory.path.join(filename(&saved(0).id))).unwrap(),
        b"torn"
    );
    assert!(
        !directory
            .path
            .join(filename(&saved(MAX_OPERATIONS).id))
            .exists()
    );
}

#[test]
fn initial_write_failure_reserves_the_id_and_other_operations_remain_usable() {
    let directory = Directory::new();
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    journal.fail_after_create = true;
    assert!(matches!(
        journal.consume(saved(1)),
        Err(SteerError::Storage)
    ));
    let failed = journal.lookup(&saved(1).id).unwrap().unwrap();
    assert!(failed.persistence_failed && failed.evidence.write_uncertain);
    assert!(!failed.evidence.core_accepted && !failed.evidence.harness_recorded);
    assert!(matches!(
        journal.consume(saved(1)).unwrap(),
        Consume::Existing(_)
    ));
    created(&mut journal, saved(2));
    drop(journal);
    let mut recovered = SteerJournal::open(&directory.path).unwrap();
    assert_eq!(recovered.lookup(&saved(1).id), Err(SteerError::Storage));
    assert!(matches!(
        recovered.consume(saved(1)),
        Err(SteerError::Storage)
    ));
    created(&mut recovered, saved(3));
}

#[test]
fn failed_evidence_append_never_publishes_unsaved_acceptance_or_recording() {
    let directory = Directory::new();
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    created(&mut journal, saved(1));
    let path = directory.path.join(filename(&saved(1).id));
    let before = fs::read(&path).unwrap();
    journal.fail_next_append = true;
    assert_eq!(
        journal.apply(
            &saved(1).id,
            Evidence {
                core_accepted: true,
                harness_recorded: true,
                ..Evidence::default()
            }
        ),
        Err(SteerError::Storage)
    );
    let receipt = journal.lookup(&saved(1).id).unwrap().unwrap();
    assert!(receipt.persistence_failed && receipt.evidence.write_uncertain);
    assert!(!receipt.evidence.core_accepted && !receipt.evidence.harness_recorded);
    assert_eq!(fs::read(&path).unwrap(), before);
    created(&mut journal, saved(2));
    drop(journal);
    let recovered = SteerJournal::open(&directory.path).unwrap();
    let receipt = recovered.lookup(&saved(1).id).unwrap().unwrap();
    assert!(receipt.evidence.write_uncertain && receipt.recovered_after_restart);
    assert!(!receipt.evidence.core_accepted && !receipt.evidence.harness_recorded);
}

#[test]
fn external_tail_and_name_replacement_are_preserved_and_disable_only_that_record() {
    for replace in [false, true] {
        let directory = Directory::new();
        let mut journal = SteerJournal::open(&directory.path).unwrap();
        created(&mut journal, saved(1));
        let path = directory.path.join(filename(&saved(1).id));
        let before = fs::read(&path).unwrap();
        if replace {
            fs::rename(&path, directory.path.join("original-retained")).unwrap();
            create(&path, b"foreign replacement");
        } else {
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"partial tail")
                .unwrap();
        }
        let foreign = fs::read(&path).unwrap();
        assert_eq!(
            journal.apply(
                &saved(1).id,
                Evidence {
                    core_accepted: true,
                    ..Evidence::default()
                }
            ),
            Err(SteerError::Storage)
        );
        assert_eq!(fs::read(&path).unwrap(), foreign);
        assert!(
            journal
                .lookup(&saved(1).id)
                .unwrap()
                .unwrap()
                .persistence_failed
        );
        if replace {
            assert_eq!(
                fs::read(directory.path.join("original-retained")).unwrap(),
                before
            );
        }
        created(&mut journal, saved(2));
    }
}

#[test]
fn lock_is_exclusive_raii_and_an_unmarked_directory_is_never_adopted() {
    let directory = Directory::new();
    let journal = SteerJournal::open(&directory.path).unwrap();
    assert!(matches!(
        SteerJournal::open(&directory.path),
        Err(SteerError::Unavailable)
    ));
    let inherited_descriptor = journal.lock.0.try_clone().unwrap();
    drop(journal);
    drop(SteerJournal::open(&directory.path).unwrap());
    drop(inherited_descriptor);
    let foreign = Directory::new();
    create(&foreign.path.join("unrelated"), b"preserve me");
    assert!(matches!(
        SteerJournal::open(&foreign.path),
        Err(SteerError::Storage)
    ));
    assert!(!foreign.path.join(DOMAIN).exists());
    assert_eq!(
        fs::read(foreign.path.join("unrelated")).unwrap(),
        b"preserve me"
    );
}

#[test]
fn recovery_resynchronizes_complete_positive_lines_and_rejects_sync_failure() {
    let directory = Directory::new();
    initialized(&directory);
    let value = saved(1);
    let mut bytes = encode(&Line::Saved {
        operation: value.clone(),
    })
    .unwrap();
    bytes.extend_from_slice(
        &encode(&Line::Evidence {
            evidence: Evidence {
                core_accepted: true,
                harness_recorded: true,
                ..Evidence::default()
            },
        })
        .unwrap(),
    );
    let name = filename(&value.id);
    let path = directory.path.join(&name);
    create(&path, &bytes);
    let (root, _, _) = open_root(&directory.path, false).unwrap();
    assert!(matches!(
        load_entry_with_sync(&root, &name, &value.id, |_, _| Err(SteerError::Storage)),
        Err(SteerError::Storage)
    ));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let recovered = load_entry_with_sync(&root, &name, &value.id, |held, parent| {
        held.sync_all().map_err(storage)?;
        parent.sync_all().map_err(storage)
    })
    .unwrap();
    assert!(recovered.receipt.recovered_after_restart);
    assert!(
        recovered.receipt.evidence.core_accepted && recovered.receipt.evidence.harness_recorded
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "sync must not rewrite evidence"
    );
}

#[test]
fn fifo_record_is_nonblocking_reserved_and_preserved() {
    let directory = Directory::new();
    initialized(&directory);
    let path = directory.path.join(filename(&saved(1).id));
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the CString is live and NUL terminated; only this owned temp path
    // is supplied, and mode is a plain libc mode_t permission mask.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    assert_eq!(journal.lookup(&saved(1).id), Err(SteerError::Storage));
    assert!(matches!(
        journal.consume(saved(1)),
        Err(SteerError::Storage)
    ));
    created(&mut journal, saved(2));
    use std::os::unix::fs::FileTypeExt;
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());
}

#[test]
fn roots_parent_swaps_and_private_mode_changes_cannot_redirect_writes() {
    let directory = Directory::new();
    let root = directory.path.join("journal");
    let mut journal = SteerJournal::open(&root).unwrap();
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, 0o700);
    created(&mut journal, saved(1));
    fs::rename(&root, directory.path.join("old")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        journal.consume(saved(2)),
        Err(SteerError::Storage)
    ));
    assert!(!root.join(filename(&saved(2).id)).exists());
    assert!(
        !directory
            .path
            .join("old")
            .join(filename(&saved(2).id))
            .exists()
    );
    let public = Directory::new();
    fs::set_permissions(&public.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        SteerJournal::open(&public.path),
        Err(SteerError::Storage)
    ));
}

#[test]
fn nofollow_rejects_root_parent_marker_and_lock_symlinks_without_touching_targets() {
    let directory = Directory::new();
    let real = directory.path.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path.join("alias");
    symlink(&real, &alias).unwrap();
    assert!(matches!(
        SteerJournal::open(&alias),
        Err(SteerError::Storage)
    ));
    assert!(matches!(
        SteerJournal::open(&alias.join("nested")),
        Err(SteerError::Storage)
    ));
    assert!(!real.join("nested").exists());
    for name in [DOMAIN, LOCK] {
        let fixture = Directory::new();
        let target = fixture.path.join("foreign");
        create(&target, b"do not modify");
        symlink(&target, fixture.path.join(name)).unwrap();
        assert!(matches!(
            SteerJournal::open(&fixture.path),
            Err(SteerError::Storage)
        ));
        assert_eq!(fs::read(target).unwrap(), b"do not modify");
    }
}

#[test]
fn unsafe_record_permissions_hardlinks_symlinks_socket_and_directory_reserve_ids() {
    for kind in 0..5 {
        let directory = Directory::new();
        initialized(&directory);
        let path = directory.path.join(filename(&saved(1).id));
        let bytes = encode(&Line::Saved {
            operation: saved(1),
        })
        .unwrap();
        let _listener = match kind {
            0 => {
                create(&path, &bytes);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                None
            }
            1 => {
                create(&path, &bytes);
                fs::hard_link(&path, directory.path.join("linked-original")).unwrap();
                None
            }
            2 => {
                create(&directory.path.join("foreign"), &bytes);
                symlink(directory.path.join("foreign"), &path).unwrap();
                None
            }
            3 => Some(UnixListener::bind(&path).unwrap()),
            4 => {
                fs::create_dir(&path).unwrap();
                None
            }
            _ => unreachable!(),
        };
        let mut journal = SteerJournal::open(&directory.path).unwrap();
        assert_eq!(journal.lookup(&saved(1).id), Err(SteerError::Storage));
        assert!(matches!(
            journal.consume(saved(1)),
            Err(SteerError::Storage)
        ));
        created(&mut journal, saved(2));
        assert!(fs::symlink_metadata(&path).is_ok());
    }
}

#[test]
fn strict_paths_and_operation_validation_do_not_create_records() {
    let directory = Directory::new();
    for path in [
        PathBuf::from("relative"),
        directory.path.join("missing/../other"),
        PathBuf::from(format!("{}/", directory.path.display())),
    ] {
        assert!(matches!(
            SteerJournal::open(&path),
            Err(SteerError::InvalidInput)
        ));
    }
    let mut journal = SteerJournal::open(&directory.path).unwrap();
    for invalid in ["../private", "short", "invalid.id"] {
        let mut value = saved(1);
        value.id = invalid.into();
        assert!(matches!(
            journal.consume(value),
            Err(SteerError::InvalidInput)
        ));
        assert_eq!(journal.lookup(invalid), Err(SteerError::InvalidInput));
    }
    let mut value = saved(1);
    value.text = "x".repeat(crate::MAX_TEXT_BYTES + 1);
    assert!(matches!(
        journal.consume(value),
        Err(SteerError::InvalidInput)
    ));
    assert_eq!(journal.slots(), 0);
}
