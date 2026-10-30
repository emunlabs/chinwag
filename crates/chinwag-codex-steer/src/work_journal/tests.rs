use super::*;
use crate::RuntimePolicyDeclaration;
use std::{
    ffi::CString,
    fs::{self, OpenOptions},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    time::Duration,
};

const ID: &str = "work-human-start-0001";
const TEXT: &str = "Keep this exact human task\nincluding trailing spaces  ";

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    config: WorkConfig,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::Builder::new()
            .prefix("cw-work-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let cwd = root.join("workdir");
        fs::create_dir(&cwd).unwrap();
        fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700)).unwrap();
        let config = WorkConfig::new(
            &root.join("declared.sock"),
            &cwd,
            &root.join("journal"),
            RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin,
        )
        .unwrap();
        assert!(!config.socket.exists(), "intent fixtures never connect");
        Self {
            _temp: temp,
            root,
            config,
        }
    }
    fn record(&self) -> PathBuf {
        self.config.journal.join(RECORD)
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn created(journal: &mut WorkJournal) -> CommittedWork {
    match journal.consume(ID, TEXT, deadline()).unwrap() {
        ConsumedWork::Created(committed) => committed,
        ConsumedWork::Existing(_) => panic!("expected first durable work intent"),
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

#[test]
fn consume_persists_exact_intent_before_returning_the_private_capsule() {
    let fixture = Fixture::new();
    let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
    assert!(journal.receipt().is_none());
    let committed = created(&mut journal);
    let bytes = fs::read(fixture.record()).unwrap();
    let Line::Intent { intent } = serde_json::from_slice(&bytes).unwrap() else {
        panic!("immutable intent first")
    };
    assert_eq!(intent.id, committed.id());
    assert_eq!(intent.text, committed.text());
    assert_eq!(intent.socket, fixture.config.socket);
    assert_eq!(intent.cwd, committed.cwd());
    assert!(
        intent.dedicated_explicit_login_consent && committed.dedicated_explicit_login_consent()
    );
    assert!(committed.deadline() > Instant::now());
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(
        fs::metadata(fixture.record()).unwrap().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(&fixture.config.journal).unwrap().mode() & 0o7777,
        0o700
    );
    let receipt = journal.receipt().unwrap();
    assert_eq!(receipt.id, ID);
    assert_eq!(receipt.text, TEXT);
    assert!(!receipt.connected && !receipt.initialized && !receipt.evidence.core_accepted);
    assert!(!fixture.config.socket.exists());
}

#[test]
fn exact_repeat_is_cached_even_after_deadline_and_conflicts_cannot_create_a_second_intent() {
    let fixture = Fixture::new();
    let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
    let _committed = created(&mut journal);
    let before = fs::read(fixture.record()).unwrap();
    match journal
        .consume(ID, TEXT, Instant::now() - Duration::from_secs(1))
        .unwrap()
    {
        ConsumedWork::Existing(receipt) => {
            assert_eq!(receipt.id, ID);
            assert_eq!(receipt.text, TEXT);
        }
        ConsumedWork::Created(_) => panic!("duplicate must not mint another capsule"),
    }
    for (id, text) in [
        ("work-human-start-0002", TEXT),
        (ID, "Different human task"),
    ] {
        assert!(matches!(
            journal.consume(id, text, deadline()),
            Err(SteerError::Conflict)
        ));
    }
    assert_eq!(fs::read(fixture.record()).unwrap(), before);
    assert_eq!(journal.lines, 1);
}

#[test]
fn expired_start_creates_no_record_or_capsule() {
    let fixture = Fixture::new();
    let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
    assert!(matches!(
        journal.consume(ID, TEXT, Instant::now() - Duration::from_secs(1)),
        Err(SteerError::PermissionDenied)
    ));
    assert!(!fixture.record().exists());
    assert!(journal.intent.is_none() && journal.receipt().is_none());
    assert_eq!(journal.lines, 0);
    let _committed = created(&mut journal);
    assert_eq!(
        journal.lines, 1,
        "only a fresh explicit consumption creates a record"
    );
}

#[test]
fn thread_epoch_binding_and_positive_recovery_never_mint_a_recovered_capsule() {
    let fixture = Fixture::new();
    {
        let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
        let committed = created(&mut journal);
        let _initial = journal
            .commit_initial(&committed, "owned-thread", &"a".repeat(32))
            .unwrap();
        assert_eq!(journal.epoch.as_deref(), Some("a".repeat(32).as_str()));
        let mut receipt = journal.receipt().unwrap();
        receipt.accepted_turn_id = Some("initial-turn".into());
        receipt.evidence = Evidence {
            frame_written: true,
            core_accepted: true,
            harness_recorded: true,
            ..Evidence::default()
        };
        journal.update(receipt.clone()).unwrap();
        let before = fs::read(fixture.record()).unwrap();
        assert!(
            journal
                .commit_initial(&committed, "other-thread", &"a".repeat(32))
                .is_err()
        );
        assert!(
            journal
                .commit_initial(&committed, "owned-thread", &"b".repeat(32))
                .is_err()
        );
        assert_eq!(fs::read(fixture.record()).unwrap(), before);
    }
    let before = fs::read(fixture.record()).unwrap();
    let mut recovered = WorkJournal::open(fixture.config.clone()).unwrap();
    let receipt = recovered.receipt().unwrap();
    assert!(receipt.recovered_after_restart && receipt.connected && receipt.initialized);
    assert!(receipt.evidence.core_accepted && receipt.evidence.harness_recorded);
    assert_eq!(receipt.thread_id.as_deref(), Some("owned-thread"));
    assert_eq!(receipt.accepted_turn_id.as_deref(), Some("initial-turn"));
    assert_eq!(recovered.epoch.as_deref(), Some("a".repeat(32).as_str()));
    assert!(matches!(
        recovered.consume(ID, TEXT, deadline()).unwrap(),
        ConsumedWork::Existing(_)
    ));
    assert_eq!(fs::read(fixture.record()).unwrap(), before);
}

#[test]
fn append_failure_on_readonly_same_inode_keeps_only_last_durable_evidence() {
    let fixture = Fixture::new();
    let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
    let committed = created(&mut journal);
    journal
        .commit_initial(&committed, "owned-thread", &"a".repeat(32))
        .unwrap();
    let before = fs::read(fixture.record()).unwrap();
    let held_before = journal.file.as_ref().unwrap().metadata().unwrap();
    let readonly = File::open(fixture.record()).unwrap();
    assert_eq!(readonly.metadata().unwrap().ino(), held_before.ino());
    journal.file = Some(readonly);
    let mut accepted = journal.receipt().unwrap();
    accepted.accepted_turn_id = Some("initial-turn".into());
    accepted.evidence.core_accepted = true;
    assert_eq!(journal.update(accepted), Err(SteerError::Storage));
    let last = journal.receipt().unwrap();
    assert!(last.persistence_failed && last.initialized);
    assert!(!last.evidence.core_accepted && !last.evidence.harness_recorded);
    assert!(last.accepted_turn_id.is_none());
    assert_eq!(fs::read(fixture.record()).unwrap(), before);
    assert!(matches!(
        journal.consume(ID, TEXT, deadline()).unwrap(),
        ConsumedWork::Existing(_)
    ));
    assert!(
        journal
            .consume("work-human-start-0002", "Another task", deadline())
            .is_err()
    );
}

#[test]
fn torn_corrupt_oversized_and_regressed_logs_preserve_bytes_and_block_new_start() {
    for kind in 0..5 {
        let fixture = Fixture::new();
        {
            let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
            let _committed = created(&mut journal);
        }
        let mut bytes = fs::read(fixture.record()).unwrap();
        match kind {
            0 => {
                bytes.pop();
            }
            1 => bytes = b"{not json}\n".to_vec(),
            2 => bytes = vec![b' '; MAX_BYTES + 1],
            3 => bytes.extend_from_slice(b"{\"kind\":\"unknown\"}\n"),
            4 => {
                let intent = WorkIntent {
                    id: ID.into(),
                    text: TEXT.into(),
                    socket: fixture.config.socket.clone(),
                    cwd: fixture.config.workdir.clone(),
                    dedicated_explicit_login_consent: true,
                };
                let mut positive = initial_receipt(&intent);
                positive.connected = true;
                bytes.extend_from_slice(
                    &encode(&Line::Receipt {
                        receipt: positive,
                        epoch: None,
                    })
                    .unwrap(),
                );
                bytes.extend_from_slice(
                    &encode(&Line::Receipt {
                        receipt: initial_receipt(&intent),
                        epoch: None,
                    })
                    .unwrap(),
                );
            }
            _ => unreachable!(),
        }
        fs::write(fixture.record(), &bytes).unwrap();
        assert!(matches!(
            WorkJournal::open(fixture.config.clone()),
            Err(SteerError::Storage)
        ));
        assert_eq!(fs::read(fixture.record()).unwrap(), bytes);
    }
}

#[test]
fn private_record_mode_links_and_special_nodes_are_never_adopted_or_modified() {
    for kind in 0..6 {
        let fixture = Fixture::new();
        drop(WorkJournal::open(fixture.config.clone()).unwrap());
        let record = fixture.record();
        let _listener = match kind {
            0 => {
                create(&record, b"unread foreign bytes");
                fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
                None
            }
            1 => {
                create(&record, b"hardlinked bytes");
                fs::hard_link(&record, fixture.root.join("linked")).unwrap();
                None
            }
            2 => {
                create(&fixture.root.join("foreign"), b"private target");
                symlink(fixture.root.join("foreign"), &record).unwrap();
                None
            }
            3 => Some(UnixListener::bind(&record).unwrap()),
            4 => {
                fs::create_dir(&record).unwrap();
                None
            }
            5 => {
                let path = CString::new(record.as_os_str().as_bytes()).unwrap();
                // SAFETY: this live CString names only the owned temp fixture.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                None
            }
            _ => unreachable!(),
        };
        let before = fs::symlink_metadata(&record).unwrap();
        let contents = before.is_file().then(|| fs::read(&record).unwrap());
        assert!(WorkJournal::open(fixture.config.clone()).is_err());
        let after = fs::symlink_metadata(&record).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.file_type(), after.file_type());
        if let Some(contents) = contents {
            assert_eq!(fs::read(&record).unwrap(), contents);
        }
        if kind == 2 {
            assert_eq!(
                fs::read(fixture.root.join("foreign")).unwrap(),
                b"private target"
            );
        }
        if kind == 5 {
            assert!(after.file_type().is_fifo());
        }
    }
}

#[test]
fn immutable_domain_exclusive_lock_and_private_path_faults_preserve_prior_state() {
    let fixture = Fixture::new();
    let journal = WorkJournal::open(fixture.config.clone()).unwrap();
    assert!(matches!(
        WorkJournal::open(fixture.config.clone()),
        Err(SteerError::Unavailable)
    ));
    let duplicate = journal.lock.0.try_clone().unwrap();
    drop(journal);
    drop(WorkJournal::open(fixture.config.clone()).unwrap());
    drop(duplicate);
    fs::write(fixture.config.journal.join(MARKER), b"foreign domain\n").unwrap();
    assert!(WorkJournal::open(fixture.config.clone()).is_err());
    assert_eq!(
        fs::read(fixture.config.journal.join(MARKER)).unwrap(),
        b"foreign domain\n"
    );
    assert!(!fixture.record().exists());

    let unmarked = Fixture::new();
    fs::create_dir(&unmarked.config.journal).unwrap();
    fs::set_permissions(&unmarked.config.journal, fs::Permissions::from_mode(0o700)).unwrap();
    create(&unmarked.record(), b"unmarked original\n");
    assert!(WorkJournal::open(unmarked.config.clone()).is_err());
    assert!(!unmarked.config.journal.join(MARKER).exists());
    assert_eq!(fs::read(unmarked.record()).unwrap(), b"unmarked original\n");

    let alias = Fixture::new();
    let physical = alias.root.join("physical");
    fs::create_dir(&physical).unwrap();
    fs::set_permissions(&physical, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&physical, &alias.config.journal).unwrap();
    assert!(WorkJournal::open(alias.config.clone()).is_err());
    assert!(!physical.join(RECORD).exists());

    for name in [LOCK, MARKER] {
        let linked = Fixture::new();
        fs::create_dir(&linked.config.journal).unwrap();
        fs::set_permissions(&linked.config.journal, fs::Permissions::from_mode(0o700)).unwrap();
        let target = linked.root.join("unrelated-target");
        create(&target, b"unchanged private bytes");
        symlink(&target, linked.config.journal.join(name)).unwrap();
        assert!(WorkJournal::open(linked.config.clone()).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged private bytes");
    }

    let public = Fixture::new();
    drop(WorkJournal::open(public.config.clone()).unwrap());
    fs::set_permissions(&public.config.journal, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(WorkJournal::open(public.config.clone()).is_err());
    assert!(!public.record().exists());
}

#[test]
fn existing_intent_rejects_different_launch_paths_and_late_record_replacement() {
    let fixture = Fixture::new();
    let mut journal = WorkJournal::open(fixture.config.clone()).unwrap();
    let _committed = created(&mut journal);
    let before = fs::read(fixture.record()).unwrap();
    fs::rename(fixture.record(), fixture.root.join("retained-original")).unwrap();
    create(&fixture.record(), b"late foreign replacement");
    assert!(journal.consume(ID, TEXT, deadline()).is_err());
    assert_eq!(
        fs::read(fixture.record()).unwrap(),
        b"late foreign replacement"
    );
    assert_eq!(
        fs::read(fixture.root.join("retained-original")).unwrap(),
        before
    );
    drop(journal);
    let other = Fixture::new();
    {
        let mut journal = WorkJournal::open(other.config.clone()).unwrap();
        let _committed = created(&mut journal);
    }
    let before = fs::read(other.record()).unwrap();
    let changed = WorkConfig::new(
        &other.root.join("different.sock"),
        &other.config.workdir,
        &other.config.journal,
        RuntimePolicyDeclaration::DedicatedRuntimeWithExplicitLogin,
    )
    .unwrap();
    assert!(WorkJournal::open(changed).is_err());
    assert_eq!(fs::read(other.record()).unwrap(), before);
}
