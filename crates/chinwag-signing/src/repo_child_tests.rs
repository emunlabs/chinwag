use super::*;

fn injected(f: &Fixture, name: &str, hooks: TestHooks) -> ConfigTransaction {
    ConfigTransaction::begin_with(
        RepoSigningRequest {
            repo: &f.repo,
            private_directory: &f.private,
            key_name: OsStr::new("signer"),
            allowed_name: OsStr::new("allowed"),
            expected_public: &f.public,
            principal: PRINCIPAL,
            scratch_name: OsStr::new(name),
            child_timeout: Duration::from_secs(2),
        },
        hooks,
    )
}
fn controlled_program(f: &Fixture) -> TestHooks {
    TestHooks {
        program: Some((
            CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap(),
            [
                "--ignored",
                "--exact",
                "repo::tests::child_cases::controlled_config_child",
                "--nocapture",
            ]
            .map(|v| CString::new(v).unwrap())
            .to_vec(),
            vec![CString::new(format!("CHINWAG_CONFIG_FIXTURE={}", f.private.display())).unwrap()],
        )),
        post_rename_sync: None,
    }
}
#[test]
#[ignore = "controlled child fixture; not an independent coverage case"]
fn controlled_config_child() {
    let Some(path) = std::env::var_os("CHINWAG_CONFIG_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(path);
    fs::write(path.join("child-started"), b"nonsecret fixture started").unwrap();
    let bound = Instant::now() + Duration::from_secs(5);
    while !path.join("release-child").exists() {
        if Instant::now() >= bound {
            std::process::exit(29);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    std::process::exit(23);
}
#[test]
fn foreign_lock_tripwire_is_never_executed() {
    let f = Fixture::new(0o600);
    fs::write(f.repo.join(".git/config.lock"), b"foreign lock").unwrap();
    fs::write(f.private.join("release-child"), b"pre-released tripwire").unwrap();
    let tx = injected(&f, "tripwire", controlled_program(&f));
    assert_eq!(tx.state(), TxState::LockHeldElsewhere);
    assert!(!f.private.join("child-started").exists());
    assert_eq!(tx.receipt().child_pid, 0);
}
#[test]
fn known_nonzero_child_cleans_only_owned_lock_and_preserves_original() {
    let mut f = Fixture::new(0o600);
    let bytes = fs::read(f.config()).unwrap();
    let inode = fs::metadata(f.config()).unwrap().ino();
    let hooks = TestHooks {
        program: Some((CString::new("/usr/bin/false").unwrap(), vec![], vec![])),
        post_rename_sync: None,
    };
    let mut tx = injected(&f, "known-failure", hooks);
    assert_eq!(f.finish(&mut tx), TxState::StagedRejected);
    assert_eq!(fs::read(f.config()).unwrap(), bytes);
    assert_eq!(fs::metadata(f.config()).unwrap().ino(), inode);
    assert!(!f.repo.join(".git/config.lock").exists());
}
#[test]
fn unknown_retains_one_child_lock_and_scratch_then_observes_same_late_exit() {
    let mut f = Fixture::new(0o600);
    let original = fs::read(f.config()).unwrap();
    let mut tx = ConfigTransaction::begin_with(
        RepoSigningRequest {
            repo: &f.repo,
            private_directory: &f.private,
            key_name: OsStr::new("signer"),
            allowed_name: OsStr::new("allowed"),
            expected_public: &f.public,
            principal: PRINCIPAL,
            scratch_name: OsStr::new("unknown"),
            child_timeout: Duration::from_millis(100),
        },
        controlled_program(&f),
    );
    let pid = match tx.state() {
        TxState::Pending { pid } => pid,
        _ => panic!("{}", tx.reason()),
    };
    let bound = Instant::now() + Duration::from_secs(2);
    while !f.private.join("child-started").exists() && Instant::now() < bound {
        std::thread::sleep(Duration::from_millis(1));
    }
    let state = loop {
        let observed = tx.poll(Instant::now());
        if !matches!(observed, TxState::Pending { .. }) {
            break observed;
        }
        if Instant::now() >= bound {
            break observed;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    if state != (TxState::ChildUnknown { pid }) {
        fs::write(f.private.join("release-child"), b"release failed fixture").unwrap();
        let _ = f.finish(&mut tx);
        panic!("expected owned timeout after actual helper start: {state:?}");
    }
    assert_eq!(tx.poll(Instant::now()), state);
    assert_eq!(tx.receipt().child_pid, pid);
    assert_eq!(tx.observe_child().unwrap(), None);
    assert!(f.repo.join(".git/config.lock").exists());
    assert!(f.private.join("unknown/staged.config").is_file());
    assert!(!f.private.join("unknown/set0.out").exists());
    fs::write(f.private.join("release-child"), b"release original child").unwrap();
    let bound = Instant::now() + Duration::from_secs(3);
    loop {
        match tx.observe_child() {
            Ok(Some(Exit::Code(23))) => break,
            Ok(None) if Instant::now() < bound => std::thread::sleep(Duration::from_millis(1)),
            observed => {
                std::mem::forget(f.temporary.take());
                panic!("original child unresolved or wrong result: {observed:?}");
            }
        }
    }
    assert_eq!(tx.poll(Instant::now()), state);
    assert!(f.repo.join(".git/config.lock").exists());
    assert_eq!(fs::read(f.config()).unwrap(), original);
    assert_eq!(tx.receipt().child_pid, pid);
}
#[test]
fn post_rename_sync_failure_is_unconfirmed_and_preserves_new_foreign_lock() {
    fn fail_with_foreign_lock(git: &OwnedFd) -> Result<(), ()> {
        exclusive_file(git, "config.lock")
            .map_err(|_| ())?
            .write_all(b"new foreign lock after rename")
            .map_err(|_| ())?;
        Err(())
    }
    let mut f = Fixture::new(0o600);
    let inode = fs::metadata(f.config()).unwrap().ino();
    let mut tx = injected(
        &f,
        "post-rename-failure",
        TestHooks {
            program: None,
            post_rename_sync: Some(fail_with_foreign_lock),
        },
    );
    assert_eq!(f.finish(&mut tx), TxState::InstallUnconfirmed);
    assert_ne!(fs::metadata(f.config()).unwrap().ino(), inode);
    assert!(
        String::from_utf8(fs::read(f.config()).unwrap())
            .unwrap()
            .contains("signingkey")
    );
    assert_eq!(
        fs::read(f.repo.join(".git/config.lock")).unwrap(),
        b"new foreign lock after rename"
    );
    assert_eq!(tx.poll(Instant::now()), TxState::InstallUnconfirmed);
    assert_eq!(
        fs::read(f.repo.join(".git/config.lock")).unwrap(),
        b"new foreign lock after rename"
    );
}
