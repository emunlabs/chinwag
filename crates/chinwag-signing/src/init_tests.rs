use super::*;
use crate::{TxState, repo::TestHooks};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
#[path = "../tests/support/init_fixture.rs"]
mod fixture;
use fixture::{Fixture, config_state, key, snapshot};

#[test]
fn key_comments_are_refused_before_material_creation() {
    let f = Fixture::new();
    for comment in ["synthetic comment", "synthetic\nsecond-line"] {
        let mut signer = key(0xA5);
        signer.private.set_comment(comment);
        let init = InitCoordinator::start_fresh(f.paths("scratch"), &signer);
        assert!(matches!(
            init.receipt(),
            InitReceipt::Refused {
                failure: InitFailure::PublicKey,
                ..
            }
        ));
        assert!(!f.private.exists());
    }
}

#[test]
fn private_post_leaf_boundary_preserves_a_foreign_allowed_file() {
    let f = Fixture::new();
    let signer = key(0xA5);
    let dir = PrivateDirectory::create_new(&f.private).unwrap();
    fs::write(
        f.private.join("allowed"),
        b"purpose-created foreign fixture",
    )
    .unwrap();
    let before = snapshot(&f.private.join("allowed"));
    // This is the private post-leaf boundary, not a concurrent public fresh call.
    let init = InitCoordinator::complete_fresh(
        dir,
        f.paths("scratch"),
        &signer,
        signer.public_bytes(),
        TestHooks::default(),
    );
    assert!(matches!(
        init.receipt(),
        InitReceipt::MaterialIncomplete {
            progress: InitProgress::KeyConfirmed,
            failure: InitFailure::Storage(Error::Exists),
            ..
        }
    ));
    assert_eq!(snapshot(&f.private.join("allowed")), before);
    assert!(f.private.join("signer").is_file());
    assert!(!f.repo.join(".git/config.lock").exists());
}

#[test]
fn unknown_child_stays_owned_through_the_coordinator_and_late_observation() {
    let mut f = Fixture::new();
    let signer = key(0xA5);
    let original = snapshot(&f.config());
    // Retain on any panic while the controlled original child may still exist.
    std::mem::forget(f.temporary.take());
    let hooks = TestHooks::for_program(
        CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap(),
        [
            "--ignored",
            "--exact",
            "repo::tests::child_cases::controlled_config_child",
            "--nocapture",
        ]
        .map(|s| CString::new(s).unwrap())
        .to_vec(),
        vec![CString::new(format!("CHINWAG_CONFIG_FIXTURE={}", f.private.display())).unwrap()],
    );
    let mut paths = f.paths("unknown");
    paths.child_timeout = Duration::from_millis(100);
    let mut init = InitCoordinator::fresh_inner(paths, &signer, hooks);
    let pid = match config_state(init.receipt()) {
        TxState::Pending { pid } => pid,
        other => panic!("{other:?}"),
    };
    let bound = Instant::now() + Duration::from_secs(2);
    while !f.private.join("child-started").exists() && Instant::now() < bound {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(f.private.join("child-started").exists());
    while matches!(
        config_state(init.poll(Instant::now())),
        TxState::Pending { .. }
    ) {
        assert!(Instant::now() < bound);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(config_state(init.receipt()), TxState::ChildUnknown { pid });
    assert_eq!(init.observe_child().unwrap(), None);
    assert!(f.repo.join(".git/config.lock").is_file());
    assert!(f.private.join("unknown/staged.config").is_file());
    assert!(!f.private.join("unknown/set0.out").exists());
    fs::write(
        f.private.join("release-child"),
        b"release only original child",
    )
    .unwrap();
    let bound = Instant::now() + Duration::from_secs(3);
    loop {
        match init.observe_child().unwrap() {
            Some(Exit::Code(23)) => break,
            None if Instant::now() < bound => std::thread::sleep(Duration::from_millis(1)),
            other => panic!("original child unresolved/wrong: {other:?}"),
        }
    }
    assert_eq!(
        config_state(init.poll(Instant::now())),
        TxState::ChildUnknown { pid }
    );
    assert_eq!(snapshot(&f.config()), original);
    assert!(f.repo.join(".git/config.lock").is_file());
    fs::remove_dir_all(&f.root).unwrap();
}
