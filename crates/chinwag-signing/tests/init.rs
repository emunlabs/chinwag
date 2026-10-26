#![cfg(target_os = "macos")]
use chinwag_signing::{
    Error, InitCoordinator, InitFailure, InitMaterial, InitPaths, InitProgress, InitReceipt,
    PrivateDirectory, SigningSecret, TxState,
};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};
#[path = "support/init_fixture.rs"]
mod fixture;
use fixture::{Fixture, PRINCIPAL, config_state, key, snapshot};

impl Fixture {
    fn finish(&mut self, init: &mut InitCoordinator) -> InitReceipt {
        let bound = Instant::now() + Duration::from_secs(12);
        loop {
            let receipt = init.poll(Instant::now());
            match config_state(receipt) {
                TxState::Pending { .. } if Instant::now() < bound => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                TxState::Pending { .. } | TxState::ChildUnknown { .. } => {
                    std::mem::forget(self.temporary.take());
                    panic!("owned coordinator child unresolved; fixture retained: {receipt:?}");
                }
                _ => return receipt,
            }
        }
    }
}

#[test]
fn fresh_sign_verify_and_explicit_reuse_preserve_confirmed_material() {
    let mut f = Fixture::new();
    let a5 = key(0xA5);
    let pin = a5.public_bytes();
    let mut init = InitCoordinator::start_fresh(f.paths("fresh"), &a5);
    assert_eq!(config_state(f.finish(&mut init)), TxState::Installed);
    match init.receipt() {
        InitReceipt::Config {
            material: InitMaterial::FreshCreated,
            transaction,
        } => assert_eq!(transaction.expected_public, pin),
        other => panic!("{other:?}"),
    }
    assert_eq!(fs::metadata(&f.private).unwrap().mode() & 0o7777, 0o700);
    for name in ["signer", "allowed"] {
        assert_eq!(
            fs::metadata(f.private.join(name)).unwrap().mode() & 0o7777,
            0o600
        );
    }
    assert!(
        f.git(&[
            "commit",
            "--allow-empty",
            "-S",
            "-m",
            "synthetic coordinator fixture"
        ])
        .status
        .success()
    );
    assert!(f.git(&["verify-commit", "HEAD"]).status.success());
    let material = PrivateDirectory::open(&f.private).unwrap();
    material
        .write_new_allowed_signers(OsStr::new("wrong"), PRINCIPAL, &key(0xA6))
        .unwrap();
    let setting = format!(
        "gpg.ssh.allowedSignersFile={}",
        f.private.join("wrong").display()
    );
    assert!(
        !f.git(&["-c", &setting, "verify-commit", "HEAD"])
            .status
            .success()
    );
    let before = [
        snapshot(&f.private.join("signer")),
        snapshot(&f.private.join("allowed")),
        snapshot(&f.config()),
    ];
    let second = InitCoordinator::start_fresh(f.paths("second-fresh"), &a5);
    assert!(matches!(
        second.receipt(),
        InitReceipt::Refused {
            failure: InitFailure::Storage(Error::Exists),
            ..
        }
    ));
    let wrong = InitCoordinator::start_reuse(f.paths("wrong-pin"), &key(0xA6).public_bytes());
    assert!(matches!(
        wrong.receipt(),
        InitReceipt::Refused {
            failure: InitFailure::Storage(Error::PublicMismatch),
            ..
        }
    ));
    assert!(!f.private.join("wrong-pin").exists());
    let mut reused = InitCoordinator::start_reuse(f.paths("reuse"), &pin);
    assert_eq!(config_state(f.finish(&mut reused)), TxState::Unchanged);
    assert!(matches!(
        reused.receipt(),
        InitReceipt::Config {
            material: InitMaterial::ExistingKeyConfirmed,
            ..
        }
    ));
    assert_eq!(
        before,
        [
            snapshot(&f.private.join("signer")),
            snapshot(&f.private.join("allowed")),
            snapshot(&f.config())
        ]
    );
    assert!(f.private.join("reuse").is_dir());
    assert!(!f.repo.join(".git/config.lock").exists());
}

#[test]
fn invalid_pure_inputs_refuse_before_creating_a_leaf() {
    let f = Fixture::new();
    let signer = key(0xA5);
    for case in 0..8 {
        let mut paths = f.paths("scratch");
        match case {
            0 => paths.principal = "*",
            1 => paths.key_name = paths.allowed_name,
            2 => paths.scratch_name = paths.key_name,
            3 => paths.allowed_name = OsStr::new("../allowed"),
            4 => paths.child_timeout = Duration::ZERO,
            5 => paths.child_timeout = Duration::from_secs(61),
            6 => paths.private_leaf = Path::new("relative"),
            _ => paths.repo = Path::new("relative"),
        }
        let mut init = InitCoordinator::start_fresh(paths, &signer);
        assert!(matches!(init.receipt(), InitReceipt::Refused { .. }));
        assert_eq!(init.poll(Instant::now()), init.receipt());
        assert!(init.observe_child().is_err());
        assert!(!f.private.exists());
    }
}

#[test]
fn actual_filesystem_name_limits_leave_typed_confirmed_partial_material() {
    for allowed in [false, true] {
        let f = Fixture::new();
        let signer = key(0xA5);
        let too_long = "a".repeat(256);
        let mut paths = f.paths("scratch");
        if allowed {
            paths.allowed_name = OsStr::new(&too_long);
        } else {
            paths.key_name = OsStr::new(&too_long);
        }
        let init = InitCoordinator::start_fresh(paths, &signer);
        let expected = if allowed {
            InitProgress::KeyConfirmed
        } else {
            InitProgress::LeafConfirmed
        };
        assert!(
            matches!(init.receipt(), InitReceipt::MaterialIncomplete { progress, failure: InitFailure::Storage(Error::Create), .. } if progress == expected)
        );
        assert_eq!(fs::metadata(&f.private).unwrap().mode() & 0o7777, 0o700);
        assert!(!f.repo.join(".git/config.lock").exists());
        assert!(!f.private.join("scratch").exists());
        if allowed {
            assert_eq!(
                PrivateDirectory::open(&f.private)
                    .unwrap()
                    .read_existing(OsStr::new("signer"), &signer.public_bytes())
                    .unwrap()
                    .public_bytes(),
                signer.public_bytes()
            );
        } else {
            assert_eq!(fs::read_dir(&f.private).unwrap().count(), 0);
        }
    }
}

#[test]
fn later_repo_refusals_keep_material_and_original_config() {
    for case in ["include", "wrong-email", "missing-repo"] {
        let mut f = Fixture::new();
        let signer = key(0xA5);
        if case == "include" {
            assert!(
                f.git(&["config", "include.path", "never-open-this"])
                    .status
                    .success()
            );
        }
        if case == "wrong-email" {
            assert!(
                f.git(&["config", "user.email", "other@chinwag.invalid"])
                    .status
                    .success()
            );
        }
        let original = snapshot(&f.config());
        let missing = f.root.join("missing-repo");
        let mut paths = f.paths("scratch");
        if case == "missing-repo" {
            paths.repo = &missing;
        }
        let mut init = InitCoordinator::start_fresh(paths, &signer);
        assert_eq!(config_state(f.finish(&mut init)), TxState::Refused);
        assert_eq!(snapshot(&f.config()), original);
        assert!(f.private.join("signer").is_file());
        assert!(f.private.join("allowed").is_file());
        assert!(!f.repo.join(".git/config.lock").exists());
    }
}
#[test]
fn foreign_lock_has_no_child_and_reuse_does_not_repair_allowed_bytes() {
    let f = Fixture::new();
    let signer = key(0xA5);
    let lock = f.repo.join(".git/config.lock");
    fs::write(&lock, b"purpose-created foreign lock").unwrap();
    let before = snapshot(&lock);
    let init = InitCoordinator::start_fresh(f.paths("fresh"), &signer);
    match init.receipt() {
        InitReceipt::Config { transaction, .. } => {
            assert_eq!(transaction.state, TxState::LockHeldElsewhere);
            assert_eq!(transaction.child_pid, 0);
        }
        other => panic!("{other:?}"),
    }
    fs::write(f.private.join("allowed"), b"foreign allowed line").unwrap();
    let allowed = snapshot(&f.private.join("allowed"));
    let reuse = InitCoordinator::start_reuse(f.paths("reuse"), &signer.public_bytes());
    match reuse.receipt() {
        InitReceipt::Config {
            material: InitMaterial::ExistingKeyConfirmed,
            transaction,
        } => {
            assert_eq!(transaction.state, TxState::Refused);
            assert_eq!(transaction.child_pid, 0);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(snapshot(&lock), before);
    assert_eq!(snapshot(&f.private.join("allowed")), allowed);
    assert!(!f.private.join("reuse").exists());
}
