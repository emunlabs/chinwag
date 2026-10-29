use super::*;
use chinwag_signing::ConfigPreimageConstraint;
use std::{fs as stdfs, io::Write, os::unix::fs::MetadataExt};

#[test]
fn each_bound_snapshot_restriction_refuses_before_any_signing_git_child() {
    for kind in ["repo", "git", "config", "hash"] {
        let name = format!("principal-bound-{kind}");
        // Operator-supplied namespace when set, else a freshly seeded temp git repository.
        let repo = chinwag_test_fixtures::git_repo("CHINWAG_PRINCIPAL_QA_REPOSITORIES", &name);
        assert!(repo.is_absolute() && !repo.join(".chinwag").exists());
        let config_path = repo.join(".git/config");
        let before = stdfs::read(&config_path).unwrap();
        let meta_repo = stdfs::metadata(&repo).unwrap();
        let meta_git = stdfs::metadata(repo.join(".git")).unwrap();
        let meta_config = stdfs::metadata(&config_path).unwrap();
        let mut repo_id = (i32::try_from(meta_repo.dev()).unwrap(), meta_repo.ino());
        let mut git_id = (i32::try_from(meta_git.dev()).unwrap(), meta_git.ino());
        let mut config_id = (i32::try_from(meta_config.dev()).unwrap(), meta_config.ino());
        let mut hash: [u8; 32] = Sha256::digest(&before).into();
        match kind {
            "repo" => repo_id.1 ^= 1,
            "git" => git_id.1 ^= 1,
            "config" => config_id.1 ^= 1,
            "hash" => hash[0] ^= 1,
            _ => unreachable!(),
        }
        let secret = SigningSecret::generate().unwrap();
        let private = repo.join(".chinwag");
        let original = InitCoordinator::start_fresh_bound(
            InitPaths {
                repo: &repo,
                private_leaf: &private,
                key_name: OsStr::new("signer"),
                allowed_name: OsStr::new("allowed_signers"),
                scratch_name: OsStr::new("initial-store-signing"),
                principal: "fixture@chinwag.test",
                child_timeout: Duration::from_secs(2),
            },
            &secret,
            ConfigPreimageConstraint::new(repo_id, git_id, config_id, hash),
        );
        let InitReceipt::Config { transaction, .. } = original.receipt() else {
            panic!("expected original bound config refusal")
        };
        assert_eq!(transaction.state, TxState::Refused);
        assert_eq!(transaction.reason, "signing_preimage_changed");
        assert_eq!(transaction.child_pid, 0);
        assert_eq!(stdfs::read(&config_path).unwrap(), before);
        assert_eq!(
            stdfs::metadata(&config_path).unwrap().ino(),
            meta_config.ino()
        );
        assert!(!private.join("initial-store-signing").exists());
        assert!(private.join("signer").is_file() && private.join("allowed_signers").is_file());
        assert!(!private.join("state.crdb").exists());
        let mut out = stdfs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(
                repo.parent()
                    .unwrap()
                    .join(format!("{name}.principal-observation.json")),
            )
            .unwrap();
        writeln!(out, "{{\"case\":\"{name}\",\"outcome\":{{\"query_pid\":null,\"signing_child_pid\":0,\"bound_restriction\":\"{kind}\",\"reason\":\"signing_preimage_changed\",\"partial_material\":true,\"original_config_unchanged\":true,\"no_scratch_or_store\":true}},\"Genesis_complete\":false}}").unwrap();
        out.sync_all().unwrap();
    }
}
