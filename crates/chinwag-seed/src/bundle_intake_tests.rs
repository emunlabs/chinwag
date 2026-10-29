use super::*;
use ssh_key::{LineEnding, PrivateKey, private::Ed25519Keypair};
use std::{
    ffi::OsString,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    hooks: PathBuf,
    bundle: PathBuf,
    signers: PathBuf,
    key: PathBuf,
    builder: [u8; 32],
    oid: String,
    tree: String,
}

impl Fixture {
    async fn new(format: &str, actual_signer_seed: u8) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("source");
        let hooks = root.join("fixture-hooks");
        for path in [&source, &hooks] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = root.join("temporary-fixture-key");
        let actual = PrivateKey::from(Ed25519Keypair::from_seed(&[actual_signer_seed; 32]));
        actual.write_openssh_file(&key, LineEnding::LF).unwrap();
        let builder_pair = Ed25519Keypair::from_seed(&[0x51; 32]);
        let builder = builder_pair.public.0;
        let builder_key = PrivateKey::from(builder_pair);
        let signers = root.join("builder-signers");
        write_private(
            &signers,
            format!(
                "fixture {}\n",
                builder_key.public_key().to_openssh().unwrap()
            )
            .as_bytes(),
        );
        let mut fixture = Self {
            _temporary: temporary,
            root: root.clone(),
            source,
            hooks,
            bundle: root.join("received.bundle"),
            signers,
            key,
            builder,
            oid: String::new(),
            tree: String::new(),
        };
        fixture
            .git(&[
                "init".into(),
                "--initial-branch=fixture".into(),
                format!("--object-format={format}").into(),
                prefixed("--template=", &fixture.hooks),
            ])
            .await;
        fs::create_dir(fixture.source.join("src")).unwrap();
        write_private(
            &fixture.source.join("Cargo.toml"),
            b"[package]\nname='temporary-bundle-fixture'\nversion='0.0.0'\nedition='2024'\n",
        );
        write_private(
            &fixture.source.join("src/lib.rs"),
            b"#[test] fn received_source() { assert_eq!(6 * 7, 42); }\n",
        );
        write_private(
            &fixture.source.join("Cargo.lock"),
            b"version = 4\n\n[[package]]\nname = \"temporary-bundle-fixture\"\nversion = \"0.0.0\"\n",
        );
        fixture.git(&["add".into(), ".".into()]).await;
        fixture
            .git(&[
                "-c".into(),
                "user.name=Temporary test fixture".into(),
                "-c".into(),
                "user.email=fixture@example.invalid".into(),
                "-c".into(),
                prefixed("user.signingkey=", &fixture.key),
                "commit".into(),
                "-S".into(),
                "-m".into(),
                "Temporary fixture, not Genesis".into(),
            ])
            .await;
        fixture.oid = fixture.line(&["rev-parse".into(), "HEAD".into()]).await;
        fixture.tree = fixture
            .line(&["rev-parse".into(), "HEAD^{tree}".into()])
            .await;
        fixture
            .git(&[
                "bundle".into(),
                "create".into(),
                fixture.bundle.clone().into_os_string(),
                "HEAD".into(),
            ])
            .await;
        fs::set_permissions(&fixture.bundle, fs::Permissions::from_mode(0o600)).unwrap();
        fixture
    }

    async fn git(&self, args: &[OsString]) -> CommandReport {
        let mut command = Command::new("/usr/bin/git");
        command
            .current_dir(&self.source)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.hooks)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-c", "core.fsmonitor=false", "-c", "gpg.format=ssh"])
            .args(["-c", "gpg.ssh.program=/usr/bin/ssh-keygen"])
            .arg("-c")
            .arg(prefixed("core.hooksPath=", &self.hooks))
            .args(args);
        let job = Arc::new(Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap());
        let result = execute_guarded(command, Duration::from_secs(10), OUTPUT_LIMIT, job)
            .await
            .unwrap();
        assert!(result.success, "fixture command failed: {result:?}");
        result
    }

    async fn line(&self, args: &[OsString]) -> String {
        String::from_utf8(self.git(args).await.stdout)
            .unwrap()
            .trim_end_matches('\n')
            .to_owned()
    }

    fn config(&self, label: &str) -> BundleOperatorConfig {
        let quarantine = self.root.join(format!("quarantine-{label}"));
        let templates = self.root.join(format!("templates-{label}"));
        for path in [&quarantine, &templates] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bytes = fs::read(&self.bundle).unwrap();
        BundleOperatorConfig {
            bundle: self.bundle.clone(),
            quarantine,
            empty_templates: templates,
            builder_signers: self.signers.clone(),
            expected: BundleExpectation::new(
                &self.oid,
                &self.tree,
                *blake3::hash(&bytes).as_bytes(),
                bytes.len() as u64,
                self.builder,
            )
            .unwrap(),
        }
    }

    fn source_bytes(&self) -> Vec<Vec<u8>> {
        [
            ".git/HEAD",
            ".git/config",
            ".git/index",
            "Cargo.toml",
            "src/lib.rs",
        ]
        .into_iter()
        .map(|path| fs::read(self.source.join(path)).unwrap())
        .collect()
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn empty_private_directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn verified_commit_materializes_and_actual_received_source_passes_offline_cargo() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new(format, 0x51).await;
        let config = fixture.config("materialize");
        let quarantine = config.quarantine.clone();
        let before = fixture.source_bytes();
        let verifier = BundleVerifier::open(config).unwrap();
        let verified = verifier.verify().await.unwrap();
        let workspace = fixture.root.join("new-received-worktree");
        empty_private_directory(&workspace);
        let received = verified.materialize(&workspace).await.unwrap();
        assert_eq!(received.expectation().oid(), fixture.oid);
        for path in ["Cargo.toml", "Cargo.lock", "src/lib.rs"] {
            assert_eq!(
                fs::read(workspace.join(path)).unwrap(),
                fs::read(fixture.source.join(path)).unwrap()
            );
        }
        assert!(!workspace.join(".git").exists());
        let marker = fs::read(quarantine.join(".chinwag-materialization-attempt.json")).unwrap();
        assert!(
            !workspace
                .join(".chinwag-materialization-attempt.json")
                .exists()
        );
        let target = workspace.join("target");
        let cache = fixture.root.join("empty-cargo-cache");
        empty_private_directory(&target);
        empty_private_directory(&cache);
        let rustc = chinwag_test_fixtures::rustc();
        let cargo = crate::cargo::CargoVerifier::new(
            received.path(),
            rustc.parent().unwrap(),
            &cache,
            &target,
        )
        .unwrap();
        let output = cargo.verify().await.unwrap();
        assert!(output.passed(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.test.unwrap().stdout).contains("1 passed"));
        assert_eq!(fixture.source_bytes(), before);
        assert_eq!(
            fs::read(quarantine.join(".chinwag-materialization-attempt.json")).unwrap(),
            marker
        );
        assert!(matches!(
            verifier.verify().await,
            Err(Error::AlreadyAttempted)
        ));
    }
}

#[tokio::test]
async fn materialization_refuses_occupied_or_overlapping_workspace() {
    let fixture = Fixture::new("sha1", 0x51).await;
    for overlap in [false, true] {
        let config = fixture.config(if overlap { "overlap" } else { "occupied" });
        let quarantine = config.quarantine.clone();
        let verified = BundleVerifier::open(config)
            .unwrap()
            .verify()
            .await
            .unwrap();
        let workspace = if overlap {
            quarantine.join("new-child")
        } else {
            fixture.root.join("occupied-worktree")
        };
        empty_private_directory(&workspace);
        if !overlap {
            write_private(&workspace.join("preserve"), b"keep");
        }
        assert!(verified.materialize(&workspace).await.is_err());
        assert!(
            !quarantine
                .join(".chinwag-materialization-attempt.json")
                .exists()
        );
        if !overlap {
            assert_eq!(fs::read(workspace.join("preserve")).unwrap(), b"keep");
        }
    }
}

#[tokio::test]
async fn canceled_materialization_keeps_quarantine_marker_and_cannot_reverify() {
    use std::{future::Future, task::Poll};
    let fixture = Fixture::new("sha1", 0x51).await;
    let config = fixture.config("cancel-materialize");
    let quarantine = config.quarantine.clone();
    let verifier = BundleVerifier::open(config).unwrap();
    let verified = verifier.verify().await.unwrap();
    let workspace = fixture.root.join("canceled-worktree");
    empty_private_directory(&workspace);
    let mut work = Box::pin(verified.materialize(&workspace));
    std::future::poll_fn(|context| {
        assert!(work.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    let marker = fs::read(quarantine.join(".chinwag-materialization-attempt.json")).unwrap();
    drop(work);
    assert_eq!(
        fs::read(quarantine.join(".chinwag-materialization-attempt.json")).unwrap(),
        marker
    );
    assert!(matches!(
        verifier.verify().await,
        Err(Error::AlreadyAttempted)
    ));
}

#[tokio::test]
async fn real_signed_sha1_and_sha256_bundles_verify_without_source_or_receiver_ref_changes() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new(format, 0x51).await;
        let before = fixture.source_bytes();
        let refs_before = fixture.git(&["show-ref".into()]).await.stdout;
        let original = fs::read(&fixture.bundle).unwrap();
        let config = fixture.config("accepted");
        let quarantine = config.quarantine.clone();
        let verifier = BundleVerifier::open(config).unwrap();
        let result = verifier.verify().await.unwrap();
        assert_eq!(result.oid(), fixture.oid);
        assert_eq!(result.tree(), fixture.tree);
        assert_eq!(result.signer(), fixture.builder);
        assert_eq!(result.hash(), *blake3::hash(&original).as_bytes());
        assert_eq!(result.size(), original.len() as u64);
        let marker = fs::read(quarantine.join(ATTEMPT)).unwrap();
        assert!(matches!(
            verifier.verify().await,
            Err(Error::AlreadyAttempted)
        ));
        assert_eq!(fs::read(quarantine.join(ATTEMPT)).unwrap(), marker);
        let mut reopen = fixture.config("fresh-process-scope");
        reopen.quarantine = quarantine.clone();
        assert!(BundleVerifier::open(reopen).is_err());
        assert_eq!(fs::read(quarantine.join(ATTEMPT)).unwrap(), marker);
        assert_eq!(fixture.source_bytes(), before);
        assert_eq!(fixture.git(&["show-ref".into()]).await.stdout, refs_before);
        assert_eq!(fs::read(&fixture.bundle).unwrap(), original);
        assert!(
            fs::read_dir(quarantine.join("refs/heads"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[tokio::test]
async fn wrong_tree_and_other_signing_key_cannot_produce_a_verified_bundle() {
    let fixture = Fixture::new("sha1", 0x51).await;
    let mut config = fixture.config("tree");
    let bytes = fs::read(&fixture.bundle).unwrap();
    config.expected = BundleExpectation::new(
        &fixture.oid,
        &"f".repeat(40),
        *blake3::hash(&bytes).as_bytes(),
        bytes.len() as u64,
        fixture.builder,
    )
    .unwrap();
    assert!(matches!(
        BundleVerifier::open(config).unwrap().verify().await,
        Err(Error::Object)
    ));
    let other = Fixture::new("sha1", 0x52).await;
    assert!(matches!(
        BundleVerifier::open(other.config("signer"))
            .unwrap()
            .verify()
            .await,
        Err(Error::Git {
            stage: "signature",
            ..
        })
    ));
}

#[tokio::test]
async fn corruption_with_matching_file_hash_still_fails_real_pack_verification() {
    let fixture = Fixture::new("sha1", 0x51).await;
    let mut bytes = fs::read(&fixture.bundle).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    write_private(&fixture.bundle, &bytes);
    let config = fixture.config("corruption");
    let quarantine = config.quarantine.clone();
    let verifier = BundleVerifier::open(config).unwrap();
    assert!(matches!(
        verifier.verify().await,
        Err(Error::Git {
            stage: "unbundle",
            ..
        })
    ));
    assert!(quarantine.join(ATTEMPT).exists());
    assert!(matches!(
        verifier.verify().await,
        Err(Error::AlreadyAttempted)
    ));
}

#[tokio::test]
async fn changed_blob_is_refused_before_arming_and_open_signer_snapshot_is_stable() {
    let fixture = Fixture::new("sha1", 0x51).await;
    let config = fixture.config("changed");
    let quarantine = config.quarantine.clone();
    let verifier = BundleVerifier::open(config).unwrap();
    let original = fs::read(&fixture.bundle).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    write_private(&fixture.bundle, &changed);
    assert!(matches!(
        verifier.verify().await,
        Err(Error::Metadata(crate::bundle::Error::Hash))
    ));
    assert!(fs::read_dir(&quarantine).unwrap().next().is_none());
    write_private(&fixture.bundle, &original);
    write_private(&fixture.signers, b"invalid-external-replacement\n");
    verifier.verify().await.unwrap();
    assert!(
        fs::read_to_string(quarantine.join(SIGNERS))
            .unwrap()
            .starts_with("fixture ssh-ed25519 ")
    );
}

#[tokio::test]
async fn symlinks_hardlinks_open_directories_and_occupied_quarantines_are_refused() {
    let fixture = Fixture::new("sha1", 0x51).await;
    let mut config = fixture.config("symlink");
    let link = fixture.root.join("bundle-link");
    symlink(&fixture.bundle, &link).unwrap();
    config.bundle = link;
    assert!(BundleVerifier::open(config).is_err());
    let hardlink = fixture.root.join("bundle-hardlink");
    fs::hard_link(&fixture.bundle, &hardlink).unwrap();
    assert!(BundleVerifier::open(fixture.config("hardlink")).is_err());
    fs::remove_file(hardlink).unwrap();
    let config = fixture.config("permissions");
    fs::set_permissions(&config.quarantine, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(BundleVerifier::open(config).is_err());
    let config = fixture.config("occupied");
    write_private(&config.quarantine.join(ATTEMPT), b"prior-outcome");
    assert!(BundleVerifier::open(config).is_err());
}

#[tokio::test]
async fn independently_opened_verifiers_cannot_both_arm_the_same_quarantine() {
    let fixture = Fixture::new("sha1", 0x51).await;
    let config = fixture.config("concurrent");
    let second_config = BundleOperatorConfig {
        bundle: config.bundle.clone(),
        quarantine: config.quarantine.clone(),
        empty_templates: config.empty_templates.clone(),
        builder_signers: config.builder_signers.clone(),
        expected: config.expected.clone(),
    };
    let quarantine = config.quarantine.clone();
    let one = BundleVerifier::open(config).unwrap();
    let two = BundleVerifier::open(second_config).unwrap();
    let (first, second) = tokio::join!(one.verify(), two.verify());
    assert!(first.is_ok() ^ second.is_ok());
    let loser = if first.is_err() { first } else { second };
    assert!(
        matches!(loser, Err(Error::Filesystem(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    let marker = fs::read(quarantine.join(ATTEMPT)).unwrap();
    assert!(matches!(one.verify().await, Err(Error::AlreadyAttempted)));
    assert!(matches!(two.verify().await, Err(Error::AlreadyAttempted)));
    assert_eq!(fs::read(quarantine.join(ATTEMPT)).unwrap(), marker);
}
