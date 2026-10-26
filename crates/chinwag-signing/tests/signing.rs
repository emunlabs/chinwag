#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chinwag_signing::{Error, PrivateDirectory, SigningSecret};
use zeroize::Zeroizing;

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().canonicalize().unwrap();
        Self {
            _temporary: temporary,
            root,
        }
    }

    fn directory(&self) -> PrivateDirectory {
        PrivateDirectory::open(&self.root).unwrap()
    }
}

fn secret() -> SigningSecret {
    let key = SigningSecret::from_seed(Zeroizing::new([0xA5; 32]));
    let public: String = key
        .public_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_ne!(
        public,
        "df7676a8680f06f1cddb51a793be9a07a0d022638cb25ebe681dd42328867931"
    );
    assert_ne!(
        public,
        "63e44fbb5054e0730793b2be61daf203b912c7cc5777f86ebbfe5f73b096c3d0"
    );
    key
}

#[test]
fn operating_system_entropy_produces_distinct_valid_public_identities() {
    let first = SigningSecret::generate().unwrap();
    let second = SigningSecret::generate().unwrap();
    assert_ne!(first.public_bytes(), second.public_bytes());
    for key in [first, second] {
        let public = ssh_key::PublicKey::from_openssh(&key.public_openssh().unwrap()).unwrap();
        assert_eq!(public.key_data().ed25519().unwrap().0, key.public_bytes());
    }
}

#[test]
fn exclusive_private_key_round_trips_with_the_expected_public_identity() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let key = secret();
    directory.write_new(OsStr::new("signer"), &key).unwrap();
    let metadata = fs::metadata(fixture.root.join("signer")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let loaded = directory
        .read_existing(OsStr::new("signer"), &key.public_bytes())
        .unwrap();
    assert_eq!(loaded.public_bytes(), key.public_bytes());
    assert_eq!(
        loaded.public_openssh().unwrap(),
        key.public_openssh().unwrap()
    );
    assert!(matches!(
        directory.read_existing(OsStr::new("signer"), &[0x22; 32]),
        Err(Error::PublicMismatch)
    ));
}

#[test]
fn existing_file_and_symlink_survive_refused_creation() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let original = fixture.root.join("existing");
    fs::write(&original, b"existing bytes must survive").unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o640)).unwrap();
    let before = fs::metadata(&original).unwrap();
    symlink(&original, fixture.root.join("link")).unwrap();
    for name in ["existing", "link"] {
        assert_eq!(
            directory.write_new(OsStr::new(name), &secret()),
            Err(Error::Exists)
        );
    }
    let after = fs::metadata(&original).unwrap();
    assert_eq!(fs::read(&original).unwrap(), b"existing bytes must survive");
    assert_eq!(before.mode(), after.mode());
    assert_eq!(before.ino(), after.ino());
    assert!(
        fs::symlink_metadata(fixture.root.join("link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn fifo_is_not_overwritten_and_nonblocking_read_rejects_it() {
    let fixture = Fixture::new();
    let fifo = fixture.root.join("fifo");
    let status = Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .env_clear()
        .status()
        .unwrap();
    assert!(status.success());
    fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::symlink_metadata(&fifo).unwrap();
    let directory = fixture.directory();
    assert_eq!(
        directory.write_new(OsStr::new("fifo"), &secret()),
        Err(Error::Exists)
    );
    assert!(matches!(
        directory.read_existing(OsStr::new("fifo"), &secret().public_bytes()),
        Err(Error::File)
    ));
    let after = fs::symlink_metadata(&fifo).unwrap();
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.mode(), after.mode());
}

#[test]
fn directory_fd_stays_anchored_after_parent_rename_and_path_replacement() {
    let fixture = Fixture::new();
    let original = fixture.root.join("original");
    let moved = fixture.root.join("moved");
    let replacement = fixture.root.join("replacement");
    for path in [&original, &replacement] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let directory = PrivateDirectory::open(&original).unwrap();
    fs::rename(&original, &moved).unwrap();
    symlink(&replacement, &original).unwrap();
    directory
        .write_new(OsStr::new("signer"), &secret())
        .unwrap();
    assert!(moved.join("signer").is_file());
    assert!(!replacement.join("signer").exists());
    assert!(
        directory
            .read_existing(OsStr::new("signer"), &secret().public_bytes())
            .is_ok()
    );
    assert!(matches!(
        PrivateDirectory::open(&original),
        Err(Error::Directory)
    ));
}

#[test]
fn unsafe_directory_paths_and_names_are_refused_before_creation() {
    let fixture = Fixture::new();
    assert!(matches!(
        PrivateDirectory::open(Path::new("relative")),
        Err(Error::Directory)
    ));
    let link = fixture.root.join("link");
    symlink(&fixture.root, &link).unwrap();
    assert!(matches!(
        PrivateDirectory::open(&link),
        Err(Error::Directory)
    ));
    assert!(matches!(
        PrivateDirectory::open(&link.join("missing")),
        Err(Error::Directory)
    ));
    let directory = fixture.directory();
    for name in [
        OsStr::new(""),
        OsStr::new("."),
        OsStr::new(".."),
        OsStr::new("../outside"),
        OsStr::new("a/b"),
        OsStr::from_bytes(b"bad\0name"),
    ] {
        assert_eq!(directory.write_new(name, &secret()), Err(Error::Name));
    }
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        PrivateDirectory::open(&fixture.root),
        Err(Error::Directory)
    ));
    assert_eq!(
        directory.write_new(OsStr::new("no-key"), &secret()),
        Err(Error::Directory)
    );
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn reader_rejects_public_oversize_shared_mode_and_hardlinked_files() {
    let fixture = Fixture::new();
    let directory = fixture.directory();
    let key = secret();
    directory.write_new(OsStr::new("signer"), &key).unwrap();
    fs::write(fixture.root.join("public"), key.public_openssh().unwrap()).unwrap();
    fs::write(fixture.root.join("oversize"), vec![0; 16_385]).unwrap();
    for name in ["public", "oversize"] {
        fs::set_permissions(fixture.root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(matches!(
        directory.read_existing(OsStr::new("public"), &key.public_bytes()),
        Err(Error::Format)
    ));
    assert!(matches!(
        directory.read_existing(OsStr::new("oversize"), &key.public_bytes()),
        Err(Error::File)
    ));
    symlink(fixture.root.join("signer"), fixture.root.join("link")).unwrap();
    assert!(matches!(
        directory.read_existing(OsStr::new("link"), &key.public_bytes()),
        Err(Error::Open)
    ));
    fs::set_permissions(
        fixture.root.join("signer"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(matches!(
        directory.read_existing(OsStr::new("signer"), &key.public_bytes()),
        Err(Error::File)
    ));
    fs::set_permissions(
        fixture.root.join("signer"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::hard_link(fixture.root.join("signer"), fixture.root.join("hardlink")).unwrap();
    assert!(matches!(
        directory.read_existing(OsStr::new("signer"), &key.public_bytes()),
        Err(Error::File)
    ));
}

fn git(root: &Path, args: &[OsString]) -> Output {
    Command::new("/usr/bin/git")
        .current_dir(root.join("repo"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", root.join("home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "protocol.allow=never", "-c", "core.fsmonitor=false"])
        .arg("-c")
        .arg(format!(
            "core.hooksPath={}",
            root.join("empty-hooks").display()
        ))
        .arg("-c")
        .arg(format!(
            "init.templateDir={}",
            root.join("empty-templates").display()
        ))
        .args([
            "-c",
            "gpg.ssh.program=/usr/bin/ssh-keygen",
            "-c",
            "gc.auto=0",
        ])
        .args([
            "-c",
            "gpg.ssh.revocationFile=/dev/null",
            "-c",
            "maintenance.auto=false",
        ])
        .args(args)
        .output()
        .unwrap()
}

fn successful_git(root: &Path, args: &[&str]) {
    let output = git(root, &args.iter().map(OsString::from).collect::<Vec<_>>());
    assert!(
        output.status.success(),
        "git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stock_git_signs_and_verifies_a_fixture_commit_and_rejects_another_signer() {
    let fixture = Fixture::new();
    let root = &fixture.root;
    fs::create_dir(root.join("home")).unwrap();
    fs::create_dir(root.join("repo")).unwrap();
    fs::create_dir(root.join("empty-hooks")).unwrap();
    fs::create_dir(root.join("empty-templates")).unwrap();
    let sentinel = b"[user]\nname = DoNotChange\nemail = sentinel@invalid\n";
    fs::write(root.join("home/.gitconfig"), sentinel).unwrap();
    let key = secret();
    fixture
        .directory()
        .write_new(OsStr::new("signer"), &key)
        .unwrap();
    let allowed = root.join("allowed_signers");
    fs::write(
        &allowed,
        format!(
            "fixture@chinwag.invalid namespaces=\"git\" {}\n",
            key.public_openssh().unwrap()
        ),
    )
    .unwrap();
    successful_git(root, &["init", "--quiet"]);
    successful_git(root, &["config", "user.name", "Fixture Signer"]);
    successful_git(root, &["config", "user.email", "fixture@chinwag.invalid"]);
    successful_git(root, &["config", "gpg.format", "ssh"]);
    for (setting, value) in [
        ("user.signingkey", root.join("signer")),
        ("gpg.ssh.allowedSignersFile", allowed.clone()),
    ] {
        let output = git(
            root,
            &["config".into(), setting.into(), value.into_os_string()],
        );
        assert!(output.status.success());
    }
    successful_git(
        root,
        &[
            "commit",
            "--allow-empty",
            "-S",
            "-m",
            "synthetic signing fixture only",
        ],
    );
    successful_git(root, &["verify-commit", "HEAD"]);
    let other = SigningSecret::from_seed(Zeroizing::new([0xA6; 32]));
    fs::write(
        &allowed,
        format!(
            "fixture@chinwag.invalid namespaces=\"git\" {}\n",
            other.public_openssh().unwrap()
        ),
    )
    .unwrap();
    let rejected = git(root, &["verify-commit".into(), "HEAD".into()]);
    assert!(!rejected.status.success());
    assert_eq!(fs::read(root.join("home/.gitconfig")).unwrap(), sentinel);
    assert_eq!(
        fs::metadata(root.join("signer")).unwrap().mode() & 0o7777,
        0o600
    );
}
