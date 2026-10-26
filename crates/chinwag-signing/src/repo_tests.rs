use super::*;
use crate::SigningSecret;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output};
use zeroize::Zeroizing;

const PRINCIPAL: &str = "fixture@chinwag.invalid";
struct Fixture {
    temporary: Option<tempfile::TempDir>,
    root: PathBuf,
    repo: PathBuf,
    private: PathBuf,
    public: [u8; 32],
}
impl Fixture {
    fn new(mode: u32) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let repo = root.join("repo");
        let private = root.join("identity");
        for dir in [
            &repo,
            &root.join("home"),
            &root.join("hooks"),
            &root.join("templates"),
        ] {
            fs::create_dir(dir).unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = SigningSecret::from_seed(Zeroizing::new([0xA5; 32]));
        let public = key.public_bytes();
        let identity = PrivateDirectory::create_new(&private).unwrap();
        identity.write_new(OsStr::new("signer"), &key).unwrap();
        identity
            .write_new_allowed_signers(OsStr::new("allowed"), PRINCIPAL, &key)
            .unwrap();
        let fixture = Self {
            temporary: Some(temporary),
            root,
            repo,
            private,
            public,
        };
        assert!(fixture.git(&["init", "--quiet"]).status.success());
        fs::set_permissions(fixture.repo.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        fixture.append_config(
            b"\n[user]\n name = Synthetic Fixture\n email = fixture@chinwag.invalid\n",
        );
        fs::set_permissions(fixture.config(), fs::Permissions::from_mode(mode)).unwrap();
        fixture
    }
    fn config(&self) -> PathBuf {
        self.repo.join(".git/config")
    }
    fn append_config(&self, bytes: &[u8]) {
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(self.config())
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn git(&self, args: &[&str]) -> Output {
        Command::new("/usr/bin/git")
            .current_dir(&self.repo)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.root.join("home"))
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_COUNT", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "protocol.allow=never",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                "-c",
                "gpg.ssh.program=/usr/bin/ssh-keygen",
                "-c",
                "gpg.ssh.revocationFile=/dev/null",
            ])
            .arg("-c")
            .arg(format!(
                "core.hooksPath={}",
                self.root.join("hooks").display()
            ))
            .arg("-c")
            .arg(format!(
                "init.templateDir={}",
                self.root.join("templates").display()
            ))
            .args(args)
            .output()
            .unwrap()
    }
    fn begin(&self, name: &str) -> ConfigTransaction {
        ConfigTransaction::begin(RepoSigningRequest {
            repo: &self.repo,
            private_directory: &self.private,
            key_name: OsStr::new("signer"),
            allowed_name: OsStr::new("allowed"),
            expected_public: &self.public,
            principal: PRINCIPAL,
            scratch_name: OsStr::new(name),
            child_timeout: Duration::from_secs(2),
        })
    }
    fn finish(&mut self, tx: &mut ConfigTransaction) -> TxState {
        let bound = Instant::now() + Duration::from_secs(12);
        loop {
            let state = tx.poll(Instant::now());
            if !matches!(state, TxState::Pending { .. }) {
                if let TxState::ChildUnknown { .. } = state {
                    // Keep the private workspace if an actual owned child has not resolved.
                    let resolve_bound = Instant::now() + Duration::from_secs(3);
                    loop {
                        match tx.observe_child() {
                            Ok(Some(_)) => break,
                            _ if Instant::now() < resolve_bound => {
                                std::thread::sleep(Duration::from_millis(2))
                            }
                            _ => {
                                std::mem::forget(self.temporary.take());
                                panic!("owned fixture child unresolved; workspace retained");
                            }
                        }
                    }
                }
                return state;
            }
            if Instant::now() >= bound {
                std::mem::forget(self.temporary.take());
                panic!("fixture operation exceeded bound; workspace retained");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn stock_git_installs_signing_preserves_mode_then_is_unchanged_and_verifies() {
    for mode in [0o600, 0o640] {
        let mut f = Fixture::new(mode);
        let original_gid = fs::metadata(f.config()).unwrap().gid();
        let mut tx = f.begin("install");
        assert!(
            matches!(tx.state(), TxState::Pending { .. }),
            "{}",
            tx.reason()
        );
        assert_eq!(f.finish(&mut tx), TxState::Installed, "{}", tx.reason());
        assert!(!f.repo.join(".git/config.lock").exists());
        let meta = fs::metadata(f.config()).unwrap();
        assert_eq!(meta.mode() & 0o7777, mode);
        assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(meta.gid(), original_gid);
        let bytes = fs::read(f.config()).unwrap();
        let mut again = f.begin("unchanged");
        assert_eq!(
            f.finish(&mut again),
            TxState::Unchanged,
            "{}",
            again.reason()
        );
        assert_eq!(fs::metadata(f.config()).unwrap().ino(), meta.ino());
        assert_eq!(fs::read(f.config()).unwrap(), bytes);
        let committed = f.git(&[
            "commit",
            "--allow-empty",
            "-S",
            "-m",
            "synthetic config transaction fixture",
        ]);
        assert!(
            committed.status.success(),
            "{}",
            String::from_utf8_lossy(&committed.stderr)
        );
        assert!(f.git(&["verify-commit", "HEAD"]).status.success());
        let other = SigningSecret::from_seed(Zeroizing::new([0xA6; 32]));
        fs::write(
            f.private.join("allowed"),
            format!(
                "{PRINCIPAL} namespaces=\"git\" {}\n",
                other.public_openssh().unwrap()
            ),
        )
        .unwrap();
        assert!(!f.git(&["verify-commit", "HEAD"]).status.success());
    }
}

#[test]
fn foreign_lock_preserves_both_files_and_starts_no_child_or_scratch() {
    let f = Fixture::new(0o600);
    let before = fs::read(f.config()).unwrap();
    let lock = f.repo.join(".git/config.lock");
    fs::write(&lock, b"foreign lock sentinel").unwrap();
    let tx = f.begin("must-not-run");
    assert_eq!(tx.state(), TxState::LockHeldElsewhere);
    assert_eq!(tx.receipt().child_pid, 0);
    assert!(!f.private.join("must-not-run").exists());
    assert_eq!(fs::read(lock).unwrap(), b"foreign lock sentinel");
    assert_eq!(fs::read(f.config()).unwrap(), before);
}

#[test]
fn moved_repo_install_is_anchored_and_replacement_survives() {
    let mut f = Fixture::new(0o600);
    let mut tx = f.begin("path-swap");
    assert!(
        matches!(tx.state(), TxState::Pending { .. }),
        "{}",
        tx.reason()
    );
    let moved = f.root.join("moved-repo");
    fs::rename(&f.repo, &moved).unwrap();
    fs::create_dir(&f.repo).unwrap();
    fs::create_dir(f.repo.join(".git")).unwrap();
    fs::write(f.config(), b"replacement sentinel").unwrap();
    assert_eq!(f.finish(&mut tx), TxState::Installed, "{}", tx.reason());
    assert_eq!(fs::read(f.config()).unwrap(), b"replacement sentinel");
    assert!(!f.repo.join(".git/config.lock").exists());
    assert!(!moved.join(".git/config.lock").exists());
    assert!(
        String::from_utf8(fs::read(moved.join(".git/config")).unwrap())
            .unwrap()
            .contains("signingkey")
    );
}

#[test]
fn unmanaged_repeated_valueless_empty_and_multiline_values_survive() {
    let mut f = Fixture::new(0o600);
    f.append_config(b"\n[unrelated]\n multi = one\n flag\n empty =\n multi = two\n multiline = \"hello\\nworld\"\n[gpg]\n program = fixture-unchanged\n");
    let before = f.git(&["config", "--local", "--null", "--list"]);
    assert!(before.status.success());
    let mut tx = f.begin("semantics");
    assert_eq!(f.finish(&mut tx), TxState::Installed, "{}", tx.reason());
    let after = f.git(&["config", "--local", "--null", "--list"]);
    assert!(after.status.success());
    let without_managed = |bytes: Vec<u8>| -> Vec<Vec<u8>> {
        bytes
            .split(|b| *b == 0)
            .filter(|record| !record.is_empty())
            .filter(|record| {
                let key = record.split(|b| *b == b'\n').next().unwrap();
                ![
                    b"gpg.format".as_slice(),
                    b"commit.gpgsign",
                    b"user.signingkey",
                    b"gpg.ssh.allowedsignersfile",
                ]
                .contains(&key)
            })
            .map(<[u8]>::to_vec)
            .collect()
    };
    assert_eq!(
        without_managed(after.stdout),
        without_managed(before.stdout)
    );
}

#[test]
fn conflict_include_unsupported_mode_and_wrong_pin_leave_config_unchanged() {
    for (suffix, mode) in [
        (b"\n[gpg]\n format = openpgp\n".as_slice(), 0o600),
        (b"\n[include]\n path = nonexistent\n", 0o600),
        (b"", 0o444),
        (b"\n[extensions]\n worktreeConfig = true\n", 0o600),
    ] {
        let mut f = Fixture::new(0o600);
        f.append_config(suffix);
        fs::set_permissions(f.config(), fs::Permissions::from_mode(mode)).unwrap();
        let before = fs::read(f.config()).unwrap();
        let inode = fs::metadata(f.config()).unwrap().ino();
        let mut tx = f.begin("refusal");
        let result = f.finish(&mut tx);
        assert_eq!(result, TxState::Refused, "{}", tx.reason());
        assert_eq!(fs::read(f.config()).unwrap(), before);
        assert_eq!(fs::metadata(f.config()).unwrap().ino(), inode);
        assert!(!f.repo.join(".git/config.lock").exists());
    }
    let f = Fixture::new(0o600);
    let tx = ConfigTransaction::begin(RepoSigningRequest {
        repo: &f.repo,
        private_directory: &f.private,
        key_name: OsStr::new("signer"),
        allowed_name: OsStr::new("allowed"),
        expected_public: &[0x22; 32],
        principal: PRINCIPAL,
        scratch_name: OsStr::new("bad-pin"),
        child_timeout: Duration::from_secs(2),
    });
    assert_eq!(tx.state(), TxState::Refused);
    assert!(!f.repo.join(".git/config.lock").exists());
    assert!(!f.private.join("bad-pin").exists());
}

#[path = "repo_child_tests.rs"]
mod child_cases;

#[test]
fn layout_markers_appearing_after_begin_refuse_install_and_retain_guard() {
    for marker in ["config.worktree", "commondir"] {
        let mut f = Fixture::new(0o600);
        let original = fs::read(f.config()).unwrap();
        let inode = fs::metadata(f.config()).unwrap().ino();
        let mut tx = f.begin("late-layout");
        assert!(matches!(tx.state(), TxState::Pending { .. }));
        fs::write(
            f.repo.join(".git").join(marker),
            b"unsupported layout marker",
        )
        .unwrap();
        assert_eq!(f.finish(&mut tx), TxState::OriginalChanged);
        assert_eq!(fs::read(f.config()).unwrap(), original);
        assert_eq!(fs::metadata(f.config()).unwrap().ino(), inode);
        assert!(f.repo.join(".git/config.lock").exists());
        assert!(!f.private.join("late-layout/set0.out").exists());
        assert_eq!(tx.receipt().child_pid, 0);
    }
}
#[test]
fn layout_change_between_sets_stops_before_next_child_and_install() {
    let mut f = Fixture::new(0o600);
    let original = fs::read(f.config()).unwrap();
    let mut tx = f.begin("between-sets");
    let bound = Instant::now() + Duration::from_secs(2);
    while !f.private.join("between-sets/set0.out").exists() {
        let state = tx.poll(Instant::now());
        if !matches!(state, TxState::Pending { .. }) || Instant::now() >= bound {
            let _ = f.finish(&mut tx);
            panic!("first managed child did not start");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    fs::write(f.repo.join(".git/commondir"), b"unsupported late layout").unwrap();
    assert_eq!(f.finish(&mut tx), TxState::OriginalChanged);
    assert_eq!(fs::read(f.config()).unwrap(), original);
    assert!(f.repo.join(".git/config.lock").exists());
    assert!(!f.private.join("between-sets/set1.out").exists());
    assert_eq!(tx.receipt().child_pid, 0);
}
