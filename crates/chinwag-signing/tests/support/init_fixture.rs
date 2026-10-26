use super::{InitPaths, InitReceipt, SigningSecret, TxState};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;
use zeroize::Zeroizing;

pub(super) const PRINCIPAL: &str = "fixture@chinwag.invalid";
pub(super) struct Fixture {
    pub(super) temporary: Option<tempfile::TempDir>,
    pub(super) root: PathBuf,
    pub(super) repo: PathBuf,
    pub(super) private: PathBuf,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["repo", "home", "hooks", "templates"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let f = Self {
            temporary: Some(temporary),
            repo: root.join("repo"),
            private: root.join("identity"),
            root,
        };
        for args in [
            vec!["init", "--quiet"],
            vec!["config", "user.email", PRINCIPAL],
            vec!["config", "user.name", "Synthetic Fixture"],
        ] {
            assert!(f.git(&args).status.success());
        }
        fs::set_permissions(f.repo.join(".git"), fs::Permissions::from_mode(0o700)).unwrap();
        f
    }
    pub(super) fn paths<'a>(&'a self, scratch: &'a str) -> InitPaths<'a> {
        InitPaths {
            repo: &self.repo,
            private_leaf: &self.private,
            key_name: OsStr::new("signer"),
            allowed_name: OsStr::new("allowed"),
            scratch_name: OsStr::new(scratch),
            principal: PRINCIPAL,
            child_timeout: Duration::from_secs(2),
        }
    }
    pub(super) fn git(&self, args: &[&str]) -> Output {
        Command::new("/usr/bin/git")
            .current_dir(&self.repo)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", self.root.join("home"))
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
    pub(super) fn config(&self) -> PathBuf {
        self.repo.join(".git/config")
    }
}
pub(super) fn key(seed: u8) -> SigningSecret {
    SigningSecret::from_seed(Zeroizing::new([seed; 32]))
}
pub(super) fn config_state(receipt: InitReceipt) -> TxState {
    match receipt {
        InitReceipt::Config { transaction, .. } => transaction.state,
        other => panic!("expected config receipt: {other:?}"),
    }
}
pub(super) fn snapshot(path: &Path) -> (u64, u32, Vec<u8>) {
    let m = fs::metadata(path).unwrap();
    (m.ino(), m.mode(), fs::read(path).unwrap())
}
