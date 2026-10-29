//! Dev-only helpers that make `cargo test --workspace` self-contained.
//!
//! Several tests were written against fixtures prepared by a one-shot QA
//! operator and handed over through environment variables
//! (`CHINWAG_STAGE1_FIXTURES`, `CHINWAG_PRINCIPAL_QA_REPOSITORIES`, ...).
//! Each helper here honours its variable unchanged when it is set, so the
//! operator flow keeps working. When it is unset, the helper seeds a fresh
//! private temp directory (or git repository) with the same shape, so the
//! unmodified assertions still run. Seeded directories live until the test
//! thread exits.
#![deny(unsafe_code)]

use std::{
    cell::RefCell,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, MutexGuard, PoisonError},
};

/// Principal written into seeded repositories, matching the operator fixtures.
pub const FIXTURE_PRINCIPAL: &str = "fixture@chinwag.test";

thread_local! {
    static SEEDED: RefCell<Vec<tempfile::TempDir>> = const { RefCell::new(Vec::new()) };
}

fn supplied(var: &str) -> Option<PathBuf> {
    env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// A fresh, canonical (no symlinked components), owner-private directory.
fn fresh_directory() -> PathBuf {
    let base = fs::canonicalize(env::temp_dir()).expect("canonical temp dir");
    let dir = tempfile::Builder::new()
        .prefix("chinwag-fixture-")
        .tempdir_in(base)
        .expect("create fixture namespace");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
    let path = fs::canonicalize(dir.path()).expect("canonical fixture namespace");
    SEEDED.with(|seeded| seeded.borrow_mut().push(dir));
    path
}

/// The directory named by `var`, or a fresh private temp directory when unset.
pub fn namespace(var: &str) -> PathBuf {
    supplied(var).unwrap_or_else(fresh_directory)
}

static SERIAL: Mutex<()> = Mutex::new(());

/// What a serialized test thread holds. `Drop` removes the seeded directories
/// first and only then do the fields release the lock, so the next test never
/// observes this one's teardown.
struct Exclusive {
    dirs: Vec<tempfile::TempDir>,
    _guard: MutexGuard<'static, ()>,
}

impl Drop for Exclusive {
    fn drop(&mut self) {
        self.dirs.clear();
    }
}

thread_local! {
    static EXCLUSIVE: RefCell<Option<Exclusive>> = const { RefCell::new(None) };
}

/// Like [`namespace`], but the calling test thread also takes a process-wide lock
/// that it keeps, together with its seeded directory, until the thread exits.
///
/// For tests whose subject verifies every ancestor directory of the fixture,
/// link counts included: while one such test runs, no sibling test in the same
/// binary creates or removes a directory next to it. A seeded directory goes
/// under `parent`, which should be quiet (for example cargo's per-package
/// `CARGO_TARGET_TMPDIR`, or the system temp directory when the subject needs a
/// location outside the repository). Further calls on the same thread reuse the lock.
pub fn serialized_namespace(var: &str, parent: &Path) -> PathBuf {
    EXCLUSIVE.with(|held| {
        let mut held = held.borrow_mut();
        let exclusive = held.get_or_insert_with(|| Exclusive {
            _guard: SERIAL.lock().unwrap_or_else(PoisonError::into_inner),
            dirs: Vec::new(),
        });
        if let Some(path) = supplied(var) {
            return path;
        }
        let base = fs::canonicalize(parent).expect("canonical fixture parent");
        let dir = tempfile::Builder::new()
            .prefix("chinwag-fixture-")
            .tempdir_in(base)
            .expect("create fixture namespace");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private mode");
        let path = fs::canonicalize(dir.path()).expect("canonical fixture namespace");
        exclusive.dirs.push(dir);
        path
    })
}

/// `<namespace>/<name>` as a git repository whose local config carries
/// [`FIXTURE_PRINCIPAL`]. A supplied namespace is trusted to already hold it.
pub fn git_repo(var: &str, name: &str) -> PathBuf {
    if let Some(root) = supplied(var) {
        return root.join(name);
    }
    let repo = fresh_directory().join(name);
    init_git_repo(&repo);
    repo
}

/// Like [`git_repo`], and with a created initial `.chinwag/state.crdb` store.
#[cfg(target_os = "macos")]
pub fn initialized_repo(var: &str, name: &str) -> PathBuf {
    if let Some(root) = supplied(var) {
        return root.join(name);
    }
    let repo = fresh_directory().join(name);
    init_git_repo(&repo);
    create_initial_store(&repo);
    repo
}

/// Like [`initialized_repo`] where `var` names the repository itself.
#[cfg(target_os = "macos")]
pub fn initialized_repo_at(var: &str) -> PathBuf {
    if let Some(repo) = supplied(var) {
        return repo;
    }
    let repo = fresh_directory().join("repo");
    init_git_repo(&repo);
    create_initial_store(&repo);
    repo
}

/// The `rustc` binary for the toolchain running the tests: `RUSTC` when set,
/// otherwise `<sysroot>/bin/rustc` of the `rustc` found on `PATH`.
pub fn rustc() -> PathBuf {
    if let Some(path) = supplied("RUSTC") {
        return path;
    }
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("run `rustc --print sysroot`");
    assert!(output.status.success(), "`rustc --print sysroot` failed");
    let sysroot = String::from_utf8(output.stdout).expect("utf-8 sysroot");
    let rustc = fs::canonicalize(Path::new(sysroot.trim()).join("bin/rustc"))
        .expect("toolchain rustc exists");
    assert!(rustc.is_absolute());
    rustc
}

fn git(repo: &Path, home: &Path, args: &[&str]) {
    let program = if Path::new("/usr/bin/git").exists() {
        "/usr/bin/git"
    } else {
        "git"
    };
    let status = Command::new(program)
        .current_dir(repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("LC_ALL", "C")
        .env("HOME", home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "init.templateDir=", "-c", "core.hooksPath=/dev/null"])
        .args(args)
        .status()
        .expect("spawn git");
    assert!(status.success(), "git {args:?} failed");
}

fn init_git_repo(repo: &Path) {
    fs::create_dir(repo).expect("create fixture repository");
    fs::set_permissions(repo, fs::Permissions::from_mode(0o700)).expect("private repository");
    let home = repo.parent().expect("namespace parent");
    git(repo, home, &["init", "--quiet"]);
    git(repo, home, &["config", "user.email", FIXTURE_PRINCIPAL]);
    git(repo, home, &["config", "user.name", "Synthetic Fixture"]);
    fs::set_permissions(repo.join(".git"), fs::Permissions::from_mode(0o700))
        .expect("private git dir");
}

#[cfg(target_os = "macos")]
fn create_initial_store(repo: &Path) {
    let private = repo.join(".chinwag");
    fs::create_dir(&private).expect("create private leaf");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("private leaf mode");
    chinwag_snapshot_session_private::initial_create::fresh_empty_store_image_for_private_fixture()
        .expect("fresh empty store image")
        .begin_private_fixture(repo)
        .expect("begin initial store")
        .finish()
        .expect("finish initial store");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_is_private_canonical_and_removed_on_thread_exit() {
        let path = std::thread::spawn(|| {
            let path = namespace("CHINWAG_FIXTURE_TEST_DOES_NOT_EXIST");
            assert!(path.is_absolute() && path.is_dir());
            assert_eq!(path, fs::canonicalize(&path).unwrap());
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            path
        })
        .join()
        .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn git_repo_is_seeded_with_the_fixture_principal() {
        let repo = git_repo("CHINWAG_FIXTURE_TEST_DOES_NOT_EXIST", "case");
        assert!(repo.join(".git").is_dir() && !repo.join(".chinwag").exists());
        let config = fs::read_to_string(repo.join(".git/config")).unwrap();
        assert!(config.contains("\temail = fixture@chinwag.test\n"));
    }

    #[test]
    fn rustc_resolves_to_an_existing_binary() {
        assert!(rustc().is_file());
    }
}
