//! Repository-scoped Git config install. The lock file is the commit.
//!
//! Comments, blank lines, and original byte layout are not preserved.
//! Unmanaged key values, including valueless versus empty, stay in order.
//! macOS fsync is not a power-loss guarantee. A same-uid writer that ignores
//! config.lock is outside this contract.

#![cfg(target_os = "macos")]

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use chinwag_host_process::owned_spawn::{Exit, OwnedChild, SpawnStdio, spawn_at};
use rustix::fd::OwnedFd;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, Stat, fchmod, fstat, fsync, mkdirat, open, openat, renameat,
    statat, unlinkat,
};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use crate::storage::PrivateDirectory;

const MAX_BYTES: usize = 65_536;
const GIT: &std::ffi::CStr = c"/usr/bin/git";
const MANAGED: [&str; 4] = [
    "gpg.format",
    "commit.gpgsign",
    "user.signingkey",
    "gpg.ssh.allowedsignersfile",
];

#[path = "repo_state.rs"]
mod state;
pub use state::{Receipt, RepoSigningRequest, TxState};
#[path = "repo_preimage.rs"]
mod preimage;
pub use preimage::ConfigPreimageConstraint;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    key: String,
    value: Option<String>,
}

#[derive(Clone, Copy)]
struct Id {
    dev: i32,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    nlink: u64,
    size: u64,
}

enum Step {
    List,
    Set(usize),
    Final,
}

enum Drive {
    Pending(u32),
    Unknown(u32),
    Done(Exit),
}

#[must_use = "poll until terminal and retain this value while a child is unknown"]
pub struct ConfigTransaction {
    reason: &'static str,
    expected_public: [u8; 32],
    preimage_constraint: Option<ConfigPreimageConstraint>,
    timeout: Duration,
    principal: String,
    private_dir: Option<PrivateDirectory>,
    repo_fd: Option<OwnedFd>,
    git_fd: Option<OwnedFd>,
    lock_file: Option<File>,
    scratch_fd: Option<OwnedFd>,
    snapshot: Vec<u8>,
    snapshot_id: Option<Id>,
    lock_id: Option<Id>,
    repo_id: Option<Id>,
    git_id: Option<Id>,
    snapshot_hash: [u8; 32],
    staged_hash: [u8; 32],
    baseline: Vec<Entry>,
    sets: Vec<(String, String)>,
    final_bytes: Vec<u8>,
    step: Option<Step>,
    child: Option<OwnedChild>,
    deadline: Option<Instant>,
    stdout_file: Option<File>,
    stderr_file: Option<File>,
    null_in: Option<File>,
    key_path: String,
    allowed_path: String,
    hooks_path: String,
    home_path: String,
    rename_attempted: bool,
    terminal: Option<TxState>,
    #[cfg(test)]
    hooks: TestHooks,
}

#[cfg(test)]
type PostRenameSync = fn(&OwnedFd) -> Result<(), ()>;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    program: Option<(CString, Vec<CString>, Vec<CString>)>,
    post_rename_sync: Option<PostRenameSync>,
}

#[cfg(test)]
impl TestHooks {
    pub(crate) fn for_program(program: CString, args: Vec<CString>, env: Vec<CString>) -> Self {
        Self {
            program: Some((program, args, env)),
            post_rename_sync: None,
        }
    }
}

impl ConfigTransaction {
    pub fn begin(request: RepoSigningRequest<'_>) -> Self {
        #[cfg(test)]
        {
            Self::begin_inner(request, None, TestHooks::default())
        }
        #[cfg(not(test))]
        {
            Self::begin_inner(request, None)
        }
    }

    #[cfg(test)]
    pub(crate) fn begin_with(request: RepoSigningRequest<'_>, hooks: TestHooks) -> Self {
        Self::begin_inner(request, None, hooks)
    }

    /// Add a source-preimage restriction to a new original transaction.
    /// This does not adopt a lock, receive an owner, or authorize a retry.
    pub fn begin_bound(
        request: RepoSigningRequest<'_>,
        expected: ConfigPreimageConstraint,
    ) -> Self {
        Self::begin_inner(
            request,
            Some(expected),
            #[cfg(test)]
            TestHooks::default(),
        )
    }

    fn begin_inner(
        request: RepoSigningRequest<'_>,
        preimage_constraint: Option<ConfigPreimageConstraint>,
        #[cfg(test)] hooks: TestHooks,
    ) -> Self {
        let mut tx = Self {
            reason: "signing_incomplete",
            expected_public: *request.expected_public,
            preimage_constraint,
            timeout: request.child_timeout,
            principal: request.principal.to_owned(),
            private_dir: None,
            repo_fd: None,
            git_fd: None,
            lock_file: None,
            scratch_fd: None,
            snapshot: Vec::new(),
            snapshot_id: None,
            lock_id: None,
            repo_id: None,
            git_id: None,
            snapshot_hash: [0; 32],
            staged_hash: [0; 32],
            baseline: Vec::new(),
            sets: Vec::new(),
            final_bytes: Vec::new(),
            step: None,
            child: None,
            deadline: None,
            stdout_file: None,
            stderr_file: None,
            null_in: None,
            key_path: String::new(),
            allowed_path: String::new(),
            hooks_path: String::new(),
            home_path: String::new(),
            rename_attempted: false,
            terminal: None,
            #[cfg(test)]
            hooks,
        };
        if let Err(reason) = tx.prepare(&request)
            && tx.terminal.is_none()
        {
            tx.fail_refused(reason);
        }
        tx
    }

    pub fn state(&self) -> TxState {
        if let Some(state) = self.terminal {
            return state;
        }
        match &self.child {
            Some(child) => TxState::Pending { pid: child.pid() },
            None => TxState::Refused,
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }

    pub fn poll(&mut self, now: Instant) -> TxState {
        if let Some(state) = self.terminal {
            return state;
        }
        match self.drive(now) {
            Drive::Pending(pid) => TxState::Pending { pid },
            Drive::Unknown(pid) => self.stop_unknown(pid),
            Drive::Done(exit) => self.on_exit(exit),
        }
    }

    /// Reads the same retained child. Does not spawn, clean up, or install.
    pub fn observe_child(&mut self) -> std::io::Result<Option<Exit>> {
        if !matches!(self.terminal, Some(TxState::ChildUnknown { .. })) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.child
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?
            .try_wait()
    }

    pub fn receipt(&self) -> Receipt {
        let id = |value: &Option<Id>| {
            value
                .as_ref()
                .map(|item| (item.dev, item.ino))
                .unwrap_or((0, 0))
        };
        let (repo_dev, repo_ino) = id(&self.repo_id);
        let (git_dev, git_ino) = id(&self.git_id);
        let (config_dev, config_ino) = id(&self.snapshot_id);
        let (lock_dev, lock_ino) = id(&self.lock_id);
        Receipt {
            state: self.state(),
            expected_public: self.expected_public,
            repo_dev,
            repo_ino,
            git_dev,
            git_ino,
            config_dev,
            config_ino,
            lock_dev,
            lock_ino,
            snapshot_sha256: self.snapshot_hash,
            staged_sha256: self.staged_hash,
            child_pid: self.child.as_ref().map(OwnedChild::pid).unwrap_or(0),
            reason: self.reason,
        }
    }

    fn prepare(&mut self, request: &RepoSigningRequest<'_>) -> Result<(), &'static str> {
        validate_token(request.principal)?;
        if request.child_timeout.is_zero() || request.child_timeout > Duration::from_secs(60) {
            return Err("signing_timeout");
        }
        validate_component(request.key_name)?;
        validate_component(request.allowed_name)?;
        validate_component(request.scratch_name)?;
        if request.key_name == request.scratch_name || request.allowed_name == request.scratch_name
        {
            return Err("signing_name");
        }
        let private_text = path_text(request.private_directory)?;
        let private =
            PrivateDirectory::open(request.private_directory).map_err(|_| "signing_directory")?;
        let again =
            PrivateDirectory::open(request.private_directory).map_err(|_| "signing_directory")?;
        let first = fstat(private.as_fd()).map_err(|_| "signing_directory")?;
        let second = fstat(again.as_fd()).map_err(|_| "signing_directory")?;
        if first.st_dev != second.st_dev || first.st_ino != second.st_ino {
            return Err("signing_race");
        }
        drop(again);
        let secret = private
            .read_existing(request.key_name, request.expected_public)
            .map_err(|_| "signing_public_mismatch")?;
        if secret.public_bytes() != *request.expected_public {
            return Err("signing_public_mismatch");
        }
        let openssh = secret.public_openssh().map_err(|_| "signing_format")?;
        drop(secret);
        let line = allowed_line(request.principal, &openssh)?;
        read_exact_public(&private, request.allowed_name, line.as_bytes())?;
        self.key_path = join_component(&private_text, request.key_name)?;
        self.allowed_path = join_component(&private_text, request.allowed_name)?;
        self.home_path = join_component(&private_text, request.scratch_name)?;
        self.hooks_path = format!("{}/hooks", self.home_path);
        self.private_dir = Some(private);

        let repo = open_absolute_dir(request.repo)?;
        self.repo_id = Some(identity(&fstat(&repo).map_err(|_| "signing_directory")?)?);
        let git = openat(
            &repo,
            ".git",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "signing_unsupported")?;
        let git_stat = fstat(&git).map_err(|_| "signing_directory")?;
        if git_stat.st_uid != rustix::process::geteuid().as_raw()
            || git_stat.st_mode & 0o022 != 0
            || git_stat.st_mode & 0o200 == 0
        {
            return Err("signing_unsupported");
        }
        self.git_id = Some(identity(&git_stat)?);
        refuse_present(&git, "commondir")?;
        refuse_present(&git, "config.worktree")?;
        // Metadata-only preflight. The first config bytes are read under our lock.
        let pre = openat(
            &git,
            "config",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "signing_file")?;
        let pre = fstat(&pre).map_err(|_| "signing_file")?;
        if FileType::from_raw_mode(pre.st_mode) != FileType::RegularFile
            || pre.st_uid != rustix::process::geteuid().as_raw()
            || pre.st_nlink != 1
            || pre.st_size < 0
            || pre.st_size > MAX_BYTES as i64
            || supported_mode(pre.st_mode).is_none()
        {
            return Err("signing_unsupported");
        }
        self.repo_fd = Some(repo);
        self.git_fd = Some(git);

        let git_fd = self.git_fd.as_ref().ok_or("signing_directory")?;
        let lock = match openat(
            git_fd,
            "config.lock",
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::EXIST) => {
                self.terminal = Some(TxState::LockHeldElsewhere);
                self.reason = "signing_lock";
                return Ok(());
            }
            Err(_) => return Err("signing_create"),
        };
        self.lock_file = Some(lock);
        let lock = self.lock_file.as_ref().unwrap();
        fchmod(lock, Mode::from_raw_mode(0o600)).map_err(|_| "signing_create")?;
        self.lock_id = Some(identity(&fstat(lock).map_err(|_| "signing_create")?)?);
        let (config_id, config_bytes) = read_named(self.git_fd.as_ref().unwrap(), "config")?;
        if supported_mode(config_id.mode).is_none() {
            return Err("signing_unsupported");
        }
        self.snapshot = config_bytes;
        self.snapshot_id = Some(config_id);
        self.snapshot_hash = digest(&self.snapshot);
        if self
            .preimage_constraint
            .is_some_and(|expected| !expected.accepts(&self.receipt()))
        {
            return Err("signing_preimage_changed");
        }
        let lock_id = self.lock_id.as_ref().unwrap();
        if lock_id.gid != config_id.gid || lock_id.uid != config_id.uid {
            return Err("signing_group");
        }

        let private = self.private_dir.as_ref().unwrap();
        match mkdirat(
            private.as_fd(),
            request.scratch_name,
            Mode::from_raw_mode(0o700),
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => return Err("signing_exists"),
            Err(_) => return Err("signing_create"),
        }
        let scratch = openat(
            private.as_fd(),
            request.scratch_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "signing_create")?;
        fchmod(&scratch, Mode::from_raw_mode(0o700)).map_err(|_| "signing_create")?;
        mkdirat(&scratch, "hooks", Mode::from_raw_mode(0o700)).map_err(|_| "signing_create")?;
        let staged = openat(
            &scratch,
            "staged.config",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| "signing_create")?;
        let mut staged_file = File::from(staged);
        staged_file
            .write_all(&self.snapshot)
            .map_err(|_| "signing_io")?;
        staged_file.sync_all().map_err(|_| "signing_io")?;
        drop(staged_file);
        self.scratch_fd = Some(scratch);
        self.null_in = Some(File::open("/dev/null").map_err(|_| "signing_io")?);
        self.spawn("list", Step::List, &["--null", "--list"])?;
        Ok(())
    }

    fn spawn(&mut self, tag: &str, step: Step, tail: &[&str]) -> Result<(), &'static str> {
        if self.child.is_some() || self.terminal.is_some() || !self.directories_safe() {
            return Err("signing_git");
        }
        let scratch = self.scratch_fd.as_ref().ok_or("signing_directory")?;
        let stdout = exclusive_file(scratch, &format!("{tag}.out"))?;
        let stderr = exclusive_file(scratch, &format!("{tag}.err"))?;
        let mut args = vec![
            CString::new("-c").unwrap(),
            CString::new("protocol.allow=never").unwrap(),
            CString::new("-c").unwrap(),
            CString::new(format!("core.hooksPath={}", self.hooks_path))
                .map_err(|_| "signing_name")?,
            CString::new("config").unwrap(),
            CString::new("--file").unwrap(),
            CString::new("staged.config").unwrap(),
            CString::new("--no-includes").unwrap(),
        ];
        for part in tail {
            args.push(CString::new(*part).map_err(|_| "signing_name")?);
        }
        let env = [
            "PATH=/usr/bin:/bin",
            &format!("HOME={}", self.home_path),
            "LC_ALL=C",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_SYSTEM=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_COUNT=0",
            "GIT_TERMINAL_PROMPT=0",
        ];
        let mut owned_env = Vec::new();
        for item in env {
            owned_env.push(CString::new(item).map_err(|_| "signing_name")?);
        }
        let stdin = self.null_in.as_ref().ok_or("signing_io")?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or("signing_timeout")?;
        #[cfg(test)]
        let (program, args, env) = match self.hooks.program.as_ref() {
            Some((program, args, env)) => (program.as_c_str(), args.as_slice(), env.as_slice()),
            None => (GIT, args.as_slice(), owned_env.as_slice()),
        };
        #[cfg(not(test))]
        let (program, args, env) = (GIT, args.as_slice(), owned_env.as_slice());
        let child = spawn_at(
            program,
            args,
            env,
            scratch.as_fd(),
            SpawnStdio {
                input: stdin.as_fd(),
                output: stdout.as_fd(),
                error: stderr.as_fd(),
            },
        )
        .map_err(|_| "signing_git")?;
        self.step = Some(step);
        self.deadline = Some(deadline);
        self.stdout_file = Some(stdout);
        self.stderr_file = Some(stderr);
        self.child = Some(child);
        self.reason = "signing_pending";
        Ok(())
    }

    fn drive(&mut self, now: Instant) -> Drive {
        let Some(child) = self.child.as_mut() else {
            return Drive::Done(Exit::Code(0));
        };
        let pid = child.pid();
        match child.try_wait() {
            Ok(None) if self.deadline.is_some_and(|deadline| now >= deadline) => {
                Drive::Unknown(pid)
            }
            Ok(None) => Drive::Pending(pid),
            Ok(Some(exit)) => {
                self.child = None;
                Drive::Done(exit)
            }
            Err(_) => Drive::Unknown(pid),
        }
    }

    fn stop_unknown(&mut self, pid: u32) -> TxState {
        self.terminal = Some(TxState::ChildUnknown { pid });
        self.reason = "signing_unknown";
        TxState::ChildUnknown { pid }
    }

    fn on_exit(&mut self, exit: Exit) -> TxState {
        if !self.directories_safe() {
            self.terminal = Some(TxState::OriginalChanged);
            self.reason = "signing_layout_changed";
            return TxState::OriginalChanged;
        }
        if !matches!(exit, Exit::Code(0)) {
            return self.reject("signing_git");
        }
        let step = self.step.take();
        match step {
            Some(Step::List) => self.after_list(),
            Some(Step::Set(index)) => {
                if index + 1 < self.sets.len() {
                    let (key, value) = self.sets[index + 1].clone();
                    if self
                        .spawn(
                            &format!("set{}", index + 1),
                            Step::Set(index + 1),
                            &[&key, &value],
                        )
                        .is_err()
                    {
                        return self.reject("signing_git");
                    }
                    TxState::Pending {
                        pid: self.child.as_ref().map(OwnedChild::pid).unwrap_or(0),
                    }
                } else if self
                    .spawn("final", Step::Final, &["--null", "--list"])
                    .is_err()
                {
                    self.reject("signing_git")
                } else {
                    TxState::Pending {
                        pid: self.child.as_ref().map(OwnedChild::pid).unwrap_or(0),
                    }
                }
            }
            Some(Step::Final) => self.after_final(),
            None => self.reject("signing_git"),
        }
    }

    fn after_list(&mut self) -> TxState {
        let bytes = match self.read_child_output() {
            Ok(bytes) => bytes,
            Err(reason) => return self.reject(reason),
        };
        let entries = match parse_null(&bytes) {
            Ok(entries) => entries,
            Err(reason) => return self.fail_refused(reason),
        };
        if let Err(reason) = validate_layout(&entries, &self.principal) {
            return self.fail_refused(reason);
        }
        self.baseline = unmanaged(&entries);
        self.sets = match planned_sets(&entries, &self.key_path, &self.allowed_path) {
            Ok(sets) => sets,
            Err(reason) => return self.fail_refused(reason),
        };
        if self.sets.is_empty() {
            return self.finish_unchanged();
        }
        let (key, value) = self.sets[0].clone();
        if self.spawn("set0", Step::Set(0), &[&key, &value]).is_err() {
            return self.reject("signing_git");
        }
        TxState::Pending {
            pid: self.child.as_ref().map(OwnedChild::pid).unwrap_or(0),
        }
    }

    fn after_final(&mut self) -> TxState {
        let bytes = match self.read_child_output() {
            Ok(bytes) => bytes,
            Err(reason) => return self.reject(reason),
        };
        let entries = match parse_null(&bytes) {
            Ok(entries) => entries,
            Err(reason) => return self.reject(reason),
        };
        if unmanaged(&entries) != self.baseline {
            return self.reject("signing_conflict");
        }
        if let Err(reason) = validate_layout(&entries, &self.principal) {
            return self.reject(reason);
        }
        if let Err(reason) = exact_managed(&entries, &self.key_path, &self.allowed_path) {
            return self.reject(reason);
        }
        let staged = match read_named(self.scratch_fd.as_ref().unwrap(), "staged.config") {
            Ok((_, bytes)) => bytes,
            Err(_) => return self.reject("signing_io"),
        };
        if staged.len() > MAX_BYTES {
            return self.reject("signing_unsupported");
        }
        self.final_bytes = staged;
        self.staged_hash = digest(&self.final_bytes);
        self.install()
    }

    fn finish_unchanged(&mut self) -> TxState {
        if self.directories_safe() && self.original_matches() && self.unlock_if_proven() {
            self.terminal = Some(TxState::Unchanged);
            self.reason = "signing_unchanged";
            TxState::Unchanged
        } else {
            self.terminal = Some(TxState::OriginalChanged);
            self.reason = "signing_lock";
            TxState::OriginalChanged
        }
    }

    fn install(&mut self) -> TxState {
        if !self.directories_safe() || !self.original_matches() || !self.lock_is_ours() {
            self.terminal = Some(TxState::OriginalChanged);
            self.reason = "signing_race";
            return TxState::OriginalChanged;
        }
        let mode = match self
            .snapshot_id
            .as_ref()
            .and_then(|id| supported_mode(id.mode))
        {
            Some(mode) => mode,
            None => return self.fail_refused("signing_unsupported"),
        };
        let gid = self.snapshot_id.as_ref().map(|id| id.gid).unwrap_or(0);
        let Some(lock) = self.lock_file.as_mut() else {
            return self.fail_refused("signing_lock");
        };
        if lock.seek(SeekFrom::Start(0)).is_err()
            || lock.write_all(&self.final_bytes).is_err()
            || lock.set_len(self.final_bytes.len() as u64).is_err()
        {
            return self.fail_refused("signing_io");
        }
        if fchmod(&*lock, Mode::from_raw_mode(mode)).is_err() || fsync(&*lock).is_err() {
            return self.fail_refused("signing_io");
        }
        let written = match fstat(&*lock) {
            Ok(stat) => stat,
            Err(_) => return self.fail_refused("signing_io"),
        };
        if written.st_gid != gid || supported_mode(written.st_mode) != Some(mode) {
            return self.fail_refused("signing_group");
        }
        if !self.directories_safe() || !self.original_matches() || !self.lock_is_ours() {
            self.terminal = Some(TxState::OriginalChanged);
            self.reason = "signing_race";
            return TxState::OriginalChanged;
        }
        let git = match self.git_fd.as_ref() {
            Some(fd) => fd,
            None => return self.fail_refused("signing_directory"),
        };
        self.rename_attempted = true;
        if renameat(git, "config.lock", git, "config").is_err() {
            return if self.original_matches() && self.unlock_if_proven() {
                self.terminal = Some(TxState::RenameFailed);
                self.reason = "signing_rename";
                TxState::RenameFailed
            } else {
                self.terminal = Some(TxState::InstallUnconfirmed);
                self.reason = "signing_unconfirmed";
                TxState::InstallUnconfirmed
            };
        }
        #[cfg(test)]
        let synced = match self.hooks.post_rename_sync {
            Some(hook) => hook(git).is_ok(),
            None => fsync(git).is_ok(),
        };
        #[cfg(not(test))]
        let synced = fsync(git).is_ok();
        let confirmed = fstat(self.lock_file.as_ref().unwrap())
            .ok()
            .and_then(|v| identity(&v).ok());
        let reread = read_named(git, "config");
        let valid = match (confirmed, reread) {
            (Some(held), Ok((named, bytes))) => {
                same_id(&held, &named)
                    && supported_mode(named.mode) == Some(mode)
                    && named.uid == rustix::process::geteuid().as_raw()
                    && named.gid == gid
                    && named.nlink == 1
                    && bytes == self.final_bytes
            }
            _ => false,
        };
        let state = if synced && valid && self.directories_safe() {
            TxState::Installed
        } else {
            TxState::InstallUnconfirmed
        };
        self.terminal = Some(state);
        self.reason = if state == TxState::Installed {
            "signing_installed"
        } else {
            "signing_unconfirmed"
        };
        state
    }

    fn directories_safe(&self) -> bool {
        let (Some(repo), Some(git)) = (&self.repo_fd, &self.git_fd) else {
            return false;
        };
        let safe = |s: &Stat| {
            FileType::from_raw_mode(s.st_mode) == FileType::Directory
                && s.st_uid == rustix::process::geteuid().as_raw()
                && s.st_mode & 0o022 == 0
                && s.st_mode & 0o200 != 0
        };
        match (
            fstat(repo),
            fstat(git),
            statat(repo, ".git", AtFlags::SYMLINK_NOFOLLOW),
        ) {
            (Ok(r), Ok(g), Ok(n)) => {
                safe(&r)
                    && safe(&g)
                    && safe(&n)
                    && g.st_dev == n.st_dev
                    && g.st_ino == n.st_ino
                    && refuse_present(git, "commondir").is_ok()
                    && refuse_present(git, "config.worktree").is_ok()
            }
            _ => false,
        }
    }

    fn reject(&mut self, reason: &'static str) -> TxState {
        if self.may_release() && self.unlock_if_proven() {
            self.terminal = Some(TxState::StagedRejected);
        } else {
            self.terminal = Some(TxState::OriginalChanged);
        }
        self.reason = reason;
        self.terminal.unwrap_or(TxState::StagedRejected)
    }

    fn fail_refused(&mut self, reason: &'static str) -> TxState {
        let state = if self.lock_file.is_some() && !(self.may_release() && self.unlock_if_proven())
        {
            TxState::OriginalChanged
        } else {
            TxState::Refused
        };
        self.terminal = Some(state);
        self.reason = reason;
        state
    }

    fn may_release(&self) -> bool {
        self.child.is_none()
            && !self.rename_attempted
            && self.directories_safe()
            && self.original_matches()
    }

    fn original_matches(&self) -> bool {
        let Some(expected) = &self.snapshot_id else {
            return false;
        };
        match self
            .git_fd
            .as_ref()
            .and_then(|fd| read_named(fd, "config").ok())
        {
            Some((id, bytes)) => same_id(&id, expected) && bytes == self.snapshot,
            None => false,
        }
    }

    fn lock_is_ours(&self) -> bool {
        let (Some(git), Some(file), Some(expected)) = (
            self.git_fd.as_ref(),
            self.lock_file.as_ref(),
            self.lock_id.as_ref(),
        ) else {
            return false;
        };
        let Ok(fd_stat) = fstat(file) else {
            return false;
        };
        let Ok(named) = statat(git, "config.lock", AtFlags::SYMLINK_NOFOLLOW) else {
            return false;
        };
        let expected_owner = self.snapshot_id.as_ref();
        FileType::from_raw_mode(fd_stat.st_mode) == FileType::RegularFile
            && fd_stat.st_nlink == 1
            && named.st_nlink == 1
            && fd_stat.st_uid == rustix::process::geteuid().as_raw()
            && expected_owner.is_some_and(|id| fd_stat.st_gid == id.gid)
            && fd_stat.st_uid == named.st_uid
            && fd_stat.st_gid == named.st_gid
            && fd_stat.st_mode == named.st_mode
            && supported_mode(fd_stat.st_mode).is_some()
            && fd_stat.st_dev == named.st_dev
            && fd_stat.st_ino == named.st_ino
            && fd_stat.st_dev == expected.dev
            && fd_stat.st_ino == expected.ino
    }

    fn unlock_if_proven(&mut self) -> bool {
        if self.child.is_some() || !self.original_matches() || !self.lock_is_ours() {
            return false;
        }
        let Some(git) = self.git_fd.as_ref() else {
            return false;
        };
        if unlinkat(git, "config.lock", AtFlags::empty()).is_err() {
            return false;
        }
        self.lock_file = None;
        true
    }

    fn read_child_output(&mut self) -> Result<Vec<u8>, &'static str> {
        let stdout = self.stdout_file.as_mut().ok_or("signing_io")?;
        let stderr = self.stderr_file.as_mut().ok_or("signing_io")?;
        let out = read_limited(stdout)?;
        let err = read_limited(stderr)?;
        if err.len() > MAX_BYTES {
            return Err("signing_io");
        }
        Ok(out)
    }
}

#[path = "repo_support.rs"]
mod support;
use support::*;
pub(crate) use support::{path_text, validate_component};

#[cfg(test)]
#[path = "repo_tests.rs"]
mod tests;
