#![forbid(unsafe_code)]
//! Retained repository/store observations and explicit controlled execution
//! enrollment. Selection alone never grants task or provider authority.
use crate::task_ref::{GitOid, Sha256Digest, TaskRefV1, validate_id};
use rustix::fs::{AtFlags, Mode, OFlags, openat, statat};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::BTreeSet,
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

pub type BindingResult<T> = std::result::Result<T, BindingError>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    InvalidSelector,
    MissingRepository,
    NamespaceChanged,
    Unsupported,
    Unenrolled,
    AuthorityChanged,
    GitMetadata,
    UnsupportedGitConfig,
    BaselineChanged,
    BranchChanged,
    OverlayChanged,
    StoreSelector,
    StoreChanged,
    StoreProfile,
    SourceMapping,
    Io(String),
    Native(String),
}
impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "execution binding refused: {self:?}")
    }
}
impl std::error::Error for BindingError {}
fn io(e: impl std::fmt::Display) -> BindingError {
    BindingError::Io(e.to_string())
}
const MAX_IMAGE: usize = 16 * 1024 * 1024;
const MAX_GIT_TEXT: usize = 1024 * 1024;
const MAX_OVERLAY_FILES: usize = 4096;
const MAX_OVERLAY_BYTES: usize = 16 * 1024 * 1024;
type Id = (u64, u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    id: Id,
    uid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
fn stamp(file: &File) -> BindingResult<Stamp> {
    let m = file.metadata().map_err(io)?;
    Ok(Stamp {
        id: (m.dev(), m.ino()),
        uid: m.uid(),
        mode: m.mode(),
        nlink: m.nlink(),
        size: m.len(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
    })
}
fn checked_path(path: &Path) -> BindingResult<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(BindingError::InvalidSelector);
    }
    Ok(())
}
#[derive(Debug)]
struct HeldDir {
    path: PathBuf,
    file: File,
    id: Id,
    uid: u32,
    mode: u32,
}
impl HeldDir {
    fn open(path: &Path) -> BindingResult<Self> {
        checked_path(path)?;
        let mut file = File::open("/").map_err(io)?;
        for component in path.components() {
            if let Component::Normal(name) = component {
                file = File::from(
                    openat(
                        &file,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(io)?,
                );
            }
        }
        let s = stamp(&file)?;
        Ok(Self {
            path: path.into(),
            file,
            id: s.id,
            uid: s.uid,
            mode: s.mode,
        })
    }
    fn duplicate(&self) -> BindingResult<Self> {
        self.verify()?;
        Ok(Self {
            path: self.path.clone(),
            file: self.file.try_clone().map_err(io)?,
            id: self.id,
            uid: self.uid,
            mode: self.mode,
        })
    }
    fn verify(&self) -> BindingResult<()> {
        let current = Self::open(&self.path)?;
        let held = stamp(&self.file)?;
        if current.id != self.id
            || held.id != self.id
            || current.uid != self.uid
            || current.mode != self.mode
        {
            return Err(BindingError::NamespaceChanged);
        }
        Ok(())
    }
}
#[derive(Debug)]
struct HeldFile {
    path: PathBuf,
    parent: HeldDir,
    file: File,
    snapshot: Stamp,
    digest: Sha256Digest,
    bytes: Vec<u8>,
}
impl HeldFile {
    fn open(path: &Path, limit: usize) -> BindingResult<Self> {
        checked_path(path)?;
        let parent = HeldDir::open(path.parent().ok_or(BindingError::InvalidSelector)?)?;
        let name = path.file_name().ok_or(BindingError::InvalidSelector)?;
        let mut file = File::from(
            openat(
                &parent.file,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        let before = stamp(&file)?;
        if !file.metadata().map_err(io)?.is_file()
            || before.nlink != 1
            || before.size > limit as u64
        {
            return Err(BindingError::NamespaceChanged);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.len() > limit || before != stamp(&file)? {
            return Err(BindingError::NamespaceChanged);
        }
        let named = statat(&parent.file, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if named.st_dev as u64 != before.id.0 || named.st_ino as u64 != before.id.1 {
            return Err(BindingError::NamespaceChanged);
        }
        parent.verify()?;
        let digest = Sha256Digest::of(&bytes);
        Ok(Self {
            path: path.into(),
            parent,
            file,
            snapshot: before,
            digest,
            bytes,
        })
    }
    fn verify(&self) -> BindingResult<()> {
        self.parent.verify()?;
        if stamp(&self.file)? != self.snapshot {
            return Err(BindingError::NamespaceChanged);
        }
        let current = Self::open(&self.path, MAX_IMAGE)?;
        if current.snapshot != self.snapshot || current.digest != self.digest {
            return Err(BindingError::NamespaceChanged);
        }
        Ok(())
    }
}
#[derive(Debug)]
struct GitPins {
    gitdir: HeldDir,
    common: HeldDir,
    gitfile: Option<HeldFile>,
    commonfile: Option<HeldFile>,
}
fn normalized_metadata(base: &Path, text: &str) -> BindingResult<PathBuf> {
    let candidate = if Path::new(text).is_absolute() {
        PathBuf::from(text)
    } else {
        base.join(text)
    };
    let mut result = PathBuf::from("/");
    for c in candidate.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => result.push(n),
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return Err(BindingError::GitMetadata);
                }
            }
            _ => return Err(BindingError::GitMetadata),
        }
    }
    Ok(result)
}
fn git_pins(root: &HeldDir) -> BindingResult<GitPins> {
    let dot = root.path.join(".git");
    let metadata = std::fs::symlink_metadata(&dot).map_err(|_| BindingError::MissingRepository)?;
    let (gitdir, gitfile) = if metadata.is_dir() {
        (HeldDir::open(&dot)?, None)
    } else if metadata.is_file() {
        let f = HeldFile::open(&dot, 4096)?;
        let text = std::str::from_utf8(&f.bytes)
            .map_err(|_| BindingError::GitMetadata)?
            .trim();
        let target = text
            .strip_prefix("gitdir:")
            .ok_or(BindingError::GitMetadata)?
            .trim();
        if target.is_empty() || target.contains(['\n', '\r']) {
            return Err(BindingError::GitMetadata);
        }
        (
            HeldDir::open(&normalized_metadata(&root.path, target)?)?,
            Some(f),
        )
    } else {
        return Err(BindingError::GitMetadata);
    };
    let path = gitdir.path.join("commondir");
    let (common, commonfile) = match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let f = HeldFile::open(&path, 4096)?;
            let text = std::str::from_utf8(&f.bytes)
                .map_err(|_| BindingError::GitMetadata)?
                .trim();
            if text.is_empty() || text.contains(['\n', '\r']) {
                return Err(BindingError::GitMetadata);
            }
            (
                HeldDir::open(&normalized_metadata(&gitdir.path, text)?)?,
                Some(f),
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (gitdir.duplicate()?, None),
        Err(e) => return Err(io(e)),
    };
    Ok(GitPins {
        gitdir,
        common,
        gitfile,
        commonfile,
    })
}
impl GitPins {
    fn verify(&self) -> BindingResult<()> {
        self.gitdir.verify()?;
        self.common.verify()?;
        if let Some(f) = &self.gitfile {
            f.verify()?
        }
        match &self.commonfile {
            Some(f) => f.verify()?,
            None => match statat(&self.gitdir.file, "commondir", AtFlags::SYMLINK_NOFOLLOW) {
                Err(error) if error == rustix::io::Errno::NOENT => {}
                _ => return Err(BindingError::NamespaceChanged),
            },
        }
        Ok(())
    }
}
pub struct RepoSelectors<'a> {
    pub explicit_repo: Option<&'a Path>,
    pub environment_repo: Option<&'a OsStr>,
    pub cwd: &'a Path,
}
pub struct StoreSelector<'a> {
    pub explicit_crdb: Option<&'a Path>,
}
#[derive(Debug)]
pub struct RepositorySelection {
    root: HeldDir,
    git: GitPins,
}
impl RepositorySelection {
    pub fn root(&self) -> &Path {
        &self.root.path
    }
    pub fn execution_root(&self) -> &Path {
        self.root()
    }
    pub fn is_linked_worktree(&self) -> bool {
        self.git.commonfile.is_some() || self.git.gitdir.id != self.git.common.id
    }
    pub fn common_worktree_root(&self) -> Option<&Path> {
        if self.git.common.path.file_name() == Some(OsStr::new(".git")) {
            self.git.common.path.parent()
        } else {
            None
        }
    }
    pub fn same_common_git_identity(&self, other: &Self) -> bool {
        self.git.common.id == other.git.common.id
    }
    pub fn verify_effective_toplevel(&self) -> BindingResult<()> {
        reject_git_pins_config_includes(&self.git)?;
        let top = safe_git(&self.root.path, &["rev-parse", "--show-toplevel"])?;
        let top = std::str::from_utf8(&top)
            .map_err(|_| BindingError::GitMetadata)?
            .strip_suffix('\n')
            .ok_or(BindingError::GitMetadata)?;
        if top.contains(['\n', '\r']) {
            return Err(BindingError::GitMetadata);
        }
        let effective_root = HeldDir::open(Path::new(top))?;
        if effective_root.path != self.root.path || effective_root.id != self.root.id {
            return Err(BindingError::NamespaceChanged);
        }
        self.revalidate()
    }
    pub fn revalidate(&self) -> BindingResult<()> {
        self.root.verify()?;
        self.git.verify()
    }
}
pub fn select_repository(selectors: RepoSelectors<'_>) -> BindingResult<RepositorySelection> {
    let root = if let Some(path) = selectors.explicit_repo {
        checked_path(path)?;
        path.to_path_buf()
    } else if let Some(value) = selectors.environment_repo {
        let path = Path::new(value);
        checked_path(path)?;
        path.to_path_buf()
    } else {
        checked_path(selectors.cwd)?;
        selectors
            .cwd
            .ancestors()
            .find(|p| std::fs::symlink_metadata(p.join(".git")).is_ok())
            .ok_or(BindingError::MissingRepository)?
            .to_path_buf()
    };
    let root = HeldDir::open(&root)?;
    let git = git_pins(&root)?;
    Ok(RepositorySelection { root, git })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchBinding {
    Branch(String),
    Detached,
}
#[derive(Clone, PartialEq, Eq)]
struct SourceEnrollment {
    root: PathBuf,
    identity: Id,
    root_generation: u64,
    source_id: String,
    source_generation: u64,
    path: String,
}
#[derive(Clone, PartialEq, Eq)]
struct StoreEnrollment {
    id: String,
    path: PathBuf,
    identity: Id,
    parent: Id,
    image: Sha256Digest,
    site: [u8; 16],
    application: i64,
    schema: i64,
}
#[derive(Clone, PartialEq, Eq)]
struct Enrollment {
    workspace: String,
    repo: String,
    worktree: String,
    root: PathBuf,
    root_id: Id,
    gitdir: Id,
    common: Id,
    generation: u64,
    authority_epoch: u64,
    baseline: GitOid,
    branch: BranchBinding,
    integration_target: String,
    overlay: Sha256Digest,
    source: SourceEnrollment,
    store: StoreEnrollment,
}
struct TrustedFixtureAuthority<'a> {
    enrollment: &'a Enrollment,
    generation: &'a Cell<u64>,
    source_generation: &'a Cell<u64>,
    epoch: &'a Cell<u64>,
}
pub struct ExecutionAuthority<'a> {
    profile: Option<TrustedFixtureAuthority<'a>>,
}
impl ExecutionAuthority<'_> {
    pub fn unsupported() -> Self {
        Self { profile: None }
    }
}
pub struct WorkspaceExecutionBinding {
    root: HeldDir,
    git: GitPins,
    source: HeldDir,
    store: HeldFile,
    enrollment: Enrollment,
    commitment: Sha256Digest,
}
fn reject_git_config_includes(bytes: &[u8]) -> BindingResult<()> {
    let _ = std::str::from_utf8(bytes).map_err(|_| BindingError::UnsupportedGitConfig)?;
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .current_dir("/")
        .args([
            "--no-pager",
            "config",
            "--no-includes",
            "--file",
            "-",
            "--list",
            "--name-only",
            "-z",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(io)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(BindingError::UnsupportedGitConfig)?;
    let output = std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let res = stdin.write_all(bytes);
            drop(stdin);
            res
        });
        let waited = child.wait_with_output();
        let write_res = writer
            .join()
            .map_err(|_| BindingError::UnsupportedGitConfig)?;
        let out = waited.map_err(io)?;
        if !out.status.success() {
            return Err(BindingError::UnsupportedGitConfig);
        }
        write_res.map_err(io)?;
        Ok(out)
    })?;
    if output.stdout.len() > MAX_GIT_TEXT {
        return Err(BindingError::UnsupportedGitConfig);
    }
    for raw_key in output.stdout.split(|&b| b == 0) {
        if raw_key.is_empty() {
            continue;
        }
        let key = std::str::from_utf8(raw_key).map_err(|_| BindingError::UnsupportedGitConfig)?;
        let section = key.split('.').next().unwrap_or("");
        if section.eq_ignore_ascii_case("include") || section.eq_ignore_ascii_case("includeif") {
            return Err(BindingError::UnsupportedGitConfig);
        }
    }
    Ok(())
}
fn reject_git_pins_config_includes(git: &GitPins) -> BindingResult<()> {
    for path in [
        git.gitdir.path.join("config"),
        git.gitdir.path.join("config.worktree"),
        git.common.path.join("config"),
    ] {
        if std::fs::symlink_metadata(&path).is_ok() {
            let f = HeldFile::open(&path, MAX_GIT_TEXT)?;
            reject_git_config_includes(&f.bytes)?;
        }
    }
    Ok(())
}
fn safe_git(root: &Path, args: &[&str]) -> BindingResult<Vec<u8>> {
    if std::fs::symlink_metadata(root.join(".git")).is_ok_and(|m| m.is_dir()) {
        let path = root.join(".git/config");
        if std::fs::symlink_metadata(&path).is_ok() {
            let f = HeldFile::open(&path, MAX_GIT_TEXT)?;
            reject_git_config_includes(&f.bytes)?;
        }
    }
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    let output = command
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "diff.external=",
            "-C",
        ])
        .arg(root)
        .args(args)
        .output()
        .map_err(io)?;
    if !output.status.success() || output.stdout.len() > MAX_GIT_TEXT {
        return Err(BindingError::GitMetadata);
    }
    Ok(output.stdout)
}
fn git_state(root: &HeldDir, git: &GitPins) -> BindingResult<(GitOid, BranchBinding)> {
    // Reject local config includes before any subprocess can follow them,
    // including the common configuration of linked worktrees.
    reject_git_pins_config_includes(git)?;
    // A local core.worktree override can preserve HEAD, branch and Git-directory
    // identities while redirecting a scrubbed child to another workspace.
    let top = safe_git(&root.path, &["rev-parse", "--show-toplevel"])?;
    let top = std::str::from_utf8(&top)
        .map_err(|_| BindingError::GitMetadata)?
        .strip_suffix('\n')
        .ok_or(BindingError::GitMetadata)?;
    if top.contains(['\n', '\r']) {
        return Err(BindingError::GitMetadata);
    }
    let effective_root = HeldDir::open(Path::new(top))?;
    if effective_root.path != root.path || effective_root.id != root.id {
        return Err(BindingError::NamespaceChanged);
    }
    root.verify()?;
    let head = safe_git(&root.path, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let baseline = GitOid::from_hex(
        std::str::from_utf8(&head)
            .map_err(|_| BindingError::GitMetadata)?
            .trim(),
    )
    .map_err(|_| BindingError::GitMetadata)?;
    let symbolic = safe_git(&root.path, &["rev-parse", "--symbolic-full-name", "HEAD"])?;
    let reference = std::str::from_utf8(&symbolic)
        .map_err(|_| BindingError::GitMetadata)?
        .trim();
    let branch = if reference == "HEAD" {
        BranchBinding::Detached
    } else if reference.starts_with("refs/heads/") {
        BranchBinding::Branch(reference.into())
    } else {
        return Err(BindingError::GitMetadata);
    };
    Ok((baseline, branch))
}
fn mapped_control_paths(store: &Path) -> BindingResult<BTreeSet<PathBuf>> {
    let parent = store.parent().ok_or(BindingError::StoreProfile)?;
    let name = store
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(BindingError::StoreProfile)?;
    Ok([
        store.to_path_buf(),
        parent.join(format!("{name}.lock")),
        parent.join(format!("{name}.next")),
        parent.join(format!("{name}.intent")),
    ]
    .into_iter()
    .collect())
}
fn overlay(root: &HeldDir, git: &GitPins, store: &Path) -> BindingResult<Sha256Digest> {
    let excluded = mapped_control_paths(store)?;
    let mut pending = vec![root.path.clone()];
    let mut entries = Vec::new();
    let mut total = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).map_err(io)? {
            let entry = entry.map_err(io)?;
            let path = entry.path();
            if path == root.path.join(".git")
                || path == git.gitdir.path
                || path == git.common.path
                || excluded.contains(&path)
            {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path).map_err(io)?;
            let relative = path
                .strip_prefix(&root.path)
                .map_err(|_| BindingError::OverlayChanged)?
                .as_os_str()
                .to_str()
                .ok_or(BindingError::OverlayChanged)?
                .to_owned();
            if meta.file_type().is_symlink() {
                return Err(BindingError::OverlayChanged);
            }
            if meta.is_dir() {
                let held = HeldDir::open(&path)?;
                entries.push((relative, meta.mode(), Vec::new()));
                pending.push(held.path);
            } else if meta.is_file() {
                let file = HeldFile::open(&path, MAX_OVERLAY_BYTES)?;
                total = total
                    .checked_add(file.bytes.len())
                    .ok_or(BindingError::OverlayChanged)?;
                if total > MAX_OVERLAY_BYTES {
                    return Err(BindingError::OverlayChanged);
                }
                entries.push((relative, meta.mode(), file.bytes));
            } else {
                return Err(BindingError::OverlayChanged);
            }
            if entries.len() > MAX_OVERLAY_FILES {
                return Err(BindingError::OverlayChanged);
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hash = Sha256::new();
    hash.update(b"chinwag-controlled-execution-overlay-v1\0");
    for (path, mode, bytes) in entries {
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        hash.update(mode.to_be_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    root.verify()?;
    git.verify()?;
    Ok(Sha256Digest(hash.finalize().into()))
}
fn current_profile<'a>(authority: &'a ExecutionAuthority<'a>) -> BindingResult<&'a Enrollment> {
    let p = authority
        .profile
        .as_ref()
        .ok_or(BindingError::Unsupported)?;
    if p.generation.get() != p.enrollment.generation
        || p.source_generation.get() != p.enrollment.source.root_generation
        || p.epoch.get() != p.enrollment.authority_epoch
    {
        return Err(BindingError::AuthorityChanged);
    }
    Ok(p.enrollment)
}
fn enrollment_bytes(e: &Enrollment) -> BindingResult<Vec<u8>> {
    use crate::task_ref::{encode_bytes_field, encode_str_field, encode_u64};
    let mut out = b"chinwag-workspace-execution-binding-v1\0".to_vec();
    fn text(out: &mut Vec<u8>, value: &str) {
        out.extend(crate::task_ref::encode_str_field(value));
    }
    fn path(out: &mut Vec<u8>, value: &Path) -> BindingResult<()> {
        text(
            out,
            value
                .as_os_str()
                .to_str()
                .ok_or(BindingError::InvalidSelector)?,
        );
        Ok(())
    }
    fn id(out: &mut Vec<u8>, value: Id) {
        out.extend(value.0.to_be_bytes());
        out.extend(value.1.to_be_bytes());
    }
    for value in [
        &e.workspace,
        &e.repo,
        &e.worktree,
        &e.source.source_id,
        &e.store.id,
    ] {
        validate_id(value, "binding enrollment").map_err(|_| BindingError::Unenrolled)?;
    }
    for value in [&e.workspace, &e.repo, &e.worktree] {
        out.extend(encode_str_field(value));
    }
    path(&mut out, &e.root)?;
    id(&mut out, e.root_id);
    id(&mut out, e.gitdir);
    id(&mut out, e.common);
    out.extend(encode_u64(e.generation));
    out.extend(encode_u64(e.authority_epoch));
    out.extend(e.baseline.encode_typed());
    match &e.branch {
        BranchBinding::Branch(reference) => {
            out.push(1);
            text(&mut out, reference)
        }
        BranchBinding::Detached => out.push(0),
    }
    text(&mut out, &e.integration_target);
    out.extend(e.overlay.encode_typed());
    path(&mut out, &e.source.root)?;
    id(&mut out, e.source.identity);
    out.extend(encode_u64(e.source.root_generation));
    text(&mut out, &e.source.source_id);
    out.extend(encode_u64(e.source.source_generation));
    text(&mut out, &e.source.path);
    text(&mut out, &e.store.id);
    path(&mut out, &e.store.path)?;
    id(&mut out, e.store.identity);
    id(&mut out, e.store.parent);
    out.extend(e.store.image.encode_typed());
    out.extend(encode_bytes_field(&e.store.site));
    out.extend(e.store.application.to_be_bytes());
    out.extend(e.store.schema.to_be_bytes());
    Ok(out)
}
fn controls_absent(store: &Path) -> BindingResult<()> {
    for path in mapped_control_paths(store)? {
        if path != store && std::fs::symlink_metadata(path).is_ok() {
            return Err(BindingError::StoreChanged);
        }
    }
    Ok(())
}
pub fn bind_execution(
    selected: &RepositorySelection,
    store: StoreSelector<'_>,
    authority: &ExecutionAuthority<'_>,
) -> BindingResult<WorkspaceExecutionBinding> {
    // Enrollment/custody precede store bytes and native import.
    let e = current_profile(authority)?.clone();
    selected.revalidate()?;
    if selected.root.uid != rustix::process::geteuid().as_raw() || selected.root.mode & 0o022 != 0 {
        return Err(BindingError::Unenrolled);
    }
    if selected.root.path != e.root
        || selected.root.id != e.root_id
        || selected.git.gitdir.id != e.gitdir
        || selected.git.common.id != e.common
    {
        return Err(BindingError::Unenrolled);
    }
    if let Some(path) = store.explicit_crdb {
        checked_path(path)?;
        if path != e.store.path {
            return Err(BindingError::StoreSelector);
        }
    }
    let root = selected.root.duplicate()?;
    let git = git_pins(&root)?;
    let source = HeldDir::open(&e.source.root)?;
    if source.id != e.source.identity {
        return Err(BindingError::SourceMapping);
    }
    let (baseline, branch) = git_state(&root, &git)?;
    if baseline != e.baseline {
        return Err(BindingError::BaselineChanged);
    }
    if branch != e.branch {
        return Err(BindingError::BranchChanged);
    }
    if overlay(&root, &git, &e.store.path)? != e.overlay {
        return Err(BindingError::OverlayChanged);
    }
    for path in mapped_control_paths(&e.store.path)? {
        if path != e.store.path && std::fs::symlink_metadata(path).is_ok() {
            return Err(BindingError::StoreChanged);
        }
    }
    let captured = HeldFile::open(&e.store.path, MAX_IMAGE)?;
    if captured.snapshot.uid != rustix::process::geteuid().as_raw()
        || captured.snapshot.mode & 0o7777 != 0o600
        || captured.parent.uid != rustix::process::geteuid().as_raw()
        || captured.parent.mode & 0o7777 != 0o700
    {
        return Err(BindingError::StoreProfile);
    }
    if captured.snapshot.id != e.store.identity
        || captured.parent.id != e.store.parent
        || captured.digest != e.store.image
    {
        return Err(BindingError::StoreChanged);
    }
    let receipt =
        chinwag_snapshot_session_private::validate_detached_private_image(&captured.bytes)
            .map_err(|e| BindingError::Native(e.to_string()))?;
    if receipt.site_id() != e.store.site
        || receipt.application_id() != e.store.application
        || receipt.schema_version() != e.store.schema
    {
        return Err(BindingError::StoreProfile);
    }
    captured.verify()?;
    let commitment = Sha256Digest::of(&enrollment_bytes(&e)?);
    let binding = WorkspaceExecutionBinding {
        root,
        git,
        source,
        store: captured,
        enrollment: e,
        commitment,
    };
    binding.revalidate(authority)?;
    Ok(binding)
}
pub fn with_execution_binding<T>(
    selection: &RepositorySelection,
    store: StoreSelector<'_>,
    authority: &ExecutionAuthority<'_>,
    effect: impl FnOnce(&mut WorkspaceExecutionBinding) -> BindingResult<T>,
) -> BindingResult<T> {
    let mut binding = bind_execution(selection, store, authority)?;
    binding.revalidate(authority)?;
    effect(&mut binding)
}
impl WorkspaceExecutionBinding {
    pub fn revalidate(&self, authority: &ExecutionAuthority<'_>) -> BindingResult<()> {
        self.revalidate_observers(authority)?;
        controls_absent(&self.enrollment.store.path)
    }
    pub fn revalidate_for_store_owner(
        &self,
        authority: &ExecutionAuthority<'_>,
        owner: &mut impl chinwag_snapshot_session_private::replacement::OriginalStoreOwner,
    ) -> BindingResult<()> {
        if self.enrollment.store.path != self.root.path.join(".chinwag/state.crdb") {
            return Err(BindingError::StoreProfile);
        }
        owner
            .verify_bound_source(
                self.root.id,
                self.store.parent.id,
                self.store.snapshot.id,
                self.store.digest.0,
            )
            .map_err(|e| BindingError::Native(e.to_string()))?;
        self.revalidate_observers(authority)?;
        let lock = self.root.path.join(".chinwag/state.crdb.lock");
        for path in mapped_control_paths(&self.enrollment.store.path)? {
            if path != self.enrollment.store.path
                && path != lock
                && std::fs::symlink_metadata(path).is_ok()
            {
                return Err(BindingError::StoreChanged);
            }
        }
        owner
            .verify_bound_source(
                self.root.id,
                self.store.parent.id,
                self.store.snapshot.id,
                self.store.digest.0,
            )
            .map_err(|e| BindingError::Native(e.to_string()))
    }
    fn revalidate_observers(&self, authority: &ExecutionAuthority<'_>) -> BindingResult<()> {
        if current_profile(authority)? != &self.enrollment {
            return Err(BindingError::AuthorityChanged);
        }
        self.root.verify()?;
        self.git.verify()?;
        self.source.verify()?;
        self.store.verify()?;
        let (baseline, branch) = git_state(&self.root, &self.git)?;
        if baseline != self.enrollment.baseline {
            return Err(BindingError::BaselineChanged);
        }
        if branch != self.enrollment.branch {
            return Err(BindingError::BranchChanged);
        }
        if overlay(&self.root, &self.git, &self.enrollment.store.path)? != self.enrollment.overlay {
            return Err(BindingError::OverlayChanged);
        }
        Ok(())
    }
    pub fn execution_root(&self) -> &Path {
        &self.root.path
    }
    pub fn workspace_id(&self) -> &str {
        &self.enrollment.workspace
    }
    pub fn repo_id(&self) -> &str {
        &self.enrollment.repo
    }
    pub fn worktree_id(&self) -> &str {
        &self.enrollment.worktree
    }
    pub fn baseline(&self) -> GitOid {
        self.enrollment.baseline
    }
    pub fn branch_binding(&self) -> &BranchBinding {
        &self.enrollment.branch
    }
    pub fn branch_ref(&self) -> Option<&str> {
        match &self.enrollment.branch {
            BranchBinding::Branch(r) => Some(r),
            BranchBinding::Detached => None,
        }
    }
    pub fn branch_metadata(&self) -> String {
        self.branch_ref()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("detached:{}", self.baseline()))
    }
    pub fn store_path(&self) -> &Path {
        &self.enrollment.store.path
    }
    pub fn store_id(&self) -> &str {
        &self.enrollment.store.id
    }
    pub fn commitment_id(&self) -> String {
        format!("binding-{}", self.commitment)
    }
    pub fn commitment(&self) -> Sha256Digest {
        self.commitment
    }
    pub fn root_identity(&self) -> Id {
        self.root.id
    }
    pub fn gitdir_identity(&self) -> Id {
        self.git.gitdir.id
    }
    pub fn common_git_identity(&self) -> Id {
        self.git.common.id
    }
    pub fn integration_target(&self) -> &str {
        &self.enrollment.integration_target
    }
    pub fn source_root(&self) -> &Path {
        &self.source.path
    }
    pub fn source_root_identity(&self) -> Id {
        self.source.id
    }
    pub fn source_root_generation(&self) -> u64 {
        self.enrollment.source.root_generation
    }
    pub fn source_id(&self) -> &str {
        &self.enrollment.source.source_id
    }
    pub fn source_generation(&self) -> u64 {
        self.enrollment.source.source_generation
    }
    pub fn canonical_task_path(&self) -> &str {
        &self.enrollment.source.path
    }
    pub fn validate_task_ref(&self, task: &TaskRefV1) -> BindingResult<()> {
        task.validate().map_err(|_| BindingError::SourceMapping)?;
        self.source.verify()?;
        if task.workspace_id != self.enrollment.workspace
            || task.repo_id != self.enrollment.repo
            || task.task_source_id != self.enrollment.source.source_id
            || task.source_generation != self.enrollment.source.source_generation
            || task.canonical_task_path != self.enrollment.source.path
            || task.baseline_commit != self.enrollment.baseline
        {
            return Err(BindingError::SourceMapping);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "execution_binding_tests.rs"]
pub(crate) mod test_support;
