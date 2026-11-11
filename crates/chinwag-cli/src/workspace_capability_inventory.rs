#![forbid(unsafe_code)]

//! Continuously maintained JJ workspace-isolation and capability-provenance
//! inventory (`CHWG-JJ-WORKSPACE-REGISTRY-01`, Slice 1).
//!
//! Invariants enforced by this module:
//! - Every source-bound agent mutation requires an exclusive physical JJ
//!   workspace directory `(dev, ino)` and an exclusive mutable JJ working-copy
//!   change ID (`jj_working_copy_change_id`), distinct from the operational
//!   checkout while sharing the backing Git object store.
//! - Path aliases, symlinks, duplicate physical `(dev, ino)` claims, shared
//!   mutable JJ changes, bare/unresolved actors, and mismatched `TaskRefV1`
//!   bindings fail closed and place conflicting claims into a scoped hold.
//! - Capability records keep `Implemented`, `Tested`, `AcceptedSource`,
//!   `Installed`, `Operational`, `Authorized`, `Unknown`, and `Held` distinct;
//!   dirty/uncommitted builds or mismatched binary digests invalidate
//!   `AcceptedSource`/`Installed`/`Operational`/`Authorized` claims.
//! - Inventory observations are never execution or production authority.
//! - Updates use an append-only, fsync-checked intent/result journal with
//!   idempotent `(operation_id, intent_digest)` replay handling, crash-recovery
//!   holds for incomplete intents, and non-mutating discovery snapshots.

use crate::agent_instance::ActorAddress;
use crate::task_ref::{GitOid, Sha256Digest, TaskRefV1, validate_id};
use crate::task_store::StoredObservation;
use crate::task_write_journal::strict_json_object;
use rustix::fs::{
    AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, Stat, fcntl_getfl, fcntl_setfl, flock,
    fstat, openat, statat,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_INVENTORY_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_INVENTORY_RECORDS: usize = 2048;
pub const MAX_SCOPE_PATHS: usize = 64;

mod git_oid_serde {
    use super::*;
    pub fn serialize<S: Serializer>(oid: &GitOid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&oid.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<GitOid, D::Error> {
        let raw = String::deserialize(deserializer)?;
        GitOid::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

mod opt_git_oid_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        oid: &Option<GitOid>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match oid {
            Some(v) => serializer.serialize_some(&v.to_string()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<GitOid>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|s| GitOid::from_hex(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

mod sha256_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        digest: &Sha256Digest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&digest.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Sha256Digest, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Sha256Digest::from_hex(&raw).map_err(serde::de::Error::custom)
    }
}

mod opt_sha256_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        digest: &Option<Sha256Digest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match digest {
            Some(v) => serializer.serialize_some(&v.to_string()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Sha256Digest>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|s| Sha256Digest::from_hex(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn decode_lower_hex(raw: &str) -> Result<Vec<u8>, &'static str> {
    if !raw.len().is_multiple_of(2) {
        return Err("odd hex length");
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_bytes().chunks_exact(2) {
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err("invalid lowercase hex character"),
        };
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

mod task_ref_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        task_ref: &TaskRefV1,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = task_ref.encode().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&encode_lower_hex(&bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<TaskRefV1, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = decode_lower_hex(&raw).map_err(serde::de::Error::custom)?;
        TaskRefV1::decode(&bytes).map_err(serde::de::Error::custom)
    }
}

mod opt_task_ref_serde {
    use super::*;
    pub fn serialize<S: Serializer>(
        task_ref: &Option<TaskRefV1>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match task_ref {
            Some(v) => {
                let bytes = v.encode().map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&encode_lower_hex(&bytes))
            }
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<TaskRefV1>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|s| {
            let bytes = decode_lower_hex(&s).map_err(serde::de::Error::custom)?;
            TaskRefV1::decode(&bytes).map_err(serde::de::Error::custom)
        })
        .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    InvalidIdentifier(String),
    InvalidPath(String),
    SymlinkOrNonDirectory(String),
    UnownedOrWritableDirectory(String),
    OperationalCheckoutForbidden(String),
    SharedGitStoreMismatch(String),
    DuplicatePhysicalWorkspace(String),
    DuplicateWorkspaceName(String),
    SharedMutableJjChange(String),
    UnresolvedOrMismatchedOwner(String),
    WorkspaceIdentityDrift(String),
    WorkspaceHeld(String),
    UnprovenCapabilityClaim(String),
    DirtyOrMismatchedBuildProvenance(String),
    InventoryNotExecutionAuthority,
    ConflictingReplay(String),
    IncompleteIntentHeld(String),
    JournalCorruptOrBounded(String),
    Io(String),
}

impl std::fmt::Display for InventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "workspace/capability inventory refused: {self:?}")
    }
}

impl std::error::Error for InventoryError {}

pub type InventoryResult<T> = Result<T, InventoryError>;

/// Checked wall clock in milliseconds since UNIX epoch.
pub fn current_unix_ms() -> InventoryResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| InventoryError::Io(format!("system clock precedes UNIX epoch: {err}")))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|err| InventoryError::Io(format!("UNIX millisecond clock overflow: {err}")))
}

/// Bind this process to its kernel start timestamp, in UNIX microseconds.
pub fn observe_current_process_birth_binding() -> InventoryResult<(u32, u64)> {
    let pid = std::process::id();
    match chinwag_host_process::inspect_process_birth(pid) {
        Ok(chinwag_host_process::ProcessBirthObservation::Alive(info)) => {
            Ok((pid, info.start_time_unix_us))
        }
        Ok(chinwag_host_process::ProcessBirthObservation::NotFoundOrZombie) => Err(
            InventoryError::Io("current process birth unavailable".to_owned()),
        ),
        Err(err) => Err(InventoryError::Io(format!(
            "current process birth inspection failed: {err}"
        ))),
    }
}

pub fn check_pid_birth_binding_live(pid: u32, expected_birth_unix_us: u64) -> Result<bool, String> {
    match chinwag_host_process::inspect_process_birth(pid) {
        Ok(chinwag_host_process::ProcessBirthObservation::Alive(info)) => {
            Ok(info.start_time_unix_us == expected_birth_unix_us)
        }
        Ok(chinwag_host_process::ProcessBirthObservation::NotFoundOrZombie) => Ok(false),
        Err(err) => Err(format!(
            "indeterminate process birth inspection for pid={pid}: {err}"
        )),
    }
}

fn jj_binary() -> &'static str {
    if fs::metadata("/opt/homebrew/bin/jj")
        .is_ok_and(|meta| meta.is_file() && meta.mode() & 0o111 != 0)
    {
        "/opt/homebrew/bin/jj"
    } else {
        "jj"
    }
}

fn read_jj_path_file(path: &Path) -> InventoryResult<PathBuf> {
    let mut bytes = Vec::new();
    let mut file = File::from(
        openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|err| InventoryError::Io(err.to_string()))?,
    );
    if FileType::from_raw_mode(
        fstat(&file)
            .map_err(|err| InventoryError::Io(err.to_string()))?
            .st_mode,
    ) != FileType::RegularFile
    {
        return Err(InventoryError::SharedGitStoreMismatch(
            "JJ backing path must be a regular file".to_owned(),
        ));
    }
    (&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|err| InventoryError::Io(err.to_string()))?;
    if bytes.len() > 4096 {
        return Err(InventoryError::SharedGitStoreMismatch(
            "JJ backing path exceeds 4096 bytes".to_owned(),
        ));
    }
    let raw = std::str::from_utf8(&bytes)
        .map_err(|err| InventoryError::SharedGitStoreMismatch(err.to_string()))?
        .trim();
    if raw.is_empty() {
        return Err(InventoryError::SharedGitStoreMismatch(
            "empty JJ backing path".to_owned(),
        ));
    }
    let joined = path
        .parent()
        .ok_or_else(|| InventoryError::InvalidPath("JJ path has no parent".to_owned()))?
        .join(raw);
    let mut resolved = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                resolved.pop();
            }
            Component::CurDir => {}
            other => resolved.push(other.as_os_str()),
        }
    }
    Ok(resolved)
}

fn read_bounded_jj_pipe(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> InventoryResult<bool> {
    let mut buffer = [0u8; 4096];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if bytes.len() + count > 65_536 {
                    return Err(InventoryError::WorkspaceIdentityDrift(
                        "live JJ output exceeded 65536 bytes".to_owned(),
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(InventoryError::Io(err.to_string())),
        }
    }
}

fn live_jj_workspace_listing(workspace_path: &Path) -> InventoryResult<Vec<u8>> {
    let mut child = Command::new(jj_binary())
        .args(["--no-pager", "--ignore-working-copy", "--color=never", "-R"])
        .arg(workspace_path)
        .args(["workspace", "list", "-T", "name ++ \"\\t\" ++ target.current_working_copy() ++ \"\\t\" ++ target.change_id() ++ \"\\t\" ++ target.commit_id() ++ \"\\n\""])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .map_err(|err| InventoryError::Io(format!("live JJ spawn failed: {err}")))?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| InventoryError::Io("missing JJ stdout".to_owned()))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| InventoryError::Io("missing JJ stderr".to_owned()))?;
        for fd in [
            &stdout as &dyn std::os::fd::AsFd,
            &stderr as &dyn std::os::fd::AsFd,
        ] {
            let flags = fcntl_getfl(fd).map_err(|err| InventoryError::Io(err.to_string()))?;
            fcntl_setfl(fd, flags | OFlags::NONBLOCK)
                .map_err(|err| InventoryError::Io(err.to_string()))?;
        }
        let deadline = Instant::now() + Duration::from_millis(5_000);
        let mut out = Vec::new();
        let mut err_out = Vec::new();
        loop {
            let stdout_done = read_bounded_jj_pipe(&mut stdout, &mut out)?;
            let stderr_done = read_bounded_jj_pipe(&mut stderr, &mut err_out)?;
            if let Some(status) = child
                .try_wait()
                .map_err(|err| InventoryError::Io(err.to_string()))?
                && stdout_done
                && stderr_done
            {
                return if status.success() {
                    Ok(out)
                } else {
                    Err(InventoryError::WorkspaceIdentityDrift(format!(
                        "live JJ query failed: {}",
                        String::from_utf8_lossy(&err_out)
                    )))
                };
            }
            if Instant::now() >= deadline {
                return Err(InventoryError::WorkspaceIdentityDrift(
                    "live JJ query timed out".to_owned(),
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// Read pinned JJ workspace metadata without snapshotting source edits. Verify
/// physical identities on both sides of the bounded, read-only child query.
#[allow(clippy::too_many_arguments)]
pub fn observe_live_jj_workspace(
    workspace_path: &Path,
    expected_workspace_identity: FsEntryIdentityV1,
    expected_shared_git_store_identity: FsEntryIdentityV1,
    operational_checkout_identity: FsEntryIdentityV1,
    expected_workspace_name: &str,
    expected_jj_change_id: &str,
    expected_jj_commit_id: GitOid,
) -> InventoryResult<()> {
    let identity = verify_private_directory_identity(workspace_path, true)?;
    if identity != expected_workspace_identity
        || identity.same_inode(&operational_checkout_identity)
        || identity.same_inode(&expected_shared_git_store_identity)
    {
        return Err(InventoryError::WorkspaceIdentityDrift(
            "live workspace physical identity mismatch".to_owned(),
        ));
    }
    let jj_dir = workspace_path.join(".jj");
    let meta = fs::symlink_metadata(&jj_dir).map_err(|err| InventoryError::Io(err.to_string()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(InventoryError::SymlinkOrNonDirectory(
            "workspace .jj must be a direct real directory".to_owned(),
        ));
    }
    let repo_entry = jj_dir.join("repo");
    let meta =
        fs::symlink_metadata(&repo_entry).map_err(|err| InventoryError::Io(err.to_string()))?;
    let repo_dir = if meta.file_type().is_symlink() {
        return Err(InventoryError::SymlinkOrNonDirectory(
            "workspace .jj/repo is a symlink".to_owned(),
        ));
    } else if meta.is_file() {
        read_jj_path_file(&repo_entry)?
    } else if meta.is_dir() {
        repo_entry
    } else {
        return Err(InventoryError::SymlinkOrNonDirectory(
            "invalid .jj/repo entry".to_owned(),
        ));
    };
    verify_private_directory_identity(&repo_dir, false)?;
    verify_private_directory_identity(&repo_dir.join("store"), false)?;
    let store_root = repo_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| InventoryError::SharedGitStoreMismatch("JJ store has no root".to_owned()))?;
    let root_id = verify_private_directory_identity(store_root, false)?;
    if root_id.same_inode(&operational_checkout_identity) {
        return Err(InventoryError::WorkspaceIdentityDrift(
            "JJ store aliases operational checkout".to_owned(),
        ));
    }
    let mut store_matches = root_id.same_inode(&expected_shared_git_store_identity);
    let git_target = repo_dir.join("store/git_target");
    match fs::symlink_metadata(&git_target) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
            let target_id =
                verify_private_directory_identity(&read_jj_path_file(&git_target)?, false)?;
            if target_id.same_inode(&operational_checkout_identity) {
                return Err(InventoryError::WorkspaceIdentityDrift(
                    "JJ Git target aliases operational checkout".to_owned(),
                ));
            }
            store_matches |= target_id.same_inode(&expected_shared_git_store_identity);
        }
        Ok(_) => {
            return Err(InventoryError::SharedGitStoreMismatch(
                "JJ Git target must be a real path file".to_owned(),
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(InventoryError::Io(err.to_string())),
    }
    if !store_matches {
        return Err(InventoryError::SharedGitStoreMismatch(
            "JJ backing store identity mismatch".to_owned(),
        ));
    }
    let stdout = live_jj_workspace_listing(workspace_path)?;
    let stdout = std::str::from_utf8(&stdout)
        .map_err(|err| InventoryError::WorkspaceIdentityDrift(err.to_string()))?;
    let mut matches = stdout.lines().filter_map(|line| {
        let fields: Vec<_> = line.split('\t').collect();
        (fields.len() == 4 && fields[0] == expected_workspace_name).then_some(fields)
    });
    let valid = matches.next().is_some_and(|fields| {
        fields[1] == "true"
            && fields[2] == expected_jj_change_id
            && GitOid::from_hex(fields[3]) == Ok(expected_jj_commit_id)
    }) && matches.next().is_none();
    if !valid {
        return Err(InventoryError::WorkspaceIdentityDrift(
            "live JJ workspace name, current target, change_id or commit_id mismatch".to_owned(),
        ));
    }
    if verify_private_directory_identity(workspace_path, true)? != expected_workspace_identity {
        return Err(InventoryError::WorkspaceIdentityDrift(
            "workspace changed during live JJ query".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsEntryIdentityV1 {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl FsEntryIdentityV1 {
    pub fn same_inode(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }
}

/// Walk an absolute canonical path component-by-component with `OFlags::NOFOLLOW`
/// and return its physical `(dev, ino, uid, gid, mode)` identity. Rejects any
/// symlink segment, relative path, `.` or `..` component, or non-directory leaf.
pub fn verify_private_directory_identity(
    path: &Path,
    require_private_mode: bool,
) -> InventoryResult<FsEntryIdentityV1> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(InventoryError::InvalidPath(
            "path must be non-empty and absolute".to_owned(),
        ));
    }
    let mut current = File::open("/").map_err(|e| InventoryError::Io(e.to_string()))?;
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                saw_normal = true;
                let st = statat(&current, part, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| InventoryError::Io(format!("{path:?}: {e}")))?;
                if (st.st_mode as u32) & 0o170000 != 0o040000 {
                    return Err(InventoryError::SymlinkOrNonDirectory(format!(
                        "{path:?} component {part:?} is not a real directory"
                    )));
                }
                current = File::from(
                    openat(
                        &current,
                        part,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|e| InventoryError::Io(format!("{path:?}: {e}")))?,
                );
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(InventoryError::InvalidPath(format!(
                    "non-canonical path component in {path:?}"
                )));
            }
        }
    }
    if !saw_normal {
        return Err(InventoryError::InvalidPath(
            "root directory '/' cannot be a workspace or store root".to_owned(),
        ));
    }
    let meta = current
        .metadata()
        .map_err(|e| InventoryError::Io(e.to_string()))?;
    let euid = rustix::process::geteuid().as_raw();
    let mode = meta.mode() & 0o7777;
    if meta.uid() != euid {
        return Err(InventoryError::UnownedOrWritableDirectory(format!(
            "directory {path:?} uid {} != euid {euid}",
            meta.uid()
        )));
    }
    if require_private_mode && (mode & 0o077 != 0) {
        return Err(InventoryError::UnownedOrWritableDirectory(format!(
            "directory {path:?} mode {mode:#o} must not grant group/other access"
        )));
    }
    if !require_private_mode && (mode & 0o022 != 0) {
        return Err(InventoryError::UnownedOrWritableDirectory(format!(
            "directory {path:?} mode {mode:#o} is group/world writable"
        )));
    }
    Ok(FsEntryIdentityV1 {
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOwnershipStatusV1 {
    Active,
    HeldConflict,
    HeldStaleOrUnknown,
    Released,
    Retired,
    Abandoned,
}

impl WorkspaceOwnershipStatusV1 {
    pub fn blocks_exclusive_claim(self) -> bool {
        matches!(
            self,
            Self::Active | Self::HeldConflict | Self::HeldStaleOrUnknown
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceOwnershipRecordV1 {
    pub record_id: String,
    pub repo_id: String,
    pub operational_checkout_path: String,
    pub operational_checkout_identity: FsEntryIdentityV1,
    pub shared_git_store_path: String,
    pub shared_git_store_identity: FsEntryIdentityV1,
    pub workspace_name: String,
    pub workspace_path: String,
    pub workspace_identity: FsEntryIdentityV1,
    pub jj_working_copy_change_id: String,
    #[serde(with = "git_oid_serde")]
    pub jj_working_copy_commit_id: GitOid,
    #[serde(with = "git_oid_serde")]
    pub base_commit_id: GitOid,
    #[serde(with = "git_oid_serde")]
    pub base_tree_id: GitOid,
    pub owner_actor: String,
    #[serde(with = "task_ref_serde")]
    pub task_ref: TaskRefV1,
    #[serde(with = "sha256_serde")]
    pub admission_digest: Sha256Digest,
    pub scope_paths: Vec<String>,
    pub review_branch: String,
    pub issued_unix_ms: u64,
    pub lease_expires_unix_ms: u64,
    pub pid_birth_binding: Option<(u32, u64)>,
    pub status: WorkspaceOwnershipStatusV1,
    pub hold_reason: Option<String>,
}

impl WorkspaceOwnershipRecordV1 {
    fn same_ownership_incarnation(&self, other: &Self) -> bool {
        self.pid_birth_binding == other.pid_birth_binding && self.same_ownership_fields(other)
    }

    fn same_ownership_incarnation_ignoring_hold(&self, other: &Self) -> bool {
        (self.status != WorkspaceOwnershipStatusV1::Active
            || self.pid_birth_binding == other.pid_birth_binding)
            && self.same_ownership_fields(other)
    }

    fn same_ownership_fields(&self, other: &Self) -> bool {
        self.record_id == other.record_id
            && self.repo_id == other.repo_id
            && self.operational_checkout_path == other.operational_checkout_path
            && self.operational_checkout_identity == other.operational_checkout_identity
            && self.shared_git_store_path == other.shared_git_store_path
            && self.shared_git_store_identity == other.shared_git_store_identity
            && self.workspace_name == other.workspace_name
            && self.workspace_path == other.workspace_path
            && self.workspace_identity == other.workspace_identity
            && self.jj_working_copy_change_id == other.jj_working_copy_change_id
            && self.jj_working_copy_commit_id == other.jj_working_copy_commit_id
            && self.base_commit_id == other.base_commit_id
            && self.base_tree_id == other.base_tree_id
            && self.owner_actor == other.owner_actor
            && self.task_ref == other.task_ref
            && self.admission_digest == other.admission_digest
            && self.scope_paths == other.scope_paths
            && self.review_branch == other.review_branch
            && self.issued_unix_ms == other.issued_unix_ms
            && self.lease_expires_unix_ms == other.lease_expires_unix_ms
    }

    pub fn validate_structural(&self) -> InventoryResult<()> {
        validate_id(&self.record_id, "record_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.repo_id, "repo_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.workspace_name, "workspace_name")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.jj_working_copy_change_id, "jj_working_copy_change_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.review_branch, "review_branch")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        self.task_ref
            .validate()
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        if self.scope_paths.is_empty() || self.scope_paths.len() > MAX_SCOPE_PATHS {
            return Err(InventoryError::InvalidIdentifier(
                "scope_paths must contain 1..=64 relative paths".to_owned(),
            ));
        }
        for scope in &self.scope_paths {
            if scope.is_empty()
                || scope.starts_with('/')
                || scope.contains("..")
                || scope.contains('\0')
            {
                return Err(InventoryError::InvalidPath(format!(
                    "invalid relative scope path: {scope:?}"
                )));
            }
        }
        let parsed_actor = ActorAddress::parse(&self.owner_actor).map_err(|e| {
            InventoryError::UnresolvedOrMismatchedOwner(format!(
                "owner_actor {:?} failed ActorAddress validation: {e}",
                self.owner_actor
            ))
        })?;
        if parsed_actor.instance().is_none() {
            return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                "owner_actor {:?} must carry a complete conversation/worker instance ID",
                self.owner_actor
            )));
        }
        if self.lease_expires_unix_ms <= self.issued_unix_ms {
            return Err(InventoryError::InvalidIdentifier(
                "lease_expires_unix_ms must be strictly greater than issued_unix_ms".to_owned(),
            ));
        }
        if self.workspace_path == self.operational_checkout_path
            || self
                .workspace_identity
                .same_inode(&self.operational_checkout_identity)
        {
            return Err(InventoryError::OperationalCheckoutForbidden(format!(
                "workspace {:?} aliases operational checkout {:?}",
                self.workspace_path, self.operational_checkout_path
            )));
        }
        if self
            .workspace_identity
            .same_inode(&self.shared_git_store_identity)
        {
            return Err(InventoryError::InvalidPath(
                "workspace directory cannot be identical to the shared Git object store".to_owned(),
            ));
        }
        if self.jj_working_copy_commit_id == self.base_commit_id {
            return Err(InventoryError::SharedMutableJjChange(
                "working-copy commit ID must be a dedicated child commit, not the immutable base commit".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClassificationV1 {
    Implemented,
    Tested,
    AcceptedSource,
    Installed,
    Operational,
    Authorized,
    Unknown,
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProvenanceRecordV1 {
    pub capability_id: String,
    pub handler_symbol: String,
    pub source_module_path: String,
    pub claimed_classification: CapabilityClassificationV1,
    pub handler_wired: bool,
    pub unit_tests_passed: bool,
    #[serde(with = "git_oid_serde")]
    pub source_commit: GitOid,
    #[serde(with = "git_oid_serde")]
    pub source_tree: GitOid,
    pub source_tree_clean: bool,
    #[serde(with = "opt_git_oid_serde")]
    pub accepted_source_commit: Option<GitOid>,
    #[serde(with = "opt_sha256_serde")]
    pub compiled_artifact_sha256: Option<Sha256Digest>,
    pub installed_binary_path: Option<String>,
    #[serde(with = "opt_sha256_serde")]
    pub installed_binary_sha256: Option<Sha256Digest>,
    pub runtime_health_verified: bool,
    #[serde(with = "opt_sha256_serde")]
    pub admission_authority_digest: Option<Sha256Digest>,
    #[serde(with = "opt_task_ref_serde")]
    pub task_ref: Option<TaskRefV1>,
    pub observed_unix_ms: u64,
    pub effective_classification: CapabilityClassificationV1,
    pub hold_or_downgrade_reason: Option<String>,
}

impl CapabilityProvenanceRecordV1 {
    fn same_capability_incarnation(&self, other: &Self) -> bool {
        self.capability_id == other.capability_id
            && self.handler_symbol == other.handler_symbol
            && self.source_module_path == other.source_module_path
            && self.claimed_classification == other.claimed_classification
            && self.handler_wired == other.handler_wired
            && self.unit_tests_passed == other.unit_tests_passed
            && self.source_commit == other.source_commit
            && self.source_tree == other.source_tree
            && self.source_tree_clean == other.source_tree_clean
            && self.accepted_source_commit == other.accepted_source_commit
            && self.compiled_artifact_sha256 == other.compiled_artifact_sha256
            && self.installed_binary_path == other.installed_binary_path
            && self.installed_binary_sha256 == other.installed_binary_sha256
            && self.runtime_health_verified == other.runtime_health_verified
            && self.admission_authority_digest == other.admission_authority_digest
            && self.task_ref == other.task_ref
            && self.observed_unix_ms == other.observed_unix_ms
    }

    /// Evaluate and verify provenance so that `Implemented`, `Tested`,
    /// `AcceptedSource`, `Installed`, `Operational`, and `Authorized` are never
    /// conflated, and dirty/uncommitted builds or mismatched binaries fail
    /// closed.
    pub fn verify_and_classify(&mut self) -> InventoryResult<CapabilityClassificationV1> {
        validate_id(&self.capability_id, "capability_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        validate_id(&self.handler_symbol, "handler_symbol")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        if self.source_module_path.is_empty()
            || self.source_module_path.starts_with('/')
            || self.source_module_path.contains("..")
        {
            return Err(InventoryError::InvalidPath(format!(
                "invalid source_module_path {:?}",
                self.source_module_path
            )));
        }

        // Dirty source tree invalidates any claim above Tested.
        if !self.source_tree_clean
            && matches!(
                self.claimed_classification,
                CapabilityClassificationV1::AcceptedSource
                    | CapabilityClassificationV1::Installed
                    | CapabilityClassificationV1::Operational
                    | CapabilityClassificationV1::Authorized
            )
        {
            self.effective_classification = CapabilityClassificationV1::Held;
            self.installed_binary_sha256 = None;
            let reason = format!(
                "capability {:?} claims {:?} on dirty/uncommitted source tree",
                self.capability_id, self.claimed_classification
            );
            self.hold_or_downgrade_reason = Some(reason.clone());
            return Err(InventoryError::DirtyOrMismatchedBuildProvenance(reason));
        }

        match self.claimed_classification {
            CapabilityClassificationV1::Unknown => {
                self.effective_classification = CapabilityClassificationV1::Unknown;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Held => {
                self.effective_classification = CapabilityClassificationV1::Held;
                self.installed_binary_sha256 = None;
                if self
                    .hold_or_downgrade_reason
                    .as_ref()
                    .is_none_or(|reason| reason.trim().is_empty())
                {
                    self.hold_or_downgrade_reason =
                        Some("explicit Held capability observation".to_owned());
                }
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Implemented => {
                if !self.handler_wired {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    self.installed_binary_sha256 = None;
                    let reason = format!(
                        "capability {:?} claims Implemented without wired handler",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Implemented;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Tested => {
                if !self.handler_wired || !self.unit_tests_passed {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    self.installed_binary_sha256 = None;
                    let reason = format!(
                        "capability {:?} claims Tested without handler_wired && unit_tests_passed",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Tested;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::AcceptedSource => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    self.installed_binary_sha256 = None;
                    let reason = format!(
                        "capability {:?} claims AcceptedSource without matching accepted_source_commit",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::AcceptedSource;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Installed => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    self.installed_binary_sha256 = None;
                    let reason = format!(
                        "capability {:?} claims Installed without AcceptedSource provenance",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                match (
                    &self.compiled_artifact_sha256,
                    &self.installed_binary_sha256,
                    &self.installed_binary_path,
                ) {
                    (Some(compiled), Some(installed), Some(path))
                        if compiled == installed && path.starts_with('/') =>
                    {
                        self.effective_classification = CapabilityClassificationV1::Installed;
                        self.hold_or_downgrade_reason = None;
                        Ok(self.effective_classification)
                    }
                    _ => {
                        self.effective_classification = CapabilityClassificationV1::Held;
                        self.installed_binary_sha256 = None;
                        let reason = format!(
                            "capability {:?} claims Installed with missing or mismatched binary digest",
                            self.capability_id
                        );
                        self.hold_or_downgrade_reason = Some(reason.clone());
                        Err(InventoryError::DirtyOrMismatchedBuildProvenance(reason))
                    }
                }
            }
            CapabilityClassificationV1::Operational => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                    || !self.runtime_health_verified
                    || self.compiled_artifact_sha256.is_none()
                    || self.compiled_artifact_sha256 != self.installed_binary_sha256
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    self.installed_binary_sha256 = None;
                    let reason = format!(
                        "capability {:?} claims Operational without verified installed binary and runtime health",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Operational;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
            CapabilityClassificationV1::Authorized => {
                if !self.handler_wired
                    || !self.unit_tests_passed
                    || self.accepted_source_commit != Some(self.source_commit)
                    || !self.runtime_health_verified
                    || self.compiled_artifact_sha256.is_none()
                    || self.compiled_artifact_sha256 != self.installed_binary_sha256
                    || self.admission_authority_digest.is_none()
                    || self.task_ref.is_none()
                {
                    self.effective_classification = CapabilityClassificationV1::Held;
                    self.installed_binary_sha256 = None;
                    let reason = format!(
                        "capability {:?} claims Authorized without full operational + admission + TaskRef provenance",
                        self.capability_id
                    );
                    self.hold_or_downgrade_reason = Some(reason.clone());
                    return Err(InventoryError::UnprovenCapabilityClaim(reason));
                }
                self.effective_classification = CapabilityClassificationV1::Authorized;
                self.hold_or_downgrade_reason = None;
                Ok(self.effective_classification)
            }
        }
    }

    /// Inventory records are descriptive/supervisory and never grant production
    /// execution authority on their own.
    pub fn require_execution_authority(&self) -> InventoryResult<()> {
        Err(InventoryError::InventoryNotExecutionAuthority)
    }
}

/// Verify that a `StoredObservation` from `task_store` also refuses production
/// authority promotion through the inventory layer.
pub fn require_stored_observation_not_authority(
    observation: &StoredObservation,
) -> InventoryResult<()> {
    let _ = observation.require_production_authority();
    Err(InventoryError::InventoryNotExecutionAuthority)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    reason = "The admitted checkpoint event carries TaskRefV1 inline; journal records have a strict byte ceiling"
)]
pub enum InventoryPayloadV1 {
    RegisterWorkspace {
        record: Box<WorkspaceOwnershipRecordV1>,
    },
    ReleaseWorkspace {
        record_id: String,
        actor: String,
        released_unix_ms: u64,
    },
    AdvanceWorkspaceCheckpoint {
        record_id: String,
        actor: String,
        #[serde(with = "task_ref_serde")]
        task_ref: TaskRefV1,
        expected_jj_working_copy_change_id: String,
        #[serde(with = "git_oid_serde")]
        expected_old_jj_working_copy_commit_id: GitOid,
        #[serde(with = "git_oid_serde")]
        new_jj_working_copy_commit_id: GitOid,
        updated_unix_ms: u64,
    },
    UpsertCapability {
        record: Box<CapabilityProvenanceRecordV1>,
    },
    HoldWorkspace {
        record_id: String,
        hold_reason: String,
        updated_unix_ms: u64,
    },
    HoldCapability {
        capability_id: String,
        hold_reason: String,
        updated_unix_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_kind", rename_all = "snake_case", deny_unknown_fields)]
#[expect(
    clippy::large_enum_variant,
    reason = "Intent carries the admitted inline checkpoint payload; all journal records are bounded before append"
)]
enum JournalEntryV1 {
    Intent {
        operation_id: String,
        intent_digest: String,
        recorded_unix_ms: u64,
        payload: InventoryPayloadV1,
    },
    Result {
        operation_id: String,
        intent_digest: String,
        completed_unix_ms: u64,
        committed: bool,
        hold_reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySubmissionOutcomeV1 {
    Applied,
    IdempotentReplay,
    ConflictingReplayHeld,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySnapshotV1 {
    pub shared_git_store_identity: FsEntryIdentityV1,
    pub operational_checkout_identity: FsEntryIdentityV1,
    pub workspaces: Vec<WorkspaceOwnershipRecordV1>,
    pub capabilities: Vec<CapabilityProvenanceRecordV1>,
    pub incomplete_operations_held: Vec<String>,
    pub corrupt_or_ambiguous_tail_reason: Option<String>,
}

/// Independently opened descriptors retain both locks for the whole transaction.
struct LockedInventoryJournal {
    dir_fd: File,
    file_fd: File,
    file_name: std::ffi::OsString,
    parent_identity: FsEntryIdentityV1,
    file_identity: (u64, u64),
    file_bytes: u64,
}

impl LockedInventoryJournal {
    fn open(journal_path: &Path, create: bool) -> InventoryResult<Option<Self>> {
        let parent = journal_path.parent().ok_or_else(|| {
            InventoryError::InvalidPath("journal_path must have a parent directory".to_owned())
        })?;
        let parent_identity = verify_private_directory_identity(parent, true)?;
        let file_name = journal_path.file_name().ok_or_else(|| {
            InventoryError::InvalidPath("journal_path must name a file".to_owned())
        })?;
        let dir_fd = File::from(
            openat(
                CWD,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| InventoryError::Io(e.to_string()))?,
        );
        Self::verify_directory(&dir_fd, parent_identity)?;
        flock(&dir_fd, FlockOperation::LockExclusive)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        Self::verify_directory(&dir_fd, parent_identity)?;
        match statat(&dir_fd, file_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                Self::file_snapshot(&stat)?;
            }
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(rustix::io::Errno::NOENT) => {}
            Err(err) => return Err(InventoryError::Io(err.to_string())),
        }
        let flags = if create {
            OFlags::RDWR | OFlags::CREATE | OFlags::APPEND
        } else {
            OFlags::RDONLY
        };
        let file_fd = File::from(
            openat(
                &dir_fd,
                file_name,
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|e| InventoryError::Io(e.to_string()))?,
        );
        flock(&file_fd, FlockOperation::LockExclusive)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        let (dev, ino, file_bytes) =
            Self::file_snapshot(&fstat(&file_fd).map_err(|e| InventoryError::Io(e.to_string()))?)?;
        let journal = Self {
            dir_fd,
            file_fd,
            file_name: file_name.to_owned(),
            parent_identity,
            file_identity: (dev, ino),
            file_bytes,
        };
        journal.verify_binding(file_bytes)?;
        Ok(Some(journal))
    }

    fn verify_directory(file: &File, identity: FsEntryIdentityV1) -> InventoryResult<()> {
        let stat = fstat(file).map_err(|e| InventoryError::Io(e.to_string()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || (stat.st_dev as u64, stat.st_ino as u64) != (identity.dev, identity.ino)
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o700
            || stat.st_nlink == 0
        {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal directory identity or private metadata changed".to_owned(),
            ));
        }
        Ok(())
    }

    fn file_snapshot(stat: &Stat) -> InventoryResult<(u64, u64, u64)> {
        let size = u64::try_from(stat.st_size).map_err(|_| {
            InventoryError::JournalCorruptOrBounded("negative journal size".to_owned())
        })?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || size > MAX_INVENTORY_JOURNAL_BYTES
        {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal must be a private, singly linked, bounded regular file".to_owned(),
            ));
        }
        Ok((stat.st_dev as u64, stat.st_ino, size))
    }

    fn verify_binding(&self, expected_size: u64) -> InventoryResult<()> {
        Self::verify_directory(&self.dir_fd, self.parent_identity)?;
        let opened = Self::file_snapshot(
            &fstat(&self.file_fd).map_err(|e| InventoryError::Io(e.to_string()))?,
        )?;
        let named = Self::file_snapshot(
            &statat(&self.dir_fd, &self.file_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| InventoryError::Io(e.to_string()))?,
        )?;
        if opened != named || opened != (self.file_identity.0, self.file_identity.1, expected_size)
        {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal inode binding or size changed".to_owned(),
            ));
        }
        Ok(())
    }

    fn read_from_start(&mut self) -> InventoryResult<Vec<u8>> {
        self.file_fd
            .rewind()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        let mut bytes = Vec::new();
        (&mut self.file_fd)
            .take(MAX_INVENTORY_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        if bytes.len() as u64 != self.file_bytes {
            return Err(InventoryError::JournalCorruptOrBounded(
                "journal size changed during replay".to_owned(),
            ));
        }
        self.verify_binding(self.file_bytes)?;
        Ok(bytes)
    }

    fn append_line(&mut self, line: &[u8]) -> InventoryResult<()> {
        let expected_size = self
            .file_bytes
            .checked_add(line.len() as u64)
            .filter(|size| *size <= MAX_INVENTORY_JOURNAL_BYTES)
            .ok_or_else(|| {
                InventoryError::JournalCorruptOrBounded(
                    "inventory journal byte ceiling exceeded".to_owned(),
                )
            })?;
        self.verify_binding(self.file_bytes)?;
        self.file_fd
            .write_all(line)
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        self.file_fd
            .sync_all()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        self.dir_fd
            .sync_all()
            .map_err(|e| InventoryError::Io(e.to_string()))?;
        self.verify_binding(expected_size)?;
        self.file_bytes = expected_size;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ContinuousInventoryRegistryV1 {
    shared_git_store_identity: FsEntryIdentityV1,
    operational_checkout_identity: FsEntryIdentityV1,
    workspaces: BTreeMap<String, WorkspaceOwnershipRecordV1>,
    next_workspace_registration_seq: u64,
    workspace_registration_seq: BTreeMap<String, u64>,
    local_workspace_holds:
        BTreeMap<String, (WorkspaceOwnershipRecordV1, u64, WorkspaceOwnershipRecordV1)>,
    capabilities: BTreeMap<String, CapabilityProvenanceRecordV1>,
    local_capability_holds:
        BTreeMap<String, (CapabilityProvenanceRecordV1, CapabilityProvenanceRecordV1)>,
    committed_ops: BTreeMap<String, String>,
    rejected_ops: BTreeMap<String, (String, Option<String>)>,
    incomplete_ops_held: BTreeMap<String, String>,
    journal_path: Option<PathBuf>,
    bound_journal_identity: Option<(FsEntryIdentityV1, std::ffi::OsString, (u64, u64))>,
    corrupt_or_ambiguous_tail_reason: Option<String>,
    #[cfg(test)]
    fail_next_result_append: bool,
}

impl ContinuousInventoryRegistryV1 {
    pub fn new(
        shared_git_store_identity: FsEntryIdentityV1,
        operational_checkout_identity: FsEntryIdentityV1,
    ) -> InventoryResult<Self> {
        if shared_git_store_identity.same_inode(&operational_checkout_identity) {
            return Err(InventoryError::InvalidPath(
                "shared_git_store_identity and operational_checkout_identity must be distinct"
                    .to_owned(),
            ));
        }
        Ok(Self {
            shared_git_store_identity,
            operational_checkout_identity,
            workspaces: BTreeMap::new(),
            next_workspace_registration_seq: 0,
            workspace_registration_seq: BTreeMap::new(),
            local_workspace_holds: BTreeMap::new(),
            capabilities: BTreeMap::new(),
            local_capability_holds: BTreeMap::new(),
            committed_ops: BTreeMap::new(),
            rejected_ops: BTreeMap::new(),
            incomplete_ops_held: BTreeMap::new(),
            journal_path: None,
            bound_journal_identity: None,
            corrupt_or_ambiguous_tail_reason: None,
            #[cfg(test)]
            fail_next_result_append: false,
        })
    }

    fn verify_or_bind_journal_identity(
        &mut self,
        journal: &LockedInventoryJournal,
    ) -> InventoryResult<()> {
        if let Some((expected_parent, expected_name, expected_file_id)) =
            &self.bound_journal_identity
        {
            if expected_parent.dev != journal.parent_identity.dev
                || expected_parent.ino != journal.parent_identity.ino
                || expected_name != &journal.file_name
                || *expected_file_id != journal.file_identity
            {
                return Err(InventoryError::InvalidPath(
                    "registry instance is already bound to a different authoritative journal identity"
                        .to_owned(),
                ));
            }
        } else {
            self.bound_journal_identity = Some((
                journal.parent_identity,
                journal.file_name.clone(),
                journal.file_identity,
            ));
        }
        Ok(())
    }

    pub fn corrupt_or_ambiguous_tail_reason(&self) -> Option<&str> {
        self.corrupt_or_ambiguous_tail_reason.as_deref()
    }

    fn payload_digest(payload: &InventoryPayloadV1) -> InventoryResult<String> {
        let bytes = serde_json::to_vec(payload).map_err(|e| InventoryError::Io(e.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(&bytes)))
    }

    fn journal_line(entry: &JournalEntryV1) -> InventoryResult<Vec<u8>> {
        let mut line = serde_json::to_vec(entry).map_err(|e| InventoryError::Io(e.to_string()))?;
        strict_json_object(&line, MAX_INVENTORY_JOURNAL_BYTES as usize)
            .map_err(|e| InventoryError::JournalCorruptOrBounded(e.to_string()))?;
        line.push(b'\n');
        Ok(line)
    }

    #[cfg(test)]
    fn append_journal_entry(journal_path: &Path, entry: &JournalEntryV1) -> InventoryResult<()> {
        let mut journal = LockedInventoryJournal::open(journal_path, true)?
            .ok_or_else(|| InventoryError::Io("created journal is missing".to_owned()))?;
        journal.append_line(&Self::journal_line(entry)?)
    }

    /// Submit an intent/result pair under shared-journal exclusion, installing
    /// the candidate registry only after both records are durable.
    /// Idempotent replay of the exact `(operation_id, intent_digest)` returns
    /// `IdempotentReplay` without duplicate side effects; conflicting reuse of
    /// `operation_id` with a different payload fails closed.
    pub fn submit_durable(
        &mut self,
        journal_path: &Path,
        operation_id: &str,
        now_unix_ms: u64,
        payload: InventoryPayloadV1,
    ) -> InventoryResult<InventorySubmissionOutcomeV1> {
        validate_id(operation_id, "operation_id")
            .map_err(|e| InventoryError::InvalidIdentifier(e.to_string()))?;
        let digest = match Self::payload_digest(&payload) {
            Ok(digest) => digest,
            Err(err) => {
                let mut candidate = self.clone();
                let _ = candidate.apply_payload(payload.clone(), false);
                self.install_local_negative_capability_overlay(
                    &candidate,
                    &payload,
                    "non-tail persistence refusal: payload serialization failed",
                );
                return Err(err);
            }
        };
        let mut journal = LockedInventoryJournal::open(journal_path, true)?
            .ok_or_else(|| InventoryError::Io("created journal is missing".to_owned()))?;
        self.verify_or_bind_journal_identity(&journal)?;
        let existing_record_count = self.refresh_from_journal_locked(journal_path, &mut journal)?;
        if let Some(reason) = &self.corrupt_or_ambiguous_tail_reason {
            return Err(InventoryError::JournalCorruptOrBounded(reason.clone()));
        }
        if let Some(existing_digest) = self.committed_ops.get(operation_id) {
            if existing_digest == &digest {
                return Ok(InventorySubmissionOutcomeV1::IdempotentReplay);
            }
            return Err(InventoryError::ConflictingReplay(format!(
                "operation_id {operation_id:?} replayed with different payload digest"
            )));
        }
        if let Some((existing_digest, hold_reason)) = self.rejected_ops.get(operation_id) {
            return Err(InventoryError::ConflictingReplay(format!(
                "operation_id {operation_id} was already durably rejected/held (digest_match={}): {}",
                existing_digest == &digest,
                hold_reason.as_deref().unwrap_or("rejected")
            )));
        }
        if self.incomplete_ops_held.contains_key(operation_id) {
            return Err(InventoryError::IncompleteIntentHeld(
                operation_id.to_owned(),
            ));
        }

        // A rejected new capability has no journal effect. An existing capability
        // must retain a durable negative observation before reporting the error.
        if let InventoryPayloadV1::UpsertCapability { record } = &payload {
            let mut observation = record.clone();
            if let Err(err) = observation.verify_and_classify() {
                if self.capabilities.contains_key(&record.capability_id)
                    && matches!(
                        err,
                        InventoryError::UnprovenCapabilityClaim(_)
                            | InventoryError::DirtyOrMismatchedBuildProvenance(_)
                    )
                {
                    return self.commit_payload(
                        &mut journal,
                        existing_record_count,
                        operation_id,
                        now_unix_ms,
                        payload,
                    );
                }
                return Err(err);
            }
        }
        self.commit_payload(
            &mut journal,
            existing_record_count,
            operation_id,
            now_unix_ms,
            payload,
        )
    }

    /// Refresh discovery state from the bound authoritative journal without
    /// appending records. An ambiguous append remains held on this handle.
    pub fn refresh_from_journal(&mut self, journal_path: &Path) -> InventoryResult<()> {
        let mut journal = LockedInventoryJournal::open(journal_path, false)?
            .ok_or_else(|| InventoryError::Io("authoritative journal is missing".to_owned()))?;
        self.refresh_from_journal_locked(journal_path, &mut journal)?;
        Ok(())
    }

    fn refresh_from_journal_locked(
        &mut self,
        journal_path: &Path,
        journal: &mut LockedInventoryJournal,
    ) -> InventoryResult<usize> {
        self.verify_or_bind_journal_identity(journal)?;
        let (mut staging, existing_record_count) = Self::replay_journal(
            self.shared_git_store_identity,
            self.operational_checkout_identity,
            journal,
        )?;
        // A local negative observation belongs to the inspected registration,
        // including its journal generation. Release and ABA replacement win.
        for (id, (inspected, seq, held)) in &self.local_workspace_holds {
            if let Some(replayed) = staging.workspaces.get_mut(id)
                && replayed.status.blocks_exclusive_claim()
                && replayed.same_ownership_incarnation_ignoring_hold(inspected)
                && staging.workspace_registration_seq.get(id).copied() == Some(*seq)
            {
                replayed.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                replayed.hold_reason.clone_from(&held.hold_reason);
                replayed.pid_birth_binding = None;
                staging
                    .local_workspace_holds
                    .insert(id.clone(), (inspected.clone(), *seq, replayed.clone()));
            }
        }
        for (id, record) in &self.workspaces {
            if (id.contains("#incomplete:")
                || record
                    .hold_reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("incomplete_journal_intent:")))
                && !staging.workspaces.contains_key(id)
            {
                staging.workspaces.insert(id.clone(), record.clone());
            }
        }
        staging
            .incomplete_ops_held
            .extend(self.incomplete_ops_held.clone());
        staging.rejected_ops.extend(self.rejected_ops.clone());
        for (cap_id, (inspected_incarnation, held_overlay)) in &self.local_capability_holds {
            if staging
                .capabilities
                .get(cap_id)
                .is_some_and(|replayed| replayed.same_capability_incarnation(inspected_incarnation))
                || (!staging.capabilities.contains_key(cap_id)
                    && (cap_id.contains("#incomplete:")
                        || held_overlay
                            .hold_or_downgrade_reason
                            .as_deref()
                            .is_some_and(|reason| {
                                reason.starts_with("incomplete_journal_intent:")
                            })))
            {
                staging
                    .capabilities
                    .insert(cap_id.clone(), held_overlay.clone());
                staging.local_capability_holds.insert(
                    cap_id.clone(),
                    (inspected_incarnation.clone(), held_overlay.clone()),
                );
            }
        }
        if self.corrupt_or_ambiguous_tail_reason.is_some()
            && staging.corrupt_or_ambiguous_tail_reason.is_none()
        {
            staging.corrupt_or_ambiguous_tail_reason =
                self.corrupt_or_ambiguous_tail_reason.clone();
        }
        staging.bound_journal_identity = self.bound_journal_identity.clone();
        staging.journal_path = Some(journal_path.to_owned());
        #[cfg(test)]
        {
            staging.fail_next_result_append = self.fail_next_result_append;
        }
        *self = staging;
        Ok(existing_record_count)
    }

    fn commit_payload(
        &mut self,
        journal: &mut LockedInventoryJournal,
        existing_record_count: usize,
        operation_id: &str,
        now_unix_ms: u64,
        payload: InventoryPayloadV1,
    ) -> InventoryResult<InventorySubmissionOutcomeV1> {
        let mut candidate = self.clone();
        let apply_outcome = candidate.apply_payload(payload.clone(), false);
        let hold_reason = apply_outcome.as_ref().err().map(ToString::to_string);
        let serialized = (|| {
            let digest = Self::payload_digest(&payload)?;
            let intent_line = Self::journal_line(&JournalEntryV1::Intent {
                operation_id: operation_id.to_owned(),
                intent_digest: digest.clone(),
                recorded_unix_ms: now_unix_ms,
                payload: payload.clone(),
            })?;
            let result_line = Self::journal_line(&JournalEntryV1::Result {
                operation_id: operation_id.to_owned(),
                intent_digest: digest.clone(),
                completed_unix_ms: now_unix_ms,
                committed: apply_outcome.is_ok(),
                hold_reason: hold_reason.clone(),
            })?;
            Ok((digest, intent_line, result_line))
        })();
        let (digest, intent_line, result_line) = match serialized {
            Ok(lines) => lines,
            Err(err) => {
                self.install_local_negative_capability_overlay(
                    &candidate,
                    &payload,
                    "non-tail persistence refusal: journal serialization failed",
                );
                return Err(err);
            }
        };
        if existing_record_count
            .checked_add(2)
            .is_none_or(|count| count > MAX_INVENTORY_RECORDS)
            || journal
                .file_bytes
                .checked_add((intent_line.len() + result_line.len()) as u64)
                .is_none_or(|size| size > MAX_INVENTORY_JOURNAL_BYTES)
        {
            self.install_local_negative_capability_overlay(&candidate, &payload, "non-tail persistence refusal: inventory journal cannot reserve both Intent and Result");
            return Err(InventoryError::JournalCorruptOrBounded(
                "inventory journal cannot reserve both Intent and Result".to_owned(),
            ));
        }
        if let Err(err) = journal.append_line(&intent_line) {
            self.hold_incomplete(operation_id.to_owned(), digest, payload);
            self.corrupt_or_ambiguous_tail_reason =
                Some(format!("ambiguous_intent_append:{operation_id}:{err}"));
            return Err(err);
        }
        #[cfg(test)]
        let result_persistence = if std::mem::take(&mut self.fail_next_result_append) {
            Err(InventoryError::Io(
                "injected failure before durable Result".to_owned(),
            ))
        } else {
            journal.append_line(&result_line)
        };
        #[cfg(not(test))]
        let result_persistence = journal.append_line(&result_line);
        if let Err(err) = result_persistence {
            self.hold_incomplete(operation_id.to_owned(), digest, payload);
            self.corrupt_or_ambiguous_tail_reason =
                Some(format!("ambiguous_result_append:{operation_id}:{err}"));
            return Err(err);
        }
        match &payload {
            InventoryPayloadV1::UpsertCapability { record } => {
                candidate
                    .local_capability_holds
                    .remove(&record.capability_id);
            }
            InventoryPayloadV1::HoldCapability { capability_id, .. } => {
                candidate.local_capability_holds.remove(capability_id);
            }
            InventoryPayloadV1::HoldWorkspace { record_id, .. } => {
                candidate.local_workspace_holds.remove(record_id);
            }
            _ => {}
        }
        match apply_outcome {
            Ok(()) => {
                candidate
                    .committed_ops
                    .insert(operation_id.to_owned(), digest);
                *self = candidate;
                Ok(InventorySubmissionOutcomeV1::Applied)
            }
            Err(err) => {
                candidate
                    .rejected_ops
                    .insert(operation_id.to_owned(), (digest, hold_reason));
                *self = candidate;
                Err(err)
            }
        }
    }

    fn install_local_negative_capability_overlay(
        &mut self,
        candidate: &Self,
        payload: &InventoryPayloadV1,
        reason_suffix: &str,
    ) {
        let cap_id = match payload {
            InventoryPayloadV1::UpsertCapability { record } => &record.capability_id,
            InventoryPayloadV1::HoldCapability { capability_id, .. } => capability_id,
            _ => return,
        };
        if let (Some(inspected), Some(mut held)) = (
            self.capabilities.get(cap_id).cloned(),
            candidate.capabilities.get(cap_id).cloned(),
        ) && held.effective_classification == CapabilityClassificationV1::Held
        {
            let inspected = self
                .local_capability_holds
                .get(cap_id)
                .map_or(inspected, |(incarnation, _)| incarnation.clone());
            held.installed_binary_sha256 = None;
            held.hold_or_downgrade_reason = Some(format!(
                "{}; {reason_suffix}",
                held.hold_or_downgrade_reason
                    .as_deref()
                    .unwrap_or("capability held")
            ));
            self.capabilities.insert(cap_id.clone(), held.clone());
            self.local_capability_holds
                .insert(cap_id.clone(), (inspected, held));
        }
    }

    fn commit_automatic_hold(
        &mut self,
        journal: &mut LockedInventoryJournal,
        record_count: usize,
        now_unix_ms: u64,
        payload: InventoryPayloadV1,
    ) -> InventoryResult<()> {
        let mut sequence = record_count;
        let operation_id = loop {
            let id = format!("auto-hold-seq-{sequence}");
            if !self.committed_ops.contains_key(&id)
                && !self.rejected_ops.contains_key(&id)
                && !self.incomplete_ops_held.contains_key(&id)
            {
                break id;
            }
            sequence += 1;
        };
        if let Err(err) = self.commit_payload(
            journal,
            record_count,
            &operation_id,
            now_unix_ms,
            payload.clone(),
        ) {
            // A persistence failure must never leave a known-bad observation ready.
            let inspected_capability = match &payload {
                InventoryPayloadV1::HoldCapability { capability_id, .. }
                    if !self.local_capability_holds.contains_key(capability_id) =>
                {
                    self.capabilities.get(capability_id).cloned()
                }
                _ => None,
            };
            self.apply_payload(payload.clone(), false)?;
            if let Some(inspected) = inspected_capability
                && let InventoryPayloadV1::HoldCapability { capability_id, .. } = &payload
                && let Some(held) = self.capabilities.get(capability_id).cloned()
            {
                self.local_capability_holds
                    .insert(capability_id.clone(), (inspected, held));
            }
            return Err(err);
        }
        Ok(())
    }

    fn matches_active_workspace_incarnation(
        &self,
        record_id: &str,
        inspected_record: &WorkspaceOwnershipRecordV1,
        inspected_seq: Option<u64>,
    ) -> bool {
        self.workspaces.get(record_id).is_some_and(|current| {
            current.status == WorkspaceOwnershipStatusV1::Active
                && current.same_ownership_incarnation(inspected_record)
                && inspected_seq.is_none_or(|seq| {
                    self.workspace_registration_seq.get(record_id).copied() == Some(seq)
                })
        })
    }

    fn apply_local_workspace_hold(
        &mut self,
        inspected: &WorkspaceOwnershipRecordV1,
        inspected_seq: Option<u64>,
        payload: InventoryPayloadV1,
    ) -> InventoryResult<bool> {
        if !self.matches_active_workspace_incarnation(
            &inspected.record_id,
            inspected,
            inspected_seq,
        ) {
            return Ok(false);
        }
        self.apply_payload(payload, false)?;
        if let Some(seq) = inspected_seq {
            self.local_workspace_holds.insert(
                inspected.record_id.clone(),
                (
                    inspected.clone(),
                    seq,
                    self.workspaces[&inspected.record_id].clone(),
                ),
            );
        }
        Ok(true)
    }

    fn hold_workspace(
        &mut self,
        inspected_record: &WorkspaceOwnershipRecordV1,
        inspected_seq: Option<u64>,
        reason: String,
        now_unix_ms: u64,
    ) -> InventoryResult<bool> {
        let payload = InventoryPayloadV1::HoldWorkspace {
            record_id: inspected_record.record_id.clone(),
            hold_reason: reason,
            updated_unix_ms: now_unix_ms,
        };
        let Some(path) = self.journal_path.clone() else {
            return self.apply_local_workspace_hold(inspected_record, inspected_seq, payload);
        };
        let opened = LockedInventoryJournal::open(&path, true).and_then(|journal| {
            journal.ok_or_else(|| InventoryError::Io("created journal is missing".to_owned()))
        });
        let mut journal = match opened {
            Ok(journal) => journal,
            Err(err) => {
                self.apply_local_workspace_hold(inspected_record, inspected_seq, payload)?;
                return Err(err);
            }
        };
        // A foreign journal cannot alter the read model belonging to this handle.
        self.verify_or_bind_journal_identity(&journal)?;
        let count = match self.refresh_from_journal_locked(&path, &mut journal) {
            Ok(count) => count,
            Err(err) => {
                self.apply_local_workspace_hold(inspected_record, inspected_seq, payload)?;
                return Err(err);
            }
        };
        if let Some(reason) = self.corrupt_or_ambiguous_tail_reason.clone() {
            return Err(InventoryError::JournalCorruptOrBounded(reason));
        }
        if !self.matches_active_workspace_incarnation(
            &inspected_record.record_id,
            inspected_record,
            inspected_seq,
        ) {
            return Ok(false);
        }
        if let Err(err) = self.commit_automatic_hold(&mut journal, count, now_unix_ms, payload) {
            if let Some(seq) = inspected_seq
                && let Some(held) = self.workspaces.get(&inspected_record.record_id)
                && held.status == WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
                && held.same_ownership_incarnation_ignoring_hold(inspected_record)
                && self
                    .workspace_registration_seq
                    .get(&inspected_record.record_id)
                    .copied()
                    == Some(seq)
            {
                self.local_workspace_holds.insert(
                    inspected_record.record_id.clone(),
                    (inspected_record.clone(), seq, held.clone()),
                );
            }
            return Err(err);
        }
        Ok(true)
    }

    fn apply_payload(
        &mut self,
        payload: InventoryPayloadV1,
        is_replay: bool,
    ) -> InventoryResult<()> {
        match payload {
            InventoryPayloadV1::RegisterWorkspace { mut record } => {
                record.validate_structural()?;
                if !record
                    .shared_git_store_identity
                    .same_inode(&self.shared_git_store_identity)
                {
                    return Err(InventoryError::SharedGitStoreMismatch(format!(
                        "workspace {:?} does not share the enrolled Git object store",
                        record.workspace_name
                    )));
                }
                if !record
                    .operational_checkout_identity
                    .same_inode(&self.operational_checkout_identity)
                {
                    return Err(InventoryError::OperationalCheckoutForbidden(
                        "operational_checkout_identity mismatch".to_owned(),
                    ));
                }
                // Historical admission is a fact about the journal, independent of
                // today's directory. Verify only live admissions against the disk.
                if !is_replay {
                    let actual_ws_identity =
                        verify_private_directory_identity(Path::new(&record.workspace_path), true)?;
                    if actual_ws_identity != record.workspace_identity {
                        return Err(InventoryError::WorkspaceIdentityDrift(format!(
                            "workspace {:?} physical identity {:?} != claimed {:?}",
                            record.workspace_path, actual_ws_identity, record.workspace_identity
                        )));
                    }
                }

                // Check against all existing active/held workspaces for physical
                // inode collision, name collision, or shared mutable JJ change.
                for existing in self.workspaces.values() {
                    if !existing.status.blocks_exclusive_claim() {
                        continue;
                    }
                    if existing.record_id == record.record_id {
                        return Err(InventoryError::DuplicateWorkspaceName(format!(
                            "record_id {:?} already active or held",
                            record.record_id
                        )));
                    }
                    if existing
                        .workspace_identity
                        .same_inode(&record.workspace_identity)
                    {
                        return Err(InventoryError::DuplicatePhysicalWorkspace(format!(
                            "physical directory (dev={}, ino={}) already claimed by {:?}",
                            record.workspace_identity.dev,
                            record.workspace_identity.ino,
                            existing.owner_actor
                        )));
                    }
                    if existing.workspace_name == record.workspace_name {
                        return Err(InventoryError::DuplicateWorkspaceName(format!(
                            "workspace_name {:?} already claimed by {:?}",
                            record.workspace_name, existing.owner_actor
                        )));
                    }
                    if existing.jj_working_copy_change_id == record.jj_working_copy_change_id
                        || existing.jj_working_copy_commit_id == record.jj_working_copy_commit_id
                    {
                        return Err(InventoryError::SharedMutableJjChange(format!(
                            "JJ working-copy change {:?} already claimed by {:?}",
                            record.jj_working_copy_change_id, existing.owner_actor
                        )));
                    }
                }

                if !is_replay {
                    if let Some((pid, birth_us)) = record.pid_birth_binding
                        && !matches!(check_pid_birth_binding_live(pid, birth_us), Ok(true))
                    {
                        return Err(InventoryError::WorkspaceHeld(format!(
                            "bound process pid={pid} birth={birth_us} is not alive at admission"
                        )));
                    }
                    observe_live_jj_workspace(
                        Path::new(&record.workspace_path),
                        record.workspace_identity,
                        self.shared_git_store_identity,
                        self.operational_checkout_identity,
                        &record.workspace_name,
                        &record.jj_working_copy_change_id,
                        record.jj_working_copy_commit_id,
                    )?;
                }
                self.next_workspace_registration_seq += 1;
                self.workspace_registration_seq.insert(
                    record.record_id.clone(),
                    self.next_workspace_registration_seq,
                );
                self.local_workspace_holds.remove(&record.record_id);
                record.status = WorkspaceOwnershipStatusV1::Active;
                record.hold_reason = None;
                self.workspaces.insert(record.record_id.clone(), *record);
                Ok(())
            }
            InventoryPayloadV1::ReleaseWorkspace {
                record_id,
                actor,
                released_unix_ms,
            } => {
                let Some(existing) = self.workspaces.get_mut(&record_id) else {
                    return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                        "unknown workspace record_id {record_id:?}"
                    )));
                };
                if existing.owner_actor != actor {
                    return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                        "actor {actor:?} cannot release workspace owned by {:?}",
                        existing.owner_actor
                    )));
                }
                if released_unix_ms < existing.issued_unix_ms {
                    return Err(InventoryError::InvalidIdentifier(
                        "released_unix_ms precedes issued_unix_ms".to_owned(),
                    ));
                }
                existing.status = WorkspaceOwnershipStatusV1::Released;
                existing.hold_reason = None;
                self.local_workspace_holds.remove(&record_id);
                Ok(())
            }
            InventoryPayloadV1::AdvanceWorkspaceCheckpoint {
                record_id,
                actor,
                task_ref,
                expected_jj_working_copy_change_id,
                expected_old_jj_working_copy_commit_id,
                new_jj_working_copy_commit_id,
                updated_unix_ms,
            } => {
                let existing = self.workspaces.get(&record_id).ok_or_else(|| {
                    InventoryError::UnresolvedOrMismatchedOwner(format!(
                        "unknown workspace record_id {record_id:?}"
                    ))
                })?;
                if existing.status != WorkspaceOwnershipStatusV1::Active {
                    return Err(InventoryError::WorkspaceHeld(format!(
                        "workspace {record_id:?} is not Active"
                    )));
                }
                if existing.owner_actor != actor || existing.task_ref != task_ref {
                    return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                        "checkpoint owner/task mismatch for {record_id:?}"
                    )));
                }
                if updated_unix_ms < existing.issued_unix_ms
                    || updated_unix_ms >= existing.lease_expires_unix_ms
                {
                    return Err(InventoryError::WorkspaceHeld(
                        "checkpoint advance outside active lease window".to_owned(),
                    ));
                }
                if existing.jj_working_copy_change_id != expected_jj_working_copy_change_id {
                    return Err(InventoryError::SharedMutableJjChange(
                        "checkpoint advance cannot switch mutable JJ change_id".to_owned(),
                    ));
                }
                if existing.jj_working_copy_commit_id != expected_old_jj_working_copy_commit_id {
                    return Err(InventoryError::WorkspaceIdentityDrift(
                        "checkpoint advance expected_old_jj_working_copy_commit_id CAS mismatch"
                            .to_owned(),
                    ));
                }
                if new_jj_working_copy_commit_id == existing.base_commit_id {
                    return Err(InventoryError::SharedMutableJjChange(
                        "new working-copy commit cannot equal immutable base_commit_id".to_owned(),
                    ));
                }
                if self.workspaces.values().any(|other| {
                    other.record_id != record_id
                        && other.status.blocks_exclusive_claim()
                        && other.jj_working_copy_commit_id == new_jj_working_copy_commit_id
                }) {
                    return Err(InventoryError::SharedMutableJjChange(
                        "checkpoint commit already claimed by another workspace".to_owned(),
                    ));
                }
                if !is_replay {
                    if let Some((pid, birth_us)) = existing.pid_birth_binding
                        && !matches!(check_pid_birth_binding_live(pid, birth_us), Ok(true))
                    {
                        return Err(InventoryError::WorkspaceHeld(format!(
                            "bound process pid={pid} birth={birth_us} is not alive at checkpoint advance"
                        )));
                    }
                    observe_live_jj_workspace(
                        Path::new(&existing.workspace_path),
                        existing.workspace_identity,
                        self.shared_git_store_identity,
                        self.operational_checkout_identity,
                        &existing.workspace_name,
                        &expected_jj_working_copy_change_id,
                        new_jj_working_copy_commit_id,
                    )?;
                }
                if let Some(existing) = self.workspaces.get_mut(&record_id) {
                    existing.jj_working_copy_commit_id = new_jj_working_copy_commit_id;
                }
                Ok(())
            }
            InventoryPayloadV1::UpsertCapability { mut record } => {
                if let Err(err) = record.verify_and_classify() {
                    if matches!(
                        err,
                        InventoryError::UnprovenCapabilityClaim(_)
                            | InventoryError::DirtyOrMismatchedBuildProvenance(_)
                    ) && self.capabilities.contains_key(&record.capability_id)
                    {
                        self.capabilities
                            .insert(record.capability_id.clone(), *record);
                    }
                    return Err(err);
                }
                self.capabilities
                    .insert(record.capability_id.clone(), *record);
                Ok(())
            }
            InventoryPayloadV1::HoldWorkspace {
                record_id,
                hold_reason,
                ..
            } => {
                if !is_replay
                    && let Some(inspected) = self.workspaces.get(&record_id)
                    && inspected.status == WorkspaceOwnershipStatusV1::Active
                    && let Some(seq) = self.workspace_registration_seq.get(&record_id).copied()
                {
                    self.local_workspace_holds.insert(
                        record_id.clone(),
                        (inspected.clone(), seq, inspected.clone()),
                    );
                }
                let record = self.workspaces.get_mut(&record_id).ok_or_else(|| {
                    InventoryError::WorkspaceHeld(format!("unknown workspace record {record_id:?}"))
                })?;
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                record.hold_reason = Some(hold_reason);
                record.pid_birth_binding = None;
                if !is_replay
                    && let Some((_, _, held)) = self.local_workspace_holds.get_mut(&record_id)
                {
                    held.clone_from(record);
                }
                Ok(())
            }
            InventoryPayloadV1::HoldCapability {
                capability_id,
                hold_reason,
                updated_unix_ms,
            } => {
                let record = self.capabilities.get_mut(&capability_id).ok_or_else(|| {
                    InventoryError::UnprovenCapabilityClaim(format!(
                        "unknown capability {capability_id:?}"
                    ))
                })?;
                record.effective_classification = CapabilityClassificationV1::Held;
                record.hold_or_downgrade_reason = Some(hold_reason);
                record.installed_binary_sha256 = None;
                record.observed_unix_ms = updated_unix_ms;
                Ok(())
            }
        }
    }

    /// Guard a source-mutating operation before execution: verifies that the
    /// workspace record is `Active`, owned by `caller_actor`, bound to
    /// `expected_task_ref`, within its lease window, and that its physical
    /// directory `(dev, ino, uid, mode)` has not drifted since admission.
    pub fn verify_workspace_for_mutation(
        &mut self,
        record_id: &str,
        caller_actor: &str,
        expected_task_ref: &TaskRefV1,
        now_unix_ms: u64,
    ) -> InventoryResult<&WorkspaceOwnershipRecordV1> {
        if let Some(journal_path) = self.journal_path.clone() {
            self.refresh_from_journal(&journal_path)?;
        }
        if let Some(reason) = &self.corrupt_or_ambiguous_tail_reason {
            return Err(InventoryError::JournalCorruptOrBounded(reason.clone()));
        }
        let record = self.workspaces.get(record_id).cloned().ok_or_else(|| {
            InventoryError::UnresolvedOrMismatchedOwner(format!(
                "workspace record {record_id:?} is not registered"
            ))
        })?;
        if record.status != WorkspaceOwnershipStatusV1::Active {
            return Err(InventoryError::WorkspaceHeld(format!(
                "workspace {record_id:?} is not Active (status={:?}, reason={:?})",
                record.status, record.hold_reason
            )));
        }
        if record.owner_actor != caller_actor || &record.task_ref != expected_task_ref {
            return Err(InventoryError::UnresolvedOrMismatchedOwner(format!(
                "workspace {record_id:?} owner/task mismatch for caller {caller_actor:?}"
            )));
        }
        let failure = if now_unix_ms >= record.lease_expires_unix_ms {
            let reason = format!(
                "workspace {record_id:?} lease expired at {}",
                record.lease_expires_unix_ms
            );
            Some((InventoryError::WorkspaceHeld(reason.clone()), reason))
        } else if let Some((pid, birth_us)) = record.pid_birth_binding
            && !matches!(check_pid_birth_binding_live(pid, birth_us), Ok(true))
        {
            let reason = format!(
                "workspace {record_id:?} bound process pid={pid} birth={birth_us} is not alive"
            );
            Some((InventoryError::WorkspaceHeld(reason.clone()), reason))
        } else {
            match verify_private_directory_identity(Path::new(&record.workspace_path), true) {
                Ok(current_id) if current_id == record.workspace_identity => {
                    observe_live_jj_workspace(
                        Path::new(&record.workspace_path),
                        record.workspace_identity,
                        self.shared_git_store_identity,
                        self.operational_checkout_identity,
                        &record.workspace_name,
                        &record.jj_working_copy_change_id,
                        record.jj_working_copy_commit_id,
                    )
                    .err()
                    .map(|err| {
                        let reason = format!(
                            "workspace {:?} live JJ verification failed: {err}",
                            record.record_id
                        );
                        (err, reason)
                    })
                }
                Ok(current_id) => {
                    let reason = format!(
                        "workspace {record_id:?} physical identity drifted from {:?} to {:?}",
                        record.workspace_identity, current_id
                    );
                    Some((
                        InventoryError::WorkspaceIdentityDrift(reason.clone()),
                        reason,
                    ))
                }
                Err(err) => {
                    let reason = format!("workspace {record_id:?} verification failed: {err}");
                    Some((err, reason))
                }
            }
        };
        if let Some((err, reason)) = failure {
            let seq = self.workspace_registration_seq.get(record_id).copied();
            self.hold_workspace(&record, seq, reason, now_unix_ms)?;
            return Err(err);
        }
        Ok(&self.workspaces[record_id])
    }

    /// Startup / pre-use / bounded runtime reconciliation. Places any expired,
    /// dead-PID, or physically drifted workspace into `HeldStaleOrUnknown`
    /// without silently deleting or stealing ownership. Persistence failures
    /// remain visible in the held record's reason and never restore readiness.
    pub fn reconcile_workspaces<F>(
        &mut self,
        now_unix_ms: u64,
        is_pid_birth_alive: F,
    ) -> Vec<String>
    where
        F: Fn(u32, u64) -> bool,
    {
        let mut holds: Vec<(WorkspaceOwnershipRecordV1, Option<u64>, String)> = Vec::new();
        for record in self.workspaces.values() {
            if record.status != WorkspaceOwnershipStatusV1::Active {
                continue;
            }
            let reason = if now_unix_ms >= record.lease_expires_unix_ms {
                Some("lease expired during reconciliation".to_owned())
            } else if let Some((pid, birth)) = record.pid_birth_binding
                && !is_pid_birth_alive(pid, birth)
            {
                Some(format!(
                    "bound process pid={pid} birth={birth} is not alive"
                ))
            } else {
                match verify_private_directory_identity(Path::new(&record.workspace_path), true) {
                    Ok(actual) if actual == record.workspace_identity => observe_live_jj_workspace(
                        Path::new(&record.workspace_path),
                        record.workspace_identity,
                        self.shared_git_store_identity,
                        self.operational_checkout_identity,
                        &record.workspace_name,
                        &record.jj_working_copy_change_id,
                        record.jj_working_copy_commit_id,
                    )
                    .err()
                    .map(|err| format!("live JJ workspace verification failed: {err}")),
                    Ok(_) | Err(_) => {
                        Some("physical workspace directory missing or identity drifted".to_owned())
                    }
                }
            };
            if let Some(reason) = reason {
                holds.push((
                    record.clone(),
                    self.workspace_registration_seq
                        .get(&record.record_id)
                        .copied(),
                    reason,
                ));
            }
        }
        let mut newly_held = Vec::new();
        for (inspected_record, inspected_seq, reason) in holds {
            match self.hold_workspace(
                &inspected_record,
                inspected_seq,
                reason.clone(),
                now_unix_ms,
            ) {
                Ok(true) => newly_held.push(inspected_record.record_id),
                Ok(false) => {}
                Err(err) => {
                    if let Some(record) = self.workspaces.get_mut(&inspected_record.record_id)
                        && record.same_ownership_incarnation_ignoring_hold(&inspected_record)
                        && inspected_seq.is_none_or(|seq| {
                            self.workspace_registration_seq
                                .get(&inspected_record.record_id)
                                .copied()
                                == Some(seq)
                        })
                        && record.status == WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
                    {
                        record.hold_reason = Some(format!("{reason}; durable hold failed: {err}"));
                        if let Some((_, _, overlay)) = self
                            .local_workspace_holds
                            .get_mut(&inspected_record.record_id)
                        {
                            overlay.clone_from(record);
                        }
                        newly_held.push(inspected_record.record_id);
                    }
                }
            }
        }
        newly_held
    }

    pub fn reconcile_workspaces_live(&mut self) -> InventoryResult<Vec<String>> {
        Ok(
            self.reconcile_workspaces(current_unix_ms()?, |pid, birth_us| {
                matches!(check_pid_birth_binding_live(pid, birth_us), Ok(true))
            }),
        )
    }

    /// Replay a durable journal from disk and place any intent lacking a
    /// matching result record into a conservative hold (`incomplete_ops_held`
    /// + `HeldStaleOrUnknown` on the target workspace).
    pub fn load_and_reconcile(
        shared_git_store_identity: FsEntryIdentityV1,
        operational_checkout_identity: FsEntryIdentityV1,
        journal_path: &Path,
    ) -> InventoryResult<Self> {
        let Some(mut journal) = LockedInventoryJournal::open(journal_path, false)? else {
            let mut registry = Self::new(shared_git_store_identity, operational_checkout_identity)?;
            registry.journal_path = Some(journal_path.to_owned());
            return Ok(registry);
        };
        let (mut registry, _) = Self::replay_journal(
            shared_git_store_identity,
            operational_checkout_identity,
            &mut journal,
        )?;
        registry.verify_or_bind_journal_identity(&journal)?;
        registry.journal_path = Some(journal_path.to_owned());
        if registry.corrupt_or_ambiguous_tail_reason.is_some() {
            return Ok(registry);
        }
        // Release the replay lock before automatic hold transactions reopen it.
        drop(journal);
        registry.reconcile_workspaces_live()?;
        Ok(registry)
    }

    fn replay_journal(
        shared_git_store_identity: FsEntryIdentityV1,
        operational_checkout_identity: FsEntryIdentityV1,
        journal: &mut LockedInventoryJournal,
    ) -> InventoryResult<(Self, usize)> {
        let mut registry = Self::new(shared_git_store_identity, operational_checkout_identity)?;
        let bytes = journal.read_from_start()?;
        if bytes.is_empty() {
            return Ok((registry, 0));
        }
        let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
        let mut pending_intents = BTreeMap::new();
        let mut count = 0usize;
        for (idx, raw_line) in lines.iter().enumerate() {
            count += 1;
            if count > MAX_INVENTORY_RECORDS {
                return Err(InventoryError::JournalCorruptOrBounded(
                    "journal record count exceeds MAX_INVENTORY_RECORDS".to_owned(),
                ));
            }
            let parsed = (|| {
                let line = raw_line.strip_suffix(b"\n").ok_or_else(|| {
                    InventoryError::JournalCorruptOrBounded(
                        "unterminated journal record".to_owned(),
                    )
                })?;
                strict_json_object(line, MAX_INVENTORY_JOURNAL_BYTES as usize)
                    .map_err(|e| InventoryError::JournalCorruptOrBounded(e.to_string()))?;
                serde_json::from_slice::<JournalEntryV1>(line)
                    .map_err(|e| InventoryError::JournalCorruptOrBounded(e.to_string()))
            })();
            let entry = match parsed {
                Ok(entry) => entry,
                Err(_) if idx + 1 == lines.len() => {
                    for (op_id, (digest, payload, inspected)) in pending_intents {
                        registry.hold_replayed_incomplete(op_id, digest, payload, inspected);
                    }
                    let reason = format!("torn_or_corrupt_journal_tail_at_line_{}", idx + 1);
                    registry.corrupt_or_ambiguous_tail_reason = Some(reason.clone());
                    registry.incomplete_ops_held.insert(
                        format!("torn-journal-tail-line-{}", idx + 1),
                        reason.clone(),
                    );
                    for (id, record) in &mut registry.workspaces {
                        if record.status == WorkspaceOwnershipStatusV1::Active {
                            let inspected = record.clone();
                            record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                            record.hold_reason = Some(format!("fenced_by_{reason}"));
                            record.pid_birth_binding = None;
                            if let Some(seq) = registry.workspace_registration_seq.get(id).copied()
                            {
                                registry
                                    .local_workspace_holds
                                    .insert(id.clone(), (inspected, seq, record.clone()));
                            }
                        }
                    }
                    // Every positive classification in this schema is evidence
                    // of readiness; none survives an untrustworthy journal tail.
                    for (id, record) in &mut registry.capabilities {
                        if !matches!(
                            record.effective_classification,
                            CapabilityClassificationV1::Unknown | CapabilityClassificationV1::Held
                        ) {
                            let inspected = record.clone();
                            record.effective_classification = CapabilityClassificationV1::Held;
                            record.hold_or_downgrade_reason = Some(format!("fenced_by_{reason}"));
                            record.installed_binary_sha256 = None;
                            registry
                                .local_capability_holds
                                .insert(id.clone(), (inspected, record.clone()));
                        }
                    }
                    return Ok((registry, count));
                }
                Err(err) => return Err(err),
            };
            match entry {
                JournalEntryV1::Intent {
                    operation_id,
                    intent_digest,
                    payload,
                    ..
                } => {
                    if intent_digest != Self::payload_digest(&payload)? {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "intent payload digest mismatch for operation_id {operation_id:?}"
                        )));
                    }
                    if registry.committed_ops.contains_key(&operation_id)
                        || registry.rejected_ops.contains_key(&operation_id)
                        || pending_intents.contains_key(&operation_id)
                    {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "duplicate journal intent for operation_id {operation_id}"
                        )));
                    }
                    let inspected = match &payload {
                        InventoryPayloadV1::ReleaseWorkspace { record_id, .. }
                        | InventoryPayloadV1::HoldWorkspace { record_id, .. }
                        | InventoryPayloadV1::AdvanceWorkspaceCheckpoint { record_id, .. } => {
                            registry
                                .workspaces
                                .get(record_id)
                                .zip(registry.workspace_registration_seq.get(record_id))
                                .map(|(record, seq)| (record.clone(), *seq))
                        }
                        _ => None,
                    };
                    pending_intents.insert(operation_id, (intent_digest, payload, inspected));
                }
                JournalEntryV1::Result {
                    operation_id,
                    intent_digest,
                    committed,
                    hold_reason,
                    ..
                } => {
                    let Some((expected_digest, payload, _)) = pending_intents.remove(&operation_id)
                    else {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "result without preceding intent for operation_id {operation_id:?}"
                        )));
                    };
                    if expected_digest != intent_digest {
                        return Err(InventoryError::JournalCorruptOrBounded(format!(
                            "intent/result digest mismatch for operation_id {operation_id:?}"
                        )));
                    }
                    if committed {
                        registry.apply_payload(payload, true)?;
                        registry.committed_ops.insert(operation_id, intent_digest);
                    } else {
                        if let InventoryPayloadV1::UpsertCapability { mut record } = payload
                            && registry.capabilities.contains_key(&record.capability_id)
                        {
                            let _ = record.verify_and_classify();
                            registry
                                .capabilities
                                .insert(record.capability_id.clone(), *record);
                        }
                        registry
                            .rejected_ops
                            .insert(operation_id, (intent_digest, hold_reason));
                    }
                }
            }
        }

        // Any intent without a matching result is held conservatively across restart.
        for (op_id, (digest, payload, inspected)) in pending_intents {
            registry.hold_replayed_incomplete(op_id, digest, payload, inspected);
        }
        journal.verify_binding(journal.file_bytes)?;
        Ok((registry, count))
    }

    fn hold_replayed_incomplete(
        &mut self,
        op_id: String,
        digest: String,
        payload: InventoryPayloadV1,
        inspected: Option<(WorkspaceOwnershipRecordV1, u64)>,
    ) {
        // A pending intent cannot resurrect an owner released later in the
        // valid journal, or hold a later registration with identical fields.
        if matches!(
            &payload,
            InventoryPayloadV1::ReleaseWorkspace { .. }
                | InventoryPayloadV1::HoldWorkspace { .. }
                | InventoryPayloadV1::AdvanceWorkspaceCheckpoint { .. }
        ) && !inspected.as_ref().is_some_and(|(record, seq)| {
            self.workspaces
                .get(&record.record_id)
                .is_some_and(|current| {
                    current.status.blocks_exclusive_claim()
                        && current.same_ownership_incarnation_ignoring_hold(record)
                        && self
                            .workspace_registration_seq
                            .get(&record.record_id)
                            .copied()
                            == Some(*seq)
                })
        }) {
            self.incomplete_ops_held.insert(op_id, digest);
            return;
        }
        self.hold_incomplete(op_id, digest, payload);
    }

    fn hold_incomplete(&mut self, op_id: String, digest: String, payload: InventoryPayloadV1) {
        self.incomplete_ops_held.insert(op_id.clone(), digest);
        let inspected_workspace = match &payload {
            InventoryPayloadV1::ReleaseWorkspace { record_id, .. }
            | InventoryPayloadV1::AdvanceWorkspaceCheckpoint { record_id, .. }
            | InventoryPayloadV1::HoldWorkspace { record_id, .. } => self
                .workspaces
                .get(record_id)
                .filter(|record| record.status == WorkspaceOwnershipStatusV1::Active)
                .zip(self.workspace_registration_seq.get(record_id))
                .map(|(record, seq)| (record.clone(), *seq)),
            _ => None,
        };
        let inspected_capability = match &payload {
            InventoryPayloadV1::UpsertCapability { record } => Some(
                self.capabilities
                    .get(&record.capability_id)
                    .cloned()
                    .unwrap_or_else(|| (**record).clone()),
            ),
            InventoryPayloadV1::HoldCapability { capability_id, .. } => {
                self.capabilities.get(capability_id).cloned()
            }
            _ => None,
        };
        match payload {
            InventoryPayloadV1::RegisterWorkspace { mut record } => {
                record.status = WorkspaceOwnershipStatusV1::HeldStaleOrUnknown;
                record.hold_reason = Some(format!(
                    "incomplete_journal_intent:{op_id}:register_workspace_unconfirmed"
                ));
                record.pid_birth_binding = None;
                if self
                    .workspaces
                    .get(&record.record_id)
                    .is_some_and(|existing| existing.status.blocks_exclusive_claim())
                {
                    let footprint_id = format!("{}#incomplete:{op_id}", record.record_id);
                    record.record_id = footprint_id;
                }
                self.workspaces.insert(record.record_id.clone(), *record);
            }
            InventoryPayloadV1::ReleaseWorkspace {
                record_id,
                released_unix_ms,
                ..
            } => {
                let _ = self.apply_payload(
                    InventoryPayloadV1::HoldWorkspace {
                        record_id,
                        hold_reason: format!(
                            "incomplete_journal_intent:{op_id}:release_workspace_unconfirmed"
                        ),
                        updated_unix_ms: released_unix_ms,
                    },
                    true,
                );
            }
            InventoryPayloadV1::AdvanceWorkspaceCheckpoint {
                record_id,
                updated_unix_ms,
                ..
            } => {
                let _ = self.apply_payload(InventoryPayloadV1::HoldWorkspace {
                    record_id,
                    hold_reason: format!("incomplete_journal_intent:{op_id}:advance_workspace_checkpoint_unconfirmed"),
                    updated_unix_ms,
                }, true);
            }
            InventoryPayloadV1::UpsertCapability { mut record } => {
                let reason =
                    format!("incomplete_journal_intent:{op_id}:upsert_capability_unconfirmed");
                let existing = self
                    .capabilities
                    .entry(record.capability_id.clone())
                    .or_insert_with(|| {
                        record.effective_classification = CapabilityClassificationV1::Held;
                        *record
                    });
                existing.effective_classification = CapabilityClassificationV1::Held;
                existing.hold_or_downgrade_reason = Some(reason);
                existing.installed_binary_sha256 = None;
            }
            hold @ (InventoryPayloadV1::HoldWorkspace { .. }
            | InventoryPayloadV1::HoldCapability { .. }) => {
                let _ = self.apply_payload(hold, true);
            }
        }
        if let Some((inspected, seq)) = inspected_workspace
            && let Some(held) = self.workspaces.get(&inspected.record_id)
        {
            let inspected = self
                .local_workspace_holds
                .get(&inspected.record_id)
                .map_or(inspected.clone(), |(original, _, _)| original.clone());
            self.local_workspace_holds
                .insert(inspected.record_id.clone(), (inspected, seq, held.clone()));
        }
        if let Some(inspected) = inspected_capability
            && let Some(held) = self.capabilities.get(&inspected.capability_id)
        {
            let inspected = self
                .local_capability_holds
                .get(&inspected.capability_id)
                .map_or(inspected.clone(), |(original, _)| original.clone());
            self.local_capability_holds
                .insert(inspected.capability_id.clone(), (inspected, held.clone()));
        }
    }

    /// Non-mutating discovery snapshot for agents and humans. Performs zero
    /// disk writes or state mutations.
    pub fn inspect_discovery_snapshot(&self) -> DiscoverySnapshotV1 {
        DiscoverySnapshotV1 {
            shared_git_store_identity: self.shared_git_store_identity,
            operational_checkout_identity: self.operational_checkout_identity,
            workspaces: self.workspaces.values().cloned().collect(),
            capabilities: self.capabilities.values().cloned().collect(),
            incomplete_operations_held: self.incomplete_ops_held.keys().cloned().collect(),
            corrupt_or_ambiguous_tail_reason: self.corrupt_or_ambiguous_tail_reason.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_writer::CanonicalTaskDocumentV1;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn sample_task_ref(task_id: &str) -> TaskRefV1 {
        let tref = TaskRefV1 {
            workspace_id: "chinwag".to_owned(),
            repo_id: "emunlabs/chinwag".to_owned(),
            task_source_id: "05a1b2c3d4e54f608192a3b4c5d6e806".to_owned(),
            source_generation: 1,
            canonical_task_path: "TASKS.md".to_owned(),
            task_id: task_id.to_owned(),
            task_spec_digest: Sha256Digest::from_hex(
                "d220229601d9a92042ff570206905bcb8faf3049d45251b145993dedb3fdd2f4",
            )
            .unwrap(),
            task_status_rev: 1,
            file_cas_rev: 1,
            baseline_commit: GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35").unwrap(),
        };
        tref.validate().unwrap();
        tref
    }

    fn test_jj(path: &Path, args: &[&str]) -> String {
        let mut command = Command::new(jj_binary());
        command.args([
            "--no-pager",
            "--color=never",
            "--config",
            "user.name=Inventory Test",
            "--config",
            "user.email=inventory@example.invalid",
        ]);
        if args.starts_with(&["git", "init"]) {
            command.current_dir(path);
        } else {
            command.arg("-R").arg(path);
        }
        let output = command.args(args).stdin(Stdio::null()).output().unwrap();
        assert!(
            output.status.success(),
            "jj {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn jj_checkpoint(path: &Path) -> (String, GitOid) {
        let output = test_jj(
            path,
            &[
                "--ignore-working-copy",
                "log",
                "--no-graph",
                "-r",
                "@",
                "-T",
                "change_id ++ \"\t\" ++ commit_id",
            ],
        );
        let (change, commit) = output.trim().split_once('\t').unwrap();
        (change.to_owned(), GitOid::from_hex(commit).unwrap())
    }

    fn jj_fixture_template() -> &'static TempDir {
        static TEMPLATE: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
        TEMPLATE.get_or_init(|| {
            let tmp = tempfile::tempdir_in("/private/tmp").unwrap();
            let store = tmp.path().join("store-repo");
            fs::create_dir(&store).unwrap();
            fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
            test_jj(&store, &["git", "init", "--colocate"]);
            for (dir, name) in [
                ("ws-agent-1", "ws-chwg-jj-workspace-registry-01-s1"),
                ("ws-agent-2", "ws-task-publish-reg-v1"),
            ] {
                let path = tmp.path().join(dir);
                test_jj(
                    &store,
                    &["workspace", "add", "--name", name, path.to_str().unwrap()],
                );
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                let _ = jj_checkpoint(&path);
            }
            tmp
        })
    }

    fn copy_fixture_tree(from: &Path, to: &Path) {
        fs::create_dir(to).unwrap();
        fs::set_permissions(to, fs::metadata(from).unwrap().permissions()).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let dest = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_fixture_tree(&entry.path(), &dest);
            } else {
                assert!(entry.file_type().unwrap().is_file());
                fs::copy(entry.path(), dest).unwrap();
            }
        }
    }

    struct EnvFixture {
        _tmp: TempDir,
        store_dir: std::path::PathBuf,
        op_dir: std::path::PathBuf,
        ws1_dir: std::path::PathBuf,
        ws2_dir: std::path::PathBuf,
        journal_path: std::path::PathBuf,
        store_id: FsEntryIdentityV1,
        op_id: FsEntryIdentityV1,
        ws1_id: FsEntryIdentityV1,
        ws2_id: FsEntryIdentityV1,
        base_unix_ms: u64,
        live_pid_birth: (u32, u64),
        ws1_change_id: String,
        ws1_commit_id: GitOid,
        ws2_change_id: String,
        ws2_commit_id: GitOid,
    }

    impl EnvFixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir_in("/private/tmp").unwrap();
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let store_dir = tmp.path().join("store-repo");
            let op_dir = tmp.path().join("operational-checkout");
            let ws1_dir = tmp.path().join("ws-agent-1");
            let ws2_dir = tmp.path().join("ws-agent-2");
            let journal_dir = tmp.path().join("journal");
            for dir in [&op_dir, &journal_dir] {
                fs::create_dir(dir).unwrap();
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let template = jj_fixture_template();
            for (source, dest) in [
                ("store-repo", &store_dir),
                ("ws-agent-1", &ws1_dir),
                ("ws-agent-2", &ws2_dir),
            ] {
                copy_fixture_tree(&template.path().join(source), dest);
            }
            let (ws1_change_id, ws1_commit_id) = jj_checkpoint(&ws1_dir);
            let (ws2_change_id, ws2_commit_id) = jj_checkpoint(&ws2_dir);
            let store_id = verify_private_directory_identity(&store_dir, true).unwrap();

            let op_id = verify_private_directory_identity(&op_dir, true).unwrap();
            let ws1_id = verify_private_directory_identity(&ws1_dir, true).unwrap();
            let ws2_id = verify_private_directory_identity(&ws2_dir, true).unwrap();
            let journal_path = journal_dir.join("inventory-journal.jsonl");
            Self {
                _tmp: tmp,
                store_dir,
                op_dir,
                ws1_dir,
                ws2_dir,
                journal_path,
                store_id,
                op_id,
                ws1_id,
                ws2_id,
                base_unix_ms: current_unix_ms().unwrap(),
                live_pid_birth: observe_current_process_birth_binding().unwrap(),
                ws1_change_id,
                ws1_commit_id,
                ws2_change_id,
                ws2_commit_id,
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn make_ws_record(
            &self,
            record_id: &str,
            ws_name: &str,
            ws_path: &Path,
            ws_id: FsEntryIdentityV1,
            change_id: &str,
            commit_hex: &str,
            actor: &str,
            task_id: &str,
        ) -> WorkspaceOwnershipRecordV1 {
            if (ws_path == self.ws1_dir || ws_path == self.ws2_dir) && ws_name != "ws-other-name" {
                let listing = test_jj(
                    ws_path,
                    &[
                        "--ignore-working-copy",
                        "workspace",
                        "list",
                        "-T",
                        "if(target.current_working_copy(), name)",
                    ],
                );
                if listing != ws_name {
                    test_jj(ws_path, &["workspace", "rename", ws_name]);
                }
            }
            let change_id: &str = match change_id {
                "pvonlxyolzsyqopzqrmtopulwnmmvmur" => &self.ws1_change_id,
                "xnslnrmrotuspxtltrpqrzpzrzmtyyok" => &self.ws2_change_id,
                other => other,
            };
            let commit = match commit_hex {
                "dcbcc601da53aada5b94e766cbb3b9acc2e0851c" => self.ws1_commit_id,
                "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2" => self.ws2_commit_id,
                other => GitOid::from_hex(other).unwrap(),
            };
            WorkspaceOwnershipRecordV1 {
                record_id: record_id.to_owned(),
                repo_id: "emunlabs/chinwag".to_owned(),
                operational_checkout_path: self.op_dir.to_str().unwrap().to_owned(),
                operational_checkout_identity: self.op_id,
                shared_git_store_path: self.store_dir.to_str().unwrap().to_owned(),
                shared_git_store_identity: self.store_id,
                workspace_name: ws_name.to_owned(),
                workspace_path: ws_path.to_str().unwrap().to_owned(),
                workspace_identity: ws_id,
                jj_working_copy_change_id: change_id.to_owned(),
                jj_working_copy_commit_id: commit,
                base_commit_id: GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35")
                    .unwrap(),
                base_tree_id: GitOid::from_hex("69c3b294b10a74190b894e2be486138c61772d83").unwrap(),
                owner_actor: actor.to_owned(),
                task_ref: sample_task_ref(task_id),
                admission_digest: Sha256Digest::from_hex(
                    "47db4ba1d53b605e82275e1994d6a591a2569aef7af7dea4749c8b410c145ed3",
                )
                .unwrap(),
                scope_paths: vec![
                    "crates/chinwag-cli/src/workspace_capability_inventory.rs".to_owned(),
                ],
                review_branch: "refs/heads/review/chwg-jj-workspace-registry-01-s1-20261109"
                    .to_owned(),
                issued_unix_ms: 1_000,
                lease_expires_unix_ms: self.base_unix_ms + 60_000,
                pid_birth_binding: Some(self.live_pid_birth),
                status: WorkspaceOwnershipStatusV1::Active,
                hold_reason: None,
            }
        }
    }

    #[test]
    fn acceptance_1_to_4_and_8_exclusive_workspace_change_alias_and_operational_checkout_guards() {
        let f = EnvFixture::new();
        let mut reg = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();

        // 1. Operational checkout is rejected as an agent workspace.
        let op_claim = f.make_ws_record(
            "rec-op",
            "ws-op",
            &f.op_dir,
            f.op_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-reject-1",
                1_500,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(op_claim),
                },
            ),
            Err(InventoryError::OperationalCheckoutForbidden(_))
        ));

        // 2. Bare/unresolved actor without #<instance> is rejected.
        let bare_actor_claim = f.make_ws_record(
            "rec-bare",
            "ws-bare",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-reject-bare",
                1_500,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(bare_actor_claim),
                },
            ),
            Err(InventoryError::UnresolvedOrMismatchedOwner(_))
        ));

        // 3. Valid registration of Workspace 1 succeeds and shares the Git store.
        let ws1_claim = f.make_ws_record(
            "rec-ws1",
            "ws-chwg-jj-workspace-registry-01-s1",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert_eq!(
            reg.submit_durable(
                &f.journal_path,
                "op-reg-ws1",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(ws1_claim.clone()),
                },
            )
            .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );

        // 4. Duplicate physical directory (same dev/ino) by another actor is rejected.
        let dup_phys = f.make_ws_record(
            "rec-dup-phys",
            "ws-other-name",
            &f.ws1_dir,
            f.ws1_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-dup-phys",
                2_100,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(dup_phys),
                },
            ),
            Err(InventoryError::DuplicatePhysicalWorkspace(_))
        ));

        // 5. Symlink alias to ws1_dir is rejected by NOFOLLOW directory walk.
        let alias_path = f._tmp.path().join("ws-symlink-alias");
        symlink(&f.ws1_dir, &alias_path).unwrap();
        let symlink_claim = f.make_ws_record(
            "rec-symlink",
            "ws-symlink",
            &alias_path,
            f.ws1_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-symlink",
                2_200,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(symlink_claim),
                },
            ),
            Err(InventoryError::SymlinkOrNonDirectory(_))
        ));

        // 6. Second distinct physical workspace sharing the same mutable JJ change is rejected.
        let shared_change = f.make_ws_record(
            "rec-ws2-shared-change",
            "ws-agent-2",
            &f.ws2_dir,
            f.ws2_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-shared-change",
                2_300,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(shared_change),
                },
            ),
            Err(InventoryError::SharedMutableJjChange(_))
        ));

        // 7. Second distinct physical workspace with its own JJ change sharing the Git store succeeds.
        let ws2_claim = f.make_ws_record(
            "rec-ws2",
            "ws-task-publish-reg-v1",
            &f.ws2_dir,
            f.ws2_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "GEMINI-PM#ef045f9c-8ad4-42a7-836e-eea718e3d198",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        assert_eq!(
            reg.submit_durable(
                &f.journal_path,
                "op-reg-ws2",
                2_400,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(ws2_claim),
                },
            )
            .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
    }

    #[test]
    fn acceptance_5_6_9_and_10_capability_provenance_dirty_build_and_non_authority() {
        let f = EnvFixture::new();
        let mut reg = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();

        let base_oid = GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35").unwrap();
        let tree_oid = GitOid::from_hex("69c3b294b10a74190b894e2be486138c61772d83").unwrap();
        let bin_sha = Sha256Digest::from_hex(
            "142c504a5f85210670c78e3671b453f0a5866383764a4b8306c4f5eac416e528",
        )
        .unwrap();

        // Dirty tree claiming Installed must fail closed.
        let dirty_installed = CapabilityProvenanceRecordV1 {
            capability_id: "cap.workspace_inventory.v1".to_owned(),
            handler_symbol: "verify_workspace_for_mutation".to_owned(),
            source_module_path: "crates/chinwag-cli/src/workspace_capability_inventory.rs"
                .to_owned(),
            claimed_classification: CapabilityClassificationV1::Installed,
            handler_wired: true,
            unit_tests_passed: true,
            source_commit: base_oid,
            source_tree: tree_oid,
            source_tree_clean: false,
            accepted_source_commit: Some(base_oid),
            compiled_artifact_sha256: Some(bin_sha),
            installed_binary_path: Some("/Users/brianspector/.local/bin/chinwag".to_owned()),
            installed_binary_sha256: Some(bin_sha),
            runtime_health_verified: false,
            admission_authority_digest: None,
            task_ref: None,
            observed_unix_ms: 3_000,
            effective_classification: CapabilityClassificationV1::Unknown,
            hold_or_downgrade_reason: None,
        };
        assert!(matches!(
            reg.submit_durable(
                &f.journal_path,
                "op-cap-dirty",
                3_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(dirty_installed.clone()),
                },
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));

        // Tested capability on uncommitted/dirty workspace is valid ONLY as Tested, never Operational/Authorized.
        let mut tested_only = dirty_installed;
        tested_only.claimed_classification = CapabilityClassificationV1::Tested;
        assert_eq!(
            reg.submit_durable(
                &f.journal_path,
                "op-cap-tested",
                3_100,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(tested_only.clone()),
                },
            )
            .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
        // Inventory record never grants execution authority.
        assert_eq!(
            tested_only.require_execution_authority(),
            Err(InventoryError::InventoryNotExecutionAuthority)
        );
    }

    #[test]
    fn acceptance_7_8_and_9_idempotent_replay_crash_recovery_reconcile_and_readonly_discovery() {
        let f = EnvFixture::new();
        let mut reg = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();

        let ws1 = f.make_ws_record(
            "rec-ws1",
            "ws-chwg-jj-workspace-registry-01-s1",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(ws1.clone()),
        };
        assert_eq!(
            reg.submit_durable(&f.journal_path, "op-1", 2_000, payload.clone())
                .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
        // Exact replay is idempotent.
        assert_eq!(
            reg.submit_durable(&f.journal_path, "op-1", 2_005, payload)
                .unwrap(),
            InventorySubmissionOutcomeV1::IdempotentReplay
        );

        // Simulate a crash after writing an Intent for ws2 without a Result record.
        let ws2 = f.make_ws_record(
            "rec-ws2-crash",
            "ws-crash",
            &f.ws2_dir,
            f.ws2_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let crash_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(ws2),
        };
        let crash_intent = JournalEntryV1::Intent {
            operation_id: "op-crash-incomplete".to_owned(),
            intent_digest: ContinuousInventoryRegistryV1::payload_digest(&crash_payload).unwrap(),
            recorded_unix_ms: 2_500,
            payload: crash_payload,
        };
        ContinuousInventoryRegistryV1::append_journal_entry(&f.journal_path, &crash_intent)
            .unwrap();

        // Reload and reconcile: ws1 is Active, ws2 is HeldStaleOrUnknown, op-crash-incomplete is held.
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        let journal_bytes_before = fs::read(&f.journal_path).unwrap();
        let snap = recovered.inspect_discovery_snapshot();
        let journal_bytes_after = fs::read(&f.journal_path).unwrap();
        assert_eq!(journal_bytes_before, journal_bytes_after);
        assert_eq!(
            snap.incomplete_operations_held,
            vec!["op-crash-incomplete".to_owned()]
        );
        let ws2_rec = snap
            .workspaces
            .iter()
            .find(|w| w.record_id == "rec-ws2-crash")
            .unwrap();
        assert_eq!(
            ws2_rec.status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );

        // Reconcile dead PID / expired lease places ws1 into HeldStaleOrUnknown.
        let newly_held =
            recovered.reconcile_workspaces(f.base_unix_ms + 70_000, |_pid, _birth| false);
        assert_eq!(newly_held, vec!["rec-ws1".to_owned()]);
        assert!(matches!(
            recovered.verify_workspace_for_mutation(
                "rec-ws1",
                "RUST#efffddad3cb4321cb1308b089f76c206",
                &ws1.task_ref,
                70_001,
            ),
            Err(InventoryError::WorkspaceHeld(_))
        ));
    }

    #[test]
    fn s2a_cross_instance_and_concurrent_shared_journal_exclusive_ownership_serialization() {
        // Exercise physical identity and mutable change collisions independently.
        for shared_change in [false, true] {
            let f = EnvFixture::new();
            let first = f.make_ws_record(
                "sequential-first",
                "sequential-first",
                &f.ws1_dir,
                f.ws1_id,
                "pvonlxyolzsyqopzqrmtopulwnmmvmur",
                "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
                "RUST#efffddad3cb4321cb1308b089f76c206",
                "CHWG-JJ-WORKSPACE-REGISTRY-01",
            );
            let mut second = first.clone();
            second.record_id = "sequential-second".to_owned();
            second.workspace_name = "sequential-second".to_owned();
            second.jj_working_copy_commit_id =
                GitOid::from_hex("9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2").unwrap();
            if shared_change {
                second.workspace_path = f.ws2_dir.to_str().unwrap().to_owned();
                second.workspace_identity = f.ws2_id;
            } else {
                second.jj_working_copy_change_id = "xnslnrmrotuspxtltrpqrzpzrzmtyyok".to_owned();
            }
            let mut owner = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            let mut stale = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            assert_eq!(
                owner
                    .submit_durable(
                        &f.journal_path,
                        "sequential-owner",
                        2_000,
                        InventoryPayloadV1::RegisterWorkspace {
                            record: Box::new(first.clone())
                        }
                    )
                    .unwrap(),
                InventorySubmissionOutcomeV1::Applied
            );
            let collision = stale.submit_durable(
                &f.journal_path,
                "sequential-collision",
                2_001,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(second),
                },
            );
            if shared_change {
                assert!(matches!(
                    collision,
                    Err(InventoryError::SharedMutableJjChange(_))
                ));
            } else {
                assert!(matches!(
                    collision,
                    Err(InventoryError::DuplicatePhysicalWorkspace(_))
                ));
            }
            assert_eq!(stale.workspaces.len(), 1);
            assert_eq!(stale.workspaces.get(&first.record_id), Some(&first));
            let loaded = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            assert_eq!(loaded.workspaces.len(), 1);
            assert_eq!(loaded.workspaces.get(&first.record_id), Some(&first));
            assert!(loaded.incomplete_ops_held.is_empty());

            let racing = EnvFixture::new();
            let mut claims = Vec::new();
            for index in 0..4 {
                let path = if shared_change {
                    let path = racing._tmp.path().join(format!("race-workspace-{index}"));
                    test_jj(
                        &racing.store_dir,
                        &[
                            "workspace",
                            "add",
                            "--name",
                            &format!("race-name-{index}"),
                            path.to_str().unwrap(),
                        ],
                    );
                    test_jj(&path, &["edit", &racing.ws1_change_id]);
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    path
                } else {
                    racing.ws1_dir.clone()
                };
                let identity = verify_private_directory_identity(&path, true).unwrap();
                let claim = racing.make_ws_record(
                    &format!("race-record-{index}"),
                    &if shared_change {
                        format!("race-name-{index}")
                    } else {
                        "ws-chwg-jj-workspace-registry-01-s1".to_owned()
                    },
                    &path,
                    identity,
                    "pvonlxyolzsyqopzqrmtopulwnmmvmur",
                    "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
                    "RUST#efffddad3cb4321cb1308b089f76c206",
                    "CHWG-JJ-WORKSPACE-REGISTRY-01",
                );
                claims.push(claim);
            }
            let barrier = std::sync::Barrier::new(4);
            let outcomes = std::thread::scope(|scope| {
                let mut threads = Vec::new();
                for (index, claim) in claims.into_iter().enumerate() {
                    let barrier = &barrier;
                    let journal_path = &racing.journal_path;
                    let store_id = racing.store_id;
                    let op_id = racing.op_id;
                    threads.push(scope.spawn(move || {
                        let mut registry =
                            ContinuousInventoryRegistryV1::new(store_id, op_id).unwrap();
                        barrier.wait();
                        registry.submit_durable(
                            journal_path,
                            &format!("race-operation-{index}"),
                            3_000,
                            InventoryPayloadV1::RegisterWorkspace {
                                record: Box::new(claim),
                            },
                        )
                    }));
                }
                threads
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .collect::<Vec<_>>()
            });
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| matches!(outcome, Ok(InventorySubmissionOutcomeV1::Applied)))
                    .count(),
                1
            );
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| if shared_change {
                        matches!(outcome, Err(InventoryError::SharedMutableJjChange(_)))
                    } else {
                        matches!(outcome, Err(InventoryError::DuplicatePhysicalWorkspace(_)))
                    })
                    .count(),
                3
            );
            let loaded = ContinuousInventoryRegistryV1::load_and_reconcile(
                racing.store_id,
                racing.op_id,
                &racing.journal_path,
            )
            .unwrap();
            assert_eq!(loaded.workspaces.len(), 1);
            assert_eq!(
                loaded.workspaces.values().next().unwrap().status,
                WorkspaceOwnershipStatusV1::Active
            );
            assert!(loaded.incomplete_ops_held.is_empty());
            assert_eq!(loaded.committed_ops.len(), 1);
        }
    }

    #[test]
    fn s2a_no_in_memory_ownership_effect_before_durable_result_and_prewrite_reservation() {
        let f = EnvFixture::new();
        let first = f.make_ws_record(
            "failed-registration",
            "failed-registration",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry.fail_next_result_append = true;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "failed-register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(first.clone())
                }
            ),
            Err(InventoryError::Io(_))
        ));
        assert!(!registry.fail_next_result_append);
        assert_eq!(
            registry.workspaces[&first.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(registry.incomplete_ops_held.contains_key("failed-register"));
        assert!(registry.committed_ops.is_empty());
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            loaded.workspaces[&first.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(loaded.incomplete_ops_held.contains_key("failed-register"));

        let f = EnvFixture::new();
        let owner = f.make_ws_record(
            "active-owner",
            "active-owner",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let owner_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(owner.clone()),
        };
        registry
            .submit_durable(
                &f.journal_path,
                "active-registration",
                2_000,
                owner_payload.clone(),
            )
            .unwrap();
        let mut collision = owner.clone();
        collision.workspace_name = "crashed-collision".to_owned();
        collision.workspace_path = f.ws2_dir.to_str().unwrap().to_owned();
        collision.workspace_identity = f.ws2_id;
        registry.fail_next_result_append = true;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "failed-collision",
                2_001,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(collision)
                }
            ),
            Err(InventoryError::Io(_))
        ));
        assert_eq!(registry.workspaces.get(&owner.record_id), Some(&owner));
        assert!(
            registry
                .incomplete_ops_held
                .contains_key("failed-collision")
        );
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(loaded.workspaces.get(&owner.record_id), Some(&owner));
        assert!(loaded.incomplete_ops_held.contains_key("failed-collision"));
        assert!(registry.corrupt_or_ambiguous_tail_reason().is_some());
        // A handle with an ambiguous append cannot attempt another mutation.
        // Explicit recovery creates a new handle from the complete prefix.
        registry = loaded;
        registry.fail_next_result_append = true;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "failed-release",
                2_002,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: owner.record_id.clone(),
                    actor: owner.owner_actor.clone(),
                    released_unix_ms: 2_002
                }
            ),
            Err(InventoryError::Io(_))
        ));
        assert_eq!(
            registry.workspaces[&owner.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(registry.incomplete_ops_held.contains_key("failed-release"));
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            loaded.workspaces[&owner.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(loaded.incomplete_ops_held.contains_key("failed-release"));
        assert!(registry.corrupt_or_ambiguous_tail_reason().is_some());
        registry = loaded;

        // A local reconciliation hold must survive an authoritative replay.
        assert_eq!(
            registry.reconcile_workspaces(f.base_unix_ms + 70_000, |_, _| true),
            Vec::<String>::new()
        );
        assert_eq!(
            registry
                .submit_durable(
                    &f.journal_path,
                    "active-registration",
                    70_001,
                    owner_payload
                )
                .unwrap(),
            InventorySubmissionOutcomeV1::IdempotentReplay
        );
        assert_eq!(
            registry.workspaces[&owner.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );

        let f = EnvFixture::new();
        let owner = f.make_ws_record(
            "reservation-owner",
            "reservation-owner",
            &f.ws1_dir,
            f.ws1_id,
            "pvonlxyolzsyqopzqrmtopulwnmmvmur",
            "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "reservation-owner",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(owner),
                },
            )
            .unwrap();
        let second = f.make_ws_record(
            "reservation-second",
            "reservation-second",
            &f.ws2_dir,
            f.ws2_id,
            "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
            "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        );
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(second),
        };
        let digest = ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap();
        let intent = JournalEntryV1::Intent {
            operation_id: "byte-reserved".to_owned(),
            intent_digest: digest.clone(),
            recorded_unix_ms: 4_000,
            payload: payload.clone(),
        };
        let result = JournalEntryV1::Result {
            operation_id: "byte-reserved".to_owned(),
            intent_digest: digest,
            completed_unix_ms: 4_000,
            committed: true,
            hold_reason: None,
        };
        let intent_bytes = serde_json::to_vec(&intent).unwrap().len() as u64 + 1;
        let result_bytes = serde_json::to_vec(&result).unwrap().len() as u64 + 1;
        let target_bytes = MAX_INVENTORY_JOURNAL_BYTES - intent_bytes - result_bytes + 1;
        assert!(target_bytes + intent_bytes < MAX_INVENTORY_JOURNAL_BYTES);
        assert!(target_bytes + intent_bytes + result_bytes > MAX_INVENTORY_JOURNAL_BYTES);
        let mut padded = fs::read(&f.journal_path).unwrap();
        assert_eq!(padded.pop(), Some(b'\n'));
        assert!(padded.len() < target_bytes as usize - 1);
        padded.resize(target_bytes as usize - 1, b' ');
        padded.push(b'\n');
        fs::write(&f.journal_path, &padded).unwrap();
        fs::set_permissions(&f.journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = registry.inspect_discovery_snapshot();
        let committed_before = registry.committed_ops.clone();
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(loaded.inspect_discovery_snapshot(), before);
        assert_eq!(loaded.committed_ops, committed_before);
        assert!(matches!(
            registry.submit_durable(&f.journal_path, "byte-reserved", 4_000, payload),
            Err(InventoryError::JournalCorruptOrBounded(_))
        ));
        assert_eq!(fs::metadata(&f.journal_path).unwrap().len(), target_bytes);
        assert_eq!(fs::read(&f.journal_path).unwrap(), padded);
        assert_eq!(registry.inspect_discovery_snapshot(), before);
        assert_eq!(registry.committed_ops, committed_before);
    }

    fn s2b_workspace(f: &EnvFixture, second: bool) -> WorkspaceOwnershipRecordV1 {
        let (id, path, identity, change, commit) = if second {
            (
                "s2b-second",
                &f.ws2_dir,
                f.ws2_id,
                "xnslnrmrotuspxtltrpqrzpzrzmtyyok",
                "9e27172b5e00c9f9e95a044a2a0b4cf0b2db7ff2",
            )
        } else {
            (
                "s2b-first",
                &f.ws1_dir,
                f.ws1_id,
                "pvonlxyolzsyqopzqrmtopulwnmmvmur",
                "dcbcc601da53aada5b94e766cbb3b9acc2e0851c",
            )
        };
        f.make_ws_record(
            id,
            id,
            path,
            identity,
            change,
            commit,
            "RUST#efffddad3cb4321cb1308b089f76c206",
            "CHWG-JJ-WORKSPACE-REGISTRY-01",
        )
    }

    fn s2b_capability(id: &str) -> CapabilityProvenanceRecordV1 {
        let source = GitOid::from_hex("d326c7129979ca43499547842daac076d80fac35").unwrap();
        let binary = Sha256Digest::from_hex(
            "142c504a5f85210670c78e3671b453f0a5866383764a4b8306c4f5eac416e528",
        )
        .unwrap();
        CapabilityProvenanceRecordV1 {
            capability_id: id.to_owned(),
            handler_symbol: "verify_workspace_for_mutation".to_owned(),
            source_module_path: "crates/chinwag-cli/src/workspace_capability_inventory.rs"
                .to_owned(),
            claimed_classification: CapabilityClassificationV1::Operational,
            handler_wired: true,
            unit_tests_passed: true,
            source_commit: source,
            source_tree: GitOid::from_hex("69c3b294b10a74190b894e2be486138c61772d83").unwrap(),
            source_tree_clean: true,
            accepted_source_commit: Some(source),
            compiled_artifact_sha256: Some(binary),
            installed_binary_path: Some("/test/chinwag".to_owned()),
            installed_binary_sha256: Some(binary),
            runtime_health_verified: true,
            admission_authority_digest: Some(binary),
            task_ref: Some(sample_task_ref("CHWG-JJ-WORKSPACE-REGISTRY-01")),
            observed_unix_ms: 2_000,
            effective_classification: CapabilityClassificationV1::Unknown,
            hold_or_downgrade_reason: None,
        }
    }

    fn read_journal_entries(path: &Path) -> Vec<JournalEntryV1> {
        fs::read(path)
            .unwrap()
            .split_inclusive(|byte| *byte == b'\n')
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    #[test]
    fn s2b_replay_survives_deleted_released_workspace_and_holds_moved_active_workspace() {
        let f = EnvFixture::new();
        let released = s2b_workspace(&f, false);
        let active = s2b_workspace(&f, true);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        for (op, record) in [
            ("register-released", &released),
            ("register-active", &active),
        ] {
            registry
                .submit_durable(
                    &f.journal_path,
                    op,
                    2_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(record.clone()),
                    },
                )
                .unwrap();
        }
        registry
            .submit_durable(
                &f.journal_path,
                "release-first",
                3_000,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: released.record_id.clone(),
                    actor: released.owner_actor.clone(),
                    released_unix_ms: 3_000,
                },
            )
            .unwrap();
        fs::remove_dir_all(&f.ws1_dir).unwrap();
        fs::rename(&f.ws2_dir, f._tmp.path().join("moved-active")).unwrap();
        // Raw replay remains independent of both missing directories.
        let mut journal = LockedInventoryJournal::open(&f.journal_path, false)
            .unwrap()
            .unwrap();
        let (replayed, _) =
            ContinuousInventoryRegistryV1::replay_journal(f.store_id, f.op_id, &mut journal)
                .unwrap();
        assert_eq!(
            replayed.workspaces[&active.record_id].status,
            WorkspaceOwnershipStatusV1::Active
        );
        drop(journal);
        let recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            recovered.workspaces[&released.record_id].status,
            WorkspaceOwnershipStatusV1::Released
        );
        assert_eq!(
            recovered.workspaces[&active.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(
            recovered.workspaces[&active.record_id]
                .hold_reason
                .as_ref()
                .unwrap()
                .contains("directory missing")
        );
        let bytes = fs::read(&f.journal_path).unwrap();
        let again =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            again.inspect_discovery_snapshot(),
            recovered.inspect_discovery_snapshot()
        );
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("\"op\":\"hold_workspace\"")
        );
        // A new live admission still rejects the missing path.
        let mut missing = active;
        missing.record_id = "missing-live-admission".to_owned();
        assert!(
            registry
                .submit_durable(
                    &f.journal_path,
                    "missing-live",
                    4_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(missing)
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn s2b_durable_workspace_hold_from_verify_workspace_for_mutation_survives_restart() {
        // Cover lease, inode drift, and missing-directory failures separately.
        for failure in 0..3 {
            let f = EnvFixture::new();
            let record = s2b_workspace(&f, false);
            let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            registry
                .submit_durable(
                    &f.journal_path,
                    "register",
                    2_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(record.clone()),
                    },
                )
                .unwrap();
            let now = match failure {
                0 => f.base_unix_ms + 70_000,
                1 => {
                    fs::rename(&f.ws1_dir, f._tmp.path().join("old-inode")).unwrap();
                    fs::create_dir(&f.ws1_dir).unwrap();
                    fs::set_permissions(&f.ws1_dir, fs::Permissions::from_mode(0o700)).unwrap();
                    3_000
                }
                _ => {
                    fs::remove_dir_all(&f.ws1_dir).unwrap();
                    3_000
                }
            };
            assert!(
                registry
                    .verify_workspace_for_mutation(
                        &record.record_id,
                        &record.owner_actor,
                        &record.task_ref,
                        now
                    )
                    .is_err()
            );
            let held = registry.workspaces[&record.record_id].clone();
            assert_eq!(held.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
            assert_eq!(held.pid_birth_binding, None);
            // Restore a valid directory binding before restart: only the journal
            // can now explain the hold (especially the expired synthetic lease).
            if failure == 1 {
                fs::remove_dir_all(&f.ws1_dir).unwrap();
                fs::rename(f._tmp.path().join("old-inode"), &f.ws1_dir).unwrap();
            }
            let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            assert_eq!(recovered.workspaces[&record.record_id], held);
            let bytes = fs::read(&f.journal_path).unwrap();
            assert_eq!(
                bytes
                    .split(|b| *b == b'\n')
                    .filter(|line| !line.is_empty())
                    .count(),
                4
            );
            let again = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            assert_eq!(again.workspaces[&record.record_id], held);
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        }
        // The same transition works without a journal for an in-memory registry.
        let f = EnvFixture::new();
        let record = s2b_workspace(&f, false);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .apply_payload(
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(record.clone()),
                },
                false,
            )
            .unwrap();
        assert!(
            registry
                .verify_workspace_for_mutation(
                    &record.record_id,
                    &record.owner_actor,
                    &record.task_ref,
                    f.base_unix_ms + 70_000
                )
                .is_err()
        );
        assert_eq!(
            registry.workspaces[&record.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert!(!f.journal_path.exists());
    }

    #[test]
    fn s2b_incomplete_release_and_upsert_intents_place_targets_in_conservative_hold_on_recovery() {
        let f = EnvFixture::new();
        let record = s2b_workspace(&f, false);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(record.clone()),
                },
            )
            .unwrap();
        let ready = s2b_capability("cap-existing");
        let unaffected = s2b_capability("cap-unaffected");
        for cap in [&ready, &unaffected] {
            registry
                .submit_durable(
                    &f.journal_path,
                    &format!("register-{}", cap.capability_id),
                    2_000,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(cap.clone()),
                    },
                )
                .unwrap();
        }
        let mut replacement = ready.clone();
        replacement.handler_symbol = "unconfirmed_replacement".to_owned();
        let pending = [
            (
                "pending-release",
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: record.record_id.clone(),
                    actor: record.owner_actor.clone(),
                    released_unix_ms: 3_000,
                },
            ),
            (
                "pending-existing",
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(replacement),
                },
            ),
            (
                "pending-new",
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(s2b_capability("cap-new")),
                },
            ),
            (
                "pending-register",
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(s2b_workspace(&f, true)),
                },
            ),
        ];
        for (operation_id, payload) in pending {
            let intent = JournalEntryV1::Intent {
                operation_id: operation_id.to_owned(),
                intent_digest: ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap(),
                recorded_unix_ms: 3_000,
                payload,
            };
            ContinuousInventoryRegistryV1::append_journal_entry(&f.journal_path, &intent).unwrap();
        }
        let bytes = fs::read(&f.journal_path).unwrap();
        for _ in 0..2 {
            let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            let held = &recovered.workspaces[&record.record_id];
            assert_eq!(held.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
            assert_eq!(held.pid_birth_binding, None);
            assert_eq!(
                held.hold_reason.as_deref(),
                Some("incomplete_journal_intent:pending-release:release_workspace_unconfirmed")
            );
            for (id, op) in [
                ("cap-existing", "pending-existing"),
                ("cap-new", "pending-new"),
            ] {
                let cap = &recovered.capabilities[id];
                assert_eq!(
                    cap.effective_classification,
                    CapabilityClassificationV1::Held
                );
                assert_eq!(cap.installed_binary_sha256, None);
                assert_eq!(
                    cap.hold_or_downgrade_reason,
                    Some(format!(
                        "incomplete_journal_intent:{op}:upsert_capability_unconfirmed"
                    ))
                );
            }
            assert_eq!(
                recovered.capabilities["cap-existing"].handler_symbol,
                ready.handler_symbol
            );
            assert_eq!(
                recovered.capabilities["cap-unaffected"].effective_classification,
                CapabilityClassificationV1::Operational
            );
            assert!(
                recovered.workspaces["s2b-second"]
                    .hold_reason
                    .as_ref()
                    .unwrap()
                    .contains("pending-register")
            );
            assert_eq!(recovered.incomplete_ops_held.len(), 4);
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        }
    }

    #[test]
    fn s2b_negative_capability_observation_downgrades_prior_ready_classification_durably() {
        for classification in [
            CapabilityClassificationV1::Implemented,
            CapabilityClassificationV1::Installed,
            CapabilityClassificationV1::Operational,
            CapabilityClassificationV1::Authorized,
        ] {
            for failure in 0..3 {
                let f = EnvFixture::new();
                let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                let mut cap = s2b_capability("cap-1");
                cap.claimed_classification = classification;
                registry
                    .submit_durable(
                        &f.journal_path,
                        "prior-ready",
                        2_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(cap.clone()),
                        },
                    )
                    .unwrap();
                let mut negative = cap.clone();
                negative.claimed_classification = CapabilityClassificationV1::Operational;
                match failure {
                    0 => negative.source_tree_clean = false,
                    1 => negative.installed_binary_sha256 = None,
                    _ => negative.handler_wired = false,
                }
                let error = registry
                    .submit_durable(
                        &f.journal_path,
                        "negative-observation",
                        3_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(negative.clone()),
                        },
                    )
                    .unwrap_err();
                let held = registry.capabilities["cap-1"].clone();
                assert_eq!(
                    held.effective_classification,
                    CapabilityClassificationV1::Held
                );
                let mut expected = negative.clone();
                assert_eq!(expected.verify_and_classify(), Err(error));
                assert_eq!(held, expected);
                assert_eq!(held.installed_binary_sha256, None);
                let bytes = fs::read(&f.journal_path).unwrap();
                let entries = read_journal_entries(&f.journal_path);
                assert_eq!(entries.len(), 4);
                assert!(matches!(
                    &entries[3],
                    JournalEntryV1::Result { operation_id, committed: false, hold_reason: Some(_), .. }
                        if operation_id == "negative-observation"
                ));
                assert!(!registry.committed_ops.contains_key("negative-observation"));
                assert!(registry.rejected_ops.contains_key("negative-observation"));
                for _ in 0..2 {
                    let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                        f.store_id,
                        f.op_id,
                        &f.journal_path,
                    )
                    .unwrap();
                    assert_eq!(recovered.capabilities["cap-1"], held);
                    assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
                }
                // Explicit Held observations remain admissible with dirty source
                // and invalid binaries, and provide a reason even if omitted.
                negative.claimed_classification = CapabilityClassificationV1::Held;
                negative.source_tree_clean = false;
                negative.installed_binary_sha256 = None;
                negative.hold_or_downgrade_reason = None;
                registry
                    .submit_durable(
                        &f.journal_path,
                        "explicit-held",
                        4_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(negative),
                        },
                    )
                    .unwrap();
                let recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                    f.store_id,
                    f.op_id,
                    &f.journal_path,
                )
                .unwrap();
                assert_eq!(
                    recovered.capabilities["cap-1"].effective_classification,
                    CapabilityClassificationV1::Held
                );
                assert!(
                    recovered.capabilities["cap-1"]
                        .hold_or_downgrade_reason
                        .as_ref()
                        .is_some_and(|reason| !reason.is_empty())
                );
                // Direct in-memory updates also retain negative observations.
                let mut memory = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                memory
                    .apply_payload(
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(cap.clone()),
                        },
                        false,
                    )
                    .unwrap();
                cap.handler_wired = false;
                assert!(
                    memory
                        .apply_payload(
                            InventoryPayloadV1::UpsertCapability {
                                record: Box::new(cap)
                            },
                            false
                        )
                        .is_err()
                );
                assert_eq!(
                    memory.capabilities["cap-1"].effective_classification,
                    CapabilityClassificationV1::Held
                );
                assert_eq!(memory.capabilities["cap-1"].installed_binary_sha256, None);
            }
        }
    }

    #[test]
    fn s2a_rejects_pre_intent_without_poisoning_sequence_or_writing_pending() {
        let f = EnvFixture::new();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let mut cap = s2b_capability("cap-dirty-s2a");
        cap.source_tree_clean = false;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "reusable-operation",
                2_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(cap.clone())
                }
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        assert!(registry.capabilities.is_empty());
        assert!(registry.committed_ops.is_empty());
        assert!(registry.incomplete_ops_held.is_empty());
        assert!(fs::read(&f.journal_path).unwrap().is_empty());
        cap.source_tree_clean = true;
        assert_eq!(
            registry
                .submit_durable(
                    &f.journal_path,
                    "reusable-operation",
                    2_001,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(cap)
                    }
                )
                .unwrap(),
            InventorySubmissionOutcomeV1::Applied
        );
    }

    #[test]
    fn registry_rejects_cross_journal_path_mutation_and_refresh() {
        let f = EnvFixture::new();
        let owner = s2b_workspace(&f, false);
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(owner.clone()),
        };
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(&f.journal_path, "op-bind", 2_000, payload.clone())
            .unwrap();
        let before = registry.inspect_discovery_snapshot();
        let binding = registry.bound_journal_identity.clone();
        let committed = registry.committed_ops.clone();
        let journal_a_bytes = fs::read(&f.journal_path).unwrap();

        // Exercise both a different leaf name and a different parent identity.
        // Invalid foreign contents prove identity rejection precedes replay.
        for journal_b in [
            f.journal_path.with_file_name("journal-b.jsonl"),
            f.ws2_dir.join(f.journal_path.file_name().unwrap()),
        ] {
            let journal_b_bytes = b"foreign journal must never be replayed\n";
            fs::write(&journal_b, journal_b_bytes).unwrap();
            fs::set_permissions(&journal_b, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                registry.submit_durable(&journal_b, "op-foreign", 3_000, payload.clone()),
                Err(InventoryError::InvalidPath(_))
            ));
            assert!(matches!(
                registry.refresh_from_journal(&journal_b),
                Err(InventoryError::InvalidPath(_))
            ));
            let mut holding = registry.clone();
            holding.journal_path = Some(journal_b.clone());
            assert!(matches!(
                holding.hold_workspace(&owner, None, "foreign hold".to_owned(), 3_000),
                Err(InventoryError::InvalidPath(_))
            ));
            assert_eq!(holding.inspect_discovery_snapshot(), before);
            assert_eq!(registry.inspect_discovery_snapshot(), before);
            assert_eq!(registry.bound_journal_identity, binding);
            assert_eq!(registry.committed_ops, committed);
            assert_eq!(fs::read(&f.journal_path).unwrap(), journal_a_bytes);
            assert_eq!(fs::read(&journal_b).unwrap(), journal_b_bytes);
        }

        registry.refresh_from_journal(&f.journal_path).unwrap();
        assert_eq!(registry.bound_journal_identity, binding);
        // The same pathname with a replacement inode is also a foreign journal.
        fs::rename(&f.journal_path, f.journal_path.with_extension("original")).unwrap();
        fs::write(&f.journal_path, &journal_a_bytes).unwrap();
        fs::set_permissions(&f.journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            registry.refresh_from_journal(&f.journal_path),
            Err(InventoryError::InvalidPath(_))
        ));
        assert_eq!(registry.inspect_discovery_snapshot(), before);
        assert_eq!(registry.bound_journal_identity, binding);
        assert_eq!(fs::read(&f.journal_path).unwrap(), journal_a_bytes);
    }

    #[test]
    fn rejected_operation_id_cannot_be_reused_with_same_or_different_payload_and_pre_admission_leaves_no_footprint()
     {
        let f = EnvFixture::new();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let ready = s2b_capability("cap-1");
        let mut dirty = ready.clone();
        dirty.source_tree_clean = false;
        let dirty_payload = InventoryPayloadV1::UpsertCapability {
            record: Box::new(dirty.clone()),
        };
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-pre-reject",
                2_000,
                dirty_payload.clone()
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        assert!(fs::read(&f.journal_path).unwrap().is_empty());
        assert!(!registry.rejected_ops.contains_key("op-pre-reject"));
        assert!(registry.capabilities.is_empty());
        assert!(registry.incomplete_ops_held.is_empty());
        let ready_payload = InventoryPayloadV1::UpsertCapability {
            record: Box::new(ready.clone()),
        };
        // Pre-admission rejection does not consume the operation ID.
        registry
            .submit_durable(
                &f.journal_path,
                "op-pre-reject",
                2_001,
                ready_payload.clone(),
            )
            .unwrap();
        let before_invalid = fs::read(&f.journal_path).unwrap();
        let mut invalid = ready.clone();
        invalid.handler_symbol.clear();
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-invalid-field",
                2_002,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(invalid)
                }
            ),
            Err(InventoryError::InvalidIdentifier(_))
        ));
        assert_eq!(fs::read(&f.journal_path).unwrap(), before_invalid);
        assert!(!registry.rejected_ops.contains_key("op-invalid-field"));
        assert_eq!(
            registry.capabilities["cap-1"].effective_classification,
            CapabilityClassificationV1::Operational
        );

        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-cap-dirty",
                3_000,
                dirty_payload.clone()
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        let entries = read_journal_entries(&f.journal_path);
        assert_eq!(entries.len(), 4);
        assert!(matches!(
            &entries[2],
            JournalEntryV1::Intent { operation_id, payload, .. }
                if operation_id == "op-cap-dirty" && payload == &dirty_payload
        ));
        assert!(matches!(
            &entries[3],
            JournalEntryV1::Result { operation_id, committed: false, hold_reason: Some(_), .. }
                if operation_id == "op-cap-dirty"
        ));
        let held = registry.capabilities["cap-1"].clone();
        assert_eq!(
            held.effective_classification,
            CapabilityClassificationV1::Held
        );
        assert_eq!(held.installed_binary_sha256, None);
        assert!(!held.source_tree_clean);
        assert!(registry.rejected_ops.contains_key("op-cap-dirty"));
        let rejected_bytes = fs::read(&f.journal_path).unwrap();
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(recovered.capabilities["cap-1"], held);
        assert_eq!(recovered.rejected_ops, registry.rejected_ops);
        for handle in [&mut registry, &mut recovered] {
            for (payload, digest_matches) in [
                (dirty_payload.clone(), true),
                (ready_payload.clone(), false),
            ] {
                let error = handle
                    .submit_durable(&f.journal_path, "op-cap-dirty", 3_001, payload)
                    .unwrap_err();
                assert!(
                    matches!(error, InventoryError::ConflictingReplay(ref reason)
                    if reason.contains(&format!("digest_match={digest_matches}")))
                );
                assert_eq!(handle.capabilities["cap-1"], held);
                assert_eq!(fs::read(&f.journal_path).unwrap(), rejected_bytes);
            }
        }

        let owner = s2b_workspace(&f, false);
        registry
            .submit_durable(
                &f.journal_path,
                "op-ws-owner",
                4_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(owner.clone()),
                },
            )
            .unwrap();
        let mut conflict = owner;
        conflict.record_id = "ws-conflict".to_owned();
        conflict.workspace_name = "ws-conflict".to_owned();
        let conflict_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(conflict),
        };
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-ws-conflict",
                4_001,
                conflict_payload.clone()
            ),
            Err(InventoryError::DuplicatePhysicalWorkspace(_))
        ));
        let entries = read_journal_entries(&f.journal_path);
        assert_eq!(entries.len(), 8);
        assert!(matches!(
            &entries[6],
            JournalEntryV1::Intent { operation_id, .. } if operation_id == "op-ws-conflict"
        ));
        assert!(matches!(
            &entries[7],
            JournalEntryV1::Result { operation_id, committed: false, hold_reason: Some(_), .. }
                if operation_id == "op-ws-conflict"
        ));
        let rejected_bytes = fs::read(&f.journal_path).unwrap();
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        let different_payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(s2b_workspace(&f, true)),
        };
        for handle in [&mut registry, &mut recovered] {
            assert!(handle.rejected_ops.contains_key("op-ws-conflict"));
            for payload in [conflict_payload.clone(), different_payload.clone()] {
                assert!(matches!(
                    handle.submit_durable(&f.journal_path, "op-ws-conflict", 4_002, payload),
                    Err(InventoryError::ConflictingReplay(_))
                ));
                assert_eq!(fs::read(&f.journal_path).unwrap(), rejected_bytes);
            }
        }
    }

    #[test]
    fn incomplete_register_workspace_colliding_record_id_and_released_record_id_preserve_both_footprints()
     {
        let f = EnvFixture::new();
        let mut owner = s2b_workspace(&f, false);
        owner.record_id = "ws-1".to_owned();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "op-owner",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(owner.clone()),
                },
            )
            .unwrap();
        let mut collision = s2b_workspace(&f, true);
        collision.record_id = owner.record_id.clone();
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(collision.clone()),
        };
        ContinuousInventoryRegistryV1::append_journal_entry(
            &f.journal_path,
            &JournalEntryV1::Intent {
                operation_id: "op-incomplete-collision".to_owned(),
                intent_digest: ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap(),
                recorded_unix_ms: 3_000,
                payload,
            },
        )
        .unwrap();
        let bytes = fs::read(&f.journal_path).unwrap();
        let mut recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(recovered.workspaces["ws-1"], owner);
        let footprint_id = "ws-1#incomplete:op-incomplete-collision";
        let footprint = &recovered.workspaces[footprint_id];
        assert_eq!(
            footprint.status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert_eq!(footprint.workspace_identity, collision.workspace_identity);
        assert_eq!(footprint.workspace_name, collision.workspace_name);
        assert_eq!(
            footprint.jj_working_copy_change_id,
            collision.jj_working_copy_change_id
        );
        assert_eq!(
            footprint.jj_working_copy_commit_id,
            collision.jj_working_copy_commit_id
        );
        assert_eq!(footprint.pid_birth_binding, None);
        assert_eq!(recovered.workspaces.len(), 2);
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        let third_path = f._tmp.path().join("ws-third");
        fs::create_dir(&third_path).unwrap();
        fs::set_permissions(&third_path, fs::Permissions::from_mode(0o700)).unwrap();
        let third_identity = verify_private_directory_identity(&third_path, true).unwrap();

        // Independently collide with the held inode, name, change, and commit.
        for conflict in 0..4 {
            let mut claim = collision.clone();
            claim.record_id = "ws-2".to_owned();
            claim.workspace_path = third_path.to_str().unwrap().to_owned();
            claim.workspace_identity = third_identity;
            claim.workspace_name = "ws-2".to_owned();
            claim.jj_working_copy_change_id = "unique-third-change".to_owned();
            claim.jj_working_copy_commit_id =
                GitOid::from_hex("1111111111111111111111111111111111111111").unwrap();
            match conflict {
                0 => {
                    claim.workspace_path.clone_from(&collision.workspace_path);
                    claim.workspace_identity = collision.workspace_identity;
                }
                1 => claim.workspace_name.clone_from(&collision.workspace_name),
                2 => claim
                    .jj_working_copy_change_id
                    .clone_from(&collision.jj_working_copy_change_id),
                _ => claim.jj_working_copy_commit_id = collision.jj_working_copy_commit_id,
            }
            let error = recovered
                .submit_durable(
                    &f.journal_path,
                    &format!("op-claim-{conflict}"),
                    4_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(claim),
                    },
                )
                .unwrap_err();
            match conflict {
                0 => assert!(matches!(
                    error,
                    InventoryError::DuplicatePhysicalWorkspace(_)
                )),
                1 => assert!(matches!(error, InventoryError::DuplicateWorkspaceName(_))),
                _ => assert!(matches!(error, InventoryError::SharedMutableJjChange(_))),
            }
            assert_eq!(recovered.workspaces["ws-1"], owner);
            assert_eq!(recovered.workspaces.len(), 2);
        }
        let before = fs::read(&f.journal_path).unwrap();
        assert!(matches!(
            recovered.submit_durable(
                &f.journal_path,
                "op-incomplete-collision",
                4_001,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(collision)
                }
            ),
            Err(InventoryError::IncompleteIntentHeld(_))
        ));
        assert_eq!(fs::read(&f.journal_path).unwrap(), before);

        let f = EnvFixture::new();
        let mut released = s2b_workspace(&f, false);
        released.record_id = "ws-rel".to_owned();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "op-register-released",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(released.clone()),
                },
            )
            .unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "op-release",
                3_000,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: released.record_id,
                    actor: released.owner_actor,
                    released_unix_ms: 3_000,
                },
            )
            .unwrap();
        let mut replacement = s2b_workspace(&f, true);
        replacement.record_id = "ws-rel".to_owned();
        let payload = InventoryPayloadV1::RegisterWorkspace {
            record: Box::new(replacement.clone()),
        };
        ContinuousInventoryRegistryV1::append_journal_entry(
            &f.journal_path,
            &JournalEntryV1::Intent {
                operation_id: "op-incomplete-reregister".to_owned(),
                intent_digest: ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap(),
                recorded_unix_ms: 4_000,
                payload,
            },
        )
        .unwrap();
        let bytes = fs::read(&f.journal_path).unwrap();
        let recovered =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        let held = &recovered.workspaces["ws-rel"];
        assert_eq!(held.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
        assert_eq!(held.workspace_identity, replacement.workspace_identity);
        assert_eq!(held.workspace_name, replacement.workspace_name);
        assert_eq!(
            held.jj_working_copy_change_id,
            replacement.jj_working_copy_change_id
        );
        assert_eq!(
            held.jj_working_copy_commit_id,
            replacement.jj_working_copy_commit_id
        );
        assert_eq!(held.pid_birth_binding, None);
        assert_eq!(
            held.hold_reason.as_deref(),
            Some(
                "incomplete_journal_intent:op-incomplete-reregister:register_workspace_unconfirmed"
            )
        );
        assert_eq!(recovered.workspaces.len(), 1);
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
    }

    #[test]
    fn torn_journal_tail_preserves_valid_prefix_for_discovery_fences_active_entries_and_blocks_mutations_without_truncating()
     {
        for tail in [
            b"{\"record_kind\":\"intent\"".as_slice(),
            b"not JSON\n".as_slice(),
            b"{\"record_kind\":\"intent\"}\n".as_slice(),
            b"{\"record_kind\":\"intent\",\"record_kind\":\"result\"}\n".as_slice(),
        ] {
            let f = EnvFixture::new();
            let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            let mut owner = s2b_workspace(&f, false);
            owner.record_id = "ws-1".to_owned();
            registry
                .submit_durable(
                    &f.journal_path,
                    "op-owner",
                    2_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(owner),
                    },
                )
                .unwrap();
            registry
                .submit_durable(
                    &f.journal_path,
                    "op-ready",
                    2_000,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(s2b_capability("cap-1")),
                    },
                )
                .unwrap();
            let pending = InventoryPayloadV1::RegisterWorkspace {
                record: Box::new(s2b_workspace(&f, true)),
            };
            ContinuousInventoryRegistryV1::append_journal_entry(
                &f.journal_path,
                &JournalEntryV1::Intent {
                    operation_id: "op-pending-prefix".to_owned(),
                    intent_digest: ContinuousInventoryRegistryV1::payload_digest(&pending).unwrap(),
                    recorded_unix_ms: 3_000,
                    payload: pending,
                },
            )
            .unwrap();
            let mut bytes = fs::read(&f.journal_path).unwrap();
            bytes.extend_from_slice(tail);
            fs::write(&f.journal_path, &bytes).unwrap();
            let size = fs::metadata(&f.journal_path).unwrap().len();
            // Reconciliation would ordinarily persist a hold for this missing
            // path. Torn-tail recovery must remain a discovery-only operation.
            fs::remove_dir_all(&f.ws1_dir).unwrap();
            let mut recovered = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            let snapshot = recovered.inspect_discovery_snapshot();
            let reason = "torn_or_corrupt_journal_tail_at_line_6";
            assert_eq!(
                snapshot.corrupt_or_ambiguous_tail_reason.as_deref(),
                Some(reason)
            );
            assert_eq!(recovered.corrupt_or_ambiguous_tail_reason(), Some(reason));
            let owner = snapshot
                .workspaces
                .iter()
                .find(|w| w.record_id == "ws-1")
                .unwrap();
            assert_eq!(owner.status, WorkspaceOwnershipStatusV1::HeldStaleOrUnknown);
            assert_eq!(owner.pid_birth_binding, None);
            assert_eq!(owner.hold_reason, Some(format!("fenced_by_{reason}")));
            let capability = snapshot
                .capabilities
                .iter()
                .find(|c| c.capability_id == "cap-1")
                .unwrap();
            assert_eq!(
                capability.effective_classification,
                CapabilityClassificationV1::Held
            );
            assert_eq!(capability.installed_binary_sha256, None);
            assert_eq!(
                capability.hold_or_downgrade_reason,
                Some(format!("fenced_by_{reason}"))
            );
            assert_eq!(
                snapshot.incomplete_operations_held,
                vec![
                    "op-pending-prefix".to_owned(),
                    "torn-journal-tail-line-6".to_owned()
                ]
            );
            assert_eq!(snapshot.workspaces.len(), 2);
            assert_eq!(
                recovered.workspaces["s2b-second"].status,
                WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
            );
            assert_eq!(fs::metadata(&f.journal_path).unwrap().len(), size);
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);

            // Both a freshly loaded handle and a stale live handle fail closed.
            for handle in [&mut recovered, &mut registry] {
                assert!(matches!(
                    handle.submit_durable(
                        &f.journal_path,
                        "op-after-tail",
                        4_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(s2b_capability("cap-after-tail"))
                        }
                    ),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                let inspected = handle.workspaces["ws-1"].clone();
                assert!(matches!(
                    handle.hold_workspace(&inspected, None, "after tail".to_owned(), 4_001),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                handle.refresh_from_journal(&f.journal_path).unwrap();
                assert_eq!(handle.inspect_discovery_snapshot(), snapshot);
                assert_eq!(fs::metadata(&f.journal_path).unwrap().len(), size);
                assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
            }
            let mut journal = LockedInventoryJournal::open(&f.journal_path, false)
                .unwrap()
                .unwrap();
            let (_, physical_record_count) =
                ContinuousInventoryRegistryV1::replay_journal(f.store_id, f.op_id, &mut journal)
                    .unwrap();
            assert_eq!(physical_record_count, 6);
        }
    }

    #[test]
    fn ambiguous_append_failures_preserve_holds_and_disposition_across_refresh() {
        for fail_result in [false, true] {
            for upsert_capability in [false, true] {
                let f = EnvFixture::new();
                let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                let owner = s2b_workspace(&f, false);
                let ready = s2b_capability("cap-1");
                registry
                    .submit_durable(
                        &f.journal_path,
                        "op-owner",
                        2_000,
                        InventoryPayloadV1::RegisterWorkspace {
                            record: Box::new(owner.clone()),
                        },
                    )
                    .unwrap();
                registry
                    .submit_durable(
                        &f.journal_path,
                        "op-ready",
                        2_000,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(ready.clone()),
                        },
                    )
                    .unwrap();
                let mut collision = owner;
                collision.record_id = "ws-conflict".to_owned();
                collision.workspace_name = "ws-conflict".to_owned();
                assert!(matches!(
                    registry.submit_durable(
                        &f.journal_path,
                        "op-rejected",
                        3_000,
                        InventoryPayloadV1::RegisterWorkspace {
                            record: Box::new(collision)
                        }
                    ),
                    Err(InventoryError::DuplicatePhysicalWorkspace(_))
                ));
                let payload = if upsert_capability {
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(ready),
                    }
                } else {
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(s2b_workspace(&f, true)),
                    }
                };
                let before_failure = fs::read(&f.journal_path).unwrap();
                let error = if fail_result {
                    registry.fail_next_result_append = true;
                    registry
                        .submit_durable(&f.journal_path, "op-ambiguous", 4_000, payload.clone())
                        .unwrap_err()
                } else {
                    // An actual read-only descriptor makes Intent append fail
                    // without changing any bytes on disk.
                    let mut journal = LockedInventoryJournal::open(&f.journal_path, false)
                        .unwrap()
                        .unwrap();
                    registry
                        .commit_payload(&mut journal, 6, "op-ambiguous", 4_000, payload.clone())
                        .unwrap_err()
                };
                assert!(matches!(error, InventoryError::Io(_)));
                let reason_prefix = if fail_result {
                    "ambiguous_result_append:op-ambiguous:"
                } else {
                    "ambiguous_intent_append:op-ambiguous:"
                };
                assert!(
                    registry
                        .corrupt_or_ambiguous_tail_reason()
                        .is_some_and(|reason| reason.starts_with(reason_prefix))
                );
                assert!(registry.incomplete_ops_held.contains_key("op-ambiguous"));
                if upsert_capability {
                    assert_eq!(
                        registry.capabilities["cap-1"].effective_classification,
                        CapabilityClassificationV1::Held
                    );
                    assert_eq!(registry.capabilities["cap-1"].installed_binary_sha256, None);
                } else {
                    assert_eq!(
                        registry.workspaces["s2b-second"].status,
                        WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
                    );
                    assert_eq!(registry.workspaces["s2b-second"].pid_birth_binding, None);
                }
                let after_failure = fs::read(&f.journal_path).unwrap();
                if fail_result {
                    assert_eq!(read_journal_entries(&f.journal_path).len(), 7);
                } else {
                    assert_eq!(after_failure, before_failure);
                }
                let snapshot = registry.inspect_discovery_snapshot();
                let rejected = registry.rejected_ops.clone();
                registry.refresh_from_journal(&f.journal_path).unwrap();
                assert_eq!(registry.inspect_discovery_snapshot(), snapshot);
                assert_eq!(registry.rejected_ops, rejected);
                assert!(matches!(
                    registry.submit_durable(&f.journal_path, "op-ambiguous", 4_001, payload),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                let inspected = registry.workspaces["s2b-first"].clone();
                assert!(matches!(
                    registry.hold_workspace(&inspected, None, "blocked hold".to_owned(), 4_001),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                assert_eq!(registry.inspect_discovery_snapshot(), snapshot);
                assert_eq!(fs::read(&f.journal_path).unwrap(), after_failure);
            }
        }
    }

    #[test]
    fn journal_semantic_corruption_and_nonfinal_syntax_errors_fail_closed() {
        let f = EnvFixture::new();
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        let mut capability = s2b_capability("cap-1");
        registry
            .submit_durable(
                &f.journal_path,
                "op-ready",
                2_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(capability.clone()),
                },
            )
            .unwrap();
        capability.source_tree_clean = false;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "op-rejected",
                3_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(capability)
                }
            ),
            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
        ));
        let entries = read_journal_entries(&f.journal_path);
        let prefix = fs::read(&f.journal_path).unwrap();
        let payload = InventoryPayloadV1::UpsertCapability {
            record: Box::new(s2b_capability("cap-new")),
        };
        let digest = ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap();
        let pending = JournalEntryV1::Intent {
            operation_id: "op-pending".to_owned(),
            intent_digest: digest.clone(),
            recorded_unix_ms: 4_000,
            payload: payload.clone(),
        };
        let orphan = JournalEntryV1::Result {
            operation_id: "op-orphan".to_owned(),
            intent_digest: digest,
            completed_unix_ms: 4_000,
            committed: false,
            hold_reason: Some("orphan result".to_owned()),
        };
        let bad_digest = JournalEntryV1::Intent {
            operation_id: "op-bad-digest".to_owned(),
            intent_digest: "invalid digest".to_owned(),
            recorded_unix_ms: 4_000,
            payload,
        };
        let mismatched_result = JournalEntryV1::Result {
            operation_id: "op-pending".to_owned(),
            intent_digest: "mismatched result digest".to_owned(),
            completed_unix_ms: 4_000,
            committed: false,
            hold_reason: Some("invalid digest".to_owned()),
        };
        let line = |entry| ContinuousInventoryRegistryV1::journal_line(entry).unwrap();
        let duplicate_pending = [line(&pending), line(&pending)].concat();
        let nonfinal_syntax = [b"not JSON\n".to_vec(), line(&pending)].concat();
        let mismatched_result = [line(&pending), line(&mismatched_result)].concat();
        for suffix in [
            line(&entries[0]), // Duplicate committed Intent.
            line(&entries[2]), // Duplicate durably rejected Intent.
            duplicate_pending,
            line(&orphan),
            line(&bad_digest),
            mismatched_result,
            nonfinal_syntax,
        ] {
            let bytes = [prefix.clone(), suffix].concat();
            fs::write(&f.journal_path, &bytes).unwrap();
            assert!(matches!(
                ContinuousInventoryRegistryV1::load_and_reconcile(
                    f.store_id,
                    f.op_id,
                    &f.journal_path
                ),
                Err(InventoryError::JournalCorruptOrBounded(_))
            ));
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        }
    }

    #[test]
    fn s2d_negative_capability_capacity_refusal_holds_same_incarnation_across_refresh_until_newer_incarnation()
     {
        for bounded_by_records in [false, true] {
            let f = EnvFixture::new();
            let mut handle_a = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            let mut incarnation_1 = s2b_capability("cap-1");
            incarnation_1.observed_unix_ms = 100;
            let ready = InventoryPayloadV1::UpsertCapability {
                record: Box::new(incarnation_1.clone()),
            };
            handle_a
                .submit_durable(&f.journal_path, "op-ready", 100, ready.clone())
                .unwrap();
            let original_prefix = fs::read(&f.journal_path).unwrap();
            let journal_identity = handle_a.bound_journal_identity.clone();
            let mut bounded = original_prefix.clone();
            if bounded_by_records {
                let padding = InventoryPayloadV1::UpsertCapability {
                    record: Box::new(s2b_capability("cap-padding")),
                };
                let digest = ContinuousInventoryRegistryV1::payload_digest(&padding).unwrap();
                for sequence in 1..MAX_INVENTORY_RECORDS / 2 {
                    for entry in [
                        JournalEntryV1::Intent {
                            operation_id: format!("op-padding-{sequence}"),
                            intent_digest: digest.clone(),
                            recorded_unix_ms: 100,
                            payload: padding.clone(),
                        },
                        JournalEntryV1::Result {
                            operation_id: format!("op-padding-{sequence}"),
                            intent_digest: digest.clone(),
                            completed_unix_ms: 100,
                            committed: true,
                            hold_reason: None,
                        },
                    ] {
                        bounded
                            .extend(ContinuousInventoryRegistryV1::journal_line(&entry).unwrap());
                    }
                }
                assert!(bounded.len() as u64 <= MAX_INVENTORY_JOURNAL_BYTES);
                assert_eq!(
                    bounded.iter().filter(|byte| **byte == b'\n').count(),
                    MAX_INVENTORY_RECORDS
                );
            } else {
                // Legal trailing JSON whitespace fills the byte budget.
                assert_eq!(bounded.pop(), Some(b'\n'));
                bounded.resize(MAX_INVENTORY_JOURNAL_BYTES as usize - 1, b' ');
                bounded.push(b'\n');
            }
            fs::write(&f.journal_path, &bounded).unwrap();

            let mut negative = incarnation_1.clone();
            negative.source_tree_clean = false;
            negative.observed_unix_ms = 150;
            let negative = InventoryPayloadV1::UpsertCapability {
                record: Box::new(negative),
            };
            assert_eq!(
                handle_a.submit_durable(&f.journal_path, "op-neg-refused", 150, negative.clone()),
                Err(InventoryError::JournalCorruptOrBounded(
                    "inventory journal cannot reserve both Intent and Result".to_owned()
                ))
            );
            assert!(!handle_a.committed_ops.contains_key("op-neg-refused"));
            assert!(!handle_a.rejected_ops.contains_key("op-neg-refused"));
            assert!(!handle_a.incomplete_ops_held.contains_key("op-neg-refused"));
            assert!(handle_a.corrupt_or_ambiguous_tail_reason().is_none());
            let held = handle_a.capabilities["cap-1"].clone();
            assert_eq!(
                held.effective_classification,
                CapabilityClassificationV1::Held
            );
            assert_eq!(held.installed_binary_sha256, None);
            assert!(
                held.hold_or_downgrade_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("non-tail persistence refusal"))
            );
            assert_eq!(
                handle_a
                    .inspect_discovery_snapshot()
                    .capabilities
                    .iter()
                    .find(|record| record.capability_id == "cap-1"),
                Some(&held)
            );
            handle_a.refresh_from_journal(&f.journal_path).unwrap();
            assert_eq!(handle_a.capabilities["cap-1"], held);

            let mut newer = incarnation_1.clone();
            newer.observed_unix_ms = 200;
            for (operation_id, record) in [
                ("op-positive-refused", newer.clone()),
                ("op-new-refused", s2b_capability("cap-new")),
            ] {
                assert!(matches!(
                    handle_a.submit_durable(
                        &f.journal_path,
                        operation_id,
                        200,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(record)
                        }
                    ),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                assert!(!handle_a.committed_ops.contains_key(operation_id));
                assert!(!handle_a.rejected_ops.contains_key(operation_id));
                assert!(!handle_a.incomplete_ops_held.contains_key(operation_id));
                assert_eq!(handle_a.capabilities["cap-1"], held);
                assert!(!handle_a.capabilities.contains_key("cap-new"));
            }
            // Repeated refusals cannot replace the inspected journal incarnation
            // with the already-held overlay and thereby lose negative knowledge.
            assert!(matches!(
                handle_a.submit_durable(&f.journal_path, "op-neg-refused", 150, negative.clone()),
                Err(InventoryError::JournalCorruptOrBounded(_))
            ));
            handle_a.refresh_from_journal(&f.journal_path).unwrap();
            assert_eq!(handle_a.capabilities["cap-1"], held);
            assert!(
                handle_a.local_capability_holds["cap-1"]
                    .0
                    .same_capability_incarnation(&incarnation_1)
            );
            assert_eq!(fs::read(&f.journal_path).unwrap(), bounded);

            // Remove only this test's padding in place, preserving the bound inode.
            fs::write(&f.journal_path, original_prefix).unwrap();
            let mut positive_writer = handle_a.clone();
            positive_writer
                .submit_durable(&f.journal_path, "op-positive-retry", 160, ready)
                .unwrap();
            assert!(!positive_writer.local_capability_holds.contains_key("cap-1"));
            assert_eq!(
                positive_writer.capabilities["cap-1"].effective_classification,
                CapabilityClassificationV1::Operational
            );
            let mut rejected_writer = handle_a.clone();
            assert!(matches!(
                rejected_writer.submit_durable(&f.journal_path, "op-neg-refused", 170, negative),
                Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
            ));
            assert!(!rejected_writer.local_capability_holds.contains_key("cap-1"));
            assert!(rejected_writer.rejected_ops.contains_key("op-neg-refused"));

            let mut handle_b = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            handle_b
                .submit_durable(
                    &f.journal_path,
                    "op-newer-incarnation",
                    200,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(newer),
                    },
                )
                .unwrap();
            handle_a.refresh_from_journal(&f.journal_path).unwrap();
            assert_eq!(handle_a.bound_journal_identity, journal_identity);
            assert_eq!(
                handle_a.capabilities["cap-1"],
                handle_b.capabilities["cap-1"]
            );
            assert_eq!(handle_a.capabilities["cap-1"].observed_unix_ms, 200);
            assert_eq!(
                handle_a.capabilities["cap-1"].effective_classification,
                CapabilityClassificationV1::Operational
            );
            assert!(!handle_a.local_capability_holds.contains_key("cap-1"));
        }
    }

    fn s2d_workspace_incarnation(f: &EnvFixture, replacement: bool) -> WorkspaceOwnershipRecordV1 {
        let mut record = s2b_workspace(f, replacement);
        record.record_id = "ws-1".to_owned();
        if replacement {
            record.owner_actor = "WORKHORSE#22222222222222222222222222222222".to_owned();
            record.issued_unix_ms = 160;
            record.lease_expires_unix_ms = f.base_unix_ms + 5_000;
        } else {
            record.owner_actor = "WORKHORSE#11111111111111111111111111111111".to_owned();
            record.issued_unix_ms = 100;
            record.lease_expires_unix_ms = f.base_unix_ms + 200;
        }
        record
    }

    #[test]
    fn s2d_stale_reconciliation_and_local_overlay_do_not_hold_replacement_workspace_incarnation() {
        let f = EnvFixture::new();
        let incarnation_1 = s2d_workspace_incarnation(&f, false);
        let incarnation_2 = s2d_workspace_incarnation(&f, true);
        let mut handle_a = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        handle_a
            .submit_durable(
                &f.journal_path,
                "op-register-1",
                100,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(incarnation_1.clone()),
                },
            )
            .unwrap();
        let mut local_overlay = handle_a.clone();
        local_overlay
            .apply_payload(
                InventoryPayloadV1::HoldWorkspace {
                    record_id: "ws-1".to_owned(),
                    hold_reason: "local hold on incarnation 1".to_owned(),
                    updated_unix_ms: 140,
                },
                false,
            )
            .unwrap();
        let mut handle_b =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        handle_b
            .submit_durable(
                &f.journal_path,
                "op-release-1",
                150,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: "ws-1".to_owned(),
                    actor: incarnation_1.owner_actor.clone(),
                    released_unix_ms: 150,
                },
            )
            .unwrap();
        let mut released_overlay = local_overlay.clone();
        released_overlay
            .refresh_from_journal(&f.journal_path)
            .unwrap();
        assert_eq!(
            released_overlay.workspaces["ws-1"].status,
            WorkspaceOwnershipStatusV1::Released
        );
        assert_eq!(released_overlay.workspaces["ws-1"].hold_reason, None);
        handle_b
            .submit_durable(
                &f.journal_path,
                "op-register-2",
                160,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(incarnation_2.clone()),
                },
            )
            .unwrap();
        let bytes = fs::read(&f.journal_path).unwrap();

        // The expired record inspected by A predates B's release and replacement.
        assert!(
            handle_a
                .reconcile_workspaces(f.base_unix_ms + 300, |_, _| false)
                .is_empty()
        );
        assert_eq!(handle_a.workspaces["ws-1"], incarnation_2);
        local_overlay.refresh_from_journal(&f.journal_path).unwrap();
        assert_eq!(local_overlay.workspaces["ws-1"], incarnation_2);
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
    }

    #[test]
    fn s2d_mutation_guard_refreshes_bound_journal_and_rejects_released_replaced_or_ambiguous_state()
    {
        let f = EnvFixture::new();
        let incarnation_1 = s2d_workspace_incarnation(&f, false);
        let incarnation_2 = s2d_workspace_incarnation(&f, true);
        let mut handle_a = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        handle_a
            .submit_durable(
                &f.journal_path,
                "op-register-1",
                100,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(incarnation_1.clone()),
                },
            )
            .unwrap();
        let mut handle_b =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        handle_b
            .submit_durable(
                &f.journal_path,
                "op-release-1",
                150,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: "ws-1".to_owned(),
                    actor: incarnation_1.owner_actor.clone(),
                    released_unix_ms: 150,
                },
            )
            .unwrap();
        assert!(matches!(
            handle_a.verify_workspace_for_mutation(
                "ws-1",
                &incarnation_1.owner_actor,
                &incarnation_1.task_ref,
                150,
            ),
            Err(InventoryError::WorkspaceHeld(_))
        ));
        assert_eq!(
            handle_a.workspaces["ws-1"].status,
            WorkspaceOwnershipStatusV1::Released
        );

        handle_b
            .submit_durable(
                &f.journal_path,
                "op-register-2",
                160,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(incarnation_2.clone()),
                },
            )
            .unwrap();
        let bytes = fs::read(&f.journal_path).unwrap();
        assert!(matches!(
            handle_a.verify_workspace_for_mutation(
                "ws-1",
                &incarnation_1.owner_actor,
                &incarnation_1.task_ref,
                170,
            ),
            Err(InventoryError::UnresolvedOrMismatchedOwner(_))
        ));
        assert_eq!(handle_a.workspaces["ws-1"], incarnation_2);
        assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        assert_eq!(
            handle_a
                .verify_workspace_for_mutation(
                    "ws-1",
                    &incarnation_2.owner_actor,
                    &incarnation_2.task_ref,
                    175,
                )
                .unwrap(),
            &incarnation_2
        );

        let mut torn = bytes;
        torn.extend_from_slice(b"{\"record_kind\":\"intent\"");
        fs::write(&f.journal_path, &torn).unwrap();
        assert!(matches!(
            handle_a.verify_workspace_for_mutation(
                "ws-1",
                &incarnation_2.owner_actor,
                &incarnation_2.task_ref,
                180,
            ),
            Err(InventoryError::JournalCorruptOrBounded(_))
        ));
        assert!(handle_a.corrupt_or_ambiguous_tail_reason().is_some());
        assert_eq!(fs::read(&f.journal_path).unwrap(), torn);
    }

    fn bound_test_journal(path: &Path, by_records: bool) -> Vec<u8> {
        let mut bytes = fs::read(path).unwrap();
        if by_records {
            let padding = InventoryPayloadV1::UpsertCapability {
                record: Box::new(s2b_capability("cap-padding")),
            };
            let digest = ContinuousInventoryRegistryV1::payload_digest(&padding).unwrap();
            let start = bytes.iter().filter(|b| **b == b'\n').count() / 2;
            for sequence in start..MAX_INVENTORY_RECORDS / 2 {
                let op = format!("padding-{sequence}");
                for entry in [
                    JournalEntryV1::Intent {
                        operation_id: op.clone(),
                        intent_digest: digest.clone(),
                        recorded_unix_ms: 100,
                        payload: padding.clone(),
                    },
                    JournalEntryV1::Result {
                        operation_id: op,
                        intent_digest: digest.clone(),
                        completed_unix_ms: 100,
                        committed: true,
                        hold_reason: None,
                    },
                ] {
                    bytes.extend(ContinuousInventoryRegistryV1::journal_line(&entry).unwrap());
                }
            }
            assert_eq!(
                bytes.iter().filter(|b| **b == b'\n').count(),
                MAX_INVENTORY_RECORDS
            );
        } else {
            assert_eq!(bytes.pop(), Some(b'\n'));
            bytes.resize(MAX_INVENTORY_JOURNAL_BYTES as usize - 1, b' ');
            bytes.push(b'\n');
        }
        fs::write(path, &bytes).unwrap();
        bytes
    }

    #[test]
    fn s2d_f3_explicit_held_upsert_and_capacity_refusal_preserve_negative_overlay() {
        for by_records in [false, true] {
            let f = EnvFixture::new();
            let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            let ready = s2b_capability("cap-1");
            registry
                .submit_durable(
                    &f.journal_path,
                    "ready",
                    100,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(ready.clone()),
                    },
                )
                .unwrap();
            let bytes = bound_test_journal(&f.journal_path, by_records);
            let mut negative = ready.clone();
            negative.claimed_classification = CapabilityClassificationV1::Held;
            negative.hold_or_downgrade_reason = Some("explicit negative observation".to_owned());
            negative.observed_unix_ms = 200;
            let negative = InventoryPayloadV1::UpsertCapability {
                record: Box::new(negative),
            };
            for _ in 0..3 {
                assert!(matches!(
                    registry.submit_durable(
                        &f.journal_path,
                        "negative-refused",
                        200,
                        negative.clone()
                    ),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                for op in ["negative-refused", "positive-refused"] {
                    assert!(!registry.committed_ops.contains_key(op));
                    assert!(!registry.rejected_ops.contains_key(op));
                    assert!(!registry.incomplete_ops_held.contains_key(op));
                }
                let held = registry.capabilities["cap-1"].clone();
                assert_eq!(
                    held.effective_classification,
                    CapabilityClassificationV1::Held
                );
                assert_eq!(held.installed_binary_sha256, None);
                assert!(
                    held.hold_or_downgrade_reason
                        .as_deref()
                        .unwrap()
                        .contains("explicit negative observation")
                );
                for _ in 0..2 {
                    registry.refresh_from_journal(&f.journal_path).unwrap();
                    assert_eq!(registry.capabilities["cap-1"], held);
                }
                assert!(
                    registry.local_capability_holds["cap-1"]
                        .0
                        .same_capability_incarnation(&ready)
                );
                assert!(matches!(
                    registry.submit_durable(
                        &f.journal_path,
                        "positive-refused",
                        300,
                        InventoryPayloadV1::UpsertCapability {
                            record: Box::new(ready.clone())
                        }
                    ),
                    Err(InventoryError::JournalCorruptOrBounded(_))
                ));
                assert_eq!(
                    registry
                        .inspect_discovery_snapshot()
                        .capabilities
                        .into_iter()
                        .find(|cap| cap.capability_id == "cap-1"),
                    Some(held)
                );
                assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
            }
        }
        // Serialization and line-bound refusals occur before capacity reservation.
        for failure in 0..3 {
            let f = EnvFixture::new();
            let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            let ready = s2b_capability("cap-1");
            registry
                .submit_durable(
                    &f.journal_path,
                    "ready",
                    100,
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(ready.clone()),
                    },
                )
                .unwrap();
            let bytes = fs::read(&f.journal_path).unwrap();
            let mut negative = ready;
            negative.claimed_classification = CapabilityClassificationV1::Held;
            let payload = match failure {
                0 => {
                    negative
                        .task_ref
                        .as_mut()
                        .unwrap()
                        .canonical_task_path
                        .clear();
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(negative),
                    }
                }
                1 => {
                    negative.source_tree_clean = false;
                    negative.claimed_classification = CapabilityClassificationV1::Operational;
                    negative.source_module_path = "p".repeat(MAX_INVENTORY_JOURNAL_BYTES as usize);
                    InventoryPayloadV1::UpsertCapability {
                        record: Box::new(negative),
                    }
                }
                _ => InventoryPayloadV1::HoldCapability {
                    capability_id: "cap-1".to_owned(),
                    hold_reason: "x".repeat(MAX_INVENTORY_JOURNAL_BYTES as usize),
                    updated_unix_ms: 200,
                },
            };
            assert!(
                registry
                    .submit_durable(&f.journal_path, "serialization-refused", 200, payload)
                    .is_err()
            );
            assert_eq!(
                registry.capabilities["cap-1"].effective_classification,
                CapabilityClassificationV1::Held
            );
            assert_eq!(registry.capabilities["cap-1"].installed_binary_sha256, None);
            registry.refresh_from_journal(&f.journal_path).unwrap();
            assert_eq!(
                registry.capabilities["cap-1"].effective_classification,
                CapabilityClassificationV1::Held
            );
            assert!(!registry.committed_ops.contains_key("serialization-refused"));
            assert!(!registry.rejected_ops.contains_key("serialization-refused"));
            assert!(
                !registry
                    .incomplete_ops_held
                    .contains_key("serialization-refused")
            );
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
        }
    }

    #[test]
    fn s2d_f7_pid_binding_and_aba_replacement_error_fallbacks_and_ambiguity_overlay_fence() {
        for change_pid in [false, true] {
            let f = EnvFixture::new();
            let record = s2b_workspace(&f, false);
            let mut a = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            a.submit_durable(
                &f.journal_path,
                "register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(record.clone()),
                },
            )
            .unwrap();
            let old_seq = a.workspace_registration_seq[&record.record_id];
            let mut local = a.clone();
            local
                .apply_local_workspace_hold(
                    &record,
                    Some(old_seq),
                    InventoryPayloadV1::HoldWorkspace {
                        record_id: record.record_id.clone(),
                        hold_reason: "old local hold".to_owned(),
                        updated_unix_ms: 2_001,
                    },
                )
                .unwrap();
            let mut b = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            b.submit_durable(
                &f.journal_path,
                "release",
                2_002,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: record.record_id.clone(),
                    actor: record.owner_actor.clone(),
                    released_unix_ms: 2_002,
                },
            )
            .unwrap();
            let mut replacement = record.clone();
            let mut child = Command::new("/bin/sleep").arg("10").spawn().unwrap();
            if change_pid {
                let chinwag_host_process::ProcessBirthObservation::Alive(info) =
                    chinwag_host_process::inspect_process_birth(child.id()).unwrap()
                else {
                    panic!("live child");
                };
                replacement.pid_birth_binding = Some((info.pid, info.start_time_unix_us));
                assert!(!replacement.same_ownership_incarnation(&record));
            }
            b.submit_durable(
                &f.journal_path,
                "replacement",
                2_003,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(replacement.clone()),
                },
            )
            .unwrap();
            let bytes = fs::read(&f.journal_path).unwrap();
            assert!(
                a.reconcile_workspaces(f.base_unix_ms, |_, _| false)
                    .is_empty()
            );
            assert_eq!(a.workspaces[&record.record_id], replacement);
            assert_ne!(a.workspace_registration_seq[&record.record_id], old_seq);
            local.refresh_from_journal(&f.journal_path).unwrap();
            assert_eq!(local.workspaces[&record.record_id], replacement);
            assert!(!local.local_workspace_holds.contains_key(&record.record_id));
            assert_eq!(fs::read(&f.journal_path).unwrap(), bytes);
            child.kill().unwrap();
            child.wait().unwrap();
        }
        for lock_open_failure in [false, true] {
            let f = EnvFixture::new();
            let r1 = s2b_workspace(&f, false);
            let r2 = s2b_workspace(&f, true);
            let mut a = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            for (op, record) in [("register-1", &r1), ("register-2", &r2)] {
                a.submit_durable(
                    &f.journal_path,
                    op,
                    2_000,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(record.clone()),
                    },
                )
                .unwrap();
            }
            let seq1 = a.workspace_registration_seq[&r1.record_id];
            let seq2 = a.workspace_registration_seq[&r2.record_id];
            let mut b = a.clone();
            b.submit_durable(
                &f.journal_path,
                "release-2",
                2_100,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: r2.record_id.clone(),
                    actor: r2.owner_actor.clone(),
                    released_unix_ms: 2_100,
                },
            )
            .unwrap();
            // Dispatch the two stale observations in reconciliation order. R1's
            // refresh observes R2's release before R2's persistence path fails.
            assert!(
                a.hold_workspace(&r1, Some(seq1), "R1 stale".to_owned(), 2_200)
                    .unwrap()
            );
            assert_eq!(
                a.workspaces[&r2.record_id].status,
                WorkspaceOwnershipStatusV1::Released
            );
            if lock_open_failure {
                fs::set_permissions(&f.journal_path, fs::Permissions::from_mode(0o400)).unwrap();
            } else {
                let mut bytes = fs::read(&f.journal_path).unwrap();
                bytes.splice(0..0, b"{}\n".iter().copied());
                fs::write(&f.journal_path, bytes).unwrap();
            }
            assert!(
                a.hold_workspace(&r2, Some(seq2), "R2 stale".to_owned(), 2_201)
                    .is_err()
            );
            assert_eq!(
                a.workspaces[&r2.record_id].status,
                WorkspaceOwnershipStatusV1::Released
            );
            assert!(!a.local_workspace_holds.contains_key(&r2.record_id));
        }
        for replace in [false, true] {
            let f = EnvFixture::new();
            let record = s2b_workspace(&f, false);
            let mut a = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
            a.submit_durable(
                &f.journal_path,
                "register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(record.clone()),
                },
            )
            .unwrap();
            a.submit_durable(
                &f.journal_path,
                "ready",
                2_000,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(s2b_capability("cap-1")),
                },
            )
            .unwrap();
            let prefix = fs::read(&f.journal_path).unwrap();
            a.fail_next_result_append = true;
            assert!(
                a.hold_workspace(
                    &record,
                    Some(a.workspace_registration_seq[&record.record_id]),
                    "ambiguous hold".to_owned(),
                    2_100
                )
                .is_err()
            );
            a.hold_incomplete(
                "local-cap-hold".to_owned(),
                "digest".to_owned(),
                InventoryPayloadV1::HoldCapability {
                    capability_id: "cap-1".to_owned(),
                    hold_reason: "ambiguous negative".to_owned(),
                    updated_unix_ms: 2_100,
                },
            );
            assert!(a.corrupt_or_ambiguous_tail_reason().is_some());
            // The valid journal retains the incomplete hold intent. A later
            // durable release/re-registration supersedes that old observation.
            assert!(fs::read(&f.journal_path).unwrap().starts_with(&prefix));
            let mut b = ContinuousInventoryRegistryV1::load_and_reconcile(
                f.store_id,
                f.op_id,
                &f.journal_path,
            )
            .unwrap();
            b.submit_durable(
                &f.journal_path,
                "release",
                2_200,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: record.record_id.clone(),
                    actor: record.owner_actor.clone(),
                    released_unix_ms: 2_200,
                },
            )
            .unwrap();
            if replace {
                b.submit_durable(
                    &f.journal_path,
                    "replacement",
                    2_300,
                    InventoryPayloadV1::RegisterWorkspace {
                        record: Box::new(record.clone()),
                    },
                )
                .unwrap();
            }
            let mut newer = s2b_capability("cap-1");
            newer.observed_unix_ms = 2_300;
            b.submit_durable(
                &f.journal_path,
                "newer-capability",
                2_300,
                InventoryPayloadV1::UpsertCapability {
                    record: Box::new(newer),
                },
            )
            .unwrap();
            a.refresh_from_journal(&f.journal_path).unwrap();
            assert!(a.corrupt_or_ambiguous_tail_reason().is_some());
            assert_eq!(
                a.workspaces[&record.record_id],
                b.workspaces[&record.record_id]
            );
            assert_eq!(a.capabilities["cap-1"], b.capabilities["cap-1"]);
            assert!(!a.local_workspace_holds.contains_key(&record.record_id));
            assert!(!a.local_capability_holds.contains_key("cap-1"));
        }
    }

    #[test]
    fn s2e_live_jj_admission_and_mutation_reject_wrong_store_name_change_commit_and_symlink() {
        for mutation in [false, true] {
            for failure in 0..10 {
                let f = EnvFixture::new();
                let mut record = s2b_workspace(&f, false);
                let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                if mutation {
                    registry
                        .submit_durable(
                            &f.journal_path,
                            "register",
                            2_000,
                            InventoryPayloadV1::RegisterWorkspace {
                                record: Box::new(record.clone()),
                            },
                        )
                        .unwrap();
                }
                match failure {
                    0 => {
                        fs::write(f.ws1_dir.join("dirty-source.rs"), "uncommitted source\n")
                            .unwrap();
                    }
                    1 => {
                        let other = EnvFixture::new();
                        fs::write(
                            f.ws1_dir.join(".jj/repo"),
                            other.store_dir.join(".jj/repo").to_str().unwrap(),
                        )
                        .unwrap();
                        // Keep the foreign store alive until after observation.
                        let result = if mutation {
                            registry
                                .verify_workspace_for_mutation(
                                    &record.record_id,
                                    &record.owner_actor,
                                    &record.task_ref,
                                    f.base_unix_ms,
                                )
                                .map(|_| ())
                        } else {
                            registry
                                .submit_durable(
                                    &f.journal_path,
                                    "wrong-store",
                                    2_000,
                                    InventoryPayloadV1::RegisterWorkspace {
                                        record: Box::new(record.clone()),
                                    },
                                )
                                .map(|_| ())
                        };
                        assert!(matches!(
                            result,
                            Err(InventoryError::SharedGitStoreMismatch(_))
                        ));
                        continue;
                    }
                    2 => {
                        if mutation {
                            test_jj(&f.ws1_dir, &["workspace", "rename", "wrong-name"]);
                        } else {
                            record.workspace_name = "wrong-name".to_owned();
                        }
                    }
                    3 => {
                        if mutation {
                            test_jj(&f.ws1_dir, &["new", "-m", "different change"]);
                        } else {
                            record.jj_working_copy_change_id = f.ws2_change_id.clone();
                        }
                    }
                    4 => {
                        if mutation {
                            test_jj(&f.ws1_dir, &["describe", "-m", "different commit"]);
                        } else {
                            record.jj_working_copy_commit_id = f.ws2_commit_id;
                        }
                    }
                    5 => {
                        let real = f._tmp.path().join("real-workspace");
                        fs::rename(&f.ws1_dir, &real).unwrap();
                        symlink(real, &f.ws1_dir).unwrap();
                    }
                    6 => {
                        let real = f.ws1_dir.join("jj-real");
                        fs::rename(f.ws1_dir.join(".jj"), &real).unwrap();
                        symlink(real, f.ws1_dir.join(".jj")).unwrap();
                    }
                    7 => {
                        fs::remove_file(f.ws1_dir.join(".jj/repo")).unwrap();
                        symlink(f.store_dir.join(".jj/repo"), f.ws1_dir.join(".jj/repo")).unwrap();
                    }
                    8 => {
                        fs::remove_dir_all(f.ws1_dir.join(".jj")).unwrap();
                    }
                    _ => {
                        fs::remove_file(f.ws1_dir.join(".jj/repo")).unwrap();
                    }
                }
                let result = if mutation {
                    registry
                        .verify_workspace_for_mutation(
                            &record.record_id,
                            &record.owner_actor,
                            &record.task_ref,
                            f.base_unix_ms,
                        )
                        .map(|_| ())
                } else {
                    registry
                        .submit_durable(
                            &f.journal_path,
                            "admission",
                            2_000,
                            InventoryPayloadV1::RegisterWorkspace {
                                record: Box::new(record.clone()),
                            },
                        )
                        .map(|_| ())
                };
                if failure == 0 {
                    result.unwrap();
                    let mut dirty_cap = s2b_capability("dirty-capability");
                    dirty_cap.source_tree_clean = false;
                    for claim in [
                        CapabilityClassificationV1::Installed,
                        CapabilityClassificationV1::Operational,
                    ] {
                        dirty_cap.claimed_classification = claim;
                        assert!(matches!(
                            dirty_cap.verify_and_classify(),
                            Err(InventoryError::DirtyOrMismatchedBuildProvenance(_))
                        ));
                    }
                } else {
                    assert!(result.is_err(), "mutation={mutation} failure={failure}");
                    if mutation {
                        assert_eq!(
                            registry.workspaces[&record.record_id].status,
                            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
                        );
                        assert_eq!(
                            registry.workspaces[&record.record_id].pid_birth_binding,
                            None
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn s2e_real_pid_birth_and_clock_startup_and_preuse_reconciliation() {
        let (pid, birth_us) = observe_current_process_birth_binding().unwrap();
        assert_eq!(pid, std::process::id());
        assert_eq!(check_pid_birth_binding_live(pid, birth_us), Ok(true));
        assert_eq!(
            check_pid_birth_binding_live(pid, birth_us + 1_000),
            Ok(false)
        );
        assert!(check_pid_birth_binding_live(0, birth_us).is_err());
        assert!(current_unix_ms().unwrap() > 1_000);
        for preuse in [false, true] {
            for failure in 0..4 {
                let f = EnvFixture::new();
                let mut record = s2b_workspace(&f, false);
                let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
                if failure == 1 {
                    let mut child = Command::new("/bin/sleep").arg("0.2").spawn().unwrap();
                    let chinwag_host_process::ProcessBirthObservation::Alive(info) =
                        chinwag_host_process::inspect_process_birth(child.id()).unwrap()
                    else {
                        panic!("live child");
                    };
                    record.pid_birth_binding = Some((info.pid, info.start_time_unix_us));
                    registry
                        .submit_durable(
                            &f.journal_path,
                            "register",
                            2_000,
                            InventoryPayloadV1::RegisterWorkspace {
                                record: Box::new(record.clone()),
                            },
                        )
                        .unwrap();
                    child.wait().unwrap();
                    assert_eq!(
                        check_pid_birth_binding_live(info.pid, info.start_time_unix_us),
                        Ok(false)
                    );
                } else {
                    if failure == 2 {
                        record.pid_birth_binding = Some((pid, birth_us + 1_000));
                    }
                    if failure == 3 {
                        record.lease_expires_unix_ms = f.base_unix_ms;
                    }
                    if failure == 2 {
                        assert!(matches!(
                            registry.submit_durable(
                                &f.journal_path,
                                "invalid-live-admission",
                                2_000,
                                InventoryPayloadV1::RegisterWorkspace {
                                    record: Box::new(record.clone())
                                }
                            ),
                            Err(InventoryError::WorkspaceHeld(_))
                        ));
                        // A historical journal can contain an owner that is no
                        // longer alive. Replay remains pure and deterministic.
                        let payload = InventoryPayloadV1::RegisterWorkspace {
                            record: Box::new(record.clone()),
                        };
                        let digest =
                            ContinuousInventoryRegistryV1::payload_digest(&payload).unwrap();
                        for entry in [
                            JournalEntryV1::Intent {
                                operation_id: "historical-register".to_owned(),
                                intent_digest: digest.clone(),
                                recorded_unix_ms: 2_000,
                                payload,
                            },
                            JournalEntryV1::Result {
                                operation_id: "historical-register".to_owned(),
                                intent_digest: digest,
                                completed_unix_ms: 2_000,
                                committed: true,
                                hold_reason: None,
                            },
                        ] {
                            ContinuousInventoryRegistryV1::append_journal_entry(
                                &f.journal_path,
                                &entry,
                            )
                            .unwrap();
                        }
                        registry.refresh_from_journal(&f.journal_path).unwrap();
                    } else {
                        registry
                            .submit_durable(
                                &f.journal_path,
                                "register",
                                2_000,
                                InventoryPayloadV1::RegisterWorkspace {
                                    record: Box::new(record.clone()),
                                },
                            )
                            .unwrap();
                    }
                }
                if preuse {
                    let result = registry.verify_workspace_for_mutation(
                        &record.record_id,
                        &record.owner_actor,
                        &record.task_ref,
                        current_unix_ms().unwrap(),
                    );
                    assert_eq!(result.is_ok(), failure == 0);
                    if failure != 0 {
                        assert!(matches!(result, Err(InventoryError::WorkspaceHeld(_))));
                    }
                } else {
                    registry = ContinuousInventoryRegistryV1::load_and_reconcile(
                        f.store_id,
                        f.op_id,
                        &f.journal_path,
                    )
                    .unwrap();
                }
                let actual = &registry.workspaces[&record.record_id];
                assert_eq!(
                    actual.status,
                    if failure == 0 {
                        WorkspaceOwnershipStatusV1::Active
                    } else {
                        WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
                    }
                );
                if failure != 0 {
                    assert_eq!(actual.pid_birth_binding, None);
                    assert!(actual.status.blocks_exclusive_claim());
                    assert_eq!(registry.inspect_discovery_snapshot().workspaces.len(), 1);
                    assert!(registry.reconcile_workspaces_live().unwrap().is_empty());
                }
            }
        }
    }

    fn checkpoint_payload(
        record: &WorkspaceOwnershipRecordV1,
        new_commit: GitOid,
        now: u64,
    ) -> InventoryPayloadV1 {
        InventoryPayloadV1::AdvanceWorkspaceCheckpoint {
            record_id: record.record_id.clone(),
            actor: record.owner_actor.clone(),
            task_ref: record.task_ref.clone(),
            expected_jj_working_copy_change_id: record.jj_working_copy_change_id.clone(),
            expected_old_jj_working_copy_commit_id: record.jj_working_copy_commit_id,
            new_jj_working_copy_commit_id: new_commit,
            updated_unix_ms: now,
        }
    }

    #[test]
    fn s2e_durable_checkpoint_advance_cas_updates_same_change_and_rejects_stale_or_different_change()
     {
        let f = EnvFixture::new();
        let original = s2b_workspace(&f, false);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(original.clone()),
                },
            )
            .unwrap();
        test_jj(&f.ws1_dir, &["describe", "-m", "checkpoint 1"]);
        let (change, new_commit) = jj_checkpoint(&f.ws1_dir);
        assert_eq!(change, original.jj_working_copy_change_id);
        assert_ne!(new_commit, original.jj_working_copy_commit_id);
        registry
            .submit_durable(
                &f.journal_path,
                "advance",
                f.base_unix_ms,
                checkpoint_payload(&original, new_commit, f.base_unix_ms),
            )
            .unwrap();
        registry
            .verify_workspace_for_mutation(
                &original.record_id,
                &original.owner_actor,
                &original.task_ref,
                f.base_unix_ms,
            )
            .unwrap();
        let advanced = registry.workspaces[&original.record_id].clone();
        assert_eq!(advanced.jj_working_copy_commit_id, new_commit);
        assert_eq!(advanced.base_commit_id, original.base_commit_id);
        assert_eq!(advanced.base_tree_id, original.base_tree_id);
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(loaded.workspaces[&original.record_id], advanced);
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "stale-cas",
                f.base_unix_ms,
                checkpoint_payload(&original, new_commit, f.base_unix_ms)
            ),
            Err(InventoryError::WorkspaceIdentityDrift(_))
        ));
        let mut wrong_actor = advanced.clone();
        wrong_actor.owner_actor = "RUST#00000000000000000000000000000000".to_owned();
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "wrong-actor",
                f.base_unix_ms,
                checkpoint_payload(&wrong_actor, new_commit, f.base_unix_ms)
            ),
            Err(InventoryError::UnresolvedOrMismatchedOwner(_))
        ));
        let mut wrong_task = advanced.clone();
        wrong_task.task_ref = sample_task_ref("OTHER-TASK");
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "wrong-task",
                f.base_unix_ms,
                checkpoint_payload(&wrong_task, new_commit, f.base_unix_ms)
            ),
            Err(InventoryError::UnresolvedOrMismatchedOwner(_))
        ));
        for (op, now) in [
            ("before-lease", advanced.issued_unix_ms - 1),
            ("after-lease", advanced.lease_expires_unix_ms),
        ] {
            assert!(matches!(
                registry.submit_durable(
                    &f.journal_path,
                    op,
                    f.base_unix_ms,
                    checkpoint_payload(&advanced, new_commit, now)
                ),
                Err(InventoryError::WorkspaceHeld(_))
            ));
        }
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "base-commit",
                f.base_unix_ms,
                checkpoint_payload(&advanced, advanced.base_commit_id, f.base_unix_ms)
            ),
            Err(InventoryError::SharedMutableJjChange(_))
        ));
        registry
            .submit_durable(
                &f.journal_path,
                "release",
                f.base_unix_ms,
                InventoryPayloadV1::ReleaseWorkspace {
                    record_id: advanced.record_id.clone(),
                    actor: advanced.owner_actor.clone(),
                    released_unix_ms: f.base_unix_ms,
                },
            )
            .unwrap();
        let mut replacement = advanced.clone();
        replacement.owner_actor = wrong_actor.owner_actor;
        registry
            .submit_durable(
                &f.journal_path,
                "replacement",
                f.base_unix_ms,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(replacement.clone()),
                },
            )
            .unwrap();
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "stale-incarnation",
                f.base_unix_ms,
                checkpoint_payload(&advanced, new_commit, f.base_unix_ms)
            ),
            Err(InventoryError::UnresolvedOrMismatchedOwner(_))
        ));
        test_jj(&f.ws1_dir, &["new", "-m", "different mutable change"]);
        let (different_change, different_commit) = jj_checkpoint(&f.ws1_dir);
        assert_ne!(different_change, replacement.jj_working_copy_change_id);
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "switch-live-change",
                f.base_unix_ms,
                checkpoint_payload(&replacement, different_commit, f.base_unix_ms)
            ),
            Err(InventoryError::WorkspaceIdentityDrift(_))
        ));
        let mut switched = replacement.clone();
        switched.jj_working_copy_change_id = different_change;
        assert!(matches!(
            registry.submit_durable(
                &f.journal_path,
                "switch-expected-change",
                f.base_unix_ms,
                checkpoint_payload(&switched, different_commit, f.base_unix_ms)
            ),
            Err(InventoryError::SharedMutableJjChange(_))
        ));
        assert!(matches!(
            registry.verify_workspace_for_mutation(
                &replacement.record_id,
                &replacement.owner_actor,
                &replacement.task_ref,
                f.base_unix_ms
            ),
            Err(InventoryError::WorkspaceIdentityDrift(_))
        ));
        assert_eq!(
            registry.workspaces[&replacement.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );

        // An incomplete checkpoint event holds its owner on crash recovery.
        let f = EnvFixture::new();
        let record = s2b_workspace(&f, false);
        let mut registry = ContinuousInventoryRegistryV1::new(f.store_id, f.op_id).unwrap();
        registry
            .submit_durable(
                &f.journal_path,
                "register",
                2_000,
                InventoryPayloadV1::RegisterWorkspace {
                    record: Box::new(record.clone()),
                },
            )
            .unwrap();
        test_jj(&f.ws1_dir, &["describe", "-m", "incomplete checkpoint"]);
        let (_, new_commit) = jj_checkpoint(&f.ws1_dir);
        let payload = checkpoint_payload(&record, new_commit, f.base_unix_ms);
        registry.fail_next_result_append = true;
        assert!(
            registry
                .submit_durable(&f.journal_path, "crashed-advance", f.base_unix_ms, payload)
                .is_err()
        );
        let loaded =
            ContinuousInventoryRegistryV1::load_and_reconcile(f.store_id, f.op_id, &f.journal_path)
                .unwrap();
        assert_eq!(
            loaded.workspaces[&record.record_id].status,
            WorkspaceOwnershipStatusV1::HeldStaleOrUnknown
        );
        assert_eq!(loaded.workspaces[&record.record_id].pid_birth_binding, None);
        assert!(loaded.incomplete_ops_held.contains_key("crashed-advance"));
    }

    #[test]
    fn canonical_task_document_v1_parses_registered_chwg_jj_workspace_registry_01_task_ref() {
        let markdown = concat!(
            "# Tasks\n\n",
            "<!-- chinwag-task-source-meta-v1 {\"workspace_id\":\"chinwag\",\"repo_id\":\"emunlabs/chinwag\",\"task_source_id\":\"05a1b2c3d4e54f608192a3b4c5d6e806\",\"source_generation\":1,\"file_cas_rev\":1,\"last_operation_id\":\"05a1b2c3d4e54f608192a3b4c5d6e806\"} -->\n",
            "### `[NEXT]` CHWG-JJ-WORKSPACE-REGISTRY-01 — Enforce isolated JJ workspaces and maintain canonical live ownership and capability inventories\n",
            "<!-- chinwag-task-begin-v1 task_id=\"CHWG-JJ-WORKSPACE-REGISTRY-01\" -->\n",
            "- [ ] **CHWG-JJ-WORKSPACE-REGISTRY-01** (`in-progress`) — Enforce isolated JJ workspaces and maintain canonical live ownership and capability inventories\n",
            "<!-- chinwag-task-entry-v1 {\"task_id\":\"CHWG-JJ-WORKSPACE-REGISTRY-01\",\"status\":\"in-progress\",\"task_status_rev\":1,\"task_spec_digest\":\"d220229601d9a92042ff570206905bcb8faf3049d45251b145993dedb3fdd2f4\",\"task_control_digest\":\"d7432f6df63ec14682feafa27e6d02bea1d0076d74e58c0242b1965286ff1ed7\",\"completion_policy_digest\":\"9324dbba9729965789cd1e148903dfb35d17cbe749defd27751b7f9f01988af3\",\"owner_actor\":\"RUST#efffddad3cb4321cb1308b089f76c206\",\"reviewer_role\":\"ARCHITECT\",\"baseline_commit\":\"d326c7129979ca43499547842daac076d80fac35\",\"candidate_commit\":null,\"overlay_digest\":null,\"execution_flags\":[\"priority:next\",\"slice:s1-admitted\"],\"dependencies\":[]} -->\n",
            "<!-- chinwag-task-end-v1 task_id=\"CHWG-JJ-WORKSPACE-REGISTRY-01\" -->\n",
        );
        let doc = CanonicalTaskDocumentV1::from_bytes(markdown.as_bytes()).unwrap();
        assert_eq!(doc.tasks.len(), 1);
        let task_ref = doc.task_ref(&doc.tasks[0], "TASKS.md");
        let encoded = task_ref.encode().unwrap();
        let digest_hex = format!("{:x}", Sha256::digest(&encoded));
        assert_eq!(
            digest_hex,
            "e880883b5510f0981cb05cc9a9db0f58697a54a373e921f2ec6a120c2638a104"
        );
    }
}
