//! Bounded public installation metadata. No application, CLI, shell or model runs.
//! Paths and fingerprints are host-local observations, never launch permission.

use crate::catalogue::{CLI_NAMES, InstallationMatch, app_family, cli_family};
use crate::{
    ClientCandidate, ClientFamily, Coverage, HostObservation, InventorySnapshot, ProcessBirth,
    ProcessRole,
};
use rustix::fs::{Mode, OFlags, open, openat, readlinkat_raw};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::{Cursor, Read},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

pub const INSTALLATION_CAPACITY: usize = 128;
pub const APP_ENTRY_CAPACITY: usize = 2048;
pub const APP_CAPACITY_PER_DIRECTORY: usize = 256;
pub const MAX_PLIST_BYTES: usize = 131_072;
pub const MAX_APPLICATION_ALIASES: usize = 2 * APP_CAPACITY_PER_DIRECTORY;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReobserveError {
    #[error("exact application reobservation is supported only on macOS")]
    UnsupportedPlatform,
    #[error("current user's fixed public application scope is unavailable")]
    ScopeUnavailable,
    #[error("observation is not a supported public-bundle native application")]
    UnsupportedInstallation,
    #[error(
        "application or alias is outside the bounded public application scope or uses an unsafe path"
    )]
    UnsafeTarget,
    #[error("selected application public metadata is unavailable")]
    Unavailable,
    #[error("selected application public plist exceeds the byte bound")]
    MetadataTooLarge,
    #[error("selected application, alias or public metadata changed; refresh the inventory")]
    Changed,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InstalledError {
    #[error("installed client discovery is supported only on macOS")]
    UnsupportedPlatform,
    #[error("current user's public application directory is unavailable")]
    HomeUnavailable,
    #[error("system clock precedes the Unix epoch")]
    Clock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationKind {
    Application,
    CommandLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableFormat {
    MachO,
    Script,
    Other,
}

/// Public stat metadata only; not a code signature or immutable executable hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableMetadata {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub mode: u32,
    pub format: ExecutableFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installation {
    /// SHA256 host-local observation identity; never a bearer grant or vendor ID.
    pub id: String,
    pub family: ClientFamily,
    pub kind: InstallationKind,
    pub match_basis: InstallationMatch,
    pub canonical_path: PathBuf,
    pub observed_paths: Vec<PathBuf>,
    pub display_name: String,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub executable_path: PathBuf,
    pub executable: ExecutableMetadata,
    /// Fingerprints bounded public plist bytes + paths/stat metadata, not code.
    pub metadata_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryStatus {
    Read,
    Missing,
    Unavailable,
    Unsafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryCoverage {
    pub path: PathBuf,
    pub status: DirectoryStatus,
    pub entries_examined: usize,
    pub app_candidates_examined: usize,
    pub entry_cap_reached: bool,
    pub app_cap_reached: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledCoverage {
    pub application_directories: Vec<DirectoryCoverage>,
    pub cli_directories: Vec<PathBuf>,
    pub cli_paths_checked: usize,
    pub missing_cli_paths: usize,
    pub unavailable_paths: usize,
    pub unsafe_paths: usize,
    pub invalid_metadata: usize,
    pub oversized_plists: usize,
    pub changed_during_read: usize,
    pub unrecognized_applications: usize,
    pub installation_capacity: usize,
    pub installation_cap_reached: bool,
    pub omitted_installations: usize,
    pub aliases_merged: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledSnapshot {
    pub observed_at_unix_ms: u64,
    pub installations: Vec<Installation>,
    pub coverage: InstalledCoverage,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstalledRunningState {
    ObservedRunning,
    ComponentsObserved,
    /// No matching process was observed. This does not prove safe-to-launch/asleep.
    NotObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledWithRunning {
    pub installation: Installation,
    pub running_state: InstalledRunningState,
    pub observed_instances: Vec<ProcessBirth>,
    pub observed_component_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedInventory {
    pub host: HostObservation,
    pub process_observed_at_unix_ms: u64,
    pub installed_observed_at_unix_ms: u64,
    pub process_coverage: Coverage,
    pub installed_coverage: InstalledCoverage,
    pub installations: Vec<InstalledWithRunning>,
    pub unmatched_running: Vec<ClientCandidate>,
}

/// Pure exact-path association. No filesystem lookups, family-only merges,
/// admission claims, or inference of absence from a bounded process sample.
pub fn merge_installed(
    process: &InventorySnapshot,
    installed: &InstalledSnapshot,
) -> MergedInventory {
    let mut matched = vec![false; process.candidates.len()];
    let installations = installed
        .installations
        .iter()
        .map(|installation| {
            let mut roots = Vec::new();
            let mut components = 0;
            for (index, candidate) in process.candidates.iter().enumerate() {
                let matches = match installation.kind {
                    InstallationKind::Application => {
                        candidate.outer_application.as_deref().is_some_and(|path| {
                            Path::new(path) == installation.canonical_path
                                || installation
                                    .observed_paths
                                    .iter()
                                    .any(|alias| alias == Path::new(path))
                        })
                    }
                    InstallationKind::CommandLine => {
                        candidate.role == ProcessRole::CommandLine
                            && (Path::new(&candidate.executable) == installation.executable_path
                                || installation
                                    .observed_paths
                                    .iter()
                                    .any(|alias| alias == Path::new(&candidate.executable)))
                    }
                };
                if !matches {
                    continue;
                }
                matched[index] = true;
                components += 1;
                if candidate.role != ProcessRole::BundledComponent
                    && candidate.instance_root == Some(candidate.birth)
                {
                    roots.push(candidate.birth);
                }
            }
            roots.sort_by_key(|birth| (birth.pid, birth.start_seconds, birth.start_microseconds));
            roots.dedup();
            let running_state = if !roots.is_empty() {
                InstalledRunningState::ObservedRunning
            } else if components > 0 {
                InstalledRunningState::ComponentsObserved
            } else {
                InstalledRunningState::NotObserved
            };
            InstalledWithRunning {
                installation: installation.clone(),
                running_state,
                observed_instances: roots,
                observed_component_count: components,
            }
        })
        .collect();
    MergedInventory {
        host: process.host.clone(),
        process_observed_at_unix_ms: process.observed_at_unix_ms,
        installed_observed_at_unix_ms: installed.observed_at_unix_ms,
        process_coverage: process.coverage.clone(),
        installed_coverage: installed.coverage.clone(),
        installations,
        unmatched_running: process
            .candidates
            .iter()
            .enumerate()
            .filter(|(index, _)| !matched[*index])
            .map(|(_, candidate)| candidate.clone())
            .collect(),
    }
}

/// Explicit public scope only. HOME/PATH, shell resolution and candidate execution
/// are not used. Home comes from the current UID's system account metadata.
pub fn installed_snapshot() -> Result<InstalledSnapshot, InstalledError> {
    #[cfg(target_os = "macos")]
    {
        let home = current_home()?;
        collect(&Scope::new(home))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(InstalledError::UnsupportedPlatform)
    }
}

/// Rechecks one previously observed exact application in the current user's
/// fixed public scope. This does not enumerate applications/processes, launch,
/// establish asleep/connected state, authenticate a vendor, or grant permission.
/// The caller must keep the host/boot binding and monotonic observation time.
/// Public metadata remains mutable after this bounded filesystem observation.
pub fn reobserve_application(previous: &Installation) -> Result<Installation, ReobserveError> {
    #[cfg(target_os = "macos")]
    {
        let home = current_home().map_err(|_| ReobserveError::ScopeUnavailable)?;
        reobserve_in_scope(previous, &Scope::new(home))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = previous;
        Err(ReobserveError::UnsupportedPlatform)
    }
}

fn direct_application_path(path: &Path, scope: &Scope) -> bool {
    path.is_absolute()
        && path.as_os_str().as_bytes().len() <= 4096
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && scope
            .apps
            .iter()
            .any(|root| path.parent() == Some(root.as_path()))
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.len() <= 256
                    && name.ends_with(".app")
                    && name.len() > 4
                    && !name.chars().any(char::is_control)
            })
}

fn reobserve_in_scope(
    previous: &Installation,
    scope: &Scope,
) -> Result<Installation, ReobserveError> {
    let binary = previous
        .executable_path
        .file_name()
        .and_then(|name| name.to_str());
    if previous.kind != InstallationKind::Application
        || previous.match_basis != InstallationMatch::PublicBundleIdentity
        || previous.executable.format != ExecutableFormat::MachO
        || previous.executable.mode & 0o111 == 0
        || binary.is_none_or(|name| !plain_component(name))
        || previous
            .bundle_id
            .as_deref()
            .zip(binary)
            .and_then(|(bundle, binary)| app_family(&previous.display_name, bundle, binary))
            != Some((previous.family, InstallationMatch::PublicBundleIdentity))
    {
        return Err(ReobserveError::UnsupportedInstallation);
    }
    // Validate every caller-carried path before stat/canonicalize/file contents.
    if !direct_application_path(&previous.canonical_path, scope)
        || previous.executable_path
            != previous
                .canonical_path
                .join("Contents/MacOS")
                .join(binary.unwrap_or_default())
        || previous.observed_paths.is_empty()
        || previous.observed_paths.len() > MAX_APPLICATION_ALIASES
        || previous
            .observed_paths
            .iter()
            .any(|path| !direct_application_path(path, scope))
        || previous
            .observed_paths
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != previous.observed_paths.len()
        || [&previous.id, &previous.metadata_fingerprint]
            .iter()
            .any(|value| value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(ReobserveError::UnsafeTarget);
    }
    // read_application never canonicalizes the selected target. In particular a
    // new symlink at that exact name is rejected rather than followed elsewhere.
    let mut fresh = read_application(&previous.canonical_path, scope)
        .map_err(reobserve_failure)?
        .ok_or(ReobserveError::Changed)?;
    for alias in &previous.observed_paths {
        verify_alias(alias, &previous.canonical_path, scope).map_err(reobserve_failure)?;
    }
    fresh.observed_paths = previous.observed_paths.clone();
    if fresh != *previous {
        return Err(ReobserveError::Changed);
    }
    Ok(fresh)
}

fn reobserve_failure(error: ReadFailure) -> ReobserveError {
    match error {
        ReadFailure::Unavailable => ReobserveError::Unavailable,
        ReadFailure::Unsafe => ReobserveError::UnsafeTarget,
        ReadFailure::Oversized => ReobserveError::MetadataTooLarge,
        ReadFailure::Invalid | ReadFailure::Changed => ReobserveError::Changed,
    }
}

fn verify_alias(alias: &Path, expected: &Path, scope: &Scope) -> Result<(), ReadFailure> {
    let mut current = alias.to_owned();
    let mut visited = BTreeSet::new();
    // Aliases may traverse only a bounded chain of depth-one public app names;
    // absolute/relative private escapes are rejected before touching that path.
    for _ in 0..8 {
        if !direct_application_path(&current, scope) || !visited.insert(current.clone()) {
            return Err(ReadFailure::Unsafe);
        }
        let parent = current.parent().ok_or(ReadFailure::Unsafe)?;
        let directory = open_directory(parent)?;
        let parent_before = directory.metadata().map_err(|_| ReadFailure::Unavailable)?;
        let name = current.file_name().ok_or(ReadFailure::Unsafe)?;
        match open_child(&directory, name, true) {
            Ok(_) if current == expected => {
                verify_directory_path(&directory, parent, &parent_before)?;
                return Ok(());
            }
            Ok(_) => return Err(ReadFailure::Changed),
            Err(ReadFailure::Unsafe) => {
                let mut bytes = [0u8; 4097];
                let count = readlinkat_raw(&directory, name, &mut bytes)
                    .map_err(|_| ReadFailure::Unsafe)?;
                if count == 0 || count >= bytes.len() || bytes[..count].contains(&0) {
                    return Err(ReadFailure::Unsafe);
                }
                let target = Path::new(std::ffi::OsStr::from_bytes(&bytes[..count]));
                let next = if target.is_absolute() {
                    target.to_owned()
                } else {
                    parent.join(target)
                };
                if !direct_application_path(&next, scope) {
                    return Err(ReadFailure::Unsafe);
                }
                verify_directory_path(&directory, parent, &parent_before)?;
                current = next;
            }
            Err(error) => return Err(error),
        }
    }
    Err(ReadFailure::Unsafe)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn current_home() -> Result<PathBuf, InstalledError> {
    use std::{mem::MaybeUninit, os::unix::ffi::OsStrExt};
    let mut buffer = [0u8; 16_384];
    let mut record = MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    // SAFETY: fixed initialized writable buffer and correctly aligned passwd
    // output; no pointer is read before success or retained after this function.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(InstalledError::HomeUnavailable);
    }
    // SAFETY: successful getpwuid_r initialized record and points strings into buffer.
    let record = unsafe { record.assume_init() };
    let offset = (record.pw_dir as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .filter(|offset| *offset < buffer.len())
        .ok_or(InstalledError::HomeUnavailable)?;
    let remaining = &buffer[offset..];
    let end = remaining
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(InstalledError::HomeUnavailable)?;
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(&remaining[..end]));
    if !home.is_absolute() || home == Path::new("/") {
        return Err(InstalledError::HomeUnavailable);
    }
    Ok(home)
}

struct Scope {
    apps: Vec<PathBuf>,
    cli: Vec<PathBuf>,
    public_binary_roots: Vec<PathBuf>,
    entry_cap: usize,
    app_cap: usize,
    installation_cap: usize,
}

impl Scope {
    fn new(home: PathBuf) -> Self {
        let apps = vec![PathBuf::from("/Applications"), home.join("Applications")];
        let cli = vec![
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/usr/local/bin"),
            home.join(".local/bin"),
            home.join(".cargo/bin"),
            home.join(".memo/bin"),
        ];
        let mut public_binary_roots = cli.clone();
        public_binary_roots.extend(apps.clone());
        public_binary_roots.extend([
            PathBuf::from("/opt/homebrew/Cellar"),
            PathBuf::from("/opt/homebrew/lib"),
            PathBuf::from("/opt/homebrew/Caskroom"),
            PathBuf::from("/usr/local/Cellar"),
            PathBuf::from("/usr/local/lib"),
            home.join(".local/share/claude/versions"),
            home.join(".codex/packages/standalone/releases"),
        ]);
        Self {
            apps,
            cli,
            public_binary_roots,
            entry_cap: APP_ENTRY_CAPACITY,
            app_cap: APP_CAPACITY_PER_DIRECTORY,
            installation_cap: INSTALLATION_CAPACITY,
        }
    }
}

#[derive(Debug)]
enum ReadFailure {
    Unavailable,
    Unsafe,
    Invalid,
    Oversized,
    Changed,
}

fn note_failure(coverage: &mut InstalledCoverage, failure: ReadFailure) {
    match failure {
        ReadFailure::Unavailable => coverage.unavailable_paths += 1,
        ReadFailure::Unsafe => coverage.unsafe_paths += 1,
        ReadFailure::Invalid => coverage.invalid_metadata += 1,
        ReadFailure::Oversized => coverage.oversized_plists += 1,
        ReadFailure::Changed => coverage.changed_during_read += 1,
    }
}

fn stat_key(metadata: &Metadata) -> (u64, u64, u64, i64, i64, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.mode(),
    )
}

fn plain_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && Path::new(value).components().count() == 1
        && matches!(
            Path::new(value).components().next(),
            Some(Component::Normal(_))
        )
}

fn open_regular(path: &Path) -> Result<File, ReadFailure> {
    let before = fs::symlink_metadata(path).map_err(|_| ReadFailure::Unavailable)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(ReadFailure::Unsafe);
    }
    let file = open_absolute(path, false)?;
    if stat_key(&before) != stat_key(&file.metadata().map_err(|_| ReadFailure::Unavailable)?) {
        return Err(ReadFailure::Changed);
    }
    Ok(file)
}

fn open_directory(path: &Path) -> Result<File, ReadFailure> {
    open_absolute(path, true)
}

fn open_absolute(path: &Path, directory: bool) -> Result<File, ReadFailure> {
    // Resolve each public path component through held directories. A leaf-only
    // NOFOLLOW would permit a replaced parent to redirect a subsequent read.
    if !path.is_absolute() {
        return Err(ReadFailure::Unsafe);
    }
    let mut current = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ReadFailure::Unavailable)?;
    let components: Vec<_> = path
        .components()
        .filter(|component| !matches!(component, Component::RootDir))
        .collect();
    if components.is_empty() || components.len() > 64 {
        return Err(ReadFailure::Unsafe);
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(ReadFailure::Unsafe);
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if directory || index + 1 != components.len() {
            flags |= OFlags::DIRECTORY;
        }
        current = openat(&current, *name, flags, Mode::empty()).map_err(|error| {
            if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
                ReadFailure::Unsafe
            } else {
                ReadFailure::Unavailable
            }
        })?;
    }
    let file = File::from(current);
    let metadata = file.metadata().map_err(|_| ReadFailure::Unavailable)?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(ReadFailure::Unsafe);
    }
    Ok(file)
}

fn open_child(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File, ReadFailure> {
    if !matches!(
        Path::new(name).components().next(),
        Some(Component::Normal(_))
    ) || Path::new(name).components().count() != 1
    {
        return Err(ReadFailure::Unsafe);
    }
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    let descriptor = openat(parent, name, flags, Mode::empty()).map_err(|error| {
        if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
            ReadFailure::Unsafe
        } else {
            ReadFailure::Unavailable
        }
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| ReadFailure::Unavailable)?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(ReadFailure::Unsafe);
    }
    Ok(file)
}

fn directory_identity(metadata: &Metadata) -> (u64, u64, u32) {
    (metadata.dev(), metadata.ino(), metadata.mode())
}

fn verify_directory_path(file: &File, path: &Path, before: &Metadata) -> Result<(), ReadFailure> {
    let named = open_directory(path)?;
    if directory_identity(before)
        != directory_identity(&file.metadata().map_err(|_| ReadFailure::Changed)?)
        || directory_identity(before)
            != directory_identity(&named.metadata().map_err(|_| ReadFailure::Changed)?)
    {
        return Err(ReadFailure::Changed);
    }
    Ok(())
}

fn verify_child(
    parent: &File,
    name: &std::ffi::OsStr,
    file: &File,
    before: &Metadata,
    directory: bool,
) -> Result<(), ReadFailure> {
    let named = open_child(parent, name, directory)?;
    if stat_key(before) != stat_key(&file.metadata().map_err(|_| ReadFailure::Changed)?)
        || stat_key(before) != stat_key(&named.metadata().map_err(|_| ReadFailure::Changed)?)
    {
        return Err(ReadFailure::Changed);
    }
    Ok(())
}

fn stable_after(file: &File, path: &Path, before: &Metadata) -> Result<(), ReadFailure> {
    let after = file.metadata().map_err(|_| ReadFailure::Unavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| ReadFailure::Changed)?;
    if stat_key(before) != stat_key(&after) || stat_key(before) != stat_key(&named) {
        return Err(ReadFailure::Changed);
    }
    Ok(())
}

fn executable(path: &Path) -> Result<ExecutableMetadata, ReadFailure> {
    let mut file = open_regular(path)?;
    let before = file.metadata().map_err(|_| ReadFailure::Unavailable)?;
    let result = executable_bytes(&mut file, &before)?;
    stable_after(&file, path, &before)?;
    Ok(result)
}

fn executable_bytes(file: &mut File, before: &Metadata) -> Result<ExecutableMetadata, ReadFailure> {
    if before.mode() & 0o111 == 0 {
        return Err(ReadFailure::Invalid);
    }
    let mut bytes = [0; 4];
    let count = file
        .read(&mut bytes)
        .map_err(|_| ReadFailure::Unavailable)?;
    let format = if count == 4
        && matches!(
            bytes,
            [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        ) {
        ExecutableFormat::MachO
    } else if count >= 2 && bytes[..2] == *b"#!" {
        ExecutableFormat::Script
    } else {
        ExecutableFormat::Other
    };
    Ok(ExecutableMetadata {
        device: before.dev(),
        inode: before.ino(),
        size: before.len(),
        modified_seconds: before.mtime(),
        modified_nanoseconds: before.mtime_nsec(),
        mode: before.mode(),
        format,
    })
}

fn digest(fields: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    format!("{:x}", hash.finalize())
}

fn finish_installation(
    mut row: Installation,
    public_bytes: &[u8],
    location: &Metadata,
) -> Installation {
    let metadata = format!("{:?}:{:?}", stat_key(location), row.executable);
    row.metadata_fingerprint = digest(&[
        b"chinwag-install-metadata/v1",
        row.canonical_path.as_os_str().as_encoded_bytes(),
        row.executable_path.as_os_str().as_encoded_bytes(),
        metadata.as_bytes(),
        public_bytes,
    ]);
    row.id = digest(&[
        b"chinwag-host-local-install/v1",
        row.canonical_path.as_os_str().as_encoded_bytes(),
        row.metadata_fingerprint.as_bytes(),
    ]);
    row
}

fn app(path: &Path, scope: &Scope) -> Result<Option<Installation>, ReadFailure> {
    let canonical = fs::canonicalize(path).map_err(|_| ReadFailure::Unavailable)?;
    read_application(&canonical, scope)
}

fn read_application(canonical: &Path, scope: &Scope) -> Result<Option<Installation>, ReadFailure> {
    if !direct_application_path(canonical, scope) {
        return Err(ReadFailure::Unsafe);
    }
    let root_path = canonical.parent().ok_or(ReadFailure::Unsafe)?;
    let application_name = canonical.file_name().ok_or(ReadFailure::Unsafe)?;
    let root = open_directory(root_path)?;
    let root_before = root.metadata().map_err(|_| ReadFailure::Unavailable)?;
    let application = open_child(&root, application_name, true)?;
    let location = application
        .metadata()
        .map_err(|_| ReadFailure::Unavailable)?;
    let contents = open_child(&application, std::ffi::OsStr::new("Contents"), true)?;
    let contents_before = contents.metadata().map_err(|_| ReadFailure::Unavailable)?;
    let macos = open_child(&contents, std::ffi::OsStr::new("MacOS"), true)?;
    let macos_before = macos.metadata().map_err(|_| ReadFailure::Unavailable)?;
    let plist_name = std::ffi::OsStr::new("Info.plist");
    let mut file = open_child(&contents, plist_name, false)?;
    let before = file.metadata().map_err(|_| ReadFailure::Unavailable)?;
    if before.len() > MAX_PLIST_BYTES as u64 {
        return Err(ReadFailure::Oversized);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_PLIST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadFailure::Unavailable)?;
    if bytes.len() > MAX_PLIST_BYTES {
        return Err(ReadFailure::Oversized);
    }
    verify_child(&contents, plist_name, &file, &before, false)?;
    let value = plist::Value::from_reader(Cursor::new(&bytes)).map_err(|_| ReadFailure::Invalid)?;
    let dictionary = value.as_dictionary().ok_or(ReadFailure::Invalid)?;
    let string = |key: &str| {
        dictionary
            .get(key)
            .and_then(plist::Value::as_string)
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
    };
    let bundle_id = string("CFBundleIdentifier").ok_or(ReadFailure::Invalid)?;
    let name = string("CFBundleName").ok_or(ReadFailure::Invalid)?;
    let binary = string("CFBundleExecutable")
        .filter(|value| plain_component(value))
        .ok_or(ReadFailure::Invalid)?;
    let Some((family, match_basis)) = app_family(name, bundle_id, binary) else {
        return Ok(None);
    };
    let executable_path = canonical.join("Contents/MacOS").join(binary);
    let mut executable_file = open_child(&macos, std::ffi::OsStr::new(binary), false)?;
    let executable_before = executable_file
        .metadata()
        .map_err(|_| ReadFailure::Unavailable)?;
    let executable = executable_bytes(&mut executable_file, &executable_before)?;
    let row = Installation {
        id: String::new(),
        family,
        kind: InstallationKind::Application,
        match_basis,
        canonical_path: canonical.to_owned(),
        observed_paths: vec![],
        display_name: string("CFBundleDisplayName").unwrap_or(name).to_owned(),
        bundle_id: Some(bundle_id.to_owned()),
        version: string("CFBundleShortVersionString")
            .or_else(|| string("CFBundleVersion"))
            .map(str::to_owned),
        executable_path,
        executable,
        metadata_fingerprint: String::new(),
    };
    verify_child(
        &macos,
        std::ffi::OsStr::new(binary),
        &executable_file,
        &executable_before,
        false,
    )?;
    verify_child(&contents, plist_name, &file, &before, false)?;
    verify_child(
        &contents,
        std::ffi::OsStr::new("MacOS"),
        &macos,
        &macos_before,
        true,
    )?;
    verify_child(
        &application,
        std::ffi::OsStr::new("Contents"),
        &contents,
        &contents_before,
        true,
    )?;
    verify_child(&root, application_name, &application, &location, true)?;
    verify_directory_path(&root, root_path, &root_before)?;
    // Root directory mtimes can change when unrelated apps are installed; only
    // its identity/mode participates. The exact app/plist/executable and nested
    // directory identities do participate, so same-byte replacements invalidate.
    let context = format!(
        "{:?}:{:?}:{:?}:{:?}",
        directory_identity(&root_before),
        directory_identity(&contents_before),
        directory_identity(&macos_before),
        stat_key(&before)
    );
    let public_fingerprint = digest(&[
        b"chinwag-application-public-metadata/v2",
        context.as_bytes(),
        &bytes,
    ]);
    Ok(Some(finish_installation(
        row,
        public_fingerprint.as_bytes(),
        &location,
    )))
}

fn cli(path: &Path, name: &str, scope: &Scope) -> Result<Installation, ReadFailure> {
    let canonical = fs::canonicalize(path).map_err(|_| ReadFailure::Unavailable)?;
    if !scope
        .public_binary_roots
        .iter()
        .any(|root| canonical.starts_with(root))
    {
        return Err(ReadFailure::Unsafe);
    }
    let location = fs::symlink_metadata(&canonical).map_err(|_| ReadFailure::Unavailable)?;
    let executable = executable(&canonical)?;
    let row = Installation {
        id: String::new(),
        family: cli_family(name).ok_or(ReadFailure::Invalid)?,
        kind: InstallationKind::CommandLine,
        match_basis: InstallationMatch::ExactCliFilenameHint,
        canonical_path: canonical.clone(),
        observed_paths: vec![],
        display_name: name.to_owned(),
        bundle_id: None,
        version: None,
        executable_path: canonical,
        executable,
        metadata_fingerprint: String::new(),
    };
    Ok(finish_installation(row, &[], &location))
}

fn insert(
    rows: &mut BTreeMap<PathBuf, Installation>,
    mut row: Installation,
    observed: PathBuf,
    coverage: &mut InstalledCoverage,
    cap: usize,
) {
    if let Some(existing) = rows.get_mut(&row.canonical_path) {
        if existing.kind != row.kind || existing.family != row.family {
            coverage.invalid_metadata += 1;
            return;
        }
        if !existing.observed_paths.contains(&observed) {
            existing.observed_paths.push(observed);
            coverage.aliases_merged += 1;
        }
        return;
    }
    if rows.len() >= cap {
        coverage.installation_cap_reached = true;
        coverage.omitted_installations += 1;
        return;
    }
    row.observed_paths.push(observed);
    rows.insert(row.canonical_path.clone(), row);
}

fn collect(scope: &Scope) -> Result<InstalledSnapshot, InstalledError> {
    let mut coverage = InstalledCoverage {
        installation_capacity: scope.installation_cap,
        cli_directories: scope.cli.clone(),
        ..InstalledCoverage::default()
    };
    let mut rows = BTreeMap::new();
    for root in &scope.apps {
        let mut directory = DirectoryCoverage {
            path: root.clone(),
            status: DirectoryStatus::Read,
            entries_examined: 0,
            app_candidates_examined: 0,
            entry_cap_reached: false,
            app_cap_reached: false,
        };
        match fs::symlink_metadata(root) {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                directory.status = DirectoryStatus::Unsafe;
                coverage.application_directories.push(directory);
                continue;
            }
            Err(error) => {
                directory.status = if error.kind() == std::io::ErrorKind::NotFound {
                    DirectoryStatus::Missing
                } else {
                    DirectoryStatus::Unavailable
                };
                coverage.application_directories.push(directory);
                continue;
            }
            _ => {}
        }
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(_) => {
                directory.status = DirectoryStatus::Unavailable;
                coverage.application_directories.push(directory);
                continue;
            }
        };
        let mut selected = Vec::new();
        for entry in entries {
            if directory.entries_examined >= scope.entry_cap {
                directory.entry_cap_reached = true;
                break;
            }
            directory.entries_examined += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    coverage.unavailable_paths += 1;
                    continue;
                }
            };
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "app")
            {
                if selected.len() >= scope.app_cap {
                    directory.app_cap_reached = true;
                    break;
                }
                selected.push(entry.path());
            }
        }
        selected.sort();
        directory.app_candidates_examined = selected.len();
        for path in selected {
            match app(&path, scope) {
                Ok(Some(row)) => {
                    insert(&mut rows, row, path, &mut coverage, scope.installation_cap)
                }
                Ok(None) => coverage.unrecognized_applications += 1,
                Err(error) => note_failure(&mut coverage, error),
            }
        }
        coverage.application_directories.push(directory);
    }
    for root in &scope.cli {
        for name in CLI_NAMES {
            let path = root.join(name);
            coverage.cli_paths_checked += 1;
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    coverage.missing_cli_paths += 1;
                    continue;
                }
                Err(_) => {
                    coverage.unavailable_paths += 1;
                    continue;
                }
                _ => {}
            }
            match cli(&path, name, scope) {
                Ok(row) => insert(&mut rows, row, path, &mut coverage, scope.installation_cap),
                Err(error) => note_failure(&mut coverage, error),
            }
        }
    }
    let observed_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| InstalledError::Clock)?
            .as_millis(),
    )
    .map_err(|_| InstalledError::Clock)?;
    Ok(InstalledSnapshot { observed_at_unix_ms,installations:rows.into_values().collect(),coverage,limitations:vec![
        "Known-family public installation metadata only; no vendor signature, account, protocol, launch permission or readiness was verified.".into(),
        "Only depth-one application entries and exact CLI filenames in explicit directories were inspected; missing or capped results do not prove absence.".into(),
        "Public Info.plist bytes and four executable format bytes are read; no shell, candidate executable, private configuration, arguments, environment or session store is inspected.".into(),
        "Metadata fingerprints are host-local observations, not content hashes or continuous installation identity.".into(),
    ] })
}

#[cfg(test)]
mod tests;
