#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Bounded, read-only resolution of explicitly enrolled task sources.
//!
//! This initial profile admits ASCII directory entries only. Rust's standard
//! library does not provide Unicode normalization or full case folding; guessing
//! at those operations could admit two authorities for one canonical name.
//! Non-ASCII requested components or siblings therefore produce an explicit
//! alias hold. Syntactic validation still preserves the caller's exact UTF-8
//! bytes, so a future reviewed Unicode profile need not rewrite stored paths.
//!
//! Descriptors pin objects, and final checks detect observed namespace drift.
//! They do not fence an uncooperative same-UID writer after the final check.

use rustix::fs::{AtFlags, CWD, Dir, FileType, Mode, OFlags, Stat, fstat, openat, statat};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub const MAX_CANONICAL_PATH_BYTES: usize = 4096;
pub const MAX_DESCENT_COMPONENTS: usize = 64;
pub const MAX_SOURCE_FILE_BYTES: u64 = 1_048_576;
/// Counts entries other than `.` and `..`, independently for each directory.
pub const MAX_DIRECTORY_ENTRIES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourcePathHoldReason {
    InvalidRelativePath,
    PathTooLong,
    TooManyComponents,
    InvalidWorkspaceRoot,
    HeldSourceMissing,
    HeldSourceInaccessible,
    HeldSourceReplacedOrDrifted,
    SymlinkRejected,
    HardlinkRejected,
    CaseOrUnicodeAliasMismatch,
    HeldSourceOwnershipMismatch,
    HeldSourceNotDirectory,
    UnsupportedFileType,
    FileTooLarge,
    HeldSourceDirectoryEnumerationLimit,
    HeldFilesystemAliasAcrossSources,
}

/// Generation is a positive signed-64-bit configuration revision, not
/// filesystem metadata. Verifying this pin proves the directory's identity and
/// owner; it does not confer authority to advance the configuration generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRootPin {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub generation: u64,
}

impl WorkspaceRootPin {
    pub fn verify(&self) -> Result<(), SourcePathHoldReason> {
        open_pinned_root(self).map(|_| ())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTaskSourceFile {
    pub canonical_relative_path: String,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    /// Permission and special bits, excluding the file-type bits.
    pub mode: u32,
    pub nlink: u64,
    pub size: u64,
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
}

/// Checks syntax without normalizing case, Unicode, separators, or whitespace.
pub fn validate_enrolled_relative_path(path: &str) -> Result<Vec<&str>, SourcePathHoldReason> {
    if path.len() > MAX_CANONICAL_PATH_BYTES {
        return Err(SourcePathHoldReason::PathTooLong);
    }
    if path.is_empty()
        || path.starts_with('/')
        || path.bytes().any(|byte| byte == 0 || byte == b'\\')
    {
        return Err(SourcePathHoldReason::InvalidRelativePath);
    }
    let components: Vec<_> = path.split('/').collect();
    if components.len() > MAX_DESCENT_COMPONENTS {
        return Err(SourcePathHoldReason::TooManyComponents);
    }
    if components
        .iter()
        .any(|component| component.is_empty() || *component == "." || *component == "..")
    {
        return Err(SourcePathHoldReason::InvalidRelativePath);
    }
    Ok(components)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl Snapshot {
    // Unix stat field widths vary by platform. These explicit conversions also
    // preserve the device-number representation used by MetadataExt::dev().
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &Stat) -> Result<Self, SourcePathHoldReason> {
        Ok(Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode as u32,
            nlink: stat.st_nlink as u64,
            size: u64::try_from(stat.st_size)
                .map_err(|_| SourcePathHoldReason::HeldSourceReplacedOrDrifted)?,
            mtime: stat.st_mtime as i64,
            mtime_nsec: stat.st_mtime_nsec as i64,
            ctime: stat.st_ctime as i64,
            ctime_nsec: stat.st_ctime_nsec as i64,
        })
    }
}

struct OpenDirectory {
    file: File,
    snapshot: Snapshot,
}

fn lookup_error(error: rustix::io::Errno) -> SourcePathHoldReason {
    match error {
        rustix::io::Errno::NOENT => SourcePathHoldReason::HeldSourceMissing,
        rustix::io::Errno::LOOP => SourcePathHoldReason::SymlinkRejected,
        rustix::io::Errno::NOTDIR => SourcePathHoldReason::HeldSourceNotDirectory,
        _ => SourcePathHoldReason::HeldSourceInaccessible,
    }
}

/// A name disappearing after its initial observation is drift, not absence.
fn recheck_error(error: rustix::io::Errno) -> SourcePathHoldReason {
    match error {
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR => {
            SourcePathHoldReason::HeldSourceReplacedOrDrifted
        }
        _ => lookup_error(error),
    }
}

fn check_kind_and_owner(
    stat: &Stat,
    leaf: bool,
    expected_uid: u32,
) -> Result<Snapshot, SourcePathHoldReason> {
    let kind = FileType::from_raw_mode(stat.st_mode);
    if kind == FileType::Symlink {
        return Err(SourcePathHoldReason::SymlinkRejected);
    }
    if leaf && kind != FileType::RegularFile {
        return Err(SourcePathHoldReason::UnsupportedFileType);
    }
    if !leaf && kind != FileType::Directory {
        return Err(SourcePathHoldReason::HeldSourceNotDirectory);
    }
    let snapshot = Snapshot::of(stat)?;
    if snapshot.uid != expected_uid {
        return Err(SourcePathHoldReason::HeldSourceOwnershipMismatch);
    }
    if leaf && snapshot.nlink != 1 {
        return Err(SourcePathHoldReason::HardlinkRejected);
    }
    if leaf && snapshot.size > MAX_SOURCE_FILE_BYTES {
        return Err(SourcePathHoldReason::FileTooLarge);
    }
    Ok(snapshot)
}

fn verify_root_spelling(root: &WorkspaceRootPin) -> Result<(), SourcePathHoldReason> {
    let bytes = root.path.as_os_str().as_bytes();
    if root.generation == 0
        || root.generation > i64::MAX as u64
        || !root.path.is_absolute()
        || bytes.len() > MAX_CANONICAL_PATH_BYTES
        || bytes.contains(&0)
        || (bytes != b"/"
            && bytes[1..]
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || component == b"." || component == b".."))
    {
        return Err(SourcePathHoldReason::InvalidWorkspaceRoot);
    }
    Ok(())
}

fn check_root_identity(
    root: &WorkspaceRootPin,
    stat: &Stat,
) -> Result<Snapshot, SourcePathHoldReason> {
    let snapshot = check_kind_and_owner(stat, false, root.uid)?;
    if snapshot.dev != root.dev || snapshot.ino != root.ino {
        return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
    }
    Ok(snapshot)
}

fn open_pinned_root(root: &WorkspaceRootPin) -> Result<OpenDirectory, SourcePathHoldReason> {
    verify_root_spelling(root)?;
    let entry =
        statat(CWD, root.path.as_path(), AtFlags::SYMLINK_NOFOLLOW).map_err(lookup_error)?;
    let expected = check_root_identity(root, &entry)?;
    let file = File::from(
        openat(
            CWD,
            root.path.as_path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(recheck_error)?,
    );
    let snapshot = check_root_identity(root, &fstat(&file).map_err(recheck_error)?)?;
    let rebound =
        statat(CWD, root.path.as_path(), AtFlags::SYMLINK_NOFOLLOW).map_err(recheck_error)?;
    if snapshot != expected || check_root_identity(root, &rebound)? != expected {
        return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
    }
    Ok(OpenDirectory { file, snapshot })
}

fn verify_exact_entry(parent: &File, component: &str) -> Result<(), SourcePathHoldReason> {
    verify_exact_entry_bounded(parent, component, MAX_DIRECTORY_ENTRIES)
}

fn require_ascii_entry(bytes: &[u8]) -> Result<(), SourcePathHoldReason> {
    if bytes.is_ascii() {
        Ok(())
    } else {
        Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
    }
}

fn verify_exact_entry_bounded(
    parent: &File,
    component: &str,
    limit: usize,
) -> Result<(), SourcePathHoldReason> {
    require_ascii_entry(component.as_bytes())?;
    let entries = Dir::read_from(parent).map_err(lookup_error)?;
    let mut count = 0;
    let mut exact = false;
    let mut alias = false;
    for entry in entries {
        let entry = entry.map_err(lookup_error)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        count += 1;
        if count > limit {
            return Err(SourcePathHoldReason::HeldSourceDirectoryEnumerationLimit);
        }
        // Even an ASCII requested name can have a Unicode-equivalent sibling
        // (for example, Kelvin sign versus K). Without normalization data, any
        // non-ASCII sibling makes the absence of an alias unprovable.
        require_ascii_entry(name)?;
        if name == component.as_bytes() {
            exact = true;
        } else if name.eq_ignore_ascii_case(component.as_bytes()) {
            alias = true;
        }
    }
    if alias {
        Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
    } else if exact {
        Ok(())
    } else {
        Err(SourcePathHoldReason::HeldSourceMissing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolutionStep {
    RootOpened,
    DirectoryOpened,
    LeafOpened,
    LeafRead,
}

#[derive(Default)]
struct Hooks {
    #[cfg(test)]
    callback: Option<Box<dyn FnMut(ResolutionStep)>>,
}

impl Hooks {
    fn hit(&mut self, _step: ResolutionStep) {
        #[cfg(test)]
        if let Some(callback) = &mut self.callback {
            callback(_step);
        }
    }
}

/// Resolves exactly this enrolled source. No fallback path or file discovery is
/// performed. Every component below the root is opened relative to its retained
/// parent descriptor with NOFOLLOW; the leaf is read at most 1 MiB plus one
/// sentinel byte, then all directory bindings and stable metadata are rechecked.
pub fn resolve_enrolled_source_under_root(
    root: &WorkspaceRootPin,
    canonical_relative_path: &str,
) -> Result<ResolvedTaskSourceFile, SourcePathHoldReason> {
    resolve_with_hooks(root, canonical_relative_path, &mut Hooks::default())
}

fn resolve_with_hooks(
    root: &WorkspaceRootPin,
    canonical_relative_path: &str,
    hooks: &mut Hooks,
) -> Result<ResolvedTaskSourceFile, SourcePathHoldReason> {
    let components = validate_enrolled_relative_path(canonical_relative_path)?;
    let mut directories = vec![open_pinned_root(root)?];
    hooks.hit(ResolutionStep::RootOpened);
    for component in &components[..components.len() - 1] {
        let parent = &directories[directories.len() - 1].file;
        verify_exact_entry(parent, component)?;
        let entry = statat(parent, *component, AtFlags::SYMLINK_NOFOLLOW).map_err(recheck_error)?;
        let expected = check_kind_and_owner(&entry, false, root.uid)?;
        let file = File::from(
            openat(
                parent,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(recheck_error)?,
        );
        let snapshot =
            check_kind_and_owner(&fstat(&file).map_err(recheck_error)?, false, root.uid)?;
        if snapshot != expected {
            return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
        }
        directories.push(OpenDirectory { file, snapshot });
        hooks.hit(ResolutionStep::DirectoryOpened);
    }
    let leaf = components[components.len() - 1];
    let parent = &directories[directories.len() - 1].file;
    verify_exact_entry(parent, leaf)?;
    let entry = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(recheck_error)?;
    let before = check_kind_and_owner(&entry, true, root.uid)?;
    let mut file = File::from(
        openat(
            parent,
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(recheck_error)?,
    );
    let opened = check_kind_and_owner(&fstat(&file).map_err(recheck_error)?, true, root.uid)?;
    if opened != before {
        return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
    }
    hooks.hit(ResolutionStep::LeafOpened);
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_SOURCE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_: io::Error| SourcePathHoldReason::HeldSourceInaccessible)?;
    if bytes.len() as u64 > MAX_SOURCE_FILE_BYTES {
        return Err(SourcePathHoldReason::FileTooLarge);
    }
    hooks.hit(ResolutionStep::LeafRead);

    for (index, directory) in directories.iter().enumerate() {
        let stat = if index == 0 {
            statat(CWD, root.path.as_path(), AtFlags::SYMLINK_NOFOLLOW)
        } else {
            statat(
                &directories[index - 1].file,
                components[index - 1],
                AtFlags::SYMLINK_NOFOLLOW,
            )
        }
        .map_err(recheck_error)?;
        let bound = check_kind_and_owner(&stat, false, root.uid)?;
        if bound != directory.snapshot {
            return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
        }
        verify_exact_entry(&directory.file, components[index]).map_err(|reason| {
            if reason == SourcePathHoldReason::HeldSourceMissing {
                SourcePathHoldReason::HeldSourceReplacedOrDrifted
            } else {
                reason
            }
        })?;
    }
    let final_entry = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(recheck_error)?;
    let bound = check_kind_and_owner(&final_entry, true, root.uid)?;
    let after = check_kind_and_owner(&fstat(&file).map_err(recheck_error)?, true, root.uid)?;
    if before != after || before != bound || before.size != bytes.len() as u64 {
        return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
    }
    for directory in &directories {
        if Snapshot::of(&fstat(&directory.file).map_err(recheck_error)?)? != directory.snapshot {
            return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
        }
    }
    let root_after =
        statat(CWD, root.path.as_path(), AtFlags::SYMLINK_NOFOLLOW).map_err(recheck_error)?;
    if check_root_identity(root, &root_after)? != directories[0].snapshot {
        return Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted);
    }
    Ok(ResolvedTaskSourceFile {
        canonical_relative_path: canonical_relative_path.to_owned(),
        dev: before.dev,
        ino: before.ino,
        uid: before.uid,
        gid: before.gid,
        mode: before.mode & 0o7777,
        nlink: before.nlink,
        size: before.size,
        sha256: Sha256::digest(&bytes).into(),
        bytes,
    })
}

/// A source ID may be observed repeatedly, but different IDs cannot enroll the
/// same filesystem object. Display paths do not override device/inode identity.
pub fn detect_filesystem_alias_across_sources(
    sources: &[(&str, &ResolvedTaskSourceFile)],
) -> Result<(), SourcePathHoldReason> {
    let mut identities = BTreeMap::new();
    for &(source_id, source) in sources {
        if let Some(previous_id) = identities.insert((source.dev, source.ino), source_id)
            && previous_id != source_id
        {
            return Err(SourcePathHoldReason::HeldFilesystemAliasAcrossSources);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        root: WorkspaceRootPin,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let path = fs::canonicalize(temp.path()).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            Self {
                _temp: temp,
                root: WorkspaceRootPin {
                    path,
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                    uid: metadata.uid(),
                    generation: 1,
                },
            }
        }

        fn write(&self, path: &str, bytes: &[u8]) {
            let path = self.root.path.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }

        fn resolve(&self, path: &str) -> Result<ResolvedTaskSourceFile, SourcePathHoldReason> {
            resolve_enrolled_source_under_root(&self.root, path)
        }
    }

    #[test]
    fn p0_source_path_rejects_noncanonical_relative_paths() {
        for path in [
            "",
            "/TASKS.md",
            "a\\b",
            "a\0b",
            "a/",
            "a//b",
            ".",
            "..",
            "a/./b",
            "a/../b",
        ] {
            assert_eq!(
                validate_enrolled_relative_path(path),
                Err(SourcePathHoldReason::InvalidRelativePath),
                "{path:?}"
            );
        }
    }

    #[test]
    fn p0_source_path_bounds_are_inclusive_and_count_utf8_bytes() {
        let maximum = "a".repeat(MAX_CANONICAL_PATH_BYTES);
        assert!(validate_enrolled_relative_path(&maximum).is_ok());
        assert_eq!(
            validate_enrolled_relative_path(&(maximum + "a")),
            Err(SourcePathHoldReason::PathTooLong)
        );
        let components = ["a"; MAX_DESCENT_COMPONENTS].join("/");
        assert!(validate_enrolled_relative_path(&components).is_ok());
        assert_eq!(
            validate_enrolled_relative_path(&(components + "/a")),
            Err(SourcePathHoldReason::TooManyComponents)
        );
        assert_eq!(
            validate_enrolled_relative_path(&"é".repeat(2049)),
            Err(SourcePathHoldReason::PathTooLong)
        );
    }

    #[test]
    fn p0_source_path_validation_preserves_case_unicode_and_whitespace() {
        assert_eq!(
            validate_enrolled_relative_path(" Tasks/é.tasks.md ").unwrap(),
            vec![" Tasks", "é.tasks.md "]
        );
    }

    #[test]
    fn p0_source_path_reads_root_and_nested_files_with_exact_metadata_and_digest() {
        let fixture = Fixture::new();
        fixture.write("TASKS.md", b"root\r\n");
        fixture.write("tasks/stream.tasks.md", b"stream\0bytes\n");
        fixture.root.verify().unwrap();
        for (path, bytes) in [
            ("TASKS.md", b"root\r\n".as_slice()),
            ("tasks/stream.tasks.md", b"stream\0bytes\n".as_slice()),
        ] {
            let resolved = fixture.resolve(path).unwrap();
            let metadata = fs::metadata(fixture.root.path.join(path)).unwrap();
            assert_eq!(resolved.canonical_relative_path, path);
            assert_eq!(resolved.bytes, bytes);
            assert_eq!(resolved.sha256, <[u8; 32]>::from(Sha256::digest(bytes)));
            assert_eq!(
                (resolved.dev, resolved.ino),
                (metadata.dev(), metadata.ino())
            );
            assert_eq!(
                (resolved.uid, resolved.gid),
                (metadata.uid(), metadata.gid())
            );
            assert_eq!(resolved.mode, metadata.mode() & 0o7777);
            assert_eq!(resolved.nlink, 1);
            assert_eq!(resolved.size, bytes.len() as u64);
        }
    }

    #[test]
    fn p0_source_path_reads_empty_file_and_exact_size_limit() {
        let fixture = Fixture::new();
        fixture.write("empty.md", b"");
        assert!(fixture.resolve("empty.md").unwrap().bytes.is_empty());
        fixture.write("maximum.md", &vec![b'x'; MAX_SOURCE_FILE_BYTES as usize]);
        assert_eq!(
            fixture.resolve("maximum.md").unwrap().size,
            MAX_SOURCE_FILE_BYTES
        );
    }

    #[test]
    fn p0_source_path_missing_never_selects_root_fallback() {
        let fixture = Fixture::new();
        fixture.write("TASKS.md", b"existing root task source");
        assert_eq!(
            fixture.resolve("absent.md"),
            Err(SourcePathHoldReason::HeldSourceMissing)
        );
        assert_eq!(
            fixture.resolve("absent/tasks.md"),
            Err(SourcePathHoldReason::HeldSourceMissing)
        );
    }

    #[test]
    fn p0_source_path_rejects_oversized_source_before_read() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"");
        File::options()
            .write(true)
            .open(fixture.root.path.join("tasks.md"))
            .unwrap()
            .set_len(MAX_SOURCE_FILE_BYTES + 1)
            .unwrap();
        assert_eq!(
            fixture.resolve("tasks.md"),
            Err(SourcePathHoldReason::FileTooLarge)
        );
    }

    #[test]
    fn p0_source_path_rejects_root_identity_and_owner_drift() {
        let fixture = Fixture::new();
        let mut changed = fixture.root.clone();
        changed.ino ^= 1;
        assert_eq!(
            changed.verify(),
            Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted)
        );
        changed = fixture.root.clone();
        changed.dev ^= 1;
        assert_eq!(
            changed.verify(),
            Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted)
        );
        changed = fixture.root.clone();
        changed.uid ^= 1;
        assert_eq!(
            changed.verify(),
            Err(SourcePathHoldReason::HeldSourceOwnershipMismatch)
        );
    }

    #[test]
    fn p0_source_path_root_generation_requires_positive_signed_revision() {
        let fixture = Fixture::new();
        let mut root = fixture.root.clone();
        for generation in [0, i64::MAX as u64 + 1, u64::MAX] {
            root.generation = generation;
            assert_eq!(
                root.verify(),
                Err(SourcePathHoldReason::InvalidWorkspaceRoot)
            );
        }
        for generation in [1, i64::MAX as u64] {
            root.generation = generation;
            assert_eq!(root.verify(), Ok(()));
        }
    }

    #[test]
    fn p0_source_path_rejects_root_symlink_and_noncanonical_root_spelling() {
        let fixture = Fixture::new();
        let sibling = Fixture::new();
        symlink(&fixture.root.path, sibling.root.path.join("root-link")).unwrap();
        let mut root = fixture.root.clone();
        root.path = sibling.root.path.join("root-link");
        assert_eq!(root.verify(), Err(SourcePathHoldReason::SymlinkRejected));
        for path in [
            PathBuf::from("relative"),
            PathBuf::from(format!("{}/", fixture.root.path.display())),
            fixture.root.path.join("../root"),
        ] {
            root.path = path;
            assert_eq!(
                root.verify(),
                Err(SourcePathHoldReason::InvalidWorkspaceRoot)
            );
        }
    }

    #[test]
    fn p0_source_path_rejects_leaf_and_intermediate_symlinks_including_escape() {
        let fixture = Fixture::new();
        let external = Fixture::new();
        external.write("tasks.md", b"outside");
        fixture.write("inside/tasks.md", b"inside");
        symlink("inside/tasks.md", fixture.root.path.join("leaf.md")).unwrap();
        symlink(&external.root.path, fixture.root.path.join("escape")).unwrap();
        symlink("inside", fixture.root.path.join("alias")).unwrap();
        for path in ["leaf.md", "escape/tasks.md", "alias/tasks.md"] {
            assert_eq!(
                fixture.resolve(path),
                Err(SourcePathHoldReason::SymlinkRejected)
            );
        }
    }

    #[test]
    fn p0_source_path_rejects_hardlinks_nonregular_leaf_and_nondirectory_component() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"tasks");
        fs::hard_link(
            fixture.root.path.join("tasks.md"),
            fixture.root.path.join("linked.md"),
        )
        .unwrap();
        assert_eq!(
            fixture.resolve("tasks.md"),
            Err(SourcePathHoldReason::HardlinkRejected)
        );
        assert_eq!(
            fixture.resolve("tasks.md/child.md"),
            Err(SourcePathHoldReason::HeldSourceNotDirectory)
        );
        fs::create_dir(fixture.root.path.join("directory.md")).unwrap();
        assert_eq!(
            fixture.resolve("directory.md"),
            Err(SourcePathHoldReason::UnsupportedFileType)
        );
        let _socket = UnixListener::bind(fixture.root.path.join("socket.md")).unwrap();
        assert_eq!(
            fixture.resolve("socket.md"),
            Err(SourcePathHoldReason::UnsupportedFileType)
        );
    }

    #[test]
    fn p0_source_path_rejects_fifo_metadata_before_open() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"fixture");
        let directory = open_pinned_root(&fixture.root).unwrap();
        let mut fifo = statat(&directory.file, "tasks.md", AtFlags::SYMLINK_NOFOLLOW).unwrap();
        // rustix 1.1.5 excludes mkfifoat/mknodat on Apple. This fixture checks
        // the FIFO metadata branch; it does not claim a real FIFO was created.
        fifo.st_mode = FileType::Fifo.as_raw_mode() | Mode::from_raw_mode(0o600).bits();
        assert_eq!(
            check_kind_and_owner(&fifo, true, fixture.root.uid),
            Err(SourcePathHoldReason::UnsupportedFileType)
        );
    }

    #[test]
    fn p0_source_path_rejects_wrong_case_intermediate_directory() {
        let fixture = Fixture::new();
        fixture.write("Streams/tasks.md", b"nested");
        assert_eq!(
            fixture.resolve("streams/tasks.md"),
            Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
        );
        assert_eq!(
            fixture.resolve("Streams/tasks.md").unwrap().bytes,
            b"nested"
        );
    }

    #[test]
    fn p0_source_path_rejects_case_mismatch_and_ambiguous_case_siblings() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"lowercase");
        assert_eq!(
            fixture.resolve("TASKS.md"),
            Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
        );
        fixture.write("TASKS.md", b"second spelling");
        // On a case-insensitive filesystem, only the original lowercase entry
        // exists; on a case-sensitive one, the two distinct entries are aliases.
        assert_eq!(
            fixture.resolve("TASKS.md"),
            Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
        );
    }

    #[test]
    fn p0_source_path_holds_unicode_requested_names_and_siblings_without_normalizing() {
        let fixture = Fixture::new();
        fixture.write("TASKS.md", b"ascii");
        fixture.write("é.md", b"unicode");
        for path in ["é.md", "e\u{301}.md", "TASKS.md"] {
            assert_eq!(
                fixture.resolve(path),
                Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
            );
        }
    }

    #[test]
    fn p0_source_path_holds_ascii_name_with_kelvin_sign_sibling() {
        let fixture = Fixture::new();
        fixture.write("K.md", b"ascii");
        fixture.write("K.md", b"unicode canonical equivalent");
        let has_unicode_entry = fs::read_dir(&fixture.root.path)
            .unwrap()
            .any(|entry| !entry.unwrap().file_name().as_bytes().is_ascii());
        // A normalization-insensitive filesystem may retain only the original
        // ASCII entry. There is then no second directory entry to reject.
        if has_unicode_entry {
            assert_eq!(
                fixture.resolve("K.md"),
                Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
            );
        } else {
            assert!(fixture.resolve("K.md").is_ok());
        }
        assert_eq!(
            fixture.resolve("K.md"),
            Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
        );
    }

    #[test]
    fn p0_source_path_holds_non_utf8_and_unicode_entry_bytes() {
        for bytes in [b"\xff".as_slice(), "é.md".as_bytes(), "K.md".as_bytes()] {
            assert_eq!(
                require_ascii_entry(bytes),
                Err(SourcePathHoldReason::CaseOrUnicodeAliasMismatch)
            );
        }
    }

    #[test]
    fn p0_source_path_resolves_maximum_descent_and_rejects_one_more() {
        let fixture = Fixture::new();
        let maximum = ["a"; MAX_DESCENT_COMPONENTS].join("/");
        fixture.write(&maximum, b"bounded");
        assert_eq!(fixture.resolve(&maximum).unwrap().bytes, b"bounded");
        assert_eq!(
            fixture.resolve(&(maximum + "/a")),
            Err(SourcePathHoldReason::TooManyComponents)
        );
    }

    #[test]
    fn p0_source_path_enforces_expected_uid_for_both_directories_and_leaf() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"owned");
        let directory = open_pinned_root(&fixture.root).unwrap();
        let wrong_uid = fixture.root.uid ^ 1;
        assert_eq!(
            check_kind_and_owner(&fstat(&directory.file).unwrap(), false, wrong_uid),
            Err(SourcePathHoldReason::HeldSourceOwnershipMismatch)
        );
        let file = File::open(fixture.root.path.join("tasks.md")).unwrap();
        assert_eq!(
            check_kind_and_owner(&fstat(&file).unwrap(), true, wrong_uid),
            Err(SourcePathHoldReason::HeldSourceOwnershipMismatch)
        );
    }

    #[test]
    fn p0_source_path_caps_descriptor_bound_directory_enumeration() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"one");
        fixture.write("other.md", b"two");
        let directory = open_pinned_root(&fixture.root).unwrap();
        assert_eq!(MAX_DIRECTORY_ENTRIES, 16_384);
        assert!(verify_exact_entry_bounded(&directory.file, "tasks.md", 2).is_ok());
        assert_eq!(
            verify_exact_entry_bounded(&directory.file, "tasks.md", 1),
            Err(SourcePathHoldReason::HeldSourceDirectoryEnumerationLimit)
        );
    }

    #[test]
    fn p0_source_path_reports_actual_permission_denial_distinct_from_missing() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"private");
        let path = fixture.root.path.join("tasks.md");
        fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();
        let result = fixture.resolve("tasks.md");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(result, Err(SourcePathHoldReason::HeldSourceInaccessible));
    }

    #[test]
    fn p0_source_path_detects_leaf_replacement_after_open() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"original");
        let path = fixture.root.path.join("tasks.md");
        let staging = fixture.root.path.join("replacement.md");
        let mut hooks = Hooks {
            callback: Some(Box::new(move |step| {
                if step == ResolutionStep::LeafOpened {
                    fs::write(&staging, b"replaced").unwrap();
                    fs::rename(&staging, &path).unwrap();
                }
            })),
        };
        assert_eq!(
            resolve_with_hooks(&fixture.root, "tasks.md", &mut hooks),
            Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted)
        );
    }

    #[test]
    fn p0_source_path_detects_leaf_content_growth_during_read() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"original");
        let path = fixture.root.path.join("tasks.md");
        let mut hooks = Hooks {
            callback: Some(Box::new(move |step| {
                if step == ResolutionStep::LeafOpened {
                    File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(MAX_SOURCE_FILE_BYTES + 1)
                        .unwrap();
                }
            })),
        };
        assert_eq!(
            resolve_with_hooks(&fixture.root, "tasks.md", &mut hooks),
            Err(SourcePathHoldReason::FileTooLarge)
        );
    }

    #[test]
    fn p0_source_path_detects_rebound_intermediate_directory() {
        let fixture = Fixture::new();
        fixture.write("tasks/stream.md", b"original");
        let directory = fixture.root.path.join("tasks");
        let moved = fixture.root.path.join("moved");
        let mut hooks = Hooks {
            callback: Some(Box::new(move |step| {
                if step == ResolutionStep::LeafRead {
                    fs::rename(&directory, &moved).unwrap();
                    fs::create_dir(&directory).unwrap();
                    fs::write(directory.join("stream.md"), b"original").unwrap();
                }
            })),
        };
        assert_eq!(
            resolve_with_hooks(&fixture.root, "tasks/stream.md", &mut hooks),
            Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted)
        );
    }

    #[test]
    fn p0_source_path_detects_same_inode_metadata_change_after_read() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"original");
        let path = fixture.root.path.join("tasks.md");
        let mut hooks = Hooks {
            callback: Some(Box::new(move |step| {
                if step == ResolutionStep::LeafRead {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                }
            })),
        };
        assert_eq!(
            resolve_with_hooks(&fixture.root, "tasks.md", &mut hooks),
            Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted)
        );
    }

    #[test]
    fn p0_source_path_detects_same_length_content_and_mtime_drift() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"original");
        let path = fixture.root.path.join("tasks.md");
        let mut hooks = Hooks {
            callback: Some(Box::new(move |step| {
                if step == ResolutionStep::LeafRead {
                    fs::write(&path, b"modified").unwrap();
                    File::open(&path)
                        .unwrap()
                        .set_modified(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap();
                }
            })),
        };
        assert_eq!(
            resolve_with_hooks(&fixture.root, "tasks.md", &mut hooks),
            Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted)
        );
    }

    #[test]
    fn p0_source_path_detects_sibling_added_after_leaf_read() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"original");
        let sibling = fixture.root.path.join("new-sibling.md");
        let mut hooks = Hooks {
            callback: Some(Box::new(move |step| {
                if step == ResolutionStep::LeafRead {
                    fs::write(&sibling, b"added").unwrap();
                }
            })),
        };
        assert_eq!(
            resolve_with_hooks(&fixture.root, "tasks.md", &mut hooks),
            Err(SourcePathHoldReason::HeldSourceReplacedOrDrifted)
        );
    }

    #[test]
    fn p0_source_path_detects_cross_source_filesystem_aliases() {
        let fixture = Fixture::new();
        fixture.write("tasks.md", b"first");
        fixture.write("other.md", b"second");
        let first = fixture.resolve("tasks.md").unwrap();
        let second = fixture.resolve("other.md").unwrap();
        assert!(
            detect_filesystem_alias_across_sources(&[("source-a", &first), ("source-b", &second)])
                .is_ok()
        );
        assert!(
            detect_filesystem_alias_across_sources(&[("source-a", &first), ("source-a", &first)])
                .is_ok()
        );
        assert_eq!(
            detect_filesystem_alias_across_sources(&[("source-a", &first), ("source-b", &first)]),
            Err(SourcePathHoldReason::HeldFilesystemAliasAcrossSources)
        );
    }
}
