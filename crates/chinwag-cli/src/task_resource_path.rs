#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Read-only filesystem observations for repository resource conflict keys.
//!
//! These descriptors do not grant a write or prove retirement. The caller pins
//! the root's binding in the wider namespace, binds repository/branch policy,
//! and retains logical path exclusion even when an authorized writer replaces
//! a target inode. Verification detects observed drift; it is not an atomic
//! fence against an uncooperative same-UID filesystem writer.

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, openat, statat};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io;

const MAX_PATH_BYTES: usize = 4096;
const MAX_COMPONENTS: usize = 64;
const MAX_SYMBOL_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FsIdentity {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum ScopeKind {
    File,
    Directory,
    Symbol { symbol: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeDescriptor {
    pub path: String,
    pub folded_path: String,
    pub kind: ScopeKind,
    pub root: FsIdentity,
    pub parent: FsIdentity,
    pub target: Option<FsIdentity>,
    /// Root through canonical parent, inclusive; never the final target.
    pub ancestors: Vec<FsIdentity>,
}

#[derive(Debug)]
pub(crate) enum ResourcePathError {
    InvalidPath,
    PathTooLong,
    TooManyComponents,
    InvalidSymbol,
    MissingParent,
    MissingTarget,
    SymlinkRejected,
    OwnershipMismatch,
    UnsupportedFileType,
    NamespaceChanged,
    Io(io::Error),
}

impl fmt::Display for ResourcePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "resource path I/O failed: {e}"),
            other => write!(f, "resource path held: {other:?}"),
        }
    }
}

impl std::error::Error for ResourcePathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

fn fs_error(error: rustix::io::Errno) -> ResourcePathError {
    if error == rustix::io::Errno::LOOP {
        ResourcePathError::SymlinkRejected
    } else {
        ResourcePathError::Io(error.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    identity: FsIdentity,
    uid: u32,
    mode: u32,
    nlink: u64,
    size: i64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl Snapshot {
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &Stat, uid: u32, directory: bool) -> Result<Self, ResourcePathError> {
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind == FileType::Symlink {
            return Err(ResourcePathError::SymlinkRejected);
        }
        if kind
            != if directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            }
        {
            return Err(ResourcePathError::UnsupportedFileType);
        }
        if stat.st_uid != uid || stat.st_nlink == 0 {
            return Err(ResourcePathError::OwnershipMismatch);
        }
        Ok(Self {
            identity: FsIdentity {
                dev: stat.st_dev as u64,
                ino: stat.st_ino as u64,
            },
            uid: stat.st_uid,
            mode: stat.st_mode as u32,
            nlink: stat.st_nlink as u64,
            size: stat.st_size as i64,
            mtime: stat.st_mtime as i64,
            mtime_nsec: stat.st_mtime_nsec as i64,
            ctime: stat.st_ctime as i64,
            ctime_nsec: stat.st_ctime_nsec as i64,
        })
    }
}

fn components(path: &str) -> Result<Vec<&str>, ResourcePathError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(ResourcePathError::PathTooLong);
    }
    if path.is_empty()
        || !path.is_ascii()
        || path.bytes().any(|b| b.is_ascii_control() || b == b'\\')
    {
        return Err(ResourcePathError::InvalidPath);
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() > MAX_COMPONENTS {
        return Err(ResourcePathError::TooManyComponents);
    }
    if parts.iter().any(|part| {
        part.is_empty()
            || *part == "."
            || *part == ".."
            || part.trim() != *part
            || part.eq_ignore_ascii_case(".git")
    }) {
        return Err(ResourcePathError::InvalidPath);
    }
    Ok(parts)
}

fn validate_kind(kind: &ScopeKind) -> Result<(), ResourcePathError> {
    if let ScopeKind::Symbol { symbol } = kind
        && (symbol.is_empty()
            || symbol.len() > MAX_SYMBOL_BYTES
            || !symbol.is_ascii()
            || symbol.trim() != symbol
            || symbol.bytes().any(|b| b.is_ascii_control()))
    {
        return Err(ResourcePathError::InvalidSymbol);
    }
    Ok(())
}

fn open_readonly(parent: &File, name: &str, directory: bool) -> Result<File, ResourcePathError> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    openat(parent, name, flags, Mode::empty())
        .map(File::from)
        .map_err(fs_error)
}

fn entry(parent: &File, name: &str) -> Result<Option<Stat>, ResourcePathError> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(stat)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(fs_error(error)),
    }
}

#[derive(Debug)]
pub(crate) struct ResolvedFsScope {
    pub descriptor: ScopeDescriptor,
    pub parent: File,
    pub target: Option<File>,
    directories: Vec<File>,
    parent_names: Vec<String>,
    pin: ScopeDescriptor,
    uid: u32,
}

impl ResolvedFsScope {
    /// Checks the original observation. Target drift never means a lease can
    /// be released: an authority must retain logical parent/name exclusion.
    pub(crate) fn verify(&self) -> Result<(), ResourcePathError> {
        if self.descriptor != self.pin
            || self.directories.len() != self.pin.ancestors.len()
            || self.parent_names.len() + 1 != self.directories.len()
        {
            return Err(ResourcePathError::NamespaceChanged);
        }
        for (index, directory) in self.directories.iter().enumerate() {
            let opened = Snapshot::of(&fstat(directory).map_err(fs_error)?, self.uid, true)?;
            if opened.identity != self.pin.ancestors[index] {
                return Err(ResourcePathError::NamespaceChanged);
            }
            if index > 0 {
                let bound = entry(&self.directories[index - 1], &self.parent_names[index - 1])?
                    .ok_or(ResourcePathError::NamespaceChanged)?;
                if Snapshot::of(&bound, self.uid, true)? != opened {
                    return Err(ResourcePathError::NamespaceChanged);
                }
            }
        }
        let parent = Snapshot::of(&fstat(&self.parent).map_err(fs_error)?, self.uid, true)?;
        if parent.identity != self.pin.parent
            || self.pin.ancestors.first() != Some(&self.pin.root)
            || self.pin.ancestors.last() != Some(&self.pin.parent)
        {
            return Err(ResourcePathError::NamespaceChanged);
        }
        let name = self
            .pin
            .path
            .rsplit('/')
            .next()
            .ok_or(ResourcePathError::InvalidPath)?;
        match (&self.target, self.pin.target, entry(&self.parent, name)?) {
            (None, None, None) => Ok(()),
            (Some(file), Some(identity), Some(bound)) => {
                let directory = self.pin.kind == ScopeKind::Directory;
                let opened = Snapshot::of(&fstat(file).map_err(fs_error)?, self.uid, directory)?;
                if opened.identity != identity
                    || Snapshot::of(&bound, self.uid, directory)? != opened
                {
                    return Err(ResourcePathError::NamespaceChanged);
                }
                Ok(())
            }
            _ => Err(ResourcePathError::NamespaceChanged),
        }
    }
}

pub(crate) fn resolve_scope(
    root: &File,
    path: &str,
    kind: ScopeKind,
) -> Result<ResolvedFsScope, ResourcePathError> {
    let parts = components(path)?;
    validate_kind(&kind)?;
    let uid = rustix::process::geteuid().as_raw();
    let original_root = Snapshot::of(&fstat(root).map_err(fs_error)?, uid, true)?;
    let retained_root = open_readonly(root, ".", true)?;
    if Snapshot::of(&fstat(&retained_root).map_err(fs_error)?, uid, true)?.identity
        != original_root.identity
    {
        return Err(ResourcePathError::NamespaceChanged);
    }
    let mut directories = vec![retained_root];
    let mut ancestors = vec![original_root.identity];
    let mut parent_names = Vec::new();
    for name in &parts[..parts.len() - 1] {
        let parent = directories
            .last()
            .ok_or(ResourcePathError::NamespaceChanged)?;
        let before = entry(parent, name)?.ok_or(ResourcePathError::MissingParent)?;
        let before = Snapshot::of(&before, uid, true)?;
        let next = open_readonly(parent, name, true)?;
        if Snapshot::of(&fstat(&next).map_err(fs_error)?, uid, true)? != before {
            return Err(ResourcePathError::NamespaceChanged);
        }
        ancestors.push(before.identity);
        parent_names.push((*name).to_owned());
        directories.push(next);
    }
    let parent = open_readonly(
        directories
            .last()
            .ok_or(ResourcePathError::NamespaceChanged)?,
        ".",
        true,
    )?;
    let name = parts.last().ok_or(ResourcePathError::InvalidPath)?;
    let directory = kind == ScopeKind::Directory;
    let target = match entry(&parent, name)? {
        Some(stat) => {
            let before = Snapshot::of(&stat, uid, directory)?;
            let file = open_readonly(&parent, name, directory)?;
            if Snapshot::of(&fstat(&file).map_err(fs_error)?, uid, directory)? != before {
                return Err(ResourcePathError::NamespaceChanged);
            }
            Some(file)
        }
        None if directory => return Err(ResourcePathError::MissingTarget),
        None => None,
    };
    let target_identity = target
        .as_ref()
        .map(|f| Snapshot::of(&fstat(f).map_err(fs_error)?, uid, directory).map(|s| s.identity))
        .transpose()?;
    let descriptor = ScopeDescriptor {
        path: path.to_owned(),
        folded_path: path.to_ascii_lowercase(),
        kind,
        root: original_root.identity,
        parent: *ancestors
            .last()
            .ok_or(ResourcePathError::NamespaceChanged)?,
        target: target_identity,
        ancestors,
    };
    let resolved = ResolvedFsScope {
        pin: descriptor.clone(),
        descriptor,
        parent,
        target,
        directories,
        parent_names,
        uid,
    };
    resolved.verify()?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    fn root() -> (tempfile::TempDir, File) {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        (temp, root)
    }

    #[test]
    fn p008_resource_missing_filename_retains_parent_and_exact_folded_keys() {
        let (temp, root) = root();
        fs::create_dir(temp.path().join("Src")).unwrap();
        let scope = resolve_scope(&root, "Src/New.rs", ScopeKind::File).unwrap();
        assert_eq!(scope.descriptor.path, "Src/New.rs");
        assert_eq!(scope.descriptor.folded_path, "src/new.rs");
        assert!(scope.target.is_none());
        assert_eq!(scope.descriptor.ancestors.len(), 2);
        scope.verify().unwrap();
        fs::write(temp.path().join("Src/New.rs"), b"created").unwrap();
        assert!(matches!(
            scope.verify(),
            Err(ResourcePathError::NamespaceChanged)
        ));
    }

    #[test]
    fn p008_resource_hardlink_aliases_share_physical_identity() {
        let (temp, root) = root();
        fs::write(temp.path().join("one.rs"), b"fn one() {}").unwrap();
        fs::hard_link(temp.path().join("one.rs"), temp.path().join("two.rs")).unwrap();
        let a = resolve_scope(&root, "one.rs", ScopeKind::File).unwrap();
        let b = resolve_scope(
            &root,
            "two.rs",
            ScopeKind::Symbol {
                symbol: "two".into(),
            },
        )
        .unwrap();
        assert_eq!(a.descriptor.target, b.descriptor.target);
        assert_ne!(a.descriptor.path, b.descriptor.path);
        a.verify().unwrap();
        b.verify().unwrap();
    }

    #[test]
    fn p008_resource_symlink_at_any_level_and_missing_parent_hold() {
        let (temp, root) = root();
        fs::create_dir(temp.path().join("real")).unwrap();
        fs::write(temp.path().join("real/x"), b"x").unwrap();
        symlink("real", temp.path().join("alias")).unwrap();
        symlink("real/x", temp.path().join("link")).unwrap();
        for path in ["alias/x", "link"] {
            assert!(matches!(
                resolve_scope(&root, path, ScopeKind::File),
                Err(ResourcePathError::SymlinkRejected)
            ));
        }
        assert!(matches!(
            resolve_scope(&root, "absent/x", ScopeKind::File),
            Err(ResourcePathError::MissingParent)
        ));
        assert!(matches!(
            resolve_scope(&root, "absent", ScopeKind::Directory),
            Err(ResourcePathError::MissingTarget)
        ));
    }

    #[test]
    fn p008_resource_directory_ancestors_are_actual_directory_identities() {
        let (temp, root) = root();
        fs::create_dir_all(temp.path().join("src/nested")).unwrap();
        let ancestor = resolve_scope(&root, "src", ScopeKind::Directory).unwrap();
        let child = resolve_scope(&root, "src/nested/new.rs", ScopeKind::File).unwrap();
        assert!(
            child
                .descriptor
                .ancestors
                .contains(&ancestor.descriptor.target.unwrap())
        );
        assert_eq!(
            child.descriptor.ancestors.first(),
            Some(&ancestor.descriptor.root)
        );
        assert!(matches!(
            resolve_scope(&root, "src", ScopeKind::File),
            Err(ResourcePathError::UnsupportedFileType)
        ));
    }

    #[test]
    fn p008_resource_parent_swap_and_atomic_target_replacement_are_detected() {
        let (temp, root) = root();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/x"), b"old").unwrap();
        let old = resolve_scope(&root, "src/x", ScopeKind::File).unwrap();
        fs::write(temp.path().join("src/replacement"), b"new").unwrap();
        fs::rename(
            temp.path().join("src/replacement"),
            temp.path().join("src/x"),
        )
        .unwrap();
        assert!(matches!(
            old.verify(),
            Err(ResourcePathError::NamespaceChanged) | Err(ResourcePathError::OwnershipMismatch)
        ));
        let current = resolve_scope(&root, "src/x", ScopeKind::File).unwrap();
        fs::rename(temp.path().join("src"), temp.path().join("old-src")).unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/x"), b"other").unwrap();
        assert!(matches!(
            current.verify(),
            Err(ResourcePathError::NamespaceChanged)
        ));
    }

    #[test]
    fn p008_resource_ascii_paths_protect_git_and_reject_ambiguous_syntax() {
        let (_temp, root) = root();
        for path in [
            "",
            "/tmp/x",
            "x/",
            "x//y",
            "./x",
            "x/../y",
            "a\\b",
            "x\ny",
            "x\0y",
            "é.rs",
            ".git/config",
            "SRC/.GiT/index",
            " x",
            "x ",
        ] {
            assert!(
                resolve_scope(&root, path, ScopeKind::File).is_err(),
                "{path:?}"
            );
        }
        assert!(matches!(
            resolve_scope(&root, &"a".repeat(4097), ScopeKind::File),
            Err(ResourcePathError::PathTooLong)
        ));
        assert!(matches!(
            resolve_scope(&root, &vec!["a"; 65].join("/"), ScopeKind::File),
            Err(ResourcePathError::TooManyComponents)
        ));
        assert!(matches!(
            resolve_scope(
                &root,
                "x",
                ScopeKind::Symbol {
                    symbol: "\n".into()
                }
            ),
            Err(ResourcePathError::InvalidSymbol)
        ));
        let lower = resolve_scope(&root, "new.rs", ScopeKind::File).unwrap();
        let upper = resolve_scope(&root, "NEW.RS", ScopeKind::File).unwrap();
        assert_eq!(lower.descriptor.folded_path, upper.descriptor.folded_path);
    }

    #[test]
    fn p008_resource_descriptor_fields_cannot_be_relabelled_after_resolution() {
        let (_temp, root) = root();
        let mut scope = resolve_scope(&root, "new", ScopeKind::File).unwrap();
        scope.descriptor.folded_path = "other".into();
        assert!(matches!(
            scope.verify(),
            Err(ResourcePathError::NamespaceChanged)
        ));
    }

    #[test]
    fn p008_resource_observation_never_returns_a_writable_target() {
        let (temp, root) = root();
        fs::write(temp.path().join("x"), b"original").unwrap();
        let scope = resolve_scope(&root, "x", ScopeKind::File).unwrap();
        let mut target = scope.target.as_ref().unwrap();
        assert!(target.write_all(b"changed").is_err());
        assert_eq!(fs::read(temp.path().join("x")).unwrap(), b"original");
        scope.verify().unwrap();
        assert!(matches!(
            resolve_scope(scope.target.as_ref().unwrap(), "child", ScopeKind::File),
            Err(ResourcePathError::UnsupportedFileType)
        ));
    }

    #[test]
    fn p008_resource_special_files_are_refused_without_opening_them() {
        let (temp, root) = root();
        let _listener = UnixListener::bind(temp.path().join("socket")).unwrap();
        assert!(matches!(
            resolve_scope(&root, "socket", ScopeKind::File),
            Err(ResourcePathError::UnsupportedFileType)
        ));
    }
}
