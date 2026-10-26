//! File tools confined to an opened workspace directory. This is a filesystem
//! capability boundary, not a sandbox for Cargo or other executed programs.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};

use rand::{RngCore, SeedableRng, rngs::StdRng};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, open, openat, renameat, statat, unlinkat};
use sha2::{Digest, Sha256};

use crate::write_gate::WritePermit;

pub const MAX_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("expected a relative workspace path without protected components")]
    Path,
    #[error("workspace input exceeds the file tool limit")]
    Size,
    #[error("file tools require a regular file with one link")]
    FileType,
    #[error("workspace filesystem operation failed")]
    Io,
    #[error("workspace file replacement could not obtain entropy")]
    Entropy,
    #[error("workspace file no longer matches its expected contents")]
    Preimage,
    #[error("workspace write permit is unavailable, expired, or out of scope")]
    Permit,
}

/// Absence and an existing empty file are different preconditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedContent {
    Absent,
    Sha256([u8; 32]),
}

/// The same-directory rename returned successfully. This is not a parent
/// directory fsync, durable-save receipt, or proof of a remote claim.
#[derive(Debug, PartialEq, Eq)]
pub struct Replaced {
    pub len: usize,
    pub postimage_sha256: [u8; 32],
}

pub struct Workspace {
    directory: OwnedFd,
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn components(path: &Path) -> Result<Vec<OsString>, Error> {
    let mut names = Vec::new();
    for part in path.components() {
        let Component::Normal(name) = part else {
            return Err(Error::Path);
        };
        // Git trust/config and local agent state are not model file tools.
        if [b".git".as_slice(), b".chinwag", b".grok", b".codex"]
            .iter()
            .any(|protected| name.as_encoded_bytes().eq_ignore_ascii_case(protected))
        {
            return Err(Error::Path);
        }
        names.push(name.to_owned());
    }
    if names.is_empty() || names.len() > 64 {
        return Err(Error::Path);
    }
    Ok(names)
}

impl Workspace {
    pub fn open(root: &Path) -> Result<Self, Error> {
        Ok(Self {
            directory: open(root, directory_flags(), Mode::empty()).map_err(|_| Error::Io)?,
        })
    }

    fn parent(&self, path: &Path) -> Result<(OwnedFd, OsString), Error> {
        let mut names = components(path)?;
        let file = names.pop().ok_or(Error::Path)?;
        let mut parent = openat(&self.directory, ".", directory_flags(), Mode::empty())
            .map_err(|_| Error::Io)?;
        for name in names {
            parent =
                openat(&parent, name, directory_flags(), Mode::empty()).map_err(|_| Error::Io)?;
        }
        Ok((parent, file))
    }

    pub fn read(&self, path: &Path) -> Result<Vec<u8>, Error> {
        self.read_optional(path)?.ok_or(Error::Io)
    }

    /// Read through the same file boundary, distinguishing a missing final file.
    pub fn read_optional(&self, path: &Path) -> Result<Option<Vec<u8>>, Error> {
        let (parent, name) = self.parent(path)?;
        let fd = match openat(
            &parent,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(Error::Io),
        };
        let stat = rustix::fs::fstat(&fd).map_err(|_| Error::Io)?;
        regular(stat.st_mode, stat.st_nlink as u64)?;
        if stat.st_size < 0 || stat.st_size as u64 > MAX_FILE_BYTES as u64 {
            return Err(Error::Size);
        }
        let mut data = Vec::new();
        File::from(fd)
            .take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| Error::Io)?;
        if data.len() > MAX_FILE_BYTES {
            return Err(Error::Size);
        }
        Ok(Some(data))
    }

    /// Atomically replace one file in an existing workspace directory. Parent
    /// directories are opened without following symlinks. A final symlink is
    /// refused, and a rename race can replace the link itself, not its target.
    pub fn write(&self, path: &Path, data: &[u8]) -> Result<(), Error> {
        if data.len() > MAX_FILE_BYTES {
            return Err(Error::Size);
        }
        let (parent, name) = self.parent(path)?;
        match statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => regular(stat.st_mode, stat.st_nlink as u64)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(Error::Io),
        }
        let mut rng = StdRng::try_from_os_rng().map_err(|_| Error::Entropy)?;
        let mut random = [0u8; 16];
        rng.fill_bytes(&mut random);
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temporary = OsString::from(format!(".chinwag-write-{suffix}"));
        let fd = openat(
            &parent,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::Io)?;
        let mut pending = Pending {
            parent: &parent,
            name: &temporary,
            published: false,
        };
        let mut file = File::from(fd);
        file.write_all(data).map_err(|_| Error::Io)?;
        file.sync_all().map_err(|_| Error::Io)?;
        drop(file);
        renameat(&parent, &temporary, &parent, &name).map_err(|_| Error::Io)?;
        pending.published = true;
        // No post-rename error can falsely report the file as unmodified.
        // A crash before directory metadata is persisted is not a durable save.
        Ok(())
    }

    /// Check the destination bytes immediately before publishing a staged file.
    ///
    /// Requires an operator-owned workspace with one writer. Another process
    /// can still change a directory entry between the check and `renameat`;
    /// this is not filesystem compare-and-swap or a remote lease fence.
    /// Consumes one scoped witness. The caller must serialize the workspace.
    ///
    /// ```compile_fail,E0382
    /// fn no_reuse(workspace: &chinwag_seed::workspace::Workspace,
    ///     permit: chinwag_seed::write_gate::WritePermit<'_>, path: &std::path::Path) {
    ///     use chinwag_seed::workspace::ExpectedContent;
    ///     workspace.replace_if(permit, path, ExpectedContent::Absent, b"first");
    ///     workspace.replace_if(permit, path, ExpectedContent::Absent, b"second");
    /// }
    /// ```
    pub fn replace_if(
        &self,
        permit: WritePermit<'_>,
        path: &Path,
        expected: ExpectedContent,
        data: &[u8],
    ) -> Result<Replaced, Error> {
        permit.validate(path).map_err(|_| Error::Permit)?;
        if data.len() > MAX_FILE_BYTES {
            return Err(Error::Size);
        }
        let (parent, name) = self.parent(path)?;
        let mut rng = StdRng::try_from_os_rng().map_err(|_| Error::Entropy)?;
        let mut random = [0u8; 16];
        rng.fill_bytes(&mut random);
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temporary = OsString::from(format!(".chinwag-write-{suffix}"));
        let fd = openat(
            &parent,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::Io)?;
        let mut pending = Pending {
            parent: &parent,
            name: &temporary,
            published: false,
        };
        let mut file = File::from(fd);
        file.write_all(data).map_err(|_| Error::Io)?;
        file.sync_all().map_err(|_| Error::Io)?;
        drop(file);
        permit.validate(path).map_err(|_| Error::Permit)?;
        check_preimage(&parent, &name, expected)?;
        permit.validate(path).map_err(|_| Error::Permit)?;
        renameat(&parent, &temporary, &parent, &name).map_err(|_| Error::Io)?;
        pending.published = true;
        Ok(Replaced {
            len: data.len(),
            postimage_sha256: Sha256::digest(data).into(),
        })
    }
}

fn check_preimage(parent: &OwnedFd, name: &OsStr, expected: ExpectedContent) -> Result<(), Error> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {
            return match expected {
                ExpectedContent::Absent => Ok(()),
                ExpectedContent::Sha256(_) => Err(Error::Preimage),
            };
        }
        Err(_) => return Err(Error::Io),
        Ok(stat) => regular(stat.st_mode, stat.st_nlink as u64)?,
    }
    let ExpectedContent::Sha256(expected) = expected else {
        return Err(Error::Preimage);
    };
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Io)?;
    let stat = rustix::fs::fstat(&fd).map_err(|_| Error::Io)?;
    regular(stat.st_mode, stat.st_nlink as u64)?;
    if stat.st_size < 0 || stat.st_size as u64 > MAX_FILE_BYTES as u64 {
        return Err(Error::Size);
    }
    let mut data = Vec::new();
    File::from(fd)
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| Error::Io)?;
    if data.len() > MAX_FILE_BYTES {
        return Err(Error::Size);
    }
    if <[u8; 32]>::from(Sha256::digest(&data)) != expected {
        return Err(Error::Preimage);
    }
    Ok(())
}

fn regular(mode: rustix::fs::RawMode, links: u64) -> Result<(), Error> {
    if FileType::from_raw_mode(mode) != FileType::RegularFile || links != 1 {
        return Err(Error::FileType);
    }
    Ok(())
}

struct Pending<'a> {
    parent: &'a OwnedFd,
    name: &'a OsStr,
    published: bool,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = unlinkat(self.parent, self.name, AtFlags::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    fn test_permit(path: &Path) -> WritePermit<'static> {
        let now = chinwag_swarm::room::now_unix().unwrap();
        WritePermit::test_fixture(
            path,
            now.saturating_sub(1),
            now + 60,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        )
    }

    #[test]
    fn reads_and_atomically_replaces_exact_bytes_without_leaving_a_temporary_file() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        let path = Path::new("src/lib.rs");
        workspace.write(path, b"first\0\n").unwrap();
        assert_eq!(workspace.read(path).unwrap(), b"first\0\n");
        workspace.write(path, b"second\n\n").unwrap();
        assert_eq!(fs::read(root.path().join(path)).unwrap(), b"second\n\n");
        assert_eq!(fs::read_dir(root.path().join("src")).unwrap().count(), 1);
    }

    #[test]
    fn absolute_parent_and_protected_paths_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        for path in [
            "",
            "/etc/passwd",
            "../secret",
            "src/../secret",
            ".git/config",
            ".chinwag/key",
            ".grok/session",
            ".codex/config.toml",
            ".Git/config",
            ".GIT/config",
            ".Chinwag/key",
            ".Grok/session",
            ".Codex/config.toml",
            "src/.gIt/config",
        ] {
            assert!(matches!(workspace.read(Path::new(path)), Err(Error::Path)));
            assert!(matches!(
                workspace.write(Path::new(path), b"x"),
                Err(Error::Path)
            ));
        }
    }

    #[test]
    fn final_and_parent_symlinks_cannot_read_or_write_outside_the_workspace() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"outside").unwrap();
        symlink(outside.path(), root.path().join("linked-dir")).unwrap();
        symlink(
            outside.path().join("secret"),
            root.path().join("linked-file"),
        )
        .unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        for path in ["linked-dir/secret", "linked-file"] {
            assert!(workspace.read(Path::new(path)).is_err());
            assert!(workspace.write(Path::new(path), b"changed").is_err());
        }
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"outside");
    }

    #[test]
    fn directories_hard_links_and_oversized_inputs_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"outside").unwrap();
        fs::hard_link(outside.path().join("secret"), root.path().join("hard-link")).unwrap();
        fs::create_dir(root.path().join("directory")).unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        for path in ["hard-link", "directory"] {
            assert!(matches!(
                workspace.read(Path::new(path)),
                Err(Error::FileType)
            ));
            assert!(matches!(
                workspace.write(Path::new(path), b"changed"),
                Err(Error::FileType)
            ));
        }
        let data = vec![0; MAX_FILE_BYTES + 1];
        assert!(matches!(
            workspace.write(Path::new("too-large"), &data),
            Err(Error::Size)
        ));
        assert!(!root.path().join("too-large").exists());
        fs::write(root.path().join("large"), &data).unwrap();
        assert!(matches!(
            workspace.read(Path::new("large")),
            Err(Error::Size)
        ));
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"outside");
    }

    #[test]
    fn absent_preimage_creates_exact_bytes_and_returns_postimage_hash() {
        let root = tempfile::tempdir().unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        let bytes = b"new\0file\n";
        let result = workspace
            .replace_if(
                test_permit(Path::new("new.rs")),
                Path::new("new.rs"),
                ExpectedContent::Absent,
                bytes,
            )
            .unwrap();
        assert_eq!(fs::read(root.path().join("new.rs")).unwrap(), bytes);
        assert_eq!(result.len, bytes.len());
        assert_eq!(
            result.postimage_sha256,
            <[u8; 32]>::from(Sha256::digest(bytes))
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn matching_preimage_replaces_and_stale_preimage_preserves_newer_edit() {
        let root = tempfile::tempdir().unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        let path = Path::new("source.rs");
        fs::write(root.path().join(path), b"original").unwrap();
        let original = Sha256::digest(workspace.read(path).unwrap()).into();
        workspace
            .replace_if(
                test_permit(path),
                path,
                ExpectedContent::Sha256(original),
                b"reviewed edit",
            )
            .unwrap();
        assert!(matches!(
            workspace.replace_if(
                test_permit(path),
                path,
                ExpectedContent::Sha256(original),
                b"stale edit",
            ),
            Err(Error::Preimage)
        ));
        assert_eq!(fs::read(root.path().join(path)).unwrap(), b"reviewed edit");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn empty_hash_and_absence_are_distinct_and_refusals_remove_staged_files() {
        let root = tempfile::tempdir().unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        let path = Path::new("empty.rs");
        let empty_hash = Sha256::digest([]).into();
        assert!(matches!(
            workspace.replace_if(
                test_permit(path),
                path,
                ExpectedContent::Sha256(empty_hash),
                b"not absent",
            ),
            Err(Error::Preimage)
        ));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        fs::write(root.path().join(path), []).unwrap();
        assert!(matches!(
            workspace.replace_if(
                test_permit(path),
                path,
                ExpectedContent::Absent,
                b"not empty",
            ),
            Err(Error::Preimage)
        ));
        assert_eq!(fs::read(root.path().join(path)).unwrap(), b"");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        workspace
            .replace_if(
                test_permit(path),
                path,
                ExpectedContent::Sha256(empty_hash),
                b"now filled",
            )
            .unwrap();
        assert_eq!(fs::read(root.path().join(path)).unwrap(), b"now filled");
    }

    #[test]
    fn preimage_replace_keeps_path_and_file_type_fences() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"outside").unwrap();
        symlink(outside.path(), root.path().join("linked-dir")).unwrap();
        symlink(
            outside.path().join("secret"),
            root.path().join("linked-file"),
        )
        .unwrap();
        fs::hard_link(outside.path().join("secret"), root.path().join("hard-link")).unwrap();
        fs::create_dir(root.path().join("directory")).unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        for path in [
            "linked-dir/secret",
            "linked-file",
            "hard-link",
            "directory",
            ".git/config",
            ".Chinwag/key",
            "../secret",
            "/etc/passwd",
        ] {
            for expected in [
                ExpectedContent::Absent,
                ExpectedContent::Sha256(Sha256::digest(b"outside").into()),
            ] {
                assert!(
                    workspace
                        .replace_if(
                            test_permit(Path::new(path)),
                            Path::new(path),
                            expected,
                            b"changed"
                        )
                        .is_err()
                );
            }
        }
        assert_eq!(fs::read(outside.path().join("secret")).unwrap(), b"outside");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 4);
    }

    #[test]
    fn oversized_data_and_preimage_leave_existing_file_and_no_temporary() {
        let root = tempfile::tempdir().unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        let path = Path::new("source.rs");
        fs::write(root.path().join(path), b"original").unwrap();
        assert!(matches!(
            workspace.replace_if(
                test_permit(path),
                path,
                ExpectedContent::Sha256(Sha256::digest(b"original").into()),
                &vec![0; MAX_FILE_BYTES + 1]
            ),
            Err(Error::Size)
        ));
        assert_eq!(fs::read(root.path().join(path)).unwrap(), b"original");
        let large = vec![0; MAX_FILE_BYTES + 1];
        fs::write(root.path().join(path), &large).unwrap();
        assert!(matches!(
            workspace.replace_if(
                test_permit(path),
                path,
                ExpectedContent::Sha256(Sha256::digest(&large).into()),
                b"replacement"
            ),
            Err(Error::Size)
        ));
        assert_eq!(fs::read(root.path().join(path)).unwrap(), large);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn expired_future_and_wrong_path_permits_publish_nothing() {
        use std::time::{Duration, Instant};
        let root = tempfile::tempdir().unwrap();
        let workspace = Workspace::open(root.path()).unwrap();
        let path = Path::new("source.rs");
        fs::write(root.path().join(path), b"original").unwrap();
        let now = chinwag_swarm::room::now_unix().unwrap();
        let future = Instant::now() + Duration::from_secs(60);
        for permit in [
            WritePermit::test_fixture(path, now.saturating_sub(1), now, future),
            WritePermit::test_fixture(path, now + 60, now + 120, future),
            WritePermit::test_fixture(path, now.saturating_sub(1), now + 60, Instant::now()),
            WritePermit::test_fixture(
                Path::new("another.rs"),
                now.saturating_sub(1),
                now + 60,
                future,
            ),
        ] {
            assert!(matches!(
                workspace.replace_if(
                    permit,
                    path,
                    ExpectedContent::Sha256(Sha256::digest(b"original").into()),
                    b"changed"
                ),
                Err(Error::Permit)
            ));
            assert_eq!(fs::read(root.path().join(path)).unwrap(), b"original");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }
}
