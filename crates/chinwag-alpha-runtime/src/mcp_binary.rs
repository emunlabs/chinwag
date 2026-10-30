//! Owner-declared MCP executable pin for human setup and artifact export.
//! This reads only the declared binary, never a client configuration or session.

use crate::onboarding::OnboardingError;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const MAX_BINARY: u64 = 64 * 1024 * 1024;

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Identity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

pub(crate) struct PinnedMcpBinary {
    path: PathBuf,
    identity: Identity,
    digest: [u8; 32],
    // Hold the original inode so a replacement cannot reuse its identity.
    _anchor: File,
}

impl PinnedMcpBinary {
    pub fn open(path: &Path) -> Result<Self, OnboardingError> {
        let (file, identity, digest) = inspect(path)?;
        Ok(Self {
            path: path.into(),
            identity,
            digest,
            _anchor: file,
        })
    }

    pub fn revalidate(&self) -> Result<(), OnboardingError> {
        let (_, identity, digest) = inspect(&self.path)?;
        if identity != self.identity || digest != self.digest {
            return Err(OnboardingError::Unavailable);
        }
        Ok(())
    }

    /// Read a bounded immutable snapshot from the original held inode, checking
    /// its identity, full digest and pathname before and after copying. This is
    /// a native-header check, not code-signature/vendor verification or a
    /// guarantee about later execution through the source pathname.
    pub fn verified_snapshot(&self) -> Result<VerifiedMcpBinary, OnboardingError> {
        self.revalidate()?;
        let fail = || OnboardingError::Unavailable;
        if Identity::of(&self._anchor.metadata().map_err(|_| fail())?) != self.identity {
            return Err(fail());
        }
        let capacity = usize::try_from(self.identity.bytes).map_err(|_| fail())?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut buffer = [0u8; 16384];
        let mut offset = 0u64;
        loop {
            let count = self
                ._anchor
                .read_at(&mut buffer, offset)
                .map_err(|_| fail())?;
            if count == 0 {
                break;
            }
            offset = offset.checked_add(count as u64).ok_or_else(fail)?;
            if offset > MAX_BINARY || offset > self.identity.bytes {
                return Err(fail());
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if offset != self.identity.bytes
            || Identity::of(&self._anchor.metadata().map_err(|_| fail())?) != self.identity
            || digest != self.digest
        {
            return Err(fail());
        }
        self.revalidate()?;
        Ok(VerifiedMcpBinary {
            path: self.path.clone(),
            bytes,
            digest,
        })
    }
}

/// Bytes verified by the pin; callers cannot replace the buffer or digest.
pub(crate) struct VerifiedMcpBinary {
    path: PathBuf,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl VerifiedMcpBinary {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.digest
    }
}

fn inspect(path: &Path) -> Result<(File, Identity, [u8; 32]), OnboardingError> {
    let fail = || OnboardingError::Unavailable;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || fs::canonicalize(path).map_err(|_| fail())? != path
    {
        return Err(OnboardingError::Invalid);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| fail())?;
    let before = file.metadata().map_err(|_| fail())?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o100 == 0
        || before.mode() & 0o022 != 0
        || before.len() < 4
        || before.len() > MAX_BINARY
    {
        return Err(OnboardingError::Invalid);
    }
    let mut header = [0u8; 4];
    file.read_exact(&mut header).map_err(|_| fail())?;
    if !matches!(
        header,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    ) {
        return Err(OnboardingError::Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(header);
    let mut bounded = Read::by_ref(&mut file).take(MAX_BINARY - 4 + 1);
    let mut total = 4u64;
    let mut buffer = [0u8; 16384];
    loop {
        let count = bounded.read(&mut buffer).map_err(|_| fail())?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_BINARY {
            return Err(OnboardingError::Invalid);
        }
        hash.update(&buffer[..count]);
    }
    let identity = Identity::of(&before);
    if total != before.len() || identity != Identity::of(&file.metadata().map_err(|_| fail())?) {
        return Err(OnboardingError::Unavailable);
    }
    Ok((file, identity, hash.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn binary(root: &Path) -> PathBuf {
        let path = root.join("chinwag-bus-mcp");
        fs::write(&path, [0xcf, 0xfa, 0xed, 0xfe, 1, 2, 3, 4]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn pinned_binary_rejects_content_change_or_valid_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let path = binary(&root);
        let pin = PinnedMcpBinary::open(&path).unwrap();
        pin.revalidate().unwrap();
        fs::write(&path, [0xcf, 0xfa, 0xed, 0xfe, 9, 9, 9, 9]).unwrap();
        assert!(pin.revalidate().is_err());
        fs::rename(&path, root.join("original-held")).unwrap();
        binary(&root);
        assert!(pin.revalidate().is_err());
    }

    #[test]
    fn setup_binary_must_be_private_owner_controlled_native_regular_file() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let path = binary(&root);
        let alias = root.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(PinnedMcpBinary::open(&alias).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(PinnedMcpBinary::open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PinnedMcpBinary::open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&path, b"#!/bin/sh\necho do-not-execute").unwrap();
        assert!(PinnedMcpBinary::open(&path).is_err());
        assert!(PinnedMcpBinary::open(&root).is_err());
    }

    #[test]
    fn snapshot_uses_exact_held_bytes_and_preserves_fixed_digest() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let path = binary(&root);
        let pin = PinnedMcpBinary::open(&path).unwrap();
        let first = pin.verified_snapshot().unwrap();
        let second = pin.verified_snapshot().unwrap();
        assert_eq!(first.path(), path);
        assert_eq!(first.bytes(), [0xcf, 0xfa, 0xed, 0xfe, 1, 2, 3, 4]);
        assert_eq!(first.bytes(), second.bytes());
        assert_eq!(
            first.sha256(),
            <[u8; 32]>::from(Sha256::digest(first.bytes()))
        );
        assert_eq!(first.sha256(), second.sha256());
    }

    #[test]
    fn snapshot_rejects_changed_source_and_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let path = binary(&root);
        let pin = PinnedMcpBinary::open(&path).unwrap();
        fs::write(&path, [0xcf, 0xfa, 0xed, 0xfe, 5, 6, 7, 8]).unwrap();
        assert!(pin.verified_snapshot().is_err());
        let path = binary(&root);
        let replacement_pin = PinnedMcpBinary::open(&path).unwrap();
        fs::rename(&path, root.join("held-original")).unwrap();
        binary(&root);
        assert!(replacement_pin.verified_snapshot().is_err());
    }

    #[test]
    fn oversized_sparse_binary_is_rejected_before_snapshot_allocation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let path = binary(&root);
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_BINARY + 1)
            .unwrap();
        assert!(PinnedMcpBinary::open(&path).is_err());
    }
}
