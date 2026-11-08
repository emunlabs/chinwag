// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Ciphertext byte storage observations. The caller must authenticate/classify
//! the envelope BEFORE calling. Hash agreement does not prove encryption, sender
//! identity, an ACU policy, archive acceptance, agent consumption, or WORM storage.

use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags, Stat},
    io::Errno,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
};

pub const MAX_CIPHERTEXT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct CiphertextClaim {
    pub sha256: [u8; 32],
    pub bytes: u64,
}

impl CiphertextClaim {
    fn valid(&self) -> bool {
        self.bytes > 0 && self.bytes <= MAX_CIPHERTEXT_BYTES as u64
    }
    fn filename(&self) -> String {
        format!("{}.cwcipher", hex::encode(self.sha256))
    }
    fn matches(&self, bytes: &[u8]) -> bool {
        self.valid()
            && self.bytes == bytes.len() as u64
            && self.sha256 == <[u8; 32]>::from(Sha256::digest(bytes))
    }
}

pub struct CiphertextStore {
    directory: OwnedFd,
}

/// An observation only. A destination signs its own correlated protocol receipt
/// AFTER this result, binding its role/identity, workflow and original envelope.
#[derive(Serialize)]
pub struct StoredBytesObservation {
    object: String,
    sha256: String,
    bytes: u64,
    file_and_directory_sync_completed: bool,
    readback_hash_and_size_verified: bool,
    reopened_same_inode_as_created: bool,
}

impl StoredBytesObservation {
    pub fn object(&self) -> &str {
        &self.object
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn created_inode_confirmed(&self) -> bool {
        self.reopened_same_inode_as_created
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("invalid ciphertext hash or size claim")]
    Claim,
    #[error("ciphertext store is not an owned private directory")]
    Directory,
    #[error("ciphertext object name already exists; observe it before further action")]
    AlreadyExists,
    #[error("could not create the private ciphertext object")]
    Create,
    #[error("ciphertext object was created but storage confirmation failed; preserve it")]
    CreatedButUnconfirmed,
    #[error("existing ciphertext object failed private-file or exact-byte readback")]
    Readback,
}

fn private_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_mode & 0o7777 == 0o700
}

fn private_file(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o600
}

impl CiphertextStore {
    pub(crate) fn directory(&self) -> rustix::fd::BorrowedFd<'_> {
        use rustix::fd::AsFd;
        self.directory.as_fd()
    }
    /// Open the explicitly owned store, refusing symlinks in every component.
    /// The capability remains anchored if the directory is subsequently renamed.
    /// No existing permission, parent, or service is changed by this method.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(StorageError::Directory);
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory =
            fs::open("/", flags, Mode::empty()).map_err(|_| StorageError::Directory)?;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(StorageError::Directory);
            };
            directory = fs::openat(&directory, name, flags, Mode::empty())
                .map_err(|_| StorageError::Directory)?;
        }
        let store = Self { directory };
        store.check()?;
        Ok(store)
    }

    pub(crate) fn check(&self) -> Result<(), StorageError> {
        if !private_directory(&fs::fstat(&self.directory).map_err(|_| StorageError::Directory)?) {
            return Err(StorageError::Directory);
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsFd;
            crate::macos_acl::require_absent(self.directory.as_fd())
                .map_err(|_| StorageError::Directory)?;
        }
        Ok(())
    }

    fn check_name(&self, claim: CiphertextClaim, opened: &Stat) -> Result<(), StorageError> {
        let named = fs::statat(&self.directory, claim.filename(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| StorageError::Readback)?;
        if !private_file(&named)
            || named.st_dev != opened.st_dev
            || named.st_ino != opened.st_ino
            || named.st_size != opened.st_size
        {
            return Err(StorageError::Readback);
        }
        Ok(())
    }

    pub fn persist_ciphertext_claim(
        &self,
        claim: CiphertextClaim,
        bytes: &[u8],
    ) -> Result<StoredBytesObservation, StorageError> {
        if !claim.matches(bytes) {
            return Err(StorageError::Claim);
        }
        self.check()?;
        let mode = Mode::RUSR | Mode::WUSR;
        let fd = fs::openat(
            &self.directory,
            claim.filename(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            mode,
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                StorageError::AlreadyExists
            } else {
                StorageError::Create
            }
        })?;
        let mut file = File::from(fd);
        let confirm = || StorageError::CreatedButUnconfirmed;
        fs::fchmod(&file, mode).map_err(|_| confirm())?;
        let original = fs::fstat(&file).map_err(|_| confirm())?;
        if !private_file(&original) {
            return Err(confirm());
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsFd;
            crate::macos_acl::require_absent(file.as_fd()).map_err(|_| confirm())?;
        }
        file.write_all(bytes).map_err(|_| confirm())?;
        file.sync_all().map_err(|_| confirm())?;
        fs::fsync(&self.directory).map_err(|_| confirm())?;
        let (observed, actual) = self.reopen_and_read(claim).map_err(|_| confirm())?;
        if original.st_dev != observed.st_dev
            || original.st_ino != observed.st_ino
            || actual != bytes
        {
            return Err(confirm());
        }
        self.check().map_err(|_| confirm())?;
        self.check_name(claim, &observed).map_err(|_| confirm())?;
        Ok(Self::observation(claim, true))
    }

    /// Independent read-only reconciliation. This does not replace an original
    /// message or acknowledge an unverified envelope; it observes one exact name.
    pub fn observe_existing(
        &self,
        claim: CiphertextClaim,
    ) -> Result<StoredBytesObservation, StorageError> {
        if !claim.valid() {
            return Err(StorageError::Claim);
        }
        self.check()?;
        let (observed, _) = self.reopen_and_read(claim)?;
        fs::fsync(&self.directory).map_err(|_| StorageError::Readback)?;
        self.check()?;
        self.check_name(claim, &observed)?;
        Ok(Self::observation(claim, false))
    }

    /// A bounded read of this exact immutable object. Caller reauthenticates
    /// the complete envelope before decrypting or asserting a qualified read.
    pub fn read_existing(&self, claim: CiphertextClaim) -> Result<Vec<u8>, StorageError> {
        if !claim.valid() {
            return Err(StorageError::Claim);
        }
        self.check()?;
        let (observed, bytes) = self.reopen_and_read(claim)?;
        fs::fsync(&self.directory).map_err(|_| StorageError::Readback)?;
        self.check()?;
        self.check_name(claim, &observed)?;
        Ok(bytes)
    }

    fn reopen_and_read(&self, claim: CiphertextClaim) -> Result<(Stat, Vec<u8>), StorageError> {
        let fd = fs::openat(
            &self.directory,
            claim.filename(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StorageError::Readback)?;
        let before = fs::fstat(&fd).map_err(|_| StorageError::Readback)?;
        if !private_file(&before) || before.st_size < 0 || before.st_size as u64 != claim.bytes {
            return Err(StorageError::Readback);
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsFd;
            crate::macos_acl::require_absent(fd.as_fd()).map_err(|_| StorageError::Readback)?;
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::with_capacity(claim.bytes as usize);
        (&mut file)
            .take(claim.bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StorageError::Readback)?;
        file.sync_all().map_err(|_| StorageError::Readback)?;
        let after = fs::fstat(&file).map_err(|_| StorageError::Readback)?;
        if !private_file(&after)
            || before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || !claim.matches(&bytes)
        {
            return Err(StorageError::Readback);
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsFd;
            crate::macos_acl::require_absent(file.as_fd()).map_err(|_| StorageError::Readback)?;
        }
        self.check()?;
        self.check_name(claim, &after)?;
        Ok((after, bytes))
    }

    fn observation(claim: CiphertextClaim, compared_created_inode: bool) -> StoredBytesObservation {
        StoredBytesObservation {
            object: claim.filename(),
            sha256: hex::encode(claim.sha256),
            bytes: claim.bytes,
            file_and_directory_sync_completed: true,
            readback_hash_and_size_verified: true,
            reopened_same_inode_as_created: compared_created_inode,
        }
    }
}

#[cfg(test)]
mod namespace_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn read_inode_must_still_have_the_observed_object_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().canonicalize().unwrap();
        let store = CiphertextStore::open(&path).unwrap();
        let bytes = b"public synthetic ciphertext fixture";
        let claim = CiphertextClaim {
            sha256: Sha256::digest(bytes).into(),
            bytes: bytes.len() as u64,
        };
        store.persist_ciphertext_claim(claim, bytes).unwrap();
        let (observed, _) = store.reopen_and_read(claim).unwrap();
        let name = path.join(claim.filename());
        std::fs::rename(&name, path.join("moved-owned-fixture")).unwrap();
        assert!(matches!(
            store.check_name(claim, &observed),
            Err(StorageError::Readback)
        ));
        let mut options = std::fs::OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt;
        let mut replacement = options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&name)
            .unwrap();
        replacement.write_all(bytes).unwrap();
        replacement.sync_all().unwrap();
        // Same private mode, length and bytes still do not make a new inode the
        // object whose FD was read back.
        assert!(matches!(
            store.check_name(claim, &observed),
            Err(StorageError::Readback)
        ));
    }
}
