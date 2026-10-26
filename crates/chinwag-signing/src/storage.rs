use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use rustix::fd::OwnedFd;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, Stat, fchmod, fstat, fsync, mkdirat, open, openat, statat,
};
use rustix::io::Errno;
use ssh_key::LineEnding;
use zeroize::Zeroizing;

use crate::{Error, MAX_KEY_BYTES, SigningSecret};

/// An owner-private directory capability, anchored independently of its path.
pub struct PrivateDirectory {
    fd: OwnedFd,
}

impl PrivateDirectory {
    /// Create one private leaf below an existing owned, non-shared parent.
    /// A post-creation error leaves the directory in place for inspection.
    /// This capability stays anchored if its parent is subsequently renamed.
    pub fn create_new(path: &Path) -> Result<Self, Error> {
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(Error::Directory);
        }
        let mut names = Vec::new();
        for component in components {
            let Component::Normal(name) = component else {
                return Err(Error::Directory);
            };
            validate_name(name)?;
            names.push(name);
        }
        let (name, parents) = names.split_last().ok_or(Error::Directory)?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut parent = open("/", flags, Mode::empty()).map_err(|_| Error::Directory)?;
        for component in parents {
            parent =
                openat(&parent, *component, flags, Mode::empty()).map_err(|_| Error::Directory)?;
        }
        let metadata = fstat(&parent).map_err(|_| Error::Directory)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_mode & 0o022 != 0
            || metadata.st_mode & 0o300 != 0o300
        {
            return Err(Error::Directory);
        }
        mkdirat(&parent, *name, Mode::from_raw_mode(0o700)).map_err(|error| {
            if error == Errno::EXIST {
                Error::Exists
            } else {
                Error::Create
            }
        })?;
        Self::confirm_created(&parent, name)
    }

    fn confirm_created(parent: &OwnedFd, name: &OsStr) -> Result<Self, Error> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = openat(parent, name, flags, Mode::empty()).map_err(unconfirmed)?;
        let directory = Self { fd };
        directory.check_directory().map_err(unconfirmed)?;
        let opened = fstat(&directory.fd).map_err(unconfirmed)?;
        fsync(&directory.fd).map_err(unconfirmed)?;
        fsync(parent).map_err(unconfirmed)?;
        let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(unconfirmed)?;
        if named.st_dev != opened.st_dev
            || named.st_ino != opened.st_ino
            || named.st_uid != opened.st_uid
            || named.st_mode != opened.st_mode
        {
            return Err(Error::CreatedButUnconfirmed);
        }
        directory.check_directory().map_err(unconfirmed)?;
        Ok(directory)
    }

    /// Open an existing absolute path without following any symlink component.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(Error::Directory);
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut fd = open("/", flags, Mode::empty()).map_err(|_| Error::Directory)?;
        for component in components {
            let Component::Normal(name) = component else {
                return Err(Error::Directory);
            };
            fd = openat(&fd, name, flags, Mode::empty()).map_err(|_| Error::Directory)?;
        }
        let metadata = fstat(&fd).map_err(|_| Error::Directory)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_mode & 0o7777 != 0o700
        {
            return Err(Error::Directory);
        }
        Ok(Self { fd })
    }

    pub fn write_new(&self, name: &OsStr, secret: &SigningSecret) -> Result<(), Error> {
        validate_name(name)?;
        self.check_directory()?;
        let encoded = secret
            .private
            .to_openssh(LineEnding::LF)
            .map_err(|_| Error::Format)?;
        self.write_new_bytes(name, encoded.as_bytes())
    }

    /// Persist exactly one Git-scoped public identity without replacing a name.
    /// The line is bound to this signer, not to an independently supplied key.
    pub fn write_new_allowed_signers(
        &self,
        name: &OsStr,
        principal: &str,
        secret: &SigningSecret,
    ) -> Result<(), Error> {
        validate_name(name)?;
        self.check_directory()?;
        let encoded = crate::allowed_signers_line(principal, secret)?;
        self.write_new_bytes(name, encoded.as_bytes())
    }

    fn write_new_bytes(&self, name: &OsStr, encoded: &[u8]) -> Result<(), Error> {
        if encoded.len() > MAX_KEY_BYTES {
            return Err(Error::Format);
        }
        let mode = Mode::RUSR | Mode::WUSR;
        let flags = OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC;
        let fd = openat(&self.fd, name, flags, mode).map_err(|error| {
            if error == Errno::EXIST {
                Error::Exists
            } else {
                Error::Create
            }
        })?;
        let mut file = File::from(fd);
        fchmod(&file, mode).map_err(unconfirmed)?;
        let created = fstat(&file).map_err(unconfirmed)?;
        if !is_private_file(&created) {
            return Err(Error::CreatedButUnconfirmed);
        }
        file.write_all(encoded).map_err(unconfirmed)?;
        file.sync_all().map_err(unconfirmed)?;
        file.seek(SeekFrom::Start(0)).map_err(unconfirmed)?;
        let mut readback = Zeroizing::new(Vec::new());
        (&mut file)
            .take((MAX_KEY_BYTES + 1) as u64)
            .read_to_end(&mut readback)
            .map_err(unconfirmed)?;
        if readback.as_slice() != encoded {
            return Err(Error::CreatedButUnconfirmed);
        }
        let named = statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(unconfirmed)?;
        if !is_private_file(&named)
            || named.st_dev != created.st_dev
            || named.st_ino != created.st_ino
            || named.st_size != encoded.len() as i64
        {
            return Err(Error::CreatedButUnconfirmed);
        }
        self.check_directory()
            .map_err(|_| Error::CreatedButUnconfirmed)?;
        fsync(&self.fd).map_err(unconfirmed)?;
        Ok(())
    }

    pub fn read_existing(
        &self,
        name: &OsStr,
        expected_public: &[u8; 32],
    ) -> Result<SigningSecret, Error> {
        validate_name(name)?;
        self.check_directory()?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let fd = openat(&self.fd, name, flags, Mode::empty()).map_err(|_| Error::Open)?;
        let metadata = fstat(&fd).map_err(|_| Error::File)?;
        if !is_private_file(&metadata)
            || metadata.st_size < 0
            || metadata.st_size as u64 > MAX_KEY_BYTES as u64
        {
            return Err(Error::File);
        }
        let mut encoded = Zeroizing::new(Vec::new());
        let mut file = File::from(fd);
        (&mut file)
            .take((MAX_KEY_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .map_err(|_| Error::Read)?;
        let after = fstat(&file).map_err(|_| Error::File)?;
        if encoded.len() > MAX_KEY_BYTES
            || !is_private_file(&after)
            || after.st_size < 0
            || after.st_size as u64 > MAX_KEY_BYTES as u64
        {
            return Err(Error::File);
        }
        SigningSecret::from_encoded(&encoded, expected_public)
    }

    /// Observe this private directory's identity without exposing a descriptor
    /// or key material. A match is not signing or initialization confirmation.
    #[cfg(target_os = "macos")]
    pub fn matches_directory_identity(&self, device: i32, inode: u64) -> Result<bool, Error> {
        self.check_directory()?;
        let held = fstat(&self.fd).map_err(|_| Error::Directory)?;
        Ok(held.st_dev == device && held.st_ino == inode)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.fd)
    }

    fn check_directory(&self) -> Result<(), Error> {
        let metadata = fstat(&self.fd).map_err(|_| Error::Directory)?;
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
            && metadata.st_uid == rustix::process::geteuid().as_raw()
            && metadata.st_mode & 0o7777 == 0o700
        {
            Ok(())
        } else {
            Err(Error::Directory)
        }
    }
}

fn unconfirmed<E>(_error: E) -> Error {
    Error::CreatedButUnconfirmed
}

fn validate_name(name: &OsStr) -> Result<(), Error> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        Err(Error::Name)
    } else {
        Ok(())
    }
}

fn is_private_file(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
        && metadata.st_uid == rustix::process::geteuid().as_raw()
        && metadata.st_mode & 0o7777 == 0o600
        && metadata.st_nlink == 1
}

#[cfg(test)]
#[path = "material_tests.rs"]
mod material_tests;
