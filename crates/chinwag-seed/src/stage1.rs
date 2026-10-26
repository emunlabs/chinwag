//! Synchronous process replacement, entered before any seed runtime or worker.
//!
//! The caller supplies an expected digest; this does not verify a release,
//! signature, G-v gate, or loaded kernel image. The final pathname lookup by
//! exec can race another writer after our last check. Use a quiescent,
//! operator-owned tree. Platform exec may select an interpreter; file format
//! and release signatures are not validated here. This is a component, not a
//! Genesis completion receipt.

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, open, openat, statat};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    ffi::OsString,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::{fd::OwnedFd, unix::process::CommandExt},
    path::{Component, Path, PathBuf},
    process::Command,
};

const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("stage1 needs an absolute, normal workspace path")]
    Path,
    #[error("stage1 needs exactly 64 lowercase SHA-256 hex characters")]
    Digest,
    #[error("stage1 arguments exceed their bounds or contain NUL")]
    Arguments,
    #[error("stage1 directory could not be opened or is unsafe")]
    Directory,
    #[error("stage1 needs an owned single-link regular executable")]
    Executable,
    #[error("stage1 executable could not be read within its size bound")]
    Read,
    #[error("stage1 executable does not match the expected digest")]
    Hash,
    #[error("stage1 path or executable changed during verification")]
    Changed,
    #[error("stage1 exec returned an error (OS code {os_code:?})")]
    Exec { os_code: Option<i32> },
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn same_node(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
}

fn safe_directory(s: &Stat) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::Directory
        && (s.st_uid == 0 || s.st_uid == rustix::process::geteuid().as_raw())
        && s.st_mode & 0o7022 == 0
}

fn safe_image(s: &Stat) -> bool {
    FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
        && s.st_uid == rustix::process::geteuid().as_raw()
        && s.st_nlink == 1
        && s.st_mode & 0o7022 == 0
        && s.st_mode & 0o500 == 0o500
        && s.st_size > 0
        && s.st_size as u64 <= MAX_IMAGE_BYTES
}

fn expected_digest(text: &str) -> Result<[u8; 32], Error> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Digest);
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| Error::Digest)?;
    }
    Ok(digest)
}

fn workspace_components(workspace: &Path) -> Result<Vec<OsString>, Error> {
    if !workspace.is_absolute() || workspace.as_os_str().len() > 4096 {
        return Err(Error::Path);
    }
    let mut names = Vec::new();
    let mut exact = PathBuf::from("/");
    for part in workspace.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                exact.push(name);
                names.push(name.to_owned());
            }
            _ => return Err(Error::Path),
        }
    }
    if names.is_empty() || names.len() > 64 || exact.as_os_str() != workspace.as_os_str() {
        return Err(Error::Path);
    }
    names.extend([OsString::from("target"), OsString::from("release")]);
    Ok(names)
}

struct Directory {
    fd: OwnedFd,
    id: Stat,
}

struct Image {
    directories: Vec<Directory>,
    names: Vec<OsString>,
    file: File,
    id: Stat,
    expected: [u8; 32],
}

impl Image {
    fn open(workspace: &Path, expected: [u8; 32]) -> Result<Self, Error> {
        let names = workspace_components(workspace)?;
        let root = open("/", directory_flags(), Mode::empty()).map_err(|_| Error::Directory)?;
        let id = fstat(&root).map_err(|_| Error::Directory)?;
        if !safe_directory(&id) {
            return Err(Error::Directory);
        }
        let mut directories = vec![Directory { fd: root, id }];
        for name in &names {
            let parent = directories.last().ok_or(Error::Directory)?;
            let fd = openat(&parent.fd, name, directory_flags(), Mode::empty())
                .map_err(|_| Error::Directory)?;
            let id = fstat(&fd).map_err(|_| Error::Directory)?;
            if !safe_directory(&id) {
                return Err(Error::Directory);
            }
            directories.push(Directory { fd, id });
        }
        let parent = directories.last().ok_or(Error::Directory)?;
        let file = File::from(
            openat(
                &parent.fd,
                "chinwag",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Executable)?,
        );
        let id = fstat(&file).map_err(|_| Error::Executable)?;
        if !safe_image(&id) {
            return Err(Error::Executable);
        }
        let mut image = Self {
            directories,
            names,
            file,
            id,
            expected,
        };
        image.verify()?;
        Ok(image)
    }

    fn verify_names(&self) -> Result<(), Error> {
        for (index, directory) in self.directories.iter().enumerate() {
            let held = fstat(&directory.fd).map_err(|_| Error::Changed)?;
            let named = if index == 0 {
                statat(&directory.fd, "/", AtFlags::SYMLINK_NOFOLLOW)
            } else {
                statat(
                    &self.directories[index - 1].fd,
                    &self.names[index - 1],
                    AtFlags::SYMLINK_NOFOLLOW,
                )
            }
            .map_err(|_| Error::Changed)?;
            if !safe_directory(&held)
                || !same_node(&held, &directory.id)
                || !same_node(&named, &directory.id)
            {
                return Err(Error::Changed);
            }
        }
        let held = fstat(&self.file).map_err(|_| Error::Changed)?;
        let named = statat(
            &self.directories.last().ok_or(Error::Changed)?.fd,
            "chinwag",
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| Error::Changed)?;
        if !safe_image(&held)
            || !same_node(&held, &self.id)
            || !same_node(&named, &self.id)
            || held.st_size != self.id.st_size
            || named.st_size != self.id.st_size
        {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn verify(&mut self) -> Result<(), Error> {
        self.verify_names()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Read)?;
        let mut digest = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = self.file.read(&mut buffer).map_err(|_| Error::Read)?;
            if count == 0 {
                break;
            }
            length += count as u64;
            if length > MAX_IMAGE_BYTES {
                return Err(Error::Read);
            }
            digest.update(&buffer[..count]);
        }
        self.verify_names()?;
        if length != self.id.st_size as u64 {
            return Err(Error::Changed);
        }
        if <[u8; 32]>::from(digest.finalize()) != self.expected {
            return Err(Error::Hash);
        }
        Ok(())
    }
}

/// On success the process is replaced: there is no returned success receipt.
/// All opened descriptors use CLOEXEC; a returned error drops their owners.
/// This function starts no child, runtime, network service, or signing action.
pub(super) fn replace(
    workspace: &Path,
    expected_hex: &str,
    arguments: &[String],
) -> Result<Infallible, Error> {
    if arguments.len() > 32
        || arguments.iter().any(|a| a.len() > 4096 || a.contains('\0'))
        || arguments.iter().map(String::len).sum::<usize>() > 16384
    {
        return Err(Error::Arguments);
    }
    let expected = expected_digest(expected_hex)?;
    let mut image = Image::open(workspace, expected)?;
    let mut command = Command::new(workspace.join("target/release/chinwag"));
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C");
    image.verify()?;
    // Keep the verified handles owned until exec returns or closes CLOEXEC FDs.
    // No parent cwd change or second execution attempt in this module.
    let error = command.exec();
    drop(image);
    Err(Error::Exec {
        os_code: error.raw_os_error(),
    })
}
