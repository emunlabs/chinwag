use crate::{Result, TeamError};
use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
use std::{
    ffi::OsString,
    fs::File,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
};

pub(crate) struct FileLock(pub(crate) File);
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}
pub(crate) fn lock(dir: &File, name: &str) -> Result<FileLock> {
    let file: File = openat(
        dir,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(storage)?
    .into();
    owned_file(&file)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| TeamError::Unavailable)?;
    let lock = FileLock(file);
    named_file(dir, name, &lock.0)?;
    Ok(lock)
}
pub(crate) fn write_new(dir: &File, name: &str, bytes: &[u8]) -> Result<File> {
    let file: File = openat(
        dir,
        name,
        OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(storage)?
    .into();
    owned_file(&file)?;
    file.write_all_at(bytes, 0).map_err(storage)?;
    file.sync_all().map_err(storage)?;
    dir.sync_all().map_err(storage)?;
    named_file(dir, name, &file)?;
    if read_bounded(&file, bytes.len())? != bytes {
        return Err(TeamError::Storage);
    }
    Ok(file)
}
pub(crate) fn verify_root(path: &Path, held: &File) -> Result<()> {
    let (named, _, _) = open_root(path, false)?;
    same_file(held, &named)
}
pub(crate) fn owned_file(file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(storage)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(TeamError::Storage);
    }
    Ok(())
}

pub(crate) fn named_file(directory: &File, name: &str, held: &File) -> Result<()> {
    owned_file(held)?;
    let named: File = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(storage)?
    .into();
    owned_file(&named)?;
    same_file(held, &named)
}

pub(crate) fn same_file(left: &File, right: &File) -> Result<()> {
    let left = left.metadata().map_err(storage)?;
    let right = right.metadata().map_err(storage)?;
    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(TeamError::Storage);
    }
    Ok(())
}

pub(crate) fn read_bounded(file: &File, max: usize) -> Result<Vec<u8>> {
    owned_file(file)?;
    let before = file.metadata().map_err(storage)?;
    if before.len() > max as u64 {
        return Err(TeamError::Storage);
    }
    let mut bytes = vec![0; before.len() as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(storage)?;
        if count == 0 {
            return Err(TeamError::Storage);
        }
        offset += count;
    }
    let after = file.metadata().map_err(storage)?;
    if before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(TeamError::Storage);
    }
    Ok(bytes)
}

pub(crate) fn open_root(root: &Path, create: bool) -> Result<(File, File, OsString)> {
    if !root.is_absolute() || root.as_os_str().len() > 4096 {
        return Err(TeamError::InvalidInput);
    }
    let mut normalized = PathBuf::new();
    for component in root.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(TeamError::InvalidInput);
        }
        normalized.push(component.as_os_str());
    }
    if normalized.as_os_str() != root.as_os_str() {
        return Err(TeamError::InvalidInput);
    }
    let components: Vec<_> = root.components().collect();
    if components.len() < 2 {
        return Err(TeamError::InvalidInput);
    }
    let mut parent: File = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(storage)?
    .into();
    for (index, part) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else {
            return Err(TeamError::InvalidInput);
        };
        let name = *name;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let child: File = match openat(&parent, name, flags, Mode::empty()) {
            Ok(file) => file.into(),
            Err(error)
                if create && index + 1 == components.len() && error == rustix::io::Errno::NOENT =>
            {
                mkdirat(&parent, name, Mode::RWXU).map_err(storage)?;
                parent.sync_all().map_err(storage)?;
                openat(&parent, name, flags, Mode::empty())
                    .map_err(storage)?
                    .into()
            }
            Err(_) => return Err(TeamError::Storage),
        };
        if index + 1 == components.len() {
            let metadata = child.metadata().map_err(storage)?;
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(TeamError::Storage);
            }
            return Ok((child, parent, name.to_os_string()));
        }
        parent = child;
    }
    Err(TeamError::InvalidInput)
}

fn storage(_: impl std::fmt::Display) -> TeamError {
    TeamError::Storage
}
