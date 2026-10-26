//! Shared private filesystem boundaries for bundle operations.
use crate::cargo::CommandReport;
use rustix::fs::{Mode, OFlags, open};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bundle intake operator scope rejected")]
    Scope,
    #[error("bundle intake already attempted; preserve the quarantine")]
    AlreadyAttempted,
    #[error("bundle intake is already running")]
    Busy,
    #[error(transparent)]
    Metadata(#[from] crate::bundle::Error),
    #[error("bundle intake filesystem operation failed")]
    Filesystem(#[from] std::io::Error),
    #[error(transparent)]
    Process(#[from] crate::cargo::Error),
    // Bounded diagnostics remain local. A future MCP adapter must not expose
    // this report or operator paths in its public error response.
    #[error("bundle Git {stage} failed")]
    Git {
        stage: &'static str,
        report: Box<CommandReport>,
    },
    #[error("received object is not the expected commit and tree")]
    Object,
    #[error("quarantine unexpectedly contains Git refs")]
    Refs,
}

pub(crate) fn prefixed(prefix: &str, path: &Path) -> OsString {
    let mut value = OsString::from(prefix);
    value.push(path.as_os_str());
    value
}

pub(crate) fn canonical(path: &Path) -> Result<PathBuf, Error> {
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err(Error::Scope);
    }
    Ok(path.to_owned())
}

pub(crate) fn private_empty_directory(path: &Path) -> Result<File, Error> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || fs::read_dir(path)?.next().is_some()
    {
        return Err(Error::Scope);
    }
    Ok(file)
}

pub(crate) fn private_directory(path: &Path) -> Result<File, Error> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::Scope);
    }
    Ok(file)
}

pub(crate) fn private_file(path: &Path) -> Result<File, Error> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::Scope);
    }
    Ok(file)
}

pub(crate) fn bounded_read(file: &mut File, limit: usize) -> Result<Vec<u8>, Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Scope);
    }
    Ok(bytes)
}
