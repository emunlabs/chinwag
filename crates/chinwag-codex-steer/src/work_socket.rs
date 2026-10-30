//! Metadata for one explicitly declared local listener, including Codex's
//! documented final symlink. No defaults, directory search or process adoption.

use crate::{
    Result, SteerError,
    journal::{open_root, same_file},
    work_api::valid_path,
};
use std::{
    fs::{self, File, Metadata},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};
use tokio::net::UnixStream;

pub(crate) struct SelectedDirectory {
    path: PathBuf,
    held: File,
}
impl SelectedDirectory {
    pub(crate) fn observe(path: &Path) -> Result<Self> {
        let held = open_selected_directory(path)?;
        Ok(Self {
            path: path.into(),
            held,
        })
    }
    pub(crate) fn verify(&self) -> Result<()> {
        let current = open_selected_directory(&self.path)?;
        same_file(&current, &self.held)
    }
}
fn open_selected_directory(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    if !valid_path(path) {
        return Err(SteerError::InvalidInput);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory: File = open("/", flags, Mode::empty()).map_err(unavailable)?.into();
    for component in path.components().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(SteerError::InvalidInput);
        };
        directory = openat(&directory, name, flags, Mode::empty())
            .map_err(unavailable)?
            .into();
    }
    let metadata = directory.metadata().map_err(unavailable)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(SteerError::PermissionDenied);
    }
    Ok(directory)
}

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    ctime: i64,
    ctime_nsec: i64,
}
impl Identity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

pub(crate) struct SelectedSocket {
    alias: PathBuf,
    target: PathBuf,
    link: Option<PathBuf>,
    alias_identity: Identity,
    target_identity: Identity,
    alias_parent: File,
    target_parent: File,
}

impl SelectedSocket {
    pub(crate) fn observe(alias: &Path) -> Result<Self> {
        if !valid_path(alias) {
            return Err(SteerError::InvalidInput);
        }
        let (alias_parent, _, _) =
            open_root(alias.parent().ok_or(SteerError::InvalidInput)?, false)?;
        let metadata = fs::symlink_metadata(alias).map_err(unavailable)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(SteerError::PermissionDenied);
        }
        let link = if metadata.file_type().is_symlink() {
            Some(fs::read_link(alias).map_err(unavailable)?)
        } else {
            None
        };
        let target = match &link {
            Some(path) if path.is_absolute() => path.clone(),
            Some(path) => alias.parent().ok_or(SteerError::InvalidInput)?.join(path),
            None => alias.into(),
        };
        if !valid_path(&target) || target.as_os_str().len() > 4096 {
            return Err(SteerError::InvalidInput);
        }
        let (target_parent, _, _) =
            open_root(target.parent().ok_or(SteerError::InvalidInput)?, false)?;
        let physical = fs::symlink_metadata(&target).map_err(unavailable)?;
        if !physical.file_type().is_socket()
            || physical.uid() != rustix::process::geteuid().as_raw()
            || physical.mode() & 0o7777 != 0o600
        {
            return Err(SteerError::PermissionDenied);
        }
        let result = Self {
            alias: alias.into(),
            target,
            link,
            alias_identity: Identity::of(&metadata),
            target_identity: Identity::of(&physical),
            alias_parent,
            target_parent,
        };
        result.verify()?;
        Ok(result)
    }

    pub(crate) fn verify(&self) -> Result<()> {
        let (alias_parent, _, _) =
            open_root(self.alias.parent().ok_or(SteerError::InvalidInput)?, false)?;
        let (target_parent, _, _) =
            open_root(self.target.parent().ok_or(SteerError::InvalidInput)?, false)?;
        same_file(&alias_parent, &self.alias_parent)?;
        same_file(&target_parent, &self.target_parent)?;
        let metadata = fs::symlink_metadata(&self.alias).map_err(unavailable)?;
        let physical = fs::symlink_metadata(&self.target).map_err(unavailable)?;
        if Identity::of(&metadata) != self.alias_identity
            || Identity::of(&physical) != self.target_identity
        {
            return Err(SteerError::Unavailable);
        }
        if let Some(link) = &self.link {
            if !metadata.file_type().is_symlink()
                || fs::read_link(&self.alias).map_err(unavailable)? != *link
            {
                return Err(SteerError::Unavailable);
            }
        } else if !metadata.file_type().is_socket() {
            return Err(SteerError::Unavailable);
        }
        if !physical.file_type().is_socket() {
            return Err(SteerError::Unavailable);
        }
        Ok(())
    }

    pub(crate) async fn connect(self) -> Result<UnixStream> {
        let pin = tokio::task::spawn_blocking(move || {
            self.verify()?;
            Ok(self)
        })
        .await
        .map_err(|_| SteerError::Unavailable)??;
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            UnixStream::connect(&pin.target),
        )
        .await
        .map_err(|_| SteerError::Unavailable)?
        .map_err(unavailable)?;
        if stream.peer_cred().map_err(unavailable)?.uid() != rustix::process::geteuid().as_raw() {
            return Err(SteerError::PermissionDenied);
        }
        tokio::task::spawn_blocking(move || pin.verify())
            .await
            .map_err(|_| SteerError::Unavailable)??;
        Ok(stream)
    }
}

fn unavailable(_: impl std::fmt::Display) -> SteerError {
    SteerError::Unavailable
}

#[cfg(test)]
mod tests;
