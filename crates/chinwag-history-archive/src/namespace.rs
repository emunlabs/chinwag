// Copyright (c) 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//! Reuses the descriptor traversal and nonblocking open contract from
//! chinwag-cli task_resource_path / bus_recovery_run selected-file readers.
//! Pins each parent while opening its child. This rejects symlink ancestry;
//! it does not fence an uncooperative same-UID writer of later DuckDB paths.
use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
use std::os::unix::fs::MetadataExt;
use std::{
    fs::File,
    path::{Component, Path, PathBuf},
};
fn absolute(path: &Path) -> Result<PathBuf, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "current directory unavailable")?
            .join(path)
    };
    if path.as_os_str().len() > 4096
        || path.components().count() > 64
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err("path outside namespace bounds; use absolute paths".into());
    }
    Ok(path)
}
fn parent(path: &Path) -> Result<(File, std::ffi::OsString), String> {
    let path = absolute(path)?;
    let mut names = path
        .components()
        .filter_map(|c| {
            if let Component::Normal(n) = c {
                Some(n.to_os_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let leaf = names.pop().ok_or("path requires a leaf")?;
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let mut fd =
        File::from(open("/", flags, Mode::empty()).map_err(|_| "namespace root unavailable")?);
    for name in names {
        fd = File::from(
            openat(&fd, name.as_os_str(), flags, Mode::empty())
                .map_err(|_| "symlink or invalid namespace ancestor")?,
        );
    }
    Ok((fd, leaf))
}
pub(crate) fn open_checked(path: &Path, directory: bool) -> Result<File, String> {
    let (parent, leaf) = parent(path)?;
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    let file = File::from(
        openat(&parent, leaf.as_os_str(), flags, Mode::empty())
            .map_err(|_| "symlink or invalid namespace leaf")?,
    );
    let m = file.metadata().map_err(|_| "file metadata unavailable")?;
    if (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink() != 1))
        || m.uid() != rustix::process::getuid().as_raw()
    {
        return Err("file type, owner or link policy rejected".into());
    }
    Ok(file)
}
pub(crate) fn create_file(path: &Path) -> Result<File, String> {
    let (parent, leaf) = parent(path)?;
    openat(
        &parent,
        leaf.as_os_str(),
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        Mode::from_bits_truncate(0o600),
    )
    .map(File::from)
    .map_err(|_| "immutable file creation rejected".into())
}
pub(crate) fn mkdir_private(path: &Path) -> Result<(), String> {
    let (parent, leaf) = parent(path)?;
    mkdirat(&parent, leaf.as_os_str(), Mode::from_bits_truncate(0o700))
        .map_err(|_| "private directory creation rejected".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_symlink_ancestors_and_fifo_without_blocking() {
        let base = PathBuf::from(std::env::var("TMPDIR").expect("owned TMPDIR required"));
        let dir = base.join(format!("namespace-test-{}", std::process::id()));
        mkdir_private(&dir).unwrap();
        let real = dir.join("physical");
        mkdir_private(&real).unwrap();
        let file = real.join("event.jsonl");
        create_file(&file).unwrap();
        let link = dir.join("redirect");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_checked(&link.join("event.jsonl"), false).is_err());
        assert!(open_checked(&link, true).is_err());
        let deep = real.join("deep");
        mkdir_private(&deep).unwrap();
        assert!(open_checked(&link.join("deep"), true).is_err());
        let fifo = real.join("pipe");
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let start = std::time::Instant::now();
        assert!(open_checked(&fifo, false).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
