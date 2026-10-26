//! Held actual current-executable file, not a caller-supplied command or image attestation.
use super::super::{Anchor, checked_close};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, openat, readlinkat, statat};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: i32,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    nlink: u64,
    size: u64,
}
fn identity(s: &rustix::fs::Stat) -> Result<Identity, &'static str> {
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != rustix::process::geteuid().as_raw()
        || s.st_nlink != 1
        || s.st_mode & 0o7022 != 0
        || s.st_mode & 0o500 != 0o500
        || s.st_size <= 0
        || s.st_size as u64 > MAX_EXECUTABLE_BYTES
    {
        return Err("unsafe_current_executable");
    }
    Ok(snapshot(s))
}
fn snapshot(s: &rustix::fs::Stat) -> Identity {
    Identity {
        dev: s.st_dev,
        ino: s.st_ino,
        uid: s.st_uid,
        gid: s.st_gid,
        mode: s.st_mode,
        nlink: u64::from(s.st_nlink),
        size: s.st_size as u64,
    }
}
struct PackagedAlias {
    name: String,
    id: Identity,
}
impl PackagedAlias {
    fn capture(anchor: &Anchor, name: &str, s: &rustix::fs::Stat) -> Result<Self, &'static str> {
        if !matches!(name, "git-chinwag" | "git-emun" | "gh-chinwag" | "gh-emun")
            || FileType::from_raw_mode(s.st_mode) != FileType::Symlink
            || s.st_uid != rustix::process::geteuid().as_raw()
            || s.st_nlink != 1
            || s.st_mode & 0o7000 != 0
            || s.st_size != 7
        {
            return Err("unsafe_current_executable_alias");
        }
        let alias = Self {
            name: name.to_owned(),
            id: snapshot(s),
        };
        alias.verify(anchor)?;
        Ok(alias)
    }
    fn verify(&self, anchor: &Anchor) -> Result<(), &'static str> {
        let named = statat(&anchor.fd, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "current_executable_alias_name")?;
        if snapshot(&named) != self.id {
            return Err("current_executable_alias_changed");
        }
        let target = readlinkat(&anchor.fd, self.name.as_str(), Vec::new())
            .map_err(|_| "current_executable_alias_target")?;
        if target.as_bytes() != b"chinwag" {
            return Err("unsupported_current_executable_alias_target");
        }
        let after = statat(&anchor.fd, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "current_executable_alias_name")?;
        if snapshot(&after) != self.id {
            return Err("current_executable_alias_changed");
        }
        Ok(())
    }
}

pub(super) struct Launcher {
    anchor: Anchor,
    alias: Option<PackagedAlias>,
    file: File,
    name: String,
    command: String,
    id: Identity,
    sha256: [u8; 32],
}
impl Launcher {
    pub(super) fn capture() -> Result<Self, &'static str> {
        let path = std::env::current_exe().map_err(|_| "current_executable_path")?;
        Self::capture_path(path)
    }
    // Only the OS-derived path enters production; the private helper also serves module tests.
    fn capture_path(path: std::path::PathBuf) -> Result<Self, &'static str> {
        let mut command = path.to_str().ok_or("current_executable_utf8")?.to_owned();
        if !path.is_absolute()
            || command.len() > 4096
            || command.contains(['\0', '\r', '\n'])
            || command.contains("${")
        {
            return Err("invalid_current_executable_path");
        }
        let mut name = path
            .file_name()
            .and_then(|x| x.to_str())
            .ok_or("current_executable_basename")?
            .to_owned();
        let anchor =
            Anchor::open_repository(path.parent().ok_or("current_executable_parent")?, None)?;
        let named = statat(&anchor.fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "open_current_executable")?;
        let alias = if FileType::from_raw_mode(named.st_mode) == FileType::Symlink {
            let alias = PackagedAlias::capture(&anchor, &name, &named)?;
            name = "chinwag".to_owned();
            command = path
                .with_file_name("chinwag")
                .to_str()
                .ok_or("current_executable_utf8")?
                .to_owned();
            Some(alias)
        } else {
            None
        };
        let file = File::from(
            openat(
                &anchor.fd,
                name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "open_current_executable")?,
        );
        let id = identity(&fstat(&file).map_err(|_| "current_executable_stat")?)?;
        let mut launcher = Self {
            anchor,
            alias,
            file,
            name,
            command,
            id,
            sha256: [0; 32],
        };
        launcher.sha256 = launcher.read_current()?;
        launcher.verify()?;
        Ok(launcher)
    }
    fn read_current(&mut self) -> Result<[u8; 32], &'static str> {
        self.anchor.check()?;
        if let Some(alias) = &self.alias {
            alias.verify(&self.anchor)?;
        }
        if identity(&fstat(&self.file).map_err(|_| "current_executable_stat")?)? != self.id {
            return Err("current_executable_changed");
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "current_executable_seek")?;
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = self
                .file
                .read(&mut buffer)
                .map_err(|_| "current_executable_read")?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            if bytes > MAX_EXECUTABLE_BYTES {
                return Err("current_executable_limit");
            }
            hash.update(&buffer[..count]);
        }
        let held = identity(&fstat(&self.file).map_err(|_| "current_executable_stat")?)?;
        let named = identity(
            &statat(
                &self.anchor.fd,
                self.name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| "current_executable_name")?,
        )?;
        self.anchor.check()?;
        if let Some(alias) = &self.alias {
            alias.verify(&self.anchor)?;
        }
        if held != self.id || named != self.id || bytes != self.id.size {
            return Err("current_executable_changed");
        }
        Ok(hash.finalize().into())
    }
    fn verify(&mut self) -> Result<(), &'static str> {
        if self.read_current()? != self.sha256 {
            return Err("current_executable_bytes_changed");
        }
        Ok(())
    }
    pub(super) fn command(&self) -> &str {
        &self.command
    }
    pub(super) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub(super) fn finish(mut self) -> Result<(usize, usize), &'static str> {
        let verified = self.verify();
        let Self { anchor, file, .. } = self;
        let file = checked_close::file(file);
        let directories = anchor.close_all();
        verified?;
        file?;
        Ok((1, directories?))
    }
}

#[cfg(test)]
mod tests;
