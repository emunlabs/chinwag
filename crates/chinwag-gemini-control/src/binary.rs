//! Metadata/digest pin of one declared native file. Pathname execution still
//! has a check-to-exec race; this is not an atomic inode/vendor authenticity claim.
use crate::{GeminiError, Result, WorkConfig};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
const MAX_BINARY: u64 = 512 * 1024 * 1024;
#[derive(PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Identity {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            uid: m.uid(),
            mode: m.mode(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}
pub(crate) struct BinaryPin {
    path: PathBuf,
    file: File,
    identity: Identity,
    digest: String,
}
impl BinaryPin {
    pub(crate) fn open(config: &WorkConfig) -> Result<Self> {
        let (file, identity, digest) = inspect(&config.binary)?;
        if digest != config.sha256 {
            return Err(GeminiError::Unavailable);
        }
        Ok(Self {
            path: config.binary.clone(),
            file,
            identity,
            digest,
        })
    }
    pub(crate) fn verify(&self) -> Result<()> {
        let (_, identity, digest) = inspect(&self.path)?;
        if identity != self.identity
            || digest != self.digest
            || Identity::of(&self.file.metadata().map_err(|_| GeminiError::Unavailable)?)
                != self.identity
        {
            Err(GeminiError::Unavailable)
        } else {
            Ok(())
        }
    }
}
fn native(header: &[u8]) -> bool {
    #[cfg(target_os = "macos")]
    {
        if header.len() < 8 {
            return false;
        }
        let magic: [u8; 4] = header[..4].try_into().unwrap();
        let arch = if matches!(magic, [0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe]) {
            u32::from_le_bytes(header[4..8].try_into().unwrap())
        } else {
            u32::from_be_bytes(header[4..8].try_into().unwrap())
        };
        let expected = if cfg!(target_arch = "aarch64") {
            0x0100000c
        } else {
            0x01000007
        };
        matches!(magic, [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe]) && arch == expected
    }
    #[cfg(not(target_os = "macos"))]
    {
        header.starts_with(b"\x7fELF")
            && header.get(4) == Some(&2)
            && header.get(5) == Some(&1)
            && header.len() >= 20
            && u16::from_le_bytes(header[18..20].try_into().unwrap())
                == if cfg!(target_arch = "aarch64") {
                    183
                } else {
                    62
                }
    }
}
fn inspect(path: &Path) -> Result<(File, Identity, String)> {
    if !crate::api::valid_path(path)
        || fs::canonicalize(path).map_err(|_| GeminiError::Unavailable)? != path
    {
        return Err(GeminiError::InvalidInput);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC)
                .bits() as i32,
        )
        .open(path)
        .map_err(|_| GeminiError::Unavailable)?;
    let before = file.metadata().map_err(|_| GeminiError::Unavailable)?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o100 == 0
        || before.mode() & 0o022 != 0
        || before.len() < 32
        || before.len() > MAX_BINARY
    {
        return Err(GeminiError::InvalidInput);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut length = 0u64;
    let mut first = true;
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| GeminiError::Unavailable)?;
        if n == 0 {
            break;
        }
        if first {
            if !native(&buffer[..n]) {
                return Err(GeminiError::InvalidInput);
            }
            first = false;
        }
        length = length
            .checked_add(n as u64)
            .ok_or(GeminiError::Unavailable)?;
        if length > MAX_BINARY || length > before.len() {
            return Err(GeminiError::Unavailable);
        }
        hasher.update(&buffer[..n]);
    }
    let after = file.metadata().map_err(|_| GeminiError::Unavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| GeminiError::Unavailable)?;
    let identity = Identity::of(&before);
    if length != before.len()
        || identity != Identity::of(&after)
        || identity != Identity::of(&named)
    {
        return Err(GeminiError::Unavailable);
    }
    Ok((file, identity, format!("{:x}", hasher.finalize())))
}
pub(crate) fn work_directory(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    if !crate::api::valid_path(path) {
        return Err(GeminiError::InvalidInput);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut held: File = open("/", flags, Mode::empty())
        .map_err(|_| GeminiError::Unavailable)?
        .into();
    for p in path.components().skip(1) {
        let std::path::Component::Normal(p) = p else {
            return Err(GeminiError::InvalidInput);
        };
        held = openat(&held, p, flags, Mode::empty())
            .map_err(|_| GeminiError::Unavailable)?
            .into();
    }
    let m = held.metadata().map_err(|_| GeminiError::Unavailable)?;
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o022 != 0 {
        return Err(GeminiError::PermissionDenied);
    }
    Ok(held)
}
pub(crate) fn verify_directory(path: &Path, held: &File) -> Result<()> {
    let fresh = work_directory(path)?;
    crate::journal::same_file(held, &fresh)
}

#[cfg(test)]
mod tests;
