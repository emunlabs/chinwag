//! Private, single-rename cursor/quota transactions. Never performs host IPC.
#![forbid(unsafe_code)]

use crate::bus_wait_message::{decode, hash, hex};
use crate::{agent_instance::ActorAddress, bus_identity::BusDirectory};
use rand::{TryRngCore, rngs::OsRng};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, mkdirat, openat, renameat};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub type Result<T> = std::result::Result<T, String>;
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
fn io(error: impl std::fmt::Display) -> String {
    format!("WAIT_STORE_UNAVAILABLE: {error}")
}

pub fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).map_err(io)?;
    Ok(hex(&bytes))
}

fn validate_file(file: &File, private: bool) -> Result<()> {
    let m = file.metadata().map_err(io)?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.nlink() != 1
        || (private && m.mode() & 0o7777 != 0o600)
        || (!private && m.mode() & 0o7022 != 0)
    {
        return Err("UNSAFE_CURSOR_OR_ENROLLMENT_PATH".into());
    }
    Ok(())
}

pub fn read_private_path(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let file = File::from(fd);
    validate_file(&file, true)?;
    read_bounded(file, bound)
}
fn read_bounded(file: File, bound: usize) -> Result<Vec<u8>> {
    if file.metadata().map_err(io)?.len() > bound as u64 {
        return Err("WAIT_INPUT_OVERSIZE".into());
    }
    let mut bytes = Vec::new();
    file.take(bound as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() > bound {
        return Err("WAIT_INPUT_OVERSIZE".into());
    }
    Ok(bytes)
}

pub struct PrivateStore {
    bus: BusDirectory,
    directory: File,
    directory_name: &'static str,
    stem: String,
}
impl PrivateStore {
    pub fn open(repo: &Path, directory_name: &'static str, actor: &str) -> Result<Self> {
        if !matches!(directory_name, "cursors" | "enrollments") {
            return Err("INVALID_STORE".into());
        }
        let address = ActorAddress::parse(actor)
            .and_then(ActorAddress::require_instance)
            .map_err(io)?;
        let bus = BusDirectory::open(repo).map_err(io)?;
        match mkdirat(&bus, directory_name, Mode::from_raw_mode(0o700)) {
            Ok(()) => (),
            Err(e) if e == rustix::io::Errno::EXIST => (),
            Err(e) => return Err(io(e)),
        }
        let directory = File::from(
            openat(
                &bus,
                directory_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        let m = directory.metadata().map_err(io)?;
        if !m.is_dir()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o7777 != 0o700
        {
            return Err("UNSAFE_CURSOR_OR_ENROLLMENT_PATH".into());
        }
        let stem = format!(
            "{}--{}",
            address.seat().to_ascii_lowercase(),
            hash(actor.as_bytes())
        );
        Ok(Self {
            bus,
            directory,
            directory_name,
            stem,
        })
    }
    fn verify(&self) -> Result<()> {
        self.bus.verify().map_err(io)?;
        let named = File::from(
            openat(
                &self.bus,
                self.directory_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(io)?,
        );
        let a = self.directory.metadata().map_err(io)?;
        let b = named.metadata().map_err(io)?;
        if a.ino() != b.ino()
            || a.dev() != b.dev()
            || b.mode() & 0o7777 != 0o700
            || b.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("WAIT_NAMESPACE_CHANGED".into());
        }
        Ok(())
    }
    fn open_named(&self, name: &str) -> Result<Option<File>> {
        self.verify()?;
        let fd = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(e) if e == rustix::io::Errno::NOENT => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let file = File::from(fd);
        validate_file(&file, true)?;
        Ok(Some(file))
    }
    pub fn read<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        self.open_named(&format!("{}.json", self.stem))?
            .map(|file| {
                let bytes = read_bounded(file, MAX_STATE_BYTES)?;
                serde_json::from_slice(&bytes).map_err(io)
            })
            .transpose()
    }
    pub fn read_named_bytes(&self, name: &str, bound: usize) -> Result<Vec<u8>> {
        if name.contains('/') || name.starts_with('.') {
            return Err("INVALID_STORE_NAME".into());
        }
        read_bounded(self.open_named(name)?.ok_or("WAIT_FILE_MISSING")?, bound)
    }
    pub fn lock(&self) -> Result<StoreLock<'_>> {
        self.verify()?;
        let file = File::from(
            openat(
                &self.directory,
                format!("{}.lock", self.stem),
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(io)?,
        );
        validate_file(&file, true)?;
        if file.metadata().map_err(io)?.len() != 0 {
            return Err("UNSAFE_LOCK_FILE".into());
        }
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "WAIT_STORE_BUSY".to_string())?;
        Ok(StoreLock {
            store: self,
            _file: file,
        })
    }
    pub fn token_name(&self, delivery_id: &str) -> Result<String> {
        decode::<32>(delivery_id)?;
        Ok(format!("{}--{delivery_id}.token", self.stem))
    }
    pub fn token_path(&self, repo: &Path, delivery_id: &str) -> Result<std::path::PathBuf> {
        Ok(repo
            .join(".chinwag/bus/cursors")
            .join(self.token_name(delivery_id)?))
    }
    pub fn write_new_token(&self, delivery_id: &str, token: &str) -> Result<()> {
        decode::<32>(token)?;
        self.verify()?;
        let file = openat(
            &self.directory,
            self.token_name(delivery_id)?,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(io)?;
        let mut file = File::from(file);
        file.write_all(token.as_bytes()).map_err(io)?;
        file.sync_all().map_err(io)?;
        self.directory.sync_all().map_err(io)
    }
    pub fn read_token(&self, delivery_id: &str) -> Result<String> {
        let bytes = self.read_named_bytes(&self.token_name(delivery_id)?, 64)?;
        let token = String::from_utf8(bytes).map_err(io)?;
        decode::<32>(&token)?;
        Ok(token)
    }
    pub fn remove_token(&self, delivery_id: &str) -> Result<()> {
        self.verify()?;
        let name = self.token_name(delivery_id)?;
        if self.open_named(&name)?.is_some() {
            rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
                .map_err(io)?;
            self.directory.sync_all().map_err(io)?;
        }
        Ok(())
    }
}

/// The lock is owned by this descriptor and released on drop. Callers must
/// drop it before any host lookup, stdout write, native wait or IPC operation.
pub struct StoreLock<'a> {
    store: &'a PrivateStore,
    _file: File,
}
impl StoreLock<'_> {
    pub fn write<T: Serialize>(&self, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(io)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err("BACKPRESSURE_PENDING_FULL".into());
        }
        self.store.verify()?;
        let target = format!("{}.json", self.store.stem);
        // Refuse an unsafe preimage rather than replacing a symlink or hardlink.
        self.store.open_named(&target)?;
        let temp = format!("{}--{}.tmp", self.store.stem, random_token()?);
        let mut file = File::from(
            openat(
                &self.store.directory,
                &temp,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(io)?,
        );
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        self.store.verify()?;
        renameat(&self.store.directory, &temp, &self.store.directory, target).map_err(io)?;
        self.store.directory.sync_all().map_err(io)?;
        self.store.verify()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub id: String,
    pub digest: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn atomic_state_is_private_lock_excludes_other_owner_and_unsafe_names_refuse() {
        let repo = tempfile::tempdir().unwrap();
        let store = PrivateStore::open(repo.path(), "cursors", "WORKHORSE#fixture").unwrap();
        let lock = store.lock().unwrap();
        lock.write(&Witness {
            id: "one".into(),
            digest: "two".into(),
        })
        .unwrap();
        assert!(store.lock().is_err());
        drop(lock);
        assert_eq!(store.read::<Witness>().unwrap().unwrap().id, "one");
        let filename = repo
            .path()
            .join(".chinwag/bus/cursors")
            .join(format!("{}.json", store.stem));
        assert_eq!(fs::metadata(&filename).unwrap().mode() & 0o777, 0o600);
        fs::set_permissions(&filename, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.read::<Witness>().is_err());
        fs::remove_file(&filename).unwrap();
        symlink(repo.path().join("unrelated"), &filename).unwrap();
        assert!(store.read::<Witness>().is_err());
    }
}
