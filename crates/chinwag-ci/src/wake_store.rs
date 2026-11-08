// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Owner-private once-only wake observations. These records never grant repair
//! authority or prove that an agent is idle. The admitted runtime must establish
//! those facts before recording a transition and before any external effect.
//! Partial persistence is held, never repaired by resetting a reservation.
use crate::storage::CiphertextStore;
use rustix::{
    fd::AsFd,
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat},
    io::Errno,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
    path::Path,
};

const LOCK: &str = "agent-controller-v1.lock";
const MAGIC: &[u8] = b"CHINWAG-CI-OWNED-WAKE-V1\0";
const MAX_METADATA: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WakePhase {
    Initiating = 1,
    Idle = 2,
    Reserved = 3,
    Started = 4,
    Finished = 5,
}
const PHASES: [WakePhase; 5] = [
    WakePhase::Initiating,
    WakePhase::Idle,
    WakePhase::Reserved,
    WakePhase::Started,
    WakePhase::Finished,
];
impl WakePhase {
    fn name(self) -> &'static str {
        match self {
            Self::Initiating => "agent-initiation-v1.json",
            Self::Idle => "agent-idle-v1.json",
            Self::Reserved => "wake-reservation-v1.json",
            Self::Started => "wake-started-v1.json",
            Self::Finished => "wake-finished-v1.json",
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WakeStoreError {
    #[error("wake store or owner binding is unavailable or changed")]
    Store,
    #[error("wake store already has an owner")]
    Busy,
    #[error("wake transition is already consumed or out of sequence")]
    Consumed,
    #[error("wake persistence is uncertain; preserve and reconcile without another launch")]
    Uncertain,
}

pub struct WakeStore {
    directory: CiphertextStore,
    lock: File,
    binding: [u8; 32],
    poisoned: bool,
}

fn private(file: impl AsFd) -> Result<Stat, WakeStoreError> {
    let s = fs::fstat(&file).map_err(|_| WakeStoreError::Store)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != rustix::process::geteuid().as_raw()
        || s.st_mode & 0o7777 != 0o600
        || s.st_nlink != 1
    {
        return Err(WakeStoreError::Store);
    }
    #[cfg(target_os = "macos")]
    crate::macos_acl::require_absent(file.as_fd()).map_err(|_| WakeStoreError::Store)?;
    Ok(s)
}

impl WakeStore {
    /// Explicit first enrollment only. No existing namespace is reset, chmodded
    /// or adopted. The binding is a digest of owner-admitted public configuration.
    pub fn initialize(path: &Path, binding: [u8; 32]) -> Result<Self, WakeStoreError> {
        let directory = CiphertextStore::open(path).map_err(|_| WakeStoreError::Store)?;
        if binding == [0; 32] {
            return Err(WakeStoreError::Store);
        }
        // A lost lock cannot erase prior observations or permit re-enrollment.
        for phase in PHASES {
            match fs::statat(
                directory.directory(),
                phase.name(),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(Errno::NOENT) => {}
                _ => return Err(WakeStoreError::Store),
            }
        }
        let mode = Mode::RUSR | Mode::WUSR;
        let fd = fs::openat(
            directory.directory(),
            LOCK,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            mode,
        )
        .map_err(|_| WakeStoreError::Store)?;
        fs::fchmod(&fd, mode).map_err(|_| WakeStoreError::Uncertain)?;
        private(&fd)?;
        fs::flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| WakeStoreError::Busy)?;
        let mut store = Self {
            directory,
            lock: File::from(fd),
            binding,
            poisoned: true,
        };
        store
            .lock
            .write_all(MAGIC)
            .map_err(|_| WakeStoreError::Uncertain)?;
        store
            .lock
            .write_all(&binding)
            .map_err(|_| WakeStoreError::Uncertain)?;
        store
            .lock
            .sync_all()
            .map_err(|_| WakeStoreError::Uncertain)?;
        fs::fsync(store.directory.directory()).map_err(|_| WakeStoreError::Uncertain)?;
        store.index()?;
        store.poisoned = false;
        Ok(store)
    }

    /// Reopen only this original enrolled namespace. Missing, partial or orphaned
    /// observations refuse before a caller may start any agent process.
    pub fn open(path: &Path, binding: [u8; 32]) -> Result<Self, WakeStoreError> {
        let directory = CiphertextStore::open(path).map_err(|_| WakeStoreError::Store)?;
        let fd = fs::openat(
            directory.directory(),
            LOCK,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| WakeStoreError::Store)?;
        private(&fd)?;
        fs::flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| WakeStoreError::Busy)?;
        let store = Self {
            directory,
            lock: File::from(fd),
            binding,
            poisoned: false,
        };
        store.index()?;
        Ok(store)
    }

    fn named(&self, name: &str, observed: &Stat) -> Result<(), WakeStoreError> {
        self.directory.check().map_err(|_| WakeStoreError::Store)?;
        let named = fs::statat(self.directory.directory(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| WakeStoreError::Store)?;
        if named.st_dev != observed.st_dev
            || named.st_ino != observed.st_ino
            || named.st_size != observed.st_size
            || named.st_nlink != 1
        {
            return Err(WakeStoreError::Store);
        }
        Ok(())
    }

    fn bytes(&self, phase: WakePhase) -> Result<Vec<u8>, WakeStoreError> {
        let fd = fs::openat(
            self.directory.directory(),
            phase.name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| WakeStoreError::Store)?;
        let start = private(&fd)?;
        if start.st_size < 1 || start.st_size as u64 > MAX_METADATA {
            return Err(WakeStoreError::Store);
        }
        let mut file = File::from(fd);
        let mut bytes = Vec::with_capacity(start.st_size as usize);
        (&mut file)
            .take(MAX_METADATA + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| WakeStoreError::Store)?;
        let end = private(&file)?;
        if end.st_size != start.st_size || bytes.len() as i64 != start.st_size {
            return Err(WakeStoreError::Store);
        }
        self.named(phase.name(), &end)?;
        Ok(bytes)
    }

    fn index(&self) -> Result<Vec<(WakePhase, [u8; 32])>, WakeStoreError> {
        let start = private(&self.lock)?;
        let header = MAGIC.len() + 32;
        if self.binding == [0; 32]
            || start.st_size < header as i64
            || start.st_size > (header + PHASES.len() * 33) as i64
        {
            return Err(WakeStoreError::Store);
        }
        let mut bytes = vec![0; start.st_size as usize];
        let mut offset = 0;
        while offset < bytes.len() {
            let n = self
                .lock
                .read_at(&mut bytes[offset..], offset as u64)
                .map_err(|_| WakeStoreError::Store)?;
            if n == 0 {
                return Err(WakeStoreError::Store);
            }
            offset += n;
        }
        if &bytes[..MAGIC.len()] != MAGIC
            || bytes[MAGIC.len()..header] != self.binding
            || !(bytes.len() - header).is_multiple_of(33)
        {
            return Err(WakeStoreError::Store);
        }
        let mut index = Vec::new();
        for (n, record) in bytes[header..].chunks_exact(33).enumerate() {
            let phase = PHASES[n];
            if record[0] != phase as u8 {
                return Err(WakeStoreError::Store);
            }
            let hash: [u8; 32] = record[1..].try_into().map_err(|_| WakeStoreError::Store)?;
            if <[u8; 32]>::from(Sha256::digest(self.bytes(phase)?)) != hash {
                return Err(WakeStoreError::Store);
            }
            index.push((phase, hash));
        }
        // An unindexed file is an uncertain interrupted commit, not a fresh
        // transition. An indexed missing/changed file was already refused above.
        for phase in PHASES.iter().skip(index.len()) {
            match fs::statat(
                self.directory.directory(),
                phase.name(),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(Errno::NOENT) => {}
                _ => return Err(WakeStoreError::Store),
            }
        }
        let end = private(&self.lock)?;
        if end.st_size != start.st_size {
            return Err(WakeStoreError::Store);
        }
        self.named(LOCK, &end)?;
        Ok(index)
    }

    /// Persist, sync and independently reopen before returning. A reservation
    /// must succeed here BEFORE spawn; any uncertainty consumes this attempt.
    pub fn record<T: Serialize>(
        &mut self,
        phase: WakePhase,
        value: &T,
    ) -> Result<(), WakeStoreError> {
        if self.poisoned {
            return Err(WakeStoreError::Uncertain);
        }
        let prior = self.index()?;
        if PHASES.get(prior.len()) != Some(&phase) {
            return Err(WakeStoreError::Consumed);
        }
        let bytes = serde_json::to_vec(value).map_err(|_| WakeStoreError::Store)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_METADATA {
            return Err(WakeStoreError::Store);
        }
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        self.poisoned = true;
        let mode = Mode::RUSR | Mode::WUSR;
        let fd = fs::openat(
            self.directory.directory(),
            phase.name(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            mode,
        )
        .map_err(|_| WakeStoreError::Uncertain)?;
        fs::fchmod(&fd, mode).map_err(|_| WakeStoreError::Uncertain)?;
        let mut file = File::from(fd);
        file.write_all(&bytes)
            .map_err(|_| WakeStoreError::Uncertain)?;
        file.sync_all().map_err(|_| WakeStoreError::Uncertain)?;
        self.named(phase.name(), &private(&file)?)?;
        fs::fsync(self.directory.directory()).map_err(|_| WakeStoreError::Uncertain)?;
        self.lock
            .seek(SeekFrom::End(0))
            .map_err(|_| WakeStoreError::Uncertain)?;
        self.lock
            .write_all(&[phase as u8])
            .map_err(|_| WakeStoreError::Uncertain)?;
        self.lock
            .write_all(&hash)
            .map_err(|_| WakeStoreError::Uncertain)?;
        self.lock
            .sync_all()
            .map_err(|_| WakeStoreError::Uncertain)?;
        fs::fsync(self.directory.directory()).map_err(|_| WakeStoreError::Uncertain)?;
        if self.index()?.last() != Some(&(phase, hash)) {
            return Err(WakeStoreError::Uncertain);
        }
        self.poisoned = false;
        Ok(())
    }

    pub fn read<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        phase: WakePhase,
    ) -> Result<T, WakeStoreError> {
        let expected = self
            .index()?
            .into_iter()
            .find(|(p, _)| *p == phase)
            .map(|(_, hash)| hash)
            .ok_or(WakeStoreError::Store)?;
        self.read_bound(phase, expected)
    }

    fn read_bound<T: Serialize + for<'a> Deserialize<'a>>(
        &self,
        phase: WakePhase,
        expected: [u8; 32],
    ) -> Result<T, WakeStoreError> {
        let bytes = self.bytes(phase)?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != expected {
            return Err(WakeStoreError::Store);
        }
        let value: T = serde_json::from_slice(&bytes).map_err(|_| WakeStoreError::Store)?;
        if serde_json::to_vec(&value).map_err(|_| WakeStoreError::Store)? != bytes {
            return Err(WakeStoreError::Store);
        }
        Ok(value)
    }
}
impl Drop for WakeStore {
    fn drop(&mut self) {
        let _ = fs::flock(&self.lock, FlockOperation::NonBlockingUnlock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn directory() -> tempfile::TempDir {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let p = tempfile::tempdir_in(parent).unwrap();
        std::fs::set_permissions(p.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }
    #[test]
    fn restart_preserves_consumed_reservation_and_excludes_concurrent_owners() {
        let p = directory();
        let mut s = WakeStore::initialize(p.path(), [1; 32]).unwrap();
        assert!(matches!(
            WakeStore::open(p.path(), [1; 32]),
            Err(WakeStoreError::Busy)
        ));
        assert!(WakeStore::initialize(p.path(), [1; 32]).is_err());
        assert_eq!(
            s.record(WakePhase::Reserved, &"failure"),
            Err(WakeStoreError::Consumed)
        );
        for phase in [WakePhase::Initiating, WakePhase::Idle, WakePhase::Reserved] {
            s.record(phase, &"original").unwrap();
        }
        drop(s);
        assert!(WakeStore::open(p.path(), [2; 32]).is_err());
        let mut s = WakeStore::open(p.path(), [1; 32]).unwrap();
        assert_eq!(s.read::<String>(WakePhase::Reserved).unwrap(), "original");
        assert_eq!(
            s.record(WakePhase::Reserved, &"duplicate"),
            Err(WakeStoreError::Consumed)
        );
        s.record(WakePhase::Started, &"actual-child").unwrap();
        s.record(WakePhase::Finished, &"actual-exit").unwrap();
        assert_eq!(
            s.record(WakePhase::Reserved, &"replay"),
            Err(WakeStoreError::Consumed)
        );
    }
    #[test]
    fn orphan_partial_missing_and_replaced_records_never_become_new_authority() {
        for mode in [
            "orphan", "partial", "missing", "changed", "hardlink", "symlink",
        ] {
            let p = directory();
            let mut s = WakeStore::initialize(p.path(), [3; 32]).unwrap();
            if mode == "orphan" {
                std::fs::write(p.path().join(WakePhase::Initiating.name()), b"\"orphan\"").unwrap();
            } else {
                s.record(WakePhase::Initiating, &"original").unwrap();
                let f = p.path().join(WakePhase::Initiating.name());
                match mode {
                    "partial" => {
                        s.lock.seek(SeekFrom::End(0)).unwrap();
                        s.lock.write_all(&[2]).unwrap();
                        s.lock.sync_all().unwrap();
                    }
                    "missing" => std::fs::remove_file(&f).unwrap(),
                    "changed" => std::fs::write(&f, b"\"tampered\"").unwrap(),
                    "hardlink" => std::fs::hard_link(&f, p.path().join("extra")).unwrap(),
                    "symlink" => {
                        std::fs::rename(&f, p.path().join("preserved")).unwrap();
                        symlink(p.path().join("preserved"), &f).unwrap();
                    }
                    _ => unreachable!(),
                }
            }
            drop(s);
            assert!(WakeStore::open(p.path(), [3; 32]).is_err(), "{mode}");
            assert!(WakeStore::initialize(p.path(), [3; 32]).is_err(), "{mode}");
        }
    }
    #[test]
    fn wrong_mode_symlinked_directory_or_lost_lock_is_not_automatic_reenrollment() {
        let p = directory();
        let mut s = WakeStore::initialize(p.path(), [4; 32]).unwrap();
        s.record(WakePhase::Initiating, &"original").unwrap();
        drop(s);
        std::fs::set_permissions(p.path().join(LOCK), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(WakeStore::open(p.path(), [4; 32]).is_err());
        std::fs::remove_file(p.path().join(LOCK)).unwrap();
        assert!(WakeStore::initialize(p.path(), [4; 32]).is_err());
        let other = directory();
        symlink(p.path(), other.path().join("link")).unwrap();
        assert!(WakeStore::open(&other.path().join("link"), [4; 32]).is_err());
    }

    #[test]
    fn replacement_between_index_validation_and_reopen_cannot_return_uncommitted_data() {
        let p = directory();
        let mut s = WakeStore::initialize(p.path(), [5; 32]).unwrap();
        s.record(WakePhase::Initiating, &"original").unwrap();
        let expected = s.index().unwrap()[0].1;
        std::fs::write(p.path().join(WakePhase::Initiating.name()), b"\"tampered\"").unwrap();
        assert!(
            s.read_bound::<String>(WakePhase::Initiating, expected)
                .is_err()
        );
    }
}
