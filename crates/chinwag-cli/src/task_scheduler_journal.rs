#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Bounded durable scheduler evidence, separate from the task-file CAS journal.
//!
//! The caller supplies an already admitted authority-directory descriptor and
//! validates scheduler record semantics after replay. This journal establishes
//! neither a scheduler grant nor the authority of fields in a JSON object.
//! It retains its own directory open description, lock and fixed-file binding.
//! The caller must additionally preserve the authority directory's binding in
//! the wider workspace namespace; an fd alone cannot detect a pathname rename.

use crate::task_write_journal::{JournalError as WriterJournalError, strict_json_object};
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, openat, statat,
};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};

pub(crate) const SCHEDULER_JOURNAL_FILE_NAME: &str = "scheduler-admissions-v1.ndjson";
/// Includes the one terminating newline, which callers do not pass to append.
pub(crate) const MAX_SCHEDULER_RECORD_BYTES: usize = 65_536;
pub(crate) const MAX_SCHEDULER_FILE_BYTES: u64 = 16_777_216;
pub(crate) const MAX_SCHEDULER_RECORDS: usize = 4_096;

#[derive(Debug)]
pub(crate) enum SchedulerJournalError {
    Io(io::Error),
    UnsafeMetadata,
    LockUnavailable,
    RecordTooLarge,
    FileLimit,
    RecordLimit,
    InvalidReservation,
    InvalidJson,
    DuplicateJsonKey,
    CorruptJournal,
    IdentityChanged,
    SymlinkRejected,
    HardlinkRejected,
    Poisoned,
}

impl fmt::Display for SchedulerJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "scheduler journal I/O failed: {e}"),
            other => write!(f, "scheduler journal held: {other:?}"),
        }
    }
}

impl std::error::Error for SchedulerJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SchedulerJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn fs_error(error: rustix::io::Errno) -> SchedulerJournalError {
    if error == rustix::io::Errno::LOOP {
        SchedulerJournalError::SymlinkRejected
    } else {
        SchedulerJournalError::Io(error.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl Snapshot {
    #[allow(clippy::unnecessary_cast)]
    fn of(stat: &Stat) -> Result<Self, SchedulerJournalError> {
        Ok(Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            uid: stat.st_uid,
            mode: stat.st_mode as u32,
            nlink: stat.st_nlink as u64,
            size: u64::try_from(stat.st_size).map_err(|_| SchedulerJournalError::UnsafeMetadata)?,
            mtime: stat.st_mtime as i64,
            mtime_nsec: stat.st_mtime_nsec as i64,
            ctime: stat.st_ctime as i64,
            ctime_nsec: stat.st_ctime_nsec as i64,
        })
    }
}

fn directory_snapshot(directory: &File, uid: u32) -> Result<Snapshot, SchedulerJournalError> {
    let stat = fstat(directory).map_err(fs_error)?;
    let snapshot = Snapshot::of(&stat)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || snapshot.uid != uid
        || snapshot.mode & 0o7777 != 0o700
        || snapshot.nlink == 0
    {
        return Err(SchedulerJournalError::UnsafeMetadata);
    }
    Ok(snapshot)
}

fn regular_snapshot(stat: &Stat, uid: u32) -> Result<Snapshot, SchedulerJournalError> {
    let kind = FileType::from_raw_mode(stat.st_mode);
    if kind == FileType::Symlink {
        return Err(SchedulerJournalError::SymlinkRejected);
    }
    let snapshot = Snapshot::of(stat)?;
    if kind != FileType::RegularFile || snapshot.uid != uid || snapshot.mode & 0o7777 != 0o600 {
        return Err(SchedulerJournalError::UnsafeMetadata);
    }
    if snapshot.nlink != 1 {
        return Err(SchedulerJournalError::HardlinkRejected);
    }
    Ok(snapshot)
}

fn validate_record(record: &[u8]) -> Result<(), SchedulerJournalError> {
    if record.len() >= MAX_SCHEDULER_RECORD_BYTES {
        return Err(SchedulerJournalError::RecordTooLarge);
    }
    if record.is_empty() || record.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(SchedulerJournalError::InvalidJson);
    }
    strict_json_object(record, MAX_SCHEDULER_RECORD_BYTES - 1).map_err(|error| match error {
        WriterJournalError::DuplicateJsonKey => SchedulerJournalError::DuplicateJsonKey,
        WriterJournalError::RecordTooLarge => SchedulerJournalError::RecordTooLarge,
        _ => SchedulerJournalError::InvalidJson,
    })
}

#[derive(Debug)]
pub(crate) struct SchedulerJournal {
    directory: File,
    file: File,
    uid: u32,
    directory_identity: (u64, u64),
    file_identity: (u64, u64),
    file_snapshot: Snapshot,
    file_bytes: u64,
    records: Vec<Vec<u8>>,
    poisoned: bool,
    #[cfg(test)]
    fail_after_partial_write: bool,
}

impl SchedulerJournal {
    pub(crate) fn open(directory: &File, expected_uid: u32) -> Result<Self, SchedulerJournalError> {
        if expected_uid != rustix::process::geteuid().as_raw() {
            return Err(SchedulerJournalError::UnsafeMetadata);
        }
        let original = directory_snapshot(directory, expected_uid)?;
        // A new open description is essential: try_clone would share the lock
        // description with the caller, including any later caller unlock.
        let retained = File::from(
            openat(
                directory,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(fs_error)?,
        );
        let parent = directory_snapshot(&retained, expected_uid)?;
        if (original.dev, original.ino) != (parent.dev, parent.ino) {
            return Err(SchedulerJournalError::IdentityChanged);
        }
        flock(&retained, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| SchedulerJournalError::LockUnavailable)?;
        let file = File::from(
            openat(
                &retained,
                SCHEDULER_JOURNAL_FILE_NAME,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::APPEND
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(fs_error)?,
        );
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| SchedulerJournalError::LockUnavailable)?;
        let snapshot = regular_snapshot(&fstat(&file).map_err(fs_error)?, expected_uid)?;
        if snapshot.size > MAX_SCHEDULER_FILE_BYTES {
            return Err(SchedulerJournalError::FileLimit);
        }
        let entry = regular_snapshot(
            &statat(
                &retained,
                SCHEDULER_JOURNAL_FILE_NAME,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(fs_error)?,
            expected_uid,
        )?;
        if snapshot != entry {
            return Err(SchedulerJournalError::IdentityChanged);
        }
        let mut journal = Self {
            directory: retained,
            file,
            uid: expected_uid,
            directory_identity: (parent.dev, parent.ino),
            file_identity: (snapshot.dev, snapshot.ino),
            file_snapshot: snapshot,
            file_bytes: snapshot.size,
            records: Vec::new(),
            poisoned: false,
            #[cfg(test)]
            fail_after_partial_write: false,
        };
        journal.load()?;
        journal.verify()?;
        // Also durably publishes creation of the empty fixed filename.
        journal.file.sync_all()?;
        journal.directory.sync_all()?;
        Ok(journal)
    }

    fn load(&mut self) -> Result<(), SchedulerJournalError> {
        let mut chunk = [0_u8; 8192];
        let mut line = Vec::new();
        let mut total = 0_u64;
        loop {
            let remaining = (MAX_SCHEDULER_FILE_BYTES + 1 - total).min(chunk.len() as u64) as usize;
            let count = self.file.read(&mut chunk[..remaining])?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > MAX_SCHEDULER_FILE_BYTES {
                return Err(SchedulerJournalError::FileLimit);
            }
            for byte in &chunk[..count] {
                if self.records.len() >= MAX_SCHEDULER_RECORDS {
                    return Err(SchedulerJournalError::RecordLimit);
                }
                if *byte == b'\n' {
                    validate_record(&line)?;
                    self.records.push(std::mem::take(&mut line));
                } else {
                    if line.len() >= MAX_SCHEDULER_RECORD_BYTES - 1 {
                        return Err(SchedulerJournalError::RecordTooLarge);
                    }
                    line.push(*byte);
                }
            }
        }
        if !line.is_empty() {
            return Err(SchedulerJournalError::CorruptJournal);
        }
        if total != self.file_bytes {
            return Err(SchedulerJournalError::IdentityChanged);
        }
        Ok(())
    }

    fn verify_size(&self, expected_size: u64) -> Result<Snapshot, SchedulerJournalError> {
        if self.poisoned {
            return Err(SchedulerJournalError::Poisoned);
        }
        let parent = directory_snapshot(&self.directory, self.uid)?;
        let opened = regular_snapshot(&fstat(&self.file).map_err(fs_error)?, self.uid)?;
        let entry = regular_snapshot(
            &statat(
                &self.directory,
                SCHEDULER_JOURNAL_FILE_NAME,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(fs_error)?,
            self.uid,
        )?;
        if (parent.dev, parent.ino) != self.directory_identity
            || (opened.dev, opened.ino) != self.file_identity
            || opened != entry
            || opened.size != expected_size
            || (expected_size == self.file_bytes && opened != self.file_snapshot)
        {
            return Err(SchedulerJournalError::IdentityChanged);
        }
        Ok(opened)
    }

    pub(crate) fn verify(&self) -> Result<(), SchedulerJournalError> {
        self.verify_size(self.file_bytes).map(|_| ())
    }

    /// The last verified durable prefix. The scheduler must check its own
    /// transitions and authority, and call verify before a protected effect.
    pub(crate) fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Reserve aggregate space for every still-required terminal/recovery row.
    /// Each reserved row is charged at the full inclusive record bound. The
    /// caller may request additional byte reserve but cannot underfund rows.
    pub(crate) fn append(
        &mut self,
        record: &[u8],
        reserve_records: usize,
        reserve_bytes: usize,
    ) -> Result<(), SchedulerJournalError> {
        self.verify()?;
        validate_record(record)?;
        let minimum_reserve = reserve_records
            .checked_mul(MAX_SCHEDULER_RECORD_BYTES)
            .ok_or(SchedulerJournalError::InvalidReservation)?;
        if reserve_bytes < minimum_reserve {
            return Err(SchedulerJournalError::InvalidReservation);
        }
        self.records
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_add(reserve_records))
            .filter(|count| *count <= MAX_SCHEDULER_RECORDS)
            .ok_or(SchedulerJournalError::RecordLimit)?;
        let new_size = self
            .file_bytes
            .checked_add(record.len() as u64 + 1)
            .ok_or(SchedulerJournalError::FileLimit)?;
        let reserve_bytes =
            u64::try_from(reserve_bytes).map_err(|_| SchedulerJournalError::InvalidReservation)?;
        new_size
            .checked_add(reserve_bytes)
            .filter(|size| *size <= MAX_SCHEDULER_FILE_BYTES)
            .ok_or(SchedulerJournalError::FileLimit)?;
        let mut line = Vec::with_capacity(record.len() + 1);
        line.extend_from_slice(record);
        line.push(b'\n');
        let written = (|| {
            #[cfg(test)]
            if self.fail_after_partial_write {
                self.fail_after_partial_write = false;
                self.file.write_all(&line[..1])?;
                return Err(SchedulerJournalError::Io(io::Error::other(
                    "injected uncertain partial append",
                )));
            }
            self.file.write_all(&line)?;
            self.file.sync_all()?;
            self.directory.sync_all()?;
            self.verify_size(new_size)
        })();
        let snapshot = match written {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.file_bytes = new_size;
        self.file_snapshot = snapshot;
        self.records.push(record.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

    fn store() -> (tempfile::TempDir, File, u32) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::open(temp.path()).unwrap();
        (temp, directory, rustix::process::geteuid().as_raw())
    }

    fn write_raw(temp: &tempfile::TempDir, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.path().join(SCHEDULER_JOURNAL_FILE_NAME))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn p007_journal_append_reopen_retains_exact_bytes_and_locks() {
        let (_temp, directory, uid) = store();
        let mut journal = SchedulerJournal::open(&directory, uid).unwrap();
        journal
            .append(br#"{"assignment":"a","state":"claimed"}"#, 1, 65_536)
            .unwrap();
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::LockUnavailable)
        ));
        // A caller descriptor cannot unlock the independently opened lock.
        flock(&directory, FlockOperation::Unlock).unwrap();
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::LockUnavailable)
        ));
        let expected = journal.records().to_vec();
        drop(journal);
        let reopened = SchedulerJournal::open(&directory, uid).unwrap();
        assert_eq!(reopened.records(), expected);
        reopened.verify().unwrap();
    }

    #[test]
    fn p007_journal_rejects_torn_duplicate_and_nonobject_records() {
        for raw in [
            b"{\"a\":1}".as_slice(),
            b"\n",
            b"[]\n",
            b"{\"a\":1,\"a\":2}\n",
            b"{\"a\":{\"x\":1,\"\\u0078\":2}}\n",
        ] {
            let (temp, directory, uid) = store();
            write_raw(&temp, raw);
            assert!(SchedulerJournal::open(&directory, uid).is_err());
        }
    }

    #[test]
    fn p007_journal_record_and_recovery_reserve_fail_before_write() {
        let (_temp, directory, uid) = store();
        let mut journal = SchedulerJournal::open(&directory, uid).unwrap();
        assert!(matches!(
            journal.append(&vec![b' '; MAX_SCHEDULER_RECORD_BYTES], 0, 0),
            Err(SchedulerJournalError::RecordTooLarge)
        ));
        assert!(matches!(
            journal.append(b"{}", 1, 0),
            Err(SchedulerJournalError::InvalidReservation)
        ));
        assert!(matches!(
            journal.append(b"{}", usize::MAX, usize::MAX),
            Err(SchedulerJournalError::InvalidReservation)
        ));
        assert!(matches!(
            journal.append(b"{}", 0, MAX_SCHEDULER_FILE_BYTES as usize),
            Err(SchedulerJournalError::FileLimit)
        ));
        assert!(matches!(
            journal.append(
                b"{}",
                MAX_SCHEDULER_RECORDS,
                MAX_SCHEDULER_RECORDS * MAX_SCHEDULER_RECORD_BYTES
            ),
            Err(SchedulerJournalError::RecordLimit)
        ));
        assert!(journal.records().is_empty());
        journal.verify().unwrap();
        journal.append(b"{}", 0, 0).unwrap();
    }

    #[test]
    fn p007_journal_inclusive_record_bound_and_empty_store_are_supported() {
        let (_temp, directory, uid) = store();
        let mut journal = SchedulerJournal::open(&directory, uid).unwrap();
        assert!(journal.records().is_empty());
        let mut record = br#"{"p":""#.to_vec();
        record.resize(MAX_SCHEDULER_RECORD_BYTES - 3, b'x');
        record.extend_from_slice(br#""}"#);
        assert_eq!(record.len(), MAX_SCHEDULER_RECORD_BYTES - 1);
        journal.append(&record, 0, 0).unwrap();
        assert_eq!(journal.records(), &[record]);
    }

    #[test]
    fn p007_journal_file_and_record_count_bounds_hold_on_reopen() {
        let (temp, directory, uid) = store();
        write_raw(&temp, &b"{}\n".repeat(MAX_SCHEDULER_RECORDS));
        let mut journal = SchedulerJournal::open(&directory, uid).unwrap();
        assert_eq!(journal.records().len(), MAX_SCHEDULER_RECORDS);
        assert!(matches!(
            journal.append(b"{}", 0, 0),
            Err(SchedulerJournalError::RecordLimit)
        ));
        drop(journal);
        let (temp, directory, uid) = store();
        write_raw(&temp, &b"{}\n".repeat(MAX_SCHEDULER_RECORDS + 1));
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::RecordLimit)
        ));
        let (temp, directory, uid) = store();
        write_raw(&temp, b"{}");
        let file = OpenOptions::new()
            .write(true)
            .open(temp.path().join(SCHEDULER_JOURNAL_FILE_NAME))
            .unwrap();
        file.set_len(MAX_SCHEDULER_FILE_BYTES + 1).unwrap();
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::FileLimit)
        ));
    }

    #[test]
    fn p007_journal_metadata_symlink_hardlink_and_uid_are_fenced() {
        let (temp, directory, uid) = store();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::UnsafeMetadata)
        ));
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            SchedulerJournal::open(&directory, uid.wrapping_add(1)),
            Err(SchedulerJournalError::UnsafeMetadata)
        ));
        let target = temp.path().join("target");
        fs::write(&target, b"{}\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, temp.path().join(SCHEDULER_JOURNAL_FILE_NAME)).unwrap();
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::SymlinkRejected)
        ));
        fs::remove_file(temp.path().join(SCHEDULER_JOURNAL_FILE_NAME)).unwrap();
        fs::hard_link(&target, temp.path().join(SCHEDULER_JOURNAL_FILE_NAME)).unwrap();
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::HardlinkRejected)
        ));
    }

    #[test]
    fn p007_journal_replacement_and_permission_change_are_detected() {
        let (temp, directory, uid) = store();
        let mut journal = SchedulerJournal::open(&directory, uid).unwrap();
        let path = temp.path().join(SCHEDULER_JOURNAL_FILE_NAME);
        fs::rename(&path, temp.path().join("original")).unwrap();
        write_raw(&temp, b"{}\n");
        assert!(matches!(
            journal.append(b"{}", 0, 0),
            Err(SchedulerJournalError::IdentityChanged)
        ));
        drop(journal);
        let mut journal = SchedulerJournal::open(&directory, uid).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            journal.append(b"{}", 0, 0),
            Err(SchedulerJournalError::UnsafeMetadata)
        ));
    }

    #[test]
    fn p007_journal_partial_append_poison_requires_original_recovery() {
        let (temp, directory, uid) = store();
        let mut journal = SchedulerJournal::open(&directory, uid).unwrap();
        journal.fail_after_partial_write = true;
        assert!(matches!(
            journal.append(b"{}", 0, 0),
            Err(SchedulerJournalError::Io(_))
        ));
        assert!(journal.records().is_empty());
        assert!(matches!(
            journal.verify(),
            Err(SchedulerJournalError::Poisoned)
        ));
        assert!(matches!(
            journal.append(b"{}", 0, 0),
            Err(SchedulerJournalError::Poisoned)
        ));
        drop(journal);
        assert_eq!(
            fs::read(temp.path().join(SCHEDULER_JOURNAL_FILE_NAME)).unwrap(),
            b"{"
        );
        assert!(matches!(
            SchedulerJournal::open(&directory, uid),
            Err(SchedulerJournalError::CorruptJournal)
        ));
    }
}
