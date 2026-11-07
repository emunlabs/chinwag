//! Retained-FD local journal persistence. Processing and remote delivery differ.
#![forbid(unsafe_code)]

use crate::{
    bus_federation::{BusMessage, FederationSink, SinkDisposition},
    bus_identity::BusDirectory,
    bus_journal::{JournalError, JournalPreparation, analyze_journal},
};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Directory,
    UnsafeFile,
    NamespaceChanged,
    Busy,
    Analysis(JournalError),
    PartialAppend,
    Readback,
    Poisoned,
    Io(std::io::ErrorKind),
}
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local bus persistence unknown or refused: {self:?}")
    }
}
impl std::error::Error for StoreError {}
type Result<T> = std::result::Result<T, StoreError>;
fn io(error: std::io::Error) -> StoreError {
    StoreError::Io(error.kind())
}
fn os(error: rustix::io::Errno) -> StoreError {
    io(error.into())
}

#[derive(Clone, Copy)]
enum Kind {
    Lock,
    Journal,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Lock => "bus.lock",
            Self::Journal => "messages.jsonl",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileState {
    id: (u64, u64),
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl FileState {
    fn read(file: &File, kind: Kind) -> Result<Self> {
        let m = file.metadata().map_err(io)?;
        if !m.is_file()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || matches!(kind, Kind::Lock) && m.len() != 0
        {
            return Err(StoreError::UnsafeFile);
        }
        Ok(Self {
            id: (m.dev(), m.ino()),
            uid: m.uid(),
            mode: m.mode() & 0o7777,
            nlink: m.nlink(),
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }
}
fn open_file(directory: &BusDirectory, kind: Kind, create: bool) -> Result<(File, FileState)> {
    let flags = OFlags::RDWR
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | if matches!(kind, Kind::Journal) {
            OFlags::APPEND
        } else {
            OFlags::empty()
        };
    let (fd, created) = match openat(directory, kind.name(), flags, Mode::empty()) {
        Ok(fd) => (fd, false),
        Err(error) if error == rustix::io::Errno::NOENT && !create => {
            return Err(StoreError::NamespaceChanged);
        }
        Err(error) if error == rustix::io::Errno::NOENT => match openat(
            directory,
            kind.name(),
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => (fd, true),
            Err(error) if error == rustix::io::Errno::EXIST => return Err(StoreError::Busy),
            Err(error) => return Err(os(error)),
        },
        Err(error) => return Err(os(error)),
    };
    let file = File::from(fd);
    let state = FileState::read(&file, kind)?;
    if created {
        if state.len != 0 {
            return Err(StoreError::UnsafeFile);
        }
        file.sync_all().map_err(io)?;
        directory.sync().map_err(|_| StoreError::Directory)?;
    }
    verify_file(directory, &file, kind, state)?;
    Ok((file, state))
}
fn verify_file(
    directory: &BusDirectory,
    file: &File,
    kind: Kind,
    expected: FileState,
) -> Result<()> {
    directory.verify().map_err(|_| StoreError::Directory)?;
    let named = File::from(
        openat(
            directory,
            kind.name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StoreError::NamespaceChanged)?,
    );
    if FileState::read(file, kind)? != expected || FileState::read(&named, kind)? != expected {
        return Err(StoreError::NamespaceChanged);
    }
    Ok(())
}
struct LockedFile {
    file: File,
    state: FileState,
    active: bool,
}
impl LockedFile {
    fn acquire(directory: &BusDirectory, create: bool) -> Result<Self> {
        let (file, state) = open_file(directory, Kind::Lock, create)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if std::io::Error::from(error).kind() == std::io::ErrorKind::WouldBlock {
                StoreError::Busy
            } else {
                os(error)
            }
        })?;
        let locked = Self {
            file,
            state,
            active: true,
        };
        locked.verify(directory)?;
        Ok(locked)
    }
    fn verify(&self, directory: &BusDirectory) -> Result<()> {
        verify_file(directory, &self.file, Kind::Lock, self.state)
    }
    fn release(mut self) -> Result<()> {
        flock(&self.file, FlockOperation::Unlock).map_err(os)?;
        self.active = false;
        Ok(())
    }
}
impl Drop for LockedFile {
    fn drop(&mut self) {
        // Success uses explicit checked release. Error cleanup cannot produce
        // Stored; closing this original FD also relinquishes its flock.
        if self.active {
            let _ = flock(&self.file, FlockOperation::Unlock);
        }
    }
}

struct ObservedFiles {
    // These private anchors keep the first observed inodes alive across
    // operations. No lock operation is performed on an anchor descriptor.
    lock: File,
    journal: File,
}
/// Advisory locks coordinate cooperating writers, not same-UID containment.
/// An uncertain instance stays poisoned until explicit outside reconciliation.
pub struct NativeJournalSink {
    directory: BusDirectory,
    poisoned: bool,
    observed_files: Option<ObservedFiles>,
    #[cfg(test)]
    cut: Option<TestCut>,
}
impl NativeJournalSink {
    pub fn open(repo_root: &Path) -> Result<Self> {
        Ok(Self {
            directory: BusDirectory::open(repo_root).map_err(|_| StoreError::Directory)?,
            poisoned: false,
            observed_files: None,
            #[cfg(test)]
            cut: None,
        })
    }
    fn persist_once(&mut self, message: &BusMessage) -> Result<SinkDisposition> {
        self.directory.verify().map_err(|_| StoreError::Directory)?;
        let create = self.observed_files.is_none();
        let lock = LockedFile::acquire(&self.directory, create)?;
        let (mut journal, before) = open_file(&self.directory, Kind::Journal, create)?;
        self.observe_files(&lock, &journal, before)?;
        journal.seek(SeekFrom::Start(0)).map_err(io)?;
        let preparation = {
            let mut reader = BufReader::new(&mut journal);
            analyze_journal(&mut reader, message)
        };
        verify_file(&self.directory, &journal, Kind::Journal, before)?;
        lock.verify(&self.directory)?;
        let prepared = match preparation {
            Ok(JournalPreparation::HistoricalReplay(replay)) => {
                self.confirm_existing(&journal, before, &lock)?;
                lock.release()?;
                return Ok(SinkDisposition::ExactReplay {
                    local_sequence: replay.local_sequence(),
                });
            }
            Err(JournalError::ConflictingOriginal) => {
                lock.release()?;
                return Ok(SinkDisposition::Conflict);
            }
            Err(error) => return Err(StoreError::Analysis(error)),
            Ok(JournalPreparation::PreparedAppend(prepared)) => prepared,
        };
        #[cfg(test)]
        self.hook(false);
        verify_file(&self.directory, &journal, Kind::Journal, before)?;
        lock.verify(&self.directory)?;
        if journal.seek(SeekFrom::End(0)).map_err(io)? != before.len {
            return Err(StoreError::NamespaceChanged);
        }
        let expected_len = before
            .len
            .checked_add(prepared.line().len() as u64)
            .ok_or(StoreError::Readback)?;
        #[cfg(test)]
        if matches!(self.cut, Some(TestCut::Partial)) {
            self.cut = None;
            let count = prepared.line().len() / 2;
            let _ = journal.write(&prepared.line()[..count]).map_err(io)?;
            return Err(StoreError::PartialAppend);
        }
        // A short/interrupted append is uncertain. Never complete it through
        // write_all, retry the original, truncate, or repair retained bytes.
        if journal.write(prepared.line()).map_err(io)? != prepared.line().len() {
            return Err(StoreError::PartialAppend);
        }
        #[cfg(test)]
        self.hook(true);
        journal.sync_all().map_err(io)?;
        self.directory.sync().map_err(|_| StoreError::Directory)?;
        let written = FileState::read(&journal, Kind::Journal)?;
        if written.id != before.id || written.len != expected_len {
            return Err(StoreError::NamespaceChanged);
        }
        journal.seek(SeekFrom::Start(before.len)).map_err(io)?;
        let mut readback = vec![0; prepared.line().len()];
        journal.read_exact(&mut readback).map_err(io)?;
        if !bool::from(readback.as_slice().ct_eq(prepared.line())) {
            return Err(StoreError::Readback);
        }
        verify_file(&self.directory, &journal, Kind::Journal, written)?;
        lock.verify(&self.directory)?;
        lock.release()?;
        Ok(SinkDisposition::Stored {
            local_sequence: prepared.local_sequence(),
        })
    }
    fn observe_files(&mut self, lock: &LockedFile, journal: &File, state: FileState) -> Result<()> {
        if let Some(original) = &self.observed_files {
            if FileState::read(&original.lock, Kind::Lock)?.id != lock.state.id
                || FileState::read(&original.journal, Kind::Journal)?.id != state.id
            {
                return Err(StoreError::NamespaceChanged);
            }
        } else {
            self.observed_files = Some(ObservedFiles {
                lock: lock.file.try_clone().map_err(io)?,
                journal: journal.try_clone().map_err(io)?,
            });
        }
        Ok(())
    }
    fn confirm_existing(&self, journal: &File, state: FileState, lock: &LockedFile) -> Result<()> {
        // Readable historical bytes alone do not establish a fresh durable
        // receipt. This flush never appends or manufactures a missing record.
        journal.sync_all().map_err(io)?;
        self.directory.sync().map_err(|_| StoreError::Directory)?;
        verify_file(&self.directory, journal, Kind::Journal, state)?;
        lock.verify(&self.directory)
    }
    fn verify_replay_once(&mut self, message: &BusMessage, expected_sequence: u64) -> Result<bool> {
        self.directory.verify().map_err(|_| StoreError::Directory)?;
        // Cache hits have no creation/append path, including absent lock or
        // journal names. Full history, not cache residence, proves replay.
        let lock = LockedFile::acquire(&self.directory, false)?;
        let (mut journal, before) = open_file(&self.directory, Kind::Journal, false)?;
        self.observe_files(&lock, &journal, before)?;
        journal.seek(SeekFrom::Start(0)).map_err(io)?;
        let preparation = {
            let mut reader = BufReader::new(&mut journal);
            analyze_journal(&mut reader, message)
        };
        verify_file(&self.directory, &journal, Kind::Journal, before)?;
        lock.verify(&self.directory)?;
        let exact = match preparation {
            Ok(JournalPreparation::HistoricalReplay(replay)) => {
                replay.local_sequence() == expected_sequence
            }
            Ok(JournalPreparation::PreparedAppend(_)) | Err(JournalError::ConflictingOriginal) => {
                false
            }
            Err(error) => return Err(StoreError::Analysis(error)),
        };
        if exact {
            self.confirm_existing(&journal, before, &lock)?;
        }
        lock.release()?;
        Ok(exact)
    }
    fn complete<T>(&mut self, result: Result<T>) -> Result<T> {
        if matches!(&result, Err(error) if *error != StoreError::Busy) {
            self.poisoned = true;
        }
        result
    }
}

impl FederationSink for NativeJournalSink {
    type Error = StoreError;
    fn persist_if_absent(&mut self, message: &BusMessage) -> Result<SinkDisposition> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let result = self.persist_once(message);
        self.complete(result)
    }
    fn verify_exact_replay(
        &mut self,
        message: &BusMessage,
        expected_sequence: u64,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let result = self.verify_replay_once(message, expected_sequence);
        self.complete(result)
    }
}
#[cfg(test)]
enum TestCut {
    Partial,
    Before(Box<dyn FnOnce() + Send>),
    After(Box<dyn FnOnce() + Send>),
}
#[cfg(test)]
impl NativeJournalSink {
    fn hook(&mut self, after: bool) {
        if matches!(
            (&self.cut, after),
            (Some(TestCut::Before(_)), false) | (Some(TestCut::After(_)), true)
        ) {
            match self.cut.take().unwrap() {
                TestCut::Before(hook) | TestCut::After(hook) => hook(),
                TestCut::Partial => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus_federation::{
        BoundedIngress, FederationEffects, IngressError, IngressLimits, IngressOutcome,
    };
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        path::PathBuf,
    };
    use tempfile::TempDir;

    fn fixture() -> (TempDir, PathBuf, NativeJournalSink) {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let sink = NativeJournalSink::open(&root).unwrap();
        (temp, root, sink)
    }
    fn journal(root: &Path) -> PathBuf {
        root.join(".chinwag/bus/messages.jsonl")
    }
    fn message(id: &str) -> BusMessage {
        BusMessage {
            id: id.into(),
            seq: 999,
            ts_unix: 100,
            ts_iso: "display timestamp".into(),
            room: "#eng".into(),
            sender: "DEV#original-instance".into(),
            sender_cast: "■".into(),
            sender_endpoint_id: "opaque-original-endpoint".into(),
            to: Some("QA#existing-instance".into()),
            task_id: Some("TASK-1".into()),
            body: "original body".into(),
            digest_sha256: "opaque-original-digest".into(),
            pubkey_ed25519: Some("opaque-public-witness".into()),
            signature_ed25519: Some("opaque-signature-witness".into()),
            sig_verified: false,
        }
    }
    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    fn serialized(message: &BusMessage) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(message).unwrap();
        bytes.push(b'\n');
        bytes
    }
    #[derive(Default)]
    struct Effects(Vec<u64>);
    impl FederationEffects for Effects {
        type Error = ();
        fn on_stored(&mut self, message: &BusMessage) -> std::result::Result<(), ()> {
            self.0.push(message.seq);
            Ok(())
        }
    }
    fn ingress() -> BoundedIngress {
        BoundedIngress::new(IngressLimits::default())
    }

    #[test]
    fn native_store_reopens_exact_original_without_append_or_repeat_effects() {
        let (_temp, root, mut sink) = fixture();
        let original = message("original");
        let mut effects = Effects::default();
        assert_eq!(
            ingress().ingest(&original, &mut sink, &mut effects),
            Ok(IngressOutcome::Stored { local_sequence: 1 })
        );
        let bytes = fs::read(journal(&root)).unwrap();
        let mut expected = original.clone();
        expected.seq = 1;
        assert_eq!(bytes, serialized(&expected));
        for name in ["bus.lock", "messages.jsonl"] {
            let metadata = fs::symlink_metadata(root.join(".chinwag/bus").join(name)).unwrap();
            assert!(metadata.is_file());
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(metadata.nlink(), 1);
        }
        // The inode anchors remain alive in this sink, while checked release
        // really relinquishes flock ownership for an independent open.
        let independent = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(".chinwag/bus/bus.lock"))
            .unwrap();
        flock(&independent, FlockOperation::NonBlockingLockExclusive).unwrap();
        flock(&independent, FlockOperation::Unlock).unwrap();
        drop(sink);
        let mut reopened = NativeJournalSink::open(&root).unwrap();
        let mut fresh_cache = ingress();
        assert_eq!(
            fresh_cache.ingest(&original, &mut reopened, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 1 })
        );
        assert_eq!(fs::read(journal(&root)).unwrap(), bytes);
        assert_eq!(effects.0, vec![1]);
        assert_eq!(
            fresh_cache.ingest(&message("second"), &mut reopened, &mut effects),
            Ok(IngressOutcome::Stored { local_sequence: 2 })
        );
        assert_eq!(effects.0, vec![1, 2]);
    }

    #[test]
    fn native_history_conflict_survives_cache_restart_without_append_or_effects() {
        let (_temp, root, mut sink) = fixture();
        sink.persist_if_absent(&message("original")).unwrap();
        let before = fs::read(journal(&root)).unwrap();
        drop(sink);
        let mut sink = NativeJournalSink::open(&root).unwrap();
        let mut changed = message("original");
        changed.body.push('!');
        let mut effects = Effects::default();
        assert_eq!(
            ingress().ingest(&changed, &mut sink, &mut effects),
            Err(IngressError::ConflictingOriginal)
        );
        assert_eq!(fs::read(journal(&root)).unwrap(), before);
        assert!(effects.0.is_empty());
    }

    #[test]
    fn cache_hit_rechecks_full_existing_history_without_append_or_repeat_effects() {
        let (_temp, root, mut sink) = fixture();
        let original = message("original");
        let mut cache = ingress();
        let mut effects = Effects::default();
        assert_eq!(
            cache.ingest(&original, &mut sink, &mut effects),
            Ok(IngressOutcome::Stored { local_sequence: 1 })
        );
        let bytes = fs::read(journal(&root)).unwrap();
        assert_eq!(
            cache.ingest(&original, &mut sink, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 1 })
        );
        assert_eq!(fs::read(journal(&root)).unwrap(), bytes);
        assert_eq!(effects.0, vec![1]);
        assert!(!sink.verify_exact_replay(&original, 9).unwrap());
        assert!(!sink.verify_exact_replay(&message("not-stored"), 1).unwrap());
        assert_eq!(fs::read(journal(&root)).unwrap(), bytes);
    }

    #[test]
    fn cache_hit_after_missing_corrupt_or_replaced_namespace_never_recreates_or_appends() {
        for kind in 0..4 {
            let (_temp, root, mut sink) = fixture();
            let original = message("original");
            let mut cache = ingress();
            let mut effects = Effects::default();
            cache.ingest(&original, &mut sink, &mut effects).unwrap();
            let path = journal(&root);
            let original_bytes = fs::read(&path).unwrap();
            let lock = root.join(".chinwag/bus/bus.lock");
            match kind {
                0 => fs::remove_file(&path).unwrap(),
                1 => {
                    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                    file.write_all(b"corrupt complete row\n").unwrap();
                    file.sync_all().unwrap();
                }
                2 => {
                    fs::rename(&path, root.join(".chinwag/bus/previous-journal")).unwrap();
                    write_private(&path, &original_bytes);
                }
                3 => fs::remove_file(&lock).unwrap(),
                _ => unreachable!(),
            }
            let before = fs::read(&path).ok();
            assert!(
                matches!(
                    cache.ingest(&original, &mut sink, &mut effects),
                    Err(IngressError::PersistenceUnknown(_))
                ),
                "case {kind}"
            );
            assert_eq!(fs::read(&path).ok(), before);
            assert_eq!(effects.0, vec![1]);
            if kind == 3 {
                assert!(!lock.exists());
            }
            if kind == 0 {
                assert!(!path.exists());
            }
        }
    }

    #[test]
    fn later_new_original_cannot_recreate_a_previously_observed_missing_journal() {
        let (_temp, root, mut sink) = fixture();
        sink.persist_if_absent(&message("first")).unwrap();
        fs::remove_file(journal(&root)).unwrap();
        assert_eq!(
            sink.persist_if_absent(&message("second")),
            Err(StoreError::NamespaceChanged)
        );
        assert!(!journal(&root).exists());
    }

    #[test]
    fn actual_full_history_uses_max_sequence_and_refuses_late_corruption_before_replay() {
        let (_temp, root, mut sink) = fixture();
        let mut first = message("first");
        first.seq = 90;
        let mut last = message("last");
        last.seq = 4;
        let mut history = serialized(&first);
        history.extend(serialized(&last));
        write_private(&journal(&root), &history);
        assert_eq!(
            sink.persist_if_absent(&message("new")),
            Ok(SinkDisposition::Stored { local_sequence: 91 })
        );
        let mut file = OpenOptions::new()
            .append(true)
            .open(journal(&root))
            .unwrap();
        file.write_all(b"late malformed row\n").unwrap();
        file.sync_all().unwrap();
        drop(file);
        drop(sink);
        let before = fs::read(journal(&root)).unwrap();
        let mut reopened = NativeJournalSink::open(&root).unwrap();
        assert_eq!(
            reopened.persist_if_absent(&first),
            Err(StoreError::Analysis(JournalError::MalformedRecord))
        );
        assert_eq!(fs::read(journal(&root)).unwrap(), before);
    }

    #[test]
    fn partial_append_is_retained_poisoned_and_never_repaired_or_refanned() {
        let (_temp, root, mut sink) = fixture();
        sink.cut = Some(TestCut::Partial);
        let mut effects = Effects::default();
        assert_eq!(
            ingress().ingest(&message("original"), &mut sink, &mut effects),
            Err(IngressError::PersistenceUnknown(StoreError::PartialAppend))
        );
        let partial = fs::read(journal(&root)).unwrap();
        assert!(!partial.is_empty());
        assert_ne!(partial.last(), Some(&b'\n'));
        assert_eq!(
            sink.persist_if_absent(&message("original")),
            Err(StoreError::Poisoned)
        );
        drop(sink);
        let mut reopened = NativeJournalSink::open(&root).unwrap();
        assert_eq!(
            ingress().ingest(&message("other"), &mut reopened, &mut effects),
            Err(IngressError::PersistenceUnknown(StoreError::Analysis(
                JournalError::PartialTail
            )))
        );
        assert_eq!(fs::read(journal(&root)).unwrap(), partial);
        assert!(effects.0.is_empty());
    }

    #[test]
    fn complete_but_unconfirmed_append_can_only_replay_without_effects_after_reopen() {
        let (_temp, root, mut sink) = fixture();
        let path = journal(&root);
        let changed = path.clone();
        sink.cut = Some(TestCut::After(Box::new(move || {
            fs::set_permissions(changed, fs::Permissions::from_mode(0o400)).unwrap();
        })));
        let mut effects = Effects::default();
        assert!(matches!(
            ingress().ingest(&message("original"), &mut sink, &mut effects),
            Err(IngressError::PersistenceUnknown(StoreError::UnsafeFile))
        ));
        let uncertain = fs::read(&path).unwrap();
        assert_eq!(uncertain.last(), Some(&b'\n'));
        assert!(effects.0.is_empty());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o400);
        // Explicit fixture-only outside reconciliation; the sink never repairs
        // permissions and cannot turn its uncertain append into a new effect.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(sink);
        let mut reopened = NativeJournalSink::open(&root).unwrap();
        assert_eq!(
            ingress().ingest(&message("original"), &mut reopened, &mut effects),
            Ok(IngressOutcome::ExactReplay { local_sequence: 1 })
        );
        assert_eq!(fs::read(path).unwrap(), uncertain);
        assert!(effects.0.is_empty());
    }

    #[test]
    fn journal_namespace_replacement_before_append_refuses_without_writing_either_file() {
        let (_temp, root, mut sink) = fixture();
        let current = journal(&root);
        let previous = root.join(".chinwag/bus/replaced-journal");
        let (hook_current, hook_previous) = (current.clone(), previous.clone());
        sink.cut = Some(TestCut::Before(Box::new(move || {
            fs::rename(&hook_current, &hook_previous).unwrap();
            write_private(&hook_current, b"");
        })));
        assert_eq!(
            sink.persist_if_absent(&message("original")),
            Err(StoreError::NamespaceChanged)
        );
        assert!(fs::read(current).unwrap().is_empty());
        assert!(fs::read(previous).unwrap().is_empty());
    }

    #[test]
    fn journal_namespace_replacement_after_append_retains_original_bytes_and_no_effects() {
        let (_temp, root, mut sink) = fixture();
        let current = journal(&root);
        let previous = root.join(".chinwag/bus/replaced-journal");
        let (hook_current, hook_previous) = (current.clone(), previous.clone());
        sink.cut = Some(TestCut::After(Box::new(move || {
            fs::rename(&hook_current, &hook_previous).unwrap();
            write_private(&hook_current, b"");
        })));
        let mut effects = Effects::default();
        assert_eq!(
            ingress().ingest(&message("original"), &mut sink, &mut effects),
            Err(IngressError::PersistenceUnknown(
                StoreError::NamespaceChanged
            ))
        );
        assert!(fs::read(current).unwrap().is_empty());
        let mut expected = message("original");
        expected.seq = 1;
        assert_eq!(fs::read(previous).unwrap(), serialized(&expected));
        assert!(effects.0.is_empty());
    }

    #[test]
    fn replaced_bus_directory_refuses_before_append_without_adopting_new_namespace() {
        let (_temp, root, mut sink) = fixture();
        let path = root.join(".chinwag/bus");
        let previous = root.join(".chinwag/previous-bus");
        let (hook_path, hook_previous) = (path.clone(), previous.clone());
        sink.cut = Some(TestCut::Before(Box::new(move || {
            fs::rename(&hook_path, hook_previous).unwrap();
            fs::create_dir(&hook_path).unwrap();
            fs::set_permissions(hook_path, fs::Permissions::from_mode(0o700)).unwrap();
        })));
        assert_eq!(
            sink.persist_if_absent(&message("original")),
            Err(StoreError::Directory)
        );
        assert!(!path.join("messages.jsonl").exists());
        assert!(
            fs::read(previous.join("messages.jsonl"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn replaced_lock_file_cannot_authorize_append_under_an_unlocked_name() {
        let (_temp, root, mut sink) = fixture();
        let lock_path = root.join(".chinwag/bus/bus.lock");
        let moved_lock = root.join(".chinwag/bus/original-locked-file");
        sink.cut = Some(TestCut::Before(Box::new(move || {
            fs::rename(&lock_path, moved_lock).unwrap();
            write_private(&lock_path, b"");
        })));
        assert_eq!(
            sink.persist_if_absent(&message("original")),
            Err(StoreError::NamespaceChanged)
        );
        assert!(fs::read(journal(&root)).unwrap().is_empty());
    }

    #[test]
    fn independently_opened_flock_refuses_busy_without_unlocked_append_then_can_retry() {
        let (_temp, root, mut sink) = fixture();
        let lock_path = root.join(".chinwag/bus/bus.lock");
        write_private(&lock_path, b"");
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        flock(&held, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert_eq!(
            sink.persist_if_absent(&message("original")),
            Err(StoreError::Busy)
        );
        assert!(!journal(&root).exists());
        flock(&held, FlockOperation::Unlock).unwrap();
        assert_eq!(
            sink.persist_if_absent(&message("original")),
            Ok(SinkDisposition::Stored { local_sequence: 1 })
        );
    }

    #[test]
    fn unsafe_journal_links_and_modes_refuse_without_overwriting_or_chmod() {
        for kind in 0..3 {
            let (_temp, root, mut sink) = fixture();
            let target = root.join("owned-target");
            write_private(&target, b"retained target bytes");
            let path = journal(&root);
            match kind {
                0 => symlink(&target, &path).unwrap(),
                1 => fs::hard_link(&target, &path).unwrap(),
                2 => {
                    write_private(&path, b"retained journal bytes");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                _ => unreachable!(),
            }
            let before = fs::read(&path).unwrap();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(sink.persist_if_absent(&message("original")).is_err());
            assert_eq!(fs::read(&target).unwrap(), b"retained target bytes");
            assert_eq!(fs::read(&path).unwrap(), before);
            let after = fs::symlink_metadata(path).unwrap();
            assert_eq!(
                (after.dev(), after.ino(), after.mode(), after.nlink()),
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mode(),
                    metadata.nlink()
                )
            );
        }
    }

    #[test]
    fn unsafe_lock_links_modes_and_contents_refuse_without_creating_journal() {
        for kind in 0..4 {
            let (_temp, root, mut sink) = fixture();
            let target = root.join("owned-target");
            write_private(&target, b"");
            let lock = root.join(".chinwag/bus/bus.lock");
            match kind {
                0 => symlink(&target, &lock).unwrap(),
                1 => fs::hard_link(&target, &lock).unwrap(),
                2 => {
                    write_private(&lock, b"");
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
                }
                3 => write_private(&lock, b"foreign lock contents"),
                _ => unreachable!(),
            }
            let before = fs::read(&lock).unwrap();
            let mode = fs::symlink_metadata(&lock).unwrap().mode();
            assert!(sink.persist_if_absent(&message("original")).is_err());
            assert!(!journal(&root).exists());
            assert_eq!(fs::read(&lock).unwrap(), before);
            assert_eq!(fs::symlink_metadata(lock).unwrap().mode(), mode);
            assert!(fs::read(target).unwrap().is_empty());
        }
    }

    #[test]
    fn sink_never_creates_loads_or_modifies_identity_key() {
        let (_temp, root, mut sink) = fixture();
        let key = root.join(".chinwag/bus/daemon_secret.key");
        assert!(!key.exists());
        sink.persist_if_absent(&message("before-key")).unwrap();
        assert!(!key.exists());
        let public = crate::bus_identity::load_or_create_daemon_secret(&root)
            .unwrap()
            .public();
        let before = fs::symlink_metadata(&key).unwrap();
        sink.persist_if_absent(&message("after-key")).unwrap();
        let after = fs::symlink_metadata(&key).unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.len(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.len(),
                after.mode(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        assert_eq!(
            crate::bus_identity::load_or_create_daemon_secret(&root)
                .unwrap()
                .public(),
            public
        );
    }
}
