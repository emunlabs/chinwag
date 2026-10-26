//! Exclusive bounded reads of existing Root-private fixtures, not a DB writer.
#![cfg(target_os = "macos")]
#![deny(unsafe_code)]
mod admission;
#[allow(unsafe_code)]
mod checked_close;
mod fs;
pub use admission::RepositoryAdmission;
use fs::{Anchor, FileId, Image};
use rustix::fs::{AtFlags, fsync, unlinkat};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, marker::PhantomData, path::Path, rc::Rc};

pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const TARGET: &str = "state.crdb";
const LOCK: &str = "state.crdb.lock";
const LOCK_BYTES: &[u8] = b"chinwag-private-snapshot-read-lock/v1\n";
const BLOCKERS: [&str; 7] = [
    LOCK,
    "state.crdb.intent",
    "state.crdb.next",
    "state.crdb.complete",
    "state.crdb-journal",
    "state.crdb-wal",
    "state.crdb-shm",
];
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub reason: &'static str,
    pub marker_created_no_retry: bool,
}
fn refusal(reason: &'static str) -> Refused {
    Refused {
        reason,
        marker_created_no_retry: false,
    }
}
fn retained(reason: &'static str) -> Refused {
    Refused {
        reason,
        marker_created_no_retry: true,
    }
}
/// No Clone or public constructor; Drop closes handles but retains the marker.
#[must_use = "Finish the original read owner or retain its lock; never replay an uncertain operation"]
pub struct ReadOwner {
    anchor: Option<Anchor>,
    source: Option<File>,
    lock: Option<File>,
    original: Image,
    lock_id: FileId,
    _owner_thread: PhantomData<Rc<()>>,
}
/// Evidence of this original readonly operation only; no persistence authority.
#[derive(Debug)]
pub struct ReadReceipt {
    sha256: [u8; 32],
    bytes: usize,
    checked_owner_fds: usize,
}
impl ReadReceipt {
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn checked_owner_fds(&self) -> usize {
        self.checked_owner_fds
    }
}
impl ReadOwner {
    /// Private fixture policy: owned nonshared owner-WX repo, 0700 .chinwag, 0600 file.
    pub fn acquire_existing_private_fixture(repo: &Path) -> Result<Self, Refused> {
        let anchor =
            Anchor::open_fixture(repo, Some(fs::ChildDirectory::PrivateLeaf)).map_err(refusal)?;
        for name in BLOCKERS {
            anchor.require_absent(name).map_err(refusal)?;
        }
        // Only metadata before acquiring the exclusive marker, no source bytes.
        let mut source = anchor.open_existing(TARGET).map_err(refusal)?;
        let observed = FileId::read(&source).map_err(refusal)?;
        anchor.check().map_err(refusal)?;
        let mut lock = anchor.exclusive(LOCK).map_err(refusal)?;
        // Every subsequent refusal retains the marker, including partially written.
        let prepared = (|| {
            lock.write_all(LOCK_BYTES).map_err(|_| "lock_write")?;
            lock.sync_all().map_err(|_| "lock_sync")?;
            let lock_id = anchor.verify(&mut lock, LOCK, LOCK_BYTES)?;
            fsync(&anchor.fd).map_err(|_| "lock_parent_sync")?;
            anchor.check()?;
            for name in &BLOCKERS[1..] {
                anchor.require_absent(name)?;
            }
            let original = anchor.read_held(&mut source, TARGET, MAX_IMAGE_BYTES)?;
            if original.id != observed {
                return Err("source_changed_before_locked_read");
            }
            anchor.check()?;
            Ok::<_, &'static str>((original, lock_id))
        })()
        .map_err(retained)?;
        Ok(Self {
            anchor: Some(anchor),
            source: Some(source),
            lock: Some(lock),
            original: prepared.0,
            lock_id: prepared.1,
            _owner_thread: PhantomData,
        })
    }
    /// These borrowed bytes are not a validated SQLite image or write authority.
    pub fn image(&self) -> &[u8] {
        &self.original.bytes
    }
    pub fn verify_unchanged(&mut self) -> Result<(), Refused> {
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("owner_anchor_missing"))?;
        anchor.check().map_err(retained)?;
        for name in &BLOCKERS[1..] {
            anchor.require_absent(name).map_err(retained)?;
        }
        let source = self
            .source
            .as_mut()
            .ok_or_else(|| retained("owner_source_missing"))?;
        if anchor
            .read_held(source, TARGET, MAX_IMAGE_BYTES)
            .map_err(retained)?
            != self.original
        {
            return Err(retained("source_changed_during_owner"));
        }
        let lock = self
            .lock
            .as_mut()
            .ok_or_else(|| retained("owner_lock_missing"))?;
        if anchor.verify(lock, LOCK, LOCK_BYTES).map_err(retained)? != self.lock_id {
            return Err(retained("owner_lock_changed"));
        }
        anchor.check().map_err(retained)?;
        Ok(())
    }
    pub fn finish_read(mut self) -> Result<ReadReceipt, Refused> {
        self.verify_unchanged()?;
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("owner_anchor_missing"))?;
        let digest: [u8; 32] = Sha256::digest(&self.original.bytes).into();
        let bytes = self.original.bytes.len();
        checked_close::file(
            self.source
                .take()
                .ok_or_else(|| retained("owner_source_missing"))?,
        )
        .map_err(retained)?;
        checked_close::file(
            self.lock
                .take()
                .ok_or_else(|| retained("owner_lock_missing"))?,
        )
        .map_err(retained)?;
        // There are no source operations after releasing exclusion. A later
        // cooperating owner may start immediately. Never infer our ack from it.
        unlinkat(&anchor.fd, LOCK, AtFlags::empty())
            .map_err(|_| retained("read_release_unlink_unknown"))?;
        fsync(&anchor.fd).map_err(|_| retained("read_release_parent_sync_unknown"))?;
        let checked = self
            .anchor
            .take()
            .ok_or_else(|| retained("owner_anchor_missing"))?
            .close_all()
            .map_err(retained)?;
        Ok(ReadReceipt {
            sha256: digest,
            bytes,
            checked_owner_fds: checked + 2,
        })
    }
}
