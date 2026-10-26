//! One initial CREATE_NEW in existing Root-private fixtures. No replacement API.
use crate::create_fs::{Anchor, FileId};
use crate::{Error, SessionError, Value, checked_close, native::Connection, schema};
use rustix::fs::{AtFlags, fsync, unlinkat};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, marker::PhantomData, path::Path, rc::Rc};

const TARGET: &str = "state.crdb";
const LOCK: &str = "state.crdb.lock";
const LOCK_BYTES: &[u8] = b"chinwag-private-snapshot-initial-create-lock/v1\n";
const OTHER_MARKERS: [&str; 6] = [
    "state.crdb.intent",
    "state.crdb.next",
    "state.crdb.complete",
    "state.crdb-journal",
    "state.crdb-wal",
    "state.crdb-shm",
];

/// This observation never grants cleanup, retry, adoption, or completion authority.
#[derive(Debug, PartialEq, Eq)]
pub struct CreateFailure {
    pub reason: &'static str,
    pub marker_created_no_retry: bool,
    pub target_created_no_retry: bool,
}
impl std::fmt::Display for CreateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}
impl std::error::Error for CreateFailure {}
fn before(reason: &'static str) -> CreateFailure {
    CreateFailure {
        reason,
        marker_created_no_retry: false,
        target_created_no_retry: false,
    }
}
fn marked(reason: &'static str) -> CreateFailure {
    CreateFailure {
        reason,
        marker_created_no_retry: true,
        target_created_no_retry: false,
    }
}
fn created(reason: &'static str) -> CreateFailure {
    CreateFailure {
        reason,
        marker_created_no_retry: true,
        target_created_no_retry: true,
    }
}

/// A fresh logical replica, returned only after its native owner checked closed.
/// No Clone, public constructor, bytes accessor, or live native handle.
#[must_use = "Consume this image once; do not clone a logical replica identity"]
pub struct EmptyStoreImage {
    bytes: Vec<u8>,
    site_id: [u8; 16],
    sha256: [u8; 32],
}
impl EmptyStoreImage {
    pub fn site_id(&self) -> [u8; 16] {
        self.site_id
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn bytes_len(&self) -> usize {
        self.bytes.len()
    }
    /// Fixture setup must already have created the private directory. This does
    /// not verify signing and must not be used as a production init coordinator.
    pub fn begin_private_fixture(self, repo: &Path) -> Result<CreationOwner, CreateFailure> {
        let anchor =
            Anchor::open_fixture(repo, Some(crate::create_fs::ChildDirectory::PrivateLeaf))
                .map_err(before)?;
        for name in [TARGET, LOCK].into_iter().chain(OTHER_MARKERS) {
            anchor.require_absent(name).map_err(before)?;
        }
        anchor.check().map_err(before)?;
        let mut lock = anchor.exclusive(LOCK).map_err(before)?;
        let lock_id = (|| {
            lock.write_all(LOCK_BYTES).map_err(|_| "init_lock_write")?;
            lock.sync_all().map_err(|_| "init_lock_sync")?;
            let id = anchor.verify(&mut lock, LOCK, LOCK_BYTES)?;
            fsync(&anchor.fd).map_err(|_| "init_lock_parent_sync")?;
            anchor.check()?;
            for name in [TARGET].into_iter().chain(OTHER_MARKERS) {
                anchor.require_absent(name)?;
            }
            Ok(id)
        })()
        .map_err(marked)?;
        let mut target = anchor.exclusive(TARGET).map_err(marked)?;
        // There is deliberately no cleanup after this CREATE_NEW, even if empty.
        let original_empty = (|| {
            let image = anchor.read_held(&mut target, TARGET, 0)?;
            if !image.bytes.is_empty() {
                return Err("initial_target_not_empty");
            }
            anchor.check()?;
            if anchor.verify(&mut lock, LOCK, LOCK_BYTES)? != lock_id {
                return Err("initial_lock_changed");
            }
            Ok(image.id)
        })()
        .map_err(created)?;
        Ok(CreationOwner {
            anchor: Some(anchor),
            target: Some(target),
            lock: Some(lock),
            original_empty,
            lock_id,
            image: self,
            _owner_thread: PhantomData,
        })
    }
    /// Controlled control-flow refusal, not OS fault injection or recovery.
    #[cfg(feature = "private-probe")]
    pub fn refuse_after_create_for_private_probe(
        self,
        repo: &Path,
    ) -> Result<CreationOwner, CreateFailure> {
        let _retained = self.begin_private_fixture(repo)?;
        Err(created("controlled_after_target_create"))
    }
}

/// Initialize and serialize in memory, then checked close before exposing bytes
/// to the initializer. Factory errors never return a usable image capability.
pub fn fresh_empty_store_image_for_private_fixture() -> Result<EmptyStoreImage, SessionError> {
    let native = Connection::open_template_memory().map_err(SessionError::Native)?;
    let outcome = (|| {
        crate::initialize_schema(&native)?;
        if crate::schema_objects(&native)?.len() != 78 {
            return Err(Error::Contract("Empty schema object count"));
        }
        for table in &schema::TABLES {
            let sql = std::ffi::CString::new(format!("SELECT count(*) FROM {}", table.name))
                .map_err(|_| Error::Contract("NUL in fixed empty-table SQL"))?;
            if native.query(&sql, &[])? != vec![vec![Value::Integer(0)]] {
                return Err(Error::Contract("Factory table not empty"));
            }
        }
        let site = crate::site_id(&native)?;
        if site != crate::metadata_site(&native)? {
            return Err(Error::Contract("Empty cached and metadata site differ"));
        }
        let bytes = native.export_empty_image_for_factory()?;
        crate::check_header(&bytes).map_err(Error::Contract)?;
        Ok((bytes, site))
    })();
    let (bytes, site_id) = crate::finish(native, outcome).map_err(SessionError::Native)?;
    let sha256 = Sha256::digest(&bytes).into();
    Ok(EmptyStoreImage {
        bytes,
        site_id,
        sha256,
    })
}

/// Abandonment retains marker and target. No Clone, recovery or persistence API.
#[must_use = "Finish the original creation once, or retain its artifacts without retry"]
pub struct CreationOwner {
    anchor: Option<Anchor>,
    target: Option<File>,
    lock: Option<File>,
    original_empty: FileId,
    lock_id: FileId,
    image: EmptyStoreImage,
    _owner_thread: PhantomData<Rc<()>>,
}
/// Original successful creation only; no signing, full init or G-v acceptance.
#[derive(Debug)]
pub struct CreatedReceipt {
    site_id: [u8; 16],
    sha256: [u8; 32],
    bytes: usize,
    checked_owner_fds: usize,
}
impl CreatedReceipt {
    pub fn site_id(&self) -> [u8; 16] {
        self.site_id
    }
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
impl CreationOwner {
    fn verify_markers_and_anchors(&mut self) -> Result<(), CreateFailure> {
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| created("init_anchor_missing"))?;
        anchor.check().map_err(created)?;
        for name in OTHER_MARKERS {
            anchor.require_absent(name).map_err(created)?;
        }
        let lock = self
            .lock
            .as_mut()
            .ok_or_else(|| created("init_lock_missing"))?;
        if anchor.verify(lock, LOCK, LOCK_BYTES).map_err(created)? != self.lock_id {
            return Err(created("init_lock_changed"));
        }
        Ok(())
    }
    pub fn finish(self) -> Result<CreatedReceipt, CreateFailure> {
        self.finish_inner(false)
    }
    /// The full image may now be readable, but there is no original completion.
    #[cfg(feature = "private-probe")]
    pub fn refuse_after_write_for_private_probe(self) -> Result<CreatedReceipt, CreateFailure> {
        self.finish_inner(true)
    }
    fn finish_inner(mut self, stop_before_sync: bool) -> Result<CreatedReceipt, CreateFailure> {
        self.verify_markers_and_anchors()?;
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| created("init_anchor_missing"))?;
        let target = self
            .target
            .as_mut()
            .ok_or_else(|| created("init_target_missing"))?;
        let empty = anchor.read_held(target, TARGET, 0).map_err(created)?;
        if empty.id != self.original_empty || !empty.bytes.is_empty() {
            return Err(created("init_empty_target_changed"));
        }
        target
            .write_all(&self.image.bytes)
            .map_err(|_| created("init_target_write_unknown"))?;
        if stop_before_sync {
            return Err(created("controlled_after_write_before_sync"));
        }
        target
            .sync_all()
            .map_err(|_| created("init_target_sync_unknown"))?;
        fsync(&anchor.fd).map_err(|_| created("init_target_parent_sync_unknown"))?;
        let written = anchor
            .read_held(target, TARGET, self.image.bytes.len())
            .map_err(created)?;
        if !written.id.same_object(self.original_empty) || written.bytes != self.image.bytes {
            return Err(created("init_written_target_changed"));
        }
        self.verify_markers_and_anchors()?;
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| created("init_anchor_missing"))?;
        let target = self
            .target
            .as_mut()
            .ok_or_else(|| created("init_target_missing"))?;
        let final_image = anchor
            .read_held(target, TARGET, self.image.bytes.len())
            .map_err(created)?;
        if final_image != written {
            return Err(created("init_final_target_changed"));
        }
        anchor.check().map_err(created)?;
        checked_close::file(
            self.target
                .take()
                .ok_or_else(|| created("init_target_missing"))?,
        )
        .map_err(created)?;
        checked_close::file(
            self.lock
                .take()
                .ok_or_else(|| created("init_lock_missing"))?,
        )
        .map_err(created)?;
        // No target removal/replacement is possible. Even late release failure
        // cannot authorize another initial CREATE_NEW of this present target.
        unlinkat(&anchor.fd, LOCK, AtFlags::empty())
            .map_err(|_| created("init_release_unlink_unknown"))?;
        fsync(&anchor.fd).map_err(|_| created("init_release_parent_sync_unknown"))?;
        let checked = self
            .anchor
            .take()
            .ok_or_else(|| created("init_anchor_missing"))?
            .close_all()
            .map_err(created)?;
        Ok(CreatedReceipt {
            site_id: self.image.site_id,
            sha256: self.image.sha256,
            bytes: self.image.bytes.len(),
            checked_owner_fds: checked + 2,
        })
    }
}
