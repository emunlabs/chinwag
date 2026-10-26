#[cfg(feature = "private-probe")]
use super::Cut;
use super::{
    Candidate, Control, NoWriteReceipt, Observation, Pending, Result, WriteReceipt, before, hex,
    retained,
};
use crate::{
    checked_close,
    replacement_fs::{Anchor, DetachedImage, FileId, Image},
};
use rustix::fs::{AtFlags, fsync, renameat, unlinkat};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, marker::PhantomData, path::Path, rc::Rc};

const TARGET: &str = "state.crdb";
const LOCK: &str = "state.crdb.lock";
const NEXT: &str = "state.crdb.next";
const INTENT: &str = "state.crdb.intent";
const LOCK_BYTES: &[u8] = b"chinwag-private-snapshot-write-lock/v1\n";
const EXTRA: [&str; 4] = [
    "state.crdb.complete",
    "state.crdb-journal",
    "state.crdb-wal",
    "state.crdb-shm",
];
fn extras_absent(anchor: &Anchor) -> std::result::Result<(), &'static str> {
    for name in EXTRA {
        anchor.require_absent(name)?;
    }
    Ok(())
}
fn remaining_absent(anchor: &Anchor) -> std::result::Result<(), &'static str> {
    for name in [NEXT, INTENT] {
        anchor.require_absent(name)?;
    }
    extras_absent(anchor)
}
fn close(file: &mut Option<File>, staged: bool, renamed: bool) -> Result<()> {
    checked_close::file(
        file.take()
            .ok_or_else(|| retained("write_fd_missing", staged, renamed))?,
    )
    .map_err(|_| retained("write_checked_close", staged, renamed))
}

#[must_use = "Only the original owner can complete its operation; Drop retains all names"]
pub struct WriteOwner {
    anchor: Option<Anchor>,
    source: Option<File>,
    lock: Option<File>,
    original: Image,
    lock_id: FileId,
    _thread: PhantomData<Rc<()>>,
}
impl WriteOwner {
    pub fn acquire_existing_private_fixture(repo: &Path) -> Result<Self> {
        let anchor = Anchor::open_fixture(repo).map_err(before)?;
        anchor.require_absent(LOCK).map_err(before)?;
        remaining_absent(&anchor).map_err(before)?;
        // Source metadata only until this original CREATE_NEW lock exists.
        let mut source = anchor.open_existing(TARGET).map_err(before)?;
        let observed = FileId::read(&source).map_err(before)?;
        anchor.check().map_err(before)?;
        let mut lock = anchor.exclusive(LOCK).map_err(before)?;
        let (original, lock_id) = (|| {
            lock.write_all(LOCK_BYTES).map_err(|_| "write_lock_write")?;
            lock.sync_all().map_err(|_| "write_lock_sync")?;
            let lock_id = anchor.verify(&mut lock, LOCK, LOCK_BYTES)?;
            fsync(&anchor.fd).map_err(|_| "write_lock_parent_sync")?;
            anchor.check()?;
            remaining_absent(&anchor)?;
            let original = anchor.read_held(&mut source, TARGET, crate::MAX_IMAGE_BYTES)?;
            if original.id != observed {
                return Err("write_source_changed_before_locked_read");
            }
            anchor.check()?;
            Ok((original, lock_id))
        })()
        .map_err(|e| retained(e, false, false))?;
        Ok(Self {
            anchor: Some(anchor),
            source: Some(source),
            lock: Some(lock),
            original,
            lock_id,
            _thread: PhantomData,
        })
    }
    pub(super) fn image(&self) -> &[u8] {
        &self.original.bytes
    }
    fn verify_original(&mut self) -> Result<()> {
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", false, false))?;
        anchor.check().map_err(|e| retained(e, false, false))?;
        extras_absent(anchor).map_err(|e| retained(e, false, false))?;
        let original = anchor
            .read_held(
                self.source
                    .as_mut()
                    .ok_or_else(|| retained("write_source_missing", false, false))?,
                TARGET,
                self.original.bytes.len(),
            )
            .map_err(|e| retained(e, false, false))?;
        if original != self.original {
            return Err(retained("write_source_changed", false, false));
        }
        if anchor
            .verify(
                self.lock
                    .as_mut()
                    .ok_or_else(|| retained("write_lock_missing", false, false))?,
                LOCK,
                LOCK_BYTES,
            )
            .map_err(|e| retained(e, false, false))?
            != self.lock_id
        {
            return Err(retained("write_lock_changed", false, false));
        }
        anchor.check().map_err(|e| retained(e, false, false))
    }
    pub(super) fn verify_unchanged(&mut self) -> Result<()> {
        self.verify_original()?;
        remaining_absent(
            self.anchor
                .as_ref()
                .ok_or_else(|| retained("write_anchor_missing", false, false))?,
        )
        .map_err(|e| retained(e, false, false))
    }
    pub(super) fn finish_unchanged(mut self, pending: Pending) -> Result<NoWriteReceipt> {
        if pending.decision.dirty || pending.old_version != pending.new_version {
            return Err(retained("write_no_change_binding", false, false));
        }
        self.verify_unchanged()?;
        close(&mut self.source, false, false)?;
        close(&mut self.lock, false, false)?;
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", false, false))?;
        anchor.check().map_err(|e| retained(e, false, false))?;
        remaining_absent(anchor).map_err(|e| retained(e, false, false))?;
        if anchor
            .named_id(TARGET)
            .map_err(|e| retained(e, false, false))?
            != self.original.id
            || anchor
                .named_id(LOCK)
                .map_err(|e| retained(e, false, false))?
                != self.lock_id
        {
            return Err(retained("write_no_change_final_identity", false, false));
        }
        unlinkat(&anchor.fd, LOCK, AtFlags::empty())
            .map_err(|_| retained("write_no_change_unlink_unknown", false, false))?;
        // No data/intent operations after exclusion release.
        fsync(&anchor.fd)
            .map_err(|_| retained("write_no_change_release_sync_unknown", false, false))?;
        let checked = self
            .anchor
            .take()
            .ok_or_else(|| retained("write_anchor_missing", false, false))?
            .close_all()
            .map_err(|e| retained(e, false, false))?;
        let digest = Sha256::digest(&self.original.bytes).into();
        Ok(NoWriteReceipt {
            observation: Observation {
                kind: pending.kind,
                outcome: pending.decision.outcome,
                old_sha256: digest,
                new_sha256: digest,
                bytes: self.original.bytes.len(),
                site_id: pending.site,
                old_db_version: pending.old_version,
                new_db_version: pending.new_version,
                request_digest: pending.request_digest,
                generation: None,
                checked_owner_fds: checked + 2,
                native_before_file_release: pending.native_closed,
                replacement_identities: None,
            },
            response: pending.decision.response,
            is_error: pending.decision.is_error,
        })
    }
    pub(super) fn install(
        mut self,
        candidate: Candidate,
        pending: Pending,
        _control: &mut Control,
    ) -> Result<InstalledCompletion> {
        self.verify_unchanged()?;
        // Every error after this staging attempt is retained, not cleanup/retry.
        self.install_inner(candidate, pending, _control)
            .map_err(|mut error| {
                error.staging_attempted_no_retry = true;
                error
            })
    }
    fn install_inner(
        mut self,
        candidate: Candidate,
        pending: Pending,
        _control: &mut Control,
    ) -> Result<InstalledCompletion> {
        let mut next = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, false))?
            .exclusive(NEXT)
            .map_err(|e| retained(e, true, false))?;
        let empty = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, false))?
            .read_held(&mut next, NEXT, 0)
            .map_err(|e| retained(e, true, false))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterNextCreate, true, false)?;
        next.write_all(&candidate.bytes)
            .map_err(|_| retained("write_next_write_unknown", true, false))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterNextWrite, true, false)?;
        next.sync_all()
            .map_err(|_| retained("write_next_sync_unknown", true, false))?;
        let staged = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, false))?
            .read_held(&mut next, NEXT, candidate.bytes.len())
            .map_err(|e| retained(e, true, false))?;
        if staged.bytes != candidate.bytes
            || !staged.id.same_inode(empty.id)
            || staged.id.same_inode(self.original.id)
        {
            return Err(retained("write_next_image_changed", true, false));
        }
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterNextSync, true, false)?;
        self.verify_original()?;
        let (intent_bytes, generation) = intent_bytes(&self, &staged, &candidate, &pending)?;
        let mut intent = {
            let anchor = self
                .anchor
                .as_ref()
                .ok_or_else(|| retained("write_anchor_missing", true, false))?;
            anchor
                .require_absent(INTENT)
                .map_err(|e| retained(e, true, false))?;
            extras_absent(anchor).map_err(|e| retained(e, true, false))?;
            anchor
                .exclusive(INTENT)
                .map_err(|e| retained(e, true, false))?
        };
        intent
            .write_all(&intent_bytes)
            .map_err(|_| retained("write_intent_write_unknown", true, false))?;
        intent
            .sync_all()
            .map_err(|_| retained("write_intent_sync_unknown", true, false))?;
        let intent_id = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, false))?
            .verify(&mut intent, INTENT, &intent_bytes)
            .map_err(|e| retained(e, true, false))?;
        fsync(
            &self
                .anchor
                .as_ref()
                .ok_or_else(|| retained("write_anchor_missing", true, false))?
                .fd,
        )
        .map_err(|_| retained("write_intent_parent_sync_unknown", true, false))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterIntent, true, false)?;
        self.verify_original()?;
        let anchor = self
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, false))?;
        if anchor
            .read_held(&mut next, NEXT, staged.bytes.len())
            .map_err(|e| retained(e, true, false))?
            != staged
            || anchor
                .verify(&mut intent, INTENT, &intent_bytes)
                .map_err(|e| retained(e, true, false))?
                != intent_id
        {
            return Err(retained("write_pre_rename_artifact_changed", true, false));
        }
        anchor.check().map_err(|e| retained(e, true, false))?;
        // Exactly one call. Any returned error is UNKNOWN; no errno-based replay.
        renameat(&anchor.fd, NEXT, &anchor.fd, TARGET)
            .map_err(|_| retained("write_rename_unknown", true, true))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterRename, true, true)?;
        let post_new = anchor
            .read_held(&mut next, TARGET, candidate.bytes.len())
            .map_err(|e| retained(e, true, true))?;
        if !post_new.id.same_renamed_image(staged.id) || post_new.bytes != candidate.bytes {
            return Err(retained("write_post_rename_image_changed", true, true));
        }
        let post_old = anchor
            .read_detached(
                self.source
                    .as_mut()
                    .ok_or_else(|| retained("write_source_missing", true, true))?,
                &self.original,
            )
            .map_err(|e| retained(e, true, true))?;
        anchor
            .require_absent(NEXT)
            .map_err(|e| retained(e, true, true))?;
        fsync(&anchor.fd).map_err(|_| retained("write_renamed_parent_sync_unknown", true, true))?;
        let mut installed = InstalledCompletion {
            owner: self,
            next: Some(next),
            intent: Some(intent),
            intent_bytes,
            intent_id,
            post_new,
            post_old,
            pending,
            generation,
            new_sha256: candidate.sha256,
            staged_id: staged.id,
        };
        installed.verify()?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterPostcheck, true, true)?;
        Ok(installed)
    }
}
fn intent_bytes(
    owner: &WriteOwner,
    staged: &Image,
    candidate: &Candidate,
    pending: &Pending,
) -> Result<(Vec<u8>, [u8; 32])> {
    let old_hash: [u8; 32] = Sha256::digest(&owner.original.bytes).into();
    let fields = [
        "chinwag-private-snapshot-replace-intent/v1".into(),
        owner.lock_id.record(),
        owner.original.id.record(),
        hex(&old_hash),
        owner.original.bytes.len().to_string(),
        staged.id.record(),
        hex(&candidate.sha256),
        candidate.bytes.len().to_string(),
        hex(&pending.site),
        pending.old_version.to_string(),
        pending.new_version.to_string(),
        pending.kind.into(),
        hex(&pending.request_digest),
    ];
    let mut hash = Sha256::new();
    for field in &fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    let generation: [u8; 32] = hash.finalize().into();
    let mut bytes = format!("generation={}\n", hex(&generation)).into_bytes();
    for field in fields {
        bytes.extend_from_slice(field.as_bytes());
        bytes.push(b'\n');
    }
    if bytes.len() > 8192 {
        return Err(retained("write_intent_limit", true, false));
    }
    Ok((bytes, generation))
}

/// Never constructed by metadata/readback; only the original verified install.
pub(super) struct InstalledCompletion {
    owner: WriteOwner,
    next: Option<File>,
    intent: Option<File>,
    intent_bytes: Vec<u8>,
    intent_id: FileId,
    post_new: Image,
    post_old: DetachedImage,
    pending: Pending,
    generation: [u8; 32],
    new_sha256: [u8; 32],
    staged_id: FileId,
}
impl InstalledCompletion {
    fn verify(&mut self) -> Result<()> {
        let anchor = self
            .owner
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, true))?;
        anchor.check().map_err(|e| retained(e, true, true))?;
        extras_absent(anchor).map_err(|e| retained(e, true, true))?;
        anchor
            .require_absent(NEXT)
            .map_err(|e| retained(e, true, true))?;
        if anchor
            .verify(
                self.owner
                    .lock
                    .as_mut()
                    .ok_or_else(|| retained("write_lock_missing", true, true))?,
                LOCK,
                LOCK_BYTES,
            )
            .map_err(|e| retained(e, true, true))?
            != self.owner.lock_id
            || anchor
                .verify(
                    self.intent
                        .as_mut()
                        .ok_or_else(|| retained("write_intent_missing", true, true))?,
                    INTENT,
                    &self.intent_bytes,
                )
                .map_err(|e| retained(e, true, true))?
                != self.intent_id
            || anchor
                .read_held(
                    self.next
                        .as_mut()
                        .ok_or_else(|| retained("write_next_missing", true, true))?,
                    TARGET,
                    self.post_new.bytes.len(),
                )
                .map_err(|e| retained(e, true, true))?
                != self.post_new
            || anchor
                .read_detached(
                    self.owner
                        .source
                        .as_mut()
                        .ok_or_else(|| retained("write_source_missing", true, true))?,
                    &self.owner.original,
                )
                .map_err(|e| retained(e, true, true))?
                != self.post_old
        {
            return Err(retained("write_original_completion_changed", true, true));
        }
        anchor.check().map_err(|e| retained(e, true, true))
    }
    fn verify_after_data_closes(&mut self, intent_present: bool) -> Result<()> {
        let anchor = self
            .owner
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, true))?;
        anchor.check().map_err(|e| retained(e, true, true))?;
        extras_absent(anchor).map_err(|e| retained(e, true, true))?;
        anchor
            .require_absent(NEXT)
            .map_err(|e| retained(e, true, true))?;
        if anchor
            .named_id(TARGET)
            .map_err(|e| retained(e, true, true))?
            != self.post_new.id
            || anchor
                .verify(
                    self.owner
                        .lock
                        .as_mut()
                        .ok_or_else(|| retained("write_lock_missing", true, true))?,
                    LOCK,
                    LOCK_BYTES,
                )
                .map_err(|e| retained(e, true, true))?
                != self.owner.lock_id
        {
            return Err(retained("write_cleanup_binding_changed", true, true));
        }
        if intent_present {
            if anchor
                .named_id(INTENT)
                .map_err(|e| retained(e, true, true))?
                != self.intent_id
            {
                return Err(retained("write_cleanup_intent_changed", true, true));
            }
        } else {
            anchor
                .require_absent(INTENT)
                .map_err(|e| retained(e, true, true))?;
        }
        Ok(())
    }
    pub(super) fn finish(mut self, _control: &mut Control) -> Result<WriteReceipt> {
        self.verify()?;
        close(&mut self.owner.source, true, true)?;
        close(&mut self.next, true, true)?;
        close(&mut self.intent, true, true)?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterDataCloses, true, true)?;
        self.verify_after_data_closes(true)?;
        let anchor = self
            .owner
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, true))?;
        unlinkat(&anchor.fd, INTENT, AtFlags::empty())
            .map_err(|_| retained("write_intent_unlink_unknown", true, true))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterIntentUnlink, true, true)?;
        fsync(&anchor.fd).map_err(|_| retained("write_intent_cleanup_sync_unknown", true, true))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterIntentSync, true, true)?;
        self.verify_after_data_closes(false)?;
        close(&mut self.owner.lock, true, true)?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterLockClose, true, true)?;
        let anchor = self
            .owner
            .anchor
            .as_ref()
            .ok_or_else(|| retained("write_anchor_missing", true, true))?;
        anchor.check().map_err(|e| retained(e, true, true))?;
        remaining_absent(anchor).map_err(|e| retained(e, true, true))?;
        if anchor
            .named_id(TARGET)
            .map_err(|e| retained(e, true, true))?
            != self.post_new.id
            || anchor.named_id(LOCK).map_err(|e| retained(e, true, true))? != self.owner.lock_id
        {
            return Err(retained("write_lock_release_binding_changed", true, true));
        }
        unlinkat(&anchor.fd, LOCK, AtFlags::empty())
            .map_err(|_| retained("write_lock_unlink_unknown", true, true))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterLockUnlink, true, true)?;
        // A fresh owner may start now. No further target/intent namespace access.
        fsync(&anchor.fd).map_err(|_| retained("write_release_sync_unknown", true, true))?;
        #[cfg(feature = "private-probe")]
        _control.visit(Cut::AfterReleaseSync, true, true)?;
        let checked = self
            .owner
            .anchor
            .take()
            .ok_or_else(|| retained("write_anchor_missing", true, true))?
            .close_all()
            .map_err(|e| retained(e, true, true))?;
        let old_sha256 = Sha256::digest(&self.owner.original.bytes).into();
        let identities = serde_json::json!({
            "old_linked": identity_json(self.owner.original.id.observation()),
            "old_detached": identity_json(self.post_old.id.observation()),
            "staged": identity_json(self.staged_id.observation()),
            "renamed_target": identity_json(self.post_new.id.observation()),
            "old_bytes_verified_unchanged": true
        });
        Ok(WriteReceipt {
            observation: Observation {
                kind: self.pending.kind,
                outcome: self.pending.decision.outcome,
                old_sha256,
                new_sha256: self.new_sha256,
                bytes: self.post_new.bytes.len(),
                site_id: self.pending.site,
                old_db_version: self.pending.old_version,
                new_db_version: self.pending.new_version,
                request_digest: self.pending.request_digest,
                generation: Some(self.generation),
                checked_owner_fds: checked + 4,
                native_before_file_release: self.pending.native_closed,
                replacement_identities: Some(identities),
            },
            response: self.pending.decision.response,
            is_error: self.pending.decision.is_error,
        })
    }
}

fn identity_json((device, inode, nlink, times): (i32, u64, u64, [i128; 4])) -> serde_json::Value {
    serde_json::json!({"device":device,"inode":inode,"nlink":nlink,
        "mtime":[times[0],times[1]],"ctime":[times[2],times[3]]})
}
