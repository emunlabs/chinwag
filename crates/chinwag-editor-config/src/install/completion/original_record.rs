//! Actual original completion ownership, never reconstructed from present records.
use super::{Completed, RecordOutcome};
use crate::install::{COMPLETED, Evidence, INTENT, LOCK, checked_close, digest, fs::FileId};
use rustix::fs::{AtFlags, fsync, unlinkat};
use std::fs::File;

#[must_use = "Retain the original guards on failure; never reconstruct this owner"]
pub(in crate::install) struct OriginalRecord {
    completed: Completed,
    record: File,
    record_bytes: Vec<u8>,
    record_id: FileId,
}
/// Observation of this original successful finish, not a constructor or retry grant.
pub(in crate::install) struct Finalized {
    evidence: Evidence,
    record_sha256: [u8; 32],
    checked_file_fds: usize,
    checked_directory_fds: usize,
}
impl Finalized {
    pub(in crate::install) fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    pub(in crate::install) fn record_sha256(&self) -> [u8; 32] {
        self.record_sha256
    }
    pub(in crate::install) fn checked_file_fds(&self) -> usize {
        self.checked_file_fds
    }
    pub(in crate::install) fn checked_directory_fds(&self) -> usize {
        self.checked_directory_fds
    }
}
impl OriginalRecord {
    // Visible only to the actual Completed writer, not its parent installer or observers.
    pub(super) fn new(
        completed: Completed,
        record: File,
        record_bytes: Vec<u8>,
        record_id: FileId,
    ) -> Self {
        Self {
            completed,
            record,
            record_bytes,
            record_id,
        }
    }
    /// Preserve the existing fixture contract: metadata only, guards retained on disk.
    pub(super) fn into_retained_receipt(self) -> RecordOutcome {
        RecordOutcome::Recorded {
            evidence: self.completed.evidence.clone(),
            record_sha256: digest(&self.record_bytes),
            record_dev: self.record_id.dev,
            record_ino: self.record_id.ino,
        }
    }
    /// A live normal outer guard is required throughout this original finish.
    pub(in crate::install) fn finish(
        mut self,
        guard: &crate::install::repository::OuterGuard,
    ) -> Result<Finalized, &'static str> {
        let verified = (|| {
            guard.verify_target(&self.completed.prepared.target)?;
            self.completed.check_original()?;
            let id = self.completed.prepared.target.anchor.verify(
                &mut self.record,
                COMPLETED,
                &self.record_bytes,
            )?;
            if id != self.record_id {
                return Err("original_record_identity_changed");
            }
            let intent_id = FileId::read(&self.completed.intent)?;
            Ok::<_, &'static str>(intent_id)
        })();
        let Self {
            completed,
            record,
            record_bytes,
            record_id,
        } = self;
        let Completed {
            prepared,
            intent,
            intent_bytes,
            evidence,
        } = completed;
        let crate::install::Prepared {
            target,
            file,
            staged,
            id: data_id,
            ..
        } = prepared;
        // Attempt every original close even after the first failure; never retry a raw FD.
        let data_closed = checked_close::file(file);
        let intent_closed = checked_close::file(intent);
        let record_closed = checked_close::file(record);
        let original_error = verified.as_ref().err().copied().or_else(|| {
            if data_closed.is_err() || intent_closed.is_err() || record_closed.is_err() {
                Some("original_record_checked_file_close")
            } else {
                None
            }
        });
        if let Some(error) = original_error {
            let _ = target.anchor.close_all();
            return Err(error);
        }
        let intent_id = verified?;
        let cleanup = (|| {
            guard.verify_target(&target)?;
            target.anchor.check()?;
            target.anchor.require_absent(LOCK)?;
            let data = target
                .anchor
                .read(target.name)?
                .ok_or("installed_data_missing")?;
            let intent = target
                .anchor
                .read_bounded(INTENT, 4096)?
                .ok_or("original_intent_missing")?;
            let record = target
                .anchor
                .read_bounded(COMPLETED, 4096)?
                .ok_or("original_record_missing")?;
            if data.id != data_id
                || data.bytes != staged
                || intent.id != intent_id
                || intent.bytes != intent_bytes
                || record.id != record_id
                || record.bytes != record_bytes
            {
                return Err("original_closed_name_or_bytes_changed");
            }
            // These are the original, just-verified names owned by this live token.
            guard.verify_target(&target)?;
            unlinkat(&target.anchor.fd, COMPLETED, AtFlags::empty())
                .map_err(|_| "original_record_unlink")?;
            fsync(&target.anchor.fd).map_err(|_| "original_record_unlink_sync")?;
            target.anchor.check()?;
            let intent = target
                .anchor
                .read_bounded(INTENT, 4096)?
                .ok_or("original_intent_missing")?;
            if intent.id != intent_id || intent.bytes != intent_bytes {
                return Err("original_intent_changed");
            }
            guard.verify_target(&target)?;
            unlinkat(&target.anchor.fd, INTENT, AtFlags::empty())
                .map_err(|_| "original_intent_unlink")?;
            fsync(&target.anchor.fd).map_err(|_| "original_intent_unlink_sync")?;
            target.anchor.check()?;
            target.anchor.require_absent(LOCK)?;
            target.anchor.require_absent(INTENT)?;
            target.anchor.require_absent(COMPLETED)?;
            let data = target
                .anchor
                .read(target.name)?
                .ok_or("installed_data_missing")?;
            if data.id != data_id || data.bytes != staged {
                return Err("installed_data_changed");
            }
            Ok::<_, &'static str>(())
        })();
        let outer_verified = guard.verify_target(&target);
        let directories = target.anchor.close_all();
        outer_verified?;
        cleanup?;
        let checked_directory_fds = directories?;
        Ok(Finalized {
            evidence,
            record_sha256: digest(&record_bytes),
            checked_file_fds: 3,
            checked_directory_fds,
        })
    }
}
