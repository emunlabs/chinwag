//! Only an original successful commit can own a completion writer.
use super::{COMPLETED, Evidence, INTENT, LOCK, Prepared, digest, fs::FileId, hex};
use rustix::fs::fsync;
mod original_record;
pub(super) use original_record::OriginalRecord;
use std::{fmt, fs::File, io::Write};

/// Opaque and consumed by writing a record. Dropping retains every guard.
#[must_use = "Dropping original completion ownership retains the intent without a completed record"]
pub struct Completed {
    prepared: Prepared,
    intent: File,
    intent_bytes: Vec<u8>,
    evidence: Evidence,
}
impl fmt::Debug for Completed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Completed")
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
#[must_use = "Persist record outcomes. An unknown record outcome must not be retried"]
pub enum RecordOutcome {
    Recorded {
        evidence: Evidence,
        record_sha256: [u8; 32],
        record_dev: i32,
        record_ino: u64,
    },
    BeforeRecordRefused {
        evidence: Evidence,
        reason: &'static str,
    },
    RecordOutcomeUnknown {
        evidence: Evidence,
        reason: &'static str,
    },
}
#[derive(Clone, Copy)]
enum RecordFault {
    None,
    #[cfg(test)]
    AfterCreate,
    #[cfg(test)]
    AfterWriteBeforeSync,
}
impl Completed {
    pub(super) fn from_original(
        prepared: Prepared,
        intent: File,
        intent_bytes: Vec<u8>,
        evidence: Evidence,
    ) -> Self {
        Self {
            prepared,
            intent,
            intent_bytes,
            evidence,
        }
    }
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    pub fn write_record(self: Box<Self>) -> RecordOutcome {
        (*self).write_inner(RecordFault::None)
    }

    fn check_original(&mut self) -> Result<(), &'static str> {
        let anchor = &self.prepared.target.anchor;
        let parent = anchor.check()?;
        if (parent.dev, parent.ino) != (self.evidence.parent_dev, self.evidence.parent_ino) {
            return Err("completed_parent_changed");
        }
        anchor.require_absent(LOCK)?;
        let installed = anchor.verify(
            &mut self.prepared.file,
            self.prepared.target.name,
            &self.prepared.staged,
        )?;
        if installed != self.prepared.id {
            return Err("completed_installed_identity_changed");
        }
        // The original intent FD must still name the original literal metadata.
        anchor.verify(&mut self.intent, INTENT, &self.intent_bytes)?;
        anchor.check()?;
        Ok(())
    }
    // Only this original successful writer can produce the live record owner.
    // Existing public metadata behavior deliberately retains all original guards.
    pub(super) fn record_original(
        self: Box<Self>,
        guard: &super::repository::OuterGuard,
    ) -> Result<OriginalRecord, Box<RecordOutcome>> {
        (*self).write_owned(RecordFault::None, Some(guard))
    }
    fn write_inner(self, fault: RecordFault) -> RecordOutcome {
        match self.write_owned(fault, None) {
            Ok(record) => record.into_retained_receipt(),
            Err(outcome) => *outcome,
        }
    }
    fn write_owned(
        mut self,
        fault: RecordFault,
        guard: Option<&super::repository::OuterGuard>,
    ) -> Result<OriginalRecord, Box<RecordOutcome>> {
        let before = (|| {
            self.prepared.target.check_guard(guard)?;
            self.check_original()?;
            self.prepared.target.anchor.require_absent(COMPLETED)?;
            let e = &self.evidence;
            let body = serde_json::to_vec(&serde_json::json!({
                "format":"chinwag-private-config-completed/v1",
                "target":e.target_basename,"parent_dev":e.parent_dev,"parent_ino":e.parent_ino,
                "original_sha256":e.original_sha256.map(|h|hex(&h)),
                "staged_sha256":hex(&e.staged_sha256),"staged_dev":e.staged_dev,"staged_ino":e.staged_ino,
                "intent_sha256":hex(&digest(&self.intent_bytes)),
            })).map_err(|_| "completed_encoding")?;
            if body.len() > 4096 {
                return Err("completed_limit");
            }
            Ok::<_, &'static str>(body)
        })();
        let body = match before {
            Ok(body) => body,
            Err(reason) => {
                return Err(Box::new(RecordOutcome::BeforeRecordRefused {
                    evidence: self.evidence,
                    reason,
                }));
            }
        };
        let mut record = match self.prepared.target.anchor.exclusive(COMPLETED) {
            Ok(file) => file,
            Err(reason) => {
                return Err(Box::new(RecordOutcome::BeforeRecordRefused {
                    evidence: self.evidence,
                    reason,
                }));
            }
        };
        // Every later error retains the created record and consumes this owner.
        let written = (|| {
            self.prepared.target.check_guard(guard)?;
            FileId::read(&record)?;
            #[cfg(test)]
            if matches!(fault, RecordFault::AfterCreate) {
                return Err("fixture_after_record_create");
            }
            self.check_original()?;
            self.prepared.target.check_guard(guard)?;
            record.write_all(&body).map_err(|_| "completed_write")?;
            #[cfg(test)]
            if matches!(fault, RecordFault::AfterWriteBeforeSync) {
                return Err("fixture_after_record_write_before_sync");
            }
            let _ = fault;
            record.sync_all().map_err(|_| "completed_sync")?;
            fsync(&self.prepared.target.anchor.fd).map_err(|_| "completed_parent_sync")?;
            self.check_original()?;
            let id = self
                .prepared
                .target
                .anchor
                .verify(&mut record, COMPLETED, &body)?;
            self.prepared.target.anchor.check()?;
            Ok::<_, &'static str>(id)
        })();
        match written {
            Ok(id) => Ok(OriginalRecord::new(self, record, body, id)),
            Err(reason) => Err(Box::new(RecordOutcome::RecordOutcomeUnknown {
                evidence: self.evidence,
                reason,
            })),
        }
    }
}

#[cfg(test)]
#[path = "completion_tests.rs"]
mod tests;
