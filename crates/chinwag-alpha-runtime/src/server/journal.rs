//! Durable operation receipts. A pending record from another process lifetime
//! is uncertain, and is never interpreted as permission to invoke a sender.

use super::{open_regular, validate_receipt};
use crate::{Result, RuntimeError};
use chinwag_bus_client::{SendReceipt, SendRequest};
use rustix::fs::{FlockOperation, OFlags, flock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

const MAX_RECORD: u64 = 96 * 1024;

#[derive(Clone, Serialize, Deserialize)]
struct StoredRequest {
    sender: String,
    room: String,
    body: String,
    to: Option<String>,
    task_id: Option<String>,
}

impl From<&SendRequest> for StoredRequest {
    fn from(request: &SendRequest) -> Self {
        Self {
            sender: request.sender.clone(),
            room: request.room.clone(),
            body: request.body.clone(),
            to: request.to.clone(),
            task_id: request.task_id.clone(),
        }
    }
}

impl StoredRequest {
    fn fingerprint(&self) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(self).map_err(|_| RuntimeError::Unavailable(
                    "could not fingerprint operation".into()
                ))?
            )
        ))
    }
    fn request(&self) -> SendRequest {
        SendRequest {
            sender: self.sender.clone(),
            room: self.room.clone(),
            body: self.body.clone(),
            to: self.to.clone(),
            task_id: self.task_id.clone(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum AttemptState {
    Pending,
    Delivered,
    Uncertain,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Attempt {
    request_id: String,
    fingerprint: String,
    request: StoredRequest,
    pub state: AttemptState,
    receipt: Option<SendReceipt>,
    error: Option<String>,
    started_at: String,
    updated_at: String,
}

impl Attempt {
    pub fn matches(&self, request: &SendRequest) -> Result<bool> {
        Ok(self.fingerprint == StoredRequest::from(request).fingerprint()?)
    }

    pub fn lookup_payload(&self) -> Value {
        let mut value = json!({"ok":true,"request_id":self.request_id,"state":self.state});
        if let Some(receipt) = &self.receipt {
            value["receipt"] = json!(receipt);
        }
        if let Some(error) = &self.error {
            value["error"] = json!(error);
        }
        value
    }

    pub fn post_payload(&self) -> (axum::http::StatusCode, Value) {
        if let Some(receipt) = &self.receipt {
            (
                axum::http::StatusCode::OK,
                json!({"ok":true,"request_id":self.request_id,"state":"delivered","message":receipt.message,"ack":receipt.ack}),
            )
        } else {
            (
                axum::http::StatusCode::BAD_GATEWAY,
                json!({"ok":false,"request_id":self.request_id,"state":self.state,"error":self.error.as_deref().unwrap_or("publication is pending; check this request ID before taking further action")}),
            )
        }
    }
}

pub(super) struct AttemptJournal {
    root: PathBuf,
    directory: File,
    _guard: File,
    active_id: Option<String>,
    healthy: bool,
}

pub(super) fn validate_id(id: &str) -> Result<()> {
    if !(16..=100).contains(&id.len())
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(RuntimeError::Invalid(
            "request ID must contain 16..100 ASCII letters, digits, '_' or '-'".into(),
        ));
    }
    Ok(())
}

impl AttemptJournal {
    pub fn open(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            return Err(RuntimeError::Invalid(
                "journal directory must be absolute".into(),
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags((OFlags::NOFOLLOW | OFlags::DIRECTORY).bits() as i32)
            .open(&root)?;
        if !directory.metadata()?.is_dir() {
            return Err(RuntimeError::Invalid(
                "journal directory must be a non-symlink directory".into(),
            ));
        }
        let guard = open_regular(&root.join("operations.lock"), true, true)?;
        flock(&guard, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            RuntimeError::Unavailable(
                "operation journal is already owned or cannot be locked".into(),
            )
        })?;
        directory.sync_all()?;
        Ok(Self {
            root,
            directory,
            _guard: guard,
            active_id: None,
            healthy: true,
        })
    }

    pub fn healthy(&self) -> bool {
        self.healthy
    }

    pub fn lookup(&self, id: &str) -> Result<Option<Attempt>> {
        validate_id(id)?;
        let path = self.root.join(format!("{id}.json"));
        let mut file = match open_regular(&path, false, false) {
            Ok(file) => file,
            Err(RuntimeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if file.metadata()?.len() > MAX_RECORD {
            return Err(RuntimeError::Unavailable(
                "operation record exceeds byte limit".into(),
            ));
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_RECORD + 1)
            .read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_RECORD {
            return Err(RuntimeError::Unavailable(
                "operation record exceeds byte limit".into(),
            ));
        }
        let mut attempt: Attempt = serde_json::from_slice(&raw).map_err(|_| {
            RuntimeError::Unavailable(
                "operation journal record is malformed; preserved for inspection".into(),
            )
        })?;
        if attempt.request_id != id || attempt.request.fingerprint()? != attempt.fingerprint {
            return Err(RuntimeError::Unavailable(
                "operation journal identity/fingerprint mismatch".into(),
            ));
        }
        match (&attempt.state, &attempt.receipt) {
            (AttemptState::Delivered, Some(receipt)) => {
                validate_receipt(&attempt.request.request(), receipt)?
            }
            (AttemptState::Pending | AttemptState::Uncertain, None) => (),
            _ => {
                return Err(RuntimeError::Unavailable(
                    "operation journal state/receipt mismatch".into(),
                ));
            }
        }
        if attempt.state == AttemptState::Pending && self.active_id.as_deref() != Some(id) {
            attempt.state = AttemptState::Uncertain;
            attempt.error = Some("the previous process stopped before saving a final receipt; this attempt will not be repeated automatically".into());
        }
        Ok(Some(attempt))
    }

    pub fn begin(&mut self, id: &str, request: &SendRequest) -> Result<Attempt> {
        if !self.healthy {
            return Err(RuntimeError::StorageUncertain(
                "operation journal persistence failed".into(),
            ));
        }
        validate_id(id)?;
        if self.lookup(id)?.is_some() {
            return Err(RuntimeError::Rejected(
                "operation already exists; use its recorded outcome".into(),
            ));
        }
        let stored = StoredRequest::from(request);
        let now = chrono::Utc::now().to_rfc3339();
        let attempt = Attempt {
            request_id: id.into(),
            fingerprint: stored.fingerprint()?,
            request: stored,
            state: AttemptState::Pending,
            receipt: None,
            error: None,
            started_at: now.clone(),
            updated_at: now,
        };
        self.persist(&attempt)?;
        self.active_id = Some(id.into());
        Ok(attempt)
    }

    pub fn finish(&mut self, mut attempt: Attempt, result: Result<SendReceipt>) -> Result<Attempt> {
        self.active_id = None;
        attempt.updated_at = chrono::Utc::now().to_rfc3339();
        match result {
            Ok(receipt) => {
                attempt.state = AttemptState::Delivered;
                attempt.receipt = Some(receipt);
                attempt.error = None;
            }
            Err(error) => {
                attempt.state = AttemptState::Uncertain;
                attempt.error = Some(error.to_string());
            }
        }
        self.persist(&attempt)?;
        Ok(attempt)
    }

    fn persist(&mut self, attempt: &Attempt) -> Result<()> {
        let raw = serde_json::to_vec(attempt)
            .map_err(|_| RuntimeError::Unavailable("could not encode operation record".into()))?;
        if raw.len() as u64 > MAX_RECORD {
            return Err(RuntimeError::Unavailable(
                "operation record exceeds byte limit".into(),
            ));
        }
        let temp = self.root.join(format!(
            ".{}-{}-{}.tmp",
            attempt.request_id,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let target = self.root.join(format!("{}.json", attempt.request_id));
        // This is storage failure handling, independent from an individual
        // publication's uncertain outcome. Uncertain attempts do not block new IDs.
        self.healthy = false;
        let result = (|| -> std::io::Result<()> {
            if let Ok(metadata) = fs::symlink_metadata(&target)
                && !metadata.file_type().is_file()
            {
                return Err(std::io::Error::other(
                    "operation record is not a regular non-symlink file",
                ));
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(OFlags::NOFOLLOW.bits() as i32)
                .open(&temp)?;
            file.write_all(&raw)?;
            file.sync_all()?;
            fs::rename(&temp, &target)?;
            self.directory.sync_all()?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            return Err(RuntimeError::StorageUncertain(format!(
                "operation journal write failed: {error}"
            )));
        }
        self.healthy = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chinwag_bus_client::{BusAck, BusMessage};
    use tempfile::TempDir;

    fn request() -> SendRequest {
        SendRequest {
            sender: "Brian".into(),
            room: "#alpha".into(),
            body: "an explicit human message".into(),
            to: None,
            task_id: None,
        }
    }
    fn receipt() -> SendReceipt {
        SendReceipt {
            message: BusMessage {
                id: "actual-ack-id".into(),
                seq: 42,
                ts_iso: "2026-10-30T01:00:00Z".into(),
                room: "#alpha".into(),
                sender: "Brian".into(),
                body: request().body,
                to: None,
                task_id: None,
                sig_verified: true,
            },
            ack: BusAck {
                ok: true,
                seq: 42,
                message_id: "actual-ack-id".into(),
                transport: "actual-cli-transport".into(),
                room: "#alpha".into(),
                sig_verified: true,
                subscribers_notified: 2,
            },
        }
    }

    #[test]
    fn pending_is_durable_before_invocation_and_becomes_uncertain_after_crash_without_blocking_new_ids()
     {
        let root = TempDir::new().unwrap();
        let mut journal = AttemptJournal::open(root.path().into()).unwrap();
        assert!(AttemptJournal::open(root.path().into()).is_err());
        journal.begin("attempt-crash-0001", &request()).unwrap();
        assert!(matches!(
            journal.lookup("attempt-crash-0001").unwrap().unwrap().state,
            AttemptState::Pending
        ));
        let bytes = fs::read(root.path().join("attempt-crash-0001.json")).unwrap();
        let saved: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(saved["state"], "pending");
        assert_eq!(saved["request"]["body"], request().body);
        drop(journal);
        let mut restarted = AttemptJournal::open(root.path().into()).unwrap();
        let previous = restarted.lookup("attempt-crash-0001").unwrap().unwrap();
        assert!(matches!(previous.state, AttemptState::Uncertain));
        assert_eq!(
            previous.post_payload().0,
            axum::http::StatusCode::BAD_GATEWAY
        );
        assert!(restarted.healthy());
        let different = restarted.begin("attempt-crash-0002", &request()).unwrap();
        restarted.finish(different, Ok(receipt())).unwrap();
        assert_eq!(
            fs::read(root.path().join("attempt-crash-0001.json")).unwrap(),
            bytes
        );
    }

    #[test]
    fn delivered_actual_receipt_survives_restart_and_fingerprints_all_request_fields() {
        let root = TempDir::new().unwrap();
        let mut journal = AttemptJournal::open(root.path().into()).unwrap();
        let pending = journal.begin("attempt-saved-0001", &request()).unwrap();
        journal.finish(pending, Ok(receipt())).unwrap();
        drop(journal);
        let journal = AttemptJournal::open(root.path().into()).unwrap();
        let attempt = journal.lookup("attempt-saved-0001").unwrap().unwrap();
        assert!(matches!(attempt.state, AttemptState::Delivered));
        assert!(attempt.matches(&request()).unwrap());
        assert_eq!(attempt.lookup_payload()["receipt"], json!(receipt()));
        for field in ["body", "room", "sender", "to", "task_id"] {
            let mut different = request();
            match field {
                "body" => different.body.push('!'),
                "room" => different.room = "#eng".into(),
                "sender" => different.sender = "CODEX".into(),
                "to" => different.to = Some("other".into()),
                _ => different.task_id = Some("task".into()),
            };
            assert!(!attempt.matches(&different).unwrap(), "{field}");
        }
    }

    #[test]
    fn uncertain_outcome_is_per_attempt_and_does_not_poison_storage() {
        let root = TempDir::new().unwrap();
        let mut journal = AttemptJournal::open(root.path().into()).unwrap();
        let pending = journal.begin("attempt-unknown-01", &request()).unwrap();
        let unknown = journal
            .finish(
                pending,
                Err(RuntimeError::SendUncertain("lost stdout".into())),
            )
            .unwrap();
        assert!(matches!(unknown.state, AttemptState::Uncertain));
        assert!(journal.healthy());
        let next = journal.begin("attempt-unknown-02", &request()).unwrap();
        journal.finish(next, Ok(receipt())).unwrap();
        assert_eq!(
            journal
                .lookup("attempt-unknown-01")
                .unwrap()
                .unwrap()
                .lookup_payload()["state"],
            "uncertain"
        );
    }

    #[test]
    fn operation_files_are_bounded_regular_non_symlink_and_unsafe_records_preserved() {
        let root = TempDir::new().unwrap();
        let journal = AttemptJournal::open(root.path().into()).unwrap();
        let path = root.path().join("attempt-unsafe-01.json");
        fs::write(&path, vec![b'x'; MAX_RECORD as usize + 1]).unwrap();
        assert!(journal.lookup("attempt-unsafe-01").is_err());
        fs::write(&path, b"malformed").unwrap();
        assert!(journal.lookup("attempt-unsafe-01").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"malformed");
        fs::remove_file(&path).unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"preserved").unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(journal.lookup("attempt-unsafe-01").is_err());
        assert_eq!(fs::read(outside).unwrap(), b"preserved");
        assert!(journal.lookup("../attempt-unsafe-01").is_err());
    }

    #[test]
    fn persistence_failure_is_a_storage_fault_separate_from_send_uncertainty() {
        let root = TempDir::new().unwrap();
        let mut journal = AttemptJournal::open(root.path().into()).unwrap();
        let pending = journal.begin("attempt-storage-01", &request()).unwrap();
        let path = root.path().join("attempt-storage-01.json");
        fs::remove_file(&path).unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"preserved").unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(matches!(
            journal.finish(pending, Ok(receipt())),
            Err(RuntimeError::StorageUncertain(_))
        ));
        assert!(!journal.healthy());
        assert!(journal.begin("attempt-storage-02", &request()).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"preserved");
    }
}
