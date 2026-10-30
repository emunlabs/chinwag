use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use chinwag_bus_client::{
    OperationState, SendOperation, SendReceipt, SendRequest, new_request_id, validate_request_id,
};
use rustix::fs::{FlockOperation, OFlags, flock};
use serde_json::{Value, json};

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 128;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptState {
    Pending,
    Uncertain(String),
    Delivered(Box<SendReceipt>),
    Rejected(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub id: String,
    pub endpoint: String,
    pub request: SendRequest,
    pub state: AttemptState,
}

impl Attempt {
    pub fn unresolved(&self) -> bool {
        matches!(
            self.state,
            AttemptState::Pending | AttemptState::Uncertain(_)
        )
    }

    pub fn visible_in_send_history(&self) -> bool {
        self.unresolved()
            || matches!(&self.state, AttemptState::Delivered(receipt) if !isolated_transport(&receipt.ack.transport))
    }

    pub fn receipt(&self) -> Option<&SendReceipt> {
        match &self.state {
            AttemptState::Delivered(receipt) => Some(receipt),
            _ => None,
        }
    }
}

pub fn isolated_transport(transport: &str) -> bool {
    transport == "local-jsonl-alpha (unsigned, isolated)"
}

pub fn receipt_summary(transport: &str, subscribers_notified: Option<usize>) -> String {
    let subscribers =
        subscribers_notified.map_or_else(|| "unavailable".into(), |count| count.to_string());
    if isolated_transport(transport) {
        format!(
            "Stored in isolated alpha; fleet delivery disabled · transport: {transport} · subscribers notified: {subscribers}"
        )
    } else {
        format!(
            "Stored in native bus; Grok Bot receipt unconfirmed · transport: {transport} · native subscribers notified: {subscribers}"
        )
    }
}

pub struct Outbox {
    path: PathBuf,
    pub attempts: Vec<Attempt>,
    _guard: File,
}

pub fn path_for_drafts(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("draft path has no filename"))?;
    Ok(path.with_file_name(format!("{}.outbox.json", name.to_string_lossy())))
}

impl Outbox {
    pub fn open(path: PathBuf) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("outbox path must be absolute"));
        }
        let lock = path.with_file_name(format!(
            "{}.lock",
            path.file_name()
                .ok_or_else(|| invalid("outbox has no filename"))?
                .to_string_lossy()
        ));
        let guard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(lock)?;
        if !guard.metadata()?.is_file() {
            return Err(invalid("outbox lock is not a regular file"));
        }
        flock(&guard,FlockOperation::NonBlockingLockExclusive).map_err(|_| invalid("another window owns this send history; use that window or a different state directory"))?;
        let attempts = match fs::symlink_metadata(&path) {
            Ok(before) => {
                if !before.is_file() || before.file_type().is_symlink() {
                    return Err(invalid("outbox must be a regular non-symlink file"));
                }
                let mut file = File::open(&path)?;
                let after = file.metadata()?;
                if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
                    return Err(invalid("outbox changed while opening"));
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take((MAX_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_BYTES {
                    return Err(invalid("outbox exceeds 4 MiB"));
                }
                let value: Value = serde_json::from_slice(&bytes).map_err(json_error)?;
                decode(&value)?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            path,
            attempts,
            _guard: guard,
        })
    }

    pub fn blocks(&self, endpoint: &str, request: &SendRequest) -> bool {
        self.attempts.iter().any(|attempt| {
            attempt.unresolved()
                && attempt.endpoint == endpoint
                && attempt.request.sender == request.sender
                && attempt.request.room == request.room
                && attempt.request.to == request.to
                && attempt.request.task_id == request.task_id
                && attempt.request.body.trim() == request.body.trim()
        })
    }

    /// The pending record reaches durable storage before a POST is permitted.
    pub fn prepare(&mut self, endpoint: &str, request: SendRequest) -> io::Result<Attempt> {
        validate_request(&request)?;
        if self.blocks(endpoint, &request) {
            return Err(invalid(
                "This exact message has an unconfirmed attempt. Use Check send receipt; it will not publish again.",
            ));
        }
        let attempt = Attempt {
            id: new_request_id().map_err(|error| invalid(&error.to_string()))?,
            endpoint: endpoint.to_owned(),
            request,
            state: AttemptState::Pending,
        };
        let mut next = self.attempts.clone();
        while next.len() >= MAX_ATTEMPTS {
            let index = next.iter().position(|entry| !entry.unresolved())
                .ok_or_else(|| invalid("Outbox is full of unconfirmed attempts; resolve an existing attempt before sending more"))?;
            next.remove(index);
        }
        next.push(attempt.clone());
        self.save(&next)?;
        self.attempts = next;
        Ok(attempt)
    }

    pub fn update(&mut self, id: &str, state: AttemptState) -> io::Result<()> {
        let mut next = self.attempts.clone();
        let entry = next
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| invalid("unknown local outbox attempt"))?;
        if let AttemptState::Delivered(actual) = &entry.state {
            if let AttemptState::Delivered(receipt) = &state
                && actual != receipt
            {
                return Err(invalid("conflicting receipts for one outbox attempt"));
            }
            // A GET racing the POST may still report pending; it cannot erase
            // the validated receipt that already arrived for this attempt.
            return Ok(());
        }
        if let AttemptState::Delivered(receipt) = &state {
            receipt
                .validate_for(&entry.request)
                .map_err(|error| invalid(&error.to_string()))?;
        }
        entry.state = state;
        self.save(&next)?;
        self.attempts = next;
        Ok(())
    }

    pub fn apply_status(&mut self, id: &str, operation: SendOperation) -> io::Result<AttemptState> {
        if operation.request_id != id {
            return Err(invalid("status belongs to a different attempt"));
        }
        let state = match operation.state {
            OperationState::Delivered(receipt) => AttemptState::Delivered(receipt),
            OperationState::Pending => AttemptState::Pending,
            OperationState::Uncertain(error) => AttemptState::Uncertain(error),
        };
        self.update(id, state)?;
        Ok(self
            .attempts
            .iter()
            .find(|entry| entry.id == id)
            .expect("update requires an existing entry")
            .state
            .clone())
    }

    fn save(&self, attempts: &[Attempt]) -> io::Result<()> {
        check_target(&self.path)?;
        let value = json!({"schema_version":1,"attempts":attempts.iter().map(|entry| {
            let (state, error, receipt) = match &entry.state {
                AttemptState::Pending => ("pending",None,None),
                AttemptState::Uncertain(error) => ("uncertain",Some(error),None),
                AttemptState::Rejected(error) => ("rejected",Some(error),None),
                AttemptState::Delivered(receipt) => ("delivered",None,Some(receipt)),
            };
            json!({"id":entry.id,"endpoint":entry.endpoint,"request":entry.request,"state":state,"error":error,"receipt":receipt})
        }).collect::<Vec<_>>()});
        let bytes = serde_json::to_vec(&value).map_err(json_error)?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("outbox exceeds 4 MiB; no send was started"));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("outbox has no parent directory"))?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".chinwag-outbox-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            check_target(&self.path)?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn decode(value: &Value) -> io::Result<Vec<Attempt>> {
    if value["schema_version"] != 1 {
        return Err(invalid("unknown outbox schema"));
    }
    let entries = value["attempts"]
        .as_array()
        .ok_or_else(|| invalid("outbox attempts must be an array"))?;
    if entries.len() > MAX_ATTEMPTS {
        return Err(invalid("too many outbox attempts"));
    }
    let mut attempts: Vec<Attempt> = Vec::new();
    for entry in entries {
        let text = |key: &str| {
            entry[key]
                .as_str()
                .ok_or_else(|| invalid("outbox text field missing"))
        };
        let id = text("id")?.to_owned();
        validate_request_id(&id).map_err(|error| invalid(&error.to_string()))?;
        if attempts.iter().any(|attempt| attempt.id == id) {
            return Err(invalid("duplicate outbox ID"));
        }
        let endpoint = text("endpoint")?.to_owned();
        if endpoint.len() > 2048 {
            return Err(invalid("outbox endpoint too long"));
        }
        let request: SendRequest =
            serde_json::from_value(entry["request"].clone()).map_err(json_error)?;
        validate_request(&request)?;
        let state = match text("state")? {
            "pending" => AttemptState::Pending,
            "uncertain" => AttemptState::Uncertain(text("error")?.to_owned()),
            "rejected" => AttemptState::Rejected(text("error")?.to_owned()),
            "delivered" => {
                let receipt: SendReceipt =
                    serde_json::from_value(entry["receipt"].clone()).map_err(json_error)?;
                receipt
                    .validate_for(&request)
                    .map_err(|error| invalid(&error.to_string()))?;
                AttemptState::Delivered(Box::new(receipt))
            }
            _ => return Err(invalid("unknown outbox attempt state")),
        };
        attempts.push(Attempt {
            id,
            endpoint,
            request,
            state,
        });
    }
    Ok(attempts)
}

fn validate_request(request: &SendRequest) -> io::Result<()> {
    if !matches!(request.room.as_str(), "#alpha" | "#mgmt" | "#eng" | "#qa")
        || request.body.trim().is_empty()
        || request.body.len() > 16000
        || request.body.contains('\0')
        || request.sender.is_empty()
        || request.sender.len() > 256
        || [&request.to, &request.task_id].iter().any(|value| {
            value.as_ref().is_some_and(|value| {
                value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
        })
    {
        return Err(invalid(
            "invalid outbox request; fixed room and 1..16000 bytes of text required",
        ));
    }
    Ok(())
}

fn check_target(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            Err(invalid("outbox must remain a regular non-symlink file"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}
fn json_error(error: serde_json::Error) -> io::Error {
    invalid(&error.to_string())
}

#[cfg(test)]
mod tests;
