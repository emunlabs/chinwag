//! Durable human opening attempts. Reconciliation never enters the POST path.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use chinwag_bus_client::{
    BusClient, NativeOpenReceipt, NativeOpenRequest, NativeOpenState, new_request_id,
    validate_request_id,
};
use rustix::fs::{FlockOperation, OFlags, flock};
use serde_json::{Value, json};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_ATTEMPTS: usize = 128;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpeningState {
    Pending,
    Uncertain(String),
    Receipt(NativeOpenReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningAttempt {
    pub id: String,
    pub endpoint: String,
    pub installation_id: String,
    pub state: OpeningState,
}

impl OpeningAttempt {
    pub fn unresolved(&self) -> bool {
        match &self.state {
            OpeningState::Pending | OpeningState::Uncertain(_) => true,
            OpeningState::Receipt(receipt) => matches!(
                receipt.state,
                NativeOpenState::Pending | NativeOpenState::Uncertain
            ),
        }
    }

    pub fn summary(&self) -> String {
        match &self.state {
            OpeningState::Pending => "Opening pending · check status before trying again".into(),
            OpeningState::Uncertain(_) => {
                "Opening unconfirmed · check status; it will not open again".into()
            }
            OpeningState::Receipt(receipt) => match receipt.state {
                NativeOpenState::OpenedOrReused => {
                    "Opened/reused · connection setup pending".into()
                }
                NativeOpenState::Rejected => format!("Opening rejected · {}", receipt.message),
                NativeOpenState::Pending => {
                    "Opening pending · check status before trying again".into()
                }
                NativeOpenState::Uncertain => {
                    "Opening unconfirmed · check status; it will not open again".into()
                }
            },
        }
    }
}

pub struct OpeningStore {
    path: PathBuf,
    pub attempts: Vec<OpeningAttempt>,
    _guard: File,
}

pub fn path_for_drafts(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("draft path has no filename"))?;
    Ok(path.with_file_name(format!("{}.openings.json", name.to_string_lossy())))
}

pub fn short_installation_id(id: &str) -> &str {
    id.get(id.len().saturating_sub(8)..).unwrap_or(id)
}

impl OpeningStore {
    pub fn open(path: PathBuf) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("opening history path must be absolute"));
        }
        let lock = path.with_file_name(format!(
            "{}.lock",
            path.file_name()
                .ok_or_else(|| invalid("opening history has no filename"))?
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
            return Err(invalid("opening history lock must be a regular file"));
        }
        flock(&guard, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| invalid("another window owns this opening history"))?;
        let attempts = match fs::symlink_metadata(&path) {
            Ok(before) => {
                check_target(&path)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
                    .open(&path)?;
                let after = file.metadata()?;
                if !after.is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
                    return Err(invalid("opening history changed while opening"));
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take((MAX_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_BYTES {
                    return Err(invalid("opening history exceeds 1 MiB"));
                }
                decode(serde_json::from_slice(&bytes).map_err(json_error)?)?
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

    pub fn blocks(&self, _endpoint: &str, installation_id: &str) -> bool {
        self.attempts
            .iter()
            .any(|attempt| attempt.unresolved() && attempt.installation_id == installation_id)
    }

    /// Durably write Pending before the caller may schedule one POST.
    pub fn prepare(&mut self, endpoint: &str, installation_id: &str) -> io::Result<OpeningAttempt> {
        validate_target(endpoint, installation_id)?;
        if self.blocks(endpoint, installation_id) {
            return Err(invalid(
                "this installation has an unconfirmed opening; use Check opening status",
            ));
        }
        let attempt = OpeningAttempt {
            id: new_request_id().map_err(|error| invalid(&error.to_string()))?,
            endpoint: endpoint.into(),
            installation_id: installation_id.into(),
            state: OpeningState::Pending,
        };
        let mut next = self.attempts.clone();
        while next.len() >= MAX_ATTEMPTS {
            let index = next
                .iter()
                .position(|attempt| !attempt.unresolved())
                .ok_or_else(|| invalid("opening history is full of unconfirmed attempts"))?;
            next.remove(index);
        }
        next.push(attempt.clone());
        self.save(&next)?;
        self.attempts = next;
        Ok(attempt)
    }

    pub fn apply_receipt(&mut self, id: &str, receipt: NativeOpenReceipt) -> io::Result<()> {
        let mut next = self.attempts.clone();
        let attempt = next
            .iter_mut()
            .find(|attempt| attempt.id == id)
            .ok_or_else(|| invalid("unknown local opening attempt"))?;
        receipt
            .validate_for(
                id,
                &NativeOpenRequest {
                    installation_id: attempt.installation_id.clone(),
                },
            )
            .map_err(|error| invalid(&error.to_string()))?;
        if let OpeningState::Receipt(actual) = &attempt.state
            && matches!(
                actual.state,
                NativeOpenState::OpenedOrReused | NativeOpenState::Rejected
            )
        {
            if matches!(
                receipt.state,
                NativeOpenState::OpenedOrReused | NativeOpenState::Rejected
            ) && actual != &receipt
            {
                return Err(invalid("conflicting terminal opening receipts"));
            }
            return Ok(());
        }
        attempt.state = OpeningState::Receipt(receipt);
        self.save(&next)?;
        self.attempts = next;
        Ok(())
    }

    pub fn mark_uncertain(&mut self, id: &str, message: &str) -> io::Result<()> {
        let mut next = self.attempts.clone();
        let attempt = next
            .iter_mut()
            .find(|attempt| attempt.id == id)
            .ok_or_else(|| invalid("unknown local opening attempt"))?;
        if !attempt.unresolved() {
            return Ok(());
        }
        attempt.state = OpeningState::Uncertain(
            message
                .chars()
                .filter(|c| !c.is_control())
                .take(240)
                .collect(),
        );
        self.save(&next)?;
        self.attempts = next;
        Ok(())
    }

    fn save(&self, attempts: &[OpeningAttempt]) -> io::Result<()> {
        check_target(&self.path)?;
        let rows: Vec<_> = attempts.iter().map(|attempt| {
            let (state, message, receipt) = match &attempt.state {
                OpeningState::Pending => ("pending", None, None),
                OpeningState::Uncertain(message) => ("uncertain", Some(message), None),
                OpeningState::Receipt(receipt) => ("receipt", None, Some(receipt)),
            };
            json!({"id":attempt.id,"endpoint":attempt.endpoint,"installation_id":attempt.installation_id,"state":state,"message":message,"receipt":receipt})
        }).collect();
        let bytes =
            serde_json::to_vec(&json!({"schema":"chinwag-opening-history/v1","attempts":rows}))
                .map_err(json_error)?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid(
                "opening history exceeds 1 MiB; no opening was started",
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("opening history has no parent"))?;
        let temporary = parent.join(format!(
            ".chinwag-openings-{}-{}.tmp",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
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

fn decode(value: Value) -> io::Result<Vec<OpeningAttempt>> {
    if value["schema"] != "chinwag-opening-history/v1" {
        return Err(invalid("unknown opening history schema"));
    }
    let rows = value["attempts"]
        .as_array()
        .filter(|rows| rows.len() <= MAX_ATTEMPTS)
        .ok_or_else(|| invalid("invalid opening history row count"))?;
    let mut attempts: Vec<OpeningAttempt> = Vec::new();
    for row in rows {
        let text = |key: &str| {
            row[key]
                .as_str()
                .ok_or_else(|| invalid("missing opening history text field"))
        };
        let id = text("id")?.to_owned();
        validate_request_id(&id).map_err(|error| invalid(&error.to_string()))?;
        if attempts.iter().any(|attempt| attempt.id == id) {
            return Err(invalid("duplicate opening attempt ID"));
        }
        let endpoint = text("endpoint")?.to_owned();
        let installation_id = text("installation_id")?.to_owned();
        validate_target(&endpoint, &installation_id)?;
        let state = match text("state")? {
            "pending" => OpeningState::Pending,
            "uncertain" => {
                let message = text("message")?;
                if message.len() > 960 || message.chars().any(char::is_control) {
                    return Err(invalid("invalid opening uncertainty message"));
                }
                OpeningState::Uncertain(message.into())
            }
            "receipt" => {
                let receipt: NativeOpenReceipt =
                    serde_json::from_value(row["receipt"].clone()).map_err(json_error)?;
                receipt
                    .validate_for(
                        &id,
                        &NativeOpenRequest {
                            installation_id: installation_id.clone(),
                        },
                    )
                    .map_err(|error| invalid(&error.to_string()))?;
                OpeningState::Receipt(receipt)
            }
            _ => return Err(invalid("unknown opening attempt state")),
        };
        attempts.push(OpeningAttempt {
            id,
            endpoint,
            installation_id,
            state,
        });
    }
    Ok(attempts)
}

fn validate_target(endpoint: &str, installation_id: &str) -> io::Result<()> {
    if endpoint.len() > 2048 {
        return Err(invalid("opening endpoint too long"));
    }
    BusClient::new(endpoint).map_err(|error| invalid(&error.to_string()))?;
    NativeOpenRequest {
        installation_id: installation_id.into(),
    }
    .validate()
    .map_err(|error| invalid(&error.to_string()))
}

fn check_target(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => Err(invalid(
            "opening history must remain a regular non-symlink file",
        )),
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
