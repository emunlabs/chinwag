// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Bounded, best-effort private phase records. These confer no authority and
//! carry no request values. Missing/limited records remain unknown evidence.
use crate::{
    github::EvidenceError,
    runtime::{HttpFailure, RuntimeError},
    storage::CiphertextStore,
};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use serde::Serialize;
use std::{
    fs::File,
    io::Write,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

const NAME: &str = "http-operation-phases-v1.jsonl";
const RECORDS: usize = 256;
fn refused<E>(_: E) -> RuntimeError {
    RuntimeError::Refused
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum Phase {
    Entered,
    Decoded,
    Ready,
    ConfigurationRead,
    ClientPrepared,
    RunStarted,
    RunCompleted,
    KeysStarted,
    KeysCompleted,
    OidcStarted,
    OidcCompleted,
    WorkflowVerified,
    LedgerWait,
    LedgerIssue,
    LedgerIssued,
    ResponseReady,
    Held,
    Limit,
}
#[derive(Serialize)]
enum Category {
    Refused,
    Held,
    Timeout,
    Connect,
    Body,
    Network,
    Response,
    HttpStatus(u16),
    EvidenceTls,
    EvidenceNetwork,
    EvidenceTimeout,
    EvidenceStatus(u16),
    EvidenceResponse,
    EvidenceScope,
}
impl Category {
    fn from_error(error: &RuntimeError) -> Self {
        match error {
            RuntimeError::Refused => Self::Refused,
            RuntimeError::AgentHeld(_) => Self::Held,
            RuntimeError::Http(h) => match h {
                HttpFailure::Timeout => Self::Timeout,
                HttpFailure::Connect => Self::Connect,
                HttpFailure::Body => Self::Body,
                HttpFailure::Network => Self::Network,
                HttpFailure::Response => Self::Response,
                HttpFailure::Status(s) => Self::HttpStatus(*s),
            },
            RuntimeError::Evidence(e) => match e {
                EvidenceError::Tls => Self::EvidenceTls,
                EvidenceError::Network => Self::EvidenceNetwork,
                EvidenceError::Timeout => Self::EvidenceTimeout,
                EvidenceError::Status(s) => Self::EvidenceStatus(*s),
                EvidenceError::Response => Self::EvidenceResponse,
                EvidenceError::Scope => Self::EvidenceScope,
            },
        }
    }
}
#[derive(Serialize)]
struct Row {
    request: u64,
    phase: Phase,
    elapsed_ms: u128,
    outcome: Option<Category>,
}
struct Sink {
    file: File,
    remaining: usize,
}
#[derive(Clone)]
pub(crate) struct Diagnostics {
    sink: Option<Arc<Mutex<Sink>>>,
    next: Arc<AtomicU64>,
}
pub(crate) struct Request {
    diagnostics: Diagnostics,
    id: u64,
    started: Instant,
}
impl Diagnostics {
    pub(crate) fn best_effort(outputs: &Path) -> Self {
        Self::create(outputs).unwrap_or_else(|_| Self {
            sink: None,
            next: Arc::new(AtomicU64::new(1)),
        })
    }
    pub(crate) fn create(outputs: &Path) -> Result<Self, RuntimeError> {
        let directory = CiphertextStore::open(outputs).map_err(refused)?;
        let fd = fs::openat(
            directory.directory(),
            NAME,
            OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(refused)?;
        fs::fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(refused)?;
        let stat = fs::fstat(&fd).map_err(refused)?;
        let named =
            fs::statat(directory.directory(), NAME, AtFlags::SYMLINK_NOFOLLOW).map_err(refused)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_nlink != 1
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_size != 0
            || stat.st_ino != named.st_ino
            || stat.st_dev != named.st_dev
        {
            return Err(RuntimeError::Refused);
        }
        #[cfg(target_os = "macos")]
        {
            use rustix::fd::AsFd;
            crate::macos_acl::require_absent(fd.as_fd()).map_err(refused)?;
        }
        directory.check().map_err(refused)?;
        Ok(Self {
            sink: Some(Arc::new(Mutex::new(Sink {
                file: File::from(fd),
                remaining: RECORDS,
            }))),
            next: Arc::new(AtomicU64::new(1)),
        })
    }
    pub(crate) fn request(&self) -> Request {
        Request {
            diagnostics: self.clone(),
            id: self.next.fetch_add(1, Ordering::Relaxed),
            started: Instant::now(),
        }
    }
}
impl Request {
    fn record(&self, phase: Phase, outcome: Option<Category>) {
        let Some(sink) = &self.diagnostics.sink else {
            return;
        };
        let Ok(mut sink) = sink.try_lock() else {
            return;
        };
        if sink.remaining == 0 {
            return;
        }
        let limited = sink.remaining == 1;
        let row = Row {
            request: self.id,
            phase: if limited { Phase::Limit } else { phase },
            elapsed_ms: self.started.elapsed().as_millis(),
            outcome: if limited { None } else { outcome },
        };
        let Ok(mut bytes) = serde_json::to_vec(&row) else {
            sink.remaining = 0;
            return;
        };
        bytes.push(b'\n');
        // Closed enums and integers bound every row. No request-dependent text
        // can reach this sink. Diagnostic limits/errors never gate an operation.
        if bytes.len() > 256 || sink.file.write_all(&bytes).is_err() {
            sink.remaining = 0;
            return;
        }
        sink.remaining -= 1;
    }
    pub(crate) fn phase(&self, phase: Phase) {
        self.record(phase, None);
    }
    pub(crate) fn result<T>(&self, phase: Phase, result: &Result<T, RuntimeError>) {
        self.record(phase, result.as_ref().err().map(Category::from_error));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn private_records_are_bounded_and_never_replace_existing_files() {
        let d = tempfile::tempdir().unwrap();
        let directory = d.path().canonicalize().unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let trace = Diagnostics::create(&directory).unwrap();
        let request = trace.request();
        for _ in 0..RECORDS + 100 {
            request.phase(Phase::Entered);
        }
        let bytes = std::fs::read(directory.join(NAME)).unwrap();
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), RECORDS);
        assert!(bytes.len() <= RECORDS * 256);
        assert!(
            String::from_utf8(bytes.clone())
                .unwrap()
                .lines()
                .last()
                .unwrap()
                .contains("\"phase\":\"Limit\"")
        );
        assert_eq!(
            std::fs::metadata(directory.join(NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(Diagnostics::create(&directory).is_err());
        let disabled = Diagnostics::best_effort(&directory);
        assert!(disabled.sink.is_none());
        disabled.request().phase(Phase::Entered);
        assert_eq!(std::fs::read(directory.join(NAME)).unwrap(), bytes);
    }
    #[test]
    fn symlinked_sink_is_refused_without_modifying_target() {
        let d = tempfile::tempdir().unwrap();
        let directory = d.path().canonicalize().unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.join("target");
        std::fs::write(&target, b"PRIVATE_SENTINEL").unwrap();
        symlink(&target, directory.join(NAME)).unwrap();
        assert!(Diagnostics::create(&directory).is_err());
        let before = std::fs::metadata(&target).unwrap().permissions().mode();
        let disabled = Diagnostics::best_effort(&directory);
        assert!(disabled.sink.is_none());
        disabled
            .request()
            .result(Phase::Held, &Err::<(), _>(RuntimeError::Refused));
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode(),
            before
        );
        assert_eq!(std::fs::read(target).unwrap(), b"PRIVATE_SENTINEL");
    }
}
