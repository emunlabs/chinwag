//! Planner-facing snapshots only: no identities, bodies, paths, or write API.
use chinwag_swarm::dispatch_wire::Refused;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

pub const STATUS_FILE: &str = "agent-dispatch-status.json";
const LOCK_FILE: &str = "agent-dispatch-listener.lock";
const SCHEMA_VERSION: u8 = 1;
const HEARTBEAT_MAX_AGE: u64 = 15;

/// Historical counters describe one listener instance. `listening` is true only
/// with a fresh heartbeat and an unexpired room lease; it is not an RPC probe.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchStatus {
    pub schema_version: u8,
    pub version: String,
    pub listening: bool,
    pub alpn: String,
    pub pinned_peer_count: u32,
    pub requests_accepted: u64,
    pub requests_refused: u64,
    pub requests_failed: u64,
    pub last_request_unix: Option<u64>,
    pub started_unix: u64,
    pub updated_unix: u64,
    pub room_valid_until_unix: u64,
}

pub(crate) enum Event {
    Accepted,
    Refused,
    Failed,
    Heartbeat,
    Stopped,
}

pub(crate) struct StatusStore {
    path: PathBuf,
    lock: PathBuf,
    state: Mutex<DispatchStatus>,
    healthy: AtomicBool,
}
impl StatusStore {
    pub(crate) fn start(repo: &Path, now: u64) -> Result<Self, Refused> {
        let directory = repo.join(".chinwag");
        let metadata = directory.symlink_metadata().map_err(|_| Refused)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(Refused);
        }
        let lock = directory.join(LOCK_FILE);
        let mut guard = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .map_err(|_| Refused)?;
        // A stale lock after a crash requires operator intervention, never a
        // PID-based automatic unlock or concurrent listener admission.
        if guard
            .write_all(b"chinwag-agent-dispatch-listener/v1\n")
            .and_then(|()| guard.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&lock);
            return Err(Refused);
        }
        let store = Self {
            path: directory.join(STATUS_FILE),
            lock,
            healthy: AtomicBool::new(true),
            state: Mutex::new(DispatchStatus {
                schema_version: SCHEMA_VERSION,
                version: env!("CARGO_PKG_VERSION").into(),
                listening: false,
                alpn: String::from_utf8_lossy(chinwag_swarm::dispatch_wire::ALPN).into_owned(),
                pinned_peer_count: 1,
                requests_accepted: 0,
                requests_refused: 0,
                requests_failed: 0,
                last_request_unix: None,
                started_unix: now,
                updated_unix: now,
                room_valid_until_unix: 0,
            }),
        };
        store.record(Event::Heartbeat, now)?;
        Ok(store)
    }
    pub(crate) fn ready(&self, now: u64, valid_until: u64) -> Result<(), Refused> {
        {
            let mut state = self.state.lock().map_err(|_| Refused)?;
            state.listening = true;
            state.room_valid_until_unix = valid_until;
        }
        self.record(Event::Heartbeat, now)
    }
    pub(crate) fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }
    pub(crate) fn record(&self, event: Event, now: u64) -> Result<(), Refused> {
        if !self.healthy() {
            return Err(Refused);
        }
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| Refused)?;
            // Concurrent callers can sample their clocks before another
            // writer obtains this lock. Preserve monotonic snapshot times.
            state.updated_unix = state.updated_unix.max(now);
            match event {
                Event::Accepted => {
                    state.requests_accepted = state.requests_accepted.saturating_add(1);
                    state.last_request_unix = Some(state.updated_unix);
                }
                Event::Refused => {
                    state.requests_refused = state.requests_refused.saturating_add(1);
                    state.last_request_unix = Some(state.updated_unix);
                }
                Event::Failed => {
                    state.requests_failed = state.requests_failed.saturating_add(1);
                }
                Event::Heartbeat => {}
                Event::Stopped => state.listening = false,
            }
            atomic_write(
                &self.path,
                &serde_json::to_vec(&*state).map_err(|_| Refused)?,
            )
        })();
        if result.is_err() {
            self.healthy.store(false, Ordering::Release);
        }
        result
    }
}
impl Drop for StatusStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock);
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Refused> {
    let parent = path.parent().ok_or(Refused)?;
    let temporary = parent.join(format!(
        ".dispatch-status-{:032x}.tmp",
        rand::random::<u128>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| Refused)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| Refused)?;
        fs::rename(&temporary, path).map_err(|_| Refused)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| Refused)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Read only; missing or malformed snapshots are errors and never create state.
pub fn read_dispatch_status(repo: &Path, now: u64) -> Result<DispatchStatus, Refused> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(repo.join(".chinwag").join(STATUS_FILE))
        .map_err(|_| Refused)?;
    let metadata = file.metadata().map_err(|_| Refused)?;
    if !metadata.is_file()
        || metadata.len() > 16_384
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(Refused);
    }
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| Refused)?;
    if bytes.len() > 16_384 {
        return Err(Refused);
    }
    let mut status: DispatchStatus = serde_json::from_slice(&bytes).map_err(|_| Refused)?;
    if status.schema_version != SCHEMA_VERSION
        || status.alpn.as_bytes() != chinwag_swarm::dispatch_wire::ALPN
        || status.version.len() > 32
        || !status
            .version
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.')
        || status.pinned_peer_count != 1
    {
        return Err(Refused);
    }
    status.listening &= now >= status.updated_unix
        && now - status.updated_unix <= HEARTBEAT_MAX_AGE
        && now < status.room_valid_until_unix;
    Ok(status)
}

pub fn run_agent_dispatch_status(repo: PathBuf, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match super::dispatch_remote::now().and_then(|now| read_dispatch_status(&repo, now)) {
        Ok(status) => {
            if serde_json::to_writer(&mut *out, &status).is_ok() && out.write_all(b"\n").is_ok() {
                0
            } else {
                1
            }
        }
        Err(_) => {
            let _ = writeln!(err, "chinwag: dispatch_status_unavailable");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshots_are_private_atomic_read_only_and_age_out() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_dispatch_status(directory.path(), 100).is_err());
        assert!(!directory.path().join(".chinwag").exists());
        fs::create_dir(directory.path().join(".chinwag")).unwrap();
        let store = StatusStore::start(directory.path(), 100).unwrap();
        assert!(StatusStore::start(directory.path(), 100).is_err());
        store.ready(101, 200).unwrap();
        store.record(Event::Accepted, 102).unwrap();
        store.record(Event::Refused, 103).unwrap();
        store.record(Event::Failed, 104).unwrap();
        let path = directory.path().join(".chinwag").join(STATUS_FILE);
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        let before = fs::read(&path).unwrap();
        let status = read_dispatch_status(directory.path(), 104).unwrap();
        assert!(status.listening);
        assert_eq!(status.requests_accepted, 1);
        assert_eq!(status.requests_refused, 1);
        assert_eq!(status.requests_failed, 1);
        assert!(
            !read_dispatch_status(directory.path(), 120)
                .unwrap()
                .listening
        );
        assert!(
            !read_dispatch_status(directory.path(), 99)
                .unwrap()
                .listening
        );
        assert_eq!(before, fs::read(&path).unwrap());
        store.record(Event::Stopped, 105).unwrap();
        assert!(
            !read_dispatch_status(directory.path(), 105)
                .unwrap()
                .listening
        );
        drop(store);
        assert!(!directory.path().join(".chinwag").join(LOCK_FILE).exists());
        assert_eq!(
            fs::read_dir(directory.path().join(".chinwag"))
                .unwrap()
                .count(),
            1
        );
    }
    #[test]
    fn status_refuses_symlinks_unknown_fields_and_nonprivate_files() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join(".chinwag")).unwrap();
        let store = StatusStore::start(directory.path(), 100).unwrap();
        let path = directory.path().join(".chinwag").join(STATUS_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_dispatch_status(directory.path(), 100).is_err());
        store.record(Event::Heartbeat, 101).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["body"] = "forbidden".into();
        atomic_write(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_dispatch_status(directory.path(), 101).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(directory.path().join("missing"), &path).unwrap();
        assert!(read_dispatch_status(directory.path(), 101).is_err());
    }
}
