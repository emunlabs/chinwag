//! Private local observer readings. Metadata does not confer network authority.
//! A sync does not preempt a caller's deadline. Same-user races remain.

use crate::bundle_io::{canonical, private_empty_directory, private_file};
use chinwag_swarm::transport::{BoundedIps, DataPlane};
use iroh::EndpointId;
use rustix::fs::{Mode, OFlags, openat};
use serde_json::json;
use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = "chinwag-private-stages/v2";
const EVENTS: &str = "events.jsonl";
const MAX_EVENTS: u64 = 128;
const MAX_TOTAL_BYTES: u64 = 65536;
const MAX_LINE_BYTES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    #[error("private stage journal refused")]
    Refused,
    #[error("private stage journal clock failed")]
    Clock,
    #[error("private stage journal failed and is unusable")]
    Unusable,
}

#[derive(Clone, Copy)]
pub enum Stage {
    SendJoinReturned,
    SendNeighborReturned,
    SendOfferQueued,
    SendAckReceived,
    ReceiveJoinReturned,
    ReceiveNeighborReturned,
    ReceiveOfferReceived,
    ReceiveFetchReturned,
    ReceiveSaveReturned,
    ReceiveAckQueued,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Stage::SendJoinReturned => "send_join_returned",
            Stage::SendNeighborReturned => "send_neighbor_returned",
            Stage::SendOfferQueued => "send_offer_queued",
            Stage::SendAckReceived => "send_ack_received",
            Stage::ReceiveJoinReturned => "receive_join_returned",
            Stage::ReceiveNeighborReturned => "receive_neighbor_returned",
            Stage::ReceiveOfferReceived => "receive_offer_received",
            Stage::ReceiveFetchReturned => "receive_fetch_returned",
            Stage::ReceiveSaveReturned => "receive_save_returned",
            Stage::ReceiveAckQueued => "receive_ack_queued",
        }
    }
}

/// Owned bounded IP metadata; never a room, freshness, or transport permit.
pub struct CachedIpSnapshot {
    own: BoundedIps,
    peer: Option<BoundedIps>,
}

/// Read existing local caches only. No network lookup, await, or clock reset.
pub(crate) fn observe_cached_ips(plane: &DataPlane, peer: Option<BoundedIps>) -> CachedIpSnapshot {
    CachedIpSnapshot {
        own: BoundedIps::from_ips(plane.endpoint_addr().ip_addrs().copied()),
        peer,
    }
}

pub struct PrivateStageJournal {
    directory_path: PathBuf,
    directory: File,
    file_path: PathBuf,
    file: File,
    own: String,
    peer: String,
    origin: Instant,
    next_seq: u64,
    written: u64,
    total_cap: u64,
    line_cap: usize,
    poisoned: bool,
}

impl PrivateStageJournal {
    pub fn create(directory: &Path, own: EndpointId, peer: EndpointId) -> Result<Self, TraceError> {
        let directory_path = canonical(directory).map_err(|_| TraceError::Refused)?;
        let directory =
            private_empty_directory(&directory_path).map_err(|_| TraceError::Refused)?;
        if directory
            .metadata()
            .map_err(|_| TraceError::Refused)?
            .mode()
            & 0o777
            != 0o700
        {
            return Err(TraceError::Refused);
        }
        let file = File::from(
            openat(
                &directory,
                EVENTS,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| TraceError::Refused)?,
        );
        file.sync_all().map_err(|_| TraceError::Refused)?;
        directory.sync_all().map_err(|_| TraceError::Refused)?;
        let journal = Self {
            file_path: directory_path.join(EVENTS),
            file,
            directory,
            directory_path,
            own: own.to_string(),
            peer: peer.to_string(),
            origin: Instant::now(),
            next_seq: 1,
            written: 0,
            total_cap: MAX_TOTAL_BYTES,
            line_cap: MAX_LINE_BYTES,
            poisoned: false,
        };
        journal.check_dir().map_err(|_| TraceError::Refused)?;
        journal.check_file().map_err(|_| TraceError::Refused)?;
        Ok(journal)
    }

    pub fn record(&mut self, stage: Stage, snapshot: &CachedIpSnapshot) -> Result<(), TraceError> {
        if self.poisoned {
            return Err(TraceError::Unusable);
        }
        match self.write_stage(stage, snapshot) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn write_stage(&mut self, stage: Stage, snapshot: &CachedIpSnapshot) -> Result<(), TraceError> {
        if self.next_seq == 0 || self.next_seq > MAX_EVENTS {
            return Err(TraceError::Unusable);
        }
        self.check_dir()?;
        self.check_file()?;
        let wall = wall_unix_ns()?;
        let elapsed = Instant::now()
            .checked_duration_since(self.origin)
            .ok_or(TraceError::Clock)?;
        let elapsed = u64::try_from(elapsed.as_nanos()).map_err(|_| TraceError::Clock)?;
        let line = self.encode_stage(stage, snapshot, wall, elapsed)?;
        if line.len() > self.line_cap || line.len() > MAX_LINE_BYTES {
            return Err(TraceError::Unusable);
        }
        let next = self
            .written
            .checked_add(line.len() as u64)
            .ok_or(TraceError::Unusable)?;
        if next > self.total_cap || next > MAX_TOTAL_BYTES {
            return Err(TraceError::Unusable);
        }
        self.file
            .seek(SeekFrom::Start(self.written))
            .map_err(|_| TraceError::Unusable)?;
        self.file
            .write_all(&line)
            .map_err(|_| TraceError::Unusable)?;
        self.file.flush().map_err(|_| TraceError::Unusable)?;
        self.file.sync_all().map_err(|_| TraceError::Unusable)?;
        self.written = next;
        self.next_seq += 1;
        self.check_dir()?;
        self.check_file()?;
        Ok(())
    }

    // Private encoder: the public writer always samples its own clocks.
    fn encode_stage(
        &self,
        stage: Stage,
        snapshot: &CachedIpSnapshot,
        wall: u64,
        elapsed: u64,
    ) -> Result<Vec<u8>, TraceError> {
        let own_ips: Vec<String> = snapshot
            .own
            .addrs()
            .iter()
            .map(ToString::to_string)
            .collect();
        let peer_ips: Vec<String> = snapshot
            .peer
            .as_ref()
            .map(|ips| ips.addrs().iter().map(ToString::to_string).collect())
            .unwrap_or_default();
        let mut line = serde_json::to_vec(&json!({
            "schema": SCHEMA, "seq": self.next_seq, "wall_unix_ns": wall,
            "monotonic_elapsed_ns": elapsed, "own": self.own, "peer": self.peer,
            "stage": stage.name(), "own_ips": own_ips,
            "own_truncated": snapshot.own.truncated(),
            "peer_cache": if snapshot.peer.is_some() { "present" } else { "unavailable" },
            "peer_ips": peer_ips,
            "peer_truncated": snapshot.peer.as_ref().is_some_and(BoundedIps::truncated),
        }))
        .map_err(|_| TraceError::Unusable)?;
        line.push(b'\n');
        Ok(line)
    }

    fn check_dir(&self) -> Result<(), TraceError> {
        let held = self
            .directory
            .metadata()
            .map_err(|_| TraceError::Unusable)?;
        let current =
            fs::symlink_metadata(&self.directory_path).map_err(|_| TraceError::Unusable)?;
        if !current.is_dir()
            || held.dev() != current.dev()
            || held.ino() != current.ino()
            || held.uid() != rustix::process::geteuid().as_raw()
            || held.mode() & 0o777 != 0o700
        {
            return Err(TraceError::Unusable);
        }
        Ok(())
    }

    fn check_file(&self) -> Result<(), TraceError> {
        let held = self.file.metadata().map_err(|_| TraceError::Unusable)?;
        let current = private_file(&self.file_path)
            .map_err(|_| TraceError::Unusable)?
            .metadata()
            .map_err(|_| TraceError::Unusable)?;
        if !held.is_file()
            || held.dev() != current.dev()
            || held.ino() != current.ino()
            || held.uid() != rustix::process::geteuid().as_raw()
            || current.uid() != held.uid()
            || held.nlink() != 1
            || held.mode() & 0o777 != 0o600
            || current.mode() & 0o777 != 0o600
            || held.len() != self.written
            || current.len() != self.written
        {
            return Err(TraceError::Unusable);
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_set_caps(&mut self, total: u64, line: usize) {
        self.total_cap = total;
        self.line_cap = line;
    }
}

fn wall_unix_ns() -> Result<u64, TraceError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TraceError::Clock)?
            .as_nanos(),
    )
    .map_err(|_| TraceError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::os::unix::fs::PermissionsExt;

    const OWN: &str = "df7676a8680f06f1cddb51a793be9a07a0d022638cb25ebe681dd42328867931";
    const PEER: &str = "63e44fbb5054e0730793b2be61daf203b912c7cc5777f86ebbfe5f73b096c3d0";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Line {
        schema: String,
        seq: u64,
        wall_unix_ns: u64,
        monotonic_elapsed_ns: u64,
        own: String,
        peer: String,
        stage: String,
        own_ips: Vec<String>,
        own_truncated: bool,
        peer_cache: String,
        peer_ips: Vec<String>,
        peer_truncated: bool,
    }

    fn snapshot() -> CachedIpSnapshot {
        CachedIpSnapshot {
            own: BoundedIps::from_ips(["192.0.2.1:4001".parse().unwrap()]),
            peer: None,
        }
    }
    fn ids() -> (EndpointId, EndpointId) {
        (OWN.parse().unwrap(), PEER.parse().unwrap())
    }
    fn private_dir() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, path)
    }
    fn events(dir: &Path) -> PathBuf {
        dir.join(EVENTS)
    }
    fn read_lines(path: &Path) -> Vec<Line> {
        let bytes = fs::read(path).unwrap();
        assert!(bytes.ends_with(b"\n"));
        bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                assert!(line.len() <= MAX_LINE_BYTES);
                serde_json::from_slice(line).unwrap()
            })
            .collect()
    }

    #[test]
    fn records_are_ordered_private_and_pinned() {
        let (_tmp, dir) = private_dir();
        let (own, peer) = ids();
        let mut journal = PrivateStageJournal::create(&dir, own, peer).unwrap();
        let stages = [
            (Stage::SendJoinReturned, "send_join_returned"),
            (Stage::SendNeighborReturned, "send_neighbor_returned"),
            (Stage::SendOfferQueued, "send_offer_queued"),
            (Stage::SendAckReceived, "send_ack_received"),
            (Stage::ReceiveJoinReturned, "receive_join_returned"),
            (Stage::ReceiveNeighborReturned, "receive_neighbor_returned"),
            (Stage::ReceiveOfferReceived, "receive_offer_received"),
            (Stage::ReceiveFetchReturned, "receive_fetch_returned"),
            (Stage::ReceiveSaveReturned, "receive_save_returned"),
            (Stage::ReceiveAckQueued, "receive_ack_queued"),
        ];
        let before = wall_unix_ns().unwrap();
        for (stage, _) in stages {
            journal.record(stage, &snapshot()).unwrap();
        }
        let after = wall_unix_ns().unwrap();
        let path = events(&dir);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let lines = read_lines(&path);
        assert_eq!(lines.len(), stages.len());
        let mut previous = 0;
        for (index, ((_, name), line)) in stages.iter().zip(lines).enumerate() {
            assert_eq!(line.schema, SCHEMA);
            assert_eq!(line.seq, (index + 1) as u64);
            assert_eq!(line.stage, *name);
            assert_eq!(line.own_ips, ["192.0.2.1:4001"]);
            assert!(!line.own_truncated);
            assert_eq!(line.peer_cache, "unavailable");
            assert!(line.peer_ips.is_empty());
            assert!(!line.peer_truncated);
            assert_eq!(line.own, own.to_string());
            assert_eq!(line.peer, peer.to_string());
            assert!(line.wall_unix_ns >= before && line.wall_unix_ns <= after);
            assert!(line.monotonic_elapsed_ns >= previous);
            previous = line.monotonic_elapsed_ns;
        }
    }

    #[test]
    fn existing_bytes_and_nonprivate_or_linked_dirs_stay_untouched() {
        let (own, peer) = ids();
        let (_tmp, dir) = private_dir();
        let path = events(&dir);
        fs::write(&path, b"keep-file").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(PrivateStageJournal::create(&dir, own, peer).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep-file");

        let (_tmp, dir) = private_dir();
        let note = dir.join("note");
        fs::write(&note, b"keep-note").unwrap();
        assert!(PrivateStageJournal::create(&dir, own, peer).is_err());
        assert_eq!(fs::read(&note).unwrap(), b"keep-note");
        assert!(!events(&dir).exists());

        let (_tmp, dir) = private_dir();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateStageJournal::create(&dir, own, peer).is_err());
        assert!(fs::read_dir(&dir).unwrap().next().is_none());

        let (_tmp, root) = private_dir();
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let child = real.join("child");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(PrivateStageJournal::create(&link, own, peer).is_err());
        assert!(PrivateStageJournal::create(&link.join("child"), own, peer).is_err());
        assert!(
            fs::read_dir(&real)
                .unwrap()
                .all(|entry| entry.unwrap().file_name() != EVENTS)
        );
        assert!(fs::read_dir(&child).unwrap().next().is_none());
    }

    #[test]
    fn tamper_poisons_and_preserves_the_file() {
        let (own, peer) = ids();
        let cases = [
            "link",
            "replace",
            "chmod",
            "truncate",
            "append",
            "move-dir",
            "chmod-dir",
        ];
        for case in cases {
            let (_tmp, root) = private_dir();
            let dir = root.join("scope");
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let mut journal = PrivateStageJournal::create(&dir, own, peer).unwrap();
            journal
                .record(Stage::SendJoinReturned, &snapshot())
                .unwrap();
            let path = events(&dir);
            let before = fs::read(&path).unwrap();
            match case {
                "link" => {
                    fs::hard_link(&path, dir.join("second")).unwrap();
                }
                "replace" => {
                    fs::rename(&path, dir.join("moved")).unwrap();
                    fs::write(&path, b"new-inode").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                "chmod" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                "truncate" => {
                    fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(0)
                        .unwrap();
                }
                "append" => {
                    fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(b"X")
                        .unwrap();
                }
                "move-dir" => {
                    let moved = dir.parent().unwrap().join(format!("moved-{case}"));
                    fs::rename(&dir, &moved).unwrap();
                    fs::create_dir(&dir).unwrap();
                    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
                }
                "chmod-dir" => {
                    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                journal
                    .record(Stage::SendNeighborReturned, &snapshot())
                    .is_err(),
                "{case}"
            );
            let mid = match case {
                "move-dir" => fs::read(
                    dir.parent()
                        .unwrap()
                        .join(format!("moved-{case}"))
                        .join(EVENTS),
                )
                .unwrap(),
                "replace" => fs::read(dir.join("moved")).unwrap(),
                _ => fs::read(&path).unwrap(),
            };
            assert!(
                journal.record(Stage::SendOfferQueued, &snapshot()).is_err(),
                "{case}"
            );
            let end = match case {
                "move-dir" => fs::read(
                    dir.parent()
                        .unwrap()
                        .join(format!("moved-{case}"))
                        .join(EVENTS),
                )
                .unwrap(),
                "replace" => fs::read(dir.join("moved")).unwrap(),
                _ => fs::read(&path).unwrap(),
            };
            assert_eq!(mid, end, "{case}");
            match case {
                "link" => assert_eq!(end, before),
                "replace" => {
                    assert_eq!(end, before);
                    assert_eq!(fs::read(&path).unwrap(), b"new-inode");
                }
                "chmod" | "chmod-dir" => assert_eq!(end, before),
                "truncate" => assert!(end.is_empty()),
                "append" => assert_eq!(end, [before.clone(), b"X".to_vec()].concat()),
                "move-dir" => {
                    assert_eq!(end, before);
                    assert!(fs::read_dir(&dir).unwrap().next().is_none());
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn event_and_byte_caps_stop_and_stay_stopped() {
        let (_tmp, dir) = private_dir();
        let (own, peer) = ids();
        let mut journal = PrivateStageJournal::create(&dir, own, peer).unwrap();
        let cycle = [
            Stage::SendJoinReturned,
            Stage::ReceiveOfferReceived,
            Stage::ReceiveSaveReturned,
            Stage::ReceiveAckQueued,
        ];
        for index in 0..MAX_EVENTS {
            journal
                .record(cycle[index as usize % cycle.len()], &snapshot())
                .unwrap();
        }
        let path = events(&dir);
        let full = fs::read(&path).unwrap();
        let lines = read_lines(&path);
        assert_eq!(lines.len() as u64, MAX_EVENTS);
        assert_eq!(lines.first().unwrap().seq, 1);
        assert_eq!(lines.last().unwrap().seq, MAX_EVENTS);
        assert!(journal.record(Stage::SendAckReceived, &snapshot()).is_err());
        assert!(journal.record(Stage::SendAckReceived, &snapshot()).is_err());
        assert_eq!(fs::read(&path).unwrap(), full);

        let (_tmp, dir) = private_dir();
        let mut journal = PrivateStageJournal::create(&dir, own, peer).unwrap();
        journal
            .record(Stage::SendJoinReturned, &snapshot())
            .unwrap();
        let path = events(&dir);
        let before = fs::read(&path).unwrap();
        journal.test_set_caps(journal.written, MAX_LINE_BYTES);
        assert!(
            journal
                .record(Stage::SendNeighborReturned, &snapshot())
                .is_err()
        );
        assert!(
            journal
                .record(Stage::SendNeighborReturned, &snapshot())
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);

        let (_tmp, dir) = private_dir();
        let mut journal = PrivateStageJournal::create(&dir, own, peer).unwrap();
        journal.test_set_caps(MAX_TOTAL_BYTES, 1);
        assert!(
            journal
                .record(Stage::ReceiveFetchReturned, &snapshot())
                .is_err()
        );
        assert!(
            journal
                .record(Stage::ReceiveFetchReturned, &snapshot())
                .is_err()
        );
        assert_eq!(fs::metadata(events(&dir)).unwrap().len(), 0);
    }
    #[test]
    fn actual_worst_ipv6_and_integer_encoding_fits_fixed_cap() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
        let (_tmp, dir) = private_dir();
        let (own, peer) = ids();
        let mut journal = PrivateStageJournal::create(&dir, own, peer).unwrap();
        let ips = (0..5)
            .map(|n| {
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(
                        0xffff,
                        0xffff,
                        0xffff,
                        0xffff,
                        0xffff,
                        0xffff,
                        0xffff,
                        0xffff - n,
                    ),
                    u16::MAX,
                    u32::MAX,
                    u32::MAX,
                ))
            })
            .collect::<Vec<_>>();
        let metadata = CachedIpSnapshot {
            own: BoundedIps::from_ips(ips.clone()),
            peer: Some(BoundedIps::from_ips(ips.clone())),
        };
        journal.next_seq = MAX_EVENTS;
        let encoded = journal
            .encode_stage(
                Stage::ReceiveNeighborReturned,
                &metadata,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        assert!(
            encoded.len() <= MAX_LINE_BYTES,
            "actual encoded bytes {}",
            encoded.len()
        );
        let row: Line = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(row.seq, MAX_EVENTS);
        assert_eq!(row.wall_unix_ns, u64::MAX);
        assert_eq!(row.monotonic_elapsed_ns, u64::MAX);
        let expected: Vec<String> = ips[..4].iter().map(ToString::to_string).collect();
        assert!(expected.iter().all(|s| s.len() > 47));
        assert_eq!(row.own_ips, expected);
        assert_eq!(row.peer_ips, expected);
        assert_eq!(row.peer_cache, "present");
        assert!(row.own_truncated && row.peer_truncated);
        // Exercise the real writer too; it must sample real clocks itself.
        journal
            .record(Stage::ReceiveNeighborReturned, &metadata)
            .unwrap();
        assert!(fs::metadata(events(&dir)).unwrap().len() <= MAX_LINE_BYTES as u64);
    }

    #[test]
    fn present_empty_peer_is_distinct_from_unavailable_and_error_preserves_prefix() {
        let (_tmp, dir) = private_dir();
        let (own, peer) = ids();
        let mut journal = PrivateStageJournal::create(&dir, own, peer).unwrap();
        let metadata = CachedIpSnapshot {
            own: BoundedIps::from_ips([]),
            peer: Some(BoundedIps::from_ips([])),
        };
        journal
            .record(Stage::ReceiveJoinReturned, &metadata)
            .unwrap();
        let rows = read_lines(&events(&dir));
        assert!(rows[0].own_ips.is_empty() && rows[0].peer_ips.is_empty());
        assert_eq!(rows[0].peer_cache, "present");
        let original = fs::read(events(&dir)).unwrap();
        journal.test_set_caps(MAX_TOTAL_BYTES, 1);
        assert!(
            journal
                .record(Stage::ReceiveNeighborReturned, &metadata)
                .is_err()
        );
        assert!(
            journal
                .record(Stage::ReceiveNeighborReturned, &metadata)
                .is_err()
        );
        assert_eq!(fs::read(events(&dir)).unwrap(), original);
    }
}
