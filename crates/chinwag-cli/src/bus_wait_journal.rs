//! Bounded-row native journal snapshots. A change notification is only a hint.
#![forbid(unsafe_code)]
use crate::{
    bus_federation::BusMessage, bus_identity::BusDirectory, bus_wait_core::Cursor,
    bus_wait_message::hash,
};
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub struct Snapshot {
    pub rows: Vec<BusMessage>,
    pub len: u64,
    pub inode: u64,
    pub first_digest: String,
}
pub fn snapshot(repo: &Path) -> Result<Snapshot, String> {
    snapshot_named(repo, "messages.jsonl")
}
fn snapshot_named(repo: &Path, name: &str) -> Result<Snapshot, String> {
    if name != "messages.jsonl"
        && (!name.starts_with("messages.jsonl.")
            || name.len() > 160
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)))
    {
        return Err("UNSAFE_JOURNAL".into());
    }
    let bus = BusDirectory::open(repo).map_err(|e| e.to_string())?;
    let fd = match openat(
        &bus,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) if e == rustix::io::Errno::NOENT => {
            return Ok(Snapshot {
                rows: vec![],
                len: 0,
                inode: 0,
                first_digest: String::new(),
            });
        }
        Err(_) => return Err("UNSAFE_JOURNAL".into()),
    };
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| "JOURNAL_METADATA")?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.nlink() != 1
        || meta.mode() & 0o7022 != 0
    {
        return Err("UNSAFE_JOURNAL".into());
    }
    // Total snapshot cap is explicit backpressure, never a silent truncated scan.
    if meta.len() > 64 * 1024 * 1024 {
        return Err("JOURNAL_SNAPSHOT_BACKPRESSURE".into());
    }
    let mut reader = BufReader::new(file.take(meta.len()));
    let mut rows = vec![];
    let mut first = String::new();
    let mut previous = 0;
    loop {
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| "JOURNAL_READ")?;
        if n == 0 {
            break;
        }
        if n > 1024 * 1024 || line.last() != Some(&b'\n') {
            return Err("JOURNAL_PARTIAL_OR_OVERSIZED".into());
        }
        if first.is_empty() {
            first = hash(&line);
        }
        let row: BusMessage = serde_json::from_slice(&line).map_err(|_| "JOURNAL_MALFORMED")?;
        if row.seq <= previous {
            return Err("JOURNAL_SEQUENCE_INVALID".into());
        }
        previous = row.seq;
        rows.push(row);
    }
    bus.verify().map_err(|e| e.to_string())?;
    Ok(Snapshot {
        rows,
        len: meta.len(),
        inode: meta.ino(),
        first_digest: first,
    })
}
/// Resolve a rotation only against a bounded, safely opened archive carrying
/// the exact previous anchor. Drain its unscanned tail before the new file.
/// Sequence reset is permitted only after that archived tail is fully scanned;
/// completed/pending ID+digest witnesses remain intact across the generation.
pub fn anchored_snapshot(repo: &Path, cursor: &mut Cursor) -> Result<Snapshot, String> {
    let current = snapshot(repo)?;
    if current.anchor(cursor).is_ok() {
        return Ok(current);
    }
    let bus = BusDirectory::open(repo).map_err(|e| e.to_string())?;
    let entries =
        std::fs::read_dir(repo.join(".chinwag/bus")).map_err(|_| "CURSOR_ANCHOR_MISSING")?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| "CURSOR_ANCHOR_MISSING")?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|s| s.starts_with("messages.jsonl."))
        {
            names.push(name);
            if names.len() > 8 {
                return Err("JOURNAL_ARCHIVE_BACKPRESSURE".into());
            }
        }
    }
    names.sort();
    let mut bytes = 0;
    for name in names {
        let archive = snapshot_named(repo, name.to_str().ok_or("UNSAFE_JOURNAL")?)?;
        bytes += archive.len;
        if bytes > 64 * 1024 * 1024 {
            return Err("JOURNAL_ARCHIVE_BACKPRESSURE".into());
        }
        if archive.first_digest != cursor.last_scanned_line1_digest
            || archive.anchor(cursor).is_err()
        {
            continue;
        }
        bus.verify().map_err(|e| e.to_string())?;
        if archive.rows.iter().any(|m| m.seq > cursor.last_scanned_seq) {
            return Ok(archive);
        }
        cursor.last_scanned_seq = 0;
        cursor.last_scanned_id.clear();
        cursor.last_scanned_digest.clear();
        return Ok(current);
    }
    Err("CURSOR_ANCHOR_MISSING".into())
}
impl Snapshot {
    pub fn anchor(&self, cursor: &Cursor) -> Result<(), String> {
        if cursor.last_scanned_seq == 0 {
            return Ok(());
        }
        if !self.rows.iter().any(|m| {
            m.seq == cursor.last_scanned_seq
                && m.id == cursor.last_scanned_id
                && m.digest_sha256 == cursor.last_scanned_digest
        }) {
            return Err("CURSOR_ANCHOR_MISSING".into());
        }
        if cursor.last_scanned_inode == self.inode
            && !cursor.last_scanned_line1_digest.is_empty()
            && cursor.last_scanned_line1_digest != self.first_digest
        {
            return Err("CURSOR_ANCHOR_MISSING".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_journal_and_partial_tail_are_distinct() {
        let repo = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(repo.path()).unwrap();
        assert!(snapshot(&root).unwrap().rows.is_empty());
        std::fs::write(root.join(".chinwag/bus/messages.jsonl"), b"{").unwrap();
        assert!(snapshot(&root).is_err());
    }
    #[test]
    fn rotation_drains_exact_archive_anchor_and_missing_archive_never_resets() {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        snapshot(&root).unwrap();
        let row = |n: u64| serde_json::json!({"id":format!("fixture-{n}"),"seq":n,"ts_unix":1,"ts_iso":"fixture","room":"#eng","sender":"GEMINI-PM#fixture","sender_cast":"","sender_endpoint_id":"fixture","to":"WORKHORSE#fixture","task_id":"TEST","body":"fixture","digest_sha256":format!("digest-{n}"),"pubkey_ed25519":null,"signature_ed25519":null,"sig_verified":false});
        let path = root.join(".chinwag/bus/messages.jsonl");
        std::fs::write(&path, format!("{}\n{}\n", row(1), row(2))).unwrap();
        let old = snapshot(&root).unwrap();
        let mut c:Cursor=serde_json::from_value(serde_json::json!({"schema":"chinwag.bus.durable-cursor-and-quota.v4","actor":"WORKHORSE#fixture","grant_id":"g","authority_epoch":1,"grant_digest_sha256":"hash","version":0,"max_turns_quota":32,"turns_used":0,"turns_reserved":0,"backlog_policy":"ExplicitWatermarkSeq",
            "last_scanned_seq":1,"last_scanned_id":"fixture-1","last_scanned_digest":"digest-1","last_scanned_inode":old.inode,"last_scanned_line1_digest":old.first_digest,"pending_deliveries":[],"completed_recent_digests":[],"completed_deliveries":[]})).unwrap();
        let archive = root.join(".chinwag/bus/messages.jsonl.1");
        std::fs::rename(&path, &archive).unwrap();
        let mut new = row(3);
        new["seq"] = serde_json::json!(1);
        std::fs::write(&path, format!("{new}\n")).unwrap();
        let catchup = anchored_snapshot(&root, &mut c).unwrap();
        assert_eq!(catchup.rows.len(), 2);
        assert_eq!(c.last_scanned_seq, 1);
        c.last_scanned_seq = 2;
        c.last_scanned_id = "fixture-2".into();
        c.last_scanned_digest = "digest-2".into();
        let next = anchored_snapshot(&root, &mut c).unwrap();
        assert_eq!(next.rows[0].id, "fixture-3");
        assert_eq!(c.last_scanned_seq, 0);
        c.last_scanned_seq = 2;
        c.last_scanned_id = "fixture-2".into();
        c.last_scanned_digest = "digest-2".into();
        std::fs::remove_file(archive).unwrap();
        assert!(
            anchored_snapshot(&root, &mut c)
                .err()
                .unwrap()
                .contains("CURSOR_ANCHOR_MISSING")
        );
        assert_eq!(c.last_scanned_seq, 2);
    }
}
