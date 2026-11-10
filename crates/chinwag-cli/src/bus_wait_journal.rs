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
    let bus = BusDirectory::open(repo).map_err(|e| e.to_string())?;
    let fd = match openat(
        &bus,
        "messages.jsonl",
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
}
