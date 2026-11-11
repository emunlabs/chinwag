//! Bounded-row native journal snapshots. A change notification is only a hint.
#![forbid(unsafe_code)]
use crate::{
    bus_federation::BusMessage,
    bus_identity::BusDirectory,
    bus_wait_core::Cursor,
    bus_wait_message::{hash, verify_original},
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
    if !safe_journal_name(name) {
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
fn safe_journal_name(name: &str) -> bool {
    name.len() <= 160
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        && (name == "messages.jsonl"
            || name.starts_with("messages.jsonl.")
            || (name.starts_with("messages.") && name.ends_with(".jsonl")))
}
/// Each generation must carry the preceding terminal original as its first
/// row. Verified ID/digest overlap proves the edge; filenames and clocks do
/// not. A reset lacking that evidence is held, even for a single rotation.
pub fn anchored_snapshot(repo: &Path, cursor: &mut Cursor) -> Result<Snapshot, String> {
    anchored_snapshot_checked(repo, cursor, |m| verify_original(m).is_ok())
}
fn anchored_snapshot_checked(
    repo: &Path,
    cursor: &mut Cursor,
    mut verified: impl FnMut(&BusMessage) -> bool,
) -> Result<Snapshot, String> {
    let current = snapshot(repo)?;
    if current.anchor(cursor).is_ok() {
        return Ok(current);
    }
    let bus = BusDirectory::open(repo).map_err(|e| e.to_string())?;
    let mut generations = Vec::new();
    let mut bytes = current.len;
    for entry in
        std::fs::read_dir(repo.join(".chinwag/bus")).map_err(|_| "CURSOR_ANCHOR_MISSING")?
    {
        let entry = entry.map_err(|_| "CURSOR_ANCHOR_MISSING")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == "messages.jsonl" || !safe_journal_name(name) {
            continue;
        }
        if generations.len() == 8 {
            return Err("JOURNAL_ARCHIVE_BACKPRESSURE".into());
        }
        let archive = snapshot_named(repo, name)?;
        bytes += archive.len;
        if bytes > 64 * 1024 * 1024 {
            return Err("JOURNAL_ARCHIVE_BACKPRESSURE".into());
        }
        generations.push(archive);
    }
    let mut originals = std::collections::BTreeMap::new();
    for m in generations
        .iter()
        .chain(std::iter::once(&current))
        .flat_map(|g| &g.rows)
    {
        if originals
            .insert(&m.id, &m.digest_sha256)
            .is_some_and(|d| d != &m.digest_sha256)
        {
            return Err("ORIGINAL_ID_CONFLICT".into());
        }
    }
    let anchors: Vec<_> = generations
        .iter()
        .enumerate()
        .filter(|(_, g)| {
            g.first_digest == cursor.last_scanned_line1_digest && g.anchor(cursor).is_ok()
        })
        .map(|(i, _)| i)
        .collect();
    if anchors.len() != 1 {
        return Err("CURSOR_ANCHOR_MISSING".into());
    }
    let start = anchors[0];
    if generations[start]
        .rows
        .iter()
        .any(|m| m.seq > cursor.last_scanned_seq)
    {
        bus.verify().map_err(|e| e.to_string())?;
        return Ok(generations.swap_remove(start));
    }
    let target = generations.len();
    generations.push(current);
    let mut path = vec![start];
    while *path.last().ok_or("CURSOR_ANCHOR_MISSING")? != target {
        let previous = *path.last().ok_or("CURSOR_ANCHOR_MISSING")?;
        let end = generations[previous]
            .rows
            .last()
            .ok_or("CURSOR_ANCHOR_MISSING")?;
        let next: Vec<_> = generations
            .iter()
            .enumerate()
            .filter(|(i, g)| {
                !path.contains(i)
                    && g.rows.first().is_some_and(|first| {
                        first.id == end.id && first.digest_sha256 == end.digest_sha256
                    })
            })
            .map(|(i, _)| i)
            .collect();
        if next.len() != 1 {
            return Err("CURSOR_GENERATION_CONTINUITY_UNPROVEN".into());
        }
        let next = next[0];
        if !verified(end) || !verified(&generations[next].rows[0]) {
            return Err("CURSOR_GENERATION_CONTINUITY_UNPROVEN".into());
        }
        path.push(next);
    }
    bus.verify().map_err(|e| e.to_string())?;
    let next = generations.swap_remove(path[1]);
    let overlap = next.rows.first().ok_or("CURSOR_ANCHOR_MISSING")?;
    cursor.last_scanned_seq = overlap.seq;
    cursor.last_scanned_id = overlap.id.clone();
    cursor.last_scanned_digest = overlap.digest_sha256.clone();
    cursor.last_scanned_inode = next.inode;
    cursor.last_scanned_line1_digest = next.first_digest.clone();
    Ok(next)
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
        let mut overlap = row(2);
        overlap["seq"] = serde_json::json!(1);
        new["seq"] = serde_json::json!(2);
        std::fs::write(&path, format!("{overlap}\n{new}\n")).unwrap();
        let catchup = anchored_snapshot_checked(&root, &mut c, |_| true).unwrap();
        assert_eq!(catchup.rows.len(), 2);
        assert_eq!(c.last_scanned_seq, 1);
        c.last_scanned_seq = 2;
        c.last_scanned_id = "fixture-2".into();
        c.last_scanned_digest = "digest-2".into();
        let next = anchored_snapshot_checked(&root, &mut c, |_| true).unwrap();
        assert_eq!(next.rows[1].id, "fixture-3");
        assert_eq!(c.last_scanned_seq, 1);
        c.last_scanned_seq = 2;
        c.last_scanned_id = "fixture-2".into();
        c.last_scanned_digest = "digest-2".into();
        std::fs::remove_file(archive).unwrap();
        assert!(
            anchored_snapshot_checked(&root, &mut c, |_| true)
                .err()
                .unwrap()
                .contains("CURSOR_ANCHOR_MISSING")
        );
        assert_eq!(c.last_scanned_seq, 2);
    }
    #[test]
    fn r1_intermediate_generation_is_drained_and_missing_edge_holds() {
        for alternate in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(temp.path()).unwrap();
            snapshot(&root).unwrap();
            let row = |id: u64, seq: u64| serde_json::json!({"id":format!("original-{id}"),"seq":seq,"ts_unix":id,"ts_iso":"fixture","room":"#eng","sender":"GEMINI-PM#fixture","sender_cast":"","sender_endpoint_id":"fixture","to":"WORKHORSE#fixture","task_id":"TEST","body":"fixture","digest_sha256":format!("digest-{id}"),"pubkey_ed25519":null,"signature_ed25519":null,"sig_verified":false});
            let path = root.join(".chinwag/bus/messages.jsonl");
            std::fs::write(&path, format!("{}\n{}\n", row(1, 1), row(2, 2))).unwrap();
            let old = snapshot(&root).unwrap();
            let mut c:Cursor=serde_json::from_value(serde_json::json!({"schema":"chinwag.bus.durable-cursor-and-quota.v4","actor":"WORKHORSE#fixture","grant_id":"g","authority_epoch":1,"grant_digest_sha256":"hash","version":0,"max_turns_quota":32,"turns_used":0,"turns_reserved":0,"backlog_policy":"ExplicitWatermarkSeq","last_scanned_seq":1,"last_scanned_id":"original-1","last_scanned_digest":"digest-1","last_scanned_inode":old.inode,"last_scanned_line1_digest":old.first_digest,"pending_deliveries":[],"completed_recent_digests":[],"completed_deliveries":[]})).unwrap();
            std::fs::rename(&path, root.join(".chinwag/bus/messages.jsonl.z-old")).unwrap();
            let middle = root.join(if alternate {
                ".chinwag/bus/messages.a-middle.jsonl"
            } else {
                ".chinwag/bus/messages.jsonl.a-middle"
            });
            std::fs::write(&middle, format!("{}\n{}\n", row(2, 1), row(3, 2))).unwrap();
            std::fs::write(&path, format!("{}\n{}\n", row(3, 1), row(4, 2))).unwrap();
            let mut delivered = vec![];
            for expected in ["original-2", "original-3", "original-4"] {
                let g = anchored_snapshot_checked(&root, &mut c, |_| true).unwrap();
                let tail: Vec<_> = g
                    .rows
                    .iter()
                    .filter(|m| m.seq > c.last_scanned_seq)
                    .collect();
                assert_eq!(tail.len(), 1);
                assert_eq!(tail[0].id, expected);
                delivered.push(tail[0].id.clone());
                c.last_scanned_seq = tail[0].seq;
                c.last_scanned_id = tail[0].id.clone();
                c.last_scanned_digest = tail[0].digest_sha256.clone();
                c.last_scanned_inode = g.inode;
                c.last_scanned_line1_digest = g.first_digest;
                if expected == "original-2" {
                    let before = serde_json::to_value(&c).unwrap();
                    std::fs::rename(&middle, root.join("missing-generation")).unwrap();
                    assert!(anchored_snapshot_checked(&root, &mut c, |_| true).is_err());
                    assert_eq!(serde_json::to_value(&c).unwrap(), before);
                    std::fs::rename(root.join("missing-generation"), &middle).unwrap();
                }
            }
            assert_eq!(delivered.len(), 3);
        }
    }
}
