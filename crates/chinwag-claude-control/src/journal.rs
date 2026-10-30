//! Private, bounded, append-only steer evidence. A consumed ID is never replayed.

use crate::{ClaudeError, InputEvidence, MAX_OPERATIONS, Receipt, Result, SavedInput};
use rustix::fs::{Dir, FlockOperation, Mode, OFlags, flock, mkdirat, open, openat};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::File,
    io::Write,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
};

const MAX_BYTES: usize = 64 * 1024;
const MAX_LINES: usize = 16;
const MAX_ENTRIES: usize = MAX_OPERATIONS * 2 + 2;
const LOCK: &str = "claude.lock";
const DOMAIN: &str = "claude-domain.json";
const DOMAIN_BYTES: &[u8] = b"{\"schema\":\"chinwag-claude-input-journal/v1\"}\n";

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Line {
    Saved { operation: Box<SavedInput> },
    InputEvidence { evidence: InputEvidence },
}

pub(crate) enum Consume {
    Created(Receipt),
    Existing(Receipt),
}

struct Entry {
    file: File,
    bytes: Vec<u8>,
    lines: usize,
    receipt: Receipt,
}

pub(crate) struct JournalLock(pub(crate) File);

impl Drop for JournalLock {
    fn drop(&mut self) {
        // Release the lease even if another inherited/duplicated FD remains open.
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

pub(crate) struct InputJournal {
    root: PathBuf,
    directory: File,
    parent: File,
    name: OsString,
    lock: JournalLock,
    marker: File,
    records: BTreeMap<String, Entry>,
    reserved: BTreeSet<String>,
    untracked: usize,
    #[cfg(test)]
    fail_next_append: bool,
    #[cfg(test)]
    fail_after_create: bool,
}

impl InputJournal {
    pub(crate) fn open(root: &Path) -> Result<Self> {
        let (directory, parent, name) = open_root(root, true)?;
        let lock: File = openat(
            &directory,
            LOCK,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(storage)?
        .into();
        owned_file(&lock)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| ClaudeError::Unavailable)?;
        let lock = JournalLock(lock);
        named_file(&directory, LOCK, &lock.0)?;
        directory.sync_all().map_err(storage)?;
        let marker = domain(&directory)?;
        let mut journal = Self {
            root: root.into(),
            directory,
            parent,
            name,
            lock,
            marker,
            records: BTreeMap::new(),
            reserved: BTreeSet::new(),
            untracked: 0,
            #[cfg(test)]
            fail_next_append: false,
            #[cfg(test)]
            fail_after_create: false,
        };
        let mut examined = 0;
        let mut orphans: BTreeSet<String> = BTreeSet::new();
        for item in Dir::read_from(&journal.directory).map_err(storage)? {
            let item = item.map_err(storage)?;
            let name = item.file_name().to_string_lossy();
            if matches!(name.as_ref(), "." | ".." | LOCK | DOMAIN) {
                continue;
            }
            examined += 1;
            if examined > MAX_ENTRIES {
                return Err(ClaudeError::Capacity);
            }
            let canonical = name
                .strip_suffix(".jsonl")
                .filter(|id| crate::api::valid_uuid(id));
            let orphan = name
                .strip_prefix('.')
                .and_then(|name| {
                    name.strip_suffix("-write.tmp")
                        .or_else(|| name.strip_suffix("-append.tmp"))
                })
                .filter(|id| crate::api::valid_uuid(id));
            if let Some(id) = orphan {
                journal.reserved.insert(id.into());
                orphans.insert(id.into());
            } else if let Some(id) = canonical {
                match load_entry(&journal.directory, &name, id) {
                    Ok(entry) => {
                        journal.records.insert(id.into(), entry);
                    }
                    Err(_) => {
                        journal.reserved.insert(id.into());
                    }
                }
            } else {
                // Unknown entries are never read or adopted, and consume capacity.
                journal.untracked += 1;
            }
        }
        for id in orphans {
            journal.records.remove(&id);
        }
        if journal.slots() > MAX_OPERATIONS {
            return Err(ClaudeError::Capacity);
        }
        journal.check_root()?;
        Ok(journal)
    }

    /// Created is returned only after the immutable Saved line and parent are synced.
    pub(crate) fn consume(&mut self, saved: SavedInput) -> Result<Consume> {
        saved.validate()?;
        self.check_root()?;
        if self.reserved.contains(&saved.id) {
            return Err(ClaudeError::Storage);
        }
        if let Some(entry) = self.records.get(&saved.id) {
            if entry.receipt.operation != saved {
                return Err(ClaudeError::Conflict);
            }
            return self
                .lookup(&saved.id)?
                .map(Consume::Existing)
                .ok_or(ClaudeError::Storage);
        }
        if self.slots() >= MAX_OPERATIONS {
            return Err(ClaudeError::Capacity);
        }
        let id = saved.id.clone();
        self.reserved.insert(id.clone());
        let file: File = openat(
            &self.directory,
            filename(&id),
            OFlags::RDWR
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(storage)?
        .into();
        let bytes = encode(&Line::Saved {
            operation: Box::new(saved.clone()),
        })?;
        let receipt = Receipt {
            operation: saved,
            evidence: InputEvidence::default(),
            recovered_after_restart: false,
            persistence_failed: false,
        };
        let mut entry = Entry {
            file,
            bytes: bytes.clone(),
            lines: 1,
            receipt,
        };
        let result = (|| {
            owned_file(&entry.file)?;
            named_file(&self.directory, &filename(&id), &entry.file)?;
            #[cfg(test)]
            if self.fail_after_create {
                self.fail_after_create = false;
                return Err(ClaudeError::Storage);
            }
            (&entry.file).write_all(&bytes).map_err(storage)?;
            entry.file.sync_all().map_err(storage)?;
            verify_entry(&self.directory, &id, &entry)?;
            self.directory.sync_all().map_err(storage)?;
            self.check_root()?;
            verify_entry(&self.directory, &id, &entry)
        })();
        if result.is_err() {
            entry.receipt.persistence_failed = true;
            entry.receipt.evidence.write_uncertain = true;
        }
        let receipt = entry.receipt.clone();
        self.reserved.remove(&id);
        self.records.insert(id, entry);
        result?;
        Ok(Consume::Created(receipt))
    }

    pub(crate) fn apply(&mut self, id: &str, evidence: InputEvidence) -> Result<Receipt> {
        if !crate::api::valid_uuid(id) {
            return Err(ClaudeError::InvalidInput);
        }
        evidence.validate()?;
        self.check_root()?;
        let entry = self.records.get_mut(id).ok_or(ClaudeError::Storage)?;
        if entry.receipt.persistence_failed {
            return Err(ClaudeError::Storage);
        }
        let merged = entry.receipt.evidence.merged(evidence)?;
        if merged == entry.receipt.evidence {
            verify_entry(&self.directory, id, entry)?;
            return Ok(entry.receipt.clone());
        }
        let append = encode(&Line::InputEvidence { evidence: merged })?;
        let result = (|| {
            verify_entry(&self.directory, id, entry)?;
            if entry.lines >= MAX_LINES || entry.bytes.len() + append.len() > MAX_BYTES {
                return Err(ClaudeError::Storage);
            }
            #[cfg(test)]
            if self.fail_next_append {
                self.fail_next_append = false;
                return Err(ClaudeError::Storage);
            }
            (&entry.file).write_all(&append).map_err(storage)?;
            entry.file.sync_all().map_err(storage)?;
            let mut expected = entry.bytes.clone();
            expected.extend_from_slice(&append);
            named_file(&self.directory, &filename(id), &entry.file)?;
            if read_bounded(&entry.file, MAX_BYTES)? != expected {
                return Err(ClaudeError::Storage);
            }
            entry.bytes = expected;
            entry.lines += 1;
            Ok(())
        })();
        if result.is_err() {
            mark_failed(entry);
            return Err(ClaudeError::Storage);
        }
        // The update is not published until both the file and original root are verified.
        if self.check_root().is_err() {
            mark_failed(self.records.get_mut(id).ok_or(ClaudeError::Storage)?);
            return Err(ClaudeError::Storage);
        }
        let entry = self.records.get_mut(id).ok_or(ClaudeError::Storage)?;
        entry.receipt.evidence = merged;
        Ok(entry.receipt.clone())
    }

    pub(crate) fn lookup(&self, id: &str) -> Result<Option<Receipt>> {
        if !crate::api::valid_uuid(id) {
            return Err(ClaudeError::InvalidInput);
        }
        self.check_root()?;
        if self.reserved.contains(id) {
            return Err(ClaudeError::Storage);
        }
        let Some(entry) = self.records.get(id) else {
            return Ok(None);
        };
        if !entry.receipt.persistence_failed {
            verify_entry(&self.directory, id, entry)?;
        }
        Ok(Some(entry.receipt.clone()))
    }

    pub(crate) fn receipts(&self) -> Result<Vec<Receipt>> {
        self.records
            .keys()
            .map(|id| self.lookup(id)?.ok_or(ClaudeError::Storage))
            .collect()
    }

    pub(crate) fn mark_persistence_failure(&mut self, id: &str) -> Result<Receipt> {
        let entry = self.records.get_mut(id).ok_or(ClaudeError::Storage)?;
        mark_failed(entry);
        Ok(entry.receipt.clone())
    }

    pub(crate) fn has_consumed(&self) -> bool {
        self.slots() > 0
    }
    fn slots(&self) -> usize {
        self.records.len() + self.reserved.len() + self.untracked
    }

    fn check_root(&self) -> Result<()> {
        let (current, parent, _) = open_root(&self.root, false)?;
        same_file(&self.directory, &current)?;
        same_file(&self.parent, &parent)?;
        let named: File = openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage)?
        .into();
        same_file(&self.directory, &named)?;
        named_file(&self.directory, LOCK, &self.lock.0)?;
        named_file(&self.directory, DOMAIN, &self.marker)?;
        if read_bounded(&self.marker, DOMAIN_BYTES.len())? != DOMAIN_BYTES {
            return Err(ClaudeError::Storage);
        }
        Ok(())
    }
}

fn mark_failed(entry: &mut Entry) {
    entry.receipt.persistence_failed = true;
    // Preserve only previously persisted positive evidence, never the failed append.
    if !entry.receipt.evidence.not_dispatched {
        entry.receipt.evidence.write_uncertain = true;
    }
}

fn encode(line: &Line) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(line).map_err(storage)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_BYTES {
        return Err(ClaudeError::Storage);
    }
    Ok(bytes)
}

fn filename(id: &str) -> String {
    format!("{id}.jsonl")
}

fn load_entry(directory: &File, name: &str, id: &str) -> Result<Entry> {
    load_entry_with_sync(directory, name, id, |file, directory| {
        file.sync_all().map_err(storage)?;
        directory.sync_all().map_err(storage)
    })
}

fn load_entry_with_sync(
    directory: &File,
    name: &str,
    id: &str,
    sync: impl FnOnce(&File, &File) -> Result<()>,
) -> Result<Entry> {
    let file: File = openat(
        directory,
        name,
        OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(storage)?
    .into();
    owned_file(&file)?;
    let bytes = read_bounded(&file, MAX_BYTES)?;
    if !bytes.ends_with(b"\n") {
        return Err(ClaudeError::Storage);
    }
    let mut lines = bytes[..bytes.len() - 1].split(|byte| *byte == b'\n');
    let first: Line =
        serde_json::from_slice(lines.next().ok_or(ClaudeError::Storage)?).map_err(storage)?;
    let Line::Saved { operation } = first else {
        return Err(ClaudeError::Storage);
    };
    operation.validate()?;
    if operation.id != id {
        return Err(ClaudeError::Storage);
    }
    let mut evidence = InputEvidence::default();
    let mut count = 1;
    for line in lines {
        count += 1;
        if count > MAX_LINES {
            return Err(ClaudeError::Storage);
        }
        let Line::InputEvidence { evidence: next } =
            serde_json::from_slice(line).map_err(storage)?
        else {
            return Err(ClaudeError::Storage);
        };
        if evidence.merged(next)? != next {
            return Err(ClaudeError::Storage);
        }
        evidence = next;
    }
    if !evidence.not_dispatched
        && !evidence.user_replayed
        && !evidence.reply_correlated
        && !evidence.result_correlated
    {
        evidence.write_uncertain = true;
    }
    let entry = Entry {
        file,
        bytes,
        lines: count,
        receipt: Receipt {
            operation: *operation,
            evidence,
            recovered_after_restart: true,
            persistence_failed: false,
        },
    };
    // A full line can survive a prior failed sync. Establish durability now,
    // without rewriting it, before publishing any recovered positive evidence.
    verify_entry(directory, id, &entry)?;
    sync(&entry.file, directory)?;
    verify_entry(directory, id, &entry)?;
    Ok(entry)
}

fn verify_entry(directory: &File, id: &str, entry: &Entry) -> Result<()> {
    named_file(directory, &filename(id), &entry.file)?;
    if read_bounded(&entry.file, MAX_BYTES)? != entry.bytes {
        return Err(ClaudeError::Storage);
    }
    Ok(())
}

fn domain(directory: &File) -> Result<File> {
    match openat(
        directory,
        DOMAIN,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => {
            let file = File::from(file);
            owned_file(&file)?;
            if read_bounded(&file, DOMAIN_BYTES.len())? != DOMAIN_BYTES {
                return Err(ClaudeError::Storage);
            }
            named_file(directory, DOMAIN, &file)?;
            Ok(file)
        }
        Err(error) if error == rustix::io::Errno::NOENT => {
            for item in Dir::read_from(directory).map_err(storage)? {
                let item = item.map_err(storage)?;
                if !matches!(item.file_name().to_bytes(), b"." | b".." | b"claude.lock") {
                    return Err(ClaudeError::Storage);
                }
            }
            let file: File = openat(
                directory,
                DOMAIN,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(storage)?
            .into();
            owned_file(&file)?;
            (&file).write_all(DOMAIN_BYTES).map_err(storage)?;
            file.sync_all().map_err(storage)?;
            directory.sync_all().map_err(storage)?;
            named_file(directory, DOMAIN, &file)?;
            Ok(file)
        }
        Err(_) => Err(ClaudeError::Storage),
    }
}

pub(crate) fn owned_file(file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(storage)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(ClaudeError::Storage);
    }
    Ok(())
}

pub(crate) fn named_file(directory: &File, name: &str, held: &File) -> Result<()> {
    owned_file(held)?;
    let named: File = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(storage)?
    .into();
    owned_file(&named)?;
    same_file(held, &named)
}

pub(crate) fn same_file(left: &File, right: &File) -> Result<()> {
    let left = left.metadata().map_err(storage)?;
    let right = right.metadata().map_err(storage)?;
    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(ClaudeError::Storage);
    }
    Ok(())
}

pub(crate) fn read_bounded(file: &File, max: usize) -> Result<Vec<u8>> {
    owned_file(file)?;
    let before = file.metadata().map_err(storage)?;
    if before.len() > max as u64 {
        return Err(ClaudeError::Storage);
    }
    let mut bytes = vec![0; before.len() as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(storage)?;
        if count == 0 {
            return Err(ClaudeError::Storage);
        }
        offset += count;
    }
    let after = file.metadata().map_err(storage)?;
    if before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(ClaudeError::Storage);
    }
    Ok(bytes)
}

pub(crate) fn open_root(root: &Path, create: bool) -> Result<(File, File, OsString)> {
    if !root.is_absolute() || root.as_os_str().len() > 4096 {
        return Err(ClaudeError::InvalidInput);
    }
    let mut normalized = PathBuf::new();
    for component in root.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(ClaudeError::InvalidInput);
        }
        normalized.push(component.as_os_str());
    }
    if normalized.as_os_str() != root.as_os_str() {
        return Err(ClaudeError::InvalidInput);
    }
    let components: Vec<_> = root.components().collect();
    if components.len() < 2 {
        return Err(ClaudeError::InvalidInput);
    }
    let mut parent: File = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(storage)?
    .into();
    for (index, part) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = part else {
            return Err(ClaudeError::InvalidInput);
        };
        let name = *name;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let child: File = match openat(&parent, name, flags, Mode::empty()) {
            Ok(file) => file.into(),
            Err(error)
                if create && index + 1 == components.len() && error == rustix::io::Errno::NOENT =>
            {
                mkdirat(&parent, name, Mode::RWXU).map_err(storage)?;
                parent.sync_all().map_err(storage)?;
                openat(&parent, name, flags, Mode::empty())
                    .map_err(storage)?
                    .into()
            }
            Err(_) => return Err(ClaudeError::Storage),
        };
        if index + 1 == components.len() {
            let metadata = child.metadata().map_err(storage)?;
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(ClaudeError::Storage);
            }
            return Ok((child, parent, name.to_os_string()));
        }
        parent = child;
    }
    Err(ClaudeError::InvalidInput)
}

fn storage(_: impl std::fmt::Display) -> ClaudeError {
    ClaudeError::Storage
}

#[cfg(test)]
mod tests;
