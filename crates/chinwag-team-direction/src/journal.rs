use crate::{
    api::valid_id,
    json,
    private::{self, FileLock},
    *,
};
use rustix::fs::{Dir, Mode, OFlags, openat};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};
const DOMAIN: &str = "team-direction-domain.json";
const MARKER: &[u8] = b"{\"schema\":\"chinwag-team-direction-actions/v1\"}\n";
const MAX_BYTES: usize = 65536;
const MAX_LINES: usize = 16;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Line {
    Saved {
        intent: Box<SavedDirection>,
    },
    Claim {
        member: String,
    },
    Admission {
        member: String,
        result: LocalAdmission,
    },
    Retired,
}
#[derive(Clone)]
pub(crate) struct Stored {
    pub(crate) intent: SavedDirection,
    pub(crate) claims: BTreeSet<String>,
    pub(crate) admissions: BTreeMap<String, LocalAdmission>,
    pub(crate) retired: bool,
    pub(crate) recovered: bool,
}
struct Entry {
    file: File,
    bytes: Vec<u8>,
    lines: usize,
    stored: Stored,
}
pub(crate) struct Journal {
    root: PathBuf,
    directory: File,
    lock: FileLock,
    marker: File,
    entries: BTreeMap<String, Entry>,
    faulted: bool,
    #[cfg(test)]
    fail_admission: bool,
}
pub(crate) struct Claimed {
    parent: String,
    member: String,
    pub(crate) stored: Stored,
}
impl Claimed {
    pub(crate) fn parent(&self) -> &str {
        &self.parent
    }
    pub(crate) fn member(&self) -> &str {
        &self.member
    }
}
fn storage(_: impl std::fmt::Display) -> TeamError {
    TeamError::Storage
}
fn filename(id: &str) -> String {
    format!("{id}.jsonl")
}
fn valid_parent(id: &str) -> bool {
    id.strip_prefix("team-").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn encode(line: &Line) -> Result<Vec<u8>> {
    let mut b = serde_json::to_vec(line).map_err(storage)?;
    b.push(b'\n');
    if b.len() > MAX_BYTES {
        return Err(TeamError::Capacity);
    }
    Ok(b)
}
impl Journal {
    #[cfg(test)]
    pub(crate) fn fail_admission_for_fixture(&mut self) {
        self.fail_admission = true;
    }

    pub(crate) fn open(root: &Path) -> Result<Self> {
        let (directory, _, _) = private::open_root(root, true)?;
        let lock = private::lock(&directory, "team-actions.lock")?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let marker = match openat(&directory, DOMAIN, flags, Mode::empty()) {
            Ok(fd) => {
                let f: File = fd.into();
                if private::read_bounded(&f, MARKER.len())? != MARKER {
                    return Err(TeamError::Storage);
                }
                private::named_file(&directory, DOMAIN, &f)?;
                f
            }
            Err(e) if e == rustix::io::Errno::NOENT => {
                for item in Dir::read_from(&directory).map_err(storage)? {
                    let item = item.map_err(storage)?;
                    if !matches!(
                        item.file_name().to_bytes(),
                        b"." | b".." | b"team-actions.lock"
                    ) {
                        return Err(TeamError::Storage);
                    }
                }
                private::write_new(&directory, DOMAIN, MARKER)?
            }
            Err(_) => return Err(TeamError::Storage),
        };
        let mut journal = Self {
            root: root.into(),
            directory,
            lock,
            marker,
            entries: BTreeMap::new(),
            faulted: false,
            #[cfg(test)]
            fail_admission: false,
        };
        for item in Dir::read_from(&journal.directory).map_err(storage)? {
            let item = item.map_err(storage)?;
            let name = item.file_name().to_str().map_err(storage)?;
            if matches!(name, "." | ".." | "team-actions.lock" | DOMAIN) {
                continue;
            }
            let id = name
                .strip_suffix(".jsonl")
                .filter(|id| valid_parent(id))
                .ok_or(TeamError::Storage)?;
            if journal.entries.len() >= MAX_DIRECTIONS {
                return Err(TeamError::Capacity);
            }
            let file: File = openat(
                &journal.directory,
                name,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(storage)?
            .into();
            let bytes = private::read_bounded(&file, MAX_BYTES)?;
            private::named_file(&journal.directory, name, &file)?;
            let entry = parse(file, bytes, id)?;
            journal.entries.insert(id.into(), entry);
        }
        journal.verify()?;
        Ok(journal)
    }
    fn verify(&self) -> Result<()> {
        if self.faulted {
            return Err(TeamError::Storage);
        }
        private::verify_root(&self.root, &self.directory)?;
        private::named_file(&self.directory, "team-actions.lock", &self.lock.0)?;
        private::named_file(&self.directory, DOMAIN, &self.marker)?;
        if private::read_bounded(&self.marker, MARKER.len())? != MARKER {
            return Err(TeamError::Storage);
        }
        Ok(())
    }
    fn verify_entry(&self, id: &str) -> Result<&Entry> {
        self.verify()?;
        let e = self.entries.get(id).ok_or(TeamError::InvalidInput)?;
        private::named_file(&self.directory, &filename(id), &e.file)?;
        if private::read_bounded(&e.file, MAX_BYTES)? != e.bytes {
            return Err(TeamError::Storage);
        }
        Ok(e)
    }
    pub(crate) fn receipts(&self) -> Result<Vec<Stored>> {
        self.verify()?;
        self.entries
            .keys()
            .map(|id| self.verify_entry(id).map(|e| e.stored.clone()))
            .collect()
    }
    pub(crate) fn lookup(&self, id: &str) -> Result<Option<Stored>> {
        self.verify()?;
        if self.entries.contains_key(id) {
            Ok(Some(self.verify_entry(id)?.stored.clone()))
        } else {
            Ok(None)
        }
    }
    pub(crate) fn save(&mut self, intent: SavedDirection) -> Result<()> {
        self.verify()?;
        check_intent(&intent)?;
        if self.entries.contains_key(&intent.id) {
            return Err(TeamError::ConsumedRevision);
        }
        if self.entries.len() >= MAX_DIRECTIONS {
            return Err(TeamError::Capacity);
        }
        let bytes = encode(&Line::Saved {
            intent: Box::new(intent.clone()),
        })?;
        let result = private::write_new(&self.directory, &filename(&intent.id), &bytes);
        let file = match result {
            Ok(f) => f,
            Err(e) => {
                self.faulted = true;
                return Err(e);
            }
        };
        self.entries.insert(
            intent.id.clone(),
            Entry {
                file,
                bytes,
                lines: 1,
                stored: Stored {
                    intent,
                    claims: BTreeSet::new(),
                    admissions: BTreeMap::new(),
                    retired: false,
                    recovered: false,
                },
            },
        );
        if let Err(e) = self.verify() {
            self.faulted = true;
            return Err(e);
        }
        Ok(())
    }
    fn append(&mut self, id: &str, line: Line) -> Result<()> {
        self.verify_entry(id)?;
        let tail = encode(&line)?;
        let e = self.entries.get_mut(id).ok_or(TeamError::InvalidInput)?;
        if e.lines >= MAX_LINES || e.bytes.len() + tail.len() > MAX_BYTES {
            return Err(TeamError::Capacity);
        }
        let mut projected = e.stored.clone();
        apply(&mut projected, line.clone())?;
        let mut next = e.bytes.clone();
        next.extend_from_slice(&tail);
        let written = (|| {
            e.file
                .write_all_at(&tail, e.bytes.len() as u64)
                .map_err(storage)?;
            e.file.sync_all().map_err(storage)?;
            private::named_file(&self.directory, &filename(id), &e.file)?;
            if private::read_bounded(&e.file, MAX_BYTES)? != next {
                return Err(TeamError::Storage);
            }
            Ok(())
        })();
        if let Err(error) = written {
            self.faulted = true;
            return Err(error);
        }
        e.stored = projected;
        e.bytes = next;
        e.lines += 1;
        if let Err(error) = self.verify() {
            self.faulted = true;
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn claim(&mut self, id: &str, member: &str) -> Result<Claimed> {
        let e = self.verify_entry(id)?;
        if e.stored.retired
            || !e.stored.intent.effective.iter().any(|v| v == member)
            || e.stored.claims.contains(member)
        {
            return Err(TeamError::ConsumedRevision);
        }
        self.append(
            id,
            Line::Claim {
                member: member.into(),
            },
        )?;
        Ok(Claimed {
            parent: id.into(),
            member: member.into(),
            stored: self
                .entries
                .get(id)
                .ok_or(TeamError::Storage)?
                .stored
                .clone(),
        })
    }
    pub(crate) fn admission(&mut self, claim: &Claimed, result: LocalAdmission) -> Result<()> {
        #[cfg(test)]
        if self.fail_admission {
            self.fail_admission = false;
            self.faulted = true;
            return Err(TeamError::Storage);
        }
        let e = self.verify_entry(claim.parent())?;
        if !e.stored.claims.contains(claim.member())
            || e.stored.admissions.contains_key(claim.member())
        {
            return Err(TeamError::InvalidInput);
        }
        self.append(
            claim.parent(),
            Line::Admission {
                member: claim.member().into(),
                result,
            },
        )
    }
    pub(crate) fn retire(&mut self, id: &str) -> Result<()> {
        self.append(id, Line::Retired)
    }
}

#[cfg(test)]
mod tests;
fn parse(file: File, bytes: Vec<u8>, id: &str) -> Result<Entry> {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err(TeamError::Storage);
    }
    let lines: Vec<_> = bytes[..bytes.len() - 1].split(|b| *b == b'\n').collect();
    if lines.len() > MAX_LINES {
        return Err(TeamError::Storage);
    }
    let first: Line = json::decode(lines[0], MAX_BYTES).map_err(storage)?;
    let Line::Saved { intent } = first else {
        return Err(TeamError::Storage);
    };
    validate(&intent).map_err(storage)?;
    if intent.id != id {
        return Err(TeamError::Storage);
    }
    let mut stored = Stored {
        intent: *intent,
        claims: BTreeSet::new(),
        admissions: BTreeMap::new(),
        retired: false,
        recovered: true,
    };
    for line in lines.iter().skip(1) {
        apply(&mut stored, json::decode(line, MAX_BYTES).map_err(storage)?)?
    }
    let count = lines.len();
    Ok(Entry {
        file,
        bytes,
        lines: count,
        stored,
    })
}
fn apply(s: &mut Stored, line: Line) -> Result<()> {
    if s.retired {
        return Err(TeamError::Storage);
    }
    match line {
        Line::Claim { member } => {
            if !s.intent.effective.contains(&member) || !s.claims.insert(member) {
                return Err(TeamError::Storage);
            }
        }
        Line::Admission { member, result } => {
            if !s.claims.contains(&member) || s.admissions.insert(member, result).is_some() {
                return Err(TeamError::Storage);
            }
        }
        Line::Retired => s.retired = true,
        Line::Saved { .. } => return Err(TeamError::Storage),
    }
    Ok(())
}
pub(crate) fn check_intent(s: &SavedDirection) -> Result<()> {
    validate(s)?;
    if encode(&Line::Saved {
        intent: Box::new(s.clone()),
    })?
    .len()
        > MAX_BYTES - 4096
    {
        return Err(TeamError::InvalidInput);
    }
    Ok(())
}
fn validate(s: &SavedDirection) -> Result<()> {
    if s.human_revision == 0
        || !s
            .host_instance
            .strip_prefix("host-")
            .is_some_and(|v| hex(v, 64))
        || !valid_parent(&s.id)
        || s.host_instance.len() > 128
        || s.host_instance.is_empty()
        || !crate::api::valid_text(&s.text)
        || s.selected.is_empty()
        || s.selected.len() > MAX_MEMBERS
        || s.effective.is_empty()
        || s.effective.len() > s.selected.len()
        || s.members.len() != s.selected.len()
    {
        return Err(TeamError::InvalidInput);
    }
    let selected: BTreeSet<_> = s.selected.iter().collect();
    let effective: BTreeSet<_> = s.effective.iter().collect();
    if selected.len() != s.selected.len()
        || effective.len() != s.effective.len()
        || !effective.is_subset(&selected)
    {
        return Err(TeamError::InvalidInput);
    }
    let mut ids = BTreeSet::new();
    let mut child_ids = BTreeSet::new();
    for m in &s.members {
        if !valid_id(&m.id)
            || !selected.contains(&m.id)
            || !ids.insert(&m.id)
            || m.label.trim().is_empty()
            || m.label.len() > 64
            || m.label.chars().any(char::is_control)
        {
            return Err(TeamError::InvalidInput);
        }
        if effective.contains(&m.id) {
            let id = m.child_id.as_ref().ok_or(TeamError::InvalidInput)?;
            if !child_ids.insert(id) || m.action.is_none() || m.excluded.is_some() {
                return Err(TeamError::InvalidInput);
            }
            let audit = m.audit.as_ref().ok_or(TeamError::InvalidInput)?;
            let matches = match audit {
                NativeAudit::Codex { operation, .. } => {
                    operation.id == *id
                        && operation.text == s.text
                        && m.action == Some(ActionLabel::CodexSteer)
                        && operation.schema == "chinwag-codex-steer-operation/v1"
                        && operation.id.len() >= 16
                        && operation.id.len() <= 100
                        && target_id(&operation.id)
                        && hex(&operation.transport_epoch, 32)
                        && target_id(&operation.thread_id)
                        && target_id(&operation.expected_turn_id)
                }
                NativeAudit::Claude { operation, .. } => {
                    operation.id == *id
                        && operation.text == s.text
                        && operation.schema == "chinwag-claude-input/v1"
                        && uuid(&operation.id)
                        && uuid(&operation.session_epoch)
                        && uuid(&operation.session_id)
                        && operation.startup.is_none()
                        && operation.kind == chinwag_claude_control::ActionKind::Direction
                        && match operation.timing {
                            ClaudeTiming::Now => m.action == Some(ActionLabel::ClaudeNow),
                            ClaudeTiming::AfterTools => {
                                m.action == Some(ActionLabel::ClaudeAfterTools)
                            }
                            ClaudeTiming::AfterTurn => {
                                m.action == Some(ActionLabel::ClaudeAfterTurn)
                            }
                        }
                }
                NativeAudit::Gemini { operation, .. } => {
                    operation.id == *id
                        && operation.text == s.text
                        && operation.schema == "chinwag-gemini-operation/v1"
                        && uuid(&operation.id)
                        && uuid(&operation.session_epoch)
                        && operation.session_id.as_ref().is_some_and(|v| uuid(v))
                        && operation.startup.is_none()
                        && operation.prompt_generation > 0
                        && operation.prompt_rpc_id == format!("prompt-{}", operation.id)
                        && operation.kind == chinwag_gemini_control::ActionKind::Prompt
                        && m.action == Some(ActionLabel::GeminiPrompt)
                }
            };
            if !matches {
                return Err(TeamError::InvalidInput);
            }
        } else if m.child_id.is_some()
            || m.audit.is_some()
            || m.action.is_some()
            || m.excluded.is_none()
        {
            return Err(TeamError::InvalidInput);
        }
    }
    Ok(())
}

fn hex(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn uuid(v: &str) -> bool {
    v.len() == 36
        && v.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}
fn target_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}
