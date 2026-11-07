#![forbid(unsafe_code)]
//! Bounded observational storage DTOs. None constructs task or writer authority.
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_QUALIFIED_RECORD_BYTES: usize = 262_144;
pub const MAX_QUALIFIED_CHUNK_BYTES: usize = crate::MAX_VALUE_BYTES;
pub const MAX_QUALIFIED_PARTS: usize = 4;
pub const MAX_QUALIFIED_BATCH_RECORDS: usize = 128;
pub const MAX_QUALIFIED_BATCH_BYTES: usize = 1_048_576;
pub const MAX_QUALIFIED_PAYLOAD_BYTES: usize = 65_536;
pub const MAX_SIGNED_BINDING_BYTES: usize = 131_072;
pub const MAX_TASK_REF_BYTES: usize = 5_091;
const MAX_ID: usize = 256;
const MAX_PATH: usize = 4096;
const TASK_REF_DOMAIN: &[u8] = b"chinwag-taskref-v1\0";
const KEY_DOMAIN: &[u8] = b"chinwag-observation-key-v1\0";
const RECORD_DOMAIN: &[u8] = b"chinwag-qualified-observation-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualifiedError {
    Invalid(&'static str),
    OversizeHeld,
    Mismatch(&'static str),
    Incomplete,
    NonCanonical,
}
impl fmt::Display for QualifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "qualified observation held: {self:?}")
    }
}
impl std::error::Error for QualifiedError {}
type Result<T> = std::result::Result<T, QualifiedError>;
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn id(value: &str) -> Result<()> {
    if value.len() > MAX_ID {
        return Err(QualifiedError::OversizeHeld);
    }
    if value.is_empty() || value.trim() != value || value.contains(['\0', '\r', '\n']) {
        return Err(QualifiedError::Invalid("identifier"));
    }
    Ok(())
}
fn workspace(value: &str) -> Result<()> {
    id(value)?;
    if value.chars().any(|c| c.is_whitespace() || c.is_control())
        || value == "."
        || value == ".."
        || value.starts_with('~')
        || value.contains(['/', '\\'])
    {
        return Err(QualifiedError::Invalid("workspace"));
    }
    Ok(())
}
fn source(value: &str) -> Result<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(QualifiedError::Invalid("source"));
    }
    Ok(())
}
fn revision(value: u64) -> Result<()> {
    if value > i64::MAX as u64 {
        return Err(QualifiedError::Invalid("revision"));
    }
    Ok(())
}
fn path(value: &str) -> Result<()> {
    if value.len() > MAX_PATH {
        return Err(QualifiedError::OversizeHeld);
    }
    if value.is_empty()
        || value.starts_with('/')
        || value.contains(['\0', '\r', '\n', '\\'])
        || value.split('/').count() > 64
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(QualifiedError::Invalid("path"));
    }
    Ok(())
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
fn put_text(out: &mut Vec<u8>, text: &str) {
    put_bytes(out, text.as_bytes());
}

struct Decoder<'a> {
    remaining: &'a [u8],
}
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if length > self.remaining.len() {
            return Err(QualifiedError::Incomplete);
        }
        let (bytes, rest) = self.remaining.split_at(length);
        self.remaining = rest;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| QualifiedError::Incomplete)?,
        ))
    }
    fn blob(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = self.u64()?;
        if length > maximum as u64 {
            return Err(QualifiedError::OversizeHeld);
        }
        self.take(usize::try_from(length).map_err(|_| QualifiedError::OversizeHeld)?)
    }
    fn text(&mut self, maximum: usize) -> Result<String> {
        Ok(std::str::from_utf8(self.blob(maximum)?)
            .map_err(|_| QualifiedError::Invalid("UTF8"))?
            .to_owned())
    }
    fn hash(&mut self) -> Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| QualifiedError::Incomplete)
    }
    fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(QualifiedError::NonCanonical)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredGitOid {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}
impl StoredGitOid {
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Sha1(_) => "git-sha1",
            Self::Sha256(_) => "git-sha256",
        }
    }
    pub fn raw(&self) -> &[u8] {
        match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
        }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        put_text(out, self.algorithm());
        put_bytes(out, self.raw());
    }
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        let algorithm = decoder.blob(10)?;
        let bytes = decoder.blob(32)?;
        match algorithm {
            b"git-sha1" => Ok(Self::Sha1(
                bytes
                    .try_into()
                    .map_err(|_| QualifiedError::Invalid("Git SHA1"))?,
            )),
            b"git-sha256" => Ok(Self::Sha256(
                bytes
                    .try_into()
                    .map_err(|_| QualifiedError::Invalid("Git SHA256"))?,
            )),
            _ => Err(QualifiedError::Invalid("Git algorithm")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRefIndexes {
    workspace_id: String,
    repo_id: String,
    task_source_id: String,
    source_generation: u64,
    canonical_task_path: String,
    task_id: String,
    task_spec_digest: [u8; 32],
    task_status_rev: u64,
    file_cas_rev: u64,
    baseline_commit: StoredGitOid,
}
impl TaskRefIndexes {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        workspace_id: String,
        repo_id: String,
        task_source_id: String,
        source_generation: u64,
        canonical_task_path: String,
        task_id: String,
        task_spec_digest: [u8; 32],
        task_status_rev: u64,
        file_cas_rev: u64,
        baseline_commit: StoredGitOid,
    ) -> Result<Self> {
        workspace(&workspace_id)?;
        id(&repo_id)?;
        source(&task_source_id)?;
        path(&canonical_task_path)?;
        id(&task_id)?;
        revision(source_generation)?;
        revision(task_status_rev)?;
        revision(file_cas_rev)?;
        Ok(Self {
            workspace_id,
            repo_id,
            task_source_id,
            source_generation,
            canonical_task_path,
            task_id,
            task_spec_digest,
            task_status_rev,
            file_cas_rev,
            baseline_commit,
        })
    }
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }
    pub fn task_source_id(&self) -> &str {
        &self.task_source_id
    }
    pub fn source_generation(&self) -> u64 {
        self.source_generation
    }
    pub fn canonical_task_path(&self) -> &str {
        &self.canonical_task_path
    }
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    pub fn task_spec_digest(&self) -> [u8; 32] {
        self.task_spec_digest
    }
    pub fn task_status_rev(&self) -> u64 {
        self.task_status_rev
    }
    pub fn file_cas_rev(&self) -> u64 {
        self.file_cas_rev
    }
    pub fn baseline_commit(&self) -> StoredGitOid {
        self.baseline_commit
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = TASK_REF_DOMAIN.to_vec();
        put_text(&mut out, &self.workspace_id);
        put_text(&mut out, &self.repo_id);
        put_text(&mut out, &self.task_source_id);
        put_u64(&mut out, self.source_generation);
        put_text(&mut out, &self.canonical_task_path);
        put_text(&mut out, &self.task_id);
        put_text(&mut out, "sha256");
        put_bytes(&mut out, &self.task_spec_digest);
        put_u64(&mut out, self.task_status_rev);
        put_u64(&mut out, self.file_cas_rev);
        self.baseline_commit.encode(&mut out);
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_TASK_REF_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        let mut d = Decoder::new(bytes);
        if d.take(TASK_REF_DOMAIN.len())? != TASK_REF_DOMAIN {
            return Err(QualifiedError::Invalid("TaskRef domain"));
        }
        let workspace = d.text(MAX_ID)?;
        let repo = d.text(MAX_ID)?;
        let source = d.text(MAX_ID)?;
        let generation = d.u64()?;
        let path = d.text(MAX_PATH)?;
        let task = d.text(MAX_ID)?;
        if d.blob(6)? != b"sha256" {
            return Err(QualifiedError::Invalid("TaskRef digest type"));
        }
        let spec = d
            .blob(32)?
            .try_into()
            .map_err(|_| QualifiedError::Invalid("TaskRef digest"))?;
        let status = d.u64()?;
        let cas = d.u64()?;
        let baseline = StoredGitOid::decode(&mut d)?;
        d.finish()?;
        let value = Self::try_new(
            workspace, repo, source, generation, path, task, spec, status, cas, baseline,
        )?;
        if value.canonical_bytes() != bytes {
            return Err(QualifiedError::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRefEnvelope {
    canonical: Vec<u8>,
    digest: [u8; 32],
    indexes: TaskRefIndexes,
}
impl TaskRefEnvelope {
    pub fn try_new(
        canonical: Vec<u8>,
        expected_digest: [u8; 32],
        indexes: TaskRefIndexes,
    ) -> Result<Self> {
        let decoded = TaskRefIndexes::decode(&canonical)?;
        if decoded != indexes || digest(&canonical) != expected_digest {
            return Err(QualifiedError::Mismatch("TaskRef bytes/digest/indexes"));
        }
        Ok(Self {
            canonical,
            digest: expected_digest,
            indexes,
        })
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn indexes(&self) -> &TaskRefIndexes {
        &self.indexes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RecordFamily {
    Source = 1,
    Projection,
    Dependency,
    Event,
    Message,
    Assignment,
    Acceptance,
    SourceWriteIntent,
    SchedulerAdmission,
}
impl RecordFamily {
    pub fn code(self) -> u8 {
        self as u8
    }
    pub fn is_replicated(self) -> bool {
        self.code() <= Self::Acceptance.code()
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "task_sources",
            Self::Projection => "task_projection",
            Self::Dependency => "task_dependency_edges",
            Self::Event => "task_events",
            Self::Message => "task_message_bindings",
            Self::Assignment => "task_assignments",
            Self::Acceptance => "task_acceptances",
            Self::SourceWriteIntent => "source_write_intents",
            Self::SchedulerAdmission => "scheduler_admissions",
        }
    }
    pub fn from_code(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Source),
            2 => Ok(Self::Projection),
            3 => Ok(Self::Dependency),
            4 => Ok(Self::Event),
            5 => Ok(Self::Message),
            6 => Ok(Self::Assignment),
            7 => Ok(Self::Acceptance),
            8 => Ok(Self::SourceWriteIntent),
            9 => Ok(Self::SchedulerAdmission),
            _ => Err(QualifiedError::Invalid("record family")),
        }
    }
    pub fn is_immutable_original(self) -> bool {
        matches!(
            self,
            Self::Event | Self::Message | Self::Assignment | Self::Acceptance
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyPart {
    Text(String),
    Number(u64),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalKey {
    family: RecordFamily,
    parts: Vec<KeyPart>,
}
impl LogicalKey {
    fn new(family: RecordFamily, parts: Vec<KeyPart>) -> Result<Self> {
        let key = Self { family, parts };
        key.validate()?;
        Ok(key)
    }
    // Shape is established by every constructor and the strict decoder. These
    // accessors cannot manufacture a fallback identity from a numeric field.
    fn text(&self, index: usize) -> &str {
        match &self.parts[index] {
            KeyPart::Text(value) => value,
            KeyPart::Number(_) => unreachable!("validated key text position"),
        }
    }
    fn number(&self, index: usize) -> u64 {
        match self.parts[index] {
            KeyPart::Number(value) => value,
            KeyPart::Text(_) => unreachable!("validated key number position"),
        }
    }
    fn validate(&self) -> Result<()> {
        let shape: &[bool] = match self.family {
            RecordFamily::Source => &[false, false, true],
            RecordFamily::Projection
            | RecordFamily::Event
            | RecordFamily::Message
            | RecordFamily::SourceWriteIntent => &[false, false, false],
            RecordFamily::Dependency => &[false, false, false, false, false],
            RecordFamily::Assignment | RecordFamily::SchedulerAdmission => &[false, false],
            RecordFamily::Acceptance => &[false, false, false, true, false, false],
        };
        if shape.len() != self.parts.len()
            || shape
                .iter()
                .zip(&self.parts)
                .any(|(number, part)| *number != matches!(part, KeyPart::Number(_)))
        {
            return Err(QualifiedError::Invalid("logical key shape"));
        }
        for part in &self.parts {
            match part {
                KeyPart::Text(value) => id(value)?,
                KeyPart::Number(0) if self.family == RecordFamily::Acceptance => {
                    return Err(QualifiedError::Invalid("zero review round"));
                }
                // Review rounds use the primary's full nonzero U64 domain;
                // source/revision counters retain their narrower profile.
                KeyPart::Number(_) if self.family == RecordFamily::Acceptance => {}
                KeyPart::Number(value) => revision(*value)?,
            }
        }
        workspace(self.text(0))?;
        match self.family {
            RecordFamily::Source
            | RecordFamily::Projection
            | RecordFamily::Event
            | RecordFamily::Acceptance
            | RecordFamily::SourceWriteIntent => source(self.text(1))?,
            RecordFamily::Dependency => {
                source(self.text(1))?;
                source(self.text(3))?;
            }
            _ => {}
        }
        Ok(())
    }
    pub fn source(workspace: String, source: String, generation: u64) -> Result<Self> {
        Self::new(
            RecordFamily::Source,
            vec![
                KeyPart::Text(workspace),
                KeyPart::Text(source),
                KeyPart::Number(generation),
            ],
        )
    }
    pub fn projection(workspace: String, source: String, task: String) -> Result<Self> {
        Self::new(
            RecordFamily::Projection,
            texts(vec![workspace, source, task]),
        )
    }
    pub fn dependency(
        workspace: String,
        dependent_source: String,
        dependent_task: String,
        prerequisite_source: String,
        prerequisite_task: String,
    ) -> Result<Self> {
        Self::new(
            RecordFamily::Dependency,
            texts(vec![
                workspace,
                dependent_source,
                dependent_task,
                prerequisite_source,
                prerequisite_task,
            ]),
        )
    }
    pub fn event(workspace: String, source: String, transition: String) -> Result<Self> {
        Self::new(
            RecordFamily::Event,
            texts(vec![workspace, source, transition]),
        )
    }
    pub fn message(workspace: String, signer: String, message: String) -> Result<Self> {
        Self::new(
            RecordFamily::Message,
            texts(vec![workspace, signer, message]),
        )
    }
    pub fn assignment(workspace: String, assignment: String) -> Result<Self> {
        Self::new(RecordFamily::Assignment, texts(vec![workspace, assignment]))
    }
    pub fn acceptance(
        workspace: String,
        source: String,
        task: String,
        round: u64,
        reviewer: String,
        acceptance: String,
    ) -> Result<Self> {
        Self::new(
            RecordFamily::Acceptance,
            vec![
                KeyPart::Text(workspace),
                KeyPart::Text(source),
                KeyPart::Text(task),
                KeyPart::Number(round),
                KeyPart::Text(reviewer),
                KeyPart::Text(acceptance),
            ],
        )
    }
    pub fn source_write_intent(
        workspace: String,
        source: String,
        operation: String,
    ) -> Result<Self> {
        Self::new(
            RecordFamily::SourceWriteIntent,
            texts(vec![workspace, source, operation]),
        )
    }
    pub fn scheduler_admission(workspace: String, admission: String) -> Result<Self> {
        Self::new(
            RecordFamily::SchedulerAdmission,
            texts(vec![workspace, admission]),
        )
    }
    pub fn family(&self) -> RecordFamily {
        self.family
    }
    pub fn workspace(&self) -> &str {
        self.text(0)
    }
    pub fn source_id(&self) -> Option<&str> {
        match self.family {
            RecordFamily::Source
            | RecordFamily::Projection
            | RecordFamily::Dependency
            | RecordFamily::Event
            | RecordFamily::Acceptance
            | RecordFamily::SourceWriteIntent => Some(self.text(1)),
            _ => None,
        }
    }
    pub fn task(&self) -> Option<&str> {
        match self.family {
            RecordFamily::Projection | RecordFamily::Dependency | RecordFamily::Acceptance => {
                Some(self.text(2))
            }
            _ => None,
        }
    }
    pub fn generation(&self) -> Option<u64> {
        (self.family == RecordFamily::Source).then(|| self.number(2))
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = KEY_DOMAIN.to_vec();
        out.push(self.family.code());
        for part in &self.parts {
            match part {
                KeyPart::Text(value) => put_text(&mut out, value),
                KeyPart::Number(value) => put_u64(&mut out, *value),
            }
        }
        out
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2048 {
            return Err(QualifiedError::OversizeHeld);
        }
        let mut d = Decoder::new(bytes);
        if d.take(KEY_DOMAIN.len())? != KEY_DOMAIN {
            return Err(QualifiedError::Invalid("key domain"));
        }
        let family = RecordFamily::from_code(d.byte()?)?;
        let shape: &[bool] = match family {
            RecordFamily::Source => &[false, false, true],
            RecordFamily::Projection
            | RecordFamily::Event
            | RecordFamily::Message
            | RecordFamily::SourceWriteIntent => &[false, false, false],
            RecordFamily::Dependency => &[false, false, false, false, false],
            RecordFamily::Assignment | RecordFamily::SchedulerAdmission => &[false, false],
            RecordFamily::Acceptance => &[false, false, false, true, false, false],
        };
        let mut parts = Vec::new();
        for number in shape {
            parts.push(if *number {
                KeyPart::Number(d.u64()?)
            } else {
                KeyPart::Text(d.text(MAX_ID)?)
            });
        }
        d.finish()?;
        let key = Self::new(family, parts)?;
        if key.canonical_bytes() != bytes {
            return Err(QualifiedError::NonCanonical);
        }
        Ok(key)
    }
}
fn texts(values: Vec<String>) -> Vec<KeyPart> {
    values.into_iter().map(KeyPart::Text).collect()
}

/// Full immutable context, not a globally unique bare message/transition ID.
/// Constructors for observations restrict originals to their four families.
pub type ImmutableOriginalKey = LogicalKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableOriginal {
    key: ImmutableOriginalKey,
    binding: Vec<u8>,
    digest: [u8; 32],
}
impl ImmutableOriginal {
    pub fn try_new(
        key: ImmutableOriginalKey,
        binding: Vec<u8>,
        expected_digest: [u8; 32],
    ) -> Result<Self> {
        if !key.family().is_immutable_original() {
            return Err(QualifiedError::Invalid("original family"));
        }
        if binding.len() > MAX_SIGNED_BINDING_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        if binding.is_empty() {
            return Err(QualifiedError::Invalid("empty original binding"));
        }
        if digest(&binding) != expected_digest {
            return Err(QualifiedError::Mismatch("original binding digest"));
        }
        Ok(Self {
            key,
            binding,
            digest: expected_digest,
        })
    }
    pub fn key(&self) -> &ImmutableOriginalKey {
        &self.key
    }
    pub fn canonical_binding(&self) -> &[u8] {
        &self.binding
    }
    pub fn binding_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn binding(&self) -> &[u8] {
        self.canonical_binding()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.binding_digest()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedRecord {
    observation_id: String,
    key: LogicalKey,
    references: Vec<TaskRefEnvelope>,
    original: Option<ImmutableOriginal>,
    payload: Vec<u8>,
    payload_digest: [u8; 32],
    canonical_digest: [u8; 32],
    canonical_len: usize,
}
impl QualifiedRecord {
    pub fn try_new(
        observation_id: String,
        key: LogicalKey,
        references: Vec<TaskRefEnvelope>,
        original: Option<ImmutableOriginal>,
        payload: Vec<u8>,
        payload_digest: [u8; 32],
    ) -> Result<Self> {
        id(&observation_id)?;
        if payload.len() > MAX_QUALIFIED_PAYLOAD_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        if digest(&payload) != payload_digest {
            return Err(QualifiedError::Mismatch("phase payload digest"));
        }
        let valid_count = match key.family() {
            RecordFamily::Source => references.is_empty(),
            RecordFamily::Dependency => references.len() == 2,
            RecordFamily::Event | RecordFamily::SourceWriteIntent => {
                (1..=2).contains(&references.len())
            }
            _ => references.len() == 1,
        };
        if !valid_count {
            return Err(QualifiedError::Invalid("TaskRef count for family"));
        }
        for reference in &references {
            let indexed = reference.indexes();
            if indexed.workspace_id() != key.workspace() {
                return Err(QualifiedError::Mismatch("TaskRef workspace/key"));
            }
            match key.family() {
                RecordFamily::Projection | RecordFamily::Acceptance => {
                    if Some(indexed.task_source_id()) != key.source_id()
                        || Some(indexed.task_id()) != key.task()
                    {
                        return Err(QualifiedError::Mismatch("TaskRef task/key"));
                    }
                }
                RecordFamily::Event | RecordFamily::SourceWriteIntent
                    if Some(indexed.task_source_id()) != key.source_id() =>
                {
                    return Err(QualifiedError::Mismatch("TaskRef source/key"));
                }
                _ => {}
            }
        }
        if key.family() == RecordFamily::Dependency {
            let dependent = references[0].indexes();
            let prerequisite = references[1].indexes();
            if dependent.task_source_id() != key.text(1)
                || dependent.task_id() != key.text(2)
                || prerequisite.task_source_id() != key.text(3)
                || prerequisite.task_id() != key.text(4)
            {
                return Err(QualifiedError::Mismatch("dependency ordered endpoints"));
            }
        }
        if references.len() == 2
            && matches!(
                key.family(),
                RecordFamily::Event | RecordFamily::SourceWriteIntent
            )
            && references[0].indexes().task_id() != references[1].indexes().task_id()
        {
            return Err(QualifiedError::Mismatch("transition task endpoints"));
        }
        if key.family().is_immutable_original() != original.is_some() {
            return Err(QualifiedError::Invalid(
                "original required exactly for immutable family",
            ));
        }
        if original
            .as_ref()
            .is_some_and(|original| original.key() != &key)
        {
            return Err(QualifiedError::Mismatch("original full context/key"));
        }
        let mut record = Self {
            observation_id,
            key,
            references,
            original,
            payload,
            payload_digest,
            canonical_digest: [0; 32],
            canonical_len: 0,
        };
        let encoded = encode_record(&record);
        if encoded.len() > MAX_QUALIFIED_RECORD_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        // The frame and phase have their own bounds. Metadata is separately
        // finite, so adding a new field cannot silently consume their reserve.
        let body_len =
            record.payload.len() + record.original.as_ref().map_or(0, |o| o.binding.len());
        if encoded.len().saturating_sub(body_len) > MAX_QUALIFIED_CHUNK_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        record.canonical_len = encoded.len();
        record.canonical_digest = digest(&encoded);
        Ok(record)
    }
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }
    pub fn key(&self) -> &LogicalKey {
        &self.key
    }
    pub fn logical_key(&self) -> &LogicalKey {
        self.key()
    }
    pub fn family(&self) -> RecordFamily {
        self.key.family()
    }
    pub fn workspace(&self) -> &str {
        self.key.workspace()
    }
    pub fn references(&self) -> &[TaskRefEnvelope] {
        &self.references
    }
    pub fn original(&self) -> Option<&ImmutableOriginal> {
        self.original.as_ref()
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }
    pub fn canonical_digest(&self) -> [u8; 32] {
        self.canonical_digest
    }
    pub fn canonical_len(&self) -> usize {
        self.canonical_len
    }
}

pub(crate) fn encode_record(record: &QualifiedRecord) -> Vec<u8> {
    let mut out = RECORD_DOMAIN.to_vec();
    put_text(&mut out, &record.observation_id);
    put_bytes(&mut out, &record.key.canonical_bytes());
    put_u64(&mut out, record.references.len() as u64);
    for reference in &record.references {
        put_bytes(&mut out, reference.canonical());
        out.extend_from_slice(&reference.digest());
    }
    match &record.original {
        None => out.push(0),
        Some(original) => {
            out.push(1);
            put_bytes(&mut out, &original.key.canonical_bytes());
            put_bytes(&mut out, &original.binding);
            out.extend_from_slice(&original.digest);
        }
    }
    put_bytes(&mut out, &record.payload);
    out.extend_from_slice(&record.payload_digest);
    out
}
pub(crate) fn decode_record(bytes: &[u8]) -> Result<QualifiedRecord> {
    if bytes.len() > MAX_QUALIFIED_RECORD_BYTES {
        return Err(QualifiedError::OversizeHeld);
    }
    let mut d = Decoder::new(bytes);
    if d.take(RECORD_DOMAIN.len())? != RECORD_DOMAIN {
        return Err(QualifiedError::Invalid("record domain"));
    }
    let observation = d.text(MAX_ID)?;
    let key = LogicalKey::from_canonical(d.blob(2048)?)?;
    let count = d.u64()?;
    if count > 2 {
        return Err(QualifiedError::Invalid("TaskRef count"));
    }
    let mut references = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let canonical = d.blob(MAX_TASK_REF_BYTES)?.to_vec();
        let indexed = TaskRefIndexes::decode(&canonical)?;
        let hash = d.hash()?;
        references.push(TaskRefEnvelope::try_new(canonical, hash, indexed)?);
    }
    let original = match d.byte()? {
        0 => None,
        1 => {
            let original_key = LogicalKey::from_canonical(d.blob(2048)?)?;
            let binding = d.blob(MAX_SIGNED_BINDING_BYTES)?.to_vec();
            let hash = d.hash()?;
            Some(ImmutableOriginal::try_new(original_key, binding, hash)?)
        }
        _ => return Err(QualifiedError::NonCanonical),
    };
    let payload = d.blob(MAX_QUALIFIED_PAYLOAD_BYTES)?.to_vec();
    let payload_digest = d.hash()?;
    d.finish()?;
    let record = QualifiedRecord::try_new(
        observation,
        key,
        references,
        original,
        payload,
        payload_digest,
    )?;
    if encode_record(&record) != bytes {
        return Err(QualifiedError::NonCanonical);
    }
    Ok(record)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationBatch {
    records: Vec<QualifiedRecord>,
    encoded_bytes: usize,
}
impl ObservationBatch {
    pub fn try_new(records: Vec<QualifiedRecord>) -> Result<Self> {
        batch(records, true).map(|(records, encoded_bytes)| Self {
            records,
            encoded_bytes,
        })
    }
    pub fn records(&self) -> &[QualifiedRecord] {
        &self.records
    }
    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalJournalMirrorBatch {
    records: Vec<QualifiedRecord>,
    encoded_bytes: usize,
}
impl LocalJournalMirrorBatch {
    pub fn try_new(records: Vec<QualifiedRecord>) -> Result<Self> {
        batch(records, false).map(|(records, encoded_bytes)| Self {
            records,
            encoded_bytes,
        })
    }
    pub fn records(&self) -> &[QualifiedRecord] {
        &self.records
    }
    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}
fn batch(records: Vec<QualifiedRecord>, replicated: bool) -> Result<(Vec<QualifiedRecord>, usize)> {
    if records.len() > MAX_QUALIFIED_BATCH_RECORDS {
        return Err(QualifiedError::OversizeHeld);
    }
    let mut encoded_bytes = 0_usize;
    for record in &records {
        if record.family().is_replicated() != replicated {
            return Err(QualifiedError::Invalid(
                "observation/local journal separation",
            ));
        }
        encoded_bytes = encoded_bytes
            .checked_add(record.canonical_len())
            .ok_or(QualifiedError::OversizeHeld)?;
        if encoded_bytes > MAX_QUALIFIED_BATCH_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
    }
    Ok((records, encoded_bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordHeader {
    family: RecordFamily,
    workspace: String,
    observation_id: String,
    record_digest: [u8; 32],
    total_length: u64,
    part_count: u16,
}
impl RecordHeader {
    pub(crate) fn try_new(
        family: RecordFamily,
        workspace_id: String,
        observation_id: String,
        record_digest: [u8; 32],
        total_length: u64,
        part_count: u16,
    ) -> Result<Self> {
        workspace(&workspace_id)?;
        id(&observation_id)?;
        if total_length == 0 || total_length > MAX_QUALIFIED_RECORD_BYTES as u64 {
            return Err(QualifiedError::OversizeHeld);
        }
        let count = (total_length as usize).div_ceil(MAX_QUALIFIED_CHUNK_BYTES);
        if usize::from(part_count) != count || count > MAX_QUALIFIED_PARTS {
            return Err(QualifiedError::Invalid("part count"));
        }
        Ok(Self {
            family,
            workspace: workspace_id,
            observation_id,
            record_digest,
            total_length,
            part_count,
        })
    }
    pub(crate) fn family(&self) -> RecordFamily {
        self.family
    }
    pub(crate) fn workspace(&self) -> &str {
        &self.workspace
    }
    pub(crate) fn observation_id(&self) -> &str {
        &self.observation_id
    }
    pub(crate) fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
    pub(crate) fn total_length(&self) -> u64 {
        self.total_length
    }
    pub(crate) fn part_count(&self) -> u16 {
        self.part_count
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordChunk {
    ordinal: u16,
    bytes: Vec<u8>,
}
impl RecordChunk {
    pub(crate) fn try_new(ordinal: u16, bytes: Vec<u8>) -> Result<Self> {
        if ordinal as usize >= MAX_QUALIFIED_PARTS
            || bytes.is_empty()
            || bytes.len() > MAX_QUALIFIED_CHUNK_BYTES
        {
            return Err(QualifiedError::Invalid("chunk bound"));
        }
        Ok(Self { ordinal, bytes })
    }
    pub(crate) fn ordinal(&self) -> u16 {
        self.ordinal
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub(crate) fn split_record(record: &QualifiedRecord) -> (RecordHeader, Vec<RecordChunk>) {
    let encoded = encode_record(record);
    // QualifiedRecord's private constructor has already established these
    // bounds; each chunk is a deterministic view of that exact encoding.
    let chunks: Vec<_> = encoded
        .chunks(MAX_QUALIFIED_CHUNK_BYTES)
        .enumerate()
        .map(|(ordinal, bytes)| RecordChunk {
            ordinal: ordinal as u16,
            bytes: bytes.to_vec(),
        })
        .collect();
    let header = RecordHeader {
        family: record.family(),
        workspace: record.workspace().to_owned(),
        observation_id: record.observation_id().to_owned(),
        record_digest: record.canonical_digest(),
        total_length: encoded.len() as u64,
        part_count: chunks.len() as u16,
    };
    (header, chunks)
}
pub(crate) fn assemble_record(
    header: &RecordHeader,
    chunks: &[RecordChunk],
) -> Result<QualifiedRecord> {
    if chunks.len() != usize::from(header.part_count) {
        return Err(QualifiedError::Incomplete);
    }
    let mut encoded = Vec::with_capacity(header.total_length as usize);
    for (ordinal, chunk) in chunks.iter().enumerate() {
        if usize::from(chunk.ordinal) != ordinal {
            return Err(QualifiedError::NonCanonical);
        }
        let expected = (header.total_length as usize - ordinal * MAX_QUALIFIED_CHUNK_BYTES)
            .min(MAX_QUALIFIED_CHUNK_BYTES);
        if chunk.bytes.len() != expected {
            return Err(QualifiedError::Incomplete);
        }
        encoded.extend_from_slice(&chunk.bytes);
    }
    if encoded.len() != header.total_length as usize || digest(&encoded) != header.record_digest {
        return Err(QualifiedError::Mismatch("complete chunk digest/length"));
    }
    let record = decode_record(&encoded)?;
    if record.family() != header.family
        || record.workspace() != header.workspace
        || record.observation_id() != header.observation_id
    {
        return Err(QualifiedError::Mismatch("record/header identity"));
    }
    Ok(record)
}
pub(crate) fn record_variant_key(header: &RecordHeader) -> String {
    let mut bytes = vec![header.family.code()];
    put_text(&mut bytes, &header.workspace);
    put_text(&mut bytes, &header.observation_id);
    bytes.extend_from_slice(&header.record_digest);
    hex(&bytes)
}
pub(crate) fn chunk_key(record_key: &str, ordinal: u16) -> String {
    format!("{record_key}:{ordinal}")
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

const LEGACY_ASSOCIATION_DOMAIN: &[u8] = b"chinwag-inferred-legacy-association-v1\0";
/// Separate inference attached to untouched historical bytes. It can never
/// enter an ObservationBatch or represent a signature by the old sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredLegacyAssociation {
    association_id: String,
    workspace: String,
    legacy_thread_id: String,
    legacy_message_id: String,
    legacy_body_sha: [u8; 32],
    migration_operation: String,
    reference: TaskRefEnvelope,
    pin_payload: Vec<u8>,
    pin_digest: [u8; 32],
}
impl InferredLegacyAssociation {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        association_id: String,
        workspace_id: String,
        legacy_thread_id: String,
        legacy_message_id: String,
        legacy_body_sha: [u8; 32],
        migration_operation: String,
        reference: TaskRefEnvelope,
        pin_payload: Vec<u8>,
        pin_digest: [u8; 32],
    ) -> Result<Self> {
        id(&association_id)?;
        workspace(&workspace_id)?;
        id(&legacy_thread_id)?;
        id(&legacy_message_id)?;
        id(&migration_operation)?;
        if reference.indexes().workspace_id() != workspace_id {
            return Err(QualifiedError::Mismatch("legacy reference workspace"));
        }
        if pin_payload.is_empty() {
            return Err(QualifiedError::Invalid("empty legacy migration pin"));
        }
        if pin_payload.len() > MAX_QUALIFIED_PAYLOAD_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        if digest(&pin_payload) != pin_digest {
            return Err(QualifiedError::Mismatch("legacy migration pin digest"));
        }
        let association = Self {
            association_id,
            workspace: workspace_id,
            legacy_thread_id,
            legacy_message_id,
            legacy_body_sha,
            migration_operation,
            reference,
            pin_payload,
            pin_digest,
        };
        if encode_legacy_association(&association).len() > MAX_QUALIFIED_CHUNK_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        Ok(association)
    }
    pub fn association_id(&self) -> &str {
        &self.association_id
    }
    pub fn workspace(&self) -> &str {
        &self.workspace
    }
    pub fn legacy_thread_id(&self) -> &str {
        &self.legacy_thread_id
    }
    pub fn legacy_message_id(&self) -> &str {
        &self.legacy_message_id
    }
    pub fn legacy_body_sha(&self) -> [u8; 32] {
        self.legacy_body_sha
    }
    pub fn legacy_body_sha256(&self) -> [u8; 32] {
        self.legacy_body_sha
    }
    pub fn migration_operation(&self) -> &str {
        &self.migration_operation
    }
    pub fn reference(&self) -> &TaskRefEnvelope {
        &self.reference
    }
    pub fn pin_payload(&self) -> &[u8] {
        &self.pin_payload
    }
    pub fn pin_digest(&self) -> [u8; 32] {
        self.pin_digest
    }
    pub fn inferred_legacy(&self) -> bool {
        true
    }
    pub fn signed_by_original_sender(&self) -> bool {
        false
    }
    pub fn canonical_digest(&self) -> [u8; 32] {
        digest(&encode_legacy_association(self))
    }
}
pub(crate) fn legacy_association_identity(association: &InferredLegacyAssociation) -> Vec<u8> {
    let mut out = Vec::new();
    put_text(&mut out, association.workspace());
    put_text(&mut out, association.legacy_thread_id());
    put_text(&mut out, association.legacy_message_id());
    put_text(&mut out, association.association_id());
    out
}
pub(crate) fn legacy_association_key(association: &InferredLegacyAssociation) -> String {
    let mut bytes = legacy_association_identity(association);
    bytes.extend_from_slice(&association.canonical_digest());
    hex(&bytes)
}
pub(crate) fn encode_legacy_association(a: &InferredLegacyAssociation) -> Vec<u8> {
    let mut out = LEGACY_ASSOCIATION_DOMAIN.to_vec();
    put_text(&mut out, &a.association_id);
    put_text(&mut out, &a.workspace);
    put_text(&mut out, &a.legacy_thread_id);
    put_text(&mut out, &a.legacy_message_id);
    out.extend_from_slice(&a.legacy_body_sha);
    put_text(&mut out, &a.migration_operation);
    put_bytes(&mut out, a.reference.canonical());
    out.extend_from_slice(&a.reference.digest());
    put_bytes(&mut out, &a.pin_payload);
    out.extend_from_slice(&a.pin_digest);
    out.extend_from_slice(&[1, 0]);
    out
}
pub(crate) fn decode_legacy_association(bytes: &[u8]) -> Result<InferredLegacyAssociation> {
    if bytes.len() > MAX_QUALIFIED_CHUNK_BYTES {
        return Err(QualifiedError::OversizeHeld);
    }
    let mut d = Decoder::new(bytes);
    if d.take(LEGACY_ASSOCIATION_DOMAIN.len())? != LEGACY_ASSOCIATION_DOMAIN {
        return Err(QualifiedError::Invalid("legacy association domain"));
    }
    let association = d.text(MAX_ID)?;
    let workspace = d.text(MAX_ID)?;
    let thread = d.text(MAX_ID)?;
    let message = d.text(MAX_ID)?;
    let body_sha = d.hash()?;
    let operation = d.text(MAX_ID)?;
    let canonical = d.blob(MAX_TASK_REF_BYTES)?.to_vec();
    let hash = d.hash()?;
    let reference =
        TaskRefEnvelope::try_new(canonical.clone(), hash, TaskRefIndexes::decode(&canonical)?)?;
    let pin = d.blob(MAX_QUALIFIED_PAYLOAD_BYTES)?.to_vec();
    let pin_digest = d.hash()?;
    if d.take(2)? != [1, 0] {
        return Err(QualifiedError::Invalid("legacy inference flags"));
    }
    d.finish()?;
    let association = InferredLegacyAssociation::try_new(
        association,
        workspace,
        thread,
        message,
        body_sha,
        operation,
        reference,
        pin,
        pin_digest,
    )?;
    if encode_legacy_association(&association) != bytes {
        return Err(QualifiedError::NonCanonical);
    }
    Ok(association)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyAssociationBatch {
    associations: Vec<InferredLegacyAssociation>,
    encoded_bytes: usize,
}
impl LegacyAssociationBatch {
    pub fn try_new(associations: Vec<InferredLegacyAssociation>) -> Result<Self> {
        if associations.len() > MAX_QUALIFIED_BATCH_RECORDS {
            return Err(QualifiedError::OversizeHeld);
        }
        let encoded_bytes = associations
            .iter()
            .map(|a| encode_legacy_association(a).len())
            .sum::<usize>();
        if encoded_bytes > MAX_QUALIFIED_BATCH_BYTES {
            return Err(QualifiedError::OversizeHeld);
        }
        Ok(Self {
            associations,
            encoded_bytes,
        })
    }
    pub fn associations(&self) -> &[InferredLegacyAssociation] {
        &self.associations
    }
    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

#[cfg(test)]
#[path = "qualified_tests.rs"]
mod tests;
