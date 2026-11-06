//! Canonical Phase 0 task identity, binary primitives, and revision checks.
//!
//! These values describe commitments. Source enrollment, commit resolution, and
//! filesystem identity must still be verified by the authority consuming them.

use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

pub const MAX_ID_UTF8_BYTES: usize = 256;
pub const MAX_CANONICAL_PATH_BYTES: usize = 4096;
pub const MAX_DESCENT_COMPONENTS: usize = 64;
pub const MAX_SCALAR_BYTES: usize = 65536;
pub const MAX_LIST_ITEMS: usize = 256;
pub const MAX_TASK_SOURCES: usize = 16;
pub const MAX_TASKS_PER_SOURCE: usize = 4096;
pub const MAX_DEPENDENCY_EDGES: usize = 16384;
/// Maximum number of edges on any dependency path (a leaf has depth zero).
pub const MAX_DEPENDENCY_DEPTH: usize = 128;
pub const MAX_REV_COUNTER: u64 = i64::MAX as u64;
pub const MAX_UNRELATED_FILE_REBASES: usize = 2;
pub const TASK_REF_V1_DOMAIN: &[u8] = b"chinwag-taskref-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskContractError {
    InvalidField(&'static str),
    LimitExceeded(&'static str),
    RevisionExhausted,
    InvalidHex,
    InvalidDigestType,
    InvalidGitOid,
    InvalidDomain,
    InvalidUtf8,
    UnexpectedEnd,
    TrailingBytes,
    InvalidOptionTag,
    DuplicateSetItem,
    InvalidSetOrder,
    DuplicateField(&'static str),
    UnknownField(String),
    MissingField(&'static str),
    AmbiguousField(&'static str),
    BareCarriageReturn,
    ContradictoryControls,
    IdentityConflict,
    TaskStatusConflict,
    AcceptanceInvalidated,
    FileRevisionConflict,
    RebaseLimitExceeded,
    DuplicateDependency,
    SelfDependency,
    CrossWorkspaceDependency,
    CrossRepositoryDependency,
    DependencyUnsatisfied,
    DependencyTargetMissing,
    DependencyCycleDetected,
    DependencyDepthExceeded,
}

impl fmt::Display for TaskContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task contract rejected: {self:?}")
    }
}

impl std::error::Error for TaskContractError {}

pub fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn encode_checked_rev(revision: u64) -> Result<[u8; 8], TaskContractError> {
    if revision > MAX_REV_COUNTER {
        return Err(TaskContractError::RevisionExhausted);
    }
    Ok(encode_u64(revision))
}

pub fn checked_next_revision(revision: u64) -> Result<u64, TaskContractError> {
    encode_checked_rev(revision)?;
    revision
        .checked_add(1)
        .filter(|next| *next <= MAX_REV_COUNTER)
        .ok_or(TaskContractError::RevisionExhausted)
}

pub fn encode_bytes_field(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(8 + bytes.len());
    encoded.extend_from_slice(&encode_u64(bytes.len() as u64));
    encoded.extend_from_slice(bytes);
    encoded
}

pub fn encode_str_field(value: &str) -> Vec<u8> {
    encode_bytes_field(value.as_bytes())
}

pub fn encode_opt<T: ?Sized>(
    value: Option<&T>,
    encode_inner: impl FnOnce(&T) -> Vec<u8>,
) -> Vec<u8> {
    match value {
        None => vec![0],
        Some(value) => {
            let mut encoded = vec![1];
            encoded.extend(encode_inner(value));
            encoded
        }
    }
}

pub fn encode_list<T>(
    items: &[T],
    encode_item: impl Fn(&T) -> Vec<u8>,
) -> Result<Vec<u8>, TaskContractError> {
    if items.len() > MAX_LIST_ITEMS {
        return Err(TaskContractError::LimitExceeded("list items"));
    }
    let mut encoded = encode_u64(items.len() as u64).to_vec();
    for item in items {
        encoded.extend(encode_item(item));
    }
    Ok(encoded)
}

pub fn encode_sorted_distinct_set(
    mut encoded_items: Vec<Vec<u8>>,
) -> Result<Vec<u8>, TaskContractError> {
    if encoded_items.len() > MAX_LIST_ITEMS {
        return Err(TaskContractError::LimitExceeded("set items"));
    }
    encoded_items.sort();
    if encoded_items.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(TaskContractError::DuplicateSetItem);
    }
    encode_list(&encoded_items, Clone::clone)
}

/// A content commitment; deliberately distinct from a Git object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    pub fn from_hex(value: &str) -> Result<Self, TaskContractError> {
        Ok(Self(parse_hex(value)?))
    }

    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn encode_typed(&self) -> Vec<u8> {
        let mut encoded = encode_str_field("sha256");
        encoded.extend(encode_bytes_field(&self.0));
        encoded
    }
}

impl FromStr for Sha256Digest {
    type Err = TaskContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitOid {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl GitOid {
    pub fn from_hex(value: &str) -> Result<Self, TaskContractError> {
        match value.len() {
            40 => Ok(Self::Sha1(parse_hex(value)?)),
            64 => Ok(Self::Sha256(parse_hex(value)?)),
            _ => Err(TaskContractError::InvalidGitOid),
        }
    }

    pub fn encode_typed(&self) -> Vec<u8> {
        let (algorithm, raw): (&str, &[u8]) = match self {
            Self::Sha1(raw) => ("git-sha1", raw),
            Self::Sha256(raw) => ("git-sha256", raw),
        };
        let mut encoded = encode_str_field(algorithm);
        encoded.extend(encode_bytes_field(raw));
        encoded
    }
}

impl FromStr for GitOid {
    type Err = TaskContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl fmt::Display for GitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: &[u8] = match self {
            Self::Sha1(raw) => raw,
            Self::Sha256(raw) => raw,
        };
        for byte in bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], TaskContractError> {
    if value.len() != N * 2 {
        return Err(TaskContractError::InvalidHex);
    }
    let mut raw = [0; N];
    for (output, pair) in raw.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(TaskContractError::InvalidHex),
        };
        *output = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(raw)
}

pub fn validate_id(value: &str, field: &'static str) -> Result<(), TaskContractError> {
    if value.len() > MAX_ID_UTF8_BYTES {
        return Err(TaskContractError::LimitExceeded(field));
    }
    if value.is_empty() || value.trim() != value || value.contains(['\0', '\r', '\n']) {
        return Err(TaskContractError::InvalidField(field));
    }
    Ok(())
}

/// An opaque bounded identifier: 1..=256 UTF-8 bytes, no whitespace or control
/// characters, no filesystem path separators '/' or '\\', no leading '~', and
/// neither "." nor "..". Enrollment authority is enforced by
/// `DependencySourceBinding` / `WorkspaceTaskPolicy`.
pub fn validate_workspace_id(value: &str) -> Result<(), TaskContractError> {
    validate_id(value, "workspace_id")?;
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
        || value == "."
        || value == ".."
        || value.starts_with('~')
        || value.contains(['/', '\\'])
    {
        return Err(TaskContractError::InvalidField("workspace_id"));
    }
    Ok(())
}

pub fn validate_task_source_id(value: &str) -> Result<(), TaskContractError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(TaskContractError::InvalidField("task_source_id"));
    }
    Ok(())
}

pub fn validate_canonical_task_path(value: &str) -> Result<(), TaskContractError> {
    if value.len() > MAX_CANONICAL_PATH_BYTES {
        return Err(TaskContractError::LimitExceeded("canonical_task_path"));
    }
    if value.is_empty()
        || value.starts_with('/')
        || value
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b'\\'))
    {
        return Err(TaskContractError::InvalidField("canonical_task_path"));
    }
    if value.split('/').count() > MAX_DESCENT_COMPONENTS {
        return Err(TaskContractError::LimitExceeded("canonical_task_path"));
    }
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(TaskContractError::InvalidField("canonical_task_path"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskKey {
    pub workspace_id: String,
    pub task_source_id: String,
    pub task_id: String,
}

impl TaskKey {
    pub fn new(
        workspace_id: impl Into<String>,
        task_source_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Result<Self, TaskContractError> {
        let key = Self {
            workspace_id: workspace_id.into(),
            task_source_id: task_source_id.into(),
            task_id: task_id.into(),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn validate(&self) -> Result<(), TaskContractError> {
        validate_workspace_id(&self.workspace_id)?;
        validate_task_source_id(&self.task_source_id)?;
        validate_id(&self.task_id, "task_id")
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = encode_str_field(&self.workspace_id);
        encoded.extend(encode_str_field(&self.task_source_id));
        encoded.extend(encode_str_field(&self.task_id));
        encoded
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TaskContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let key = decoder.task_key()?;
        decoder.finish()?;
        Ok(key)
    }
}

impl Ord for TaskKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.encode().cmp(&other.encode())
    }
}

impl PartialOrd for TaskKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for TaskKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}

/// A borrowed decoder checks lengths before copying or allocating field storage.
pub struct CanonicalDecoder<'a> {
    remaining: &'a [u8],
}

impl<'a> CanonicalDecoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], TaskContractError> {
        if count > self.remaining.len() {
            return Err(TaskContractError::UnexpectedEnd);
        }
        let (value, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        Ok(value)
    }

    pub fn u64(&mut self) -> Result<u64, TaskContractError> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(raw))
    }

    pub fn revision(&mut self) -> Result<u64, TaskContractError> {
        let value = self.u64()?;
        encode_checked_rev(value)?;
        Ok(value)
    }

    pub fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], TaskContractError> {
        let count = self.u64()?;
        if count > maximum as u64 {
            return Err(TaskContractError::LimitExceeded("encoded field"));
        }
        let count = usize::try_from(count)
            .map_err(|_| TaskContractError::LimitExceeded("encoded field"))?;
        self.take(count)
    }

    pub fn string(&mut self, maximum: usize) -> Result<String, TaskContractError> {
        let value = std::str::from_utf8(self.bytes(maximum)?)
            .map_err(|_| TaskContractError::InvalidUtf8)?;
        Ok(value.to_owned())
    }

    pub fn optional<T>(
        &mut self,
        decode_inner: impl FnOnce(&mut Self) -> Result<T, TaskContractError>,
    ) -> Result<Option<T>, TaskContractError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(decode_inner(self)?)),
            _ => Err(TaskContractError::InvalidOptionTag),
        }
    }

    pub fn list<T>(
        &mut self,
        mut decode_item: impl FnMut(&mut Self) -> Result<T, TaskContractError>,
    ) -> Result<Vec<T>, TaskContractError> {
        let count = self.u64()?;
        if count > MAX_LIST_ITEMS as u64 {
            return Err(TaskContractError::LimitExceeded("list items"));
        }
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(decode_item(self)?);
        }
        Ok(items)
    }

    pub fn sha256_digest(&mut self) -> Result<Sha256Digest, TaskContractError> {
        if self.bytes(6)? != b"sha256" {
            return Err(TaskContractError::InvalidDigestType);
        }
        let bytes = self.bytes(32)?;
        let raw = bytes
            .try_into()
            .map_err(|_| TaskContractError::InvalidDigestType)?;
        Ok(Sha256Digest(raw))
    }

    /// Checks the bytes received, rather than repairing a noncanonical set.
    pub fn sorted_distinct_set<T>(
        &mut self,
        mut decode_item: impl FnMut(&mut Self) -> Result<T, TaskContractError>,
    ) -> Result<Vec<T>, TaskContractError> {
        let count = self.u64()?;
        if count > MAX_LIST_ITEMS as u64 {
            return Err(TaskContractError::LimitExceeded("set items"));
        }
        let mut items = Vec::new();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..count {
            let before = self.remaining;
            let item = decode_item(self)?;
            let encoded = &before[..before.len() - self.remaining.len()];
            if let Some(previous) = previous {
                match previous.cmp(encoded) {
                    Ordering::Equal => return Err(TaskContractError::DuplicateSetItem),
                    Ordering::Greater => return Err(TaskContractError::InvalidSetOrder),
                    Ordering::Less => {}
                }
            }
            previous = Some(encoded);
            items.push(item);
        }
        Ok(items)
    }

    pub fn git_oid(&mut self) -> Result<GitOid, TaskContractError> {
        let algorithm = self.bytes(10)?;
        let raw = self.bytes(32)?;
        match algorithm {
            b"git-sha1" => Ok(GitOid::Sha1(
                raw.try_into()
                    .map_err(|_| TaskContractError::InvalidGitOid)?,
            )),
            b"git-sha256" => Ok(GitOid::Sha256(
                raw.try_into()
                    .map_err(|_| TaskContractError::InvalidGitOid)?,
            )),
            _ => Err(TaskContractError::InvalidGitOid),
        }
    }

    pub fn task_key(&mut self) -> Result<TaskKey, TaskContractError> {
        TaskKey::new(
            self.string(MAX_ID_UTF8_BYTES)?,
            self.string(MAX_ID_UTF8_BYTES)?,
            self.string(MAX_ID_UTF8_BYTES)?,
        )
    }

    pub fn finish(self) -> Result<(), TaskContractError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(TaskContractError::TrailingBytes)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRefV1 {
    pub workspace_id: String,
    pub repo_id: String,
    pub task_source_id: String,
    pub source_generation: u64,
    pub canonical_task_path: String,
    pub task_id: String,
    pub task_spec_digest: Sha256Digest,
    pub task_status_rev: u64,
    pub file_cas_rev: u64,
    pub baseline_commit: GitOid,
}

impl TaskRefV1 {
    pub fn task_key(&self) -> TaskKey {
        TaskKey {
            workspace_id: self.workspace_id.clone(),
            task_source_id: self.task_source_id.clone(),
            task_id: self.task_id.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), TaskContractError> {
        self.task_key().validate()?;
        validate_id(&self.repo_id, "repo_id")?;
        validate_canonical_task_path(&self.canonical_task_path)?;
        // The frozen profile permits all nonnegative storage-range revisions.
        encode_checked_rev(self.source_generation)?;
        encode_checked_rev(self.task_status_rev)?;
        encode_checked_rev(self.file_cas_rev)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TaskContractError> {
        self.validate()?;
        let mut encoded = TASK_REF_V1_DOMAIN.to_vec();
        encoded.extend(encode_str_field(&self.workspace_id));
        encoded.extend(encode_str_field(&self.repo_id));
        encoded.extend(encode_str_field(&self.task_source_id));
        encoded.extend(encode_checked_rev(self.source_generation)?);
        encoded.extend(encode_str_field(&self.canonical_task_path));
        encoded.extend(encode_str_field(&self.task_id));
        encoded.extend(self.task_spec_digest.encode_typed());
        encoded.extend(encode_checked_rev(self.task_status_rev)?);
        encoded.extend(encode_checked_rev(self.file_cas_rev)?);
        encoded.extend(self.baseline_commit.encode_typed());
        Ok(encoded)
    }

    pub fn task_ref_digest(&self) -> Result<Sha256Digest, TaskContractError> {
        Ok(Sha256Digest::of(&self.encode()?))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TaskContractError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        if decoder.take(TASK_REF_V1_DOMAIN.len())? != TASK_REF_V1_DOMAIN {
            return Err(TaskContractError::InvalidDomain);
        }
        let value = Self {
            workspace_id: decoder.string(MAX_ID_UTF8_BYTES)?,
            repo_id: decoder.string(MAX_ID_UTF8_BYTES)?,
            task_source_id: decoder.string(MAX_ID_UTF8_BYTES)?,
            source_generation: decoder.revision()?,
            canonical_task_path: decoder.string(MAX_CANONICAL_PATH_BYTES)?,
            task_id: decoder.string(MAX_ID_UTF8_BYTES)?,
            task_spec_digest: decoder.sha256_digest()?,
            task_status_rev: decoder.revision()?,
            file_cas_rev: decoder.revision()?,
            baseline_commit: decoder.git_oid()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasEligibility {
    Exact,
    UnrelatedFileRebase,
}

/// Checks the TaskRef portion of CAS. The caller must also pin unchanged control,
/// candidate, overlay, and review-policy commitments on every comparison.
pub fn check_cas_eligibility(
    admitted: &TaskRefV1,
    current: &TaskRefV1,
    unrelated_rebases_used: usize,
) -> Result<CasEligibility, TaskContractError> {
    admitted.validate()?;
    current.validate()?;
    if admitted.task_key() != current.task_key() || admitted.repo_id != current.repo_id {
        return Err(TaskContractError::IdentityConflict);
    }
    if admitted.task_spec_digest != current.task_spec_digest
        || admitted.source_generation != current.source_generation
        || admitted.canonical_task_path != current.canonical_task_path
        || admitted.baseline_commit != current.baseline_commit
    {
        return Err(TaskContractError::AcceptanceInvalidated);
    }
    if admitted.task_status_rev != current.task_status_rev {
        return Err(TaskContractError::TaskStatusConflict);
    }
    if current.file_cas_rev < admitted.file_cas_rev {
        return Err(TaskContractError::FileRevisionConflict);
    }
    if unrelated_rebases_used > MAX_UNRELATED_FILE_REBASES {
        return Err(TaskContractError::RebaseLimitExceeded);
    }
    if current.file_cas_rev == admitted.file_cas_rev {
        return Ok(CasEligibility::Exact);
    }
    if unrelated_rebases_used == MAX_UNRELATED_FILE_REBASES {
        return Err(TaskContractError::RebaseLimitExceeded);
    }
    Ok(CasEligibility::UnrelatedFileRebase)
}

/// Produces counters for an authorized transition; this does not authorize a write.
pub fn advance_task_revision(
    current: &TaskRefV1,
    status_changed: bool,
) -> Result<TaskRefV1, TaskContractError> {
    current.validate()?;
    let mut next = current.clone();
    next.file_cas_rev = checked_next_revision(current.file_cas_rev)?;
    if status_changed {
        next.task_status_rev = checked_next_revision(current.task_status_rev)?;
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn fixture() -> TaskRefV1 {
        TaskRefV1 {
            workspace_id: "p0-fixture-workspace".into(),
            repo_id: "p0-fixture-repo".into(),
            task_source_id: "00000000000000000000000000000001".into(),
            source_generation: 1,
            canonical_task_path: "TASKS.md".into(),
            task_id: "P0-FIXTURE-1".into(),
            task_spec_digest: Sha256Digest([0; 32]),
            task_status_rev: 0,
            file_cas_rev: 0,
            baseline_commit: GitOid::from_hex("c4f8395af729fd7aecf5365f6a4b261a824d83ce").unwrap(),
        }
    }

    #[test]
    fn p0_contract_u64_b_o_l_primitive_vectors() {
        assert_eq!(hex(&encode_u64(0)), "0000000000000000");
        assert_eq!(hex(&encode_u64(1)), "0000000000000001");
        assert_eq!(hex(&encode_str_field("é")), "0000000000000002c3a9");
        assert_eq!(
            hex(&encode_str_field("e\u{0301}")),
            "000000000000000365cc81"
        );
        assert_eq!(hex(&encode_opt::<str>(None, encode_str_field)), "00");
        assert_eq!(
            hex(&encode_opt(Some("x"), encode_str_field)),
            "01000000000000000178"
        );
        assert_eq!(
            hex(&encode_list(&["a", "b"], |s| encode_str_field(s)).unwrap()),
            "0000000000000002000000000000000161000000000000000162"
        );
    }

    #[test]
    fn p0_contract_task_ref_v1_golden_vector_268b() {
        let reference = fixture();
        let encoded = reference.encode().unwrap();
        assert_eq!(encoded.len(), 268);
        assert_eq!(
            hex(&encoded),
            concat!(
                "6368696e7761672d7461736b7265662d763100",
                "000000000000001470302d666978747572652d776f726b7370616365",
                "000000000000000f70302d666978747572652d7265706f",
                "00000000000000203030303030303030303030303030303030303030303030303030303030303031",
                "000000000000000100000000000000085441534b532e6d64",
                "000000000000000c50302d464958545552452d31",
                "00000000000000067368613235360000000000000020",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
                "00000000000000086769742d736861310000000000000014",
                "c4f8395af729fd7aecf5365f6a4b261a824d83ce"
            )
        );
        assert_eq!(
            reference.task_ref_digest().unwrap().to_string(),
            "ac2421645d450eebef30a65a069427ecf86a32952faa647fa29babe9cdcef997"
        );
    }

    #[test]
    fn p0_contract_task_ref_roundtrip_and_trailing_bytes_rejected() {
        let reference = fixture();
        let mut encoded = reference.encode().unwrap();
        assert_eq!(TaskRefV1::decode(&encoded).unwrap(), reference);
        for length in 0..encoded.len() {
            assert!(TaskRefV1::decode(&encoded[..length]).is_err());
        }
        encoded.push(0);
        assert_eq!(
            TaskRefV1::decode(&encoded),
            Err(TaskContractError::TrailingBytes)
        );
        encoded[0] ^= 1;
        assert_eq!(
            TaskRefV1::decode(&encoded),
            Err(TaskContractError::InvalidDomain)
        );
    }

    #[test]
    fn p0_contract_decoder_rejects_huge_lengths_invalid_utf8_and_tags() {
        let huge = u64::MAX.to_be_bytes();
        assert!(matches!(
            CanonicalDecoder::new(&huge).bytes(256),
            Err(TaskContractError::LimitExceeded(_))
        ));
        assert!(matches!(
            CanonicalDecoder::new(&huge).list(|d| d.u64()),
            Err(TaskContractError::LimitExceeded(_))
        ));
        let invalid = encode_bytes_field(&[0xff]);
        assert_eq!(
            CanonicalDecoder::new(&invalid).string(256),
            Err(TaskContractError::InvalidUtf8)
        );
        assert_eq!(
            CanonicalDecoder::new(&[2]).optional(|d| d.u64()),
            Err(TaskContractError::InvalidOptionTag)
        );
    }

    #[test]
    fn p0_contract_primitive_decoder_roundtrips_option_and_list() {
        let absent = encode_opt::<str>(None, encode_str_field);
        let present = encode_opt(Some("x"), encode_str_field);
        assert_eq!(
            CanonicalDecoder::new(&absent)
                .optional(|d| d.string(256))
                .unwrap(),
            None
        );
        assert_eq!(
            CanonicalDecoder::new(&present)
                .optional(|d| d.string(256))
                .unwrap(),
            Some("x".into())
        );
        let list = encode_list(&["a", "é"], |s| encode_str_field(s)).unwrap();
        let mut decoder = CanonicalDecoder::new(&list);
        assert_eq!(decoder.list(|d| d.string(256)).unwrap(), vec!["a", "é"]);
        decoder.finish().unwrap();
    }

    #[test]
    fn p0_contract_typed_sha256_and_git_oid_distinctness() {
        let hex_digest = "Ab".repeat(32);
        let digest = Sha256Digest::from_hex(&hex_digest).unwrap();
        assert_eq!(digest.to_string(), "ab".repeat(32));
        assert_eq!(
            CanonicalDecoder::new(&digest.encode_typed())
                .sha256_digest()
                .unwrap(),
            digest
        );
        for oid in [GitOid::Sha1([7; 20]), GitOid::Sha256([7; 32])] {
            let encoded = oid.encode_typed();
            assert_eq!(CanonicalDecoder::new(&encoded).git_oid().unwrap(), oid);
            assert!(CanonicalDecoder::new(&encoded).sha256_digest().is_err());
        }
        assert!(
            CanonicalDecoder::new(&digest.encode_typed())
                .git_oid()
                .is_err()
        );
        for bad in ["", "abc", &"z".repeat(64), &"0".repeat(63)] {
            assert!(Sha256Digest::from_hex(bad).is_err());
            assert!(GitOid::from_hex(bad).is_err());
        }
    }

    #[test]
    fn p0_contract_typed_encodings_reject_wrong_lengths_and_algorithms() {
        let mut wrong_length = encode_str_field("sha256");
        wrong_length.extend(encode_bytes_field(&[0; 31]));
        assert!(
            CanonicalDecoder::new(&wrong_length)
                .sha256_digest()
                .is_err()
        );
        let mut unknown = encode_str_field("git-md5");
        unknown.extend(encode_bytes_field(&[0; 20]));
        assert!(CanonicalDecoder::new(&unknown).git_oid().is_err());
        let mut wrong_git = encode_str_field("git-sha1");
        wrong_git.extend(encode_bytes_field(&[0; 32]));
        assert!(CanonicalDecoder::new(&wrong_git).git_oid().is_err());
    }

    #[test]
    fn p0_contract_revision_counter_i64_max_exhaustion_held() {
        assert!(encode_checked_rev(MAX_REV_COUNTER).is_ok());
        assert_eq!(
            checked_next_revision(MAX_REV_COUNTER - 1).unwrap(),
            MAX_REV_COUNTER
        );
        assert_eq!(
            checked_next_revision(MAX_REV_COUNTER),
            Err(TaskContractError::RevisionExhausted)
        );
        assert_eq!(
            encode_checked_rev(MAX_REV_COUNTER + 1),
            Err(TaskContractError::RevisionExhausted)
        );
        for field in 0..3 {
            let mut reference = fixture();
            match field {
                0 => reference.source_generation = MAX_REV_COUNTER + 1,
                1 => reference.task_status_rev = MAX_REV_COUNTER + 1,
                _ => reference.file_cas_rev = MAX_REV_COUNTER + 1,
            }
            assert_eq!(
                reference.encode(),
                Err(TaskContractError::RevisionExhausted)
            );
        }
        let mut reference = fixture();
        reference.task_status_rev = MAX_REV_COUNTER;
        assert_eq!(
            advance_task_revision(&reference, true),
            Err(TaskContractError::RevisionExhausted)
        );
        reference.file_cas_rev = MAX_REV_COUNTER;
        assert_eq!(
            advance_task_revision(&reference, false),
            Err(TaskContractError::RevisionExhausted)
        );
    }

    #[test]
    fn p0_contract_task_key_order_hash_and_exact_bytes() {
        let mut short = fixture().task_key();
        short.task_id = "z".into();
        let mut long = short.clone();
        long.task_id = "aa".into();
        assert!(short < long); // Encoded length precedes UTF-8 bytes.
        assert_eq!(short.cmp(&long), short.encode().cmp(&long.encode()));
        let mut a = DefaultHasher::new();
        let mut b = DefaultHasher::new();
        short.hash(&mut a);
        short.clone().hash(&mut b);
        assert_eq!(a.finish(), b.finish());
        assert_eq!(TaskKey::decode(&short.encode()).unwrap(), short);
        let mut lower = short.clone();
        lower.task_id = "Z".into();
        assert_ne!(short, lower);
    }

    #[test]
    fn p0_contract_identity_and_path_bounds_preserve_case_unicode() {
        assert!(validate_id(&"é".repeat(128), "task_id").is_ok());
        assert!(validate_id(&"é".repeat(129), "task_id").is_err());
        for bad in ["", " task", "task\t", "task\r\n", "ta\0sk"] {
            assert!(validate_id(bad, "task_id").is_err());
        }
        for bad in [
            "",
            "/abs",
            "a//b",
            "./TASKS.md",
            "../TASKS.md",
            "a/../b",
            "a/./b",
            "a\\b",
            "a\rb",
            "a\nb",
            "a\0b",
        ] {
            assert_eq!(
                validate_canonical_task_path(bad),
                Err(TaskContractError::InvalidField("canonical_task_path"))
            );
        }
        assert!(validate_canonical_task_path(&"a".repeat(MAX_CANONICAL_PATH_BYTES)).is_ok());
        assert!(validate_canonical_task_path(&"a".repeat(MAX_CANONICAL_PATH_BYTES + 1)).is_err());
        assert_ne!(encode_str_field("TASKS.md"), encode_str_field("tasks.md"));
        assert_ne!(encode_str_field("é"), encode_str_field("e\u{301}"));
        assert!(validate_task_source_id("0000000000000000000000000000000A").is_err());
        assert!(validate_task_source_id("1").is_err());
    }

    #[test]
    fn p0_contract_workspace_id_opaque_bounded_and_enrollment_external() {
        for valid in [
            "workspace.v1",
            "urn:workspace:fixture",
            "workspace@fixture",
            "localhost",
        ] {
            assert_eq!(validate_workspace_id(valid), Ok(()));
            let mut reference = fixture();
            reference.workspace_id = valid.into();
            assert_eq!(
                TaskRefV1::decode(&reference.encode().unwrap()).unwrap(),
                reference
            );
        }
        for bad in [
            "",
            ".",
            "..",
            "~/ws",
            "a/b",
            "a\\b",
            "ws with space",
            "ws\tname",
            "ws\u{00a0}name",
            "ws\u{001b}name",
        ] {
            assert_eq!(
                validate_workspace_id(bad),
                Err(TaskContractError::InvalidField("workspace_id"))
            );
        }
        assert_eq!(validate_workspace_id(&"é".repeat(128)), Ok(()));
        assert_eq!(
            validate_workspace_id(&"é".repeat(129)),
            Err(TaskContractError::LimitExceeded("workspace_id"))
        );
    }

    #[test]
    fn p0_contract_canonical_task_path_preserves_exact_utf8_and_bounds_descent() {
        for path in [" Tasks/é.tasks.md ", "stream:v1/TASKS.md"] {
            let mut reference = fixture();
            reference.canonical_task_path = path.into();
            assert_eq!(reference.validate(), Ok(()));
            let decoded = TaskRefV1::decode(&reference.encode().unwrap()).unwrap();
            assert_eq!(decoded.canonical_task_path.as_bytes(), path.as_bytes());
            assert_eq!(decoded, reference);
        }
        let exact = format!("{}TASKS.md", "a/".repeat(MAX_DESCENT_COMPONENTS - 1));
        assert_eq!(validate_canonical_task_path(&exact), Ok(()));
        let too_deep = format!("a/{exact}");
        assert_eq!(
            validate_canonical_task_path(&too_deep),
            Err(TaskContractError::LimitExceeded("canonical_task_path"))
        );
    }

    #[test]
    fn p0_contract_sorted_sets_reject_duplicates_and_bound_lists() {
        let a = encode_str_field("a");
        let b = encode_str_field("b");
        assert_eq!(
            encode_sorted_distinct_set(vec![b.clone(), a.clone()]).unwrap(),
            encode_list(&[a.clone(), b], Clone::clone).unwrap()
        );
        assert_eq!(
            encode_sorted_distinct_set(vec![a.clone(), a]),
            Err(TaskContractError::DuplicateSetItem)
        );
        assert!(encode_list(&vec![0; MAX_LIST_ITEMS + 1], |_| vec![]).is_err());
        assert!(encode_sorted_distinct_set(vec![vec![]; MAX_LIST_ITEMS + 1]).is_err());
        assert!(encode_list(&vec![0; MAX_LIST_ITEMS], |_| vec![0]).is_ok());
    }

    #[test]
    fn p0_contract_set_decoder_rejects_unsorted_and_duplicate_bytes() {
        let canonical = encode_list(&["a", "b"], |s| encode_str_field(s)).unwrap();
        assert_eq!(
            CanonicalDecoder::new(&canonical)
                .sorted_distinct_set(|d| d.string(256))
                .unwrap(),
            vec!["a", "b"]
        );
        let unsorted = encode_list(&["b", "a"], |s| encode_str_field(s)).unwrap();
        assert_eq!(
            CanonicalDecoder::new(&unsorted).sorted_distinct_set(|d| d.string(256)),
            Err(TaskContractError::InvalidSetOrder)
        );
        let duplicate = encode_list(&["a", "a"], |s| encode_str_field(s)).unwrap();
        assert_eq!(
            CanonicalDecoder::new(&duplicate).sorted_distinct_set(|d| d.string(256)),
            Err(TaskContractError::DuplicateSetItem)
        );
    }

    #[test]
    fn p0_contract_task_ref_decoder_checks_revisions_and_sha256_git_oid() {
        let mut reference = fixture();
        reference.baseline_commit = GitOid::Sha256([0x55; 32]);
        reference.source_generation = 0;
        reference.task_status_rev = MAX_REV_COUNTER;
        reference.file_cas_rev = MAX_REV_COUNTER;
        assert_eq!(
            TaskRefV1::decode(&reference.encode().unwrap()).unwrap(),
            reference
        );
        let mut bytes = reference.encode().unwrap();
        let generation_offset = TASK_REF_V1_DOMAIN.len()
            + encode_str_field(&reference.workspace_id).len()
            + encode_str_field(&reference.repo_id).len()
            + encode_str_field(&reference.task_source_id).len();
        bytes[generation_offset..generation_offset + 8]
            .copy_from_slice(&(MAX_REV_COUNTER + 1).to_be_bytes());
        assert_eq!(
            TaskRefV1::decode(&bytes),
            Err(TaskContractError::RevisionExhausted)
        );
    }

    #[test]
    fn p0_contract_unrelated_file_rebase_bounded_and_status_conflicts() {
        let admitted = fixture();
        assert_eq!(
            check_cas_eligibility(&admitted, &admitted, 0).unwrap(),
            CasEligibility::Exact
        );
        let unrelated = advance_task_revision(&admitted, false).unwrap();
        assert_eq!(unrelated.task_status_rev, admitted.task_status_rev);
        for used in 0..MAX_UNRELATED_FILE_REBASES {
            assert_eq!(
                check_cas_eligibility(&admitted, &unrelated, used).unwrap(),
                CasEligibility::UnrelatedFileRebase
            );
        }
        assert_eq!(
            check_cas_eligibility(&admitted, &unrelated, 2),
            Err(TaskContractError::RebaseLimitExceeded)
        );
        let changed = advance_task_revision(&admitted, true).unwrap();
        assert_eq!(changed.file_cas_rev, 1);
        assert_eq!(changed.task_status_rev, 1);
        assert_eq!(
            check_cas_eligibility(&admitted, &changed, 0),
            Err(TaskContractError::TaskStatusConflict)
        );
        assert_eq!(
            check_cas_eligibility(&unrelated, &admitted, 0),
            Err(TaskContractError::FileRevisionConflict)
        );
    }

    #[test]
    fn p0_contract_spec_source_baseline_and_identity_invalidate_acceptance() {
        let admitted = fixture();
        for field in 0..4 {
            let mut changed = admitted.clone();
            match field {
                0 => changed.task_spec_digest = Sha256Digest([1; 32]),
                1 => changed.source_generation += 1,
                2 => changed.baseline_commit = GitOid::Sha1([1; 20]),
                _ => changed.canonical_task_path = "tasks/TASKS.md".into(),
            }
            assert_eq!(
                check_cas_eligibility(&admitted, &changed, 0),
                Err(TaskContractError::AcceptanceInvalidated)
            );
        }
        let mut changed = admitted.clone();
        changed.task_id = "another-task".into();
        assert_eq!(
            check_cas_eligibility(&admitted, &changed, 0),
            Err(TaskContractError::IdentityConflict)
        );
    }
}
