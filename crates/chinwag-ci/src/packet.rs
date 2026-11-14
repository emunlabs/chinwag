// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Canonical unsigned `ReviewPacketV2` (`chinwag.review-packet.v2`) and
//! `SealedWakeCardPayloadV1` (`chinwag.sealed-wake-card.v1`) wire contract
//! (`INV-SINGLE-CWCARD-SCHEMA-01`, `design-v2` §§4.1–4.4, §5.1, and
//! `return-envelope-acu-contract-v1.2` §4.5).
//!
//! No parallel `.cwcard` schema is permitted anywhere in `chinwag-ci`.
//! Every type here represents untrusted or caller-supplied data/bindings and
//! never confers workload identity, execution authority, merge permission,
//! or gate waiver.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Largest supported integer in the restricted RFC 8785 JCS data model (`2^53 - 1`).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Maximum tokens permitted in a `ReviewPacketV2` `failure_header` (`design-v2` §4.4.4).
pub const MAX_FAILURE_HEADER_TOKENS: u64 = 400;

/// Maximum UTF-8 bytes permitted in a `ReviewPacketV2` `failure_header` (`design-v2` §4.4.4).
pub const MAX_FAILURE_HEADER_BYTES: usize = 1_600;

/// `COMPACT` finalized-wire token ceiling (`design-v2` §5.1).
pub const COMPACT_MAX_TOKENS: u64 = 4_000;
/// `COMPACT` finalized-wire byte ceiling (`design-v2` §5.1).
pub const COMPACT_MAX_BYTES: u64 = 16_384;

/// `STANDARD` finalized-wire token ceiling (`design-v2` §5.1).
pub const STANDARD_MAX_TOKENS: u64 = 16_000;
/// `STANDARD` finalized-wire byte ceiling (`design-v2` §5.1).
pub const STANDARD_MAX_BYTES: u64 = 65_536;

/// Mandatory policy/framing overhead token ceiling (`design-v2` §5.1).
pub const MANDATORY_OVERHEAD_MAX_TOKENS: u64 = 8_000;
/// Mandatory policy/framing overhead byte ceiling (`design-v2` §5.1).
pub const MANDATORY_OVERHEAD_MAX_BYTES: u64 = 32_768;

/// Guaranteed candidate content token floor (`design-v2` §5.1).
pub const CANDIDATE_GUARANTEED_TOKENS: u64 = 8_000;
/// Guaranteed candidate content byte floor (`design-v2` §5.1).
pub const CANDIDATE_GUARANTEED_BYTES: u64 = 32_768;

/// Packet validation or canonicalization error.
#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("invalid supported JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("missing required suite: {0}")]
    MissingSuite(String),
    #[error("external facts are unverified; offline binding is not authority")]
    ExternalVerificationRequired,
}

pub type PacketResult<T> = Result<T, PacketError>;

pub(crate) fn nonempty(value: &str) -> PacketResult<()> {
    if value.is_empty() {
        return Err(PacketError::Invalid("empty identifier"));
    }
    Ok(())
}

/// SHA-256 of exact bytes (64 lowercase ASCII hex characters).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let text = String::deserialize(decoder)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

impl Sha256Digest {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn parse(value: &str) -> PacketResult<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PacketError::Invalid(
                "SHA-256 must be 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lossless encoding of supplied artifact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Utf8,
    Base64,
}

/// Exact original bytes, byte length, and computed SHA-256.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    encoding: Encoding,
    raw_bytes: u64,
    sha256: Sha256Digest,
    data: String,
}

impl Artifact {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let (encoding, data) = match std::str::from_utf8(bytes) {
            Ok(text) => (Encoding::Utf8, text.to_owned()),
            Err(_) => (Encoding::Base64, STANDARD.encode(bytes)),
        };
        Self {
            encoding,
            raw_bytes: bytes.len() as u64,
            sha256: Sha256Digest::of(bytes),
            data,
        }
    }

    pub fn original_bytes(&self) -> PacketResult<Vec<u8>> {
        let bytes = match self.encoding {
            Encoding::Utf8 => self.data.as_bytes().to_vec(),
            Encoding::Base64 => {
                let bytes = STANDARD
                    .decode(&self.data)
                    .map_err(|_| PacketError::Invalid("invalid base64 artifact"))?;
                if STANDARD.encode(&bytes) != self.data || std::str::from_utf8(&bytes).is_ok() {
                    return Err(PacketError::Invalid("noncanonical artifact encoding"));
                }
                bytes
            }
        };
        if self.raw_bytes > MAX_SAFE_INTEGER
            || self.raw_bytes != bytes.len() as u64
            || self.sha256 != Sha256Digest::of(&bytes)
        {
            return Err(PacketError::Invalid(
                "artifact original length or SHA-256 mismatch",
            ));
        }
        Ok(bytes)
    }

    #[must_use]
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    #[must_use]
    pub fn raw_bytes(&self) -> u64 {
        self.raw_bytes
    }

    #[must_use]
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
}

/// Canonical repository-relative byte path (no filesystem access or globbing).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoPath(Artifact);

impl RepoPath {
    pub fn from_bytes(bytes: &[u8]) -> PacketResult<Self> {
        validate_repo_path(bytes)?;
        Ok(Self(Artifact::from_bytes(bytes)))
    }

    pub fn from_str_path(path: &str) -> PacketResult<Self> {
        Self::from_bytes(path.as_bytes())
    }

    pub fn original_bytes(&self) -> PacketResult<Vec<u8>> {
        let bytes = self.0.original_bytes()?;
        validate_repo_path(&bytes)?;
        Ok(bytes)
    }

    pub fn as_utf8_str(&self) -> PacketResult<String> {
        let bytes = self.original_bytes()?;
        String::from_utf8(bytes).map_err(|_| PacketError::Invalid("non-UTF-8 repository path"))
    }
}

fn validate_repo_path(bytes: &[u8]) -> PacketResult<()> {
    if bytes.is_empty()
        || bytes.contains(&0)
        || bytes
            .split(|b| *b == b'/')
            .any(|seg| seg.is_empty() || seg == b"." || seg == b"..")
    {
        return Err(PacketError::Invalid(
            "expected a repository-relative byte path",
        ));
    }
    Ok(())
}

struct SupportedValue(Value);

impl<'de> Deserialize<'de> for SupportedValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SupportedVisitor)
    }
}

struct SupportedVisitor;

impl<'de> Visitor<'de> for SupportedVisitor {
    type Value = SupportedValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with unique keys, valid Unicode, and safe integers only")
    }

    fn visit_unit<E: de::Error>(self) -> Result<SupportedValue, E> {
        Ok(SupportedValue(Value::Null))
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<SupportedValue, E> {
        Ok(SupportedValue(Value::Bool(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<SupportedValue, E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("integer exceeds the supported exact range"));
        }
        Ok(SupportedValue(Value::Number(Number::from(v))))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<SupportedValue, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(E::custom("integer exceeds the supported exact range"));
        }
        Ok(SupportedValue(Value::Number(Number::from(v))))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<SupportedValue, E> {
        Err(E::custom("floating-point syntax is unsupported"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<SupportedValue, E> {
        Ok(SupportedValue(Value::String(v.to_owned())))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<SupportedValue, E> {
        Ok(SupportedValue(Value::String(v)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SupportedValue, A::Error> {
        let mut values = Vec::new();
        while let Some(SupportedValue(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(SupportedValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SupportedValue, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate decoded object property"));
            }
            let SupportedValue(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(SupportedValue(Value::Object(values)))
    }
}

/// Parses JSON without collapsing duplicate keys and serializes strict RFC 8785 JCS UTF-8 bytes.
pub fn canonicalize_jcs_bytes(input: &[u8]) -> PacketResult<Vec<u8>> {
    let mut decoder = serde_json::Deserializer::from_slice(input);
    let SupportedValue(value) = SupportedValue::deserialize(&mut decoder)?;
    decoder.end()?;
    let mut bytes = Vec::new();
    write_jcs_value(&value, &mut bytes);
    Ok(bytes)
}

/// Serializes any `Serialize` value into strict RFC 8785 JCS UTF-8 bytes.
pub fn jcs_from_serializable<T: Serialize>(value: &T) -> PacketResult<Vec<u8>> {
    canonicalize_jcs_bytes(&serde_json::to_vec(value)?)
}

fn write_jcs_value(value: &Value, bytes: &mut Vec<u8>) {
    match value {
        Value::Null => bytes.extend_from_slice(b"null"),
        Value::Bool(true) => bytes.extend_from_slice(b"true"),
        Value::Bool(false) => bytes.extend_from_slice(b"false"),
        Value::Number(n) => bytes.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_jcs_string(s, bytes),
        Value::Array(values) => {
            bytes.push(b'[');
            for (i, item) in values.iter().enumerate() {
                if i > 0 {
                    bytes.push(b',');
                }
                write_jcs_value(item, bytes);
            }
            bytes.push(b']');
        }
        Value::Object(values) => {
            let mut fields: Vec<_> = values.iter().collect();
            fields.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            bytes.push(b'{');
            for (i, (key, val)) in fields.into_iter().enumerate() {
                if i > 0 {
                    bytes.push(b',');
                }
                write_jcs_string(key, bytes);
                bytes.push(b':');
                write_jcs_value(val, bytes);
            }
            bytes.push(b'}');
        }
    }
}

fn write_jcs_string(value: &str, bytes: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes.push(b'"');
    for c in value.chars() {
        match c {
            '"' => bytes.extend_from_slice(br#"\""#),
            '\\' => bytes.extend_from_slice(br"\\"),
            '\u{8}' => bytes.extend_from_slice(br"\b"),
            '\t' => bytes.extend_from_slice(br"\t"),
            '\n' => bytes.extend_from_slice(br"\n"),
            '\u{c}' => bytes.extend_from_slice(br"\f"),
            '\r' => bytes.extend_from_slice(br"\r"),
            '\0'..='\u{1f}' => {
                let n = c as usize;
                bytes.extend_from_slice(br"\u00");
                bytes.push(HEX[n >> 4]);
                bytes.push(HEX[n & 15]);
            }
            _ => bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    bytes.push(b'"');
}

fn reject_signed_envelope(input: &[u8]) -> PacketResult<()> {
    let value: Value = serde_json::from_slice(input)?;
    if let Some(object) = value.as_object()
        && (object.contains_key("packet_sha256") || object.contains_key("host_signature_ed25519"))
    {
        return Err(PacketError::Invalid(
            "signed envelope fields are not unsigned packet fields",
        ));
    }
    Ok(())
}

/// Offline unverified external facts marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalFacts {
    UnverifiedOfflineInputs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertedPolicySnapshot {
    pub source_id: String,
    pub revision: String,
    pub body: Artifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredSuite {
    pub id: String,
    pub argv: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedPinnedPolicy {
    pub base_commit_id: String,
    pub workflow: Artifact,
    pub required_plan: Artifact,
    pub mandatory_global_policies: Vec<AssertedPolicySnapshot>,
    pub external_snapshots: Vec<AssertedPolicySnapshot>,
    pub required_test_suites: Vec<RequiredSuite>,
    pub binary_review_exempt_paths: Vec<RepoPath>,
}

impl UnverifiedPinnedPolicy {
    pub fn asserted_digest(&self) -> PacketResult<Sha256Digest> {
        let mut policy = self.clone();
        policy.normalize()?;
        Ok(Sha256Digest::of(&jcs_from_serializable(&policy)?))
    }

    fn normalize(&mut self) -> PacketResult<()> {
        nonempty(&self.base_commit_id)?;
        if self.workflow.original_bytes()?.is_empty()
            || self.required_plan.original_bytes()?.is_empty()
        {
            return Err(PacketError::Invalid(
                "workflow and required lane-plan bytes must be explicit",
            ));
        }
        for snapshots in [
            &mut self.mandatory_global_policies,
            &mut self.external_snapshots,
        ] {
            snapshots.sort_by(|a, b| a.source_id.cmp(&b.source_id));
            let mut seen = BTreeSet::new();
            for snapshot in snapshots {
                nonempty(&snapshot.source_id)?;
                nonempty(&snapshot.revision)?;
                snapshot.body.original_bytes()?;
                if !seen.insert(&snapshot.source_id) {
                    return Err(PacketError::Invalid("duplicate policy snapshot source"));
                }
            }
        }
        self.required_test_suites.sort_by(|a, b| a.id.cmp(&b.id));
        let mut seen = BTreeSet::new();
        for suite in &self.required_test_suites {
            nonempty(&suite.id)?;
            validate_argv(&suite.argv)?;
            if !seen.insert(&suite.id) {
                return Err(PacketError::Invalid("duplicate required suite"));
            }
        }
        sort_paths(&mut self.binary_review_exempt_paths)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "families",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum AuthorshipClaim {
    HumanOnly,
    SingleAiFamily(String),
    MixedAiFamilies(Vec<String>),
    UnknownUnverified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedAuthorProvenance {
    pub asserted_authorship: AuthorshipClaim,
    pub claimed_signed_records: Vec<Artifact>,
}

impl UnverifiedAuthorProvenance {
    fn normalize(&mut self) -> PacketResult<()> {
        match &mut self.asserted_authorship {
            AuthorshipClaim::SingleAiFamily(family) => nonempty(family)?,
            AuthorshipClaim::MixedAiFamilies(families) => {
                families.sort();
                if families.len() < 2 || families.windows(2).any(|w| w[0] == w[1]) {
                    return Err(PacketError::Invalid(
                        "mixed authorship requires at least two distinct families",
                    ));
                }
                for family in families {
                    nonempty(family)?;
                }
            }
            AuthorshipClaim::HumanOnly | AuthorshipClaim::UnknownUnverified => {}
        }
        if !matches!(self.asserted_authorship, AuthorshipClaim::UnknownUnverified)
            && self.claimed_signed_records.is_empty()
        {
            return Err(PacketError::Invalid(
                "known authorship claims require explicit purported attestations",
            ));
        }
        for record in &self.claimed_signed_records {
            if record.original_bytes()?.is_empty() {
                return Err(PacketError::Invalid("empty purported provenance record"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedReviewer {
    pub route_id: String,
    pub expected_family: String,
    pub profile_epoch: String,
    pub profile_snapshot: Artifact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileMode {
    #[serde(rename = "100644")]
    Regular,
    #[serde(rename = "100755")]
    Executable,
    #[serde(rename = "120000")]
    Symlink,
    #[serde(rename = "160000")]
    Submodule,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobMetadata {
    pub mode: FileMode,
    pub sha256: Sha256Digest,
    pub raw_bytes: u64,
}

impl BlobMetadata {
    #[must_use]
    pub fn from_bytes(mode: FileMode, bytes: &[u8]) -> Self {
        Self {
            mode,
            sha256: Sha256Digest::of(bytes),
            raw_bytes: bytes.len() as u64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssertedContentKind {
    Text,
    BinaryOrNonUtf8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedPath {
    pub old_path: Option<RepoPath>,
    pub new_path: Option<RepoPath>,
    pub old: Option<BlobMetadata>,
    pub new: Option<BlobMetadata>,
    pub asserted_content_kind: AssertedContentKind,
}

impl ChangedPath {
    fn key(&self) -> PacketResult<Vec<u8>> {
        self.new_path
            .as_ref()
            .or(self.old_path.as_ref())
            .ok_or(PacketError::Invalid("change has no endpoint"))?
            .original_bytes()
    }

    pub fn paths(&self) -> impl Iterator<Item = &RepoPath> {
        self.old_path.iter().chain(self.new_path.iter())
    }

    fn needs_exemption(&self) -> PacketResult<bool> {
        let non_utf8_path = self
            .paths()
            .map(RepoPath::original_bytes)
            .collect::<PacketResult<Vec<_>>>()?
            .iter()
            .any(|p| std::str::from_utf8(p).is_err());
        Ok(
            self.asserted_content_kind == AssertedContentKind::BinaryOrNonUtf8
                || self
                    .old
                    .iter()
                    .chain(self.new.iter())
                    .any(|b| b.mode == FileMode::Submodule)
                || non_utf8_path,
        )
    }
}

/// Supported tombstone scope (`GLOBAL` or `EXACT_PATH` — ad-hoc globs forbidden).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "path",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum TombstoneScope {
    Global,
    ExactPath(RepoPath),
}

/// Unmodified tombstone bytes and asserted scope/activity (`ReviewPacketV2`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertedTombstone {
    pub id: String,
    pub active: bool,
    pub scope: TombstoneScope,
    pub body: Artifact,
}

/// Retains every supplied active `GLOBAL` or exact `old_path`/`new_path` match, sorted by ID.
pub fn select_tombstones(
    supplied: &[AssertedTombstone],
    changes: &[ChangedPath],
) -> PacketResult<Vec<AssertedTombstone>> {
    let paths = changes
        .iter()
        .flat_map(ChangedPath::paths)
        .map(RepoPath::original_bytes)
        .collect::<PacketResult<BTreeSet<_>>>()?;
    let mut ids = BTreeSet::new();
    let mut selected = Vec::new();
    for tombstone in supplied {
        nonempty(&tombstone.id)?;
        tombstone.body.original_bytes()?;
        if !ids.insert(&tombstone.id) {
            return Err(PacketError::Invalid("duplicate tombstone id"));
        }
        let matches = match &tombstone.scope {
            TombstoneScope::Global => true,
            TombstoneScope::ExactPath(path) => paths.contains(&path.original_bytes()?),
        };
        if tombstone.active && matches {
            selected.push(tombstone.clone());
        }
    }
    selected.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(selected)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssertedVerificationOrigin {
    AuthorRanHostChecked,
    IndependentQaVerified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCounts {
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
    pub filtered: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertedFailureHeader {
    pub body: Artifact,
    pub asserted_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertedSuiteRun {
    pub suite_id: String,
    pub argv: Vec<String>,
    pub toolchain: String,
    pub exit_code: i32,
    pub counts: TestCounts,
    pub full_log: Artifact,
    pub failure_header: Option<AssertedFailureHeader>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedTestEvidence {
    pub tested_commit_id: String,
    pub execution_snapshot_commit_id: String,
    pub asserted_clean_snapshot: bool,
    pub asserted_verification_origin: AssertedVerificationOrigin,
    pub runs: Vec<AssertedSuiteRun>,
}

impl UnverifiedTestEvidence {
    fn bind(&mut self, candidate: &str, required: &[RequiredSuite]) -> PacketResult<()> {
        if self.tested_commit_id != candidate
            || self.execution_snapshot_commit_id != candidate
            || !self.asserted_clean_snapshot
        {
            return Err(PacketError::Invalid(
                "evidence must assert the same clean immutable candidate",
            ));
        }
        self.runs.sort_by(|a, b| a.suite_id.cmp(&b.suite_id));
        let mut seen = BTreeSet::new();
        for run in &self.runs {
            if !seen.insert(&run.suite_id) {
                return Err(PacketError::Invalid("duplicate suite execution"));
            }
            let suite =
                required
                    .iter()
                    .find(|s| s.id == run.suite_id)
                    .ok_or(PacketError::Invalid(
                        "execution names a suite outside the supplied required plan",
                    ))?;
            if run.argv != suite.argv {
                return Err(PacketError::Invalid(
                    "execution argv does not match the exact required target",
                ));
            }
            nonempty(&run.toolchain)?;
            run.full_log.original_bytes()?;
            for count in [
                run.counts.passed,
                run.counts.failed,
                run.counts.ignored,
                run.counts.filtered,
            ] {
                if count > MAX_SAFE_INTEGER {
                    return Err(PacketError::Invalid(
                        "test count exceeds exact integer range",
                    ));
                }
            }
            if run.counts.failed > 0 {
                if run.exit_code == 0 {
                    return Err(PacketError::Invalid(
                        "failing assertions cannot have a successful exit",
                    ));
                }
                let header = run.failure_header.as_ref().ok_or(PacketError::Invalid(
                    "failing assertions require an explicit failure header",
                ))?;
                let bytes = header.body.original_bytes()?;
                if bytes.is_empty()
                    || bytes.len() > MAX_FAILURE_HEADER_BYTES
                    || std::str::from_utf8(&bytes).is_err()
                    || !(1..=MAX_FAILURE_HEADER_TOKENS).contains(&header.asserted_tokens)
                {
                    return Err(PacketError::Invalid(
                        "unsupported failure header or asserted token count",
                    ));
                }
            } else if run.failure_header.is_some() {
                return Err(PacketError::Invalid(
                    "failure header without failed assertions",
                ));
            }
        }
        for suite in required {
            if !seen.contains(&suite.id) {
                return Err(PacketError::MissingSuite(suite.id.clone()));
            }
        }
        Ok(())
    }
}

/// Complete supplied payload for `ReviewPacketV2`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketInput {
    pub schema: String,
    pub contract_version: String,
    pub external_facts: ExternalFacts,
    pub repo_id: String,
    pub case_id: String,
    pub intent_id: String,
    pub base_commit_id: String,
    pub candidate_commit_id: String,
    pub author_provenance: UnverifiedAuthorProvenance,
    pub reviewer: UnverifiedReviewer,
    pub governing_policy: UnverifiedPinnedPolicy,
    pub governing_policy_sha256: Sha256Digest,
    pub canonical_diff: Artifact,
    pub changed_paths: Vec<ChangedPath>,
    pub tombstone_snapshot: Vec<AssertedTombstone>,
    pub test_evidence: UnverifiedTestEvidence,
    pub author_context_note: Option<Artifact>,
}

/// Structurally bound, explicitly unverified `ReviewPacketV2` (`chinwag.review-packet.v2`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewPacketV2 {
    #[serde(flatten)]
    input: PacketInput,
    selected_tombstones: Vec<AssertedTombstone>,
    unreviewed_exempt_binary_paths: Vec<RepoPath>,
}

impl ReviewPacketV2 {
    pub fn bind_asserted(mut input: PacketInput) -> PacketResult<Self> {
        if input.schema != "chinwag.review-packet.v2" || input.contract_version != "2" {
            return Err(PacketError::Invalid(
                "unsupported packet schema or contract version",
            ));
        }
        for id in [
            &input.repo_id,
            &input.case_id,
            &input.intent_id,
            &input.base_commit_id,
            &input.candidate_commit_id,
            &input.reviewer.route_id,
            &input.reviewer.expected_family,
            &input.reviewer.profile_epoch,
        ] {
            nonempty(id)?;
        }
        if input.governing_policy.base_commit_id != input.base_commit_id {
            return Err(PacketError::Invalid(
                "policy base differs from the packet base",
            ));
        }
        input.governing_policy.normalize()?;
        if input.governing_policy.asserted_digest()? != input.governing_policy_sha256 {
            return Err(PacketError::Invalid(
                "governing policy source/projection digest mismatch",
            ));
        }
        input.author_provenance.normalize()?;
        input.reviewer.profile_snapshot.original_bytes()?;
        input.canonical_diff.original_bytes()?;
        if let Some(note) = &input.author_context_note {
            note.original_bytes()?;
        }
        let exemptions = input
            .governing_policy
            .binary_review_exempt_paths
            .iter()
            .map(RepoPath::original_bytes)
            .collect::<PacketResult<BTreeSet<_>>>()?;
        let mut old_paths = BTreeSet::new();
        let mut new_paths = BTreeSet::new();
        let mut keyed_changes = Vec::new();
        let mut unreviewed = Vec::new();
        for change in input.changed_paths {
            if change.old_path.is_some() != change.old.is_some()
                || change.new_path.is_some() != change.new.is_some()
            {
                return Err(PacketError::Invalid(
                    "every change endpoint requires a path and explicit blob/mode",
                ));
            }
            for blob in change.old.iter().chain(change.new.iter()) {
                Sha256Digest::parse(blob.sha256.as_str())?;
                if blob.raw_bytes > MAX_SAFE_INTEGER {
                    return Err(PacketError::Invalid(
                        "blob size exceeds exact integer range",
                    ));
                }
            }
            for (path, seen) in [
                (&change.old_path, &mut old_paths),
                (&change.new_path, &mut new_paths),
            ] {
                if let Some(path) = path
                    && !seen.insert(path.original_bytes()?)
                {
                    return Err(PacketError::Invalid("duplicate old or new tree endpoint"));
                }
            }
            if change.old_path == change.new_path && change.old == change.new {
                return Err(PacketError::Invalid("empty or unchanged tree entry"));
            }
            if change.needs_exemption()? {
                for path in change.paths() {
                    if !exemptions.contains(&path.original_bytes()?) {
                        return Err(PacketError::Invalid(
                            "unreviewable binary artifact lacks an asserted pinned-base exemption",
                        ));
                    }
                    unreviewed.push(path.clone());
                }
            }
            keyed_changes.push((change.key()?, change));
        }
        keyed_changes.sort_by(|a, b| a.0.cmp(&b.0));
        input.changed_paths = keyed_changes
            .into_iter()
            .map(|(_, change)| change)
            .collect();

        let mut keyed = unreviewed
            .into_iter()
            .map(|p| Ok((p.original_bytes()?, p)))
            .collect::<PacketResult<Vec<_>>>()?;
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        keyed.dedup_by(|a, b| a.0 == b.0);
        let unreviewed = keyed.into_iter().map(|(_, path)| path).collect();

        let selected_tombstones =
            select_tombstones(&input.tombstone_snapshot, &input.changed_paths)?;
        input.tombstone_snapshot.sort_by(|a, b| a.id.cmp(&b.id));
        input.test_evidence.bind(
            &input.candidate_commit_id,
            &input.governing_policy.required_test_suites,
        )?;
        let packet = Self {
            input,
            selected_tombstones,
            unreviewed_exempt_binary_paths: unreviewed,
        };
        jcs_from_serializable(&packet)?;
        Ok(packet)
    }

    pub fn parse_asserted_input(bytes: &[u8]) -> PacketResult<Self> {
        let bytes = canonicalize_jcs_bytes(bytes)?;
        reject_signed_envelope(&bytes)?;
        Self::bind_asserted(serde_json::from_slice(&bytes)?)
    }

    pub fn parse_unsigned(bytes: &[u8]) -> PacketResult<Self> {
        let bytes = canonicalize_jcs_bytes(bytes)?;
        reject_signed_envelope(&bytes)?;
        let mut value: Value = serde_json::from_slice(&bytes)?;
        let object = value
            .as_object_mut()
            .ok_or(PacketError::Invalid("packet must be an object"))?;
        if object.remove("selected_tombstones").is_none()
            || object.remove("unreviewed_exempt_binary_paths").is_none()
        {
            return Err(PacketError::Invalid(
                "unsigned packet requires explicit derived selections",
            ));
        }
        let packet = Self::bind_asserted(serde_json::from_value(value)?)?;
        if packet.canonical_unsigned()?.canonical_unsigned_bytes() != bytes {
            return Err(PacketError::Invalid(
                "unsigned packet selections or set ordering do not match its input",
            ));
        }
        Ok(packet)
    }

    pub fn canonical_unsigned(&self) -> PacketResult<UnverifiedUnsignedPacket> {
        let bytes = jcs_from_serializable(self)?;
        let packet_sha256 = Sha256Digest::of(&bytes);
        Ok(UnverifiedUnsignedPacket {
            bytes,
            packet_sha256,
        })
    }

    #[must_use]
    pub fn input(&self) -> &PacketInput {
        &self.input
    }

    #[must_use]
    pub fn selected_tombstones(&self) -> &[AssertedTombstone] {
        &self.selected_tombstones
    }

    #[must_use]
    pub fn unreviewed_exempt_binary_paths(&self) -> &[RepoPath] {
        &self.unreviewed_exempt_binary_paths
    }

    pub fn require_verified_external_facts(&self) -> PacketResult<()> {
        Err(PacketError::ExternalVerificationRequired)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedUnsignedPacket {
    bytes: Vec<u8>,
    packet_sha256: Sha256Digest,
}

impl UnverifiedUnsignedPacket {
    #[must_use]
    pub fn canonical_unsigned_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn packet_sha256(&self) -> &Sha256Digest {
        &self.packet_sha256
    }
}

/// Two-axis finalized wire tier (`COMPACT` or `STANDARD`) per `design-v2` §5.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CardTierV1 {
    Compact,
    Standard,
}

/// Complete two-axis classification outcome (`design-v2` §5.1 priority rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TierClassificationOutcome {
    Admitted(CardTierV1),
    UnavailableSystemOverheadExceeded,
    ActionNeededCandidateTooLarge,
}

/// Classifies finalized wire measurements + mandatory overhead attribution per `design-v2` §5.1.
///
/// Priority rule: validate mandatory policy/framing overhead first (`<= 8,000` tokens AND
/// `<= 32,768` bytes). Bloated mandatory overhead is ALWAYS quarantined to the Project Operator
/// (`UnavailableSystemOverheadExceeded`), never blamed on the Change Author.
#[must_use]
pub fn classify_two_axis_tier(
    finalized_wire_tokens: u64,
    finalized_wire_bytes: u64,
    mandatory_overhead_tokens: u64,
    mandatory_overhead_bytes: u64,
    candidate_tokens: u64,
    candidate_bytes: u64,
) -> TierClassificationOutcome {
    if mandatory_overhead_tokens > MANDATORY_OVERHEAD_MAX_TOKENS
        || mandatory_overhead_bytes > MANDATORY_OVERHEAD_MAX_BYTES
    {
        return TierClassificationOutcome::UnavailableSystemOverheadExceeded;
    }
    if finalized_wire_tokens <= COMPACT_MAX_TOKENS && finalized_wire_bytes <= COMPACT_MAX_BYTES {
        return TierClassificationOutcome::Admitted(CardTierV1::Compact);
    }
    if finalized_wire_tokens <= STANDARD_MAX_TOKENS && finalized_wire_bytes <= STANDARD_MAX_BYTES {
        return TierClassificationOutcome::Admitted(CardTierV1::Standard);
    }
    if candidate_tokens <= CANDIDATE_GUARANTEED_TOKENS
        && candidate_bytes <= CANDIDATE_GUARANTEED_BYTES
    {
        TierClassificationOutcome::UnavailableSystemOverheadExceeded
    } else {
        TierClassificationOutcome::ActionNeededCandidateTooLarge
    }
}

/// Canonical inner wake-card payload (`chinwag.sealed-wake-card.v1`, `return-envelope-acu-contract-v1.2` §4.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedWakeCardPayloadV1 {
    pub schema: String,
    pub logical_event_id: String,
    pub task_id: String,
    pub candidate_commit_oid: String,
    pub proof_bundle_sha256: Sha256Digest,
    pub card_tier: CardTierV1,
    pub canonical_cwcard_sha256: Sha256Digest,
    pub canonical_cwcard_jcs: String,
    pub scoped_tombstones: Vec<AssertedTombstone>,
}

impl SealedWakeCardPayloadV1 {
    /// Binds a `ReviewPacketV2` into a `SealedWakeCardPayloadV1` after checking conjunctive
    /// `COMPACT`/`STANDARD` byte & measured-token bounds.
    pub fn bind_from_packet(
        logical_event_id: &str,
        task_id: &str,
        proof_bundle_sha256: Sha256Digest,
        measured_finalized_tokens: u64,
        mandatory_overhead_tokens: u64,
        mandatory_overhead_bytes: u64,
        packet: &ReviewPacketV2,
    ) -> PacketResult<Self> {
        nonempty(logical_event_id)?;
        nonempty(task_id)?;
        let unsigned = packet.canonical_unsigned()?;
        let jcs_bytes = unsigned.canonical_unsigned_bytes();
        let jcs_str = std::str::from_utf8(jcs_bytes)
            .map_err(|_| PacketError::Invalid("canonical JCS must be UTF-8"))?;
        let finalized_bytes = jcs_bytes.len() as u64;
        let candidate_bytes = finalized_bytes.saturating_sub(mandatory_overhead_bytes);
        let candidate_tokens = measured_finalized_tokens.saturating_sub(mandatory_overhead_tokens);

        let card_tier = match classify_two_axis_tier(
            measured_finalized_tokens,
            finalized_bytes,
            mandatory_overhead_tokens,
            mandatory_overhead_bytes,
            candidate_tokens,
            candidate_bytes,
        ) {
            TierClassificationOutcome::Admitted(tier) => tier,
            TierClassificationOutcome::UnavailableSystemOverheadExceeded => {
                return Err(PacketError::Invalid("UNAVAILABLE_SYSTEM_OVERHEAD_EXCEEDED"));
            }
            TierClassificationOutcome::ActionNeededCandidateTooLarge => {
                return Err(PacketError::Invalid("OVERFLOW_SPLIT_REQUIRED"));
            }
        };

        let payload = Self {
            schema: "chinwag.sealed-wake-card.v1".to_owned(),
            logical_event_id: logical_event_id.to_owned(),
            task_id: task_id.to_owned(),
            candidate_commit_oid: packet.input().candidate_commit_id.clone(),
            proof_bundle_sha256,
            card_tier,
            canonical_cwcard_sha256: unsigned.packet_sha256().clone(),
            canonical_cwcard_jcs: jcs_str.to_owned(),
            scoped_tombstones: packet.selected_tombstones().to_vec(),
        };
        let encoded = jcs_from_serializable(&payload)?;
        if encoded.len() as u64 > STANDARD_MAX_BYTES {
            return Err(PacketError::Invalid(
                "SealedWakeCardPayloadV1 exceeds 65536-byte intake ceiling",
            ));
        }
        Ok(payload)
    }

    /// Strictly verifies `schema`, `ReviewPacketV2::parse_unsigned`, exact `canonical_cwcard_sha256`
    /// equality, `candidate_commit_oid` match, and byte-for-byte `scoped_tombstones` equality.
    pub fn verify_roundtrip(&self) -> PacketResult<ReviewPacketV2> {
        if self.schema != "chinwag.sealed-wake-card.v1" {
            return Err(PacketError::Invalid(
                "unsupported SealedWakeCardPayloadV1 schema",
            ));
        }
        nonempty(&self.logical_event_id)?;
        nonempty(&self.task_id)?;
        nonempty(&self.candidate_commit_oid)?;

        let canonical_bytes = canonicalize_jcs_bytes(self.canonical_cwcard_jcs.as_bytes())?;
        if canonical_bytes != self.canonical_cwcard_jcs.as_bytes() {
            return Err(PacketError::Invalid(
                "canonical_cwcard_jcs is not in canonical RFC 8785 JCS form",
            ));
        }
        let computed_sha = Sha256Digest::of(&canonical_bytes);
        if computed_sha != self.canonical_cwcard_sha256 {
            return Err(PacketError::Invalid("canonical_cwcard_sha256 mismatch"));
        }
        match self.card_tier {
            CardTierV1::Compact if canonical_bytes.len() as u64 > COMPACT_MAX_BYTES => {
                return Err(PacketError::Invalid(
                    "COMPACT card exceeds 16384-byte bound",
                ));
            }
            CardTierV1::Standard if canonical_bytes.len() as u64 > STANDARD_MAX_BYTES => {
                return Err(PacketError::Invalid(
                    "STANDARD card exceeds 65536-byte bound",
                ));
            }
            _ => {}
        }

        let packet = ReviewPacketV2::parse_unsigned(&canonical_bytes)?;
        if packet.input().candidate_commit_id != self.candidate_commit_oid {
            return Err(PacketError::Invalid(
                "candidate_commit_oid does not match packet candidate_commit_id",
            ));
        }
        if jcs_from_serializable(&self.scoped_tombstones)?
            != jcs_from_serializable(&packet.selected_tombstones())?
        {
            return Err(PacketError::Invalid(
                "scoped_tombstones does not match ReviewPacketV2 selected_tombstones",
            ));
        }
        Ok(packet)
    }
}

fn validate_argv(argv: &[String]) -> PacketResult<()> {
    if argv.is_empty() || argv.iter().any(|s| s.is_empty() || s.contains('\0')) {
        return Err(PacketError::Invalid(
            "required suite argv must be explicit and contain no empty/NUL arguments",
        ));
    }
    Ok(())
}

fn sort_paths(paths: &mut Vec<RepoPath>) -> PacketResult<()> {
    let mut keyed = paths
        .drain(..)
        .map(|p| Ok((p.original_bytes()?, p)))
        .collect::<PacketResult<Vec<_>>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(PacketError::Invalid("duplicate binary exemption path"));
    }
    *paths = keyed.into_iter().map(|(_, path)| path).collect();
    Ok(())
}
