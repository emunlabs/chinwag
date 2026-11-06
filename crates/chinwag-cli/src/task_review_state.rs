#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Descriptor-fenced, append-only controlled fixture review state.
//! The retained namespace lock covers load, validation, reservation, consumption
//! and reconciliation. Every durable event retains the admitted fixture origin.
//! Reopening never deserializes an approval capability. Production Done is held.
//! ROOT owns the writer/journal/projection join; a fixture receipt is not live Done.

use crate::task_acceptance::{self as acceptance, AcceptanceError, FixtureProvenanceV1,
    ReviewHighwaterV1, ReviewVerdict, SignedFixtureAssignmentV1, SignedFixtureSubmissionV1,
    SignedCandidateV1, SignedAcceptanceBundleV1, FixtureVerificationEvidenceV1,
    TrustedFixtureVerifier, VerifiedFixtureAcceptanceV1, verify_fixture_quorum,
    digest_json, key_json};
use crate::task_ref::{Sha256Digest, TaskRefV1, checked_next_revision, validate_id};
use crate::task_writer::WriterCommitProof;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, Stat, flock, fstat, openat, statat};
use serde::{Deserialize, Serialize};
use std::{fmt, fs::File, io::{Read, Seek, SeekFrom, Write}};

pub const MAX_REVIEW_RECORD_BYTES: usize = 65_536;
pub const MAX_REVIEW_FILE_BYTES: u64 = 16_777_216;
pub const MAX_REVIEW_RECORDS: usize = 4096;
pub const REVIEW_STATE_FILE_NAME: &str = "task-review-fixture-v1.ndjson";
const COMPLETION_RECORD_RESERVE: usize = 1;

#[derive(Debug)]
pub enum ReviewStateError {
    Io(std::io::Error), Acceptance(AcceptanceError), LockUnavailable, UnsafeMetadata,
    IdentityChanged, ContentChanged, ReadOnly, CorruptState, TruncatedState,
    UnsupportedRecord, RecordTooLarge, FileTooLarge, TooManyRecords, ReplayConflict,
    MissingAssignment, MissingSubmission, InvalidTransition, HighwaterRollback,
    ReconciliationRequired, UnknownWriterStateHeld, WriterProofMismatch,
    FixtureNamespaceMismatch, FixtureNotProduction, Poisoned,
}
impl fmt::Display for ReviewStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "review state held: {self:?}") }
}
impl std::error::Error for ReviewStateError {}
impl From<std::io::Error> for ReviewStateError { fn from(e: std::io::Error) -> Self { Self::Io(e) } }
impl From<rustix::io::Errno> for ReviewStateError { fn from(e: rustix::io::Errno) -> Self { Self::Io(e.into()) } }
impl From<AcceptanceError> for ReviewStateError { fn from(e: AcceptanceError) -> Self { Self::Acceptance(e) } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskReviewLifecycleState { NotSubmitted, CandidateSubmitted, ReviewAttestedApproved, RejectedByReviewer, AcceptedDone, HeldConflict }

/// Caller requests are inert until joined to sealed fixture approval and quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReservationRequestV1 {
    pub original_operation_id: String, pub assignment_id: String, pub target_transition_id: String,
    #[serde(with = "digest_json")] pub request_digest: Sha256Digest,
    #[serde(with = "digest_json")] pub predecessor_sha256: Sha256Digest,
    #[serde(with = "digest_json")] pub successor_sha256: Sha256Digest,
    pub predecessor_bytes: u64, pub successor_bytes: u64,
    pub predecessor_file_rev: u64, pub successor_file_rev: u64,
    pub writer_epoch: u64, pub authority_epoch: u64,
    /// Exact bounded outcome shape is fixed before any writer effect.
    pub maximum_outcome_bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservedV1 {
    request: ReviewReservationRequestV1,
    #[serde(with = "digest_json")] candidate_digest: Sha256Digest,
    #[serde(with = "digest_json")] acceptance_digest: Sha256Digest,
    #[serde(with = "key_json")] nonce: [u8; 32],
    reviewer_principal: String, review_round: u64,
    #[serde(with = "acceptance::TaskRefJson")] qualified_current: TaskRefV1, rebases_used: u8,
    bundle: SignedAcceptanceBundleV1, evidence: FixtureVerificationEvidenceV1,
    approvals: Vec<(SignedAcceptanceBundleV1, FixtureVerificationEvidenceV1)>,
    highwater: ReviewHighwaterV1,
}
/// Sealed handle includes the immutable fixture origin and exact durable reservation.
#[derive(Clone, Debug)]
pub struct FixtureReservationV1 { reservation: ReservedV1, provenance: FixtureProvenanceV1 }
impl FixtureReservationV1 {
    pub fn original_operation_id(&self) -> &str { &self.reservation.request.original_operation_id }
    pub fn acceptance_digest(&self) -> Sha256Digest { self.reservation.acceptance_digest }
    pub fn require_production(&self) -> Result<(), ReviewStateError> { Err(ReviewStateError::FixtureNotProduction) }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRecordedOutcomeV1 {
    original_operation_id: String, target_transition_id: String,
    #[serde(with = "digest_json")] acceptance_digest: Sha256Digest,
    #[serde(with = "digest_json")] request_digest: Sha256Digest,
    #[serde(with = "digest_json")] committed_postimage_sha256: Sha256Digest,
    committed_file_rev: u64, committed_bytes: u64,
    provenance: FixtureProvenanceV1,
}
impl FixtureRecordedOutcomeV1 {
    pub fn original_operation_id(&self) -> &str { &self.original_operation_id }
    pub fn require_production(&self) -> Result<(), ReviewStateError> { Err(ReviewStateError::FixtureNotProduction) }
}
#[derive(Clone, Debug)]
pub enum ReservationDispositionV1 {
    Reserved(FixtureReservationV1),
    PendingOriginalOperation(FixtureReservationV1),
    Consumed(FixtureRecordedOutcomeV1),
}

/// Only ROOT's shared writer/journal module may implement this trait. An external
/// caller cannot implement the crate-private seal, provide scalar "verified"
/// fields, or strip fixture provenance. The writer must derive this complete
/// view from its original durable request and finalized projection transaction.
pub(crate) mod writer_finalization_seal { pub trait Sealed {} }
pub trait QualifiedReviewWriterFinalizationV1: writer_finalization_seal::Sealed {
    fn writer_commit_proof(&self) -> &WriterCommitProof;
    fn review_finalization_binding(&self) -> &ReviewWriterFinalizationBindingV1;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewWriterFinalizationBindingV1 {
    pub(crate) request_digest: Sha256Digest,
    pub(crate) acceptance_digest: Sha256Digest,
    pub(crate) candidate_digest: Sha256Digest,
    pub(crate) target_transition_id: String,
    pub(crate) target_task_status_rev: u64,
    pub(crate) target_status: crate::task_writer::CanonicalTaskStatus,
    pub(crate) fixture_provenance: FixtureProvenanceV1,
}

/// Caller observations do not authorize recovery effects. They classify which
/// original operation ROOT must revalidate through its qualified writer journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationDispositionV1 { ResumeOriginalOperation, RepairOriginalConsumption, UnknownStateHeld }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
enum EventV1 {
    Assignment(SignedFixtureAssignmentV1),
    Submission { candidate: SignedCandidateV1, transition: SignedFixtureSubmissionV1 },
    Reserved(Box<ReservedV1>),
    Rejected { bundle: Box<SignedAcceptanceBundleV1>, evidence: Box<FixtureVerificationEvidenceV1>, highwater: ReviewHighwaterV1 },
    Consumed { reservation_digest: String, outcome: FixtureRecordedOutcomeV1 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskRecordV1 {
    version: u64, sequence: u64,
    #[serde(with = "digest_json")] previous: Sha256Digest,
    provenance: FixtureProvenanceV1, event: EventV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity { dev: u64, ino: u64, uid: u32, mode: u32, nlink: u64, size: u64, mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64 }
impl Identity {
    #[allow(clippy::unnecessary_cast)]
    fn from(s: &Stat) -> Result<Self, ReviewStateError> {
        Ok(Self { dev: s.st_dev as u64, ino: s.st_ino as u64, uid: s.st_uid, mode: s.st_mode as u32,
            nlink: s.st_nlink as u64, size: u64::try_from(s.st_size).map_err(|_| ReviewStateError::UnsafeMetadata)?,
            mtime: s.st_mtime as i64, mtime_ns: s.st_mtime_nsec as i64, ctime: s.st_ctime as i64, ctime_ns: s.st_ctime_nsec as i64 })
    }
    fn key(self) -> (u64, u64) { (self.dev, self.ino) }
}
fn directory(file: &File, uid: u32) -> Result<Identity, ReviewStateError> {
    let stat = fstat(file)?; let id = Identity::from(&stat)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || id.uid != uid || id.mode & 0o7777 != 0o700 { return Err(ReviewStateError::UnsafeMetadata); }
    Ok(id)
}
fn regular(stat: &Stat, uid: u32) -> Result<Identity, ReviewStateError> {
    let id = Identity::from(stat)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || id.uid != uid || id.nlink != 1
        || !matches!(id.mode & 0o7777, 0o600 | 0o400) { return Err(ReviewStateError::UnsafeMetadata); }
    if id.size > MAX_REVIEW_FILE_BYTES { return Err(ReviewStateError::FileTooLarge); } Ok(id)
}
fn component(name: &str) -> Result<(), ReviewStateError> {
    if name.is_empty() || name.len() > 256 || name == "." || name == ".." || name.contains('/') || name.contains('\0') { return Err(ReviewStateError::UnsafeMetadata); } Ok(())
}
struct RecordBuffer(Vec<u8>);
impl Write for RecordBuffer {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > (MAX_REVIEW_RECORD_BYTES - 1).saturating_sub(self.0.len()) { return Err(std::io::Error::other("review record bound")); }
        self.0.extend_from_slice(b); Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
fn encode_record(record: &DiskRecordV1) -> Result<Vec<u8>, ReviewStateError> {
    let mut buffer = RecordBuffer(Vec::new());
    serde_json::to_writer(&mut buffer, record).map_err(|_| ReviewStateError::RecordTooLarge)?;
    buffer.0.push(b'\n'); Ok(buffer.0)
}
fn reservation_digest(r: &ReservedV1) -> Result<String, ReviewStateError> {
    Ok(Sha256Digest::of(&acceptance::fixture_statement("durable-reservation", r)?).to_string())
}

/// Retained independently opened directory descriptions own the advisory lock.
/// A second opener contends even in this process; no clone shares lock ownership.
#[derive(Debug)]
pub struct ReviewStateStoreV1 {
    parent: File, namespace: File, file: File, namespace_name: String, uid: u32,
    parent_identity: (u64, u64), namespace_identity: (u64, u64), file_identity: Identity,
    exact_bytes: Vec<u8>, exact_hash: Sha256Digest, records: Vec<DiskRecordV1>,
    provenance: FixtureProvenanceV1, highwater: ReviewHighwaterV1, poisoned: bool,
    qualified_finalizations: Vec<(WriterCommitProof, ReviewWriterFinalizationBindingV1)>,
}
impl ReviewStateStoreV1 {
    pub fn open(parent: &File, namespace_name: &str, p: &TrustedFixtureVerifier) -> Result<Self, ReviewStateError> {
        Self::reopen_with_finalizations(parent, namespace_name, p, &[])
    }
    /// Consumed records require the original sealed writer/journal finalization
    /// again after restart. Deserializing predictable outcome fields is never proof.
    pub fn reopen_with_finalizations(parent: &File, namespace_name: &str, p: &TrustedFixtureVerifier,
        finalizations: &[&dyn QualifiedReviewWriterFinalizationV1]) -> Result<Self, ReviewStateError> {
        if finalizations.len() > MAX_REVIEW_RECORDS { return Err(ReviewStateError::TooManyRecords); }
        component(namespace_name)?;
        let uid = rustix::process::geteuid().as_raw();
        let caller = directory(parent, uid)?;
        let retained_parent = File::from(openat(parent, ".", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?);
        if directory(&retained_parent, uid)?.key() != caller.key() { return Err(ReviewStateError::IdentityChanged); }
        let namespace = File::from(openat(&retained_parent, namespace_name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?);
        let ns = directory(&namespace, uid)?;
        if ns.key() != (p.provenance().namespace_dev, p.provenance().namespace_ino) { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        flock(&namespace, FlockOperation::NonBlockingLockExclusive).map_err(|_| ReviewStateError::LockUnavailable)?;
        let existing = openat(&namespace, REVIEW_STATE_FILE_NAME, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty());
        let file = match existing {
            Ok(fd) => {
                let read_file = File::from(fd); let id = regular(&fstat(&read_file)?, uid)?;
                if id.mode & 0o7777 == 0o400 { read_file } else {
                    let writable = File::from(openat(&namespace, REVIEW_STATE_FILE_NAME, OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?);
                    if regular(&fstat(&writable)?, uid)? != id { return Err(ReviewStateError::IdentityChanged); } writable
                }
            }
            Err(e) if e == rustix::io::Errno::NOENT => File::from(openat(&namespace, REVIEW_STATE_FILE_NAME,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR)?),
            Err(e) => return Err(e.into()),
        };
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| ReviewStateError::LockUnavailable)?;
        let id = regular(&fstat(&file)?, uid)?;
        let mut store = Self { parent: retained_parent, namespace, file, namespace_name: namespace_name.into(), uid,
            parent_identity: caller.key(), namespace_identity: ns.key(), file_identity: id,
            exact_bytes: Vec::new(), exact_hash: Sha256Digest::of(&[]), records: Vec::new(),
            provenance: p.provenance().clone(), highwater: ReviewHighwaterV1::default(), poisoned: false,
            qualified_finalizations: finalizations.iter().map(|f| (f.writer_commit_proof().clone(), f.review_finalization_binding().clone())).collect() };
        store.check_identity()?; store.load(p)?; store.check_exact()?;
        store.file.sync_all()?; store.namespace.sync_all()?; store.parent.sync_all()?;
        Ok(store)
    }
    /// Explicit reopen replays the entire bounded chain under the same retained
    /// namespace lock and revalidates signatures/profile/provenance, never a token.
    pub fn reopen(parent: &File, name: &str, p: &TrustedFixtureVerifier) -> Result<Self, ReviewStateError> { Self::open(parent, name, p) }
    pub fn highwater(&self) -> ReviewHighwaterV1 { self.highwater }
    pub fn lifecycle(&self, acceptance_digest: Sha256Digest) -> TaskReviewLifecycleState {
        for record in self.records.iter().rev() {
            match &record.event {
                EventV1::Consumed { outcome, .. } if outcome.acceptance_digest == acceptance_digest => return TaskReviewLifecycleState::AcceptedDone,
                EventV1::Reserved(r) if r.acceptance_digest == acceptance_digest => return TaskReviewLifecycleState::ReviewAttestedApproved,
                EventV1::Rejected { bundle, .. } if bundle.acceptance.payload.canonical_digest().ok() == Some(acceptance_digest) => return TaskReviewLifecycleState::RejectedByReviewer,
                _ => {}
            }
        }
        TaskReviewLifecycleState::NotSubmitted
    }
    fn check_identity(&self) -> Result<(), ReviewStateError> {
        if self.poisoned { return Err(ReviewStateError::Poisoned); }
        if directory(&self.parent, self.uid)?.key() != self.parent_identity || directory(&self.namespace, self.uid)?.key() != self.namespace_identity { return Err(ReviewStateError::IdentityChanged); }
        let named_ns = statat(&self.parent, self.namespace_name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(named_ns.st_mode) != FileType::Directory || Identity::from(&named_ns)?.key() != self.namespace_identity { return Err(ReviewStateError::IdentityChanged); }
        let fd = regular(&fstat(&self.file)?, self.uid)?;
        let named = regular(&statat(&self.namespace, REVIEW_STATE_FILE_NAME, AtFlags::SYMLINK_NOFOLLOW)?, self.uid)?;
        if fd != named || fd != self.file_identity { return Err(ReviewStateError::IdentityChanged); } Ok(())
    }
    fn check_exact(&mut self) -> Result<(), ReviewStateError> {
        self.check_identity()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut self.file).take(MAX_REVIEW_FILE_BYTES + 1).read_to_end(&mut bytes)?;
        self.check_identity()?;
        if bytes != self.exact_bytes || Sha256Digest::of(&bytes) != self.exact_hash { return Err(ReviewStateError::ContentChanged); } Ok(())
    }
    fn load(&mut self, p: &TrustedFixtureVerifier) -> Result<(), ReviewStateError> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut buffer = [0; 8192]; let mut line = Vec::new(); let mut total = 0_u64;
        loop {
            let count = self.file.read(&mut buffer)?; if count == 0 { break; }
            total = total.checked_add(count as u64).ok_or(ReviewStateError::FileTooLarge)?;
            if total > MAX_REVIEW_FILE_BYTES { return Err(ReviewStateError::FileTooLarge); }
            for byte in &buffer[..count] {
                if self.records.len() == MAX_REVIEW_RECORDS { return Err(ReviewStateError::TooManyRecords); }
                if *byte == b'\n' {
                    crate::task_write_journal::strict_json_object(&line, MAX_REVIEW_RECORD_BYTES - 1).map_err(|_| ReviewStateError::CorruptState)?;
                    let record: DiskRecordV1 = serde_json::from_slice(&line).map_err(|_| ReviewStateError::CorruptState)?;
                    // Exact serialization is required, so duplicate/alternate views cannot hide.
                    let encoded = encode_record(&record)?;
                    if encoded[..encoded.len()-1] != line { return Err(ReviewStateError::CorruptState); }
                    self.validate_next(p, &record)?;
                    self.highwater = event_highwater(&record.event).unwrap_or(self.highwater);
                    self.records.push(record); self.exact_bytes.extend(encoded); line.clear();
                } else {
                    if line.len() >= MAX_REVIEW_RECORD_BYTES - 1 { return Err(ReviewStateError::RecordTooLarge); }
                    line.push(*byte);
                }
            }
        }
        if !line.is_empty() { return Err(ReviewStateError::TruncatedState); }
        if total != self.file_identity.size { return Err(ReviewStateError::ContentChanged); }
        self.exact_hash = Sha256Digest::of(&self.exact_bytes); Ok(())
    }
    fn next_record(&self, event: EventV1) -> Result<DiskRecordV1, ReviewStateError> {
        let previous = match self.records.last() { Some(last) => Sha256Digest::of(&encode_record(last)?), None => Sha256Digest::of(&[]) };
        Ok(DiskRecordV1 { version: 1, sequence: self.records.len() as u64, previous, provenance: self.provenance.clone(), event })
    }
    fn assignment(&self, id: &str) -> Option<&SignedFixtureAssignmentV1> {
        self.records.iter().find_map(|r| match &r.event { EventV1::Assignment(a) if a.payload.assignment_id == id => Some(a), _ => None })
    }
    fn submissions(&self, id: &str) -> Vec<SignedFixtureSubmissionV1> {
        self.records.iter().filter_map(|r| match &r.event { EventV1::Submission { candidate, transition } if candidate.payload.assignment_id == id => Some(transition.clone()), _ => None }).collect()
    }
    fn validate_next(&self, p: &TrustedFixtureVerifier, record: &DiskRecordV1) -> Result<(), ReviewStateError> {
        let expected = self.next_record(record.event.clone())?;
        if record.version != 1 { return Err(ReviewStateError::UnsupportedRecord); }
        if record.sequence != expected.sequence || record.previous != expected.previous || record.provenance != self.provenance || p.provenance() != &record.provenance { return Err(ReviewStateError::CorruptState); }
        if let Some(h) = event_highwater(&record.event) { if !self.highwater.permits(h) { return Err(ReviewStateError::HighwaterRollback); } }
        match &record.event {
            EventV1::Assignment(a) => {
                acceptance::verify_assignment(p, a)?;
                if self.assignment(&a.payload.assignment_id).is_some() { return Err(ReviewStateError::ReplayConflict); }
            }
            EventV1::Submission { candidate, transition } => {
                let a = self.assignment(&candidate.payload.assignment_id).ok_or(ReviewStateError::MissingAssignment)?;
                let mut history = self.submissions(&candidate.payload.assignment_id); history.push(transition.clone());
                // A prefix may end in InProgress; validate it as a qualified chain
                // without pretending it is a review-ready pending snapshot.
                acceptance::verify_history_prefix(p, a, candidate, &history)?;
            }
            EventV1::Reserved(r) => {
                validate_request(&r.request)?;
                self.validate_retained(p, &r.bundle, &r.evidence, record_highwater(&r.bundle, &r.evidence))?;
                if r.approvals.is_empty() || r.approvals.len() > 64 || r.approvals[0] != (r.bundle.clone(), r.evidence.clone()) { return Err(ReviewStateError::CorruptState); }
                let mut principals = std::collections::BTreeSet::new(); let mut keys = std::collections::BTreeSet::new();
                let mut aggregate = ReviewHighwaterV1::default();
                for (b, e) in &r.approvals {
                    let h = record_highwater(b, e);
                    self.validate_retained(p, b, e, h)?;
                    if !self.highwater.permits(h) { return Err(ReviewStateError::HighwaterRollback); }
                    aggregate = merge_highwater(aggregate, h);
                    if e.authority != r.evidence.authority || b.acceptance.payload.candidate_digest != r.candidate_digest
                        || b.acceptance.payload.task_ref != r.bundle.acceptance.payload.task_ref || b.acceptance.payload.review_round != r.review_round
                        || b.review.verdict != ReviewVerdict::Approved || b.acceptance.payload.verdict != ReviewVerdict::Approved
                        || !principals.insert(&b.acceptance.payload.reviewer_principal) || !keys.insert(b.review.k1_pubkey) { return Err(ReviewStateError::ReplayConflict); }
                }
                if aggregate != r.highwater { return Err(ReviewStateError::HighwaterRollback); }
                if principals.len() < r.evidence.authority.payload.quorum as usize { return Err(ReviewStateError::InvalidTransition); }
                if r.bundle.acceptance.payload.verdict != ReviewVerdict::Approved || r.bundle.review.verdict != ReviewVerdict::Approved
                    || r.candidate_digest != r.bundle.candidate.payload.canonical_digest()?
                    || r.acceptance_digest != r.bundle.acceptance.payload.canonical_digest()?
                    || r.nonce != r.bundle.acceptance.payload.nonce || r.reviewer_principal != r.bundle.acceptance.payload.reviewer_principal
                    || r.review_round != r.bundle.acceptance.payload.review_round { return Err(ReviewStateError::CorruptState); }
                if self.find_reservation(r)?.is_some() { return Err(ReviewStateError::ReplayConflict); }
                crate::task_ref::check_cas_eligibility(&r.bundle.acceptance.payload.task_ref, &r.qualified_current, r.rebases_used as usize).map_err(AcceptanceError::from)?;
                if r.request.predecessor_file_rev != r.qualified_current.file_cas_rev
                    || r.request.original_operation_id != r.bundle.acceptance.payload.operation_id || r.request.assignment_id != r.bundle.acceptance.payload.assignment_id
                    || r.request.writer_epoch != r.highwater.writer_epoch || r.request.authority_epoch != r.highwater.authority_epoch { return Err(ReviewStateError::ReplayConflict); }
            }
            EventV1::Rejected { bundle, evidence, highwater } => {
                self.validate_retained(p, bundle, evidence, *highwater)?;
                if bundle.review.verdict != ReviewVerdict::Rejected || bundle.acceptance.payload.verdict != ReviewVerdict::Rejected { return Err(ReviewStateError::InvalidTransition); }
                if self.records.iter().any(|r| event_approvals(&r.event).iter().any(|old| replay_collision(old, bundle))) { return Err(ReviewStateError::ReplayConflict); }
            }
            EventV1::Consumed { reservation_digest: digest, outcome } => {
                let r = self.records.iter().find_map(|record| match &record.event { EventV1::Reserved(r) if reservation_digest(r).ok().as_ref() == Some(digest) => Some(r.as_ref()), _ => None }).ok_or(ReviewStateError::MissingSubmission)?;
                let qualified = self.qualified_finalizations.iter().find(|(_, binding)| binding.acceptance_digest == r.acceptance_digest
                    && binding.request_digest == r.request.request_digest).ok_or(ReviewStateError::ReconciliationRequired)?;
                validate_finalization(r, &self.provenance, &qualified.0, &qualified.1)?;
                if outcome != &expected_outcome(r, &self.provenance) { return Err(ReviewStateError::WriterProofMismatch); }
                if self.records.iter().any(|r| matches!(&r.event, EventV1::Consumed { reservation_digest, .. } if reservation_digest == digest)) { return Err(ReviewStateError::ReplayConflict); }
            }
        }
        Ok(())
    }
    fn validate_retained(&self, p: &TrustedFixtureVerifier, bundle: &SignedAcceptanceBundleV1, evidence: &FixtureVerificationEvidenceV1, highwater: ReviewHighwaterV1) -> Result<(), ReviewStateError> {
        let a = self.assignment(&bundle.candidate.payload.assignment_id).ok_or(ReviewStateError::MissingAssignment)?;
        let history = self.submissions(&a.payload.assignment_id);
        acceptance::verify_history(p, a, &bundle.candidate, &history, &bundle.acceptance.payload.task_ref)?;
        acceptance::verify_retained_fixture_record(p, bundle, evidence, highwater)?;
        Ok(())
    }
    fn append(&mut self, p: &TrustedFixtureVerifier, event: EventV1) -> Result<(), ReviewStateError> {
        self.check_exact()?;
        if self.file_identity.mode & 0o7777 != 0o600 { return Err(ReviewStateError::ReadOnly); }
        let record = self.next_record(event)?; self.validate_next(p, &record)?;
        let encoded = encode_record(&record)?;
        self.capacity(&encoded, &record.event)?;
        // Poison before the first byte; uncertain writes can only be reopened.
        self.poisoned = true;
        self.file.write_all(&encoded)?; self.file.sync_all()?; self.namespace.sync_all()?;
        self.file_identity = regular(&fstat(&self.file)?, self.uid)?;
        self.exact_bytes.extend(&encoded); self.exact_hash = Sha256Digest::of(&self.exact_bytes);
        self.highwater = event_highwater(&record.event).unwrap_or(self.highwater);
        self.records.push(record); self.poisoned = false; self.check_exact()?; Ok(())
    }
    fn capacity(&self, encoded: &[u8], event: &EventV1) -> Result<(), ReviewStateError> {
        let mut pending: usize = 0;
        for record in &self.records {
            if let EventV1::Reserved(r) = &record.event {
                let digest = reservation_digest(r)?;
                if !self.records.iter().any(|record| matches!(&record.event, EventV1::Consumed { reservation_digest, .. } if *reservation_digest == digest)) { pending += 1; }
            }
        }
        let pending_after = match event { EventV1::Reserved(_) => pending + 1, EventV1::Consumed { .. } => pending.saturating_sub(1), _ => pending };
        if self.records.len() + 1 + pending_after * COMPLETION_RECORD_RESERVE > MAX_REVIEW_RECORDS { return Err(ReviewStateError::TooManyRecords); }
        let reserved_bytes = pending_after as u64 * MAX_REVIEW_RECORD_BYTES as u64;
        if self.exact_bytes.len() as u64 + encoded.len() as u64 + reserved_bytes > MAX_REVIEW_FILE_BYTES { return Err(ReviewStateError::FileTooLarge); } Ok(())
    }
    pub fn record_assignment(&mut self, p: &TrustedFixtureVerifier, a: &SignedFixtureAssignmentV1) -> Result<(), ReviewStateError> {
        self.check_exact()?;
        if p.provenance() != &self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        acceptance::verify_assignment(p, a)?;
        if let Some(old) = self.assignment(&a.payload.assignment_id) { return if old == a { Ok(()) } else { Err(ReviewStateError::ReplayConflict) }; }
        self.append(p, EventV1::Assignment(a.clone()))
    }
    pub fn record_submission(&mut self, p: &TrustedFixtureVerifier, candidate: &SignedCandidateV1, transition: &SignedFixtureSubmissionV1) -> Result<(), ReviewStateError> {
        self.check_exact()?;
        if p.provenance() != &self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        acceptance::fixture_statement("bounded-submission", &(candidate, transition))?;
        for record in &self.records {
            if let EventV1::Submission { candidate: c, transition: t } = &record.event {
                if t.payload.next == transition.payload.next { return if c == candidate && t == transition { Ok(()) } else { Err(ReviewStateError::ReplayConflict) }; }
            }
        }
        self.append(p, EventV1::Submission { candidate: candidate.clone(), transition: transition.clone() })
    }
    fn find_reservation(&self, next: &ReservedV1) -> Result<Option<&ReservedV1>, ReviewStateError> {
        let mut found = None;
        for record in &self.records {
            if let EventV1::Reserved(old) = &record.event {
                if old.as_ref() == next { found = Some(old.as_ref()); continue; }
            }
            if event_approvals(&record.event).iter().any(|old| next.approvals.iter().any(|(b, _)| replay_collision(old, b))) {
                return Err(ReviewStateError::ReplayConflict);
            }
        }
        Ok(found)
    }
    fn require_exact_cohort(&self, r: &ReservedV1, tokens: &[VerifiedFixtureAcceptanceV1]) -> Result<(), ReviewStateError> {
        verify_fixture_quorum(tokens)?;
        if tokens.len() != r.approvals.len() || self.highwater != r.highwater { return Err(ReviewStateError::HighwaterRollback); }
        let mut aggregate = ReviewHighwaterV1::default();
        for t in tokens {
            let pair = (t.signed_bundle().clone(), t.evidence().clone());
            if !r.approvals.contains(&pair) || t.provenance() != &self.provenance
                || self.assignment(&r.request.assignment_id) != Some(t.assignment()) || self.submissions(&r.request.assignment_id) != t.history()
                || t.qualified_current() != &r.qualified_current || t.rebases_used() != r.rebases_used
                || t.highwater() != record_highwater(t.signed_bundle(), t.evidence()) { return Err(ReviewStateError::ReplayConflict); }
            aggregate = merge_highwater(aggregate, t.highwater());
        }
        if aggregate != r.highwater { return Err(ReviewStateError::HighwaterRollback); }
        Ok(())
    }
    /// Only an exact durable reserved cohort may use its authenticated prior
    /// boundary. ROOT must supply freshly qualified current observations here;
    /// historical signatures alone do not establish external host freshness.
    pub(crate) fn revalidate_reserved_cohort(&mut self, p: &TrustedFixtureVerifier, handle: &FixtureReservationV1,
        observed: &[(SignedAcceptanceBundleV1, FixtureVerificationEvidenceV1)], context: acceptance::AcceptanceVerificationContextV1<'_>)
        -> Result<Vec<VerifiedFixtureAcceptanceV1>, ReviewStateError> {
        self.check_exact()?;
        if handle.provenance != self.provenance || p.provenance() != &self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        let r = self.find_reservation(&handle.reservation)?.ok_or(ReviewStateError::MissingSubmission)?;
        if observed.len() != r.approvals.len() || observed.len() > 64 || self.highwater != r.highwater
            || context.persisted_highwater != self.highwater
            || observed.iter().any(|pair| !r.approvals.contains(pair)) { return Err(ReviewStateError::ReplayConflict); }
        if self.assignment(&r.request.assignment_id) != Some(context.assignment) || self.submissions(&r.request.assignment_id) != context.history
            || context.current != &r.qualified_current || context.rebases_used != r.rebases_used { return Err(ReviewStateError::ReplayConflict); }
        let mut prior = ReviewHighwaterV1::default();
        for record in &self.records {
            if matches!(&record.event, EventV1::Reserved(old) if old.as_ref() == r) { break; }
            prior = event_highwater(&record.event).unwrap_or(prior);
        }
        let tokens: Vec<_> = observed.iter().map(|(b, e)| acceptance::authorize_reviewed_acceptance(p, acceptance::LegacyReviewProfileMode::FixtureProfileV1, b, e,
            acceptance::AcceptanceVerificationContextV1 { snapshot: context.snapshot, current: context.current, assignment: context.assignment,
                history: context.history, dependencies: context.dependencies, rebases_used: context.rebases_used, persisted_highwater: prior }))
            .collect::<Result<_, _>>()?;
        self.require_exact_cohort(r, &tokens)?;
        Ok(tokens)
    }
    pub fn reserve(&mut self, p: &TrustedFixtureVerifier, tokens: &[VerifiedFixtureAcceptanceV1], request: ReviewReservationRequestV1) -> Result<ReservationDispositionV1, ReviewStateError> {
        self.check_exact()?; verify_fixture_quorum(tokens)?;
        if tokens.len() > 64 { return Err(ReviewStateError::RecordTooLarge); }
        let borrowed: Vec<_> = tokens.iter().map(|t| (t.signed_bundle(), t.evidence())).collect();
        acceptance::fixture_statement("bounded-durable-quorum", &borrowed)?;
        let t = tokens.first().ok_or(ReviewStateError::MissingSubmission)?;
        if t.provenance() != &self.provenance || p.provenance() != &self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        if self.assignment(&request.assignment_id) != Some(t.assignment()) || self.submissions(&request.assignment_id) != t.history() { return Err(ReviewStateError::MissingSubmission); }
        let a = &t.signed_bundle().acceptance.payload;
        let r = ReservedV1 { request, candidate_digest: t.candidate_digest()?, acceptance_digest: t.acceptance_digest()?, nonce: a.nonce,
            reviewer_principal: a.reviewer_principal.clone(), review_round: a.review_round, qualified_current: t.qualified_current().clone(), rebases_used: t.rebases_used(), bundle: t.signed_bundle().clone(), evidence: t.evidence().clone(),
            approvals: tokens.iter().map(|t| (t.signed_bundle().clone(), t.evidence().clone())).collect(),
            highwater: tokens.iter().fold(ReviewHighwaterV1::default(), |h, t| merge_highwater(h, t.highwater())) };
        if let Some(old) = self.find_reservation(&r)? {
            let digest = reservation_digest(old)?;
            if let Some(outcome) = self.records.iter().find_map(|record| match &record.event { EventV1::Consumed { reservation_digest, outcome } if *reservation_digest == digest => Some(outcome), _ => None }) { return Ok(ReservationDispositionV1::Consumed(outcome.clone())); }
            return Ok(ReservationDispositionV1::PendingOriginalOperation(FixtureReservationV1 { reservation: old.clone(), provenance: self.provenance.clone() }));
        }
        if tokens.iter().any(|t| !self.highwater.permits(t.highwater())) { return Err(ReviewStateError::HighwaterRollback); }
        let receipt = serde_json::to_vec(&expected_outcome(&r, &self.provenance)).map_err(|_| ReviewStateError::RecordTooLarge)?;
        if receipt.len() as u64 > r.request.maximum_outcome_bytes { return Err(ReviewStateError::RecordTooLarge); }
        let handle = FixtureReservationV1 { reservation: r.clone(), provenance: self.provenance.clone() };
        // Reservation and bounded completion capacity are durable before writer use.
        self.append(p, EventV1::Reserved(Box::new(r)))?;
        Ok(ReservationDispositionV1::Reserved(handle))
    }
    pub fn lookup_original(&mut self, operation: &str, acceptance_digest: Sha256Digest, request_digest: Sha256Digest) -> Result<Option<ReservationDispositionV1>, ReviewStateError> {
        self.check_exact()?;
        let r = self.records.iter().find_map(|record| match &record.event { EventV1::Reserved(r) if r.request.original_operation_id == operation => Some(r.as_ref()), _ => None });
        let Some(r) = r else { return Ok(None); };
        if r.acceptance_digest != acceptance_digest || r.request.request_digest != request_digest { return Err(ReviewStateError::ReplayConflict); }
        let digest = reservation_digest(r)?;
        if let Some(outcome) = self.records.iter().find_map(|record| match &record.event { EventV1::Consumed { reservation_digest, outcome } if *reservation_digest == digest => Some(outcome), _ => None }) { return Ok(Some(ReservationDispositionV1::Consumed(outcome.clone()))); }
        Ok(Some(ReservationDispositionV1::PendingOriginalOperation(FixtureReservationV1 { reservation: r.clone(), provenance: self.provenance.clone() })))
    }
    pub fn reject(&mut self, p: &TrustedFixtureVerifier, t: &VerifiedFixtureAcceptanceV1) -> Result<(), ReviewStateError> {
        self.check_exact()?;
        if p.provenance() != &self.provenance || t.provenance() != &self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        for record in &self.records {
            if let EventV1::Rejected { bundle, evidence, highwater } = &record.event {
                if bundle.as_ref() == t.signed_bundle() && evidence.as_ref() == t.evidence() && *highwater == t.highwater() { return Ok(()); }
            }
        }
        if t.provenance() != &self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        self.append(p, EventV1::Rejected { bundle: Box::new(t.signed_bundle().clone()), evidence: Box::new(t.evidence().clone()), highwater: t.highwater() })
    }
    /// Consumed requires the existing sealed original writer commit proof. The
    /// proof is issued by ROOT's writer only after durable projection recording.
    /// This API cannot issue that proof or invoke a replacement/ACK callback.
    pub fn consume(&mut self, p: &TrustedFixtureVerifier, handle: &FixtureReservationV1,
        revalidated: &[VerifiedFixtureAcceptanceV1], finalization: &dyn QualifiedReviewWriterFinalizationV1) -> Result<FixtureRecordedOutcomeV1, ReviewStateError> {
        self.check_exact()?; verify_fixture_quorum(revalidated)?;
        let proof = finalization.writer_commit_proof(); let joined = finalization.review_finalization_binding();
        let token = revalidated.first().ok_or(ReviewStateError::MissingSubmission)?;
        if handle.provenance != self.provenance || token.provenance() != &self.provenance || p.provenance() != &self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        let r = self.find_reservation(&handle.reservation)?.ok_or(ReviewStateError::MissingSubmission)?.clone();
        let digest = reservation_digest(&r)?;
        if let Some(outcome) = self.records.iter().find_map(|record| match &record.event { EventV1::Consumed { reservation_digest, outcome } if *reservation_digest == digest => Some(outcome), _ => None }) { return Ok(outcome.clone()); }
        self.require_exact_cohort(&r, revalidated)?;
        let q = &r.request;
        validate_finalization(&r, &self.provenance, proof, joined)?;
        let outcome = expected_outcome(&r, &self.provenance);
        let encoded_outcome = serde_json::to_vec(&outcome).map_err(|_| ReviewStateError::RecordTooLarge)?;
        if encoded_outcome.len() as u64 > q.maximum_outcome_bytes { return Err(ReviewStateError::RecordTooLarge); }
        self.qualified_finalizations.push((proof.clone(), joined.clone()));
        self.append(p, EventV1::Consumed { reservation_digest: digest, outcome: outcome.clone() })?;
        Ok(outcome)
    }
    /// ROOT can inspect the original state; a successor observation alone cannot
    /// mint a finalization proof or mark Consumed. Repair uses consume after join.
    pub fn reconcile(&mut self, handle: &FixtureReservationV1, observed_hash: Sha256Digest, observed_rev: u64) -> Result<ReconciliationDispositionV1, ReviewStateError> {
        self.check_exact()?;
        if handle.provenance != self.provenance { return Err(ReviewStateError::FixtureNamespaceMismatch); }
        let r = self.find_reservation(&handle.reservation)?.ok_or(ReviewStateError::MissingSubmission)?;
        let q = &r.request;
        if observed_hash == q.predecessor_sha256 && observed_rev == q.predecessor_file_rev { return Ok(ReconciliationDispositionV1::ResumeOriginalOperation); }
        if observed_hash == q.successor_sha256 && observed_rev == q.successor_file_rev { return Ok(ReconciliationDispositionV1::RepairOriginalConsumption); }
        Ok(ReconciliationDispositionV1::UnknownStateHeld)
    }
}
fn record_highwater(b: &SignedAcceptanceBundleV1, e: &FixtureVerificationEvidenceV1) -> ReviewHighwaterV1 {
    ReviewHighwaterV1 { authority_epoch: e.authority.payload.authority_epoch, writer_epoch: e.authority.payload.writer_epoch, roughtime_us: b.review.roughtime_midpoint_us }
}
fn merge_highwater(a: ReviewHighwaterV1, b: ReviewHighwaterV1) -> ReviewHighwaterV1 {
    ReviewHighwaterV1 { authority_epoch: a.authority_epoch.max(b.authority_epoch), writer_epoch: a.writer_epoch.max(b.writer_epoch), roughtime_us: a.roughtime_us.max(b.roughtime_us) }
}
fn replay_collision(a: &SignedAcceptanceBundleV1, b: &SignedAcceptanceBundleV1) -> bool {
    let a = &a.acceptance.payload; let b = &b.acceptance.payload;
    a.nonce == b.nonce || a.operation_id == b.operation_id
        || (a.reviewer_principal == b.reviewer_principal && a.review_round == b.review_round && a.task_ref.task_key() == b.task_ref.task_key())
}
fn event_approvals(e: &EventV1) -> Vec<&SignedAcceptanceBundleV1> {
    match e { EventV1::Reserved(r) => r.approvals.iter().map(|(b, _)| b).collect(), EventV1::Rejected { bundle, .. } => vec![bundle], _ => Vec::new() }
}
fn validate_request(q: &ReviewReservationRequestV1) -> Result<(), ReviewStateError> {
    for id in [&q.original_operation_id, &q.assignment_id, &q.target_transition_id] { validate_id(id, "review reservation").map_err(AcceptanceError::from)?; }
    if q.successor_file_rev != checked_next_revision(q.predecessor_file_rev).map_err(AcceptanceError::from)?
        || q.writer_epoch == 0 || q.authority_epoch == 0 || q.maximum_outcome_bytes < 1024 || q.maximum_outcome_bytes > 4096
        || q.predecessor_bytes == 0 || q.successor_bytes == 0 || q.predecessor_bytes > crate::task_source_path::MAX_SOURCE_FILE_BYTES
        || q.successor_bytes > crate::task_source_path::MAX_SOURCE_FILE_BYTES { return Err(ReviewStateError::InvalidTransition); } Ok(())
}
fn expected_outcome(r: &ReservedV1, provenance: &FixtureProvenanceV1) -> FixtureRecordedOutcomeV1 {
    FixtureRecordedOutcomeV1 { original_operation_id: r.request.original_operation_id.clone(), target_transition_id: r.request.target_transition_id.clone(),
        acceptance_digest: r.acceptance_digest, request_digest: r.request.request_digest,
        committed_postimage_sha256: r.request.successor_sha256, committed_file_rev: r.request.successor_file_rev,
        committed_bytes: r.request.successor_bytes, provenance: provenance.clone() }
}
fn event_highwater(e: &EventV1) -> Option<ReviewHighwaterV1> {
    match e { EventV1::Reserved(r) => Some(r.highwater), EventV1::Rejected { highwater, .. } => Some(*highwater), _ => None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_acceptance::fixtures::{Fixture, signed};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    struct DiskFixture { _root: tempfile::TempDir, parent: File, namespace: std::path::PathBuf, fixture: Fixture }
    impl DiskFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let namespace = root.path().join("fixture"); std::fs::create_dir(&namespace).unwrap();
            std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
            let metadata = namespace.metadata().unwrap(); let fixture = Fixture::new(metadata.dev(), metadata.ino());
            let parent = File::open(root.path()).unwrap(); Self { _root: root, parent, namespace, fixture }
        }
        fn open(&self) -> ReviewStateStoreV1 { ReviewStateStoreV1::open(&self.parent, "fixture", &self.fixture.provider).unwrap() }
        fn prepare(&self, store: &mut ReviewStateStoreV1) {
            store.record_assignment(&self.fixture.provider, &self.fixture.assignment).unwrap();
            for transition in &self.fixture.history { store.record_submission(&self.fixture.provider, &self.fixture.bundle.candidate, transition).unwrap(); }
        }
        fn reserve(&self, store: &mut ReviewStateStoreV1) -> FixtureReservationV1 {
            let token = self.fixture.verify(store.highwater()).unwrap();
            match store.reserve(&self.fixture.provider, &[token], request()).unwrap() { ReservationDispositionV1::Reserved(r) => r, _ => panic!("expected fresh fixture reservation") }
        }
    }
    fn request() -> ReviewReservationRequestV1 {
        ReviewReservationRequestV1 { original_operation_id: "original-operation".into(), assignment_id: "assignment".into(), target_transition_id: "fixture-transition".into(),
            request_digest: Sha256Digest::of(b"exact original writer request"), predecessor_sha256: Sha256Digest::of(b"pending"), successor_sha256: Sha256Digest::of(b"done"),
            predecessor_bytes: 7, successor_bytes: 4, predecessor_file_rev: 8, successor_file_rev: 9, writer_epoch: 3, authority_epoch: 2, maximum_outcome_bytes: 4096 }
    }
    #[test]
    fn p0_acceptance_durable_locked_concurrent_reservation_and_reopen_pending() {
        let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); let handle = f.reserve(&mut store);
        assert!(matches!(ReviewStateStoreV1::open(&f.parent, "fixture", &f.fixture.provider), Err(ReviewStateError::LockUnavailable)));
        assert_eq!(handle.require_production().unwrap_err().to_string(), ReviewStateError::FixtureNotProduction.to_string());
        let token = f.fixture.verify(store.highwater()).unwrap();
        assert!(matches!(store.reserve(&f.fixture.provider, &[token], request()).unwrap(), ReservationDispositionV1::PendingOriginalOperation(_)));
        let before = std::fs::read(f.namespace.join(REVIEW_STATE_FILE_NAME)).unwrap(); drop(store);
        let mut reopened = ReviewStateStoreV1::reopen(&f.parent, "fixture", &f.fixture.provider).unwrap();
        assert_eq!(reopened.highwater().roughtime_us, 100_000_000);
        assert!(matches!(reopened.lookup_original(handle.original_operation_id(), handle.acceptance_digest(), request().request_digest).unwrap(), Some(ReservationDispositionV1::PendingOriginalOperation(_))));
        assert_eq!(std::fs::read(f.namespace.join(REVIEW_STATE_FILE_NAME)).unwrap(), before);
        assert_eq!(reopened.reconcile(&handle, request().predecessor_sha256, 8).unwrap(), ReconciliationDispositionV1::ResumeOriginalOperation);
        assert_eq!(reopened.reconcile(&handle, request().successor_sha256, 9).unwrap(), ReconciliationDispositionV1::RepairOriginalConsumption);
        assert_eq!(reopened.reconcile(&handle, Sha256Digest([0; 32]), 9).unwrap(), ReconciliationDispositionV1::UnknownStateHeld);
        assert_eq!(reopened.lifecycle(handle.acceptance_digest()), TaskReviewLifecycleState::ReviewAttestedApproved);
    }
    #[test]
    fn p0_acceptance_durable_conflicting_request_nonce_candidate_and_round() {
        let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); let handle = f.reserve(&mut store);
        let token = f.fixture.verify(store.highwater()).unwrap();
        for case in 0..4 {
            let mut q = request(); match case { 0 => q.request_digest = Sha256Digest([0; 32]), 1 => q.target_transition_id = "substitute".into(), 2 => q.original_operation_id = "other".into(), _ => q.successor_sha256 = Sha256Digest([1; 32]) }
            assert!(matches!(store.reserve(&f.fixture.provider, &[token.clone()], q), Err(ReviewStateError::ReplayConflict)));
        }
        drop(store); let mut reopened = f.open();
        assert!(reopened.lookup_original(handle.original_operation_id(), Sha256Digest([0; 32]), request().request_digest).is_err());
    }
    #[test]
    fn p0_acceptance_forged_consumption_and_reopen_require_original_writer_proof() {
        let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); let handle = f.reserve(&mut store);
        let outcome = expected_outcome(&handle.reservation, &handle.provenance);
        let event = EventV1::Consumed { reservation_digest: reservation_digest(&handle.reservation).unwrap(), outcome: outcome.clone() };
        assert!(matches!(store.append(&f.fixture.provider, event.clone()), Err(ReviewStateError::ReconciliationRequired)));
        // Simulate a forged on-disk outcome with a correct hash chain: reopening
        // must still require the original ROOT writer/journal sealed finalization.
        let encoded = encode_record(&store.next_record(event).unwrap()).unwrap(); drop(store);
        let mut file = std::fs::OpenOptions::new().append(true).open(f.namespace.join(REVIEW_STATE_FILE_NAME)).unwrap();
        file.write_all(&encoded).unwrap(); file.sync_all().unwrap(); drop(file);
        assert!(matches!(ReviewStateStoreV1::reopen(&f.parent, "fixture", &f.fixture.provider), Err(ReviewStateError::ReconciliationRequired)));
        assert!(outcome.require_production().is_err());
    }
    #[test]
    fn p0_acceptance_durable_rejected_record_and_highwater_survive_reopen() {
        let mut f = DiskFixture::new(); f.fixture.bundle.review.verdict = ReviewVerdict::Rejected;
        f.fixture.bundle.acceptance.payload.verdict = ReviewVerdict::Rejected; f.fixture.refresh_signed_records();
        let mut store = f.open(); f.prepare(&mut store); let rejected = f.fixture.verify(Default::default()).unwrap();
        store.reject(&f.fixture.provider, &rejected).unwrap(); let digest = rejected.acceptance_digest().unwrap(); drop(store);
        let reopened = f.open(); assert_eq!(reopened.lifecycle(digest), TaskReviewLifecycleState::RejectedByReviewer);
        assert_eq!(reopened.highwater().authority_epoch, 2);
    }
    #[test]
    fn p0_acceptance_durable_corruption_truncation_duplicate_and_unknown_record() {
        for case in 0..5 {
            let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); f.reserve(&mut store); drop(store);
            let path = f.namespace.join(REVIEW_STATE_FILE_NAME); let mut bytes = std::fs::read(&path).unwrap();
            match case {
                0 => { bytes.pop(); }
                1 => { bytes[0] = b'!'; }
                2 => { let first = bytes.iter().position(|b| *b == b'\n').unwrap(); let line = bytes[..=first].to_vec(); bytes.extend(line); }
                3 => { let text = String::from_utf8(bytes).unwrap().replacen("\"version\":1", "\"version\":2", 1); bytes = text.into_bytes(); }
                _ => { let text = String::from_utf8(bytes).unwrap().replacen("\"version\":1", "\"version\":1,\"version\":1", 1); bytes = text.into_bytes(); }
            }
            std::fs::write(&path, bytes).unwrap(); assert!(ReviewStateStoreV1::reopen(&f.parent, "fixture", &f.fixture.provider).is_err(), "case {case}");
        }
    }
    #[test]
    fn p0_acceptance_durable_symlink_hardlink_private_modes_and_namespace_fence() {
        for case in 0..4 {
            let f = DiskFixture::new(); let store = f.open(); drop(store); let path = f.namespace.join(REVIEW_STATE_FILE_NAME);
            match case {
                0 => { let target = f.namespace.join("aliased"); std::fs::rename(&path, &target).unwrap(); symlink(&target, &path).unwrap(); }
                1 => std::fs::hard_link(&path, f.namespace.join("alias")).unwrap(),
                2 => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(),
                _ => std::fs::set_permissions(&f.namespace, std::fs::Permissions::from_mode(0o755)).unwrap(),
            }
            assert!(ReviewStateStoreV1::open(&f.parent, "fixture", &f.fixture.provider).is_err());
        }
        let f = DiskFixture::new(); let other = DiskFixture::new(); assert!(ReviewStateStoreV1::open(&other.parent, "fixture", &f.fixture.provider).is_err());
    }
    #[test]
    fn p0_acceptance_durable_readonly_exact_bytes_and_descriptor_replacement() {
        let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); drop(store);
        let path = f.namespace.join(REVIEW_STATE_FILE_NAME); std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let mut store = f.open(); let token = f.fixture.verify(Default::default()).unwrap(); assert!(matches!(store.reserve(&f.fixture.provider, &[token], request()), Err(ReviewStateError::ReadOnly))); drop(store);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut store = f.open(); let original = std::fs::read(&path).unwrap();
        std::fs::rename(&path, f.namespace.join("old")).unwrap(); std::fs::write(&path, original).unwrap(); std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.check_exact().is_err());
    }
    #[test]
    fn p0_acceptance_durable_record_file_count_and_completion_capacity_bounds() {
        let f = DiskFixture::new(); let store = f.open();
        let mut a = f.fixture.assignment.clone(); a.payload.author_principal = "x".repeat(MAX_REVIEW_RECORD_BYTES);
        let record = store.next_record(EventV1::Assignment(a)).unwrap(); assert!(matches!(encode_record(&record), Err(ReviewStateError::RecordTooLarge)));
        let oversized = File::create(f.namespace.join("oversized")).unwrap(); oversized.set_len(MAX_REVIEW_FILE_BYTES + 1).unwrap();
        std::fs::set_permissions(f.namespace.join("oversized"), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(regular(&fstat(&oversized).unwrap(), rustix::process::geteuid().as_raw()), Err(ReviewStateError::FileTooLarge)));
        assert_eq!(MAX_REVIEW_RECORD_BYTES, 65_536); assert_eq!(MAX_REVIEW_FILE_BYTES, 16_777_216); assert_eq!(MAX_REVIEW_RECORDS, 4096);
    }
    #[test]
    fn p0_acceptance_durable_reopened_assignment_history_cannot_substitute() {
        let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); drop(store); let mut store = f.open();
        let mut a = f.fixture.assignment.clone(); a.payload.overlay_commitment = None; a = signed("immutable-assignment", a.payload, 40);
        assert!(matches!(store.record_assignment(&f.fixture.provider, &a), Err(ReviewStateError::ReplayConflict)));
        let mut transition = f.fixture.history[0].clone(); transition.payload.candidate_digest = Sha256Digest([9; 32]); transition = signed("qualified-submission-transition", transition.payload, 40);
        assert!(store.record_submission(&f.fixture.provider, &f.fixture.bundle.candidate, &transition).is_err());
    }
    #[test]
    fn p0_acceptance_durable_highwater_rollback_and_fixture_provenance_cannot_be_relabelled() {
        let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); let handle = f.reserve(&mut store);
        let mut rollback = handle.reservation.clone(); rollback.highwater.roughtime_us -= 1;
        let record = store.next_record(EventV1::Reserved(Box::new(rollback))).unwrap();
        assert!(matches!(store.validate_next(&f.fixture.provider, &record), Err(ReviewStateError::HighwaterRollback)));
        drop(store);
        let path = f.namespace.join(REVIEW_STATE_FILE_NAME); let original = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, original.replacen("FixtureProfileV1", "ProductionHeld", 1)).unwrap();
        assert!(ReviewStateStoreV1::reopen(&f.parent, "fixture", &f.fixture.provider).is_err());
    }
    #[test]
    fn p0_acceptance_durable_completion_space_reserved_before_writer_effect() {
        let f = DiskFixture::new(); let mut store = f.open(); f.prepare(&mut store); let handle = f.reserve(&mut store);
        let event = EventV1::Reserved(Box::new(handle.reservation.clone()));
        let record = store.next_record(event.clone()).unwrap(); let encoded = encode_record(&record).unwrap();
        let filler = store.records[0].clone(); store.records.resize(MAX_REVIEW_RECORDS - 1, filler);
        assert!(matches!(store.capacity(&encoded, &event), Err(ReviewStateError::TooManyRecords)));
        store.records.truncate(3); store.exact_bytes.resize(MAX_REVIEW_FILE_BYTES as usize - MAX_REVIEW_RECORD_BYTES, 0);
        assert!(matches!(store.capacity(&encoded, &event), Err(ReviewStateError::FileTooLarge)));
    }

    fn rejected(f: &mut DiskFixture) -> VerifiedFixtureAcceptanceV1 {
        f.fixture.bundle.review.verdict = ReviewVerdict::Rejected;
        f.fixture.bundle.acceptance.payload.verdict = ReviewVerdict::Rejected;
        f.fixture.refresh_signed_records();
        f.fixture.verify(Default::default()).unwrap()
    }
    fn quorum_second(f: &mut DiskFixture) -> Fixture {
        f.fixture.evidence.authority.payload.quorum = 2; f.fixture.resign_authority();
        let ns = f.namespace.metadata().unwrap(); let mut other = Fixture::new(ns.dev(), ns.ino());
        other.evidence.authority = f.fixture.evidence.authority.clone();
        other.bundle.review.reviewer_id = "reviewer-two".into();
        other.bundle.review.k1_pubkey = crate::task_acceptance::fixtures::key(3);
        other.bundle.review.roughtime_midpoint_us = 105_000_000;
        other.bundle.acceptance.payload.reviewer_principal = "reviewer-two".into();
        other.bundle.acceptance.payload.reviewer_full_instance = "REVIEW2#fixture".into();
        other.bundle.acceptance.payload.nonce = [9; 32];
        other.evidence.scope.payload.reviewer_principal = "reviewer-two".into();
        other.evidence.scope.payload.reviewer_instance = "REVIEW2#fixture".into();
        other.evidence.scope.payload.nonce = [9; 32];
        for t in &mut other.evidence.time { t.payload.nonce = [9; 32]; t.payload.midpoint_us = 105_000_000; }
        other.refresh_reviewer(3); other
    }
    fn context<'a>(f: &'a Fixture, highwater: ReviewHighwaterV1) -> acceptance::AcceptanceVerificationContextV1<'a> {
        acceptance::AcceptanceVerificationContextV1 { snapshot: &f.snapshot, current: &f.current, assignment: &f.assignment,
            history: &f.history, dependencies: &[], rebases_used: 0, persisted_highwater: highwater }
    }
    #[test]
    fn p0_acceptance_rejected_exact_replay_and_resigned_conflict_live_and_reopen() {
        let mut f = DiskFixture::new(); let original = rejected(&mut f);
        let mut store = f.open(); f.prepare(&mut store); store.reject(&f.fixture.provider, &original).unwrap();
        let path = f.namespace.join(REVIEW_STATE_FILE_NAME); let before = std::fs::read(&path).unwrap();
        store.reject(&f.fixture.provider, &original).unwrap(); assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(store); let mut store = f.open(); store.reject(&f.fixture.provider, &original).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        f.fixture.bundle.acceptance.payload.expires_at_unix = 111; f.fixture.refresh_signed_records();
        let changed = f.fixture.verify(store.highwater()).unwrap();
        assert!(matches!(store.reject(&f.fixture.provider, &changed), Err(ReviewStateError::ReplayConflict)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let event = EventV1::Rejected { bundle: Box::new(changed.signed_bundle().clone()), evidence: Box::new(changed.evidence().clone()), highwater: changed.highwater() };
        let bytes = encode_record(&store.next_record(event).unwrap()).unwrap(); drop(store);
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap(); file.write_all(&bytes).unwrap(); file.sync_all().unwrap(); drop(file);
        assert!(matches!(ReviewStateStoreV1::reopen(&f.parent, "fixture", &f.fixture.provider), Err(ReviewStateError::ReplayConflict)));
    }
    #[test]
    fn p0_acceptance_reserved_rejected_replay_conflict_is_symmetric() {
        for reject_first in [false, true] {
            let mut f = DiskFixture::new(); let approved = f.fixture.verify(Default::default()).unwrap();
            let rejection = rejected(&mut f); let mut store = f.open(); f.prepare(&mut store);
            if reject_first { store.reject(&f.fixture.provider, &rejection).unwrap(); }
            else { store.reserve(&f.fixture.provider, &[approved.clone()], request()).unwrap(); }
            let path = f.namespace.join(REVIEW_STATE_FILE_NAME); let before = std::fs::read(&path).unwrap();
            if reject_first { assert!(matches!(store.reserve(&f.fixture.provider, &[approved], request()), Err(ReviewStateError::ReplayConflict))); }
            else { assert!(matches!(store.reject(&f.fixture.provider, &rejection), Err(ReviewStateError::ReplayConflict))); }
            assert_eq!(std::fs::read(&path).unwrap(), before); drop(store); f.open();
        }
    }
    #[test]
    fn p0_acceptance_quorum_highwater_order_independent_reopen_and_exact_revalidation() {
        for reverse in [false, true] {
            let mut f = DiskFixture::new(); let mut other = quorum_second(&mut f); let mut store = f.open(); f.prepare(&mut store);
            let mut tokens = vec![f.fixture.verify(Default::default()).unwrap(), other.verify(Default::default()).unwrap()];
            if reverse { tokens.reverse(); }
            let handle = match store.reserve(&f.fixture.provider, &tokens, request()).unwrap() { ReservationDispositionV1::Reserved(h) => h, _ => panic!("new reservation") };
            assert_eq!(store.highwater().roughtime_us, 105_000_000); drop(store); let mut store = f.open();
            assert_eq!(store.highwater().roughtime_us, 105_000_000);
            let before = std::fs::read(f.namespace.join(REVIEW_STATE_FILE_NAME)).unwrap();
            let observed = handle.reservation.approvals.clone();
            let h = store.highwater(); let revalidated = store.revalidate_reserved_cohort(&f.fixture.provider, &handle, &observed, context(&f.fixture, h)).unwrap();
            store.require_exact_cohort(&handle.reservation, &revalidated).unwrap();
            assert_eq!(std::fs::read(f.namespace.join(REVIEW_STATE_FILE_NAME)).unwrap(), before);
            other.bundle.review.roughtime_midpoint_us = 102_000_000;
            for t in &mut other.evidence.time { t.payload.midpoint_us = 102_000_000; }
            other.refresh_reviewer(3); assert!(other.verify(store.highwater()).is_err());
        }
    }
    #[test]
    fn p0_acceptance_reserved_cohort_changed_authority_time_or_members_held() {
        let mut f = DiskFixture::new(); let other = quorum_second(&mut f); let mut store = f.open(); f.prepare(&mut store);
        let tokens = vec![f.fixture.verify(Default::default()).unwrap(), other.verify(Default::default()).unwrap()];
        let handle = match store.reserve(&f.fixture.provider, &tokens, request()).unwrap() { ReservationDispositionV1::Reserved(h) => h, _ => panic!("new reservation") };
        for change in 0..5 {
            let mut observed = handle.reservation.approvals.clone();
            match change {
                0 => { for (_, e) in &mut observed { e.authority.payload.authority_epoch += 1; e.authority = signed("current-authority", e.authority.payload.clone(), 40); } }
                1 => { observed[0].1.time[0].payload.response_elapsed_ms += 1; observed[0].1.time[0] = signed("roughtime-response", observed[0].1.time[0].payload.clone(), 6); }
                2 => { observed.pop(); }
                3 => { observed[1] = observed[0].clone(); }
                _ => { observed[0].1.authority.payload.principals[1].revoked = true; observed[0].1.authority = signed("current-authority", observed[0].1.authority.payload.clone(), 40); }
            }
            if change < 2 {
                let valid: Vec<_> = observed.iter().map(|(b, e)| acceptance::authorize_reviewed_acceptance(&f.fixture.provider, acceptance::LegacyReviewProfileMode::FixtureProfileV1, b, e, context(&f.fixture, Default::default())).unwrap()).collect();
                verify_fixture_quorum(&valid).unwrap(); assert!(store.require_exact_cohort(&handle.reservation, &valid).is_err());
            }
            let h = store.highwater(); assert!(store.revalidate_reserved_cohort(&f.fixture.provider, &handle, &observed, context(&f.fixture, h)).is_err(), "change {change}");
        }
        let original_h = store.highwater; store.highwater.roughtime_us += 1;
        let h = store.highwater(); assert!(store.revalidate_reserved_cohort(&f.fixture.provider, &handle, &handle.reservation.approvals, context(&f.fixture, h)).is_err());
        store.highwater = original_h;
    }
    #[test]
    fn p0_acceptance_reopen_refuses_forged_first_only_quorum_highwater() {
        let mut f = DiskFixture::new(); let other = quorum_second(&mut f); let mut store = f.open(); f.prepare(&mut store);
        let tokens = vec![f.fixture.verify(Default::default()).unwrap(), other.verify(Default::default()).unwrap()];
        let handle = match store.reserve(&f.fixture.provider, &tokens, request()).unwrap() { ReservationDispositionV1::Reserved(h) => h, _ => panic!("new reservation") };
        let mut records = store.records.clone(); drop(store);
        let mut r = handle.reservation; r.highwater.roughtime_us = 100_000_000;
        records.last_mut().unwrap().event = EventV1::Reserved(Box::new(r));
        let bytes: Vec<_> = records.iter().flat_map(|record| encode_record(record).unwrap()).collect();
        std::fs::write(f.namespace.join(REVIEW_STATE_FILE_NAME), bytes).unwrap();
        assert!(matches!(ReviewStateStoreV1::reopen(&f.parent, "fixture", &f.fixture.provider), Err(ReviewStateError::HighwaterRollback)));
    }

    fn another_task(mut f: Fixture) -> Fixture {
        f.assignment.payload.assignment_id = "another-assignment".into(); f.assignment.payload.operation_id = "another-operation".into();
        f.assignment.payload.original_task_ref.task_id = "ANOTHER".into();
        f.assignment = signed("immutable-assignment", f.assignment.payload.clone(), 40);
        f.current.task_id = "ANOTHER".into(); f.snapshot.task_id = "ANOTHER".into();
        f.bundle.candidate.payload.original_assignment_task_ref = f.assignment.payload.original_task_ref.clone();
        f.bundle.candidate.payload.assignment_id = "another-assignment".into(); f.bundle.candidate.payload.operation_id = "another-operation".into();
        f.bundle.candidate.author_k1 = crate::task_acceptance::fixtures::signature(1, &f.bundle.candidate.payload.canonical_bytes().unwrap());
        let digest = f.bundle.candidate.payload.canonical_digest().unwrap();
        for t in &mut f.history {
            t.payload.assignment_id = "another-assignment".into(); t.payload.operation_id = "another-operation".into();
            t.payload.prior = f.assignment.payload.original_task_ref.clone(); t.payload.next = f.current.clone();
            t.payload.assignment_record_digest = acceptance::assignment_digest(&f.assignment).unwrap(); t.payload.candidate_digest = digest;
            *t = signed("qualified-submission-transition", t.payload.clone(), 40);
        }
        f.bundle.review.task_id = "ANOTHER".into(); f.bundle.review.assignment_id = "another-assignment".into(); f.bundle.review.operation_id = "another-operation".into();
        f.bundle.acceptance.payload.task_ref = f.current.clone(); f.bundle.acceptance.payload.assignment_id = "another-assignment".into();
        f.bundle.acceptance.payload.operation_id = "another-operation".into(); f.bundle.acceptance.payload.candidate_digest = digest;
        f.bundle.review.verdict = ReviewVerdict::Rejected; f.bundle.acceptance.payload.verdict = ReviewVerdict::Rejected;
        f.refresh_reviewer(3); f
    }
    #[test]
    fn p0_acceptance_secondary_quorum_nonce_conflict_and_distinct_decision() {
        let mut f = DiskFixture::new(); let mut other = another_task(quorum_second(&mut f));
        let mut store = f.open(); f.prepare(&mut store); let second = quorum_second(&mut f);
        let tokens = vec![f.fixture.verify(Default::default()).unwrap(), second.verify(Default::default()).unwrap()];
        store.reserve(&f.fixture.provider, &tokens, request()).unwrap();
        store.record_assignment(&f.fixture.provider, &other.assignment).unwrap();
        for t in &other.history { store.record_submission(&f.fixture.provider, &other.bundle.candidate, t).unwrap(); }
        let conflicting = other.verify(store.highwater()).unwrap();
        assert!(!replay_collision(tokens[0].signed_bundle(), conflicting.signed_bundle()));
        assert!(replay_collision(tokens[1].signed_bundle(), conflicting.signed_bundle()));
        let path = f.namespace.join(REVIEW_STATE_FILE_NAME); let before = std::fs::read(&path).unwrap();
        assert!(matches!(store.reject(&f.fixture.provider, &conflicting), Err(ReviewStateError::ReplayConflict)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        other.bundle.acceptance.payload.nonce = [10; 32]; other.evidence.scope.payload.nonce = [10; 32];
        for t in &mut other.evidence.time { t.payload.nonce = [10; 32]; }
        other.refresh_reviewer(3); let distinct = other.verify(store.highwater()).unwrap();
        store.reject(&f.fixture.provider, &distinct).unwrap(); drop(store); f.open();
    }
    #[test]
    fn p0_acceptance_each_quorum_member_must_pass_prior_water_guard() {
        let mut f = DiskFixture::new(); let second = quorum_second(&mut f);
        f.fixture.bundle.review.roughtime_midpoint_us = 99_000_000;
        for t in &mut f.fixture.evidence.time { t.payload.midpoint_us = 99_000_000; }
        f.fixture.refresh_signed_records();
        let tokens = vec![f.fixture.verify(Default::default()).unwrap(), second.verify(Default::default()).unwrap()];
        let mut store = f.open(); f.prepare(&mut store);
        // Isolate the state guard with a supplied prior boundary; this is not a
        // claim that the following scalar itself proves a durable observation.
        store.highwater = ReviewHighwaterV1 { authority_epoch: 2, writer_epoch: 3, roughtime_us: 100_000_000 };
        let path = f.namespace.join(REVIEW_STATE_FILE_NAME); let before = std::fs::read(&path).unwrap();
        assert!(matches!(store.reserve(&f.fixture.provider, &tokens, request()), Err(ReviewStateError::HighwaterRollback)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

}

fn validate_finalization(r: &ReservedV1, provenance: &FixtureProvenanceV1, proof: &WriterCommitProof, joined: &ReviewWriterFinalizationBindingV1) -> Result<(), ReviewStateError> {
    let q = &r.request; let a = &r.bundle.acceptance.payload;
        if joined.request_digest != q.request_digest || joined.acceptance_digest != r.acceptance_digest
            || joined.candidate_digest != r.candidate_digest || joined.target_transition_id != q.target_transition_id
            || joined.target_status != crate::task_writer::CanonicalTaskStatus::Done
            || joined.target_task_status_rev != checked_next_revision(a.expected_task_status_rev).map_err(AcceptanceError::from)?
            || joined.fixture_provenance != *provenance
            || proof.operation_id() != q.original_operation_id || proof.workspace_id() != a.task_ref.workspace_id
            || proof.repo_id() != a.task_ref.repo_id || proof.task_source_id() != a.task_ref.task_source_id
            || proof.canonical_relative_path() != a.task_ref.canonical_task_path || proof.source_generation() != a.task_ref.source_generation
            || proof.writer_epoch() != q.writer_epoch || proof.authority_epoch() != q.authority_epoch
            || proof.writer_principal() != r.evidence.authority.payload.writer_principal
            || proof.expected_file_cas_rev() != q.predecessor_file_rev || proof.committed_file_cas_rev() != q.successor_file_rev
            || proof.expected_preimage_sha256() != &q.predecessor_sha256.0 || proof.committed_postimage_sha256() != &q.successor_sha256.0
            || proof.expected_preimage_bytes() != q.predecessor_bytes || proof.committed_postimage_bytes() != q.successor_bytes {
            return Err(ReviewStateError::WriterProofMismatch);
        }
    Ok(())
}
