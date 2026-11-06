#![forbid(unsafe_code)]
#![cfg(target_os = "macos")]

//! Review lifecycle and bounded replay fences for the P0-06 library surface.
//!
//! These checks bind an independently authenticated review to the pending task.
//! They neither perform a writer commit nor supply durable replay persistence.

use crate::agent_instance::ActorAddress;
use crate::task_acceptance::{ReviewAttestationV1, TaskAcceptanceV1, TaskCandidateV1};
use crate::task_ref::{
    CasEligibility, GitOid, MAX_UNRELATED_FILE_REBASES, Sha256Digest, TaskContractError, TaskRefV1,
    check_cas_eligibility, checked_next_revision, validate_id, validate_task_source_id,
    validate_workspace_id,
};
use crate::task_writer::{CanonicalTaskStatus, TaskEntrySnapshotV1};
use std::fmt;

pub const MAX_ACCEPTANCE_PAYLOAD_UTF8_BYTES: usize = 65_536;
pub const MAX_EVIDENCE_DIGESTS_PER_CANDIDATE: usize = 64;
pub const MAX_REQUIRED_CHECKS_PER_ATTESTATION: usize = 64;
pub const MAX_VERIFICATION_CHECKS_PASSED: usize = 64;
pub const MAX_FINDINGS_PER_ATTESTATION: usize = 64;
pub const MAX_DISPLAY_TEXT_UTF8_BYTES: usize = 4096;
pub const MAX_REPLAY_LEDGER_ENTRIES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewStateError {
    SelfReviewForbidden,
    UnauthorizedReviewerRole,
    UnauthorizedWriterPrincipal,
    StaleTaskSpecDigest,
    ArtifactCommitmentMismatch,
    ForbiddenExecutionFlag,
    PolicyCommitmentMismatch,
    TargetTaskRevisionConflict,
    RebaseLimitExceeded,
    TargetTaskMutated,
    VerificationChecksMismatch,
    ActorCommitmentMismatch,
    ReplayPayloadConflict,
    ReplayLedgerFull,
    InvalidTransition,
    InvalidActor,
    Contract(TaskContractError),
}

impl fmt::Display for ReviewStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task review rejected: {self:?}")
    }
}

impl std::error::Error for ReviewStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TaskContractError> for ReviewStateError {
    fn from(error: TaskContractError) -> Self {
        Self::Contract(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskReviewLifecycleState {
    NotSubmitted,
    CandidateSubmitted,
    ReviewAttestedPass,
    ChangesRequested,
    RejectedByReviewer,
    InvalidatedStale,
    AcceptedDone,
    HeldConflict,
}

impl TaskReviewLifecycleState {
    pub const fn can_transition(self, next: Self) -> bool {
        use TaskReviewLifecycleState::*;
        matches!(
            (self, next),
            (NotSubmitted, CandidateSubmitted | InvalidatedStale | HeldConflict)
                | (CandidateSubmitted, ReviewAttestedPass | ChangesRequested | RejectedByReviewer | InvalidatedStale | HeldConflict)
                | (ReviewAttestedPass, AcceptedDone | InvalidatedStale | HeldConflict)
                | (ChangesRequested | RejectedByReviewer | InvalidatedStale, CandidateSubmitted | HeldConflict)
        )
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        self.can_transition(next)
    }

    pub fn transition_to(&mut self, next: Self) -> Result<(), ReviewStateError> {
        if !self.can_transition(next) {
            return Err(ReviewStateError::InvalidTransition);
        }
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskReviewStateRecord {
    pub state: TaskReviewLifecycleState,
    pub active_candidate_digest: Option<Sha256Digest>,
    pub active_attestation_digest: Option<Sha256Digest>,
    pub task_status_rev: Option<u64>,
    pub snapshot: Option<TaskEntrySnapshotV1>,
}

impl TaskReviewStateRecord {
    pub fn new() -> Self {
        Self {
            state: TaskReviewLifecycleState::NotSubmitted,
            active_candidate_digest: None,
            active_attestation_digest: None,
            task_status_rev: None,
            snapshot: None,
        }
    }

    pub fn transition_to(&mut self, next: TaskReviewLifecycleState) -> Result<(), ReviewStateError> {
        self.state.transition_to(next)
    }
}

impl Default for TaskReviewStateRecord {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewerRolePolicy {
    pub authorized_reviewer_seats: Vec<String>,
    /// A canonical seat grants that writer seat; a full address pins an instance.
    pub expected_writer_principal: String,
}

fn canonical_actor(raw: &str) -> Result<ActorAddress, ReviewStateError> {
    let actor = ActorAddress::parse(raw)
        .and_then(ActorAddress::require_instance)
        .map_err(|_| ReviewStateError::InvalidActor)?;
    if actor.is_human() || actor.seat() == "ALL" || actor.instance().is_none()
        || actor.to_string() != raw
    {
        return Err(ReviewStateError::InvalidActor);
    }
    Ok(actor)
}

fn canonical_policy_principal(raw: &str) -> Option<ActorAddress> {
    ActorAddress::parse(raw).ok().filter(|actor| {
        !actor.is_human() && actor.seat() != "ALL" && actor.to_string() == raw
    })
}

/// Actor labels must agree with the authenticated keys supplied by the caller.
/// Another conversation instance of a seat is never an independent reviewer.
pub fn verify_separation_of_duties(
    snapshot: &TaskEntrySnapshotV1,
    candidate: &TaskCandidateV1,
    attestation: &ReviewAttestationV1,
    acceptance: &TaskAcceptanceV1,
    policy: &ReviewerRolePolicy,
    implementer_public_key: &[u8; 32],
    reviewer_public_key: &[u8; 32],
) -> Result<(), ReviewStateError> {
    let implementer = canonical_actor(&candidate.implementer_actor)?;
    let attested_implementer = canonical_actor(&attestation.implementer_actor)?;
    let accepted_implementer = canonical_actor(&acceptance.implementer_actor)?;
    let reviewer = canonical_actor(&attestation.reviewer_actor)?;
    let accepted_reviewer = canonical_actor(&acceptance.reviewer_actor)?;
    let writer = canonical_actor(&acceptance.writer_actor)?;
    let owner = snapshot.owner_actor.as_deref()
        .ok_or(ReviewStateError::TargetTaskRevisionConflict)?;
    canonical_actor(owner)?;
    if owner != candidate.implementer_actor {
        return Err(ReviewStateError::TargetTaskRevisionConflict);
    }
    if implementer != attested_implementer || implementer != accepted_implementer
        || reviewer != accepted_reviewer
    {
        return Err(ReviewStateError::ActorCommitmentMismatch);
    }
    if reviewer.seat() == implementer.seat()
        || implementer_public_key == reviewer_public_key
    {
        return Err(ReviewStateError::SelfReviewForbidden);
    }
    if snapshot.reviewer_role.is_empty()
        || candidate.reviewer_role != snapshot.reviewer_role
        || attestation.reviewer_role != snapshot.reviewer_role
        || acceptance.reviewer_role != snapshot.reviewer_role
        || policy.authorized_reviewer_seats.is_empty()
        || policy.authorized_reviewer_seats.len() > MAX_REQUIRED_CHECKS_PER_ATTESTATION
    {
        return Err(ReviewStateError::UnauthorizedReviewerRole);
    }
    let mut reviewer_allowed = false;
    for raw in &policy.authorized_reviewer_seats {
        let allowed = canonical_policy_principal(raw)
            .filter(|actor| actor.instance().is_none())
            .ok_or(ReviewStateError::UnauthorizedReviewerRole)?;
        reviewer_allowed |= allowed.seat() == reviewer.seat();
    }
    if !reviewer_allowed {
        return Err(ReviewStateError::UnauthorizedReviewerRole);
    }
    let expected_writer = canonical_policy_principal(&policy.expected_writer_principal)
        .ok_or(ReviewStateError::UnauthorizedWriterPrincipal)?;
    if writer.seat() == implementer.seat()
        || writer.seat() != expected_writer.seat()
        || (expected_writer.instance().is_some() && expected_writer != writer)
    {
        return Err(ReviewStateError::UnauthorizedWriterPrincipal);
    }
    Ok(())
}

fn zero_commit(commit: GitOid) -> bool {
    match commit {
        GitOid::Sha1(bytes) => bytes == [0; 20],
        GitOid::Sha256(bytes) => bytes == [0; 32],
    }
}

/// Revalidates the original, immutable review commitments against current state.
/// `rebases_used` includes the proposed rebase: 1 and 2 are admitted, 3 is held.
pub fn verify_candidate_and_attestation_freshness(
    snapshot: &TaskEntrySnapshotV1,
    current_ref: &TaskRefV1,
    rebases_used: u8,
    candidate: &TaskCandidateV1,
    attestation: &ReviewAttestationV1,
    acceptance: &TaskAcceptanceV1,
    forbidden_flags: &[String],
) -> Result<CasEligibility, ReviewStateError> {
    if candidate.evidence_digests.len() > MAX_EVIDENCE_DIGESTS_PER_CANDIDATE
        || attestation.evidence_digests.len() > MAX_EVIDENCE_DIGESTS_PER_CANDIDATE
        || acceptance.evidence_digests.len() > MAX_EVIDENCE_DIGESTS_PER_CANDIDATE
    {
        return Err(TaskContractError::LimitExceeded("review evidence digests").into());
    }
    if attestation.required_checks.len() > MAX_REQUIRED_CHECKS_PER_ATTESTATION
        || candidate.verification_checks_passed.len() > MAX_VERIFICATION_CHECKS_PASSED
        || acceptance.verification_checks_passed.len() > MAX_VERIFICATION_CHECKS_PASSED
    {
        return Err(TaskContractError::LimitExceeded("review verification checks").into());
    }
    let admitted = &candidate.task_ref;
    admitted.validate()?;
    current_ref.validate()?;
    attestation.reviewed_task_ref.validate()?;
    acceptance.task_ref.validate()?;
    if snapshot.status != CanonicalTaskStatus::DonePendingReview
        || snapshot.task_status_rev != admitted.task_status_rev
        || current_ref.task_status_rev != admitted.task_status_rev
        || attestation.reviewed_task_ref.task_status_rev != admitted.task_status_rev
        || acceptance.task_ref.task_status_rev != admitted.task_status_rev
        || acceptance.accepted_from_task_status_rev != snapshot.task_status_rev
        || acceptance.committed_task_status_rev != checked_next_revision(snapshot.task_status_rev)?
    {
        return Err(ReviewStateError::TargetTaskRevisionConflict);
    }
    if snapshot.task_spec_digest != admitted.task_spec_digest
        || current_ref.task_spec_digest != admitted.task_spec_digest
        || attestation.reviewed_task_ref.task_spec_digest != admitted.task_spec_digest
        || acceptance.task_ref.task_spec_digest != admitted.task_spec_digest
    {
        return Err(ReviewStateError::StaleTaskSpecDigest);
    }
    if current_ref.baseline_commit != admitted.baseline_commit
        || attestation.reviewed_task_ref.baseline_commit != admitted.baseline_commit
        || acceptance.task_ref.baseline_commit != admitted.baseline_commit
    {
        return Err(ReviewStateError::ArtifactCommitmentMismatch);
    }
    if snapshot.task_id != admitted.task_id
        || attestation.reviewed_task_ref != *admitted
        || acceptance.task_ref != *admitted
    {
        return Err(ReviewStateError::TargetTaskMutated);
    }
    if snapshot.task_control_digest != candidate.task_control_digest
        || snapshot.task_control_digest != attestation.reviewed_task_control_digest
        || snapshot.task_control_digest != acceptance.task_control_digest
        || snapshot.completion_policy_digest != candidate.completion_policy_digest
        || snapshot.completion_policy_digest != attestation.completion_policy_digest
        || snapshot.completion_policy_digest != acceptance.completion_policy_digest
    {
        return Err(ReviewStateError::PolicyCommitmentMismatch);
    }
    if snapshot.baseline_commit != admitted.baseline_commit
        || candidate.baseline_commit != admitted.baseline_commit
        || attestation.baseline_commit != admitted.baseline_commit
        || acceptance.baseline_commit != admitted.baseline_commit
        || snapshot.candidate_commit != Some(candidate.candidate_commit)
        || attestation.candidate_commit != candidate.candidate_commit
        || acceptance.candidate_commit != candidate.candidate_commit
        || snapshot.overlay_digest != candidate.overlay_digest
        || attestation.overlay_digest != candidate.overlay_digest
        || acceptance.overlay_digest != candidate.overlay_digest
        || snapshot.execution_flags != candidate.execution_flags
        || attestation.execution_flags != candidate.execution_flags
        || acceptance.execution_flags != candidate.execution_flags
        || attestation.evidence_digests != candidate.evidence_digests
        || acceptance.evidence_digests != candidate.evidence_digests
        || zero_commit(candidate.baseline_commit)
        || zero_commit(candidate.candidate_commit)
    {
        return Err(ReviewStateError::ArtifactCommitmentMismatch);
    }
    if candidate.execution_flags.iter().any(|flag| forbidden_flags.contains(flag)) {
        return Err(ReviewStateError::ForbiddenExecutionFlag);
    }
    if acceptance.verification_checks_passed != candidate.verification_checks_passed
        || candidate.verification_checks_passed.iter().any(|check| {
            !attestation.required_checks.iter().any(|result| &result.check_id == check)
        })
    {
        return Err(ReviewStateError::VerificationChecksMismatch);
    }
    if attestation.candidate_operation_id != candidate.operation_id
        || acceptance.candidate_operation_id != candidate.operation_id
        || attestation.candidate_digest != candidate.canonical_digest()
        || acceptance.candidate_digest != candidate.canonical_digest()
        || acceptance.attestation_id != attestation.attestation_id
        || acceptance.attestation_digest != attestation.canonical_digest()
    {
        return Err(ReviewStateError::ArtifactCommitmentMismatch);
    }
    let file_cas_delta = current_ref.file_cas_rev.checked_sub(admitted.file_cas_rev)
        .ok_or(ReviewStateError::TargetTaskMutated)?;
    if usize::from(rebases_used) > MAX_UNRELATED_FILE_REBASES
        || file_cas_delta > MAX_UNRELATED_FILE_REBASES as u64
        || file_cas_delta > u64::from(rebases_used)
    {
        return Err(ReviewStateError::RebaseLimitExceeded);
    }
    // task_ref's budget counts completed rebases before the impending attempt;
    // this API counts the attempt itself, so translate the inclusive budget.
    let previous_rebases = if admitted.file_cas_rev != current_ref.file_cas_rev {
        usize::from(rebases_used).saturating_sub(1)
    } else {
        0
    };
    check_cas_eligibility(admitted, current_ref, previous_rebases).map_err(|error| match error {
        TaskContractError::TaskStatusConflict => ReviewStateError::TargetTaskRevisionConflict,
        TaskContractError::RebaseLimitExceeded => ReviewStateError::RebaseLimitExceeded,
        TaskContractError::AcceptanceInvalidated | TaskContractError::IdentityConflict
            | TaskContractError::FileRevisionConflict => ReviewStateError::TargetTaskMutated,
        other => ReviewStateError::Contract(other),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayEntryV1 {
    pub workspace_id: String,
    pub task_source_id: String,
    pub operation_id: String,
    pub signer_principal: String,
    pub message_id: String,
    pub canonical_digest_sha256: Sha256Digest,
}

impl ReplayEntryV1 {
    fn validate(&self) -> Result<(), ReviewStateError> {
        validate_workspace_id(&self.workspace_id)?;
        validate_task_source_id(&self.task_source_id)?;
        validate_id(&self.operation_id, "operation_id")?;
        validate_id(&self.message_id, "message_id")?;
        let principal = Sha256Digest::from_hex(&self.signer_principal)?;
        if self.signer_principal.len() != 64 || principal.to_string() != self.signer_principal {
            return Err(TaskContractError::InvalidField("signer_principal").into());
        }
        Ok(())
    }

    fn same_operation(&self, other: &Self) -> bool {
        self.workspace_id == other.workspace_id
            && self.task_source_id == other.task_source_id
            && self.operation_id == other.operation_id
    }

    fn same_message(&self, other: &Self) -> bool {
        self.workspace_id == other.workspace_id
            && self.signer_principal == other.signer_principal
            && self.message_id == other.message_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayDisposition {
    Fresh,
    IdempotentDuplicate,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReviewReplayLedger {
    entries: Vec<ReplayEntryV1>,
}

impl ReviewReplayLedger {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Checks both scoped indexes before adding any member of the batch.
    /// Identical digest aliases are retained under both indexes so a retry
    /// cannot leave a new message key available for a conflicting payload.
    pub fn record_batch(
        &mut self,
        entries: &[ReplayEntryV1],
        state: &mut TaskReviewStateRecord,
    ) -> Result<ReplayDisposition, ReviewStateError> {
        if entries.len() > MAX_REPLAY_LEDGER_ENTRIES {
            return Err(ReviewStateError::ReplayLedgerFull);
        }
        if entries.is_empty() {
            return Err(ReviewStateError::Contract(TaskContractError::InvalidField("replay_batch")));
        }
        let mut duplicate_count = 0;
        for (index, entry) in entries.iter().enumerate() {
            entry.validate()?;
            let mut duplicate = false;
            for previous in self.entries.iter().chain(entries[..index].iter()) {
                if previous.same_operation(entry) || previous.same_message(entry) {
                    if previous.canonical_digest_sha256 != entry.canonical_digest_sha256 {
                        // A conflict holds future effects even after a committed
                        // outcome; retained digests and revision remain intact.
                        state.state = TaskReviewLifecycleState::HeldConflict;
                        return Err(ReviewStateError::ReplayPayloadConflict);
                    }
                    duplicate = true;
                }
            }
            if duplicate {
                duplicate_count += 1;
            }
        }
        if duplicate_count != 0 && duplicate_count != entries.len() {
            state.state = TaskReviewLifecycleState::HeldConflict;
            return Err(ReviewStateError::ReplayPayloadConflict);
        }
        let additions = entries.iter().enumerate().filter(|(index, entry)| {
            !self.entries.contains(entry) && !entries[..*index].contains(entry)
        }).count();
        if additions > MAX_REPLAY_LEDGER_ENTRIES.saturating_sub(self.entries.len()) {
            return Err(ReviewStateError::ReplayLedgerFull);
        }
        for entry in entries {
            if !self.entries.contains(entry) {
                self.entries.push(entry.clone());
            }
        }
        Ok(if duplicate_count == entries.len() {
            ReplayDisposition::IdempotentDuplicate
        } else {
            ReplayDisposition::Fresh
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(index: usize) -> ReplayEntryV1 {
        ReplayEntryV1 {
            workspace_id: "workspace".to_owned(),
            task_source_id: "0123456789abcdef0123456789abcdef".to_owned(),
            operation_id: format!("operation-{index}"),
            signer_principal: Sha256Digest([7; 32]).to_string(),
            message_id: format!("message-{index}"),
            canonical_digest_sha256: Sha256Digest::of(index.to_string().as_bytes()),
        }
    }

    #[test]
    fn p0_acceptance_review_transition_matrix_is_closed() {
        use TaskReviewLifecycleState::*;
        let states = [NotSubmitted, CandidateSubmitted, ReviewAttestedPass, ChangesRequested,
            RejectedByReviewer, InvalidatedStale, AcceptedDone, HeldConflict];
        let edges = [(NotSubmitted, CandidateSubmitted), (NotSubmitted, InvalidatedStale), (NotSubmitted, HeldConflict),
            (CandidateSubmitted, ReviewAttestedPass), (CandidateSubmitted, ChangesRequested),
            (CandidateSubmitted, RejectedByReviewer), (CandidateSubmitted, InvalidatedStale),
            (CandidateSubmitted, HeldConflict), (ReviewAttestedPass, AcceptedDone),
            (ReviewAttestedPass, InvalidatedStale), (ReviewAttestedPass, HeldConflict),
            (ChangesRequested, CandidateSubmitted), (ChangesRequested, HeldConflict),
            (RejectedByReviewer, CandidateSubmitted), (RejectedByReviewer, HeldConflict),
            (InvalidatedStale, CandidateSubmitted), (InvalidatedStale, HeldConflict)];
        for from in states {
            for to in states {
                let mut actual = from;
                assert_eq!(from.can_transition(to), edges.contains(&(from, to)));
                assert_eq!(actual.transition_to(to).is_ok(), edges.contains(&(from, to)));
                assert_eq!(actual, if edges.contains(&(from, to)) { to } else { from });
            }
        }
    }

    #[test]
    fn p0_acceptance_done_requires_pass_and_conflict_cannot_escape() {
        use TaskReviewLifecycleState::*;
        for from in [NotSubmitted, CandidateSubmitted, ChangesRequested, RejectedByReviewer,
            InvalidatedStale, AcceptedDone, HeldConflict]
        {
            assert!(!from.can_transition(AcceptedDone));
        }
        let mut state = TaskReviewStateRecord::new();
        state.transition_to(CandidateSubmitted).unwrap();
        state.transition_to(ReviewAttestedPass).unwrap();
        state.transition_to(AcceptedDone).unwrap();
        assert_eq!(state.transition_to(HeldConflict), Err(ReviewStateError::InvalidTransition));
        assert!(!HeldConflict.can_transition(CandidateSubmitted));
    }

    #[test]
    fn p0_acceptance_review_record_default_is_unsubmitted_and_clone_isolated() {
        let state = TaskReviewStateRecord::default();
        assert_eq!(state.state, TaskReviewLifecycleState::NotSubmitted);
        assert!(state.active_candidate_digest.is_none());
        assert!(state.active_attestation_digest.is_none());
        assert!(state.task_status_rev.is_none());
        assert!(state.snapshot.is_none());
        let mut staged = state.clone();
        staged.transition_to(TaskReviewLifecycleState::CandidateSubmitted).unwrap();
        assert_eq!(state.state, TaskReviewLifecycleState::NotSubmitted);
    }

    #[test]
    fn p0_acceptance_actor_requires_exact_nonhuman_instance() {
        assert!(canonical_actor("REVIEWER#one").is_ok());
        for raw in ["REVIEWER", "reviewer#one", "@REVIEWER#one", " REVIEWER#one",
            "REVIEWER#one ", "Brian", "Brian#one", "Nic#one", "ALL", "ALL#one"]
        {
            assert_eq!(canonical_actor(raw), Err(ReviewStateError::InvalidActor));
        }
        assert_eq!(canonical_actor("REVIEWER#one").unwrap().seat(),
            canonical_actor("REVIEWER#two").unwrap().seat());
    }

    #[test]
    fn p0_acceptance_replay_batch_is_fresh_then_idempotent() {
        let mut ledger = ReviewReplayLedger::default();
        let mut state = TaskReviewStateRecord::new();
        let batch = [entry(1), entry(2), entry(3)];
        assert!(ledger.is_empty());
        assert_eq!(ledger.record_batch(&batch, &mut state), Ok(ReplayDisposition::Fresh));
        assert_eq!(ledger.len(), 3);
        let before = ledger.clone();
        assert_eq!(ledger.record_batch(&batch, &mut state), Ok(ReplayDisposition::IdempotentDuplicate));
        assert_eq!(ledger, before);
        assert_eq!(state.state, TaskReviewLifecycleState::NotSubmitted);
    }

    #[test]
    fn p0_acceptance_replay_operation_conflict_holds_without_partial_insert() {
        let mut ledger = ReviewReplayLedger::default();
        let mut state = TaskReviewStateRecord::new();
        ledger.record_batch(&[entry(1)], &mut state).unwrap();
        let before = ledger.clone();
        let mut changed = entry(1);
        changed.canonical_digest_sha256 = Sha256Digest::of(b"changed");
        assert_eq!(ledger.record_batch(&[entry(2), changed], &mut state),
            Err(ReviewStateError::ReplayPayloadConflict));
        assert_eq!(ledger, before);
        assert_eq!(state.state, TaskReviewLifecycleState::HeldConflict);
    }

    #[test]
    fn p0_acceptance_replay_message_index_spans_sources_and_operations() {
        let mut ledger = ReviewReplayLedger::default();
        let mut state = TaskReviewStateRecord::new();
        ledger.record_batch(&[entry(1)], &mut state).unwrap();
        let mut changed = entry(2);
        changed.task_source_id = "fedcba9876543210fedcba9876543210".to_owned();
        changed.message_id = entry(1).message_id;
        assert_eq!(ledger.record_batch(&[changed], &mut state),
            Err(ReviewStateError::ReplayPayloadConflict));
        assert_eq!(ledger.len(), 1);
        assert_eq!(state.state, TaskReviewLifecycleState::HeldConflict);
    }

    #[test]
    fn p0_acceptance_replay_alias_cannot_hide_a_second_index_conflict() {
        let mut ledger = ReviewReplayLedger::default();
        let mut state = TaskReviewStateRecord::new();
        ledger.record_batch(&[entry(1), entry(2)], &mut state).unwrap();
        let mut retained_alias = entry(1);
        retained_alias.message_id = "alias-message".to_owned();
        assert_eq!(ledger.record_batch(&[retained_alias], &mut state),
            Ok(ReplayDisposition::IdempotentDuplicate));
        assert_eq!(ledger.len(), 3);
        let mut alias = entry(1);
        alias.message_id = entry(2).message_id;
        assert_eq!(ledger.record_batch(&[alias], &mut state),
            Err(ReviewStateError::ReplayPayloadConflict));
        assert_eq!(ledger.len(), 3);
        let mut changed = entry(3);
        changed.message_id = "alias-message".to_owned();
        assert_eq!(ledger.record_batch(&[changed], &mut state),
            Err(ReviewStateError::ReplayPayloadConflict));
        assert_eq!(ledger.len(), 3);
        assert_eq!(state.state, TaskReviewLifecycleState::HeldConflict);
    }

    #[test]
    fn p0_acceptance_replay_mixed_duplicate_and_fresh_batch_is_atomic_conflict() {
        let mut ledger = ReviewReplayLedger::default();
        let mut state = TaskReviewStateRecord::new();
        ledger.record_batch(&[entry(1)], &mut state).unwrap();
        assert_eq!(ledger.record_batch(&[entry(1), entry(2)], &mut state),
            Err(ReviewStateError::ReplayPayloadConflict));
        assert_eq!(ledger.len(), 1);
        assert_eq!(state.state, TaskReviewLifecycleState::HeldConflict);
    }

    #[test]
    fn p0_acceptance_replay_ledger_bound_keeps_exact_retry_available() {
        let mut ledger = ReviewReplayLedger::default();
        let mut state = TaskReviewStateRecord::new();
        let entries: Vec<_> = (0..MAX_REPLAY_LEDGER_ENTRIES).map(entry).collect();
        assert_eq!(ledger.record_batch(&entries, &mut state), Ok(ReplayDisposition::Fresh));
        assert_eq!(ledger.len(), MAX_REPLAY_LEDGER_ENTRIES);
        assert_eq!(ledger.record_batch(&[entry(MAX_REPLAY_LEDGER_ENTRIES)], &mut state),
            Err(ReviewStateError::ReplayLedgerFull));
        assert_eq!(ledger.record_batch(&[entry(0)], &mut state),
            Ok(ReplayDisposition::IdempotentDuplicate));
        assert_eq!(ledger.len(), MAX_REPLAY_LEDGER_ENTRIES);
        let mut oversized = entries;
        oversized.push(entry(MAX_REPLAY_LEDGER_ENTRIES));
        assert_eq!(ledger.record_batch(&oversized, &mut state), Err(ReviewStateError::ReplayLedgerFull));
        assert_eq!(state.state, TaskReviewLifecycleState::NotSubmitted);
    }
}
