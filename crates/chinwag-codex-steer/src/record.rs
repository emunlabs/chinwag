use serde::{Deserialize, Serialize};

pub const MAX_OPERATIONS: usize = 128;
pub const MAX_TEXT_BYTES: usize = 8192;
pub(crate) const OPERATION_SCHEMA: &str = "chinwag-codex-steer-operation/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SteerError {
    #[error("invalid bounded human steer input")]
    InvalidInput,
    #[error("this owner has not granted human control of the target")]
    PermissionDenied,
    #[error("no active turn was observed on this owned connection")]
    NoActiveTurn,
    #[error("the captured active turn changed; select the current target")]
    StaleTarget,
    #[error("a frame write is active; no automatic queue or replay is available")]
    Busy,
    #[error("the retained operation capacity is exhausted")]
    Capacity,
    #[error("private steer persistence is unavailable; original files are retained")]
    Storage,
    #[error("this steer operation ID is already bound to different input")]
    Conflict,
    #[error("the owned steering transport is unavailable")]
    Unavailable,
    #[error("the original steer outcome is unknown; do not resend automatically")]
    Uncertain,
    #[error("the protocol owner must handle an unsupported server request")]
    OwnerInterventionRequired,
}

/// Immutable consumed operation data. These fields are observations, not a
/// deserializable control grant. Only the controller can commit a wire attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSteer {
    pub schema: String,
    pub id: String,
    pub transport_epoch: String,
    pub thread_id: String,
    pub expected_turn_id: String,
    pub text: String,
}

impl SavedSteer {
    pub(crate) fn validate(&self) -> super::Result<()> {
        if self.schema != OPERATION_SCHEMA
            || !valid_operation_id(&self.id)
            || self.transport_epoch.len() != 32
            || !self
                .transport_epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !valid_target_id(&self.thread_id)
            || !valid_target_id(&self.expected_turn_id)
            || !valid_text(&self.text)
        {
            return Err(SteerError::InvalidInput);
        }
        Ok(())
    }
}

/// Independent protocol facts. No field means the model saw or applied input.
/// `write_uncertain` records uncertainty, including before later acceptance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub frame_written: bool,
    pub write_uncertain: bool,
    pub not_dispatched: bool,
    pub core_accepted: bool,
    pub harness_recorded: bool,
    pub peer_error_observed: bool,
}

impl Evidence {
    pub(crate) fn merged(self, other: Self) -> super::Result<Self> {
        let value = Self {
            frame_written: self.frame_written || other.frame_written,
            write_uncertain: self.write_uncertain || other.write_uncertain,
            not_dispatched: self.not_dispatched || other.not_dispatched,
            core_accepted: self.core_accepted || other.core_accepted,
            harness_recorded: self.harness_recorded || other.harness_recorded,
            peer_error_observed: self.peer_error_observed || other.peer_error_observed,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> super::Result<()> {
        if self.not_dispatched
            && (self.frame_written
                || self.write_uncertain
                || self.core_accepted
                || self.harness_recorded
                || self.peer_error_observed)
        {
            Err(SteerError::InvalidInput)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation: SavedSteer,
    pub evidence: Evidence,
    pub recovered_after_restart: bool,
    pub persistence_failed: bool,
}

pub(crate) fn valid_operation_id(value: &str) -> bool {
    (16..=100).contains(&value.len()) && valid_target_id(value)
}

pub(crate) fn valid_target_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

pub(crate) fn valid_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
