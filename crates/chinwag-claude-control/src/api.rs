use serde::{Deserialize, Serialize};
use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tokio::sync::watch;
pub const MAX_TEXT_BYTES: usize = 8192;
pub const MAX_OPERATIONS: usize = 128;
pub const CLI_VERSION: &str = "2.1.314";
pub type Result<T> = std::result::Result<T, ClaudeError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaudeError {
    #[error("invalid bounded human Claude input")]
    InvalidInput,
    #[error("the human control scope or action expired")]
    PermissionDenied,
    #[error("no session has been observed on this owned child")]
    NoSession,
    #[error("the captured owned session changed")]
    StaleSession,
    #[error("a submission is in flight; no automatic queue is provided")]
    Busy,
    #[error("the retained operation capacity is full")]
    Capacity,
    #[error("private receipt persistence is unavailable")]
    Storage,
    #[error("the operation ID is already consumed for different input")]
    Conflict,
    #[error("the declared owned Claude runtime is unavailable")]
    Unavailable,
    #[error("the original outcome is unknown; do not resend automatically")]
    Uncertain,
    #[error("the owner must handle an unsupported runtime request")]
    OwnerInterventionRequired,
}
#[derive(Clone, Copy)]
pub enum StartupPolicyDeclaration {
    ManagedPolicyProseOnly,
}
#[derive(Clone)]
pub struct WorkConfig {
    pub(crate) binary: PathBuf,
    pub(crate) sha256: String,
    pub(crate) workdir: PathBuf,
    pub(crate) journal: PathBuf,
}
impl WorkConfig {
    pub fn new(
        binary: &Path,
        sha256: &str,
        workdir: &Path,
        journal: &Path,
        _policy: StartupPolicyDeclaration,
    ) -> Result<Self> {
        if !valid_path(binary)
            || !valid_path(workdir)
            || !valid_path(journal)
            || !valid_hash(sha256)
            || binary == journal
            || workdir == journal
        {
            return Err(ClaudeError::InvalidInput);
        }
        Ok(Self {
            binary: binary.into(),
            sha256: sha256.into(),
            workdir: workdir.into(),
            journal: journal.into(),
        })
    }
    pub fn folder_label(&self) -> String {
        self.workdir
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| n.len() <= 120 && !n.chars().any(char::is_control))
            .unwrap_or("Selected work folder")
            .into()
    }
}
pub(crate) fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path
            .to_str()
            .is_some_and(|s| !s.chars().any(char::is_control))
        && path
            .components()
            .all(|p| matches!(p, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
        && path.file_name().is_some()
}
pub(crate) fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(n, b)| {
            if [8, 13, 18, 23].contains(&n) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub(crate) fn valid_text(s: &str) -> bool {
    !s.trim().is_empty()
        && s.len() <= MAX_TEXT_BYTES
        && !s
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
pub fn new_operation_id() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| ClaudeError::Unavailable)?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputTiming {
    Now,
    AfterTools,
    AfterTurn,
}
impl InputTiming {
    pub(crate) fn wire(self) -> &'static str {
        match self {
            Self::Now => "now",
            Self::AfterTools => "next",
            Self::AfterTurn => "later",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Start,
    Direction,
    Lookup,
    EndInput,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkPhase {
    Ready,
    Starting,
    Working,
    Idle,
    OutcomeUnknown,
    OwnerActionRequired,
    InputEnded,
    Exited,
    Unavailable,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputEvidence {
    pub frame_written: bool,
    pub write_uncertain: bool,
    pub not_dispatched: bool,
    pub user_replayed: bool,
    pub reply_correlated: bool,
    pub result_correlated: bool,
    pub peer_error_observed: bool,
}
impl InputEvidence {
    pub(crate) fn merged(self, other: Self) -> Result<Self> {
        let v = Self {
            frame_written: self.frame_written || other.frame_written,
            write_uncertain: self.write_uncertain || other.write_uncertain,
            not_dispatched: self.not_dispatched || other.not_dispatched,
            user_replayed: self.user_replayed || other.user_replayed,
            reply_correlated: self.reply_correlated || other.reply_correlated,
            result_correlated: self.result_correlated || other.result_correlated,
            peer_error_observed: self.peer_error_observed || other.peer_error_observed,
        };
        v.validate()?;
        Ok(v)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.not_dispatched
            && (self.frame_written
                || self.write_uncertain
                || self.user_replayed
                || self.reply_correlated
                || self.result_correlated
                || self.peer_error_observed)
        {
            Err(ClaudeError::InvalidInput)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupRecord {
    pub binary: PathBuf,
    pub sha256: String,
    pub workdir: PathBuf,
    pub policy: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedInput {
    pub schema: String,
    pub id: String,
    pub session_epoch: String,
    pub session_id: String,
    pub kind: ActionKind,
    pub timing: InputTiming,
    pub text: String,
    pub startup: Option<StartupRecord>,
}
impl SavedInput {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != "chinwag-claude-input/v1"
            || !valid_uuid(&self.id)
            || !valid_uuid(&self.session_epoch)
            || !valid_uuid(&self.session_id)
            || !valid_text(&self.text)
            || !matches!(self.kind, ActionKind::Start | ActionKind::Direction)
        {
            return Err(ClaudeError::InvalidInput);
        }
        match (&self.kind, &self.startup) {
            (ActionKind::Start, Some(s))
                if valid_path(&s.binary)
                    && valid_path(&s.workdir)
                    && valid_hash(&s.sha256)
                    && s.policy == "managed_policy_prose_only"
                    && self.timing == InputTiming::Now => {}
            (ActionKind::Direction, None) => {}
            _ => return Err(ClaudeError::InvalidInput),
        };
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation: SavedInput,
    pub evidence: InputEvidence,
    pub recovered_after_restart: bool,
    pub persistence_failed: bool,
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LifecycleFacts {
    pub stdin_ended: bool,
    pub stdout_eof: bool,
    pub stderr_eof: bool,
    pub child_exited: bool,
    pub exit_code: Option<i32>,
    pub reader_joined: bool,
    pub stderr_joined: bool,
    pub child_wait_joined: bool,
}
#[derive(Debug, Clone)]
pub struct ObservedSession {
    pub(crate) identity: Arc<()>,
    pub(crate) epoch: String,
    pub(crate) session_id: String,
    pub(crate) generation: u64,
}
impl ObservedSession {
    pub fn session_epoch(&self) -> &str {
        &self.epoch
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
#[derive(Debug, Clone)]
pub struct WorkSubmission {
    pub id: String,
    pub kind: ActionKind,
    pub saved: bool,
    pub error: Option<ClaudeError>,
}
#[derive(Debug, Clone)]
pub struct WorkSnapshot {
    pub phase: WorkPhase,
    pub folder_label: String,
    pub start: Option<Receipt>,
    pub inputs: Vec<Receipt>,
    pub session: Option<ObservedSession>,
    pub agent_text: Option<String>,
    pub last_submission: Option<WorkSubmission>,
    pub lifecycle: LifecycleFacts,
    pub revision: u64,
}
impl WorkSnapshot {
    pub fn ready(folder_label: String) -> Self {
        Self {
            phase: WorkPhase::Ready,
            folder_label,
            start: None,
            inputs: Vec::new(),
            session: None,
            agent_text: None,
            last_submission: None,
            lifecycle: LifecycleFacts::default(),
            revision: 0,
        }
    }
}

/// Read-only captured human input; data summaries cannot recreate its authority.
pub struct PreparedDirection {
    pub(crate) target: ObservedSession,
    pub(crate) operation: SavedInput,
    pub(crate) deadline: Instant,
    pub(crate) sequence: u64,
}
impl PreparedDirection {
    pub fn operation(&self) -> &SavedInput {
        &self.operation
    }
    pub fn captured_sequence(&self) -> u64 {
        self.sequence
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

pub trait HumanWorkPort: Send + Sync {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot>;
    fn start(&self, id: &str, text: &str) -> Result<()>;
    fn direction(
        &self,
        target: &ObservedSession,
        id: &str,
        text: &str,
        timing: InputTiming,
    ) -> Result<()>;
    fn prepare_direction(
        &self,
        _target: &ObservedSession,
        _id: &str,
        _text: &str,
        _timing: InputTiming,
        _deadline: Instant,
    ) -> Result<PreparedDirection> {
        Err(ClaudeError::Unavailable)
    }
    fn submit_prepared_direction(&self, _prepared: PreparedDirection) -> Result<()> {
        Err(ClaudeError::Unavailable)
    }
    fn lookup(&self, id: &str) -> Result<()>;
    fn end_input(&self) -> Result<()>;
}
