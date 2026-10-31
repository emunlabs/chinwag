use serde::{Deserialize, Serialize};
use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tokio::sync::watch;
pub const MAX_TEXT_BYTES: usize = 8192;
pub const MAX_OPERATIONS: usize = 128;
pub const CLI_VERSION: &str = "0.66.0";
pub type Result<T> = std::result::Result<T, GeminiError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GeminiError {
    #[error("invalid bounded human Gemini input")]
    InvalidInput,
    #[error("the human control scope or action expired")]
    PermissionDenied,
    #[error("no fresh session has been observed on this owned child")]
    NoSession,
    #[error("the captured owned session or prompt changed")]
    StaleTarget,
    #[error("a submission or prompt is in flight; no automatic queue is provided")]
    Busy,
    #[error("the retained operation capacity is full")]
    Capacity,
    #[error("private receipt persistence is unavailable")]
    Storage,
    #[error("the operation ID is consumed for different input")]
    Conflict,
    #[error("the declared owned Gemini runtime is unavailable")]
    Unavailable,
    #[error("the original outcome is unknown; do not resend automatically")]
    Uncertain,
    #[error("this owned runtime needs an explicit owner action")]
    OwnerInterventionRequired,
}
#[derive(Clone, Copy)]
pub enum StartupPolicyDeclaration {
    ConfiguredRuntimeEffectsManualModeExtensionsDisabled,
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
            return Err(GeminiError::InvalidInput);
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
pub(crate) fn valid_path(p: &Path) -> bool {
    p.is_absolute()
        && p.as_os_str().len() <= 4096
        && p.to_str().is_some_and(|s| !s.chars().any(char::is_control))
        && p.components()
            .all(|x| matches!(x, Component::RootDir | Component::Normal(_)))
        && p.components().collect::<PathBuf>().as_os_str() == p.as_os_str()
        && p.file_name().is_some()
}
pub(crate) fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub(crate) fn valid_text(s: &str) -> bool {
    let trimmed = s.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    !trimmed.trim().is_empty()
        && !trimmed.starts_with(['/', '$'])
        && s.len() <= MAX_TEXT_BYTES
        && !s
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
pub(crate) fn valid_rpc(s: &str) -> bool {
    s.strip_prefix("prompt-").is_some_and(valid_uuid)
}
pub fn new_operation_id() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| GeminiError::Unavailable)?;
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
pub enum ActionKind {
    Start,
    Prompt,
    Cancel,
    Lookup,
    EndInput,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkPhase {
    Ready,
    Starting,
    Prompting,
    Idle,
    Cancelling,
    OwnerActionRequired,
    InputEnded,
    Exited,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    MaxTokens,
    MaxTurnRequests,
    Refusal,
    Cancelled,
}
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub frame_written: bool,
    pub write_uncertain: bool,
    pub not_dispatched: bool,
    pub bound_session_id: Option<String>,
    pub terminal: Option<StopReason>,
    pub terminal_unknown: bool,
    pub rpc_error: bool,
    pub permission_cancel_responses_written: u32,
    pub permission_cancel_responses_uncertain: bool,
}
impl Evidence {
    pub(crate) fn merged(&self, other: Self) -> Result<Self> {
        if self
            .bound_session_id
            .as_ref()
            .zip(other.bound_session_id.as_ref())
            .is_some_and(|(a, b)| a != b)
            || self
                .terminal
                .zip(other.terminal)
                .is_some_and(|(a, b)| a != b)
        {
            return Err(GeminiError::Conflict);
        }
        let out = Self {
            frame_written: self.frame_written || other.frame_written,
            write_uncertain: self.write_uncertain || other.write_uncertain,
            not_dispatched: self.not_dispatched || other.not_dispatched,
            bound_session_id: self.bound_session_id.clone().or(other.bound_session_id),
            terminal: self.terminal.or(other.terminal),
            terminal_unknown: self.terminal_unknown || other.terminal_unknown,
            rpc_error: self.rpc_error || other.rpc_error,
            permission_cancel_responses_uncertain: self.permission_cancel_responses_uncertain
                || other.permission_cancel_responses_uncertain,
            permission_cancel_responses_written: self
                .permission_cancel_responses_written
                .max(other.permission_cancel_responses_written),
        };
        out.validate()?;
        Ok(out)
    }
    pub(crate) fn validate_for(&self, operation: &SavedOperation) -> Result<()> {
        self.validate()?;
        if operation.kind == ActionKind::Cancel
            && (self.terminal.is_some() || self.rpc_error || self.terminal_unknown)
            || operation.kind != ActionKind::Cancel
                && (self.permission_cancel_responses_written > 0
                    || self.permission_cancel_responses_uncertain)
            || operation.kind != ActionKind::Start && self.bound_session_id.is_some()
        {
            return Err(GeminiError::InvalidInput);
        }
        Ok(())
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self
            .bound_session_id
            .as_ref()
            .is_some_and(|s| !valid_uuid(s))
            || self.permission_cancel_responses_written > 32
            || self.not_dispatched
                && (self.frame_written
                    || self.write_uncertain
                    || self.terminal.is_some()
                    || self.rpc_error
                    || self.terminal_unknown)
            || self.terminal.is_some() && self.rpc_error
        {
            Err(GeminiError::InvalidInput)
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
pub struct SavedOperation {
    pub schema: String,
    pub id: String,
    pub kind: ActionKind,
    pub text: String,
    pub session_epoch: String,
    pub session_id: Option<String>,
    pub prompt_rpc_id: String,
    pub prompt_generation: u64,
    pub startup: Option<StartupRecord>,
}
impl SavedOperation {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != "chinwag-gemini-operation/v1"
            || !valid_uuid(&self.id)
            || !valid_uuid(&self.session_epoch)
            || !valid_rpc(&self.prompt_rpc_id)
            || self.prompt_generation == 0
        {
            return Err(GeminiError::InvalidInput);
        }
        match (self.kind, &self.startup, &self.session_id) {
            (ActionKind::Start, Some(s), None)
                if valid_text(&self.text)
                    && valid_path(&s.binary)
                    && valid_path(&s.workdir)
                    && valid_hash(&s.sha256)
                    && s.policy == "configured_runtime_effects_manual_mode_extensions_disabled"
                    && self.prompt_rpc_id == format!("prompt-{}", self.id) => {}
            (ActionKind::Prompt, None, Some(s))
                if valid_text(&self.text)
                    && valid_uuid(s)
                    && self.prompt_rpc_id == format!("prompt-{}", self.id) => {}
            (ActionKind::Cancel, None, Some(s)) if self.text.is_empty() && valid_uuid(s) => {}
            _ => return Err(GeminiError::InvalidInput),
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation: SavedOperation,
    pub evidence: Evidence,
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
pub struct ObservedActivePrompt {
    pub(crate) session: ObservedSession,
    pub(crate) rpc_id: String,
    pub(crate) operation_id: String,
    pub(crate) generation: u64,
}
impl ObservedActivePrompt {
    pub fn session_epoch(&self) -> &str {
        self.session.session_epoch()
    }
    pub fn session_id(&self) -> &str {
        self.session.session_id()
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn rpc_id(&self) -> &str {
        &self.rpc_id
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}
#[derive(Debug, Clone)]
pub struct WorkSubmission {
    pub id: String,
    pub kind: ActionKind,
    pub saved: bool,
    pub error: Option<GeminiError>,
}
#[derive(Debug, Clone)]
pub struct WorkSnapshot {
    pub phase: WorkPhase,
    pub folder_label: String,
    pub start: Option<Receipt>,
    pub operations: Vec<Receipt>,
    pub session: Option<ObservedSession>,
    pub active_prompt: Option<ObservedActivePrompt>,
    pub can_prompt: bool,
    pub cancel_pending: bool,
    pub control_expired: bool,
    pub pending_permissions: usize,
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
            operations: Vec::new(),
            session: None,
            active_prompt: None,
            can_prompt: false,
            cancel_pending: false,
            control_expired: false,
            pending_permissions: 0,
            agent_text: None,
            last_submission: None,
            lifecycle: LifecycleFacts::default(),
            revision: 0,
        }
    }
}

/// Read-only captured human input; data summaries cannot recreate its authority.
pub struct PreparedPrompt {
    pub(crate) target: ObservedSession,
    pub(crate) operation: SavedOperation,
    pub(crate) deadline: Instant,
    pub(crate) sequence: u64,
}
impl PreparedPrompt {
    pub fn operation(&self) -> &SavedOperation {
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
    fn prompt(&self, target: &ObservedSession, id: &str, text: &str) -> Result<()>;
    fn cancel(&self, target: &ObservedActivePrompt, id: &str) -> Result<()>;
    fn prepare_prompt(
        &self,
        _target: &ObservedSession,
        _id: &str,
        _text: &str,
        _deadline: Instant,
    ) -> Result<PreparedPrompt> {
        Err(GeminiError::Unavailable)
    }
    fn submit_prepared_prompt(&self, _prepared: PreparedPrompt) -> Result<()> {
        Err(GeminiError::Unavailable)
    }
    fn lookup(&self, id: &str) -> Result<()>;
    fn end_input(&self) -> Result<()>;
}
