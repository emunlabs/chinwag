use chinwag_claude_control as claude;
use chinwag_codex_steer as codex;
use chinwag_gemini_control as gemini;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, sync::Arc, time::Instant};

pub use claude::InputTiming as ClaudeTiming;
pub type Result<T> = std::result::Result<T, TeamError>;
pub const MAX_MEMBERS: usize = 4;
pub const MAX_DIRECTIONS: usize = 128;
pub const MAX_TEXT_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamError {
    #[error("invalid team input")]
    InvalidInput,
    #[error("team action storage is unavailable")]
    Storage,
    #[error("another team submission is in progress")]
    Busy,
    #[error("the original human revision was already admitted")]
    ConsumedRevision,
    #[error("the selected plan changed or is unavailable")]
    StalePlan,
    #[error("the original human action expired")]
    Expired,
    #[error("team input is closed")]
    Closed,
    #[error("team history capacity is exhausted")]
    Capacity,
    #[error("the team owner is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub enum HeldWorkPort {
    Codex(Arc<dyn codex::HumanWorkPort>),
    Claude(Arc<dyn claude::HumanWorkPort>),
    Gemini(Arc<dyn gemini::HumanWorkPort>),
}
#[derive(Clone)]
pub struct Member {
    pub id: String,
    pub label: String,
    pub port: HeldWorkPort,
}
#[derive(Clone)]
pub enum NativeSnapshot {
    Codex(codex::WorkSnapshot),
    Claude(claude::WorkSnapshot),
    Gemini(gemini::WorkSnapshot),
}
#[derive(Clone)]
pub struct MemberSnapshot {
    pub id: String,
    pub label: String,
    pub native: NativeSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionLabel {
    CodexSteer,
    ClaudeNow,
    ClaudeAfterTools,
    ClaudeAfterTurn,
    GeminiPrompt,
}
impl fmt::Display for ActionLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CodexSteer => "Steer this active turn",
            Self::ClaudeNow => "Direction now — may interrupt",
            Self::ClaudeAfterTools => "Direction after running tools",
            Self::ClaudeAfterTurn => "Direction after this turn",
            Self::GeminiPrompt => "Send a new prompt",
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    NotStarted,
    NoActiveTurn,
    NoSession,
    ResponsePending,
    CancellationPending,
    ControlExpired,
    OwnerActionRequired,
    InputEnded,
    Unavailable,
    InvalidText,
}
impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotStarted => "Start explicitly in the member work window",
            Self::NoActiveTurn => "No active turn; no new turn will be started",
            Self::NoSession => "No current owned session",
            Self::ResponsePending => "Response pending; Cancel and a later Send are separate",
            Self::CancellationPending => "Waiting for the original cancellation to retire",
            Self::ControlExpired => "Original human control scope expired",
            Self::OwnerActionRequired => "Owner action required",
            Self::InputEnded => "Input or control connection ended",
            Self::Unavailable => "Owner unavailable",
            Self::InvalidText => "This text is not eligible for the member's native action",
        })
    }
}
#[derive(Clone)]
pub struct PlanRow {
    pub id: String,
    pub label: String,
    pub action: Option<ActionLabel>,
    pub blocked: Option<BlockReason>,
}
#[derive(Clone)]
pub(crate) enum Target {
    Codex(codex::ObservedActiveTurn),
    Claude(claude::ObservedSession, ClaudeTiming),
    Gemini(gemini::ObservedSession),
}
#[derive(Clone)]
pub struct RenderedPlan {
    pub(crate) identity: Arc<()>,
    pub(crate) rows: Vec<PlanRow>,
    pub(crate) selected: Vec<String>,
    pub(crate) ready: Vec<String>,
    pub(crate) text: String,
    pub(crate) targets: BTreeMap<String, Target>,
}
impl RenderedPlan {
    pub fn rows(&self) -> &[PlanRow] {
        &self.rows
    }
    pub fn selected(&self) -> &[String] {
        &self.selected
    }
    pub fn ready(&self) -> &[String] {
        &self.ready
    }
    pub fn text(&self) -> &str {
        &self.text
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeAudit {
    Codex {
        operation: codex::SavedSteer,
        captured_sequence: u64,
    },
    Claude {
        operation: claude::SavedInput,
        captured_sequence: u64,
    },
    Gemini {
        operation: gemini::SavedOperation,
        captured_sequence: u64,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedMember {
    pub id: String,
    pub label: String,
    pub child_id: Option<String>,
    pub action: Option<ActionLabel>,
    pub excluded: Option<BlockReason>,
    pub audit: Option<NativeAudit>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedDirection {
    pub id: String,
    pub host_instance: String,
    pub text: String,
    pub human_revision: u64,
    pub selected: Vec<String>,
    pub effective: Vec<String>,
    pub members: Vec<SavedMember>,
}
pub(crate) enum PreparedNative {
    Codex(codex::PreparedWorkSteer),
    Claude(claude::PreparedDirection),
    Gemini(gemini::PreparedPrompt),
}
pub struct CapturedTeamDirection {
    pub(crate) identity: Arc<()>,
    pub(crate) saved: SavedDirection,
    pub(crate) tokens: Vec<(String, PreparedNative)>,
    pub(crate) deadline: Instant,
}
impl CapturedTeamDirection {
    pub fn id(&self) -> &str {
        &self.saved.id
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAdmission {
    Queued,
    Rejected,
}
#[derive(Clone)]
pub enum NativeReceipt {
    Codex(codex::Receipt),
    Claude(claude::Receipt),
    Gemini(gemini::Receipt),
}
#[derive(Clone)]
pub struct MemberOutcome {
    pub id: String,
    pub label: String,
    pub claimed: bool,
    pub admission: Option<LocalAdmission>,
    pub child_saved: bool,
    pub clear_safe: bool,
    pub native: Option<NativeReceipt>,
    pub summary: String,
}
#[derive(Clone)]
pub struct DirectionReceipt {
    pub intent: SavedDirection,
    pub members: Vec<MemberOutcome>,
    pub stage_retired: bool,
    pub persistence_failed: bool,
    pub recovered: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Submit,
    Lookup,
}
#[derive(Clone)]
pub struct SubmissionReport {
    pub id: String,
    pub kind: ReportKind,
    pub lookup_serial: Option<u64>,
    pub admitted: bool,
    pub stage_retired: bool,
    pub error: Option<TeamError>,
}
#[derive(Clone, Default)]
pub struct TeamSnapshot {
    pub members: Vec<MemberSnapshot>,
    pub directions: Vec<DirectionReceipt>,
    /// Retained local stage results, including failures before a parent save.
    pub submissions: BTreeMap<String, SubmissionReport>,
    /// Latest completed read-only check per immutable known parent. A newer
    /// serial for that same parent can retire an older pending local check.
    pub lookups: BTreeMap<String, SubmissionReport>,
    pub admission_closed: bool,
    pub busy: bool,
    pub revision: u64,
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id.as_bytes()[0].is_ascii_lowercase()
        && id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}
pub(crate) fn valid_text(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= MAX_TEXT_BYTES
        && !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
pub(crate) fn new_id(prefix: &str) -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| TeamError::Unavailable)?;
    let mut id = String::from(prefix);
    use std::fmt::Write;
    for byte in bytes {
        write!(&mut id, "{byte:02x}").map_err(|_| TeamError::Unavailable)?;
    }
    Ok(id)
}
