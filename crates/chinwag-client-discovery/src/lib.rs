//! Bounded process metadata observations, not connector admission or readiness.
//!
//! No client is invoked. Arguments, environments, ports, open files and private
//! application stores are not read. A snapshot cannot detect a same-path re-exec
//! or prove continuous identity; admission needs its own lifecycle/protocol proof.
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod catalogue;
mod installed;
pub use installed::{
    APP_CAPACITY_PER_DIRECTORY, APP_ENTRY_CAPACITY, DirectoryCoverage, DirectoryStatus,
    ExecutableFormat, ExecutableMetadata, INSTALLATION_CAPACITY, Installation, InstallationKind,
    InstalledCoverage, InstalledError, InstalledRunningState, InstalledSnapshot,
    InstalledWithRunning, MAX_PLIST_BYTES, MergedInventory, installed_snapshot, merge_installed,
};

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(any(target_os = "macos", test))]
mod observation;

pub const PID_CAPACITY: usize = 4096;
pub const CANDIDATE_CAPACITY: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error("client process discovery is supported only on macOS")]
    UnsupportedPlatform,
    #[error("Darwin process enumeration failed (OS code {0})")]
    Enumeration(i32),
    #[error("invalid Darwin process snapshot: {0}")]
    InvalidSnapshot(&'static str),
    #[error("host metadata unavailable: {0}")]
    HostMetadata(&'static str),
    #[error("system clock precedes the Unix epoch")]
    Clock,
}

/// Host and boot labels are observed metadata, not authenticated host identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostObservation {
    pub label: String,
    pub boot_uuid: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessBirth {
    pub pid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientFamily {
    GrokBot,
    ClaudeCode,
    ClaudeDesktop,
    CodexCli,
    CodexDesktop,
    ChatgptDesktop,
    GeminiCli,
    GeminiDesktop,
    GoogleAntigravity,
    Opencode,
    Aider,
    GithubCopilot,
    Kiro,
    AmazonQ,
    Cursor,
    Windsurf,
    Ollama,
    LmStudio,
    Goose,
    Amp,
    Droid,
    Continue,
    Cline,
    RooCode,
    MistralVibe,
    Warp,
    Zed,
    VisualStudioCode,
    Jan,
    Msty,
    CherryStudio,
    Boltai,
    Chatbox,
    Gpt4all,
    AnythingLlm,
    Perplexity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRole {
    MainApplication,
    BundledComponent,
    CommandLine,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateState {
    DetectedUnverified,
}

/// Family matching is a path/name hint, never proof of vendor or account identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientCandidate {
    pub family: ClientFamily,
    pub role: ProcessRole,
    pub state: CandidateState,
    pub birth: ProcessBirth,
    pub parent_pid: u32,
    pub uid: u32,
    pub process_group: u32,
    pub executable: String,
    /// Derived outer app path only; no Info.plist or bundle identifier is read.
    pub outer_application: Option<String>,
    /// Parent sampled with stable metadata, same UID, and an earlier birth.
    pub sampled_parent_birth: Option<ProcessBirth>,
    /// Helpers need a verified sampled ancestry to a main app. Otherwise None.
    /// Main apps and independent CLI candidates point to their own birth.
    pub instance_root: Option<ProcessBirth>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Coverage {
    pub pid_capacity: usize,
    pub candidate_capacity: usize,
    pub sampled_pid_count: usize,
    pub pid_capacity_reached: bool,
    pub zero_pid_slots: usize,
    pub candidate_capacity_reached: bool,
    pub omitted_candidate_count: usize,
    pub raced_processes: usize,
    pub permission_denied_processes: usize,
    pub unavailable_processes: usize,
    pub invalid_process_metadata: usize,
    pub unclassified_interpreters: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventorySnapshot {
    pub observed_at_unix_ms: u64,
    pub host: HostObservation,
    pub uid: u32,
    pub coverage: Coverage,
    pub candidates: Vec<ClientCandidate>,
    pub limitations: Vec<String>,
}

/// Observe the current user's allowlisted executable families. Does not connect,
/// admit, authenticate, start, stop, or inspect private state in any client.
pub fn snapshot() -> Result<InventorySnapshot, DiscoveryError> {
    #[cfg(target_os = "macos")]
    {
        darwin::snapshot()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(DiscoveryError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_is_not_an_empty_success() {
        assert_eq!(
            super::snapshot(),
            Err(super::DiscoveryError::UnsupportedPlatform)
        );
    }
}
