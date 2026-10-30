//! Typed port for an explicit human-owned work surface. There is no wire or bus
//! deserialization path from data into this control interface.

use crate::{Evidence, ObservedActiveTurn, Receipt, Result, SteerError};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use tokio::sync::watch;

#[derive(Clone)]
pub struct WorkConfig {
    pub(crate) socket: PathBuf,
    pub(crate) workdir: PathBuf,
    pub(crate) journal: PathBuf,
}

/// An explicit trusted-owner declaration, not an identity or exclusivity check.
#[derive(Clone, Copy)]
pub enum RuntimePolicyDeclaration {
    DedicatedRuntimeWithExplicitLogin,
}

impl WorkConfig {
    /// The trusted host declares a dedicated owner listener and work directory.
    /// Construction is inert: no connection, authentication or model work.
    pub fn new(
        socket: &Path,
        workdir: &Path,
        journal: &Path,
        _declaration: RuntimePolicyDeclaration,
    ) -> Result<Self> {
        if !valid_path(socket)
            || !valid_path(workdir)
            || !valid_path(journal)
            || socket == journal
            || workdir == journal
        {
            return Err(SteerError::InvalidInput);
        }
        Ok(Self {
            socket: socket.into(),
            workdir: workdir.into(),
            journal: journal.into(),
        })
    }

    pub fn work_folder_label(&self) -> String {
        self.workdir
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| name.len() <= 120 && !name.chars().any(char::is_control))
            .unwrap_or("Selected work folder")
            .into()
    }
}

pub(crate) fn valid_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    path.is_absolute()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
        && path.file_name().is_some()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WorkPhase {
    Ready,
    Starting,
    Working,
    Finished,
    StartUnknown,
    OwnerActionRequired,
    Closed,
    Unavailable,
}

/// Independent facts for the one consumed initial work operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkStartReceipt {
    pub id: String,
    pub text: String,
    pub connected: bool,
    pub initialized: bool,
    pub bootstrap_uncertain: bool,
    pub thread_id: Option<String>,
    pub accepted_turn_id: Option<String>,
    pub evidence: Evidence,
    pub recovered_after_restart: bool,
    pub persistence_failed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WorkActionKind {
    Start,
    Steer,
    Lookup,
    Close,
}

#[derive(Clone)]
pub struct WorkSubmission {
    pub id: String,
    pub kind: WorkActionKind,
    pub saved: bool,
    pub error: Option<SteerError>,
}

#[derive(Clone)]
pub struct WorkSnapshot {
    pub phase: WorkPhase,
    pub folder_label: String,
    pub target: Option<ObservedActiveTurn>,
    pub start: Option<WorkStartReceipt>,
    pub steers: Vec<Receipt>,
    pub agent_text: Option<String>,
    pub last_submission: Option<WorkSubmission>,
    pub revision: u64,
}

impl WorkSnapshot {
    pub fn ready(folder_label: String) -> Self {
        Self {
            phase: WorkPhase::Ready,
            folder_label,
            target: None,
            start: None,
            steers: Vec::new(),
            agent_text: None,
            last_submission: None,
            revision: 0,
        }
    }
}

/// A trusted native human-action handler uses this port. Queue admission is not
/// protocol acceptance. Original receipts arrive through the retained snapshot.
/// Dropping a view, receiver or caller never requests Close.
pub trait HumanWorkPort: Send + Sync {
    fn subscribe(&self) -> watch::Receiver<WorkSnapshot>;
    fn start(&self, operation_id: &str, text: &str) -> Result<()>;
    fn steer(&self, target: &ObservedActiveTurn, operation_id: &str, text: &str) -> Result<()>;
    fn lookup(&self, operation_id: &str) -> Result<()>;
    /// Closes this connection only. Work may continue; no server-stop claim.
    fn close(&self) -> Result<()>;
}
