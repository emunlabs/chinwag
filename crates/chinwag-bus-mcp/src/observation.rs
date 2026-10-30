//! Independent, bounded facts observed by this server. No peer metadata or
//! transport/client/model receipt is inferred from a prepared output.

use rmcp::model::ProtocolVersion;
use serde::Serialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NegotiatedProtocol {
    #[serde(rename = "2025-06-18")]
    June2025,
    #[serde(rename = "2025-11-25")]
    November2025,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolEnd {
    NotObserved,
    Closed,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    DrainNotObserved,
    Drained,
    Failed,
}

/// An owner-held read-only projection, not connection authority. Fields are
/// independent observations; preparing output proves no downstream receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LifecycleSnapshot {
    pub schema: &'static str,
    pub negotiated_protocol: Option<NegotiatedProtocol>,
    pub initialized_notification_seen: bool,
    pub catalogue_outputs_prepared: u64,
    pub read_windows_prepared: u64,
    pub lease_expired: bool,
    pub admission_closed: bool,
    pub input_eof_seen: bool,
    pub input_error_seen: bool,
    pub protocol_end: ProtocolEnd,
    pub owner_close_requested: bool,
    pub worker_state: WorkerState,
    pub output_evidence: &'static str,
}

pub(crate) struct Observation {
    deadline: Instant,
    closed: Arc<AtomicBool>,
    owner_close: Arc<AtomicBool>,
    protocol: AtomicU8,
    initialized: AtomicBool,
    catalogue: AtomicU64,
    reads: AtomicU64,
    eof: AtomicBool,
    input_error: AtomicBool,
    protocol_end: AtomicU8,
    worker: AtomicU8,
}

impl Observation {
    pub(crate) fn new(
        deadline: Instant,
        closed: Arc<AtomicBool>,
        owner_close: Arc<AtomicBool>,
    ) -> Self {
        Self {
            deadline,
            closed,
            owner_close,
            protocol: AtomicU8::new(0),
            initialized: AtomicBool::new(false),
            catalogue: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            eof: AtomicBool::new(false),
            input_error: AtomicBool::new(false),
            protocol_end: AtomicU8::new(0),
            worker: AtomicU8::new(0),
        }
    }

    pub(crate) fn negotiated(&self, version: &ProtocolVersion) {
        let fixed = if version == &ProtocolVersion::V_2025_06_18 {
            1
        } else if version == &ProtocolVersion::V_2025_11_25 {
            2
        } else {
            return;
        };
        self.protocol.store(fixed, Ordering::Release);
    }

    pub(crate) fn initialized(&self) {
        self.initialized.store(true, Ordering::Release);
    }

    pub(crate) fn owner_close_requested(&self) {
        self.owner_close.store(true, Ordering::Release);
    }

    pub(crate) fn catalogue_prepared(&self) {
        saturating_increment(&self.catalogue);
    }

    pub(crate) fn read_prepared(&self) {
        saturating_increment(&self.reads);
    }

    pub(crate) fn input_ended(&self, end: crate::wire::InputEnd) {
        match end {
            crate::wire::InputEnd::Eof => &self.eof,
            crate::wire::InputEnd::Error => &self.input_error,
        }
        .store(true, Ordering::Release);
    }

    pub(crate) fn protocol_ended(&self, end: ProtocolEnd) {
        self.protocol_end.store(
            match end {
                ProtocolEnd::NotObserved => 0,
                ProtocolEnd::Closed => 1,
                ProtocolEnd::Cancelled => 2,
                ProtocolEnd::Error => 3,
            },
            Ordering::Release,
        );
    }

    pub(crate) fn worker_finished(&self, success: bool) {
        self.worker
            .store(if success { 1 } else { 2 }, Ordering::Release);
    }

    pub(crate) fn snapshot(&self, now: Instant) -> LifecycleSnapshot {
        LifecycleSnapshot {
            schema: "chinwag-mcp-connection-observation/v1",
            negotiated_protocol: match self.protocol.load(Ordering::Acquire) {
                1 => Some(NegotiatedProtocol::June2025),
                2 => Some(NegotiatedProtocol::November2025),
                _ => None,
            },
            initialized_notification_seen: self.initialized.load(Ordering::Acquire),
            catalogue_outputs_prepared: self.catalogue.load(Ordering::Acquire),
            read_windows_prepared: self.reads.load(Ordering::Acquire),
            lease_expired: now >= self.deadline,
            admission_closed: self.closed.load(Ordering::Acquire),
            input_eof_seen: self.eof.load(Ordering::Acquire),
            input_error_seen: self.input_error.load(Ordering::Acquire),
            protocol_end: match self.protocol_end.load(Ordering::Acquire) {
                1 => ProtocolEnd::Closed,
                2 => ProtocolEnd::Cancelled,
                3 => ProtocolEnd::Error,
                _ => ProtocolEnd::NotObserved,
            },
            owner_close_requested: self.owner_close.load(Ordering::Acquire),
            worker_state: match self.worker.load(Ordering::Acquire) {
                1 => WorkerState::Drained,
                2 => WorkerState::Failed,
                _ => WorkerState::DrainNotObserved,
            },
            output_evidence: "prepared_only",
        }
    }

    #[cfg(test)]
    pub(crate) fn saturate_counters_for_test(&self) {
        self.catalogue.store(u64::MAX, Ordering::Release);
        self.reads.store(u64::MAX, Ordering::Release);
    }
}

fn saturating_increment(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    });
}
