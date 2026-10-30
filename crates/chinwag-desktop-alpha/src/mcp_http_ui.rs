//! Ephemeral samples of the selected runtime's anonymous HTTP inbox.
//! No networking, capability access, clipboard write or durable state lives here.

use chinwag_bus_client::{McpProtocolEnd, McpProtocolVersion, RuntimeMcpStatus};
use chrono::{DateTime, Utc};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpHttpRequestKind {
    Check,
    Copy,
}

/// An in-process, single-completion token. Identity is independent of counters,
/// so clearing or counter exhaustion can never revive an older completion.
#[derive(Clone)]
pub struct McpHttpRequest {
    identity: Arc<()>,
    endpoint: String,
    connection_generation: u64,
    generation: u64,
    kind: McpHttpRequestKind,
}

impl McpHttpRequest {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

pub enum McpHttpState {
    NotRequested,
    Loading {
        kind: McpHttpRequestKind,
    },
    NotAvailable,
    Ready {
        status: Box<RuntimeMcpStatus>,
        checked_at: u64,
    },
    Unavailable,
}

pub struct McpHttpPanel {
    state: McpHttpState,
    context: Option<(String, u64)>,
    active: Option<McpHttpRequest>,
    generation: u64,
}

impl Default for McpHttpPanel {
    fn default() -> Self {
        Self {
            state: McpHttpState::NotRequested,
            context: None,
            active: None,
            generation: 0,
        }
    }
}

impl McpHttpPanel {
    pub fn state(&self) -> &McpHttpState {
        &self.state
    }

    pub fn clear(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.active = None;
        self.context = None;
        self.state = McpHttpState::NotRequested;
    }

    pub fn sync_context(&mut self, endpoint: &str, connection_generation: u64) {
        if self.context.as_ref().is_some_and(|(previous, generation)| {
            previous != endpoint || *generation != connection_generation
        }) {
            self.clear();
        }
    }

    /// The caller performs one fresh status GET for either explicit action.
    /// Beginning Copy never exposes JSON from the previously displayed sample.
    pub fn begin(
        &mut self,
        kind: McpHttpRequestKind,
        endpoint: String,
        connection_generation: u64,
    ) -> McpHttpRequest {
        self.sync_context(&endpoint, connection_generation);
        self.generation = self.generation.saturating_add(1);
        self.context = Some((endpoint.clone(), connection_generation));
        let request = McpHttpRequest {
            identity: Arc::new(()),
            endpoint,
            connection_generation,
            generation: self.generation,
            kind,
        };
        self.active = Some(request.clone());
        self.state = McpHttpState::Loading { kind };
        request
    }

    /// Results come from BusClient::mcp_http_status, which validates them against
    /// its canonical origin. This panel correlates the exact raw UI endpoint.
    /// Only a current Copy completion can return secret-free clipboard JSON.
    pub fn complete(
        &mut self,
        request: &McpHttpRequest,
        current_endpoint: &str,
        current_connection_generation: u64,
        checked_at_unix_ms: u64,
        result: Result<Option<RuntimeMcpStatus>, String>,
    ) -> Option<String> {
        if !self.active.as_ref().is_some_and(|active| {
            Arc::ptr_eq(&active.identity, &request.identity)
                && active.generation == request.generation
                && active.endpoint == request.endpoint
                && active.connection_generation == request.connection_generation
                && active.kind == request.kind
        }) {
            return None;
        }
        if request.endpoint != current_endpoint
            || request.connection_generation != current_connection_generation
        {
            self.clear();
            return None;
        }
        self.active = None;
        if checked_at_unix_ms == 0 || checked_at_unix_ms > 253_402_300_799_999 {
            self.state = McpHttpState::Unavailable;
            return None;
        }
        let status = match result {
            Ok(Some(status)) => status,
            Ok(None) => {
                self.state = McpHttpState::NotAvailable;
                return None;
            }
            Err(_) => {
                self.state = McpHttpState::Unavailable;
                return None;
            }
        };
        let copy = if request.kind == McpHttpRequestKind::Copy && eligible(&status) {
            match status.setup_offer.as_ref().and_then(|offer| {
                offer
                    .vscode_configuration()
                    .ok()
                    .and_then(|json| serde_json::to_string_pretty(&json).ok())
            }) {
                Some(json) => Some(json),
                None => {
                    self.state = McpHttpState::Unavailable;
                    return None;
                }
            }
        } else {
            None
        };
        self.state = McpHttpState::Ready {
            status: Box::new(status),
            checked_at: checked_at_unix_ms,
        };
        copy
    }

    /// Enables the explicit Copy control only. Clipboard content still requires
    /// a fresh begin(Copy)/complete cycle; there is no cached-copy accessor.
    pub fn copy_eligible(&self) -> bool {
        matches!(&self.state, McpHttpState::Ready { status, .. } if eligible(status))
    }

    pub fn message(&self) -> &'static str {
        match &self.state {
            McpHttpState::NotRequested => "Check this runtime’s read-only #mgmt inbox setup.",
            McpHttpState::Loading {
                kind: McpHttpRequestKind::Check,
            } => "Checking this runtime…",
            McpHttpState::Loading {
                kind: McpHttpRequestKind::Copy,
            } => "Checking before copying…",
            McpHttpState::NotAvailable => {
                "HTTP inbox observation is not available on this runtime."
            }
            McpHttpState::Unavailable => {
                "Runtime inbox check failed. Check again for a new sample."
            }
            McpHttpState::Ready { status, .. } => {
                let observation = &status.transport.connection_observation;
                if observation.lease_expired {
                    "The owner grant expired. Copying configuration does not renew access."
                } else if status.transport.session_closed || observation.admission_closed {
                    "The owner transport closed. A fresh explicit owner session is required."
                } else if status.transport.session_started {
                    "This owner session slot has already been used."
                } else if status.setup_offer.is_none() {
                    "This runtime provides observations without a setup offer."
                } else {
                    "VS Code Local only: merge the configuration into your profile and enter the token in VS Code’s password prompt."
                }
            }
        }
    }

    pub fn sample_lines(&self) -> Vec<String> {
        let McpHttpState::Ready { status, checked_at } = &self.state else {
            return Vec::new();
        };
        let observation = &status.transport.connection_observation;
        let time = i64::try_from(*checked_at)
            .ok()
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unavailable".into());
        let protocol = match observation.negotiated_protocol {
            None => "not observed",
            Some(McpProtocolVersion::June2025) => "2025-06-18",
            Some(McpProtocolVersion::November2025) => "2025-11-25",
        };
        let end = match observation.protocol_end {
            McpProtocolEnd::NotObserved => "not observed",
            McpProtocolEnd::Closed => "closed",
            McpProtocolEnd::Cancelled => "cancelled",
            McpProtocolEnd::Error => "error",
        };
        let yes = |value| if value { "yes" } else { "no" };
        vec![
            format!("Sample checked {time}"),
            "Read-only #mgmt · owner-local HTTP · peer unattributed".into(),
            format!("Protocol negotiation: {protocol}"),
            format!(
                "Initialized notification observed: {}",
                yes(observation.initialized_notification_seen)
            ),
            format!(
                "Catalogue outputs prepared: {}",
                observation.catalogue_outputs_prepared
            ),
            format!(
                "Inbox windows prepared: {}",
                observation.read_windows_prepared
            ),
            format!(
                "Grant expired in sample: {} · admission closed: {}",
                yes(observation.lease_expired),
                yes(observation.admission_closed)
            ),
            format!(
                "Session started: {} · session closed: {}",
                yes(status.transport.session_started),
                yes(status.transport.session_closed)
            ),
            format!("Protocol end: {end}"),
            format!(
                "Transport worker join observed: {} · reader worker join observed: {}",
                yes(status.transport.transport_worker_joined),
                yes(status.transport.reader_worker_joined)
            ),
            "Prepared output does not verify client receipt or message delivery.".into(),
        ]
    }
}

fn eligible(status: &RuntimeMcpStatus) -> bool {
    status.setup_offer.is_some()
        && !status.transport.session_started
        && !status.transport.session_closed
        && !status.transport.connection_observation.lease_expired
        && !status.transport.connection_observation.admission_closed
}

#[cfg(test)]
mod tests;
