// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Observations from an owner's exact Codex CLI child, not agent admission or
//! proof of a repair. The official non-interactive JSONL protocol supplies
//! thread/turn/item events. Never retain reasoning, command output or messages
//! in a public observation. OS closure and actual source checks remain separate.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

const MAX_RECORD: usize = 1024 * 1024;
const MAX_ITEMS: usize = 16384;

// Unknown fields are skipped by the deserializer, including all reasoning,
// message text and command output. They are never copied into a JSON Value.
#[derive(Deserialize)]
struct Event {
    r#type: String,
    thread_id: Option<String>,
    item: Option<Item>,
    usage: Option<Usage>,
}
#[derive(Deserialize)]
struct Usage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}
#[derive(Deserialize)]
struct Item {
    id: String,
    r#type: String,
    status: Option<String>,
    exit_code: Option<i64>,
    changes: Option<Vec<Change>>,
}
#[derive(Deserialize)]
struct Change {
    path: String,
}

#[derive(Debug, thiserror::Error)]
#[error("coding-agent event stream is incomplete, mismatched or failed")]
pub struct AgentEventError;

#[derive(Clone, Serialize)]
pub struct AgentTurnObservation {
    pub classification: &'static str,
    pub session_id: String,
    pub turn_started: bool,
    pub turn_completed: bool,
    pub command_completions: u64,
    pub failed_commands: u64,
    pub reported_file_changes: u64,
    pub failed_file_changes: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

/// Incremental decoder. A record bound can refuse evidence, but its caller must
/// still drain the owned child and observe its original terminal OS status.
/// No aggregate wire limit may terminate an otherwise running coding turn.
pub struct CodexEvents {
    expected: String,
    pending: Vec<u8>,
    thread: bool,
    started: bool,
    completed: bool,
    poisoned: bool,
    active: BTreeMap<String, String>,
    seen: BTreeSet<String>,
    commands: u64,
    failed_commands: u64,
    changes: u64,
    failed_changes: u64,
    usage: Option<Usage>,
}

pub fn session_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && id
            .bytes()
            .any(|b| (b'1'..=b'9').contains(&b) || (b'a'..=b'f').contains(&b))
}

impl CodexEvents {
    pub fn new(expected_session: &str) -> Result<Self, AgentEventError> {
        if !session_uuid(expected_session) {
            return Err(AgentEventError);
        }
        Ok(Self {
            expected: expected_session.into(),
            pending: Vec::with_capacity(MAX_RECORD),
            thread: false,
            started: false,
            completed: false,
            poisoned: false,
            active: BTreeMap::new(),
            seen: BTreeSet::new(),
            commands: 0,
            failed_commands: 0,
            changes: 0,
            failed_changes: 0,
            usage: None,
        })
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<(), AgentEventError> {
        if self.poisoned {
            return Err(AgentEventError);
        }
        for &byte in bytes {
            if byte == b'\n' {
                let line = std::mem::take(&mut self.pending);
                let result = self.record(&line);
                let mut line = line;
                line.as_mut_slice().zeroize();
                line.clear();
                self.pending = line;
                if result.is_err() {
                    self.poisoned = true;
                    return Err(AgentEventError);
                }
            } else if self.pending.len() >= MAX_RECORD {
                self.pending.zeroize();
                self.poisoned = true;
                return Err(AgentEventError);
            } else {
                self.pending.push(byte);
            }
        }
        Ok(())
    }

    fn record(&mut self, line: &[u8]) -> Result<(), AgentEventError> {
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let v: Event = serde_json::from_slice(line).map_err(|_| AgentEventError)?;
        let event = v.r#type.as_str();
        if event == "thread.started" {
            if self.thread || self.started || v.thread_id.as_deref() != Some(&self.expected) {
                return Err(AgentEventError);
            }
            self.thread = true;
            return Ok(());
        }
        if !self.thread || self.completed || matches!(event, "error" | "turn.failed") {
            return Err(AgentEventError);
        }
        match event {
            "turn.started" if !self.started => self.started = true,
            "turn.completed" if self.started && self.active.is_empty() => {
                self.completed = true;
                self.usage = v.usage;
            }
            "item.started" | "item.updated" | "item.completed" if self.started => {
                self.item(event, &v.item.ok_or(AgentEventError)?)?;
            }
            _ => return Err(AgentEventError),
        }
        Ok(())
    }

    fn item(&mut self, event: &str, item: &Item) -> Result<(), AgentEventError> {
        let id = item.id.as_str();
        let kind = item.r#type.as_str();
        let fresh_id = !self.seen.contains(id) && !self.active.contains_key(id);
        if id.is_empty()
            || id.len() > 128
            || kind.len() > 128
            || (fresh_id && self.seen.len() + self.active.len() >= MAX_ITEMS)
        {
            return Err(AgentEventError);
        }
        if event == "item.started" {
            if self.seen.contains(id) || self.active.insert(id.into(), kind.into()).is_some() {
                return Err(AgentEventError);
            }
            return Ok(());
        }
        if event == "item.updated" {
            return if self.active.get(id).is_some_and(|k| k == kind) {
                Ok(())
            } else {
                Err(AgentEventError)
            };
        }
        if !self.seen.insert(id.into()) {
            return Err(AgentEventError);
        }
        let started_kind = self.active.remove(id);
        if started_kind.as_ref().is_some_and(|k| k != kind) {
            return Err(AgentEventError);
        }
        match kind {
            "command_execution" => {
                if started_kind.is_none()
                    || !matches!(item.status.as_deref(), Some("completed" | "failed"))
                {
                    return Err(AgentEventError);
                }
                let code = item.exit_code.ok_or(AgentEventError)?;
                self.commands += 1;
                self.failed_commands += u64::from(code != 0);
            }
            "file_change" => {
                if !matches!(item.status.as_deref(), Some("completed" | "failed")) {
                    return Err(AgentEventError);
                }
                let changes = item.changes.as_ref().ok_or(AgentEventError)?;
                if changes.is_empty() || changes.iter().any(|c| c.path.is_empty()) {
                    return Err(AgentEventError);
                }
                if item.status.as_deref() == Some("completed") {
                    self.changes += changes.len() as u64;
                } else {
                    self.failed_changes += changes.len() as u64;
                }
            }
            // Reasoning and message bodies are intentionally not retained.
            _ => {}
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<AgentTurnObservation, AgentEventError> {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            let result = self.record(&line);
            let mut line = line;
            line.as_mut_slice().zeroize();
            result?;
        }
        if self.poisoned || !self.thread || !self.started || !self.completed {
            return Err(AgentEventError);
        }
        Ok(AgentTurnObservation {
            classification: "EXACT_SESSION_TURN_OBSERVED_NOT_OS_CLOSE_OR_VERIFIED_REPAIR",
            session_id: self.expected.clone(),
            turn_started: true,
            turn_completed: true,
            command_completions: self.commands,
            failed_commands: self.failed_commands,
            reported_file_changes: self.changes,
            failed_file_changes: self.failed_changes,
            input_tokens: self.usage.as_ref().and_then(|u| u.input_tokens),
            output_tokens: self.usage.as_ref().and_then(|u| u.output_tokens),
        })
    }
}

impl Drop for CodexEvents {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "0199a213-81c0-7800-8aa1-bbab2a035a53";
    fn stream(items: &str) -> String {
        format!(
            "{{\"type\":\"thread.started\",\"thread_id\":\"{ID}\"}}\n{{\"type\":\"turn.started\"}}\n{items}{{\"type\":\"turn.completed\",\"usage\":{{}}}}\n"
        )
    }
    #[test]
    fn fragmented_exact_session_stream_observes_real_tool_events_without_retaining_payloads() {
        let wire = stream(concat!(
            "{\"type\":\"item.started\",\"item\":{\"id\":\"cmd1\",\"type\":\"command_execution\"}}\n",
            "{\"type\":\"item.completed\",\"item\":{\"id\":\"cmd1\",\"type\":\"command_execution\",\"status\":\"completed\",\"exit_code\":0,\"aggregated_output\":\"PRIVATE_LOG\"}}\n",
            "{\"type\":\"item.completed\",\"item\":{\"id\":\"patch1\",\"type\":\"file_change\",\"status\":\"completed\",\"changes\":[{\"path\":\"fixture.rs\",\"kind\":\"update\"}]}}\n",
            "{\"type\":\"item.completed\",\"item\":{\"id\":\"msg1\",\"type\":\"agent_message\",\"text\":\"PRIVATE_REPLY\"}}\n"
        ));
        let mut p = CodexEvents::new(ID).unwrap();
        for chunk in wire.as_bytes().chunks(7) {
            p.push(chunk).unwrap();
        }
        let evidence = p.finish().unwrap();
        assert_eq!(evidence.command_completions, 1);
        assert_eq!(evidence.reported_file_changes, 1);
        let public = serde_json::to_string(&evidence).unwrap();
        assert!(!public.contains("PRIVATE"));
        assert!(!public.contains("fixture.rs"));
    }
    #[test]
    fn wrong_session_failed_or_incomplete_turn_and_duplicate_events_are_not_success() {
        let examples = [
            stream("").replace(ID, "0199a213-81c0-7800-8aa1-bbab2a035a54"),
            stream("").replace("turn.completed", "turn.failed"),
            stream("").replace("{\"type\":\"turn.completed\",\"usage\":{}}\n", ""),
            stream("{\"type\":\"turn.started\"}\n"),
            stream("{\"type\":\"error\",\"message\":\"private\"}\n"),
            stream(
                "{\"type\":\"item.started\",\"item\":{\"id\":\"cmd1\",\"type\":\"command_execution\"}}\n",
            ),
        ];
        for wire in examples {
            let mut p = CodexEvents::new(ID).unwrap();
            if p.push(wire.as_bytes()).is_ok() {
                assert!(p.finish().is_err());
            }
        }
    }
    #[test]
    fn arbitrary_session_selectors_and_oversized_records_are_refused() {
        for id in [
            "--last",
            "ALL",
            "a-thread-name",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(CodexEvents::new(id).is_err());
        }
        let mut p = CodexEvents::new(ID).unwrap();
        assert!(p.push(&vec![b'x'; MAX_RECORD + 1]).is_err());
        assert!(p.push(stream("").as_bytes()).is_err());
        assert!(p.finish().is_err());
    }

    #[test]
    fn unfinished_items_are_bounded_before_completion_and_wire_volume_is_not_a_stop_gate() {
        let mut p = CodexEvents::new(ID).unwrap();
        p.push(format!("{{\"type\":\"thread.started\",\"thread_id\":\"{ID}\"}}\n{{\"type\":\"turn.started\"}}\n").as_bytes()).unwrap();
        for n in 0..MAX_ITEMS {
            p.push(format!("{{\"type\":\"item.started\",\"item\":{{\"id\":\"item{n}\",\"type\":\"reasoning\"}}}}\n").as_bytes()).unwrap();
        }
        p.push(
            b"{\"type\":\"item.completed\",\"item\":{\"id\":\"item0\",\"type\":\"reasoning\"}}\n",
        )
        .unwrap();
        assert!(p.push(b"{\"type\":\"item.started\",\"item\":{\"id\":\"overflow\",\"type\":\"reasoning\"}}\n").is_err());
        assert!(p.finish().is_err());
        let mut p = CodexEvents::new(ID).unwrap();
        let wire = stream("");
        p.push(&vec![b' '; MAX_RECORD]).unwrap();
        p.push(b"\n").unwrap();
        p.push(wire.as_bytes()).unwrap();
        assert!(p.finish().is_ok());
    }

    #[test]
    fn failed_patch_then_successful_patch_is_a_valid_completed_turn_with_distinct_counts() {
        let wire = stream(concat!(
            "{\"type\":\"item.completed\",\"item\":{\"id\":\"patch1\",\"type\":\"file_change\",\"status\":\"failed\",\"changes\":[{\"path\":\"fixture.rs\",\"kind\":\"update\"}]}}\n",
            "{\"type\":\"item.completed\",\"item\":{\"id\":\"patch2\",\"type\":\"file_change\",\"status\":\"completed\",\"changes\":[{\"path\":\"fixture.rs\",\"kind\":\"update\"}]}}\n"
        ));
        let mut p = CodexEvents::new(ID).unwrap();
        p.push(wire.as_bytes()).unwrap();
        let observed = p.finish().unwrap();
        assert_eq!(observed.reported_file_changes, 1);
        assert_eq!(observed.failed_file_changes, 1);
    }
}
