// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Durable WAL-mode SQLite outbox (`slack_outbox.sqlite3`) for offline queuing,
//! idempotent retry, channel-archetype mapping, and one-time post-verify CLI nudge state.
//! Uses hex-encoded SQL literals piped over `stdin` to `/usr/bin/sqlite3 -json` —
//! zero `unsafe`, zero SQL injection surface, and zero `argv` exposure (`ROG-580`).

use crate::slack::authorization::{
    AuthStateError, RequestedMetadataMode, ensure_safe_state_dir, verify_not_symlink_if_exists,
};
use chinwag_slack_contract::{Digest32, EventId, SignedBlindSlackBeatV1, to_jcs_bytes};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const OUTBOX_DB_NAME: &str = "slack_outbox.sqlite3";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRow {
    pub event_id: String,
    pub operation_id: String,
    pub beat_digest: String,
    pub payload_jcs: String,
    pub channel_override: Option<String>,
    pub delivery_state: String,
    pub attempts: u32,
    pub next_retry_at_ms: u64,
    pub last_error: Option<String>,
    pub k2_receipt_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMappingRow {
    pub archetype: String,
    pub channel_id: String,
    pub metadata_mode: String,
    pub updated_at_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OutboxError {
    IdempotencyConflict(String),
    InvalidChannelMapping(String),
    Storage(String),
}

impl std::fmt::Display for OutboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdempotencyConflict(msg) => write!(f, "outbox idempotency conflict: {msg}"),
            Self::InvalidChannelMapping(msg) => write!(f, "invalid channel mapping: {msg}"),
            Self::Storage(msg) => write!(f, "SQLite outbox error: {msg}"),
        }
    }
}

impl From<AuthStateError> for OutboxError {
    fn from(value: AuthStateError) -> Self {
        Self::Storage(value.to_string())
    }
}

fn sql_text_hex(value: &str) -> String {
    format!("CAST(X'{}' AS TEXT)", hex::encode(value.as_bytes()))
}

pub struct SqliteSlackOutbox {
    db_path: PathBuf,
}

impl SqliteSlackOutbox {
    pub fn open(state_dir: &Path) -> Result<Self, OutboxError> {
        ensure_safe_state_dir(state_dir)?;
        let db_path = state_dir.join(OUTBOX_DB_NAME);
        if !verify_not_symlink_if_exists(&db_path)? {
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&db_path)
                .map_err(|e| OutboxError::Storage(e.to_string()))?;
            drop(f);
        }
        let store = Self { db_path };
        store.init_schema()?;
        Ok(store)
    }

    fn run_sql(&self, sql: &str, json_output: bool) -> Result<String, OutboxError> {
        let _ = verify_not_symlink_if_exists(&self.db_path)?;
        let mut cmd = Command::new("/usr/bin/sqlite3");
        if json_output {
            cmd.arg("-json");
        }
        cmd.arg("-bail")
            .arg(&self.db_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| OutboxError::Storage(e.to_string()))?;
        let preamble = ".timeout 5000\nPRAGMA foreign_keys=ON;\n";
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(preamble.as_bytes())
                .and_then(|()| stdin.write_all(sql.as_bytes()))
                .and_then(|()| stdin.write_all(b"\n"))
                .map_err(|e| OutboxError::Storage(e.to_string()))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| OutboxError::Storage(e.to_string()))?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(OutboxError::Storage(err));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn init_schema(&self) -> Result<(), OutboxError> {
        let ddl = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS slack_outbox (
    event_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    beat_digest TEXT NOT NULL,
    payload_jcs TEXT NOT NULL,
    channel_override TEXT,
    delivery_state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at_ms INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    k2_receipt_ref TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_slack_outbox_pending
    ON slack_outbox(delivery_state, next_retry_at_ms);

CREATE TABLE IF NOT EXISTS slack_channel_map (
    archetype TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL,
    metadata_mode TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS slack_nudge_state (
    nudge_key TEXT PRIMARY KEY,
    shown_at_ms INTEGER NOT NULL,
    operation_id TEXT NOT NULL
);
"#;
        self.run_sql(ddl, false)?;

        // Online migration for pre-existing slack_outbox databases created prior to `channel_override`
        #[derive(Deserialize)]
        struct TableColInfo {
            name: String,
        }
        let info_raw = self.run_sql("PRAGMA table_info(slack_outbox);", true)?;
        if let Some(idx) = info_raw.find('[') {
            let cols: Vec<TableColInfo> = serde_json::from_str(info_raw[idx..].trim())
                .map_err(|e| OutboxError::Storage(e.to_string()))?;
            if !cols.iter().any(|c| c.name == "channel_override") {
                self.run_sql(
                    "ALTER TABLE slack_outbox ADD COLUMN channel_override TEXT;",
                    false,
                )?;
            }
        }
        Ok(())
    }

    /// Durably persists a signed beat BEFORE network egress inside an atomic `BEGIN IMMEDIATE` transaction.
    /// Idempotent if `(event_id, beat_digest, channel_override)` already exists; fails closed on mutated digest or channel.
    pub fn enqueue_idempotent(
        &self,
        signed: &SignedBlindSlackBeatV1,
        digest: &Digest32,
        channel_override: Option<&str>,
        now_ms: u64,
    ) -> Result<(), OutboxError> {
        if let Some(ch) = channel_override {
            validate_slack_channel_id(ch)?;
        }
        let jcs_bytes = to_jcs_bytes(signed).map_err(|e| OutboxError::Storage(e.to_string()))?;
        let jcs_str =
            String::from_utf8(jcs_bytes).map_err(|e| OutboxError::Storage(e.to_string()))?;
        let event_id = signed.beat.event_id.as_str();
        let digest_str = digest.to_prefixed_string();
        let ch_sql = match channel_override {
            Some(ch) => sql_text_hex(ch),
            None => "NULL".to_owned(),
        };

        let sql = format!(
            "BEGIN IMMEDIATE;\n\
             INSERT OR IGNORE INTO slack_outbox \
             (event_id, operation_id, beat_digest, payload_jcs, channel_override, delivery_state, attempts, next_retry_at_ms, created_at_ms, updated_at_ms) \
             VALUES ({}, {}, {}, {}, {ch_sql}, 'pending', 0, {now_ms}, {now_ms}, {now_ms});\n\
             COMMIT;",
            sql_text_hex(event_id),
            sql_text_hex(signed.beat.operation_id.as_str()),
            sql_text_hex(&digest_str),
            sql_text_hex(&jcs_str),
        );
        self.run_sql(&sql, false)?;

        let existing = self
            .get_row(&signed.beat.event_id)?
            .ok_or_else(|| OutboxError::Storage("inserted outbox row missing".to_owned()))?;
        if existing.beat_digest != digest_str
            || existing.channel_override.as_deref() != channel_override
        {
            return Err(OutboxError::IdempotencyConflict(format!(
                "event_id {event_id} already recorded with different beat_digest or channel_override"
            )));
        }
        Ok(())
    }

    pub fn get_row(&self, event_id: &EventId) -> Result<Option<OutboxRow>, OutboxError> {
        let sql = format!(
            "SELECT event_id, operation_id, beat_digest, payload_jcs, channel_override, delivery_state, \
             attempts, next_retry_at_ms, last_error, k2_receipt_ref \
             FROM slack_outbox WHERE event_id = {} LIMIT 1;",
            sql_text_hex(event_id.as_str())
        );
        let out = self.run_sql(&sql, true)?;
        Self::parse_rows(&out).map(|mut v| v.pop())
    }

    pub fn list_due_pending(&self, now_ms: u64, limit: u32) -> Result<Vec<OutboxRow>, OutboxError> {
        let sql = format!(
            "SELECT event_id, operation_id, beat_digest, payload_jcs, channel_override, delivery_state, \
             attempts, next_retry_at_ms, last_error, k2_receipt_ref \
             FROM slack_outbox \
             WHERE delivery_state = 'pending' AND next_retry_at_ms <= {now_ms} \
             ORDER BY created_at_ms ASC LIMIT {limit};"
        );
        let out = self.run_sql(&sql, true)?;
        Self::parse_rows(&out)
    }

    pub fn pending_count(&self) -> Result<u64, OutboxError> {
        #[derive(Deserialize)]
        struct CountRow {
            cnt: u64,
        }
        let out = self.run_sql(
            "SELECT COUNT(*) AS cnt FROM slack_outbox WHERE delivery_state = 'pending';",
            true,
        )?;
        let trimmed = out.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }
        let rows: Vec<CountRow> =
            serde_json::from_str(trimmed).map_err(|e| OutboxError::Storage(e.to_string()))?;
        Ok(rows.first().map_or(0, |r| r.cnt))
    }

    pub fn mark_acknowledged(
        &self,
        event_id: &EventId,
        k2_receipt_ref: Option<&str>,
        now_ms: u64,
    ) -> Result<(), OutboxError> {
        let rcpt_sql = match k2_receipt_ref {
            Some(r) => sql_text_hex(r),
            None => "NULL".to_owned(),
        };
        let sql = format!(
            "UPDATE slack_outbox \
             SET delivery_state = 'acked', attempts = attempts + 1, k2_receipt_ref = {rcpt_sql}, \
                 last_error = NULL, updated_at_ms = {now_ms} \
             WHERE event_id = {};",
            sql_text_hex(event_id.as_str())
        );
        self.run_sql(&sql, false)?;
        Ok(())
    }

    pub fn record_transient_failure(
        &self,
        event_id: &EventId,
        reason: &str,
        retry_after_ms: u64,
        now_ms: u64,
    ) -> Result<(), OutboxError> {
        let next_ms = now_ms.saturating_add(retry_after_ms);
        let sql = format!(
            "UPDATE slack_outbox \
             SET delivery_state = 'pending', attempts = attempts + 1, \
                 next_retry_at_ms = {next_ms}, last_error = {}, updated_at_ms = {now_ms} \
             WHERE event_id = {};",
            sql_text_hex(reason),
            sql_text_hex(event_id.as_str())
        );
        self.run_sql(&sql, false)?;
        Ok(())
    }

    pub fn mark_revoked_or_quarantined(
        &self,
        event_id: &EventId,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), OutboxError> {
        let sql = format!(
            "UPDATE slack_outbox \
             SET delivery_state = 'quarantined', attempts = attempts + 1, \
                 last_error = {}, updated_at_ms = {now_ms} \
             WHERE event_id = {};",
            sql_text_hex(reason),
            sql_text_hex(event_id.as_str())
        );
        self.run_sql(&sql, false)?;
        Ok(())
    }

    fn parse_rows(raw: &str) -> Result<Vec<OutboxRow>, OutboxError> {
        // sqlite3 -json prints a trailing newline after journal_mode=WAL output if not separated;
        // find the JSON array `[` or treat empty as `[]`.
        let json_slice = match raw.find('[') {
            Some(idx) => raw[idx..].trim(),
            None => return Ok(Vec::new()),
        };
        serde_json::from_str(json_slice).map_err(|e| OutboxError::Storage(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Channel archetype mappings (`ci-builds`, `security`, `pair`, `delivery`)
    // -----------------------------------------------------------------------
    pub fn set_channel_mapping(
        &self,
        archetype: &str,
        channel_id: &str,
        mode: RequestedMetadataMode,
        now_ms: u64,
    ) -> Result<(), OutboxError> {
        validate_archetype(archetype)?;
        validate_slack_channel_id(channel_id)?;
        let sql = format!(
            "INSERT INTO slack_channel_map (archetype, channel_id, metadata_mode, updated_at_ms) \
             VALUES ({}, {}, {}, {now_ms}) \
             ON CONFLICT(archetype) DO UPDATE SET \
                 channel_id = excluded.channel_id, \
                 metadata_mode = excluded.metadata_mode, \
                 updated_at_ms = excluded.updated_at_ms;",
            sql_text_hex(archetype),
            sql_text_hex(channel_id),
            sql_text_hex(mode.as_str()),
        );
        self.run_sql(&sql, false)?;
        Ok(())
    }

    pub fn clear_channel_mapping(&self, archetype: &str) -> Result<(), OutboxError> {
        validate_archetype(archetype)?;
        let sql = format!(
            "DELETE FROM slack_channel_map WHERE archetype = {};",
            sql_text_hex(archetype)
        );
        self.run_sql(&sql, false)?;
        Ok(())
    }

    pub fn list_channel_mappings(&self) -> Result<Vec<ChannelMappingRow>, OutboxError> {
        let out = self.run_sql(
            "SELECT archetype, channel_id, metadata_mode, updated_at_ms \
             FROM slack_channel_map ORDER BY archetype ASC;",
            true,
        )?;
        let json_slice = match out.find('[') {
            Some(idx) => out[idx..].trim(),
            None => return Ok(Vec::new()),
        };
        serde_json::from_str(json_slice).map_err(|e| OutboxError::Storage(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Post-first-verified-function one-line CLI expansion nudge state
    // -----------------------------------------------------------------------
    pub fn try_claim_one_time_nudge(
        &self,
        nudge_key: &str,
        operation_id: &str,
        now_ms: u64,
    ) -> Result<bool, OutboxError> {
        #[derive(Deserialize)]
        struct ExistingRow {
            nudge_key: String,
        }
        let check_sql = format!(
            "SELECT nudge_key FROM slack_nudge_state WHERE nudge_key = {} LIMIT 1;",
            sql_text_hex(nudge_key)
        );
        let check_out = self.run_sql(&check_sql, true)?;
        if let Some(idx) = check_out.find('[') {
            let rows: Vec<ExistingRow> = serde_json::from_str(check_out[idx..].trim())
                .map_err(|e| OutboxError::Storage(e.to_string()))?;
            if rows.iter().any(|r| r.nudge_key == nudge_key) {
                return Ok(false);
            }
        }
        let insert_sql = format!(
            "INSERT OR IGNORE INTO slack_nudge_state (nudge_key, shown_at_ms, operation_id) \
             VALUES ({}, {now_ms}, {});",
            sql_text_hex(nudge_key),
            sql_text_hex(operation_id),
        );
        self.run_sql(&insert_sql, false)?;
        Ok(true)
    }
}

pub fn validate_archetype(archetype: &str) -> Result<(), OutboxError> {
    match archetype {
        "ci-builds" | "security" | "pair" | "delivery" => Ok(()),
        _ => Err(OutboxError::InvalidChannelMapping(format!(
            "unsupported channel archetype '{archetype}'; expected ci-builds|security|pair|delivery"
        ))),
    }
}

pub fn validate_slack_channel_id(channel_id: &str) -> Result<(), OutboxError> {
    let bytes = channel_id.as_bytes();
    if bytes.len() < 9
        || bytes.len() > 15
        || !matches!(bytes[0], b'C' | b'G')
        || !bytes[1..]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(OutboxError::InvalidChannelMapping(
            "Slack channel ID must match ^[CG][A-Z0-9]{8,14}$".to_owned(),
        ));
    }
    Ok(())
}
