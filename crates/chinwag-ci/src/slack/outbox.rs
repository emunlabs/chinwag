// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Durable `0600` symlink-safe WAL-mode SQLite CI outbox (`ci_slack_outbox.sqlite3`)
//! so concurrent CI shards and runner network/Slack outages never drop blind beats,
//! corrupt state, or fail the wrapped CI job.

use chinwag_slack_contract::{Digest32, SignedBlindSlackBeatV1, to_jcs_bytes};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CI_OUTBOX_DB_FILE: &str = "ci_slack_outbox.sqlite3";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiOutboxEntry {
    pub event_id: String,
    pub beat_digest: String,
    pub signed_beat: SignedBlindSlackBeatV1,
    pub acked: bool,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Deserialize)]
struct RawSqliteRow {
    event_id: String,
    beat_digest: String,
    payload_jcs: String,
    acked: i64,
    attempts: u32,
    last_error: Option<String>,
}

fn sql_text_hex(value: &str) -> String {
    format!("CAST(X'{}' AS TEXT)", hex::encode(value.as_bytes()))
}

pub struct CiSlackOutbox {
    db_path: PathBuf,
}

impl CiSlackOutbox {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let meta = fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err("CI outbox directory must be a real non-symlink directory".to_owned());
        }
        if (meta.permissions().mode() & 0o077) != 0 {
            return Err("CI outbox directory must have 0700 permissions".to_owned());
        }

        let db_path = dir.join(CI_OUTBOX_DB_FILE);
        if !Self::check_not_symlink_and_0600(&db_path)? {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&db_path)
            {
                Ok(f) => drop(f),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = Self::check_not_symlink_and_0600(&db_path)?;
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        let outbox = Self { db_path };
        outbox.init_schema()?;
        Ok(outbox)
    }

    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn check_not_symlink_and_0600(path: &Path) -> Result<bool, String> {
        match fs::symlink_metadata(path) {
            Ok(m) => {
                if m.file_type().is_symlink() || !m.is_file() {
                    return Err("CI outbox SQLite file must not be a symlink".to_owned());
                }
                if (m.permissions().mode() & 0o077) != 0 {
                    return Err("CI outbox SQLite file must have 0600 permissions".to_owned());
                }
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    fn run_sql(&self, sql: &str, json_output: bool) -> Result<String, String> {
        let _ = Self::check_not_symlink_and_0600(&self.db_path)?;
        let bin = if Path::new("/usr/bin/sqlite3").exists() {
            "/usr/bin/sqlite3"
        } else {
            "sqlite3"
        };
        let mut cmd = Command::new(bin);
        if json_output {
            cmd.arg("-json");
        }
        cmd.arg("-bail")
            .arg(&self.db_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                let preamble = ".timeout 5000\nPRAGMA foreign_keys=ON;\n";
                if let Some(mut stdin) = child.stdin.take() {
                    stdin
                        .write_all(preamble.as_bytes())
                        .and_then(|()| stdin.write_all(sql.as_bytes()))
                        .and_then(|()| stdin.write_all(b"\n"))
                        .map_err(|e| e.to_string())?;
                }
                let out = child.wait_with_output().map_err(|e| e.to_string())?;
                if !out.status.success() {
                    return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
                }
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::run_sql_via_python(&self.db_path, sql, json_output)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn run_sql_via_python(db_path: &Path, sql: &str, json_output: bool) -> Result<String, String> {
        let py = r#"
import json, sqlite3, sys
db_path, want_json = sys.argv[1], sys.argv[2] == "1"
sql = sys.stdin.read()
con = sqlite3.connect(db_path, timeout=5.0, isolation_level=None)
con.row_factory = sqlite3.Row
con.execute("PRAGMA foreign_keys=ON;")
if want_json:
    cur = con.execute(sql)
    rows = [dict(r) for r in cur.fetchall()]
    sys.stdout.write(json.dumps(rows))
else:
    con.executescript(sql)
con.close()
"#;
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(py)
            .arg(db_path)
            .arg(if json_output { "1" } else { "0" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(sql.as_bytes()).map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn init_schema(&self) -> Result<(), String> {
        let ddl = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS ci_slack_outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    beat_digest TEXT NOT NULL,
    payload_jcs TEXT NOT NULL,
    acked INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_ci_slack_outbox_acked
    ON ci_slack_outbox(acked, seq);
"#;
        self.run_sql(ddl, false)?;
        Ok(())
    }

    pub fn enqueue(&self, signed: SignedBlindSlackBeatV1, digest: &Digest32) -> Result<(), String> {
        let ev = signed.beat.event_id.as_str().to_owned();
        let dig = digest.to_prefixed_string();
        let jcs_bytes = to_jcs_bytes(&signed).map_err(|e| e.to_string())?;
        let jcs_str = String::from_utf8(jcs_bytes).map_err(|e| e.to_string())?;

        let tx = format!(
            "BEGIN IMMEDIATE;\n\
             INSERT OR IGNORE INTO ci_slack_outbox (event_id, beat_digest, payload_jcs, acked, attempts) \
             VALUES ({}, {}, {}, 0, 0);\n\
             COMMIT;",
            sql_text_hex(&ev),
            sql_text_hex(&dig),
            sql_text_hex(&jcs_str),
        );
        self.run_sql(&tx, false)?;

        // Verify stored digest matches inside WAL view to catch mutated event_id replays fail-closed
        #[derive(Deserialize)]
        struct DigestRow {
            beat_digest: String,
        }
        let check_sql = format!(
            "SELECT beat_digest FROM ci_slack_outbox WHERE event_id = {} LIMIT 1;",
            sql_text_hex(&ev)
        );
        let raw = self.run_sql(&check_sql, true)?;
        let json_slice = raw
            .find('[')
            .map(|i| raw[i..].trim())
            .ok_or_else(|| "missing CI outbox row after insert".to_owned())?;
        let rows: Vec<DigestRow> = serde_json::from_str(json_slice).map_err(|e| e.to_string())?;
        let stored = rows
            .first()
            .ok_or_else(|| "missing CI outbox row after insert".to_owned())?;
        if stored.beat_digest != dig {
            return Err(format!("idempotency conflict on CI event_id {ev}"));
        }
        Ok(())
    }

    fn parse_entries(raw: &str) -> Result<Vec<CiOutboxEntry>, String> {
        let Some(idx) = raw.find('[') else {
            return Ok(Vec::new());
        };
        let rows: Vec<RawSqliteRow> =
            serde_json::from_str(raw[idx..].trim()).map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let signed_beat: SignedBlindSlackBeatV1 =
                serde_json::from_str(&r.payload_jcs).map_err(|e| e.to_string())?;
            out.push(CiOutboxEntry {
                event_id: r.event_id,
                beat_digest: r.beat_digest,
                signed_beat,
                acked: r.acked != 0,
                attempts: r.attempts,
                last_error: r.last_error,
            });
        }
        Ok(out)
    }

    pub fn pending_entries(&self) -> Result<Vec<CiOutboxEntry>, String> {
        let out = self.run_sql(
            "SELECT event_id, beat_digest, payload_jcs, acked, attempts, last_error \
             FROM ci_slack_outbox WHERE acked = 0 ORDER BY seq ASC;",
            true,
        )?;
        Self::parse_entries(&out)
    }

    pub fn all_entries(&self) -> Result<Vec<CiOutboxEntry>, String> {
        let out = self.run_sql(
            "SELECT event_id, beat_digest, payload_jcs, acked, attempts, last_error \
             FROM ci_slack_outbox ORDER BY seq ASC;",
            true,
        )?;
        Self::parse_entries(&out)
    }

    pub fn mark_acked(&self, event_id: &str) -> Result<(), String> {
        let sql = format!(
            "BEGIN IMMEDIATE;\n\
             UPDATE ci_slack_outbox SET acked = 1, attempts = attempts + 1, last_error = NULL \
             WHERE event_id = {};\n\
             COMMIT;",
            sql_text_hex(event_id)
        );
        self.run_sql(&sql, false)?;
        Ok(())
    }

    pub fn mark_failed_attempt(&self, event_id: &str, err: &str) -> Result<(), String> {
        let sql = format!(
            "BEGIN IMMEDIATE;\n\
             UPDATE ci_slack_outbox SET attempts = attempts + 1, last_error = {} \
             WHERE event_id = {};\n\
             COMMIT;",
            sql_text_hex(err),
            sql_text_hex(event_id)
        );
        self.run_sql(&sql, false)?;
        Ok(())
    }
}
