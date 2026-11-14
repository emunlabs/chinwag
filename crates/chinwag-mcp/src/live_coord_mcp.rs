//! Universal model-agnostic MCP live session lease & `<1ms` `[chinwag-bus-delta]` piggybacking
//! (`CHWG-0250` · `INV-UNIVERSAL-COORDINATION-01`).
#![forbid(unsafe_code)]

use chinwag_snapshot_read_owner_private::ReadOwner;
use chinwag_snapshot_session_private::{
    CrdbHeaderStamp, Rows, SnapshotSession, Value as SqlValue, fast_crdb_header_stamp,
    replacement::{LiveSessionLeaseRecord, WriteOwner, WriteSession},
};
use rmcp::model::{CallToolResult, ContentBlock, ResourceUpdatedNotificationParam};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LIVE_COORD_RESOURCE_URI: &str = "chinwag://live-coord/beacons";
const MAX_DELTA_SUMMARY_BYTES: usize = 2048;
const DEFAULT_LEASE_TTL_MS: i64 = 15 * 60 * 1000;
const LEASE_RENEWAL_INTERVAL_MS: i64 = 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveBeaconSummary {
    pub seq: u64,
    pub beacon_id: String,
    pub kind: String,
    pub actor: String,
    pub ticket_id: String,
    pub worktree: String,
    pub branch_ref: String,
    pub claimed_paths: Vec<String>,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusDeltaEnvelope {
    pub invariant: String,
    pub data_version: i64,
    pub db_version: i64,
    pub from_seq_exclusive: u64,
    pub through_seq_inclusive: u64,
    pub beacons: Vec<LiveBeaconSummary>,
}

impl BusDeltaEnvelope {
    pub fn summary_line(&self) -> String {
        let mut items = Vec::with_capacity(self.beacons.len().min(8));
        for beacon in self.beacons.iter().take(8) {
            let paths = if beacon.claimed_paths.is_empty() {
                String::new()
            } else {
                format!(" [{}]", beacon.claimed_paths.join(","))
            };
            let ticket = if beacon.ticket_id.is_empty() {
                "-".to_owned()
            } else {
                beacon.ticket_id.clone()
            };
            items.push(format!(
                "#{} {} {} by {}{}",
                beacon.seq, beacon.kind, ticket, beacon.actor, paths
            ));
        }
        if self.beacons.len() > 8 {
            items.push(format!("+{} more", self.beacons.len() - 8));
        }
        let raw = format!(
            "[chinwag-bus-delta · INV-UNIVERSAL-COORDINATION-01] seq {}..={} (data_v={}, db_v={}): {}",
            self.from_seq_exclusive.saturating_add(1),
            self.through_seq_inclusive,
            self.data_version,
            self.db_version,
            items.join("; ")
        );
        truncate_utf8(&raw, MAX_DELTA_SUMMARY_BYTES)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "invariant": self.invariant,
            "data_version": self.data_version,
            "db_version": self.db_version,
            "from_seq_exclusive": self.from_seq_exclusive,
            "through_seq_inclusive": self.through_seq_inclusive,
            "summary": self.summary_line(),
            "beacons": self.beacons,
        })
    }
}

pub fn build_resource_updated_param() -> ResourceUpdatedNotificationParam {
    ResourceUpdatedNotificationParam::new(LIVE_COORD_RESOURCE_URI)
}

pub fn attach_bus_delta_to_tool_result(
    mut result: CallToolResult,
    delta: Option<&BusDeltaEnvelope>,
) -> CallToolResult {
    let Some(delta) = delta else {
        return result;
    };
    if delta.beacons.is_empty() {
        return result;
    }
    result
        .content
        .insert(0, ContentBlock::text(delta.summary_line()));
    if let Some(Value::Object(map)) = result.structured_content.as_mut() {
        map.insert("_chinwag_bus_delta".to_owned(), delta.to_json());
    }
    result
}

#[derive(Clone, Debug)]
pub struct LiveSessionTracker {
    pub actor_instance: String,
    pub pid: u32,
    pub worktree: String,
    pub last_seen_seq: u64,
    pub last_notified_seq: u64,
    pub last_delivered_stamp: Option<CrdbHeaderStamp>,
    pub last_notified_stamp: Option<CrdbHeaderStamp>,
    pub last_own_write_stamp: Option<CrdbHeaderStamp>,
    pub last_lease_renewed_ms: i64,
}

impl LiveSessionTracker {
    pub fn for_repo(repo: &Path) -> Self {
        let pid = std::process::id();
        let actor_instance = std::env::var("CHINWAG_ACTOR")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("mcp-client#pid-{pid}"));
        Self {
            actor_instance,
            pid,
            worktree: repo.to_string_lossy().into_owned(),
            last_seen_seq: 0,
            last_notified_seq: 0,
            last_delivered_stamp: None,
            last_notified_stamp: None,
            last_own_write_stamp: None,
            last_lease_renewed_ms: 0,
        }
    }

    pub fn initialize_from_open_session(&mut self, repo: &Path, session: &SnapshotSession) {
        if let Ok(rows) = session.live_coord_beacons() {
            let max_seq = parse_beacon_rows(&rows)
                .into_iter()
                .map(|b| b.seq)
                .max()
                .unwrap_or(0);
            self.last_seen_seq = max_seq;
            self.last_notified_seq = max_seq;
        }
        let stamp = fast_crdb_header_stamp(repo);
        self.last_delivered_stamp = stamp;
        self.last_notified_stamp = stamp;
    }

    pub fn record_own_write_stamp(&mut self, repo: &Path) {
        self.record_exact_own_write_stamp(fast_crdb_header_stamp(repo));
    }

    pub fn record_exact_own_write_stamp(&mut self, stamp: Option<CrdbHeaderStamp>) {
        self.last_own_write_stamp = stamp;
        self.last_delivered_stamp = stamp;
        self.last_notified_stamp = stamp;
    }

    /// Returns `true` if unread external beacons exist above `last_seen_seq` OR the SQLite
    /// header stamp changed outside this session's own writes (independent of watcher ticks!).
    pub fn has_external_change(&self, current: Option<CrdbHeaderStamp>) -> bool {
        if self.last_notified_seq > self.last_seen_seq {
            return true;
        }
        let Some(cur) = current else {
            return false;
        };
        if self.last_delivered_stamp == Some(cur) || self.last_own_write_stamp == Some(cur) {
            return false;
        }
        true
    }

    pub fn consume_delta_from_open_session(
        &mut self,
        repo: &Path,
        session: &SnapshotSession,
    ) -> Option<BusDeltaEnvelope> {
        let rows = session.live_coord_beacons().ok()?;
        let (data_version, db_version) = session.pragma_data_and_db_version().unwrap_or((0, 0));
        let all = parse_beacon_rows(&rows);
        let max_seq = all
            .iter()
            .map(|b| b.seq)
            .max()
            .unwrap_or(self.last_seen_seq);
        let from_seq = self.last_seen_seq;
        let unread: Vec<LiveBeaconSummary> = all
            .into_iter()
            .filter(|b| b.seq > from_seq && b.actor != self.actor_instance)
            .collect();
        self.last_seen_seq = max_seq;
        self.last_notified_seq = self.last_notified_seq.max(max_seq);
        let stamp = fast_crdb_header_stamp(repo);
        self.last_delivered_stamp = stamp;
        self.last_notified_stamp = stamp;
        if unread.is_empty() {
            None
        } else {
            Some(BusDeltaEnvelope {
                invariant: "INV-UNIVERSAL-COORDINATION-01".to_owned(),
                data_version,
                db_version,
                from_seq_exclusive: from_seq,
                through_seq_inclusive: max_seq,
                beacons: unread,
            })
        }
    }

    /// Checks whether `.chinwag/state.crdb` has unread beacons above `last_notified_seq`
    /// without advancing `last_seen_seq` or `last_delivered_stamp` (so even after multiple
    /// watcher ticks, the next read OR write `call_tool` still piggybacks `[chinwag-bus-delta]`).
    pub fn peek_unnotified_beacons(&mut self, repo: &Path) -> Result<bool, String> {
        let Some(current) = fast_crdb_header_stamp(repo) else {
            return Ok(false);
        };
        if self.last_notified_stamp == Some(current) || self.last_own_write_stamp == Some(current) {
            return Ok(false);
        }
        let owner = ReadOwner::acquire_existing_private_fixture(repo)
            .map_err(|e| format!("acquire_read_owner: {}", e.reason))?;
        let session = SnapshotSession::from_owner(owner).map_err(|e| e.to_string())?;
        let rows = session.live_coord_beacons().map_err(|e| e.to_string());
        session.finish().map_err(|e| e.to_string())?;
        let rows = rows?;
        self.last_notified_stamp = Some(current);
        let all = parse_beacon_rows(&rows);
        let max_external = all
            .iter()
            .filter(|b| b.seq > self.last_notified_seq && b.actor != self.actor_instance)
            .map(|b| b.seq)
            .max();
        if let Some(seq) = max_external {
            self.last_notified_seq = seq;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn renew_lease_if_due(&mut self, repo: &Path, force: bool) -> Result<bool, String> {
        let now = now_ms();
        if !force
            && self.last_lease_renewed_ms > 0
            && now.saturating_sub(self.last_lease_renewed_ms) < LEASE_RENEWAL_INTERVAL_MS
        {
            return Ok(false);
        }
        let _ = self.persist_lease_to_crdb(repo)?;
        Ok(true)
    }

    pub fn persist_lease_to_crdb(&mut self, repo: &Path) -> Result<Value, String> {
        let now = now_ms();
        let expires = now.saturating_add(DEFAULT_LEASE_TTL_MS);
        let record = LiveSessionLeaseRecord::try_new(
            self.actor_instance.clone(),
            self.pid,
            self.worktree.clone(),
            self.last_seen_seq,
            now,
            expires,
        )
        .map_err(str::to_owned)?;
        // Capture both `before_stamp` and `after_stamp` strictly from `completion.observation()`,
        // which samples the held file identities under the exclusive `.chinwag` write lock before
        // replacement and prior to lock release (zero pre-lock or post-unlock TOCTOU window).
        let owner = WriteOwner::acquire_existing_private_fixture(repo)
            .map_err(|e| format!("lease_write_owner: {}", e.reason))?;
        let session = WriteSession::from_owner(owner).map_err(|e| e.to_string())?;
        let prepared = session
            .prepare_live_session_lease(record, || false)
            .map_err(|e| e.to_string())?;
        let completion = prepared.commit(false).map_err(|e| e.to_string())?;
        let before_stamp = completion.observation().before_header_stamp();
        let after_stamp = completion.observation().after_header_stamp();
        let had_external_before = self.has_external_change(before_stamp);
        let had_unnotified_before = before_stamp.is_some_and(|cur| {
            self.last_notified_stamp != Some(cur) && self.last_own_write_stamp != Some(cur)
        });
        if had_external_before {
            self.last_own_write_stamp = None;
            if !had_unnotified_before {
                self.last_notified_stamp = after_stamp;
            }
        } else {
            self.record_exact_own_write_stamp(after_stamp);
        }
        self.last_lease_renewed_ms = now;
        if completion.is_error() {
            Err(completion.response().to_string())
        } else {
            Ok(completion.response().clone())
        }
    }
}

pub fn register_live_session_lease(
    repo: &Path,
    actor_instance: &str,
    pid: u32,
    worktree: &str,
    last_seen_seq: u64,
) -> Result<Value, String> {
    let mut tracker = LiveSessionTracker {
        actor_instance: actor_instance.to_owned(),
        pid,
        worktree: worktree.to_owned(),
        last_seen_seq,
        last_notified_seq: last_seen_seq,
        last_delivered_stamp: None,
        last_notified_stamp: None,
        last_own_write_stamp: None,
        last_lease_renewed_ms: 0,
    };
    tracker.persist_lease_to_crdb(repo)
}

pub fn parse_beacon_rows(rows: &Rows) -> Vec<LiveBeaconSummary> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let [
            SqlValue::Text(id),
            SqlValue::Text(actor),
            SqlValue::Text(role),
            SqlValue::Text(body),
            SqlValue::Integer(created_at_ms),
        ] = row.as_slice()
        else {
            continue;
        };
        let (seq_str, kind_str) = role.split_once(':').unwrap_or(("0", role.as_str()));
        let seq = seq_str.parse::<u64>().unwrap_or(0);
        let parsed: Value = serde_json::from_str(body).unwrap_or_else(|_| json!({}));
        let ticket_id = parsed
            .get("ticket_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let worktree = parsed
            .get("worktree")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let branch_ref = parsed
            .get("branch_ref")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let claimed_paths = parsed
            .get("claimed_paths")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        out.push(LiveBeaconSummary {
            seq,
            beacon_id: id.clone(),
            kind: kind_str.to_owned(),
            actor: actor.clone(),
            ticket_id,
            worktree,
            branch_ref,
            claimed_paths,
            created_at_ms: *created_at_ms,
        });
    }
    out
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(all(test, feature = "private-http-probe"))]
mod tests {
    use super::*;
    use crate::owner::Owner;
    use chinwag_snapshot_session_private::replacement::LiveCoordBeaconRecord;
    use rmcp::{ServiceExt, transport::async_rw::AsyncRwTransport};
    use std::time::Instant;

    fn emit_test_beacon(
        repo: &Path,
        id: &str,
        kind: &str,
        actor: &str,
        ticket: &str,
        paths: Vec<String>,
    ) {
        let owner = WriteOwner::acquire_existing_private_fixture(repo).unwrap();
        let session = WriteSession::from_owner(owner).unwrap();
        let payload = json!({
            "actor": actor,
            "ticket_id": ticket,
            "worktree": repo.to_string_lossy(),
            "branch_ref": "refs/heads/feat-test",
            "claimed_paths": paths,
        })
        .to_string();
        let rec = LiveCoordBeaconRecord::try_new(
            id.to_owned(),
            kind.to_owned(),
            actor.to_owned(),
            "local/repo".to_owned(),
            "refs/heads/feat-test".to_owned(),
            repo.to_string_lossy().into_owned(),
            ticket.to_owned(),
            paths,
            payload,
            "sha256:test".to_owned(),
            2_000_000_000_000,
            1_700_000_000_000,
        )
        .unwrap();
        let prepared = session.prepare_live_coord_beacon(rec, || false).unwrap();
        let done = prepared.commit(false).unwrap();
        assert!(!done.is_error());
    }

    #[test]
    fn mcp_session_lease_fast_stamp_and_bus_delta_piggyback_work_end_to_end() {
        let _serial = crate::http_tests::serialize_native_probe();
        let repo = chinwag_test_fixtures::initialized_repo_at("CHINWAG_MCP_LIVE_COORD_FIXTURE");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (server, owner) = Owner::start(repo.clone(), true).await.unwrap();
            let lease_val = owner.register_session_lease().await.unwrap();
            assert_eq!(lease_val["last_seen_seq"], 0);

            // Seed a thread via chinwag_pin_context first so we can read it later.
            let (client_io, server_io) = tokio::io::duplex(65_536);
            let (server_read, server_write) = tokio::io::split(server_io);
            let (mut client_read, mut client_write) = tokio::io::split(client_io);
            let transport =
                AsyncRwTransport::new(server_read, crate::wire::BoundedWriter::new(server_write))
                    .with_max_line_length(crate::wire::MAX_INPUT_BYTES);
            let serve_task = tokio::spawn(async move { server.serve(transport).await });

            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let mut reader = BufReader::new(&mut client_read);

            // 1. Initialize MCP session over stdio duplex (completes `server.serve` handshake).
            let init_req = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "universal-test-client", "version": "1.0.0" }
                }
            });
            client_write
                .write_all(format!("{init_req}\n").as_bytes())
                .await
                .unwrap();
            client_write.flush().await.unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let init_resp: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(init_resp["id"], 1);

            let initialized_notif = json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            });
            client_write
                .write_all(format!("{initialized_notif}\n").as_bytes())
                .await
                .unwrap();
            client_write.flush().await.unwrap();

            let running = serve_task.await.unwrap().unwrap();
            let peer = running.peer().clone();

            // 2. Pin initial thread (no external beacons yet -> zero delta).
            let pin_req = json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "chinwag_pin_context",
                    "arguments": {
                        "id": "pin-1",
                        "thread_id": "thread-1",
                        "file_path": "src/lib.rs",
                        "symbol_hash": "sym-1",
                        "source_commit": "abc1234",
                        "body": "Initial context",
                        "created_at_ms": 1000,
                        "create_thread": {
                            "repo_id": "local/repo",
                            "branch_ref": "refs/heads/main",
                            "title": "Test Thread"
                        }
                    }
                }
            });
            client_write
                .write_all(format!("{pin_req}\n").as_bytes())
                .await
                .unwrap();
            client_write.flush().await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let pin_resp: Value = serde_json::from_str(&line).unwrap();
            assert!(
                pin_resp["result"]["structuredContent"]
                    .get("_chinwag_bus_delta")
                    .is_none()
            );

            // 3. Measure `<1ms` fast header stamp check when unchanged.
            let t0 = Instant::now();
            let stamp_before = fast_crdb_header_stamp(&repo).unwrap();
            let elapsed_us = t0.elapsed().as_micros();
            assert!(
                elapsed_us < 1_000,
                "fast_crdb_header_stamp took {elapsed_us}us (expected <1000us)"
            );

            // 4. External agent emits CLAIM_ACQUIRED + PR_OPENED beacons into state.crdb!
            emit_test_beacon(
                &repo,
                "beacon-ext-1",
                "CLAIM_ACQUIRED",
                "ARCHITECT#0123456789abcdef0123456789abcdef",
                "CHWG-0250",
                vec!["crates/chinwag-cli/src/live_coord.rs".to_owned()],
            );
            emit_test_beacon(
                &repo,
                "beacon-ext-2",
                "PR_OPENED",
                "ARCHITECT#0123456789abcdef0123456789abcdef",
                "CHWG-0250",
                vec![],
            );
            let stamp_after = fast_crdb_header_stamp(&repo).unwrap();
            assert_ne!(stamp_before, stamp_after);

            // 5. Peek unnotified delta and push standard `notifications/resources/updated`!
            assert!(owner.peek_unnotified_delta().await.unwrap());
            peer.notify_resource_updated(build_resource_updated_param())
                .await
                .unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let notif_msg: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(notif_msg["method"], "notifications/resources/updated");
            assert_eq!(notif_msg["params"]["uri"], LIVE_COORD_RESOURCE_URI);

            // 6. Next tool call (`chinwag_read_thread`) receives prepended `[chinwag-bus-delta]`!
            let read_req = json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "chinwag_read_thread",
                    "arguments": { "thread_id": "thread-1" }
                }
            });
            client_write
                .write_all(format!("{read_req}\n").as_bytes())
                .await
                .unwrap();
            client_write.flush().await.unwrap();

            // `call_tool` also emits notifications/resources/updated before returning the response;
            // read lines until id == 3 arrives.
            let read_resp = loop {
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                let msg: Value = serde_json::from_str(&line).unwrap();
                if msg.get("id") == Some(&json!(3)) {
                    break msg;
                }
            };
            let first_text = read_resp["result"]["content"][0]["text"].as_str().unwrap();
            assert!(
                first_text.starts_with("[chinwag-bus-delta · INV-UNIVERSAL-COORDINATION-01]"),
                "unexpected first_text: {first_text}"
            );
            assert!(first_text.contains("CLAIM_ACQUIRED CHWG-0250"));
            assert!(first_text.contains("PR_OPENED CHWG-0250"));
            let structured_delta = &read_resp["result"]["structuredContent"]["_chinwag_bus_delta"];
            assert_eq!(structured_delta["from_seq_exclusive"], 0);
            assert_eq!(structured_delta["through_seq_inclusive"], 2);
            assert_eq!(structured_delta["beacons"].as_array().unwrap().len(), 2);

            // 7. Subsequent read with no new beacons has ZERO delta attached.
            let read_req_2 = json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "chinwag_read_thread",
                    "arguments": { "thread_id": "thread-1" }
                }
            });
            client_write
                .write_all(format!("{read_req_2}\n").as_bytes())
                .await
                .unwrap();
            client_write.flush().await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let read_resp_2: Value = serde_json::from_str(&line).unwrap();
            assert!(
                read_resp_2["result"]["structuredContent"]
                    .get("_chinwag_bus_delta")
                    .is_none()
            );

            // 8. Verify multi-tick watcher peeks + forced lease renewal NEVER suppress
            // `[chinwag-bus-delta]` piggybacking on a subsequent write tool (`chinwag_pin_context`)!
            emit_test_beacon(
                &repo,
                "beacon-ext-3",
                "PR_MERGED",
                "ARCHITECT#0123456789abcdef0123456789abcdef",
                "CHWG-0250",
                vec![],
            );
            // Tick 1 detects new external beacon; Tick 2 sees same stamp -> returns false;
            // Forced lease renewal writes to CRDB while external delta is still undelivered!
            assert!(owner.peek_unnotified_delta().await.unwrap());
            assert!(!owner.peek_unnotified_delta().await.unwrap());
            assert!(!owner.renew_session_lease(false).await.unwrap());
            assert!(owner.renew_session_lease(true).await.unwrap());

            let pin_req_2 = json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "chinwag_pin_context",
                    "arguments": {
                        "id": "pin-2",
                        "thread_id": "thread-1",
                        "file_path": "src/lib.rs",
                        "symbol_hash": "sym-2",
                        "source_commit": "def5678",
                        "body": "Follow-up pin after multi-tick peek + lease renewal",
                        "created_at_ms": 2000
                    }
                }
            });
            client_write
                .write_all(format!("{pin_req_2}\n").as_bytes())
                .await
                .unwrap();
            client_write.flush().await.unwrap();
            let pin_resp_2 = loop {
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                let msg: Value = serde_json::from_str(&line).unwrap();
                if msg.get("id") == Some(&json!(5)) {
                    break msg;
                }
            };
            let pin_text_2 = pin_resp_2["result"]["content"][0]["text"].as_str().unwrap();
            assert!(
                pin_text_2.starts_with("[chinwag-bus-delta · INV-UNIVERSAL-COORDINATION-01]"),
                "write tool after multi-tick peek + lease renewal missed bus delta: {pin_text_2}"
            );
            assert!(pin_text_2.contains("PR_MERGED CHWG-0250"));
            assert_eq!(
                pin_resp_2["result"]["structuredContent"]["_chinwag_bus_delta"]
                    ["through_seq_inclusive"],
                3
            );

            drop(peer);
            drop(reader);
            drop(client_read);
            drop(client_write);
            let _ = running.waiting().await;
            owner.shutdown().await.unwrap();
        });
    }
}
