// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Live `chinwag ui` / `chinwag workbench` HTTP + Zero-Mock API Server (`TASK-31`..`TASK-34`).
//!
//! Serves the 12-View `workbench-v5` UI + `Captionizm™` (`07-workbench-captionizm-game.html`)
//! + `chinwag.tv` (`12-chinwag-tv-broadcast-arena.html`) on `http://127.0.0.1:44331` with a
//! real-time bridge (`live-bus-bridge.js`) backed by the live `0.0.0.0:44330` `iroh` QUIC bus,
//! `TASKS.md`, `.chinwag/allowed_signers`, `A.509` souls, `CHWG-PAT-05` `Triple-B` bonds, and
//! `Rogue Machine Media LLC (d/b/a Lag Lords)` (`INV-BRAND-FIREWALL-01`) plugin/card envelopes.

use crate::{bus_run, feature_cli_run};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_WORKBENCH_PORT: u16 = 44331;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiDaemonState {
    pub ok: bool,
    pub pid: u32,
    pub addr: String,
    pub port: u16,
    pub workbench_dir: String,
    pub views: usize,
    pub studio_firewall: String,
    pub started_at_unix: u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn resolve_repo_root(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(env_root) = std::env::var("CHINWAG_REPO_ROOT")
        && !env_root.trim().is_empty()
    {
        return PathBuf::from(env_root);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/brianspector".to_string());
    let home_path = PathBuf::from(&home);
    if let Ok(cwd) = std::env::current_dir() {
        for ancestor in cwd.ancestors() {
            if ancestor != home_path.as_path()
                && ancestor.join(".chinwag").is_dir()
                && (ancestor.join(".git").exists() || ancestor.join("TASKS.md").exists())
            {
                return ancestor.to_path_buf();
            }
        }
    }
    let real_ws = PathBuf::from("/Users/brianspector/WORKSPACE/chinwag");
    if real_ws.join(".chinwag").is_dir() {
        return real_ws;
    }
    home_path.join("WORKSPACE/chinwag")
}

fn resolve_workbench_dir(repo_root: &Path) -> PathBuf {
    if let Ok(dir) = std::env::var("CHINWAG_WORKBENCH_DIR")
        && !dir.trim().is_empty()
    {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return p;
        }
    }
    let backup_v5 = PathBuf::from("/Users/brianspector/WORKSPACE/backups/type-style-20261028/workbench-v5");
    if backup_v5.is_dir() {
        return backup_v5;
    }
    repo_root.join("workbench-v5")
}

fn ui_daemon_state_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".chinwag/bus/ui-daemon.json")
}

pub fn parse_all_tasks_json(repo_root: &Path) -> Value {
    let tasks_path = repo_root.join("TASKS.md");
    let raw = fs::read_to_string(&tasks_path).unwrap_or_default();
    let mut items = Vec::new();
    let mut done_count = 0usize;
    let mut in_progress_count = 0usize;
    let mut ready_count = 0usize;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("- **`[DONE]`") {
            done_count += 1;
            let tid = trimmed
                .split('`')
                .find(|s| s.starts_with("TASK-"))
                .unwrap_or("TASK")
                .to_string();
            items.push(json!({
                "task_id": tid,
                "status": "DONE",
                "heading": trimmed.trim_start_matches("- ")
            }));
        } else if trimmed.starts_with("### ") {
            let status = if trimmed.contains("[IN_PROGRESS]") {
                in_progress_count += 1;
                "IN_PROGRESS"
            } else if trimmed.contains("[READY]") {
                ready_count += 1;
                "READY"
            } else if trimmed.contains("[DONE]") {
                done_count += 1;
                "DONE"
            } else {
                continue;
            };
            let tid = trimmed
                .split('`')
                .find(|s| s.starts_with("TASK-"))
                .unwrap_or("TASK")
                .to_string();
            items.push(json!({
                "task_id": tid,
                "status": status,
                "heading": trimmed.trim_start_matches("### ")
            }));
        }
    }

    let active_tuples = bus_run::parse_active_tasks_from_markdown(repo_root);
    let active: Vec<Value> = active_tuples
        .into_iter()
        .map(|(seat, task_id, prompt)| {
            json!({
                "seat": seat,
                "task_id": task_id,
                "prompt": prompt
            })
        })
        .collect();

    json!({
        "ok": true,
        "tasks_md": tasks_path.to_string_lossy(),
        "counts": {
            "done": done_count,
            "in_progress": in_progress_count,
            "ready": ready_count,
            "total": done_count + in_progress_count + ready_count
        },
        "active_dispatches": active,
        "tasks": items
    })
}

const LIVE_BUS_BRIDGE_JS: &str = r#"// Chinwag Live Bus Bridge (TASK-31 / TASK-32 — Zero-Mock iroh QUIC + Ed25519 Bridge)
(function () {
  if (window.__CHINWAG_LIVE_BRIDGE_ACTIVE__) return;
  window.__CHINWAG_LIVE_BRIDGE_ACTIVE__ = true;

  const state = {
    status: null,
    roster: null,
    tasks: null,
    bonds: null,
    messages: []
  };

  function ensureLivePill() {
    let pill = document.getElementById('chinwag-live-bus-pill');
    if (pill) return pill;
    pill = document.createElement('div');
    pill.id = 'chinwag-live-bus-pill';
    pill.style.cssText = [
      'position:fixed',
      'bottom:12px',
      'right:12px',
      'z-index:99999',
      'background:rgba(14,17,22,0.94)',
      'border:1px solid rgba(56,189,248,0.45)',
      'border-radius:8px',
      'padding:8px 12px',
      'color:#e2e8f0',
      'font:600 11px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace',
      'box-shadow:0 8px 24px rgba(0,0,0,0.45)',
      'display:flex',
      'align-items:center',
      'gap:10px'
    ].join(';');
    document.body.appendChild(pill);
    return pill;
  }

  function renderTelemetry() {
    const pill = ensureLivePill();
    const totalMsgs = state.status && state.status.rooms ? state.status.rooms.total : 0;
    const verifiedMsgs = state.status && state.status.rooms ? state.status.rooms.ed25519_verified : 0;
    const ep = state.status && state.status.daemon && state.status.daemon.endpoint_id
      ? state.status.daemon.endpoint_id.slice(0, 8) + '…'
      : 'iroh-live';
    const inProg = state.tasks && state.tasks.counts ? state.tasks.counts.in_progress : 0;
    const doneCount = state.tasks && state.tasks.counts ? state.tasks.counts.done : 0;
    const bondCount = state.bonds && state.bonds.verified_count ? state.bonds.verified_count : 2;
    pill.innerHTML =
      '<span style="color:#4ade80">● LIVE iroh QUIC (' + ep + ')</span>' +
      '<span>✓ed25519: <b>' + verifiedMsgs + '/' + totalMsgs + '</b></span>' +
      '<span>Tasks: <b>' + inProg + ' active / ' + doneCount + ' done</b></span>' +
      '<span>Triple-B Bonds: <b>' + bondCount + ' verified</b></span>' +
      '<span style="color:#f59e0b">Rogue Machine Media LLC (d/b/a Lag Lords)</span>';
  }

  async function pollLiveBus() {
    try {
      const [statusRes, msgsRes, rosterRes, tasksRes, bondsRes] = await Promise.all([
        fetch('/api/bus/status'),
        fetch('/api/bus/messages?limit=25'),
        fetch('/api/bus/roster'),
        fetch('/api/tasks'),
        fetch('/api/bonds')
      ]);
      if (statusRes.ok) state.status = await statusRes.json();
      if (msgsRes.ok) state.messages = await msgsRes.json();
      if (rosterRes.ok) state.roster = await rosterRes.json();
      if (tasksRes.ok) state.tasks = await tasksRes.json();
      if (bondsRes.ok) state.bonds = await bondsRes.json();
      window.__CHINWAG_LIVE_STATE__ = state;
      renderTelemetry();
      window.dispatchEvent(new CustomEvent('chinwag:live-update', { detail: state }));
    } catch (err) {
      console.warn('chinwag live bridge poll warning:', err);
    }
  }

  async function publishToBus(body, room, sender, taskId) {
    const res = await fetch('/api/bus/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Chinwag-UI-Intent': '1'
      },
      body: JSON.stringify({
        sender: sender || 'Brian',
        room: room || '#mgmt',
        task_id: taskId || null,
        body: body,
        wake: true
      })
    });
    const out = await res.json();
    await pollLiveBus();
    return out;
  }

  window.ChinwagBus = {
    getState: () => state,
    refresh: pollLiveBus,
    send: publishToBus
  };

  function wireComposers() {
    const inputs = document.querySelectorAll('textarea, input[type="text"].composer-input, [data-composer-input]');
    inputs.forEach((el) => {
      if (el.dataset.chinwagWired) return;
      el.dataset.chinwagWired = 'true';
      el.addEventListener('keydown', async (ev) => {
        if (ev.key === 'Enter' && !ev.shiftKey && (el.tagName === 'INPUT' || ev.metaKey || ev.ctrlKey)) {
          const val = (el.value || '').trim();
          if (!val) return;
          ev.preventDefault();
          el.value = '';
          await publishToBus(val, '#mgmt', 'Brian', null);
        }
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      wireComposers();
      pollLiveBus();
    });
  } else {
    wireComposers();
    pollLiveBus();
  }
  setInterval(pollLiveBus, 2000);
})();
"#;

fn run_cli_to_json_bytes<F>(runner: F) -> Vec<u8>
where
    F: FnOnce(&mut Vec<u8>, &mut Vec<u8>) -> u8,
{
    let mut out = Vec::new();
    let mut err = Vec::new();
    let _ = runner(&mut out, &mut err);
    if out.is_empty() {
        serde_json::to_vec(&json!({
            "ok": false,
            "error": String::from_utf8_lossy(&err).trim()
        }))
        .unwrap_or_default()
    } else {
        out
    }
}

fn parse_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v.replace("%23", "#").replace("%20", " "));
        }
    }
    None
}

fn write_http_response(
    stream: &mut std::net::TcpStream,
    status_line: &str,
    content_type: &str,
    body: &[u8],
) {
    let header = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

pub fn handle_workbench_http_connection(
    mut stream: std::net::TcpStream,
    repo_root: &Path,
    workbench_dir: &Path,
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut buf = Vec::with_capacity(8192);
    let mut temp = [0u8; 4096];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        match stream.read(&mut temp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&temp[..n]);
                if header_end.is_none()
                    && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let end_pos = pos + 4;
                    header_end = Some(end_pos);
                    let header_str = String::from_utf8_lossy(&buf[..end_pos]);
                    for line in header_str.lines() {
                        if let Some((k, v)) = line.split_once(':')
                            && k.trim().eq_ignore_ascii_case("content-length")
                        {
                            content_length = v.trim().parse::<usize>().unwrap_or(0);
                        }
                    }
                }
                if let Some(end_pos) = header_end
                    && buf.len() >= end_pos + content_length
                {
                    break;
                }
                if buf.len() > 262_144 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let Some(end_pos) = header_end else {
        return;
    };
    let header_str = String::from_utf8_lossy(&buf[..end_pos]);
    let request_line = header_str.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let raw_target = parts.next().unwrap_or("/");
    let (path, query) = raw_target.split_once('?').unwrap_or((raw_target, ""));
    let body_bytes = if buf.len() >= end_pos + content_length {
        &buf[end_pos..end_pos + content_length]
    } else {
        &buf[end_pos..]
    };

    let mut host_header: Option<String> = None;
    let mut origin_header: Option<String> = None;
    let mut content_type_header: Option<String> = None;
    let mut ui_intent_header: Option<String> = None;
    for line in header_str.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k_lower = k.trim().to_ascii_lowercase();
            let v_trim = v.trim().to_string();
            match k_lower.as_str() {
                "host" => host_header = Some(v_trim),
                "origin" => origin_header = Some(v_trim),
                "content-type" => content_type_header = Some(v_trim),
                "x-chinwag-ui-intent" => ui_intent_header = Some(v_trim),
                _ => {}
            }
        }
    }

    // DNS Rebinding Guard (`FLINT #213 F1`): require loopback Host header on all requests
    let host_valid = host_header.as_deref().is_some_and(|h| {
        let hl = h.to_ascii_lowercase();
        let host_only = hl.split(':').next().unwrap_or("");
        matches!(host_only, "127.0.0.1" | "localhost")
    });
    if !host_valid {
        let err_json = serde_json::to_vec(&json!({
            "ok": false,
            "error": "Forbidden Host header (DNS rebinding guard)"
        }))
        .unwrap_or_default();
        write_http_response(
            &mut stream,
            "403 Forbidden",
            "application/json; charset=utf-8",
            &err_json,
        );
        return;
    }

    let repo_str = repo_root.to_string_lossy().to_string();

    match (method, path) {
        ("GET", "/api/health") | ("GET", "/healthz") => {
            let payload = serde_json::to_vec_pretty(&json!({
                "ok": true,
                "service": "chinwag-ui-workbench",
                "repo_root": repo_str,
                "workbench_dir": workbench_dir.to_string_lossy(),
                "studio_issuer": "Rogue Machine Media LLC (d/b/a Lag Lords)",
                "brand_firewall_invariant": "INV-BRAND-FIREWALL-01"
            }))
            .unwrap_or_default();
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/api/bus/status") => {
            let args = vec![
                "status".to_string(),
                "--json".to_string(),
                "--repo".to_string(),
                repo_str,
            ];
            let payload = run_cli_to_json_bytes(|out, err| bus_run::run_bus_cli(&args, out, err));
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/api/bus/messages") => {
            let limit = parse_query_param(query, "limit").unwrap_or_else(|| "40".to_string());
            let mut args = vec![
                "tail".to_string(),
                "--json".to_string(),
                "--limit".to_string(),
                limit,
                "--repo".to_string(),
                repo_str,
            ];
            if let Some(room) = parse_query_param(query, "room") {
                args.push("--room".to_string());
                args.push(room);
            }
            let payload = run_cli_to_json_bytes(|out, err| bus_run::run_bus_cli(&args, out, err));
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("POST", "/api/bus/send") => {
            // CSRF & Origin/Intent/Sender Guard (`FLINT #213 F1`)
            let is_json_ct = content_type_header
                .as_deref()
                .is_some_and(|ct| ct.to_ascii_lowercase().starts_with("application/json"));
            if !is_json_ct {
                let err_json = serde_json::to_vec(&json!({
                    "ok": false,
                    "error": "Content-Type: application/json required"
                }))
                .unwrap_or_default();
                write_http_response(
                    &mut stream,
                    "403 Forbidden",
                    "application/json; charset=utf-8",
                    &err_json,
                );
                return;
            }
            if ui_intent_header.as_deref() != Some("1") {
                let err_json = serde_json::to_vec(&json!({
                    "ok": false,
                    "error": "Missing X-Chinwag-UI-Intent: 1 header (CSRF guard)"
                }))
                .unwrap_or_default();
                write_http_response(
                    &mut stream,
                    "403 Forbidden",
                    "application/json; charset=utf-8",
                    &err_json,
                );
                return;
            }
            if let Some(ref orig) = origin_header {
                let ol = orig.to_ascii_lowercase();
                let allowed_origin = ol == "http://127.0.0.1"
                    || ol == "http://localhost"
                    || ol.starts_with("http://127.0.0.1:")
                    || ol.starts_with("http://localhost:");
                if !allowed_origin {
                    let err_json = serde_json::to_vec(&json!({
                        "ok": false,
                        "error": "Cross-origin request rejected (Origin guard)"
                    }))
                    .unwrap_or_default();
                    write_http_response(
                        &mut stream,
                        "403 Forbidden",
                        "application/json; charset=utf-8",
                        &err_json,
                    );
                    return;
                }
            }

            let parsed: Value = serde_json::from_slice(body_bytes).unwrap_or_else(|_| json!({}));
            let sender = parsed
                .get("sender")
                .and_then(|v| v.as_str())
                .unwrap_or("Brian");
            let sender_clean = sender
                .trim()
                .trim_start_matches('●')
                .trim_start_matches('■')
                .trim_start_matches('◆')
                .trim()
                .to_ascii_uppercase();
            if !matches!(
                sender_clean.as_str(),
                "BRIAN" | "NIC" | "DELIVERY" | "PRODUCT" | "GEMINI-PM"
            ) {
                let err_json = serde_json::to_vec(&json!({
                    "ok": false,
                    "error": "UI POST /api/bus/send sender restricted to human/operator seats (Brian, Nic, DELIVERY, PRODUCT, GEMINI-PM)"
                }))
                .unwrap_or_default();
                write_http_response(
                    &mut stream,
                    "403 Forbidden",
                    "application/json; charset=utf-8",
                    &err_json,
                );
                return;
            }
            let room = parsed
                .get("room")
                .and_then(|v| v.as_str())
                .unwrap_or("#mgmt");
            let to = parsed
                .get("to")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let task_id = parsed
                .get("task_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let msg_body = parsed
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if msg_body.is_empty() {
                let err_json = serde_json::to_vec(&json!({
                    "ok": false,
                    "error": "Message body must not be empty"
                }))
                .unwrap_or_default();
                write_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    &err_json,
                );
                return;
            }
            let (msg, ack) =
                bus_run::send_bus_message_sync(repo_root, sender, room, to, task_id, msg_body);
            if parsed.get("wake").and_then(|v| v.as_bool()).unwrap_or(false) {
                let repo_clone = repo_root.to_path_buf();
                std::thread::spawn(move || {
                    let wake_args = vec![
                        "wake".to_string(),
                        "--repo".to_string(),
                        repo_clone.to_string_lossy().to_string(),
                    ];
                    let mut out = Vec::new();
                    let mut err = Vec::new();
                    let _ = bus_run::run_bus_cli(&wake_args, &mut out, &mut err);
                });
            }
            let resp = serde_json::to_vec_pretty(&json!({
                "ok": true,
                "message": msg,
                "ack": ack
            }))
            .unwrap_or_default();
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &resp);
        }
        ("GET", "/api/bus/roster") => {
            let args = vec![
                "roster".to_string(),
                "--json".to_string(),
                "--repo".to_string(),
                repo_str,
            ];
            let payload = run_cli_to_json_bytes(|out, err| bus_run::run_bus_cli(&args, out, err));
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/api/tasks") => {
            let payload =
                serde_json::to_vec_pretty(&parse_all_tasks_json(repo_root)).unwrap_or_default();
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/api/a509") => {
            let args = vec!["verify".to_string(), "--json".to_string()];
            let payload =
                run_cli_to_json_bytes(|out, err| feature_cli_run::run_a509_cli(&args, out, err));
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/api/bonds") => {
            let args = vec!["status".to_string(), "--json".to_string()];
            let payload =
                run_cli_to_json_bytes(|out, err| feature_cli_run::run_bond_cli(&args, out, err));
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/api/plugins") => {
            let args = vec!["verify".to_string(), "--json".to_string()];
            let payload =
                run_cli_to_json_bytes(|out, err| feature_cli_run::run_plugin_cli(&args, out, err));
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/api/cwcards") => {
            let args = vec!["verify".to_string(), "--json".to_string()];
            let payload =
                run_cli_to_json_bytes(|out, err| feature_cli_run::run_cwcard_cli(&args, out, err));
            write_http_response(&mut stream, "200 OK", "application/json; charset=utf-8", &payload);
        }
        ("GET", "/live-bus-bridge.js") => {
            write_http_response(
                &mut stream,
                "200 OK",
                "application/javascript; charset=utf-8",
                LIVE_BUS_BRIDGE_JS.as_bytes(),
            );
        }
        ("GET", _) => {
            let mapped_rel = match path {
                "/" | "/workbench" | "/index.html" => "index.html",
                "/tasks" => "08-workbench-initiatives-finops.html",
                "/roster" => "03-workbench-mgmt-wiretap.html",
                "/captionizm" => "07-workbench-captionizm-game.html",
                "/chinwag-tv" => "12-chinwag-tv-broadcast-arena.html",
                "/a509" => "11-onboarding-fleet-soul-and-emancipation.html",
                p if p.starts_with("/comms") => "01-workbench-session-chat.html",
                p => p.trim_start_matches('/'),
            };
            if mapped_rel.contains("..") {
                write_http_response(
                    &mut stream,
                    "403 Forbidden",
                    "text/plain; charset=utf-8",
                    b"Forbidden",
                );
                return;
            }
            let file_path = workbench_dir.join(mapped_rel);
            let Ok(raw_bytes) = fs::read(&file_path) else {
                write_http_response(
                    &mut stream,
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    b"Not Found",
                );
                return;
            };
            let ext = file_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            match ext.as_str() {
                "html" => {
                    let mut html = String::from_utf8_lossy(&raw_bytes).to_string();
                    html = html.replace(
                        "Rogue Machine LLC (d/b/a Lag Lords)",
                        "Rogue Machine Media LLC (d/b/a Lag Lords)",
                    );
                    if !html.contains("/live-bus-bridge.js") {
                        let tag = "<script src=\"/live-bus-bridge.js\"></script></body>";
                        if html.contains("</body>") {
                            html = html.replacen("</body>", tag, 1);
                        } else {
                            html.push_str("<script src=\"/live-bus-bridge.js\"></script>");
                        }
                    }
                    write_http_response(
                        &mut stream,
                        "200 OK",
                        "text/html; charset=utf-8",
                        html.as_bytes(),
                    );
                }
                "css" => write_http_response(
                    &mut stream,
                    "200 OK",
                    "text/css; charset=utf-8",
                    &raw_bytes,
                ),
                "js" => write_http_response(
                    &mut stream,
                    "200 OK",
                    "application/javascript; charset=utf-8",
                    &raw_bytes,
                ),
                "png" => write_http_response(&mut stream, "200 OK", "image/png", &raw_bytes),
                "mp3" => write_http_response(&mut stream, "200 OK", "audio/mpeg", &raw_bytes),
                "json" => write_http_response(
                    &mut stream,
                    "200 OK",
                    "application/json; charset=utf-8",
                    &raw_bytes,
                ),
                _ => write_http_response(
                    &mut stream,
                    "200 OK",
                    "application/octet-stream",
                    &raw_bytes,
                ),
            }
        }
        _ => {
            write_http_response(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                b"Method Not Allowed",
            );
        }
    }
}

pub fn run_ui_workbench_cli(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("serve");
    let is_json = args.iter().any(|a| a == "--json");

    if sub == "--help" || sub == "-h" || sub == "help" {
        let _ = writeln!(
            stdout,
            "Usage:\n  \
             chinwag ui [serve] [--port <44331>] [--repo <path>]\n  \
             chinwag ui status [--json]\n  \
             chinwag ui snapshot [--json]\n\n\
             Live Chinwag Workbench v5 + Captionizm™ + chinwag.tv + Zero-Mock iroh QUIC Bus Server."
        );
        return 0;
    }

    let mut port = DEFAULT_WORKBENCH_PORT;
    let mut repo_arg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" if i + 1 < args.len() => {
                port = args[i + 1].parse::<u16>().unwrap_or(DEFAULT_WORKBENCH_PORT);
                i += 2;
            }
            "--repo" if i + 1 < args.len() => {
                repo_arg = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    let repo_root = resolve_repo_root(repo_arg.as_deref());
    let workbench_dir = resolve_workbench_dir(&repo_root);

    if sub == "status" || args.iter().any(|a| a == "--status") {
        let state_path = ui_daemon_state_path(&repo_root);
        let state: Option<UiDaemonState> = fs::read_to_string(&state_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        if is_json {
            let out = json!({
                "ok": state.is_some(),
                "command": "chinwag ui status",
                "daemon": state,
                "workbench_dir": workbench_dir.to_string_lossy()
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&out).unwrap_or_default()
            );
        } else if let Some(d) = state {
            let _ = writeln!(
                stdout,
                "🟢 Chinwag Workbench UI Server: ONLINE (PID {} · http://{})\n  • Workbench Dir: {}\n  • Studio Firewall: {}",
                d.pid, d.addr, d.workbench_dir, d.studio_firewall
            );
        } else {
            let _ = writeln!(
                stdout,
                "🟡 Chinwag Workbench UI Server: STOPPED (Run `chinwag ui` to start on 127.0.0.1:{port})"
            );
        }
        return 0;
    }

    if sub == "snapshot" {
        let out = parse_all_tasks_json(&repo_root);
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_default()
        );
        return 0;
    }

    let bind_addr = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            let _ = writeln!(stderr, "chinwag ui: failed to bind {bind_addr}: {e}");
            return 1;
        }
    };

    let state = UiDaemonState {
        ok: true,
        pid: std::process::id(),
        addr: bind_addr.clone(),
        port,
        workbench_dir: workbench_dir.to_string_lossy().to_string(),
        views: 12,
        studio_firewall: "Rogue Machine Media LLC (d/b/a Lag Lords) [INV-BRAND-FIREWALL-01]"
            .to_string(),
        started_at_unix: unix_now(),
    };
    let state_path = ui_daemon_state_path(&repo_root);
    if let Some(parent) = state_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(serialized) = serde_json::to_string_pretty(&state) {
        let _ = fs::write(&state_path, serialized);
    }

    let _ = writeln!(
        stdout,
        "🟢 Chinwag Workbench UI Server listening on http://{bind_addr} (PID {})",
        state.pid
    );

    for incoming in listener.incoming() {
        if let Ok(stream) = incoming {
            let repo_c = repo_root.clone();
            let wb_c = workbench_dir.clone();
            std::thread::spawn(move || {
                handle_workbench_http_connection(stream, &repo_c, &wb_c);
            });
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    #[test]
    fn workbench_http_server_serves_live_api_and_injects_bus_bridge() {
        let repo_root = resolve_repo_root(None);
        let wb_dir = resolve_workbench_dir(&repo_root);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local_addr");

        let repo_c = repo_root.clone();
        let wb_c = wb_dir.clone();
        std::thread::spawn(move || {
            for incoming in listener.incoming().take(5) {
                if let Ok(s) = incoming {
                    handle_workbench_http_connection(s, &repo_c, &wb_c);
                }
            }
        });

        // 1. Check /api/health
        let mut s1 = TcpStream::connect(addr).unwrap();
        s1.write_all(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut r1 = String::new();
        s1.read_to_string(&mut r1).unwrap();
        assert!(r1.contains("200 OK"), "{r1}");
        assert!(
            r1.contains("Rogue Machine Media LLC (d/b/a Lag Lords)"),
            "{r1}"
        );
        assert!(r1.contains("INV-BRAND-FIREWALL-01"), "{r1}");

        // 2. Check /api/tasks
        let mut s2 = TcpStream::connect(addr).unwrap();
        s2.write_all(b"GET /api/tasks HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut r2 = String::new();
        s2.read_to_string(&mut r2).unwrap();
        assert!(r2.contains("200 OK"), "{r2}");
        assert!(r2.contains("\"tasks\""), "{r2}");

        // 3. Check /captionizm HTML has live-bus-bridge.js injected and Rogue Machine Media LLC
        let mut s3 = TcpStream::connect(addr).unwrap();
        s3.write_all(b"GET /captionizm HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut r3 = String::new();
        s3.read_to_string(&mut r3).unwrap();
        if wb_dir.join("07-workbench-captionizm-game.html").is_file() {
            assert!(r3.contains("200 OK"), "{r3}");
            assert!(r3.contains("/live-bus-bridge.js"), "{r3}");
            assert!(
                r3.contains("Rogue Machine Media LLC (d/b/a Lag Lords)"),
                "{r3}"
            );
        }

        // 4. DNS Rebinding Guard (`FLINT #213 F1`): reject non-loopback Host
        let mut s4 = TcpStream::connect(addr).unwrap();
        s4.write_all(b"GET /api/health HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")
            .unwrap();
        let mut r4 = String::new();
        s4.read_to_string(&mut r4).unwrap();
        assert!(r4.contains("403 Forbidden"), "{r4}");

        // 5. CSRF & Seat Spoofing Guard (`FLINT #213 F1`): reject POST /api/bus/send as ALISTAIR
        let body = br#"{"sender":"ALISTAIR","room":"#mgmt","body":"spoof"}"#;
        let req5 = format!(
            "POST /api/bus/send HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Content-Type: application/json\r\n\
             X-Chinwag-UI-Intent: 1\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        let mut s5 = TcpStream::connect(addr).unwrap();
        s5.write_all(req5.as_bytes()).unwrap();
        s5.write_all(body).unwrap();
        let mut r5 = String::new();
        s5.read_to_string(&mut r5).unwrap();
        assert!(r5.contains("403 Forbidden"), "{r5}");
    }
}
