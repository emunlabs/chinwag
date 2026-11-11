// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Live event-stream publisher (`ui_sse.rs`) for `chinwag ui`.
//!
//! Streams verified local `messages.jsonl` envelopes to browser tabs
//! authenticated via a single-use `30s` CSPRNG ticket (`Layer 4`), applying
//! `scrub_customer_ui_json` so internal terms never reach customer UI chrome.

use crate::ui_auth::{ParsedHttpRequest, STRICT_UI_CSP, unix_now_ms};
use crate::ui_workbench_run::{fetch_recent_messages_vec, scrub_customer_ui_json};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

fn fetch_tail_messages(repo_root: &Path, limit: usize) -> Vec<Value> {
    let mut msgs = fetch_recent_messages_vec(repo_root, limit);
    for msg in &mut msgs {
        scrub_customer_ui_json(msg);
    }
    msgs
}

const MAX_SSE_TICKS: usize = 7_200;

fn safe_messages_len(path: &Path) -> u64 {
    match fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_symlink() && m.is_file() => m.len(),
        _ => 0,
    }
}

pub fn serve_bus_sse_stream(
    mut stream: TcpStream,
    repo_root: &Path,
    req: &ParsedHttpRequest,
    max_ticks: Option<usize>,
) {
    let effective_max_ticks = max_ticks
        .map(|t| t.min(MAX_SSE_TICKS))
        .unwrap_or(MAX_SSE_TICKS);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream; charset=utf-8\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Content-Security-Policy: {STRICT_UI_CSP}\r\n\
         Connection: keep-alive\r\n\r\n"
    );
    if stream.write_all(headers.as_bytes()).is_err() || stream.flush().is_err() {
        return;
    }

    let last_event_id: Option<u64> = req
        .header("last-event-id")
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            req.query_param("since_seq")
                .and_then(|v| v.parse::<u64>().ok())
        });

    let initial_msgs = fetch_tail_messages(repo_root, 50);
    let mut cursor_seq = initial_msgs
        .last()
        .and_then(|m| m.get("seq").and_then(Value::as_u64))
        .unwrap_or(0);

    if let Some(since) = last_event_id {
        for msg in &initial_msgs {
            let seq = msg.get("seq").and_then(Value::as_u64).unwrap_or(0);
            if seq > since {
                let frame = format!("id: {seq}\nevent: message\ndata: {msg}\n\n");
                if stream.write_all(frame.as_bytes()).is_err() {
                    return;
                }
                cursor_seq = cursor_seq.max(seq);
            }
        }
    }

    let ready_payload = json!({
        "ok": true,
        "cursor_seq": cursor_seq,
        "ts_ms": unix_now_ms()
    });
    let ready_frame = format!("event: ready\ndata: {ready_payload}\n\n");
    if stream.write_all(ready_frame.as_bytes()).is_err() || stream.flush().is_err() {
        return;
    }

    let messages_jsonl = repo_root.join(".chinwag/bus/messages.jsonl");
    let mut last_len = safe_messages_len(&messages_jsonl);
    let mut ticks = 0usize;

    loop {
        if ticks >= effective_max_ticks {
            break;
        }
        ticks += 1;
        std::thread::sleep(Duration::from_millis(500));

        let current_len = safe_messages_len(&messages_jsonl);
        if current_len != last_len {
            last_len = current_len;
            let recent = fetch_tail_messages(repo_root, 20);
            for msg in recent {
                let seq = msg.get("seq").and_then(Value::as_u64).unwrap_or(0);
                if seq > cursor_seq {
                    let frame = format!("id: {seq}\nevent: message\ndata: {msg}\n\n");
                    if stream.write_all(frame.as_bytes()).is_err() || stream.flush().is_err() {
                        return;
                    }
                    cursor_seq = seq;
                }
            }
        } else if ticks.is_multiple_of(20) {
            let keepalive = format!(": keepalive {}\n\n", unix_now_ms());
            if stream.write_all(keepalive.as_bytes()).is_err() || stream.flush().is_err() {
                return;
            }
        }
    }
}
