// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Durable outbox-backed `SignedBlindSlackBeatV1` HTTP/HTTPS emitter.

use crate::slack::outbox::SqliteSlackOutbox;
use chinwag_slack_contract::{
    ApprovedHttpsUrl, BlindSlackBeatV1, Ed25519KeyPairSigner, EventId, sign_blind_slack_beat,
    to_jcs_bytes,
};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Acked {
        event_id: String,
        k2_receipt_ref: Option<String>,
    },
    AuthDeniedOrRevoked {
        status: u16,
        message: String,
    },
    QueuedTransient {
        reason: String,
        retry_after_ms: u64,
    },
}

#[derive(Clone, Debug)]
pub struct RelayDispatchTarget {
    pub endpoint_url: String,
    pub allow_loopback_http: bool,
    pub timeout_ms: u64,
}

#[derive(Deserialize)]
struct RelayAckBody {
    #[serde(default)]
    k2_receipt_ref: Option<String>,
}

/// Signs `beat` with `k1_signer`, persists durably in SQLite `outbox`, and attempts HTTP delivery.
pub fn sign_enqueue_and_dispatch(
    k1_signer: &Ed25519KeyPairSigner,
    beat: BlindSlackBeatV1,
    outbox: &SqliteSlackOutbox,
    target: &RelayDispatchTarget,
    channel_override: Option<&str>,
    now_ms: u64,
) -> Result<DeliveryOutcome, String> {
    let event_id = beat.event_id.clone();
    let (digest, signed) = sign_blind_slack_beat(k1_signer, beat).map_err(|e| e.to_string())?;
    outbox
        .enqueue_idempotent(&signed, &digest, channel_override, now_ms)
        .map_err(|e| e.to_string())?;

    let body = to_jcs_bytes(&signed).map_err(|e| e.to_string())?;
    dispatch_raw_jcs_row(&event_id, &body, outbox, target, channel_override, now_ms)
}

/// Drains due pending beats from the SQLite outbox against `target`, preserving any persisted `channel_override`.
pub fn flush_due_outbox(
    outbox: &SqliteSlackOutbox,
    target: &RelayDispatchTarget,
    now_ms: u64,
    limit: u32,
) -> Result<usize, String> {
    let rows = outbox
        .list_due_pending(now_ms, limit)
        .map_err(|e| e.to_string())?;
    let mut acked = 0usize;
    for row in rows {
        let ev = EventId::parse(&row.event_id).map_err(|e| e.to_string())?;
        let outcome = dispatch_raw_jcs_row(
            &ev,
            row.payload_jcs.as_bytes(),
            outbox,
            target,
            row.channel_override.as_deref(),
            now_ms,
        )?;
        if matches!(outcome, DeliveryOutcome::Acked { .. }) {
            acked += 1;
        }
    }
    Ok(acked)
}

fn dispatch_raw_jcs_row(
    event_id: &EventId,
    jcs_body: &[u8],
    outbox: &SqliteSlackOutbox,
    target: &RelayDispatchTarget,
    channel_override: Option<&str>,
    now_ms: u64,
) -> Result<DeliveryOutcome, String> {
    match send_http_post(target, event_id.as_str(), channel_override, jcs_body) {
        Ok((status, retry_after_ms, resp_body)) => match status {
            200..=299 => {
                let k2_ref = serde_json::from_str::<RelayAckBody>(&resp_body)
                    .ok()
                    .and_then(|b| b.k2_receipt_ref);
                outbox
                    .mark_acknowledged(event_id, k2_ref.as_deref(), now_ms)
                    .map_err(|e| e.to_string())?;
                Ok(DeliveryOutcome::Acked {
                    event_id: event_id.as_str().to_owned(),
                    k2_receipt_ref: k2_ref,
                })
            }
            401 | 403 | 410 => {
                let reason = format!("HTTP {status} authorization denied or revoked");
                outbox
                    .mark_revoked_or_quarantined(event_id, &reason, now_ms)
                    .map_err(|e| e.to_string())?;
                Ok(DeliveryOutcome::AuthDeniedOrRevoked {
                    status,
                    message: reason,
                })
            }
            429 | 500..=599 => {
                let backoff = retry_after_ms.unwrap_or(2_000);
                let reason = format!("HTTP {status} transient service error");
                outbox
                    .record_transient_failure(event_id, &reason, backoff, now_ms)
                    .map_err(|e| e.to_string())?;
                Ok(DeliveryOutcome::QueuedTransient {
                    reason,
                    retry_after_ms: backoff,
                })
            }
            other => {
                let reason = format!("HTTP {other} unexpected relay response");
                outbox
                    .mark_revoked_or_quarantined(event_id, &reason, now_ms)
                    .map_err(|e| e.to_string())?;
                Err(reason)
            }
        },
        Err(transport_err) => {
            outbox
                .record_transient_failure(event_id, &transport_err, 2_000, now_ms)
                .map_err(|e| e.to_string())?;
            Ok(DeliveryOutcome::QueuedTransient {
                reason: transport_err,
                retry_after_ms: 2_000,
            })
        }
    }
}

pub(crate) fn send_http_post(
    target: &RelayDispatchTarget,
    idempotency_key: &str,
    channel_override: Option<&str>,
    body: &[u8],
) -> Result<(u16, Option<u64>, String), String> {
    let parsed = Url::parse(&target.endpoint_url).map_err(|e| format!("invalid URL: {e}"))?;
    match parsed.scheme() {
        "https" => {
            let _ = ApprovedHttpsUrl::parse(&target.endpoint_url).map_err(|e| e.to_string())?;
            send_https_via_curl(
                &target.endpoint_url,
                idempotency_key,
                channel_override,
                body,
                target.timeout_ms,
            )
        }
        "http" if target.allow_loopback_http => {
            let host = parsed.host_str().unwrap_or("");
            if host != "127.0.0.1" && host != "localhost" && host != "::1" {
                return Err(
                    "plain HTTP is restricted strictly to loopback test endpoints".to_owned(),
                );
            }
            send_loopback_http(
                &parsed,
                idempotency_key,
                channel_override,
                body,
                target.timeout_ms,
            )
        }
        _ => Err("HTTPS endpoint required for Slack beat dispatch".to_owned()),
    }
}

fn send_loopback_http(
    url: &Url,
    idempotency_key: &str,
    channel_override: Option<&str>,
    body: &[u8],
    timeout_ms: u64,
) -> Result<(u16, Option<u64>, String), String> {
    let port = url.port_or_known_default().unwrap_or(80);
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let timeout = Duration::from_millis(timeout_ms.max(200));
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect failed: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };
    let mut req_head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         Idempotency-Key: {idempotency_key}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body.len()
    );
    if let Some(ch) = channel_override {
        req_head.push_str(&format!("X-Chinwag-Channel-Hint: {ch}\r\n"));
    }
    req_head.push_str("\r\n");

    let mut full_req = Vec::with_capacity(req_head.len() + body.len());
    full_req.extend_from_slice(req_head.as_bytes());
    full_req.extend_from_slice(body);
    stream
        .write_all(&full_req)
        .and_then(|()| stream.flush())
        .map_err(|e| format!("write failed: {e}"))?;

    let mut raw_resp = Vec::with_capacity(1024);
    stream
        .take(65_536)
        .read_to_end(&mut raw_resp)
        .map_err(|e| format!("read failed: {e}"))?;
    let text = String::from_utf8_lossy(&raw_resp);
    let (headers_part, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = headers_part.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "empty HTTP response".to_owned())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed HTTP status line: {status_line}"))?;

    let mut retry_after_ms = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("retry-after")
            && let Ok(secs) = v.trim().parse::<u64>()
        {
            retry_after_ms = Some(secs.saturating_mul(1_000));
        }
    }
    Ok((status_code, retry_after_ms, resp_body.to_owned()))
}

fn send_https_via_curl(
    endpoint_url: &str,
    idempotency_key: &str,
    channel_override: Option<&str>,
    body: &[u8],
    timeout_ms: u64,
) -> Result<(u16, Option<u64>, String), String> {
    let max_secs = (timeout_ms.div_ceil(1_000)).max(1).to_string();
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--proto")
        .arg("=https")
        .arg("--tlsv1.2")
        .arg("--max-time")
        .arg(&max_secs)
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg(format!("Idempotency-Key: {idempotency_key}"));
    if let Some(ch) = channel_override {
        cmd.arg("-H").arg(format!("X-Chinwag-Channel-Hint: {ch}"));
    }
    cmd.arg("--data-binary")
        .arg("@-")
        .arg("-w")
        .arg("\n__CHINWAG_HTTP_CODE__:%{http_code}")
        .arg(endpoint_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("curl spawn failed: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body)
            .map_err(|e| format!("curl stdin write failed: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("curl wait failed: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let (resp_body, code_str) = stdout_str
        .rsplit_once("\n__CHINWAG_HTTP_CODE__:")
        .ok_or_else(|| "missing HTTP status trailer from curl".to_owned())?;
    let status_code = code_str
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("invalid HTTP status trailer: {code_str}"))?;
    Ok((status_code, None, resp_body.to_owned()))
}
