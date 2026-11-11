// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Five-Layer Loopback Security Guard (`ui_auth.rs`) for `chinwag ui` (`127.0.0.1:5487`).
//!
//! Enforces:
//!   - Layer 1: Exact `Host: 127.0.0.1:<port>` check (`421 Misdirected Request` on `localhost`,
//!     mismatched port, or DNS-rebound external hostnames; strict `https://chinwag.sh` CORS
//!     solely on `GET /api/bus/ping` for zero-knowledge desktop bounce probes).
//!   - Layer 2: `Sec-Fetch-Site: same-origin` isolation + `Origin: http://127.0.0.1:<port>` and
//!     `Content-Type: application/json` enforcement on `POST /api/*`.
//!   - Layer 3: Port-bound `HttpOnly; SameSite=Strict` cookie (`__chinwag_ui_<port>`) paired with
//!     double-submit `X-Chinwag-Local-CSRF` header injected into `index.html`.
//!   - Layer 4: Single-use `30s` CSPRNG ticket (`POST /api/bus/stream-ticket`) for `EventSource`
//!     connections on `GET /api/bus/stream?ticket=...`.
//!   - Layer 5: `Cross-Origin-Resource-Policy: same-origin`, `Cross-Origin-Opener-Policy: same-origin`,
//!     `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and strict zero-CDN CSP.

use rand::RngCore;
use rustix::fs::{AtFlags, CWD, Mode, OFlags, fsync, openat, renameat, statat, unlinkat};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STREAM_TICKET_TTL_MS: u64 = 30_000;
pub const SEND_IDEMPOTENCY_TTL_MS: u64 = 60_000;
pub const MAX_UI_HTTP_REQUEST_BYTES: usize = 262_144;

pub const STRICT_UI_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Debug)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub raw_target: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl ParsedHttpRequest {
    pub fn header(&self, lower_key: &str) -> Option<&str> {
        self.headers.get(lower_key).map(String::as_str)
    }

    pub fn query_param(&self, key: &str) -> Option<String> {
        for pair in self.query.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && k == key
            {
                return Some(percent_decode_simple(v));
            }
        }
        None
    }

    pub fn cookie_value(&self, cookie_name: &str) -> Option<String> {
        let raw_cookie = self.header("cookie")?;
        for part in raw_cookie.split(';') {
            if let Some((k, v)) = part.trim().split_once('=')
                && k.trim() == cookie_name
            {
                return Some(v.trim().to_string());
            }
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthDecision {
    Allow {
        cors_origin: Option<String>,
    },
    RedirectLoopback {
        location: String,
    },
    Reject {
        status_line: &'static str,
        error_code: &'static str,
        message: String,
    },
}

pub struct UiSecurityContext {
    port: u16,
    csrf_token_hex: String,
    cookie_name: String,
    cookie_value_hex: String,
    console_human_actor: String,
    stream_tickets: Mutex<HashMap<String, u64>>,
    idempotency_cache: Mutex<HashMap<String, (u64, Vec<u8>)>>,
}

impl UiSecurityContext {
    pub fn for_port(port: u16, persist_key: bool) -> Self {
        let csrf_token_hex = if persist_key {
            load_or_create_persisted_csrf_key(port)
        } else {
            csprng_hex(32)
        };
        Self::from_csrf_token(port, csrf_token_hex)
    }

    pub fn from_csrf_token(port: u16, csrf_token_hex: String) -> Self {
        let cookie_name = format!("__chinwag_ui_{port}");
        let mut hasher = Sha256::new();
        hasher.update(b"chinwag-ui-cookie-v3.3:");
        hasher.update(port.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(csrf_token_hex.as_bytes());
        let cookie_value_hex = bytes_to_hex(&hasher.finalize());
        let short_inst = &csrf_token_hex[..16.min(csrf_token_hex.len())];
        let console_human_actor = format!("Brian#ui-{short_inst}");
        Self {
            port,
            csrf_token_hex,
            cookie_name,
            cookie_value_hex,
            console_human_actor,
            stream_tickets: Mutex::new(HashMap::new()),
            idempotency_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn csrf_token_hex(&self) -> &str {
        &self.csrf_token_hex
    }

    #[cfg(test)]
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    #[cfg(test)]
    pub fn cookie_value_hex(&self) -> &str {
        &self.cookie_value_hex
    }

    pub fn console_human_actor(&self) -> &str {
        &self.console_human_actor
    }

    pub fn set_cookie_header_value(&self) -> String {
        format!(
            "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400",
            self.cookie_name, self.cookie_value_hex
        )
    }

    pub fn mint_stream_ticket(&self) -> String {
        let now = unix_now_ms();
        let ticket = csprng_hex(16);
        if let Ok(mut guard) = self.stream_tickets.lock() {
            guard.retain(|_, exp| *exp > now);
            guard.insert(ticket.clone(), now + STREAM_TICKET_TTL_MS);
        }
        ticket
    }

    pub fn consume_stream_ticket(&self, candidate: &str) -> bool {
        if candidate.len() != 32 || !candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        let now = unix_now_ms();
        let Ok(mut guard) = self.stream_tickets.lock() else {
            return false;
        };
        guard.retain(|_, exp| *exp > now);
        let mut matched_key: Option<String> = None;
        for stored in guard.keys() {
            if constant_time_eq(stored.as_bytes(), candidate.as_bytes()) {
                matched_key = Some(stored.clone());
                break;
            }
        }
        if let Some(key) = matched_key
            && let Some(expires_at) = guard.remove(&key)
        {
            return now <= expires_at;
        }
        false
    }

    pub fn check_idempotency(&self, key: &str) -> Option<Vec<u8>> {
        let now = unix_now_ms();
        let Ok(mut guard) = self.idempotency_cache.lock() else {
            return None;
        };
        guard.retain(|_, (exp, _)| *exp > now);
        guard.get(key).map(|(_, payload)| payload.clone())
    }

    pub fn record_idempotency(&self, key: String, response_bytes: Vec<u8>) {
        let now = unix_now_ms();
        if let Ok(mut guard) = self.idempotency_cache.lock() {
            guard.retain(|_, (exp, _)| *exp > now);
            guard.insert(key, (now + SEND_IDEMPOTENCY_TTL_MS, response_bytes));
        }
    }

    pub fn verify_request(&self, req: &ParsedHttpRequest) -> AuthDecision {
        let expected_host = format!("127.0.0.1:{}", self.port);
        let expected_origin = format!("http://127.0.0.1:{}", self.port);

        if req.path.starts_with("/api/") {
            // Layer 1: Exact Host: 127.0.0.1:<port> byte-for-byte check
            if req.header("host") != Some(expected_host.as_str()) {
                return AuthDecision::Reject {
                    status_line: "421 Misdirected Request",
                    error_code: "misdirected_host",
                    message: format!(
                        "Host header must match {expected_host} exactly on /api/* routes"
                    ),
                };
            }

            // Sole exception: GET/OPTIONS /api/bus/ping for https://chinwag.sh/open desktop probe
            if req.path == "/api/bus/ping" && matches!(req.method.as_str(), "GET" | "OPTIONS") {
                return match req.header("origin") {
                    None => AuthDecision::Allow { cors_origin: None },
                    Some("https://chinwag.sh") => AuthDecision::Allow {
                        cors_origin: Some("https://chinwag.sh".to_string()),
                    },
                    Some(orig) if orig == expected_origin => {
                        AuthDecision::Allow { cors_origin: None }
                    }
                    Some(_) => AuthDecision::Reject {
                        status_line: "403 Forbidden",
                        error_code: "forbidden_origin",
                        message: "Disallowed Origin on /api/bus/ping".to_string(),
                    },
                };
            }

            // Layer 2: Sec-Fetch-Site isolation
            if let Some(sfs) = req.header("sec-fetch-site")
                && sfs != "same-origin"
            {
                return AuthDecision::Reject {
                    status_line: "403 Forbidden",
                    error_code: "cross_site_fetch_rejected",
                    message: "Sec-Fetch-Site must be same-origin".to_string(),
                };
            }

            // Layer 4: Single-use 30s stream ticket on live event endpoint
            if req.path == "/api/bus/stream" && req.method == "GET" {
                let Some(ticket) = req.query_param("ticket") else {
                    return AuthDecision::Reject {
                        status_line: "403 Forbidden",
                        error_code: "missing_stream_ticket",
                        message: "Missing single-use live stream ticket".to_string(),
                    };
                };
                if !self.consume_stream_ticket(&ticket) {
                    return AuthDecision::Reject {
                        status_line: "403 Forbidden",
                        error_code: "invalid_stream_ticket",
                        message: "Invalid, replayed, or expired live stream ticket".to_string(),
                    };
                }
                return AuthDecision::Allow { cors_origin: None };
            }

            // Layer 2 POST Origin + Content-Type checks
            if req.method == "POST" {
                let is_json = req
                    .header("content-type")
                    .is_some_and(|ct| ct.to_ascii_lowercase().starts_with("application/json"));
                if !is_json {
                    return AuthDecision::Reject {
                        status_line: "403 Forbidden",
                        error_code: "invalid_content_type",
                        message: "Content-Type: application/json required on POST".to_string(),
                    };
                }
                if let Some(orig) = req.header("origin")
                    && orig != expected_origin
                {
                    return AuthDecision::Reject {
                        status_line: "403 Forbidden",
                        error_code: "origin_mismatch",
                        message: format!("Origin must match {expected_origin}"),
                    };
                }
            }

            // Layer 3: Double-submit port-bound cookie + X-Chinwag-Csrf / X-Chinwag-Token header
            let cookie_ok = req.cookie_value(&self.cookie_name).is_some_and(|val| {
                constant_time_eq(val.as_bytes(), self.cookie_value_hex.as_bytes())
            });
            let provided_csrf_headers: Vec<&str> = [
                req.header("x-chinwag-csrf"),
                req.header("x-chinwag-token"),
                req.header("x-chinwag-local-csrf"),
            ]
            .into_iter()
            .flatten()
            .collect();
            let csrf_ok = !provided_csrf_headers.is_empty()
                && provided_csrf_headers
                    .iter()
                    .all(|hdr| constant_time_eq(hdr.as_bytes(), self.csrf_token_hex.as_bytes()));
            if !cookie_ok || !csrf_ok {
                return AuthDecision::Reject {
                    status_line: "403 Forbidden",
                    error_code: "csrf_verification_failed",
                    message: "Missing or invalid port-bound cookie or X-Chinwag-Csrf / X-Chinwag-Token header"
                        .to_string(),
                };
            }

            return AuthDecision::Allow { cors_origin: None };
        }

        // Static UI routes: enforce Host == 127.0.0.1:<port> (or redirect localhost:<port>)
        match req.header("host") {
            Some(h) if h == expected_host => AuthDecision::Allow { cors_origin: None },
            Some(h)
                if h.eq_ignore_ascii_case(&format!("localhost:{}", self.port))
                    && req.method == "GET"
                    && req.raw_target.starts_with('/')
                    && !req.raw_target.starts_with("//") =>
            {
                AuthDecision::RedirectLoopback {
                    location: format!("http://127.0.0.1:{}{}", self.port, req.raw_target),
                }
            }
            _ => AuthDecision::Reject {
                status_line: "421 Misdirected Request",
                error_code: "misdirected_host",
                message: format!("Host header must match {expected_host}"),
            },
        }
    }
}

pub fn read_http_request(stream: &mut TcpStream) -> Option<ParsedHttpRequest> {
    parse_http_request_from_reader(stream)
}

fn parse_http_request_from_reader(reader: &mut impl Read) -> Option<ParsedHttpRequest> {
    let mut buf = Vec::with_capacity(8192);
    let mut temp = [0u8; 4096];
    let mut header_end = None;
    let mut content_length: Option<usize> = None;

    loop {
        match reader.read(&mut temp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&temp[..n]);
                if buf.len() > MAX_UI_HTTP_REQUEST_BYTES {
                    return None;
                }
                if header_end.is_none()
                    && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let end_pos = pos.checked_add(4)?;
                    header_end = Some(end_pos);
                    let header_str = String::from_utf8_lossy(&buf[..end_pos]);
                    for line in header_str.lines().skip(1) {
                        if let Some((k, v)) = line.split_once(':')
                            && k.trim().eq_ignore_ascii_case("content-length")
                        {
                            let parsed_cl = v.trim().parse::<usize>().ok()?;
                            if parsed_cl > MAX_UI_HTTP_REQUEST_BYTES {
                                return None;
                            }
                            if let Some(prev) = content_length
                                && prev != parsed_cl
                            {
                                return None;
                            }
                            content_length = Some(parsed_cl);
                        }
                    }
                    let expected_total = end_pos.checked_add(content_length.unwrap_or(0))?;
                    if expected_total > MAX_UI_HTTP_REQUEST_BYTES {
                        return None;
                    }
                }
                if let Some(end_pos) = header_end {
                    let expected_total = end_pos.checked_add(content_length.unwrap_or(0))?;
                    if buf.len() >= expected_total {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    let end_pos = header_end?;
    let declared_len = content_length.unwrap_or(0);
    let expected_total = end_pos.checked_add(declared_len)?;
    if expected_total > MAX_UI_HTTP_REQUEST_BYTES {
        return None;
    }

    let header_str = String::from_utf8_lossy(&buf[..end_pos]);
    let request_line = header_str.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    let raw_target = parts.next()?.to_string();
    let (path, query) = raw_target
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or_else(|| (raw_target.clone(), String::new()));

    let mut headers = HashMap::new();
    for line in header_str.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let body_end = expected_total.min(buf.len());
    let body = buf.get(end_pos..body_end)?.to_vec();

    Some(ParsedHttpRequest {
        method,
        raw_target,
        path,
        query,
        headers,
        body,
    })
}

pub fn write_hardened_response(
    stream: &mut TcpStream,
    status_line: &str,
    content_type: &str,
    body: &[u8],
    set_cookie: Option<&str>,
    cors_origin: Option<&str>,
) {
    let corp = if cors_origin.is_some() {
        "cross-origin"
    } else {
        "same-origin"
    };
    let mut extra_headers = String::new();
    if let Some(cookie) = set_cookie {
        extra_headers.push_str(&format!("Set-Cookie: {cookie}\r\n"));
    }
    if let Some(origin) = cors_origin {
        extra_headers.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\n\
             Access-Control-Allow-Methods: GET, OPTIONS\r\n\
             Vary: Origin\r\n"
        ));
    }
    let header = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Cross-Origin-Resource-Policy: {corp}\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Content-Security-Policy: {STRICT_UI_CSP}\r\n\
         {extra_headers}\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

pub fn write_json_error(
    stream: &mut TcpStream,
    status_line: &str,
    error_code: &str,
    message: &str,
) {
    let payload = serde_json::to_vec(&json!({
        "ok": false,
        "error_code": error_code,
        "error": message
    }))
    .unwrap_or_default();
    write_hardened_response(
        stream,
        status_line,
        "application/json; charset=utf-8",
        &payload,
        None,
        None,
    );
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn csprng_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut buf);
    bytes_to_hex(&buf)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn load_or_create_persisted_csrf_key(port: u16) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let run_dir = PathBuf::from(home).join(".chinwag/run");
    let leaf_name = format!("ui_csrf_{port}.key");

    let _ = fs::create_dir_all(&run_dir);
    let _ = fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700));

    let Ok(dir_fd) = openat(
        CWD,
        &run_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return csprng_hex(32);
    };

    if let Ok(raw_fd) = openat(
        &dir_fd,
        leaf_name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        let mut f = File::from(raw_fd);
        let mut existing = String::new();
        if f.read_to_string(&mut existing).is_ok() {
            let trimmed = existing.trim();
            if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                return trimmed.to_ascii_lowercase();
            }
        }
    }

    let fresh = csprng_hex(32);
    if let Ok(st) = statat(&dir_fd, leaf_name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        && ((u32::from(st.st_mode) & 0o170000) != 0o100000 || st.st_nlink != 1)
    {
        return fresh;
    }

    let tmp_name = format!(".{leaf_name}.tmp.{}", csprng_hex(8));
    if let Ok(tmp_fd) = openat(
        &dir_fd,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        let mut file = File::from(tmp_fd);
        if writeln!(file, "{fresh}").is_ok() && file.sync_all().is_ok() {
            if renameat(&dir_fd, tmp_name.as_str(), &dir_fd, leaf_name.as_str()).is_ok() {
                let _ = fsync(&dir_fd);
            } else {
                let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
            }
        } else {
            let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
        }
    }
    fresh
}

fn percent_decode_simple(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn http_parser_rejects_overflowing_oversized_and_conflicting_content_length_without_panic() {
        let overflow_req = b"POST /api/v4/inbox/action HTTP/1.1\r\nHost: 127.0.0.1:5487\r\nContent-Length: 18446744073709551615\r\n\r\n{}";
        assert!(parse_http_request_from_reader(&mut Cursor::new(&overflow_req[..])).is_none());

        let oversized_req = b"POST /api/v4/inbox/action HTTP/1.1\r\nHost: 127.0.0.1:5487\r\nContent-Length: 300000\r\n\r\n{}";
        assert!(parse_http_request_from_reader(&mut Cursor::new(&oversized_req[..])).is_none());

        let malformed_req = b"POST /api/v4/inbox/action HTTP/1.1\r\nHost: 127.0.0.1:5487\r\nContent-Length: -42\r\n\r\n{}";
        assert!(parse_http_request_from_reader(&mut Cursor::new(&malformed_req[..])).is_none());

        let conflicting_req = b"POST /api/v4/inbox/action HTTP/1.1\r\nHost: 127.0.0.1:5487\r\nContent-Length: 2\r\nContent-Length: 8\r\n\r\n{}";
        assert!(parse_http_request_from_reader(&mut Cursor::new(&conflicting_req[..])).is_none());

        let valid_req = b"POST /api/v4/inbox/action HTTP/1.1\r\nHost: 127.0.0.1:5487\r\nContent-Length: 2\r\n\r\n{}";
        let parsed = parse_http_request_from_reader(&mut Cursor::new(&valid_req[..])).unwrap();
        assert_eq!(parsed.body, b"{}");
    }

    #[test]
    fn localhost_redirect_rejects_scheme_relative_or_absolute_targets() {
        let ctx = UiSecurityContext::for_port(5487, false);
        let evil = parse_http_request_from_reader(&mut Cursor::new(
            &b"GET //evil.example/path HTTP/1.1\r\nHost: localhost:5487\r\n\r\n"[..],
        ))
        .unwrap();
        assert!(matches!(
            ctx.verify_request(&evil),
            AuthDecision::Reject { .. }
        ));

        let good = parse_http_request_from_reader(&mut Cursor::new(
            &b"GET /#credits HTTP/1.1\r\nHost: localhost:5487\r\n\r\n"[..],
        ))
        .unwrap();
        assert!(matches!(
            ctx.verify_request(&good),
            AuthDecision::RedirectLoopback { ref location } if location == "http://127.0.0.1:5487/#credits"
        ));
    }
}
