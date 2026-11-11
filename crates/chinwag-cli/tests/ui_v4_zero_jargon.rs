// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! End-to-End Integration & Zero-Jargon Gate for `chinwag ui` (`v4.1` · `CHWG-0209` & `CHWG-0207.3`).

#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct ChildKillGuard(Child);

impl Drop for ChildKillGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn reserve_ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

fn send_raw_http(addr: SocketAddr, raw_req: &str) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).expect("connect ui");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw_req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

fn split_headers_and_body(raw: &[u8]) -> (String, &[u8]) {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        let hdr = String::from_utf8_lossy(&raw[..pos]).to_string();
        (hdr, &raw[pos + 4..])
    } else {
        (String::from_utf8_lossy(raw).to_string(), &[])
    }
}

fn extract_cookie_and_csrf(headers: &str, html_body: &str, port: u16) -> (String, String) {
    let cookie_prefix = format!("__chinwag_ui_{port}=");
    let mut cookie_pair = String::new();
    for line in headers.lines() {
        if let Some(rest) = line
            .strip_prefix("Set-Cookie: ")
            .or_else(|| line.strip_prefix("set-cookie: "))
            && rest.starts_with(&cookie_prefix)
        {
            cookie_pair = rest.split(';').next().unwrap_or("").trim().to_string();
            break;
        }
    }
    assert!(
        !cookie_pair.is_empty(),
        "expected Set-Cookie {cookie_prefix}... in headers:\n{headers}"
    );

    let marker = r#"name="chinwag-csrf" content=""#;
    let start = html_body
        .find(marker)
        .expect("expected chinwag-csrf meta tag in index.html")
        + marker.len();
    let end = html_body[start..]
        .find('"')
        .expect("closing quote on chinwag-csrf meta")
        + start;
    let csrf = html_body[start..end].to_string();
    assert_eq!(csrf.len(), 64, "expected 64-hex CSRF token, got {csrf}");

    (cookie_pair, csrf)
}

fn assert_zero_customer_jargon(surface_name: &str, text: &str) {
    let lower = text.to_ascii_lowercase();
    let forbidden_substrings: &[&str] = &[
        concat!("inception/", "mercury-3"),
        concat!("mercury", "-3"),
        concat!("mercury", " 3"),
        concat!("vercel-ai", "-gateway"),
        concat!("cloud", "flareos-ai"),
        concat!("clef", "-flash"),
        concat!("clair", "ic"),
        concat!("deep", "seek"),
        concat!("claude-", "fable"),
        concat!("opus", " 5"),
        concat!("gpt-", "6"),
        concat!("gr", "ok"),
        concat!("recursive ", "flint"),
        concat!("state.", "crdb"),
        concat!("cr", "sqlite"),
        concat!("cr-", "sqlite"),
        concat!("ed25", "519"),
        concat!("bbs", "+"),
        concat!("cp-", "omp"),
        concat!("a.", "509"),
        concat!("gemini", "-pm"),
        concat!("work", "horse"),
        concat!("alis", "tair"),
        concat!("eagle", "-eye"),
        concat!("house", "keeping"),
        concat!("infra", "jr"),
        concat!("mac ", "studio"),
    ];
    for pat in forbidden_substrings {
        assert!(
            !lower.contains(pat),
            "INV-UI-ZERO-JARGON-01 violation on {surface_name}: found forbidden substring '{pat}'"
        );
    }

    // Token-boundary checks for short acronyms (`crdb`, `leann`, `hpke`, `flint`, `clef`, `fable`, `dora`, `sse`)
    let forbidden_tokens: &[&str] = &[
        concat!("cr", "db"),
        concat!("le", "ann"),
        concat!("hp", "ke"),
        concat!("fl", "int"),
        concat!("cl", "ef"),
        concat!("fa", "ble"),
        concat!("do", "ra"),
        concat!("ss", "e"),
    ];
    for tok in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
        for &bad in forbidden_tokens {
            // In `app.js` source code, lowercase `"sse"` is an internal PostHog telemetry enum value
            // (`transport_mode: "sse"` on `ui_sse_stream_reconnected`), never rendered in UI copy.
            if surface_name == "/assets/v4/app.js" && bad == concat!("ss", "e") {
                continue;
            }
            assert_ne!(
                tok, bad,
                "INV-UI-ZERO-JARGON-01 violation on {surface_name}: found forbidden standalone token '{bad}'"
            );
        }
    }
    if surface_name == "/assets/v4/app.js" {
        for raw_tok in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
            assert_ne!(
                raw_tok,
                concat!("SS", "E"),
                "INV-UI-ZERO-JARGON-01 violation on /assets/v4/app.js: uppercase acronym found in UI copy"
            );
        }
    }
}

fn assert_verified_chinwag_sh_routes_and_no_404s(surface_name: &str, text: &str) {
    for forbidden_404 in ["/contact", "chinwag.sh/invite"] {
        assert!(
            !text.contains(forbidden_404),
            "CHWG-0249 broken link regression on {surface_name}: found forbidden 404 route '{forbidden_404}'"
        );
    }

    const ORIGIN: &str = "https://chinwag.sh";
    const ALLOWED_PATHS: &[&str] = &["", "/", "/pricing", "/open", "/security", "/privacy"];
    let mut rest = text;
    while let Some(idx) = rest.find(ORIGIN) {
        let after_origin = &rest[idx + ORIGIN.len()..];
        let end_idx = after_origin
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(c, '"' | '\'' | '`' | '$' | ')' | '(' | '<' | '>' | '\\')
            })
            .unwrap_or(after_origin.len());
        let raw_tail = &after_origin[..end_idx];
        let route_path = raw_tail.split(['?', '#']).next().unwrap_or("");
        assert!(
            ALLOWED_PATHS.contains(&route_path),
            "CHWG-0249 unverified outbound chinwag.sh route on {surface_name}: '{ORIGIN}{raw_tail}' (path '{route_path}' not in {ALLOWED_PATHS:?})"
        );
        rest = &after_origin[end_idx..];
    }
}

fn extract_css_rule_body<'a>(css: &'a str, selector_needle: &str) -> &'a str {
    let start = css
        .find(selector_needle)
        .unwrap_or_else(|| panic!("missing CSS selector '{selector_needle}' in styles.css"));
    let after = &css[start..];
    let open = after
        .find('{')
        .unwrap_or_else(|| panic!("missing '{{' after '{selector_needle}'"));
    let close = after[open + 1..]
        .find('}')
        .unwrap_or_else(|| panic!("missing '}}' after '{selector_needle}'"));
    &after[open + 1..open + 1 + close]
}

#[test]
fn ui_v4_server_static_assets_scrubber_workflows_credits_and_telemetry_pass_end_to_end() {
    let raw_temp_repo: PathBuf = std::env::temp_dir().join(format!(
        "chinwag-ui-v4-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(raw_temp_repo.join(".chinwag/bus")).unwrap();
    fs::create_dir_all(raw_temp_repo.join(".cursor/rules")).unwrap();
    let temp_repo = fs::canonicalize(&raw_temp_repo).unwrap();

    // Plant internal jargon inside TASKS.md and messages.jsonl to prove scrubber catches everything!
    let planted_tasks = format!(
        "### **`[IN_PROGRESS]`** `CHWG-9001` — Wire {} with {} and {} on {}\n\
         - **`[DONE]`** `CHWG-9000` — Shipped checkout validation with {} and {}\n",
        concat!("WORK", "HORSE#inst1"),
        concat!("inception/", "mercury-3"),
        concat!("state.", "crdb"),
        concat!("Node 1 · ", "Mac Studio"),
        concat!("ALIS", "TAIR#qa1"),
        concat!("ed25", "519")
    );
    fs::write(temp_repo.join("TASKS.md"), planted_tasks).unwrap();

    let planted_msg = json!({
        "id": "msg-planted-1",
        "seq": 1,
        "ts_unix": 1_790_000_000u64,
        "ts_iso": "2026-11-11T00:00:00Z",
        "room": "#eng",
        "sender": concat!("GEMINI", "-PM#thread99"),
        "sender_cast": concat!("GEMINI", "-PM"),
        "sender_endpoint_id": "ep-internal",
        "to": Some(concat!("WORK", "HORSE#inst1")),
        "task_id": Some("CHWG-9001"),
        "body": format!(
            "Checked {} + {} + {} + {} metrics; all checks passed!",
            concat!("cr", "db"),
            concat!("le", "ann"),
            concat!("DO", "RA"),
            concat!("SS", "E")
        ),
        "digest_sha256": "deadbeef",
        "pubkey_ed25519": "aaaa",
        "signature_ed25519": "bbbb",
        "sig_verified": true
    });
    fs::write(
        temp_repo.join(".chinwag/bus/messages.jsonl"),
        format!("{planted_msg}\n"),
    )
    .unwrap();

    fs::write(
        temp_repo.join(".cursor/rules/testing.mdc"),
        "---\ndescription: Run unit tests before opening review\n---\nPrefer deterministic tests.",
    )
    .unwrap();

    // Start local mock PostHog edge collector for telemetry verification
    let ph_listener = TcpListener::bind("127.0.0.1:0").expect("bind mock ph listener");
    let ph_addr = ph_listener.local_addr().unwrap();
    let captured_ph: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_ph_clone = Arc::clone(&captured_ph);
    std::thread::spawn(move || {
        for mut stream in ph_listener.incoming().take(8).flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
            if let Some((_, body)) = req_str.split_once("\r\n\r\n") {
                captured_ph_clone.lock().unwrap().push(body.to_string());
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
            );
        }
    });

    let ui_port = reserve_ephemeral_port();
    let ui_addr: SocketAddr = format!("127.0.0.1:{ui_port}").parse().unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "ui",
            "serve",
            "--port",
            &ui_port.to_string(),
            "--repo",
            temp_repo.to_str().unwrap(),
        ])
        .env(
            "CHINWAG_TELEMETRY_TEST_ENDPOINT",
            format!("http://{ph_addr}/ph/track"),
        )
        .env_remove("CHINWAG_NO_TELEMETRY")
        .env_remove("CHINWAG_TELEMETRY_DISABLED")
        .env_remove("DO_NOT_TRACK")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chinwag ui serve");
    let _guard = ChildKillGuard(child);

    // Wait for /api/bus/ping to come online
    let boot_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&ui_addr, Duration::from_millis(100)).is_ok() {
            break;
        }
        assert!(
            Instant::now() < boot_deadline,
            "timed out waiting for chinwag ui on {ui_addr}"
        );
        std::thread::sleep(Duration::from_millis(40));
    }

    // 1. Probe GET /api/bus/ping (CORS + ui_version 4.1)
    let ping_raw = send_raw_http(
        ui_addr,
        &format!(
            "GET /api/bus/ping HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\nOrigin: https://chinwag.sh\r\n\r\n"
        ),
    );
    let (ping_hdr, ping_body) = split_headers_and_body(&ping_raw);
    assert!(ping_hdr.starts_with("HTTP/1.1 200 OK"), "{ping_hdr}");
    assert!(
        ping_hdr.contains("Access-Control-Allow-Origin: https://chinwag.sh"),
        "{ping_hdr}"
    );
    let ping_json: Value = serde_json::from_slice(ping_body).unwrap();
    assert_eq!(ping_json["ui_version"], "4.1");

    // 2. Fetch root / and all embedded /assets/v4/* files; verify CSP & zero jargon
    let root_raw = send_raw_http(
        ui_addr,
        &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\n\r\n"),
    );
    let (root_hdr, root_body_bytes) = split_headers_and_body(&root_raw);
    assert!(root_hdr.starts_with("HTTP/1.1 200 OK"), "{root_hdr}");
    assert!(root_hdr.contains("font-src 'self'"), "{root_hdr}");
    assert!(!root_hdr.contains("unsafe-inline"), "{root_hdr}");
    let root_html = String::from_utf8_lossy(root_body_bytes);
    assert_zero_customer_jargon("GET /", &root_html);
    assert_verified_chinwag_sh_routes_and_no_404s("GET /", &root_html);
    let (cookie_pair, csrf) = extract_cookie_and_csrf(&root_hdr, &root_html, ui_port);

    for text_asset in [
        "/assets/v4/theme-boot.js",
        "/assets/v4/styles.css",
        "/assets/v4/motion.css",
        "/assets/v4/motion.js",
        "/assets/v4/app.js",
    ] {
        let raw = send_raw_http(
            ui_addr,
            &format!("GET {text_asset} HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\n\r\n"),
        );
        let (hdr, body) = split_headers_and_body(&raw);
        assert!(
            hdr.starts_with("HTTP/1.1 200 OK"),
            "{text_asset} failed: {hdr}"
        );
        assert!(
            !body.is_empty(),
            "{text_asset} must return non-empty asset payload"
        );
        let asset_text = String::from_utf8_lossy(body);
        assert_zero_customer_jargon(text_asset, &asset_text);
        if text_asset == "/assets/v4/styles.css" {
            let select_rule = extract_css_rule_body(&asset_text, "}\n\n.select {");
            for req in [
                "appearance: none;",
                "-webkit-appearance: none;",
                "padding: 0 36px 0 12px;",
                "right 12px center",
            ] {
                assert!(
                    select_rule.contains(req),
                    "/assets/v4/styles.css .select missing '{req}': {select_rule}"
                );
            }
            assert!(
                asset_text.contains("[data-theme=\"dark\"] .select"),
                "/assets/v4/styles.css must define dark-theme .select chevron contrast override"
            );

            let pill_fn_rule = extract_css_rule_body(&asset_text, "\n.pill-fn {");
            for req in [
                "min-height: 22px;",
                "white-space: nowrap;",
                "flex-shrink: 0;",
            ] {
                assert!(
                    pill_fn_rule.contains(req),
                    "/assets/v4/styles.css .pill-fn missing '{req}': {pill_fn_rule}"
                );
            }
            assert!(
                !pill_fn_rule.contains("height: 20px"),
                "/assets/v4/styles.css .pill-fn must not clamp height: 20px: {pill_fn_rule}"
            );

            let btn_secondary_pos = asset_text
                .find("\n.btn-secondary {")
                .expect(".btn-secondary rule in styles.css");
            let desktop_menu_hide_pos = asset_text
                .find(".app-header .menu-btn,\n.btn-secondary.menu-btn,\n.menu-btn {\n  display: none;")
                .expect("desktop .app-header .menu-btn display:none rule in styles.css");
            let mobile_breakpoint_pos = asset_text
                .find("@media (max-width: 719.98px) {\n  .app-header .menu-btn,")
                .expect("mobile @media (max-width: 719.98px) .menu-btn rule in styles.css");
            assert!(
                btn_secondary_pos < desktop_menu_hide_pos
                    && desktop_menu_hide_pos < mobile_breakpoint_pos,
                "desktop .menu-btn hide rule must appear AFTER .btn-secondary and BEFORE mobile media query"
            );
        }
        if text_asset == "/assets/v4/app.js" {
            assert_verified_chinwag_sh_routes_and_no_404s(text_asset, &asset_text);
            for required_token in [
                "Starter Pack",
                "Team Pack",
                "Growth Pack",
                "Scale Pack",
                "pack_50",
                "pack_160",
                "pack_560",
                "pack_1000",
                "6250",
                "25000",
                "100000",
                "200000",
                "Buy Starter Pack · $50 (6,250 Cr)",
                "500 free starter credits (valid 90 days)",
                "12 months",
                "https://chinwag.sh/pricing",
                "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
                "https://chinwag.sh/pricing?source=local_ui_referral",
                "https://chinwag.sh/security",
                "Verified agent handoff",
                "Repository context sync",
                "Protected-path safety check",
                "Cleanroom test run",
                "Independent second-tool review",
                "Verified PR ship & receipt",
                "Quad-programming · 200 Cr",
                "Three-tool check · 150 Cr",
                "test_verifier_tool",
                "security_verifier_tool",
                "Fix latest failing test",
                "Add webhook retry backoff",
                "Audit auth & billing checks",
            ] {
                assert!(
                    asset_text.contains(required_token),
                    "/assets/v4/app.js missing required commercial/CHWG-0235 string: {required_token}"
                );
            }
            for forbidden_legacy in [
                "What needs my attention",
                "Summarize what needs my decision",
                "Security review · 200 Cr",
                "item(s)",
            ] {
                assert!(
                    !asset_text.contains(forbidden_legacy),
                    "/assets/v4/app.js must not contain retired copy: {forbidden_legacy}"
                );
            }
            assert!(
                !asset_text.contains("prod_") && !asset_text.contains("price_1"),
                "/assets/v4/app.js must not expose internal Stripe/Metronome IDs"
            );
        }
    }

    for font_asset in [
        "/assets/v4/Geist-Latin.woff2",
        "/assets/v4/GeistMono-Latin.woff2",
    ] {
        let raw = send_raw_http(
            ui_addr,
            &format!("GET {font_asset} HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\n\r\n"),
        );
        let (hdr, body) = split_headers_and_body(&raw);
        assert!(hdr.starts_with("HTTP/1.1 200 OK"), "{hdr}");
        assert!(hdr.contains("Content-Type: font/woff2"), "{hdr}");
        assert!(
            body.starts_with(b"wOF2"),
            "{font_asset} must begin with wOF2 magic bytes"
        );
    }

    // 3. Audit every JSON API route for zero-jargon scrubbing (even with planted TASKS.md & messages.jsonl!)
    for (idx, api_path) in [
        "/api/v4/bootstrap",
        "/api/v4/diff?id=sample-walkthrough",
        "/api/v4/diff?id=CHWG-9001",
        "/api/v4/board",
        "/api/v4/agents",
        "/api/v4/credits",
        "/api/v4/cursor/preview",
        "/api/bus/status",
        "/api/bus/roster",
        "/api/bus/messages",
        "/api/tasks",
    ]
    .into_iter()
    .enumerate()
    {
        // Alternate between X-Chinwag-Csrf and X-Chinwag-Token to prove both headers authenticate cleanly
        let csrf_hdr_name = if idx % 2 == 0 {
            "X-Chinwag-Csrf"
        } else {
            "X-Chinwag-Token"
        };
        let raw = send_raw_http(
            ui_addr,
            &format!(
                "GET {api_path} HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\nSec-Fetch-Site: same-origin\r\nCookie: {cookie_pair}\r\n{csrf_hdr_name}: {csrf}\r\n\r\n"
            ),
        );
        let (hdr, body) = split_headers_and_body(&raw);
        assert!(
            hdr.starts_with("HTTP/1.1 200 OK"),
            "{api_path} failed: {hdr}"
        );
        let body_str = String::from_utf8_lossy(body);
        assert_zero_customer_jargon(api_path, &body_str);
        if api_path.starts_with("/api/v4/") {
            assert_verified_chinwag_sh_routes_and_no_404s(api_path, &body_str);
        }

        if api_path == "/api/v4/bootstrap" {
            let boot_json: Value = serde_json::from_slice(body).expect("valid bootstrap JSON");
            assert_eq!(
                boot_json["privacy"]["ciso_review_url"],
                "https://chinwag.sh/pricing?talk=1&source=local_ui#founders"
            );
            assert_eq!(
                boot_json["invite"]["referral_url"],
                "https://chinwag.sh/pricing?source=local_ui_referral"
            );
            assert_eq!(boot_json["invite"]["open_url"], "https://chinwag.sh/open");
        }

        if api_path == "/api/v4/credits" {
            let cred_json: Value = serde_json::from_slice(body).expect("valid credits JSON");
            assert_eq!(cred_json["pricing_url"], "https://chinwag.sh/pricing");
            let expiry_notice = cred_json["pack_expiry_notice"].as_str().unwrap_or("");
            assert!(
                expiry_notice.contains("500 free starter credits (valid 90 days)")
                    && expiry_notice.contains("12 months"),
                "unexpected pack_expiry_notice: {expiry_notice}"
            );
            assert!(
                !body_str.contains("prod_") && !body_str.contains("price_1"),
                "must never expose internal Stripe/Metronome IDs: {body_str}"
            );
            let packs = cred_json["packs"].as_array().expect("packs array");
            assert_eq!(packs.len(), 4);
            for (idx, (sku, label, cr, usd, rate_sub)) in [
                ("pack_50", "Starter Pack", 6_250u64, 50u64, "$0.0080 / Cr"),
                ("pack_160", "Team Pack", 25_000u64, 160u64, "$0.0064 / Cr"),
                (
                    "pack_560",
                    "Growth Pack",
                    100_000u64,
                    560u64,
                    "$0.0056 / Cr",
                ),
                (
                    "pack_1000",
                    "Scale Pack",
                    200_000u64,
                    1_000u64,
                    "$0.0050 / Cr",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(packs[idx]["sku"], sku);
                assert_eq!(packs[idx]["label"], label);
                assert_eq!(packs[idx]["credits"], cr);
                assert_eq!(packs[idx]["price_usd"], usd);
                assert_eq!(packs[idx]["expires_months"], 12);
                assert!(
                    packs[idx]["rate_note"]
                        .as_str()
                        .unwrap_or("")
                        .contains(rate_sub)
                        && packs[idx]["rate_note"]
                            .as_str()
                            .unwrap_or("")
                            .contains("12 months")
                );
            }
            let sched = cred_json["function_schedule"]
                .as_array()
                .expect("function_schedule array");
            for (idx, (label, cr)) in [
                ("Verified agent handoff", 15u64),
                ("Repository context sync", 50u64),
                ("Protected-path safety check", 50u64),
                ("Cleanroom test run", 100u64),
                ("Independent second-tool review", 150u64),
                ("Verified PR ship & receipt", 200u64),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(sched[idx]["label"], label);
                assert_eq!(sched[idx]["credits"], cr);
            }
        }

        if api_path == "/api/bus/messages" {
            // Confirm word-boundary scrubber preserved normal English "passed" while scrubbing DORA/SSE/GEMINI-PM!
            assert!(
                body_str.contains("all checks passed!"),
                "expected 'passed' to remain intact in scrubbed message: {body_str}"
            );
            assert!(
                body_str.contains("Chinwag PM"),
                "expected internal sender seat to map to 'Chinwag PM': {body_str}"
            );
        }
    }

    // 4. Verify Cursor rule import + .chinwag/workflow.yaml persistence + SampleWalkthroughShipForbidden
    let post_json = |path: &str, payload: Value| -> (String, Value) {
        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: 127.0.0.1:{ui_port}\r\n\
             Sec-Fetch-Site: same-origin\r\n\
             Origin: http://127.0.0.1:{ui_port}\r\n\
             Content-Type: application/json\r\n\
             Cookie: {cookie_pair}\r\n\
             X-Chinwag-Csrf: {csrf}\r\n\
             Content-Length: {}\r\n\r\n{}",
            body_bytes.len(),
            String::from_utf8_lossy(&body_bytes)
        );
        let raw = send_raw_http(ui_addr, &req);
        let (hdr, b) = split_headers_and_body(&raw);
        let parsed: Value = serde_json::from_slice(b).unwrap_or_else(|_| json!({}));
        (hdr, parsed)
    };

    let (sample_ship_hdr, sample_ship_val) = post_json(
        "/api/v4/inbox/action",
        json!({ "id": "sample-walkthrough", "action": "approve", "is_sample": true }),
    );
    assert!(sample_ship_hdr.starts_with("HTTP/1.1 403 Forbidden"));
    assert_eq!(
        sample_ship_val["error_code"],
        "SampleWalkthroughShipForbidden"
    );

    let (real_reject_hdr, real_reject_val) = post_json(
        "/api/v4/inbox/action",
        json!({
            "id": "CHWG-9001",
            "action": "reject",
            "note": "Always validate webhook signatures before database writes."
        }),
    );
    assert!(real_reject_hdr.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(real_reject_val["new_status"], "rejected");

    let (cursor_hdr, cursor_val) =
        post_json("/api/v4/cursor/apply", json!({ "selected_ids": ["cr-0"] }));
    assert!(cursor_hdr.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(cursor_val["imported_count"], 1);
    assert!(temp_repo.join(".chinwag/rules/cursor-testing.md").is_file());

    let (wf_hdr, wf_val) = post_json(
        "/api/v4/workflow",
        json!({
            "independent_review": true,
            "review_tier_credits": 200,
            "driver_tool": "claude_code",
            "reviewer_tool": "codex_cli",
            "test_verifier_tool": "gemini_cli",
            "security_verifier_tool": "cursor",
            "protect_sensitive_paths": true,
            "auto_test_before_review": false
        }),
    );
    assert!(wf_hdr.starts_with("HTTP/1.1 200 OK"), "{wf_hdr}");
    assert_eq!(wf_val["workflow"]["auto_test_before_review"], false);
    assert_eq!(wf_val["workflow"]["review_tier_credits"], 200);
    assert_eq!(wf_val["workflow"]["review_mode"], "quad_programming");
    assert_eq!(wf_val["workflow"]["driver_tool"], "claude_code");
    assert_eq!(wf_val["workflow"]["reviewer_tool"], "codex_cli");
    assert_eq!(wf_val["workflow"]["test_verifier_tool"], "gemini_cli");
    assert_eq!(wf_val["workflow"]["security_verifier_tool"], "cursor");
    assert!(temp_repo.join(".chinwag/workflow.yaml").is_file());
    let wf_yaml_text = fs::read_to_string(temp_repo.join(".chinwag/workflow.yaml")).unwrap();
    assert!(wf_yaml_text.contains("review_tier_credits: 200"));
    assert!(wf_yaml_text.contains("review_mode: \"quad_programming\""));
    assert!(wf_yaml_text.contains("test_verifier_tool: \"gemini_cli\""));
    assert!(wf_yaml_text.contains("security_verifier_tool: \"cursor\""));

    // Verify GET /api/v4/bootstrap round-trips Quad-programming workflow fields cleanly
    let boot_after_wf_raw = send_raw_http(
        ui_addr,
        &format!(
            "GET /api/v4/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\nSec-Fetch-Site: same-origin\r\nCookie: {cookie_pair}\r\nX-Chinwag-Csrf: {csrf}\r\n\r\n"
        ),
    );
    let (boot_after_wf_hdr, boot_after_wf_body) = split_headers_and_body(&boot_after_wf_raw);
    assert!(boot_after_wf_hdr.starts_with("HTTP/1.1 200 OK"));
    let boot_after_wf_json: Value = serde_json::from_slice(boot_after_wf_body).unwrap();
    assert_eq!(
        boot_after_wf_json["agents"]["workflow"]["review_tier_credits"],
        200
    );
    assert_eq!(
        boot_after_wf_json["agents"]["workflow"]["review_mode"],
        "quad_programming"
    );
    assert_eq!(
        boot_after_wf_json["agents"]["workflow"]["test_verifier_tool"],
        "gemini_cli"
    );
    assert_eq!(
        boot_after_wf_json["agents"]["workflow"]["security_verifier_tool"],
        "cursor"
    );

    // Verify server deduplicates duplicate slots, persists custom & empty `protected_paths: []` round-trip, and rejects invalid inputs
    let (dedup_wf_hdr, dedup_wf_val) = post_json(
        "/api/v4/workflow",
        json!({
            "driver_tool": "cursor",
            "reviewer_tool": "cursor",
            "test_verifier_tool": "cursor",
            "security_verifier_tool": "cursor",
            "protected_paths": ["billing/**", "auth/**"]
        }),
    );
    assert!(
        dedup_wf_hdr.starts_with("HTTP/1.1 200 OK"),
        "{dedup_wf_hdr}"
    );
    let slot_set: std::collections::BTreeSet<&str> = [
        dedup_wf_val["workflow"]["driver_tool"].as_str().unwrap(),
        dedup_wf_val["workflow"]["reviewer_tool"].as_str().unwrap(),
        dedup_wf_val["workflow"]["test_verifier_tool"]
            .as_str()
            .unwrap(),
        dedup_wf_val["workflow"]["security_verifier_tool"]
            .as_str()
            .unwrap(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        slot_set.len(),
        4,
        "expected 4 pairwise-distinct workflow slots: {dedup_wf_val}"
    );
    assert_eq!(
        dedup_wf_val["workflow"]["protected_paths"],
        json!(["billing/**", "auth/**"])
    );

    let (clear_paths_hdr, clear_paths_val) =
        post_json("/api/v4/workflow", json!({ "protected_paths": [] }));
    assert!(
        clear_paths_hdr.starts_with("HTTP/1.1 200 OK"),
        "{clear_paths_hdr}"
    );
    assert_eq!(clear_paths_val["workflow"]["protected_paths"], json!([]));

    let boot_empty_paths_raw = send_raw_http(
        ui_addr,
        &format!(
            "GET /api/v4/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\nSec-Fetch-Site: same-origin\r\nCookie: {cookie_pair}\r\nX-Chinwag-Csrf: {csrf}\r\n\r\n"
        ),
    );
    let (boot_empty_paths_hdr, boot_empty_paths_body) =
        split_headers_and_body(&boot_empty_paths_raw);
    assert!(boot_empty_paths_hdr.starts_with("HTTP/1.1 200 OK"));
    let boot_empty_paths_json: Value = serde_json::from_slice(boot_empty_paths_body).unwrap();
    assert_eq!(
        boot_empty_paths_json["agents"]["workflow"]["protected_paths"],
        json!([]),
        "removing final protected path must persist empty [] across bootstrap"
    );
    assert!(
        boot_empty_paths_json["agents"]["protected_paths"].is_null(),
        "server bootstrap must not emit a conflicting top-level agents.protected_paths field"
    );

    let (bad_credits_hdr, bad_credits_val) =
        post_json("/api/v4/workflow", json!({ "review_tier_credits": 75 }));
    assert!(
        bad_credits_hdr.starts_with("HTTP/1.1 400 Bad Request"),
        "{bad_credits_hdr}"
    );
    assert_eq!(bad_credits_val["error_code"], "invalid_review_tier_credits");

    let (bad_mode_hdr, bad_mode_val) =
        post_json("/api/v4/workflow", json!({ "review_mode": "invalid_tier" }));
    assert!(
        bad_mode_hdr.starts_with("HTTP/1.1 400 Bad Request"),
        "{bad_mode_hdr}"
    );
    assert_eq!(bad_mode_val["error_code"], "invalid_review_mode");

    let (empty_task_hdr, empty_task_val) = post_json(
        "/api/v4/board/tasks",
        json!({ "title": "   ", "tool": "claude_code" }),
    );
    assert!(
        empty_task_hdr.starts_with("HTTP/1.1 400 Bad Request"),
        "{empty_task_hdr}"
    );
    assert_eq!(empty_task_val["error_code"], "missing_title");

    // Verify POST /api/v4/board/tasks persists directly and surfaces in GET /api/v4/board queued column
    let (create_task_hdr, create_task_val) = post_json(
        "/api/v4/board/tasks",
        json!({
            "title": "Add exponential retry backoff to webhook handler",
            "tool": "claude_code",
            "workstream": "engineering"
        }),
    );
    assert!(
        create_task_hdr.starts_with("HTTP/1.1 200 OK"),
        "{create_task_hdr}"
    );
    assert_eq!(create_task_val["ok"], true);
    assert_eq!(create_task_val["task"]["workstream"], "engineering");
    assert_eq!(create_task_val["task"]["tool_label"], "Claude Code");

    let board_after_create_raw = send_raw_http(
        ui_addr,
        &format!(
            "GET /api/v4/board HTTP/1.1\r\nHost: 127.0.0.1:{ui_port}\r\nSec-Fetch-Site: same-origin\r\nCookie: {cookie_pair}\r\nX-Chinwag-Csrf: {csrf}\r\n\r\n"
        ),
    );
    let (board_after_create_hdr, board_after_create_body) =
        split_headers_and_body(&board_after_create_raw);
    assert!(board_after_create_hdr.starts_with("HTTP/1.1 200 OK"));
    let board_after_create_json: Value = serde_json::from_slice(board_after_create_body).unwrap();
    let queued_items = board_after_create_json["columns"][0]["items"]
        .as_array()
        .expect("queued column items array");
    assert!(
        queued_items.iter().any(|item| {
            item["title"] == "Add exponential retry backoff to webhook handler"
                && item["workstream"] == "engineering"
                && item["tool_label"] == "Claude Code"
        }),
        "expected newly queued engineering task in GET /api/v4/board queued column: {queued_items:?}"
    );

    let (sync_hdr, sync_val) = post_json("/api/v4/board/sync", json!({ "target": "github" }));
    assert!(sync_hdr.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(sync_val["credits_charged"], 0);

    // 4b. Verify POST /api/v4/credits/checkout maps all 4 pack SKUs to chinwag.sh/pricing wizard slugs
    for (sku, expected_wizard_slug) in [
        ("pack_50", "developer"),
        ("pack_160", "growth"),
        ("pack_560", "scale"),
        ("pack_1000", "volume"),
    ] {
        let (chk_hdr, chk_val) = post_json(
            "/api/v4/credits/checkout",
            json!({ "pack_sku": sku, "trigger_surface": "credits_tab" }),
        );
        assert!(
            chk_hdr.starts_with("HTTP/1.1 200 OK"),
            "checkout failed for {sku}: {chk_hdr} {chk_val}"
        );
        assert_eq!(chk_val["ok"], true);
        assert_eq!(chk_val["pack_sku"], sku);
        assert_eq!(chk_val["pricing_url"], "https://chinwag.sh/pricing");
        let checkout_url = chk_val["checkout_url"].as_str().unwrap_or("");
        let expected_prefix = format!(
            "https://chinwag.sh/pricing?pack={expected_wizard_slug}&source=local_ui&attempt="
        );
        assert!(
            checkout_url.starts_with(&expected_prefix),
            "expected checkout_url for {sku} to start with '{expected_prefix}', got '{checkout_url}'"
        );
        assert_verified_chinwag_sh_routes_and_no_404s(
            "/api/v4/credits/checkout",
            &chk_val.to_string(),
        );
    }

    // 5. Telemetry forwarding: valid event reaches local mock PostHog collector; PII & sample ship rejected!
    let (bad_pii_hdr, bad_pii_val) = post_json(
        "/api/v4/telemetry/track",
        json!({
            "event": "ui_view_navigated",
            "properties": {
                "previous_view": "/Users/alice/secret-repo/main.rs",
                "view": "board",
                "nav_trigger": "top_tab"
            }
        }),
    );
    assert!(bad_pii_hdr.starts_with("HTTP/1.1 400 Bad Request"));
    assert_eq!(bad_pii_val["ok"], false);
    assert_eq!(bad_pii_val["reason"], "ForbiddenPathOrDotfile");

    let (ok_tel_hdr, ok_tel_val) = post_json(
        "/api/v4/telemetry/track",
        json!({
            "event": "ui_view_navigated",
            "properties": {
                "previous_view": "inbox",
                "view": "credits",
                "nav_trigger": "top_tab"
            }
        }),
    );
    assert!(
        ok_tel_hdr.starts_with("HTTP/1.1 202 Accepted"),
        "{ok_tel_hdr}"
    );
    assert_eq!(ok_tel_val["ok"], true);
    assert_eq!(ok_tel_val["queued"], true);

    for chip_slug in [
        "scope_fix_last_test",
        "retry_backoff_webhook",
        "audit_auth_billing",
    ] {
        let (chip_hdr, chip_val) = post_json(
            "/api/v4/telemetry/track",
            json!({
                "event": "ui_board_task_modal_opened",
                "properties": {
                    "trigger_surface": "onboarding_banner",
                    "chip_slug": chip_slug
                }
            }),
        );
        assert!(
            chip_hdr.starts_with("HTTP/1.1 202 Accepted"),
            "expected 202 Accepted for ui_board_task_modal_opened chip_slug={chip_slug}: {chip_hdr} {chip_val}"
        );
        assert_eq!(chip_val["ok"], true);
    }

    // Wait up to 3s for background curl worker to deliver to ph_listener
    let ph_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if !captured_ph.lock().unwrap().is_empty() {
            break;
        }
        assert!(
            Instant::now() < ph_deadline,
            "timed out waiting for background curl delivery to mock PostHog endpoint"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let delivered = captured_ph.lock().unwrap()[0].clone();
    let delivered_json: Value = serde_json::from_str(&delivered).expect("valid PostHog JSON");
    assert_eq!(delivered_json["event"], "ui_view_navigated");
    assert!(
        delivered_json["distinct_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("ui_")
    );
    assert_eq!(delivered_json["properties"]["surface"], "chinwag_ui");
    assert_eq!(delivered_json["properties"]["ui_version"], "4.1");
    assert_eq!(delivered_json["properties"]["view"], "credits");

    let _ = fs::remove_dir_all(&temp_repo);
}

#[test]
fn ui_v4_app_js_behavioral_rollback_and_serialization() {
    let node_ver = Command::new("node")
        .arg("--version")
        .output()
        .expect("node binary must be installed on PATH for UI v4 behavioral harness");
    assert!(
        node_ver.status.success(),
        "node --version failed: {:?}",
        node_ver
    );

    let app_js_path = format!("{}/assets/ui-v4/app.js", env!("CARGO_MANIFEST_DIR"));
    let harness = r#"
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

const src = fs.readFileSync(process.env.APP_JS_PATH, "utf8")
  .replace(/^import\s+\*\s+as\s+Motion\s+from\s+"\.\/motion\.js";/m, "const Motion = new Proxy({ guardAction: async (_btn, fn) => ({ value: await fn(), release: () => {} }) }, { get(t, k) { return k in t ? t[k] : () => ({ update() {}, destroy() {}, show() {}, dismiss() {} }); } });")
  .replace(/^export\s+/gm, "");

let mockWorkflowHandler = async (body) => ({ ok: true, workflow: body });
let mockBootstrapHandler = async () => ({ agents: { workflow: { review_tier_credits: 100 } } });
let mockBoardTaskHandler = async (body) => ({ ok: true, task: { id: "TASK-LOCAL-1", title: body.title, workstream: body.workstream, tool_label: "Claude Code" } });
const trackedEvents = [];

const sandbox = {
  console,
  setTimeout,
  clearTimeout,
  Date,
  Math,
  JSON,
  Number,
  String,
  Boolean,
  Array,
  Object,
  Set,
  Map,
  Promise,
  Error,
  RegExp,
  encodeURIComponent,
  decodeURIComponent,
  SERVER_PORT: 5487,
  CSRF_TOKEN: "test-csrf",
  fetch: async (url, opts = {}) => {
    const body = opts.body ? JSON.parse(opts.body) : {};
    if (url === "/api/v4/telemetry/track") {
      trackedEvents.push(body);
      return { ok: true, status: 202, json: async () => ({ ok: true }) };
    }
    if (url === "/api/v4/bootstrap") {
      const res = await mockBootstrapHandler();
      return { ok: true, status: 200, json: async () => res };
    }
    if (url === "/api/v4/workflow") {
      try {
        const res = await mockWorkflowHandler(body);
        return { ok: true, status: 200, json: async () => res };
      } catch (e) {
        return { ok: false, status: 500, json: async () => ({ ok: false, error: e.message }) };
      }
    }
    if (url === "/api/v4/board/tasks") {
      const res = await mockBoardTaskHandler(body);
      return { ok: true, status: 200, json: async () => res };
    }
    return { ok: true, status: 200, json: async () => ({ ok: true }) };
  },
};

vm.createContext(sandbox);
vm.runInContext(
  src + "\nglobalThis.__test = { state, normalizeBootstrap, ensureDistinctPairingSlots, saveWorkflowSettings, refreshBootstrapQuietly, queueEngineeringTaskFromLauncher, formatHumanList };",
  sandbox
);

(async () => {
  const T = sandbox.__test;

  // 1. formatHumanList Oxford-comma formatting
  assert.strictEqual(T.formatHumanList(["Claude Code"]), "Claude Code");
  assert.strictEqual(T.formatHumanList(["Claude Code", "Cursor"]), "Claude Code and Cursor");
  assert.strictEqual(T.formatHumanList(["Claude Code", "Codex CLI", "Cursor"]), "Claude Code, Codex CLI, and Cursor");

  // 2. normalizeBootstrap preserves empty protected_paths [] and maps active/review board columns
  const booted = T.normalizeBootstrap({
    board: {
      columns: [
        { id: "queued", items: [{ id: "Q1" }] },
        { id: "active", items: [{ id: "A1" }] },
        { id: "review", items: [{ id: "R1" }] },
        { id: "shipped", items: [{ id: "S1" }] },
      ],
    },
    agents: {
      driver_tool: "gemini",
      reviewer_tool: "codex",
      workflow: {
        review_mode: "triad_sandbox",
        protected_paths: [],
      },
    },
  });
  assert.strictEqual(booted.board.columns.in_progress[0].id, "A1");
  assert.strictEqual(booted.board.columns.needs_review[0].id, "R1");
  assert.deepStrictEqual(booted.agents.protected_paths, []);
  assert.strictEqual(booted.agents.driver_tool, "gemini_cli");
  assert.strictEqual(booted.agents.reviewer_tool, "codex_cli");
  assert.strictEqual(booted.agents.test_verifier_tool, "claude_code");
  assert.strictEqual(booted.agents.security_verifier_tool, "cursor");
  assert.strictEqual(booted.agents.review_tier_credits, 150);

  // 3. Failed save rolls back tier, slot, and protected_paths to committed state and permits retry
  T.state.data = T.normalizeBootstrap({
    agents: {
      workflow: {
        driver_tool: "claude_code",
        reviewer_tool: "codex_cli",
        test_verifier_tool: "gemini_cli",
        security_verifier_tool: "cursor",
        review_tier_credits: 100,
        protected_paths: ["auth/**"],
      },
    },
  });
  T.state.committedWorkflow = null;
  trackedEvents.length = 0;

  mockWorkflowHandler = async () => { throw new Error("disk full"); };
  let failed = false;
  try {
    await T.saveWorkflowSettings(
      { review_tier_credits: 200, protected_paths: ["auth/**", "billing/**"] },
      {
        changedSlotIdx: 1,
        nextTool: "cursor",
        prevTool: "codex_cli",
        onCommitted: () => trackedEvents.push({ event: "ui_cross_tool_pairing_updated" }),
      }
    );
  } catch (e) {
    failed = true;
  }
  assert.strictEqual(failed, true);
  assert.strictEqual(T.state.data.agents.review_tier_credits, 100, "failed tier save must revert to committed 100 Cr");
  assert.strictEqual(T.state.data.agents.reviewer_tool, "codex_cli", "failed slot swap must revert to codex_cli");
  assert.strictEqual(T.state.data.agents.security_verifier_tool, "cursor", "failed slot swap must revert security slot");
  assert.deepStrictEqual([...T.state.data.agents.protected_paths], ["auth/**"], "failed path add must revert to committed paths");
  assert.strictEqual(trackedEvents.some((e) => e.event === "ui_cross_tool_pairing_updated"), false);

  // Retry of 200 Cr succeeds cleanly once backend recovers
  mockWorkflowHandler = async (body) => ({ ok: true, workflow: body });
  await T.saveWorkflowSettings({ review_tier_credits: 200 });
  assert.strictEqual(T.state.data.agents.review_tier_credits, 200);

  // 4. Overlapping saves + mixed-failure interleavings (A-ok/B-fail -> 150 Cr; A-fail/B-ok -> 200 Cr)
  let callOrder = [];
  mockWorkflowHandler = async (body) => {
    callOrder.push(body.review_tier_credits);
    if (body.review_tier_credits === 150) {
      await new Promise((r) => setTimeout(r, 30));
    }
    return { ok: true, workflow: body };
  };
  const p1 = T.saveWorkflowSettings({ review_tier_credits: 150 });
  const p2 = T.saveWorkflowSettings({ review_tier_credits: 200 });
  await Promise.all([p1, p2]);
  assert.deepStrictEqual(callOrder, [150, 200]);
  assert.strictEqual(T.state.data.agents.review_tier_credits, 200);

  // Mixed A-ok (150) then B-fail (50) -> rolls back to 150
  mockWorkflowHandler = async (body) => {
    if (body.review_tier_credits === 50) throw new Error("reject 50");
    return { ok: true, workflow: body };
  };
  const m1 = T.saveWorkflowSettings({ review_tier_credits: 150 });
  const m2 = T.saveWorkflowSettings({ review_tier_credits: 50 }).catch(() => "caught");
  await Promise.all([m1, m2]);
  assert.strictEqual(T.state.data.agents.review_tier_credits, 150);

  // Mixed A-fail (50) then B-ok (200) -> commits 200 without rollback clobber
  const m3 = T.saveWorkflowSettings({ review_tier_credits: 50 }).catch(() => "caught");
  const m4 = T.saveWorkflowSettings({ review_tier_credits: 200 });
  await Promise.all([m3, m4]);
  assert.strictEqual(T.state.data.agents.review_tier_credits, 200);

  // 5. Delayed bootstrap GET started before a save that completes BEFORE the GET returns must NOT overwrite committed 200 Cr
  T.state.data = T.normalizeBootstrap({ agents: { workflow: { review_tier_credits: 100 } } });
  T.state.committedWorkflow = null;
  let releaseStaleBootstrap;
  const staleBootstrapGate = new Promise((resolve) => { releaseStaleBootstrap = resolve; });
  mockBootstrapHandler = async () => {
    await staleBootstrapGate;
    return { agents: { workflow: { review_tier_credits: 100, protected_paths: ["stale/**"] } } };
  };
  let lastPersistedPayload = null;
  mockWorkflowHandler = async (body) => {
    lastPersistedPayload = body;
    return { ok: true, workflow: body };
  };
  const refreshPromise = T.refreshBootstrapQuietly();
  await T.saveWorkflowSettings({ review_tier_credits: 200, protected_paths: [] });
  releaseStaleBootstrap();
  await refreshPromise;
  assert.strictEqual(T.state.data.agents.review_tier_credits, 200, "delayed stale bootstrap GET must not revert completed 200 Cr save");
  assert.strictEqual(T.state.committedWorkflow.review_tier_credits, 200);
  assert.deepStrictEqual([...T.state.data.agents.protected_paths], []);

  // Subsequent unrelated toggle save must persist 200 Cr (not stale 100 Cr)
  await T.saveWorkflowSettings({ auto_test_before_review: false });
  assert.strictEqual(lastPersistedPayload.review_tier_credits, 200);
  assert.deepStrictEqual(lastPersistedPayload.protected_paths, []);

  // 5b. Delayed bootstrap GET started DURING an active save (hadInFlightAtStart = true) where the save completes BEFORE the GET returns
  T.state.data = T.normalizeBootstrap({ agents: { workflow: { review_tier_credits: 100, protected_paths: ["old/**"] } } });
  T.state.committedWorkflow = null;
  let releaseSaveDuringGet;
  const saveDuringGetGate = new Promise((resolve) => { releaseSaveDuringGet = resolve; });
  let releaseGetDuringSave;
  const getDuringSaveGate = new Promise((resolve) => { releaseGetDuringSave = resolve; });
  mockWorkflowHandler = async (body) => {
    await saveDuringGetGate;
    lastPersistedPayload = body;
    return { ok: true, workflow: body };
  };
  mockBootstrapHandler = async () => {
    await getDuringSaveGate;
    return { agents: { workflow: { review_tier_credits: 100, protected_paths: ["old/**"] } } };
  };
  const inFlightSavePromise = T.saveWorkflowSettings({ review_tier_credits: 200, protected_paths: ["fresh/**"] });
  assert.strictEqual(T.state.workflowSaveInFlight, 1);
  const refreshDuringSavePromise = T.refreshBootstrapQuietly();
  releaseSaveDuringGet();
  await inFlightSavePromise;
  assert.strictEqual(T.state.workflowSaveInFlight, 0);
  releaseGetDuringSave();
  await refreshDuringSavePromise;
  assert.strictEqual(T.state.data.agents.review_tier_credits, 200, "GET started during active save must not revert 200 Cr after save completes");
  assert.strictEqual(T.state.committedWorkflow.review_tier_credits, 200);
  assert.deepStrictEqual([...T.state.data.agents.protected_paths], ["fresh/**"]);
  mockWorkflowHandler = async (body) => {
    lastPersistedPayload = body;
    return { ok: true, workflow: body };
  };
  await T.saveWorkflowSettings({ independent_review: true });
  assert.strictEqual(lastPersistedPayload.review_tier_credits, 200);
  assert.deepStrictEqual(lastPersistedPayload.protected_paths, ["fresh/**"]);

  // 6. queueEngineeringTaskFromLauncher uses server-scrubbed title and deduplicates by task id
  mockBoardTaskHandler = async () => ({
    ok: true,
    task: {
      id: "TASK-LOCAL-99",
      title: "Scrubbed webhook retry task",
      workstream: "engineering",
      tool_label: "Claude Code",
    },
  });
  await T.queueEngineeringTaskFromLauncher("Raw internal title");
  await T.queueEngineeringTaskFromLauncher("Duplicate id replay");
  assert.strictEqual(T.state.data.board.columns.queued.length, 1);
  assert.strictEqual(T.state.data.board.columns.queued[0].title, "Scrubbed webhook retry task");
  assert.strictEqual(T.state.launcherDraft, "");
  console.log("NODE_VM_HARNESS_OK=6_SUITES");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
"#;

    let out = Command::new("node")
        .arg("-e")
        .arg(harness)
        .env("APP_JS_PATH", &app_js_path)
        .output()
        .expect("execute node VM behavioral harness");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout_str.contains("NODE_VM_HARNESS_OK=6_SUITES"),
        "node VM behavioral harness failed:\nstdout: {}\nstderr: {}",
        stdout_str,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ui_v4_popover_race_and_mobile_menu_privacy_handoff() {
    let app_js_path = format!("{}/assets/ui-v4/app.js", env!("CARGO_MANIFEST_DIR"));
    let harness = r##"
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");

class StubNode {
  constructor(tagName) {
    this.tagName = String(tagName || "DIV").toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.dataset = {};
    this.listeners = new Map();
    this.className = "";
    this.id = "";
    this.hidden = false;
    this.checked = false;
    this.selected = false;
    this.value = "";
    this.onclick = null;
    this._text = "";
  }
  get firstChild() {
    return this.children.length > 0 ? this.children[0] : null;
  }
  get isConnected() {
    return true;
  }
  get textContent() {
    if (this.tagName === "__TEXT__") return this._text;
    return this.children.map((c) => c.textContent).join("");
  }
  set textContent(val) {
    this.children = [];
    if (this.tagName === "__TEXT__") {
      this._text = String(val ?? "");
    } else if (val !== null && val !== undefined && String(val) !== "") {
      const t = new StubNode("__TEXT__");
      t._text = String(val);
      this.appendChild(t);
    }
  }
  appendChild(child) {
    if (!child) return child;
    if (child.parentNode) {
      child.parentNode.removeChild(child);
    }
    child.parentNode = this;
    this.children.push(child);
    return child;
  }
  append(...nodes) {
    for (const n of nodes) {
      if (n === null || n === undefined) continue;
      if (n instanceof StubNode) {
        this.appendChild(n);
      } else {
        const t = new StubNode("__TEXT__");
        t._text = String(n);
        this.appendChild(t);
      }
    }
  }
  removeChild(child) {
    const idx = this.children.indexOf(child);
    if (idx !== -1) {
      this.children.splice(idx, 1);
      child.parentNode = null;
    }
    return child;
  }
  setAttribute(k, v) {
    const sv = String(v);
    if (k === "id") this.id = sv;
    if (k === "class") this.className = sv;
    this.attributes.set(k, sv);
  }
  getAttribute(k) {
    if (k === "id" && this.id) return this.id;
    if (k === "class" && this.className) return this.className;
    return this.attributes.has(k) ? this.attributes.get(k) : null;
  }
  removeAttribute(k) {
    this.attributes.delete(k);
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  click() {
    const ev = {
      type: "click",
      target: this,
      preventDefault() {},
      stopPropagation() {},
    };
    if (typeof this.onclick === "function") this.onclick(ev);
    for (const fn of this.listeners.get("click") || []) {
      fn(ev);
    }
  }
  focus() {
    stubDocument.activeElement = this;
  }
  matchesSimple(sel) {
    if (this.tagName === "__TEXT__") return false;
    const s = sel.trim();
    if (s === '.popover[data-state="closing"]') {
      return this.className.split(/\s+/).includes("popover") && this.dataset.state === "closing";
    }
    if (s.startsWith(".")) {
      const cls = s.slice(1);
      return this.className.split(/\s+/).includes(cls);
    }
    if (s === "[href]") {
      return this.attributes.has("href");
    }
    if (s === "button.btn-primary") {
      return this.tagName === "BUTTON" && this.className.split(/\s+/).includes("btn-primary");
    }
    return this.tagName === s.toUpperCase();
  }
  querySelectorAll(selector) {
    const parts = selector.split(",").map((p) => p.trim()).filter(Boolean);
    const results = [];
    const visit = (node) => {
      for (const child of node.children) {
        if (parts.some((p) => child.matchesSimple(p))) {
          results.push(child);
        }
        visit(child);
      }
    };
    visit(this);
    return results;
  }
  querySelector(selector) {
    const all = this.querySelectorAll(selector);
    return all.length > 0 ? all[0] : null;
  }
}

const byId = new Map();
function mountEl(tag, id, hidden = false) {
  const n = new StubNode(tag);
  n.id = id;
  n.hidden = hidden;
  byId.set(id, n);
  return n;
}

const docEl = new StubNode("html");
docEl.setAttribute("data-theme", "stone");
const btnPrivacy = mountEl("button", "btn-privacy");
const btnMobileMenu = mountEl("button", "btn-mobile-menu");
const btnInvite = mountEl("button", "btn-invite");
btnInvite._computedDisplay = "none";
const popoverLayer = mountEl("div", "popover-layer", true);
const modalScrim = mountEl("div", "modal-scrim", true);
const modalLayer = mountEl("div", "modal-layer", true);
mountEl("div", "toast-region", false);
mountEl("div", "sr-announcer", false);

const stubDocument = {
  readyState: "loading",
  hidden: false,
  title: "",
  activeElement: null,
  documentElement: docEl,
  createElement: (tag) => new StubNode(tag),
  createElementNS: (_ns, tag) => new StubNode(tag),
  createTextNode: (txt) => {
    const t = new StubNode("__TEXT__");
    t._text = String(txt ?? "");
    return t;
  },
  getElementById: (id) => byId.get(id) || null,
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener() {},
};

const stubWindow = {
  location: { hash: "#inbox" },
  addEventListener() {},
  setInterval: () => 1,
  getComputedStyle: (el) => ({ display: el && el._computedDisplay ? el._computedDisplay : "inline-flex" }),
};

const src = fs
  .readFileSync(process.env.APP_JS_PATH, "utf8")
  .replace(
    /^import\s+\*\s+as\s+Motion\s+from\s+"\.\/motion\.js";/m,
    `const Motion = new Proxy({
      settled: () => new Promise((r) => setTimeout(r, 25)),
      guardAction: async (_btn, fn) => ({ value: await fn(), release: () => {} }),
      createToaster: () => ({ show() {}, dismiss() {} }),
      createElapsedClock: () => ({ bind() {}, destroy() {} }),
      bindIndicator: () => ({ update() {}, destroy() {} }),
      observeLoop: () => {},
      switchTheme: (next) => stubDocument.documentElement.setAttribute("data-theme", next),
    }, { get(t, k) { return k in t ? t[k] : () => ({ update() {}, destroy() {}, show() {}, dismiss() {} }); } });`
  )
  .replace(/^export\s+/gm, "");

const sandbox = {
  console,
  setTimeout,
  clearTimeout,
  requestAnimationFrame: (fn) => setTimeout(fn, 0),
  Date,
  Math,
  JSON,
  Number,
  String,
  Boolean,
  Array,
  Object,
  Set,
  Map,
  Promise,
  Error,
  RegExp,
  encodeURIComponent,
  decodeURIComponent,
  Node: StubNode,
  stubDocument,
  document: stubDocument,
  window: stubWindow,
  localStorage: {
    _m: new Map(),
    getItem(k) { return this._m.has(k) ? this._m.get(k) : null; },
    setItem(k, v) { this._m.set(k, String(v)); },
    removeItem(k) { this._m.delete(k); },
  },
  SERVER_PORT: 5487,
  CSRF_TOKEN: "test-csrf",
  fetch: async () => ({ ok: true, status: 202, json: async () => ({ ok: true, telemetry_enabled: true }) }),
};

vm.createContext(sandbox);
vm.runInContext(
  src + "\nglobalThis.__domTest = { openPrivacyPopover, openMobileMenuPopover, openInviteModal, closePopover, closeModal, wizardPackSlugForSku };",
  sandbox
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const T = sandbox.__domTest;
  btnPrivacy.addEventListener("click", () => T.openPrivacyPopover(btnPrivacy));
  btnMobileMenu.addEventListener("click", () => T.openMobileMenuPopover(btnMobileMenu));

  // 1. Direct #btn-privacy click mounts Local privacy dialog + verified security/founders links and survives settle window
  btnPrivacy.click();
  assert.strictEqual(popoverLayer.hidden, false, "direct #btn-privacy click must unhide #popover-layer");
  const h2Direct = popoverLayer.querySelector("h2");
  assert.ok(h2Direct && h2Direct.textContent === "Local privacy", "expected Local privacy heading on direct click");
  const links = popoverLayer.querySelectorAll("a").map((a) => a.getAttribute("href"));
  assert.deepStrictEqual(links, [
    "https://chinwag.sh/security",
    "https://chinwag.sh/pricing?talk=1&source=local_ui#founders",
  ]);
  await sleep(40);
  assert.strictEqual(popoverLayer.hidden, false, "Local privacy popover must remain open after Motion.settled window");

  // 2. Stale closePopover() timer race: start animated close (25ms), re-click #btn-privacy 5ms later -> must NOT wipe newly opened popover
  const closingPromise = T.closePopover();
  await sleep(5);
  btnPrivacy.click();
  assert.strictEqual(popoverLayer.hidden, false);
  await closingPromise;
  await sleep(35);
  assert.strictEqual(popoverLayer.hidden, false, "stale closePopover() Motion.settled completion must never wipe re-opened Local privacy popover");
  assert.strictEqual(popoverLayer.querySelector("h2").textContent, "Local privacy");

  await T.closePopover({ immediate: true });
  assert.strictEqual(popoverLayer.hidden, true);

  // 3. Mobile Menu -> "Local privacy & analytics" handoff on same triggerEl opens Local privacy deterministically
  btnMobileMenu.click();
  assert.strictEqual(popoverLayer.hidden, false);
  assert.strictEqual(popoverLayer.querySelector("h2").textContent, "Menu");
  const menuPrivacyBtn = popoverLayer
    .querySelectorAll("button")
    .find((b) => b.textContent.includes("Local privacy & analytics"));
  assert.ok(menuPrivacyBtn, "Menu must render Local privacy & analytics button");
  menuPrivacyBtn.click();
  assert.strictEqual(popoverLayer.hidden, false, "clicking Local privacy & analytics in Menu must immediately open Local privacy");
  assert.strictEqual(popoverLayer.querySelector("h2").textContent, "Local privacy");
  await sleep(40);
  assert.strictEqual(popoverLayer.hidden, false, "Local privacy opened from Menu must survive async Motion.settled timers");
  assert.strictEqual(popoverLayer.querySelector("h2").textContent, "Local privacy");

  // 4. Mobile Menu -> "Invite teammate · +250 Cr" closes popover immediately, mounts Invite modal with verified referral URL, and restores focus to mobile trigger when #btn-invite is display:none
  await T.closePopover({ immediate: true });
  btnMobileMenu.click();
  const menuInviteBtn = popoverLayer
    .querySelectorAll("button")
    .find((b) => b.textContent.includes("Invite teammate"));
  assert.ok(menuInviteBtn, "Menu must render Invite teammate button");
  menuInviteBtn.click();
  assert.strictEqual(popoverLayer.hidden, true, "Invite handoff must close Menu popover immediately");
  assert.strictEqual(modalLayer.hidden, false, "Invite handoff must open #modal-layer");
  const copyFields = modalLayer.querySelectorAll(".copy-field").map((n) => n.textContent);
  assert.ok(
    copyFields.includes("https://chinwag.sh/pricing?source=local_ui_referral"),
    `expected verified referral_url in Invite modal, got ${JSON.stringify(copyFields)}`
  );
  await T.closeModal();
  assert.strictEqual(modalLayer.hidden, true);
  assert.strictEqual(stubDocument.activeElement, btnMobileMenu, "closing Invite modal opened from mobile menu must restore focus to #btn-mobile-menu");

  // 5. Fallback checkout pack slug mapping matches pricing.html wizard keys
  assert.strictEqual(T.wizardPackSlugForSku("pack_50"), "developer");
  assert.strictEqual(T.wizardPackSlugForSku("pack_160"), "growth");
  assert.strictEqual(T.wizardPackSlugForSku("pack_560"), "scale");
  assert.strictEqual(T.wizardPackSlugForSku("pack_1000"), "volume");

  console.log("POPOVER_DOM_HARNESS_OK=5_SUITES");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
"##;

    let out = Command::new("node")
        .arg("-e")
        .arg(harness)
        .env("APP_JS_PATH", &app_js_path)
        .output()
        .expect("execute node VM popover DOM harness");
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout_str.contains("POPOVER_DOM_HARNESS_OK=5_SUITES"),
        "node VM popover DOM harness failed:\nstdout: {}\nstderr: {}",
        stdout_str,
        String::from_utf8_lossy(&out.stderr)
    );
}
