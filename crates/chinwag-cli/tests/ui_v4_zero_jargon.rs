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
        if text_asset == "/assets/v4/app.js" {
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
                "https://chinwag.sh/pricing.html#credit-packs",
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

        if api_path == "/api/v4/credits" {
            let cred_json: Value = serde_json::from_slice(body).expect("valid credits JSON");
            assert_eq!(
                cred_json["pricing_url"],
                "https://chinwag.sh/pricing.html#credit-packs"
            );
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
