// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! End-to-end integration tests for `CHWG-0251`:
//! 1. `chinwag memory tombstone --promote-regression` & `chinwag regression add|verify|list`
//!    (`INV-CI-BEHAVIORAL-RATCHET-01` & `INV-CI-ZERO-SECRET-LEAK-01`).
//! 2. Real `chinwag ui-gate --url <url> --out <audit.json>` headless Chromium CDP + HTTP `<a href>`
//!    link inspector (`1440x900` Desktop Light/Dark + `390x844` Mobile).
//! 3. Fail-closed `UiGateSurface::LocalApp` validator (`0` desktop or `0` mobile records -> exit 1).

#![cfg(target_os = "macos")]

use chinwag_cli::regression_ratchet::{PromoteRegressionReceipt, RegressionVerifyReportV1};
use chinwag_cli::ui_gate_run::{
    UiAuditReportV1, UiAuditViewportRecordV1, UiGateReceiptV1, UiGateSurface, UiInspectorDriver,
    inspect_and_gate_url, resolve_chromium_binary,
};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

fn chinwag_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_chinwag"))
}

#[test]
fn tombstone_promote_regression_scrubs_secrets_is_jcs_deterministic_and_ratchets_offline() {
    let base_tmp = fs::canonicalize(std::env::temp_dir()).unwrap();
    let dir = tempfile::tempdir_in(base_tmp).unwrap();
    let repo = dir.path();
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(
        repo.join("src/coord.rs"),
        "pub fn sync_state() { let _v = pragma_data_version(); }\n",
    )
    .unwrap();

    // Construct fake secret tokens dynamically so source scanners see zero literal secrets:
    let fake_anthropic = format!("{}{}", concat!("sk", "-ant-api03-"), "A".repeat(36));
    let fake_ghp = format!("{}{}", concat!("gh", "p_"), "9".repeat(36));
    let reason_with_secrets = format!(
        "Killed background polling loop that leaked {fake_anthropic} and {fake_ghp} in debug logs"
    );

    let out = chinwag_cmd()
        .args([
            "memory",
            "tombstone",
            "--id",
            "tombstone-no-sleep-poll-v1",
            "--file-scope",
            "src/*.rs",
            "--reason",
            &reason_with_secrets,
            "--alternative",
            "Read SQLite pragma_data_version header stamp directly",
            "--promote-regression",
            "--forbidden-pattern",
            "std::thread::sleep",
            "--required-pattern",
            "pragma_data_version",
            "--repo",
            repo.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let reg_path = repo
        .join(".chinwag/regressions")
        .join("tombstone-no-sleep-poll-v1.json");
    let cas_path = repo
        .join(".chinwag/cassettes")
        .join("tombstone-no-sleep-poll-v1.json");
    assert!(reg_path.is_file(), "expected regression spec JSON");
    assert!(cas_path.is_file(), "expected TombstoneCassetteV1 JSON");

    let reg_bytes_1 = fs::read_to_string(&reg_path).unwrap();
    let cas_bytes_1 = fs::read_to_string(&cas_path).unwrap();
    assert!(!reg_bytes_1.contains(&fake_anthropic));
    assert!(!reg_bytes_1.contains(&fake_ghp));
    assert!(!cas_bytes_1.contains(&fake_anthropic));
    assert!(!cas_bytes_1.contains(&fake_ghp));
    assert!(cas_bytes_1.contains("\"TombstoneCassetteV1\""));

    // Re-running with identical inputs produces byte-for-byte identical RFC-8785 output:
    let out2 = chinwag_cmd()
        .args([
            "regression",
            "add",
            "--id",
            "tombstone-no-sleep-poll-v1",
            "--file-scope",
            "src/*.rs",
            "--reason",
            &reason_with_secrets,
            "--alternative",
            "Read SQLite pragma_data_version header stamp directly",
            "--forbidden-pattern",
            "std::thread::sleep",
            "--required-pattern",
            "pragma_data_version",
            "--repo",
            repo.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let add_receipt: PromoteRegressionReceipt = serde_json::from_slice(&out2.stdout).unwrap();
    add_receipt.verify_signature().unwrap();
    assert_eq!(reg_bytes_1, fs::read_to_string(&reg_path).unwrap());
    assert_eq!(cas_bytes_1, fs::read_to_string(&cas_path).unwrap());

    // Offline $0 verification passes when codebase obeys the ratchet:
    let verify_ok = chinwag_cmd()
        .args([
            "regression",
            "verify",
            "--repo",
            repo.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        verify_ok.status.success(),
        "verify_ok stderr={}",
        String::from_utf8_lossy(&verify_ok.stderr)
    );
    let verify_ok_report: RegressionVerifyReportV1 =
        serde_json::from_slice(&verify_ok.stdout).unwrap();
    verify_ok_report.verify_signature().unwrap();
    assert!(verify_ok_report.passed);
    assert_eq!(verify_ok_report.specs_verified, 1);
    assert_eq!(verify_ok_report.cassettes_verified, 1);

    // Reintroducing the tombstoned anti-pattern trips the behavioral ratchet immediately:
    fs::write(
        repo.join("src/coord.rs"),
        "pub fn sync_state() { std::thread::sleep(std::time::Duration::from_secs(5)); let _v = pragma_data_version(); }\n",
    )
    .unwrap();
    let verify_fail = chinwag_cmd()
        .args([
            "regression",
            "verify",
            "--repo",
            repo.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(verify_fail.status.code(), Some(1));
    let verify_fail_report: RegressionVerifyReportV1 =
        serde_json::from_slice(&verify_fail.stdout).unwrap();
    verify_fail_report.verify_signature().unwrap();
    assert!(!verify_fail_report.passed);
    assert!(!verify_fail_report.failures.is_empty());
}

struct LocalTestHttpServer {
    base_url: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl LocalTestHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);

        let handle = std::thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));
                        let mut buf = [0_u8; 4096];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        if n == 0 {
                            continue;
                        }
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("/");
                        let (status_line, extra_headers, body) = match path {
                            "/" | "/clean" => (
                                "HTTP/1.1 200 OK",
                                "Content-Type: text/html; charset=utf-8\r\n",
                                concat!(
                                    "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                                    "<style>body{margin:0;padding:16px;font-family:sans-serif;}",
                                    ".pill{display:inline-block;padding:4px 12px;}",
                                    "button{padding:8px 14px;min-width:64px;min-height:32px;}",
                                    "select{padding:4px 24px 4px 8px;min-width:120px;height:34px;font-size:14px;}",
                                    "</style></head><body>",
                                    "<span class=\"pill\">Healthy</span>",
                                    "<button id=\"act-btn\" type=\"button\" onclick=\"this.dataset.clicked='1'\">Run</button>",
                                    "<select id=\"mode-sel\"><option value=\"fast\">Fast</option></select>",
                                    "<a href=\"/docs\">Docs</a> <a href=\"/redirect-ok\">Pricing</a>",
                                    "</body></html>"
                                ),
                            ),
                            "/docs" => (
                                "HTTP/1.1 200 OK",
                                "Content-Type: text/html; charset=utf-8\r\n",
                                "<!DOCTYPE html><html><body><h1>Docs OK</h1></body></html>",
                            ),
                            "/redirect-ok" => (
                                "HTTP/1.1 302 Found",
                                "Location: /docs\r\nContent-Type: text/plain\r\n",
                                "redirecting",
                            ),
                            "/broken" => (
                                "HTTP/1.1 200 OK",
                                "Content-Type: text/html; charset=utf-8\r\n",
                                concat!(
                                    "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                                    "<style>body{margin:0;padding:8px;}",
                                    ".pill-bad{display:inline-block;width:40px;overflow:hidden;white-space:nowrap;}",
                                    "select#bad-sel{width:14px;height:12px;padding:0 12px;font-size:16px;}",
                                    "button#zero-btn{width:0;height:0;padding:0;border:0;}",
                                    "</style></head><body>",
                                    "<div style=\"width:2200px\">Wide overflow banner</div>",
                                    "<span class=\"pill-bad\">Overflowing Status Pill Label Text</span>",
                                    "<button id=\"zero-btn\" type=\"button\"></button>",
                                    "<button id=\"bad-pop\" type=\"button\" popovertarget=\"missing-popover\">Pop</button>",
                                    "<select id=\"bad-sel\"><option>Clipped Option Label</option></select>",
                                    "<a href=\"/missing-404\">Dead Link</a>",
                                    "</body></html>"
                                ),
                            ),
                            _ => (
                                "HTTP/1.1 404 Not Found",
                                "Content-Type: text/plain\r\n",
                                "not found",
                            ),
                        };
                        let resp = format!(
                            "{status_line}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for LocalTestHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct MockDualViewportDriver {
    clean: bool,
}

impl UiInspectorDriver for MockDualViewportDriver {
    fn inspect_url(
        &self,
        target_url: &str,
        _timeout_ms: u64,
    ) -> Result<Vec<UiAuditViewportRecordV1>, String> {
        let base = target_url
            .trim_end_matches("/clean")
            .trim_end_matches("/broken")
            .trim_end_matches('/');
        if self.clean {
            let links = vec![format!("{base}/docs"), format!("{base}/redirect-ok")];
            Ok(vec![
                UiAuditViewportRecordV1 {
                    path: "/clean".to_owned(),
                    viewport: "desktop-light".to_owned(),
                    color_scheme: "light".to_owned(),
                    status: 200,
                    check: json!({
                        "vw": 1440,
                        "vh": 900,
                        "scrollWidth": 1440,
                        "scrollHeight": 900,
                        "pageOverflow": false,
                        "pillOverflow": [],
                        "verticalOverflow": [],
                        "buttonsExercised": 1,
                        "selectsChecked": 1,
                        "deadButtons": [],
                        "popoverDefects": [],
                        "selectGeometryDefects": [],
                        "artifacts": [],
                        "tableBroken": []
                    }),
                    console: vec![],
                    pageerrors: vec![],
                    bad_requests: vec![],
                    broken_links: vec![],
                    discovered_links: links.clone(),
                },
                UiAuditViewportRecordV1 {
                    path: "/clean".to_owned(),
                    viewport: "desktop-dark".to_owned(),
                    color_scheme: "dark".to_owned(),
                    status: 200,
                    check: json!({
                        "vw": 1440,
                        "vh": 900,
                        "scrollWidth": 1440,
                        "scrollHeight": 900,
                        "pageOverflow": false,
                        "pillOverflow": [],
                        "verticalOverflow": [],
                        "buttonsExercised": 1,
                        "selectsChecked": 1,
                        "deadButtons": [],
                        "popoverDefects": [],
                        "selectGeometryDefects": [],
                        "artifacts": [],
                        "tableBroken": []
                    }),
                    console: vec![],
                    pageerrors: vec![],
                    bad_requests: vec![],
                    broken_links: vec![],
                    discovered_links: links.clone(),
                },
                UiAuditViewportRecordV1 {
                    path: "/clean".to_owned(),
                    viewport: "mobile".to_owned(),
                    color_scheme: "light".to_owned(),
                    status: 200,
                    check: json!({
                        "vw": 390,
                        "vh": 844,
                        "scrollWidth": 390,
                        "scrollHeight": 844,
                        "pageOverflow": false,
                        "pillOverflow": [],
                        "verticalOverflow": [],
                        "buttonsExercised": 1,
                        "selectsChecked": 1,
                        "deadButtons": [],
                        "popoverDefects": [],
                        "selectGeometryDefects": [],
                        "artifacts": [],
                        "tableBroken": []
                    }),
                    console: vec![],
                    pageerrors: vec![],
                    bad_requests: vec![],
                    broken_links: vec![],
                    discovered_links: links,
                },
            ])
        } else {
            let links = vec![format!("{base}/missing-404")];
            Ok(vec![
                UiAuditViewportRecordV1 {
                    path: "/broken".to_owned(),
                    viewport: "desktop-light".to_owned(),
                    color_scheme: "light".to_owned(),
                    status: 200,
                    check: json!({
                        "vw": 1440,
                        "vh": 900,
                        "scrollWidth": 2200,
                        "scrollHeight": 900,
                        "pageOverflow": true,
                        "pillOverflow": [{"selector": "span.pill-bad", "scrollWidth": 210, "clientWidth": 40}],
                        "verticalOverflow": [],
                        "buttonsExercised": 0,
                        "selectsChecked": 1,
                        "deadButtons": [{"selector": "button#zero-btn", "reason": "zero-or-tiny-hitbox:0x0"}],
                        "popoverDefects": [{"selector": "button#bad-pop", "reason": "missing-target:#missing-popover"}],
                        "selectGeometryDefects": [{"selector": "select#bad-sel", "reason": "undersized:14x12"}],
                        "artifacts": [],
                        "tableBroken": []
                    }),
                    console: vec![],
                    pageerrors: vec![],
                    bad_requests: vec![],
                    broken_links: vec![],
                    discovered_links: links.clone(),
                },
                UiAuditViewportRecordV1 {
                    path: "/broken".to_owned(),
                    viewport: "mobile".to_owned(),
                    color_scheme: "light".to_owned(),
                    status: 200,
                    check: json!({
                        "vw": 390,
                        "vh": 844,
                        "scrollWidth": 2200,
                        "scrollHeight": 844,
                        "pageOverflow": true,
                        "pillOverflow": [],
                        "verticalOverflow": [],
                        "buttonsExercised": 0,
                        "selectsChecked": 1,
                        "deadButtons": [],
                        "popoverDefects": [],
                        "selectGeometryDefects": [],
                        "artifacts": [],
                        "tableBroken": []
                    }),
                    console: vec![],
                    pageerrors: vec![],
                    bad_requests: vec![],
                    broken_links: vec![],
                    discovered_links: links,
                },
            ])
        }
    }
}

#[test]
fn ui_gate_driver_and_real_http_link_verifier_validate_clean_and_defective_pages() {
    let srv = LocalTestHttpServer::start();
    let dir = tempfile::tempdir().unwrap();

    // 1. Clean page: 200 + 302->200 links, 1440x900 light/dark + 390x844 mobile -> PASS!
    let clean_audit = dir.path().join("clean-audit.json");
    let (report_ok, receipt_ok) = inspect_and_gate_url(
        &MockDualViewportDriver { clean: true },
        &format!("{}/clean", srv.base_url),
        Some(&clean_audit),
        UiGateSurface::LocalApp,
        "CHWG-0251",
        "deadbeef",
        "org_test",
        5_000,
    )
    .unwrap();
    report_ok.verify_signature().unwrap();
    receipt_ok.verify_signature().unwrap();
    assert!(receipt_ok.passed, "{receipt_ok:?}");
    assert_eq!(receipt_ok.desktop_1440x900_records, 2);
    assert_eq!(receipt_ok.mobile_390x844_records, 1);
    assert_eq!(report_ok.links_verified, 2);
    assert!(report_ok.broken_links.is_empty());
    assert!(clean_audit.is_file());

    // Validate the emitted `UiAuditReportV1` file via CLI `--surface local-app --audit-json`:
    let cli_ok = chinwag_cmd()
        .args([
            "ui-gate",
            "--surface",
            "local-app",
            "--audit-json",
            clean_audit.to_str().unwrap(),
            "--ticket",
            "CHWG-0251",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(cli_ok.status.success());
    let parsed_receipt: UiGateReceiptV1 = serde_json::from_slice(&cli_ok.stdout).unwrap();
    assert!(parsed_receipt.passed);
    parsed_receipt.verify_signature().unwrap();

    // 2. Defective page: pill overflow + dead button + popover missing target + <select> inset + HTTP 404 link -> FAIL!
    let bad_audit = dir.path().join("bad-audit.json");
    let (report_bad, receipt_bad) = inspect_and_gate_url(
        &MockDualViewportDriver { clean: false },
        &format!("{}/broken", srv.base_url),
        Some(&bad_audit),
        UiGateSurface::LocalApp,
        "CHWG-0251",
        "deadbeef",
        "org_test",
        5_000,
    )
    .unwrap();
    assert!(!receipt_bad.passed);
    assert_eq!(report_bad.broken_links.len(), 1);
    assert_eq!(report_bad.broken_links[0].status, 404);
    assert!(
        receipt_bad.violations.len() >= 5,
        "{:?}",
        receipt_bad.violations
    );

    // 3. If Headless Chrome / Chromium is installed on this host, also exercise the REAL CDP WebSocket driver!
    if resolve_chromium_binary(None).is_ok() {
        let chrome_clean_out = dir.path().join("chrome-clean-audit.json");
        let chrome_ok = chinwag_cmd()
            .args([
                "ui-gate",
                "--url",
                &format!("{}/clean", srv.base_url),
                "--out",
                chrome_clean_out.to_str().unwrap(),
                "--surface",
                "local-app",
                "--ticket",
                "CHWG-0251",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            chrome_ok.status.success(),
            "real Chrome clean failed: stdout={} stderr={}",
            String::from_utf8_lossy(&chrome_ok.stdout),
            String::from_utf8_lossy(&chrome_ok.stderr)
        );
        let written_report: UiAuditReportV1 =
            serde_json::from_str(&fs::read_to_string(&chrome_clean_out).unwrap()).unwrap();
        written_report.verify_signature().unwrap();
        assert_eq!(written_report.records.len(), 3);
        assert_eq!(written_report.links_verified, 2);
        assert!(written_report.broken_links.is_empty());

        let chrome_bad_out = dir.path().join("chrome-bad-audit.json");
        let chrome_bad = chinwag_cmd()
            .args([
                "ui-gate",
                "--url",
                &format!("{}/broken", srv.base_url),
                "--out",
                chrome_bad_out.to_str().unwrap(),
                "--surface",
                "local-app",
                "--ticket",
                "CHWG-0251",
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(chrome_bad.status.code(), Some(1));
        let bad_report_disk: UiAuditReportV1 =
            serde_json::from_str(&fs::read_to_string(&chrome_bad_out).unwrap()).unwrap();
        assert_eq!(bad_report_disk.broken_links.len(), 1);
        assert_eq!(bad_report_disk.broken_links[0].status, 404);
    }
}

#[test]
fn local_app_surface_fails_closed_when_zero_desktop_or_zero_mobile_records_exist() {
    let base_tmp = fs::canonicalize(std::env::temp_dir()).unwrap();
    let dir = tempfile::tempdir_in(base_tmp).unwrap();

    let desktop_only_report = UiAuditReportV1::build_signed(
        "http://127.0.0.1:4173",
        "CHWG-0251",
        0,
        Vec::new(),
        vec![UiAuditViewportRecordV1 {
            path: "/".to_owned(),
            viewport: "desktop-light".to_owned(),
            color_scheme: "light".to_owned(),
            status: 200,
            check: json!({
                "vw": 1440,
                "vh": 900,
                "scrollWidth": 1440,
                "pageOverflow": false,
            }),
            console: Vec::new(),
            pageerrors: Vec::new(),
            bad_requests: Vec::new(),
            broken_links: Vec::new(),
            discovered_links: Vec::new(),
        }],
    )
    .unwrap();
    let desktop_only = dir.path().join("desktop-only.json");
    fs::write(
        &desktop_only,
        serde_json::to_vec_pretty(&desktop_only_report).unwrap(),
    )
    .unwrap();

    for surface in ["local-app", "all"] {
        let out1 = chinwag_cmd()
            .args([
                "ui-gate",
                "--surface",
                surface,
                "--audit-json",
                desktop_only.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(out1.status.code(), Some(1), "surface={surface}");
        let r1: UiGateReceiptV1 = serde_json::from_slice(&out1.stdout).unwrap();
        r1.verify_signature().unwrap();
        assert!(!r1.passed, "surface={surface}");
        assert!(
            r1.violations.iter().any(|v| v.detail.contains("390x844")),
            "expected missing 390x844 violation for surface={surface}: {:?}",
            r1.violations
        );
    }

    let mobile_only_report = UiAuditReportV1::build_signed(
        "http://127.0.0.1:4173",
        "CHWG-0251",
        0,
        Vec::new(),
        vec![UiAuditViewportRecordV1 {
            path: "/".to_owned(),
            viewport: "mobile".to_owned(),
            color_scheme: "light".to_owned(),
            status: 200,
            check: json!({
                "vw": 390,
                "vh": 844,
                "scrollWidth": 390,
                "pageOverflow": false,
            }),
            console: Vec::new(),
            pageerrors: Vec::new(),
            bad_requests: Vec::new(),
            broken_links: Vec::new(),
            discovered_links: Vec::new(),
        }],
    )
    .unwrap();
    let mobile_only = dir.path().join("mobile-only.json");
    fs::write(
        &mobile_only,
        serde_json::to_vec_pretty(&mobile_only_report).unwrap(),
    )
    .unwrap();

    for surface in ["local-app", "all"] {
        let out2 = chinwag_cmd()
            .args([
                "ui-gate",
                "--surface",
                surface,
                "--audit-json",
                mobile_only.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(out2.status.code(), Some(1), "surface={surface}");
        let r2: UiGateReceiptV1 = serde_json::from_slice(&out2.stdout).unwrap();
        r2.verify_signature().unwrap();
        assert!(!r2.passed, "surface={surface}");
        assert!(
            r2.violations.iter().any(|v| v.detail.contains("1440x900")),
            "expected missing 1440x900 violation for surface={surface}: {:?}",
            r2.violations
        );
    }

    // Forged unsigned UiAuditReportV1 JSON, stripped-schema JSON object, and unsigned top-level array ALL fail closed:
    for (fname, payload) in [
        (
            "forged-unsigned.json",
            r#"{"schema":"UiAuditReportV1","records":[{"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900,"scrollWidth":1440,"pageOverflow":false}},{"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844,"scrollWidth":390,"pageOverflow":false}}]}"#,
        ),
        (
            "stripped-schema.json",
            r#"{"records":[{"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900,"scrollWidth":1440,"pageOverflow":false}},{"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844,"scrollWidth":390,"pageOverflow":false}}]}"#,
        ),
        (
            "raw-array.json",
            r#"[{"path":"/","viewport":"desktop-light","status":200,"check":{"vw":1440,"vh":900,"scrollWidth":1440,"pageOverflow":false}},{"path":"/","viewport":"mobile","status":200,"check":{"vw":390,"vh":844,"scrollWidth":390,"pageOverflow":false}}]"#,
        ),
    ] {
        let forged = dir.path().join(fname);
        fs::write(&forged, payload).unwrap();
        for surface in ["local-app", "all"] {
            let forged_out = chinwag_cmd()
                .args([
                    "ui-gate",
                    "--surface",
                    surface,
                    "--audit-json",
                    forged.to_str().unwrap(),
                    "--json",
                ])
                .output()
                .unwrap();
            assert_eq!(
                forged_out.status.code(),
                Some(1),
                "fname={fname} surface={surface}"
            );
            let forged_rcpt: UiGateReceiptV1 = serde_json::from_slice(&forged_out.stdout).unwrap();
            assert!(!forged_rcpt.passed, "fname={fname} surface={surface}");
        }
    }

    // Relative `--out rel_sub/receipt.json` + `--org acme-corp` creates `./rel_sub/receipt.json` (never `rel_sub/rel_sub`):
    let rel_out = chinwag_cmd()
        .current_dir(dir.path())
        .args([
            "ui-gate",
            "--surface",
            "site",
            "--repo",
            ".",
            "--org",
            "acme-corp",
            "--out",
            "rel_sub/receipt.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        rel_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&rel_out.stderr)
    );
    assert!(dir.path().join("rel_sub/receipt.json").is_file());
    assert!(!dir.path().join("rel_sub/rel_sub").exists());
    let rel_rcpt: UiGateReceiptV1 =
        serde_json::from_str(&fs::read_to_string(dir.path().join("rel_sub/receipt.json")).unwrap())
            .unwrap();
    rel_rcpt.verify_signature().unwrap();
    assert_eq!(rel_rcpt.org_id_hash.len(), 64);
    assert!(!rel_rcpt.org_id_hash.contains("acme-corp"));

    // Symlinked --audit-json fails closed:
    let sym = dir.path().join("symlink-audit.json");
    std::os::unix::fs::symlink(&desktop_only, &sym).unwrap();
    let sym_out = chinwag_cmd()
        .args([
            "ui-gate",
            "--surface",
            "site",
            "--audit-json",
            sym.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(sym_out.status.code(), Some(1));
}
