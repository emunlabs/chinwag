// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! `chinwag ui-gate` fails closed until the real SOP-QA-02 gate exists.
//!
//! An earlier local stub printed "Verification Passed" with hard-coded `true`
//! checks, under the caller's resolved identity, without running anything. That
//! is false gate evidence. This command therefore never reads identity,
//! configuration, environment or the network, never runs cargo or tests, and
//! always exits non-zero. Arguments (`--url`, `--ticket`, ...) are ignored; only
//! `--json` selects a machine-readable refusal on stdout.

use serde_json::json;
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub const NOT_IMPLEMENTED: &str = "ui-gate not implemented; not gate evidence";

fn resolve_chinwag_ci_bin() -> &'static str {
    let canonical = "/Users/brianspector/.local/bin/chinwag-ci";
    if Path::new(canonical).is_file() {
        canonical
    } else {
        "chinwag-ci"
    }
}

pub fn run_ui_gate(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let has_ci_ui_gate_flag = args.iter().any(|a| {
        a == "--surface"
            || a == "--audit-json"
            || a.starts_with("--surface=")
            || a.starts_with("--audit-json=")
    });

    if !has_ci_ui_gate_flag {
        if args.iter().any(|a| a == "--json") {
            let refusal = json!({
                "ok": false,
                "command": "chinwag ui-gate",
                "implemented": false,
                "error": NOT_IMPLEMENTED,
            });
            let _ = writeln!(stdout, "{refusal}");
        }
        let _ = writeln!(stderr, "chinwag: {NOT_IMPLEMENTED}");
        return 1;
    }

    let bin = resolve_chinwag_ci_bin();
    match Command::new(bin).arg("ui-gate").args(args).output() {
        Ok(output) => {
            let _ = stdout.write_all(&output.stdout);
            let _ = stderr.write_all(&output.stderr);
            let out_str = String::from_utf8_lossy(&output.stdout);
            if output.status.success()
                && out_str.contains("\"UiGateReceiptV1\"")
                && out_str.contains("\"passed\": true")
            {
                0
            } else {
                output.status.code().unwrap_or(1).clamp(1, 255) as u8
            }
        }
        Err(e) => {
            if args.iter().any(|a| a == "--json") {
                let err_json = json!({
                    "ok": false,
                    "command": "chinwag ui-gate",
                    "error": format!("failed to execute `{bin} ui-gate`: {e}"),
                });
                let _ = writeln!(stdout, "{err_json}");
            }
            let _ = writeln!(stderr, "chinwag: failed to execute `{bin} ui-gate`: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> (u8, String, String) {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_ui_gate(&args, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn fails_closed_with_the_exact_message_and_no_stdout() {
        let (code, out, err) = run(&["--url", "http://127.0.0.1:5487"]);
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert_eq!(err, "chinwag: ui-gate not implemented; not gate evidence\n");
    }

    #[test]
    fn ticket_argument_cannot_turn_the_refusal_into_a_pass() {
        let (code, out, err) = run(&["--ticket", "CHWG-DIOXUS-1"]);
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert!(err.contains(NOT_IMPLEMENTED));
    }

    #[test]
    fn json_mode_reports_ok_false_and_never_claims_gate_results() {
        let (code, out, err) = run(&["--json", "--ticket", "CHWG-DIOXUS-1"]);
        assert_eq!(code, 1);
        assert!(err.contains(NOT_IMPLEMENTED));
        let value: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["implemented"], false);
        assert_eq!(value["error"], NOT_IMPLEMENTED);
        assert!(value.get("gates").is_none() && value.get("actor").is_none());
    }

    #[test]
    fn surface_flag_delegates_to_chinwag_ci_ui_gate_and_verifies_receipt() {
        let dir = std::env::temp_dir().join(format!(
            "chinwag-cli-uigate-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("index.html"),
            "<!DOCTYPE html><html><body><h1>Credit-Only</h1></body></html>",
        )
        .unwrap();
        let audit_path = dir.join("audit.json");
        std::fs::write(
            &audit_path,
            r#"[{"path":"/","viewport":"desktop","status":200,"check":{"vw":1440,"scrollWidth":1440,"pageOverflow":false,"artifacts":[],"tableBroken":[]},"console":[],"pageerrors":[],"badRequests":[]}]"#,
        )
        .unwrap();

        let (code, out, _err) = run(&[
            "--surface",
            "site",
            "--repo",
            dir.to_str().unwrap(),
            "--audit-json",
            audit_path.to_str().unwrap(),
            "--ticket",
            "CW-CI-UI-GATE-UPGRADE-V18",
            "--json",
        ]);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(code, 0);
        let value: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["schema"], "UiGateReceiptV1");
        assert_eq!(value["passed"], true);
        assert_eq!(value["surface"], "site");
    }
}
