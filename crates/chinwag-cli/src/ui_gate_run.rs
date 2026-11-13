// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! `chinwag ui-gate` refuses unsupported legacy requests and delegates explicit surface gates.
//!
//! Delegation requires both a successful child exit and a structured passing
//! `UiGateReceiptV1`. Unit driver fixtures test this process boundary; they do
//! not provide evidence that an actual UI gate ran.

use serde_json::json;
use std::ffi::OsStr;
use std::io::Write;
use std::process::Command;

pub const NOT_IMPLEMENTED: &str = "ui-gate not implemented; not gate evidence";

fn resolve_chinwag_ci_bin() -> String {
    std::env::var("CHINWAG_CI_BIN")
        .ok()
        .filter(|binary| !binary.trim().is_empty())
        .unwrap_or_else(|| "chinwag-ci".to_owned())
}

pub fn run_ui_gate(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    run_ui_gate_with_binary(args, None, stdout, stderr)
}

fn run_ui_gate_with_binary(
    args: &[String],
    binary: Option<&OsStr>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
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

    let bin = binary
        .map(OsStr::to_os_string)
        .unwrap_or_else(|| resolve_chinwag_ci_bin().into());
    let display_bin = bin.to_string_lossy();
    match Command::new(&bin).arg("ui-gate").args(args).output() {
        Ok(output) => {
            let _ = stdout.write_all(&output.stdout);
            let _ = stderr.write_all(&output.stderr);
            let valid_receipt = serde_json::from_slice::<serde_json::Value>(&output.stdout)
                .is_ok_and(|receipt| {
                    receipt["schema"] == "UiGateReceiptV1"
                        && receipt["ok"] == true
                        && receipt["passed"] == true
                });
            if output.status.success() && valid_receipt {
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
                    "error": format!("failed to execute `{display_bin} ui-gate`: {e}"),
                });
                let _ = writeln!(stdout, "{err_json}");
            }
            let _ = writeln!(
                stderr,
                "chinwag: failed to execute `{display_bin} ui-gate`: {e}"
            );
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

    fn fixture_driver(
        directory: &tempfile::TempDir,
        receipt: &str,
        exit_code: u8,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let binary = directory.path().join("unit-delegation-driver");
        // This fixed receipt is solely a unit fixture for delegation and argv forwarding.
        // It deliberately does not run a UI audit or claim actual gate evidence.
        std::fs::write(&binary, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\nprintf '%s\\n' '{receipt}'\nexit {exit_code}\n")).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        binary
    }

    #[test]
    fn surface_flag_delegates_exact_argv_and_validates_unit_receipt_contract() {
        let directory = tempfile::TempDir::new().unwrap();
        let binary = fixture_driver(
            &directory,
            r#"{"ok":true,"schema":"UiGateReceiptV1","passed":true,"surface":"site","fixture":"unit-delegation-contract"}"#,
            0,
        );
        let args = vec![
            "--surface".into(),
            "site".into(),
            "--repo".into(),
            directory.path().display().to_string(),
            "--audit-json".into(),
            directory.path().join("audit.json").display().to_string(),
            "--ticket".into(),
            "fixture-ticket".into(),
            "--json".into(),
        ];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run_ui_gate_with_binary(&args, Some(binary.as_os_str()), &mut out, &mut err),
            0
        );
        assert!(err.is_empty());
        let actual = std::fs::read_to_string(binary.with_extension("argv")).unwrap();
        let expected = std::iter::once("ui-gate")
            .chain(args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(actual, expected);
        let receipt: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(receipt["fixture"], "unit-delegation-contract");
    }

    #[test]
    fn nonzero_child_cannot_be_authorized_by_a_passing_receipt_fixture() {
        let directory = tempfile::TempDir::new().unwrap();
        let binary = fixture_driver(
            &directory,
            r#"{"ok":true,"schema":"UiGateReceiptV1","passed":true,"fixture":"unit-delegation-contract"}"#,
            9,
        );
        let args = vec!["--surface".into(), "site".into(), "--json".into()];
        assert_eq!(
            run_ui_gate_with_binary(
                &args,
                Some(binary.as_os_str()),
                &mut Vec::new(),
                &mut Vec::new()
            ),
            9
        );
    }

    #[test]
    fn successful_child_requires_the_exact_receipt_schema() {
        let directory = tempfile::TempDir::new().unwrap();
        let binary = fixture_driver(
            &directory,
            r#"{"ok":true,"schema":"unrelated","passed":true,"note":"UiGateReceiptV1"}"#,
            0,
        );
        let args = vec!["--surface".into(), "site".into(), "--json".into()];
        assert_eq!(
            run_ui_gate_with_binary(
                &args,
                Some(binary.as_os_str()),
                &mut Vec::new(),
                &mut Vec::new()
            ),
            1
        );
    }
}
