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

pub const NOT_IMPLEMENTED: &str = "ui-gate not implemented; not gate evidence";

pub fn run_ui_gate(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
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
    1
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
}
