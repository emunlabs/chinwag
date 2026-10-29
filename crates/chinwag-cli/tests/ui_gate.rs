// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! The real `chinwag ui-gate` binary must fail closed: no pass text, no
//! identity, and a non-zero exit, even with the ticket the gate was asked for.
use std::process::Command;

fn ui_gate(args: &[&str]) -> std::process::Output {
    // Empty environment: nothing may depend on, or leak, the caller's identity.
    Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .arg("ui-gate")
        .args(args)
        .env_clear()
        .output()
        .unwrap()
}

#[test]
fn ui_gate_exits_non_zero_without_claiming_a_pass() {
    for args in [
        &[][..],
        &["--url", "http://127.0.0.1:5487"][..],
        &["--ticket", "CHWG-DIOXUS-1"][..],
        &["--ticket", "CHWG-DIOXUS-1", "--json"][..],
    ] {
        let out = ui_gate(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stdout = String::from_utf8(out.stdout).unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            stderr.contains("ui-gate not implemented; not gate evidence"),
            "{stderr}"
        );
        for text in ["Passed", "✅", "● Brian", "actor", "\"ok\":true", "true"] {
            assert!(!stdout.contains(text), "{args:?}: {stdout}");
        }
    }
}
