// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0
//! `chinwag ui-gate` must fail closed when invoked without reachable gate targets:
//! no pass text, no caller identity leak, and exit code 1.
use std::net::TcpListener;
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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);
    let unreachable_url = format!("http://127.0.0.1:{closed_port}");

    for args in [
        vec![],
        vec!["--url", unreachable_url.as_str()],
        vec!["--ticket", "CHWG-0251"],
        vec!["--ticket", "CHWG-0251", "--json"],
    ] {
        let out = ui_gate(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stdout = String::from_utf8(out.stdout).unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            stderr.contains("chinwag:")
                && (stderr.contains("not gate evidence") || stderr.contains("unreachable")),
            "{stderr}"
        );
        for text in ["Passed", "✅", "● Brian", "actor", "\"ok\":true", "true"] {
            assert!(!stdout.contains(text), "{args:?}: {stdout}");
        }
    }
}
