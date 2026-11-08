// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#[test]
fn refused_runner_reports_fixed_phase_without_echoing_untrusted_configuration() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("PRIVATE_TOKEN_NONCE_SENTINEL.json");
    std::fs::write(&p, b"{PRIVATE_TOKEN_NONCE_SENTINEL").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chinwag-ci"))
        .arg("runner")
        .arg(&p)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("CI_RUNNER_PHASE phase=CONFIGURATION elapsed_ms="));
    assert!(stderr.contains("CI_RUNNER_HELD phase=CONFIGURATION elapsed_ms="));
    assert!(!stderr.contains("SENTINEL"));
    assert!(!stderr.contains(d.path().to_str().unwrap()));
}
