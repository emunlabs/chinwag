// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn cli_env_lock_and_check_roundtrip_and_drift_detection() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.1\"\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"sample-cleanroom\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();

    // 1. `chinwag env lock --repo <tmp> --json`
    let out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run chinwag env lock");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lock_json: Value = serde_json::from_slice(&out.stdout).expect("valid lock JSON");
    assert_eq!(lock_json["ok"], true);
    assert_eq!(lock_json["zero_nix_syntax"], true);
    let signer_hex = lock_json["signer_public_key_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(tmp.path().join(".chinwag/flake.lock").is_file());
    assert!(tmp.path().join(".chinwag/env-lock.receipt.json").is_file());

    // 2. `chinwag env lock --check --repo <tmp> --signer-pubkey-hex <hex> --json`
    let check_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--check",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--signer-pubkey-hex",
            &signer_hex,
            "--json",
        ])
        .output()
        .expect("run chinwag env lock --check");
    assert!(check_out.status.success());
    let check_json: Value = serde_json::from_slice(&check_out.stdout).unwrap();
    assert_eq!(check_json["ok"], true);
    assert_eq!(check_json["closure_sha256"], lock_json["closure_sha256"]);

    // 3. Mutate `Cargo.toml` -> `--check` exits non-zero on drift
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"sample-cleanroom\"\nversion = \"0.2.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    let drift_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--check",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!drift_out.status.success());
    let drift_json: Value = serde_json::from_slice(&drift_out.stdout).unwrap();
    assert_eq!(drift_json["ok"], false);
}

#[test]
fn cli_env_lock_rejects_forbidden_nix_files() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(tmp.path().join("default.nix"), "{}").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["env", "lock", "--repo", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("INV-NIX-ZERO-SYNTAX-01"));
}

#[test]
fn cli_runner_start_ephemeral_enforces_flags_trust_split_and_pool_admission() {
    let tmp = TempDir::new().unwrap();

    // 1. Missing `--ephemeral` fails closed with exit code 2
    let no_ephemeral = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["runner", "start", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(no_ephemeral.status.code(), Some(2));

    // 2. Valid `--ephemeral --dry-run --json` emits deterministic Tart + Seatbelt plan
    let ok_dry = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--profile",
            "public",
            "--base-image",
            "macos-sequoia-cleanroom-v1",
            "--run-name",
            "job-pr-32",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        ok_dry.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&ok_dry.stderr)
    );
    let plan: Value = serde_json::from_slice(&ok_dry.stdout).unwrap();
    assert_eq!(plan["ok"], true);
    assert_eq!(plan["profile"], "chinwag-ephemeral-public");
    assert_eq!(plan["allow_release_keys"], false);
    assert_eq!(
        plan["tart_plan"]["run"],
        serde_json::json!([
            "run",
            "--no-graphics",
            "--dir=nix-store:/nix/store:ro",
            "--dir=sccache:/var/tmp/chinwag-sccache:ro",
            "job-pr-32"
        ])
    );
    assert_eq!(
        plan["tart_plan"]["defer_delete"],
        serde_json::json!(["delete", "job-pr-32"])
    );

    // 3. Untrusted fork PR requesting `--profile release` fails closed
    let fork_release = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--profile",
            "release",
            "--fork-pr",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!fork_release.status.success());
    let refused: Value = serde_json::from_slice(&fork_release.stdout).unwrap();
    assert_eq!(refused["ok"], false);
    assert_eq!(refused["stage"], "trust_gate");

    // 4. Opportunistic laptop on battery power (`--ac-power false`) fails pool admission
    let battery_opp = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--opportunistic",
            "--ac-power",
            "false",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!battery_opp.status.success());
    let deferred: Value = serde_json::from_slice(&battery_opp.stdout).unwrap();
    assert_eq!(deferred["ok"], false);
    assert_eq!(deferred["stage"], "pool_admission");
    assert_eq!(
        deferred["admission"]["reason"],
        "opportunistic_requires_ac_wall_power"
    );
}
