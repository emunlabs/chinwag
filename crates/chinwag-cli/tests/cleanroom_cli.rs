// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chinwag_cleanroom_vm::{
    ReleaseSignerAttestation, SealedFailureBundleV1, generate_recipient_kem_keypair,
    open_failure_diagnostic_bundle,
};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn cli_env_lock_and_check_enforces_pinned_signers_by_default_and_detects_drift() {
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

    let seed_file = tmp.path().join("signer-seed.hex");
    let seed_bytes = [0x37u8; 32];
    fs::write(&seed_file, hex::encode(seed_bytes)).unwrap();
    let sk = SigningKey::from_bytes(&seed_bytes);
    let pk = sk.verifying_key().to_bytes();

    // 1. `chinwag env lock --repo <tmp> --signing-seed-file <seed> --json`
    let out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--signing-seed-file",
            seed_file.to_str().unwrap(),
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

    // 2. Without `.chinwag/allowed_signers` or `--signer-pubkey-hex`, `--check` MUST fail closed!
    let unpinned_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
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
    assert!(!unpinned_out.status.success());

    // 3. Populate `.chinwag/allowed_signers` -> `--check` verifies pinned signer automatically!
    let mut ssh_wire = Vec::with_capacity(51);
    ssh_wire.extend_from_slice(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20");
    ssh_wire.extend_from_slice(&pk);
    fs::write(
        tmp.path().join(".chinwag/allowed_signers"),
        format!(
            "ci@example.invalid ssh-ed25519 {} test\n",
            BASE64_STANDARD.encode(&ssh_wire)
        ),
    )
    .unwrap();

    let check_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--check",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run chinwag env lock --check");
    assert!(check_out.status.success());
    let check_json: Value = serde_json::from_slice(&check_out.stdout).unwrap();
    assert_eq!(check_json["ok"], true);
    assert_eq!(check_json["pinned_signer_verified"], true);
    assert_eq!(check_json["closure_sha256"], lock_json["closure_sha256"]);

    // 4. Mutate `Cargo.toml` -> `--check` exits non-zero on drift
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
fn cli_env_lock_rejects_forbidden_nested_nix_files() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::create_dir_all(tmp.path().join("subdir")).unwrap();
    fs::write(tmp.path().join("subdir/default.nix"), "{}").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["env", "lock", "--repo", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("INV-NIX-ZERO-SYNTAX-01"));
}

#[test]
fn cli_runner_start_ephemeral_enforces_seatbelt_exec_release_attestation_and_failure_sealing() {
    let tmp = TempDir::new().unwrap();
    let slot_dir = tmp.path().join("slots");

    // 1. Missing `--ephemeral` fails closed with exit code 2
    let no_ephemeral = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["runner", "start", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(no_ephemeral.status.code(), Some(2));

    // 2. Valid `--ephemeral --dry-run --json` emits deterministic Tart + sandbox-exec plan
    let ok_dry = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--slot-dir",
            slot_dir.to_str().unwrap(),
            "--profile",
            "public",
            "--base-image",
            "macos-sequoia-cleanroom-v1",
            "--run-name",
            "job-pr-32",
            "--dry-run",
            "--json",
            "--",
            "cargo",
            "test",
            "--offline",
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
    assert_eq!(plan["tart_plan"]["exec_sandboxed"][0], "exec");
    assert_eq!(
        plan["tart_plan"]["exec_sandboxed"][2],
        "/usr/bin/sandbox-exec"
    );
    assert_eq!(
        plan["tart_plan"]["defer_delete"],
        serde_json::json!(["delete", "job-pr-32"])
    );

    // 3. Valid `--profile release` with customer `ReleaseRefPolicy` + `ReleaseSignerAttestation` succeeds
    let rel_sk = SigningKey::from_bytes(&[0x62u8; 32]);
    let rel_pk = rel_sk.verifying_key().to_bytes();
    let mut ssh_wire = Vec::with_capacity(51);
    ssh_wire.extend_from_slice(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20");
    ssh_wire.extend_from_slice(&rel_pk);
    let signers_path = tmp.path().join("allowed_signers");
    fs::write(
        &signers_path,
        format!(
            "rel@example.invalid ssh-ed25519 {} rel\n",
            BASE64_STANDARD.encode(&ssh_wire)
        ),
    )
    .unwrap();
    let oid = "e".repeat(40);
    let att = ReleaseSignerAttestation::sign("refs/heads/release/v1", &oid, &rel_sk);
    let att_file = tmp.path().join("attestation.json");
    fs::write(&att_file, serde_json::to_vec(&att).unwrap()).unwrap();

    let rel_dry = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--slot-dir",
            slot_dir.to_str().unwrap(),
            "--profile",
            "release",
            "--git-ref",
            "refs/heads/release/v1",
            "--commit-oid",
            &oid,
            "--allow-release-prefix",
            "refs/heads/release/",
            "--release-attestation-file",
            att_file.to_str().unwrap(),
            "--allowed-signers",
            signers_path.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        rel_dry.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rel_dry.stderr)
    );
    let rel_plan: Value = serde_json::from_slice(&rel_dry.stdout).unwrap();
    assert_eq!(rel_plan["allow_release_keys"], true);

    // 4. Failed Tart invocation automatically writes `SealedFailureBundleV1` (`X25519-MLKEM768`)
    let (recipient_sk, recipient_pk) = generate_recipient_kem_keypair().unwrap();
    let pk_file = tmp.path().join("recipient-xwing.pk");
    fs::write(&pk_file, &recipient_pk).unwrap();
    let runner_seed_file = tmp.path().join("runner.seed");
    fs::write(&runner_seed_file, hex::encode([0x84u8; 32])).unwrap();
    let expected_runner_pk = SigningKey::from_bytes(&[0x84u8; 32])
        .verifying_key()
        .to_bytes();
    let bundle_out = tmp.path().join("failure-bundle.json");

    let fail_run = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--slot-dir",
            slot_dir.to_str().unwrap(),
            "--tart-bin",
            "/usr/bin/false",
            "--seal-failure-bundle",
            bundle_out.to_str().unwrap(),
            "--diagnostic-recipient-pubkey-file",
            pk_file.to_str().unwrap(),
            "--runner-signing-seed-file",
            runner_seed_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!fail_run.status.success());
    assert!(bundle_out.is_file());
    let sealed: SealedFailureBundleV1 =
        serde_json::from_slice(&fs::read(&bundle_out).unwrap()).unwrap();
    let opened =
        open_failure_diagnostic_bundle(&sealed, &recipient_sk, &expected_runner_pk).unwrap();
    assert_eq!(opened.exit_code, 1);
}
