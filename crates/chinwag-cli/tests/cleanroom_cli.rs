// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use chinwag_cleanroom_vm::{
    ReleaseSignerAttestation, SealedFailureBundleV1, StoreClosureEntry,
    format_openssh_allowed_signer_line, generate_recipient_kem_keypair,
    open_failure_diagnostic_bundle,
};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn cli_env_lock_and_check_enforces_pinned_signers_store_closures_and_detects_drift() {
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

    // 0. Without resolved `.chinwag/store-closures.json`, `chinwag env lock` MUST fail closed!
    let missing_closures = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--signing-seed-file",
            seed_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!missing_closures.status.success());

    fs::create_dir_all(tmp.path().join(".chinwag")).unwrap();
    let mut closures = BTreeMap::new();
    closures.insert(
        "rust-toolchain".to_owned(),
        StoreClosureEntry {
            store_path: "/nix/store/00000000000000000000000000000000-rust-1.97.1".to_owned(),
            nar_sha256_hex: Some(hex::encode([0x42u8; 32])),
            artifact_file: None,
        },
    );
    fs::write(
        tmp.path().join(".chinwag/store-closures.json"),
        serde_json::to_vec_pretty(&closures).unwrap(),
    )
    .unwrap();

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
    fs::write(
        tmp.path().join(".chinwag/allowed_signers"),
        format_openssh_allowed_signer_line("ci@example.invalid", &pk, "test"),
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
    let signers_path = tmp.path().join("allowed_signers");
    fs::write(
        &signers_path,
        format_openssh_allowed_signer_line("rel@example.invalid", &rel_pk, "rel"),
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

    // 5. Concurrent background `tart run` (`sleep 30`) + live `tart exec` + teardown-only `delete` failure:
    //    proves `spawn_tart_run` does NOT block `tart exec` AND teardown-only failure seals `SealedFailureBundleV1`!
    let mock_tart = tmp.path().join("mock-tart.sh");
    let trace_file = tmp.path().join("tart-trace.log");
    fs::write(
        &mock_tart,
        format!(
            "#!/bin/sh\necho \"$1\" >> \"{}\"\ncase \"$1\" in\n  clone|set|exec|stop) exit 0 ;;\n  run) exec /bin/sleep 30 ;;\n  delete) echo 'simulated delete failure' >&2; exit 1 ;;\n  *) exit 1 ;;\nesac\n",
            trace_file.display()
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&mock_tart).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&mock_tart, perms).unwrap();

    let teardown_bundle = tmp.path().join("teardown-failure-bundle.json");
    let teardown_fail = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            tmp.path().to_str().unwrap(),
            "--slot-dir",
            slot_dir.to_str().unwrap(),
            "--tart-bin",
            mock_tart.to_str().unwrap(),
            "--seal-failure-bundle",
            teardown_bundle.to_str().unwrap(),
            "--diagnostic-recipient-pubkey-file",
            pk_file.to_str().unwrap(),
            "--runner-signing-seed-file",
            runner_seed_file.to_str().unwrap(),
            "--json",
            "--",
            "cargo",
            "test",
            "--offline",
        ])
        .output()
        .unwrap();
    assert!(!teardown_fail.status.success());
    let td_json: Value = serde_json::from_slice(&teardown_fail.stdout).unwrap();
    assert_eq!(td_json["ok"], false);
    assert_eq!(td_json["cleanup_ok"], false);
    assert!(teardown_bundle.is_file());
    let td_sealed: SealedFailureBundleV1 =
        serde_json::from_slice(&fs::read(&teardown_bundle).unwrap()).unwrap();
    let td_opened =
        open_failure_diagnostic_bundle(&td_sealed, &recipient_sk, &expected_runner_pk).unwrap();
    assert!(td_opened.stderr_tail.contains("teardown failed"));

    let trace = fs::read_to_string(&trace_file).unwrap();
    let trace_lines: Vec<&str> = trace.lines().collect();
    assert_eq!(trace_lines.len(), 7);
    assert_eq!(&trace_lines[..2], &["clone", "set"]);
    // `run` is spawned asynchronously in the background, so its shell append may land just
    // before or alongside the concurrent `wait-ready` (`exec`) probe.
    assert!(trace_lines[2..5].contains(&"run"));
    assert_eq!(
        trace_lines[2..5].iter().filter(|&&s| s == "exec").count(),
        2
    );
    assert_eq!(&trace_lines[5..], &["stop", "delete"]);
}
