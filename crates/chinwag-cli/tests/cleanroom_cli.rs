// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use chinwag_cleanroom_vm::{
    GUEST_NIX_STORE_MOUNT, GUEST_SCCACHE_MOUNT, GUEST_WORKTREE_MOUNT, ReleaseSignerAttestation,
    SealedFailureBundleV1, StoreClosureEntry, format_openssh_allowed_signer_line,
    generate_recipient_kem_keypair, open_failure_diagnostic_bundle,
};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn init_signed_cleanroom_worktree(repo: &Path, signer_seed: [u8; 32]) -> [u8; 32] {
    fs::write(
        repo.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.1\"\n",
    )
    .unwrap();
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"sample-cleanroom\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    fs::create_dir_all(repo.join(".chinwag")).unwrap();
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
        repo.join(".chinwag/store-closures.json"),
        serde_json::to_vec_pretty(&closures).unwrap(),
    )
    .unwrap();

    let sk = SigningKey::from_bytes(&signer_seed);
    let pk = sk.verifying_key().to_bytes();
    fs::write(
        repo.join(".chinwag/allowed_signers"),
        format_openssh_allowed_signer_line("ci@example.invalid", &pk, "cleanroom-lock"),
    )
    .unwrap();

    // Write seed OUTSIDE `repo` so `repo` stays clean, then run `chinwag env lock`
    let seed_tmp = TempDir::new().unwrap();
    let seed_file = seed_tmp.path().join("lock.seed");
    fs::write(&seed_file, hex::encode(signer_seed)).unwrap();

    let lock_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--repo",
            repo.to_str().unwrap(),
            "--signing-seed-file",
            seed_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        lock_out.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&lock_out.stderr)
    );
    pk
}

#[test]
fn cli_env_lock_and_check_enforces_explicit_key_pinned_signers_store_closures_and_detects_drift() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    fs::write(
        repo.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.1\"\n",
    )
    .unwrap();
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"sample-cleanroom\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();

    let seed_file = tmp.path().join("signer-seed.hex");
    let seed_bytes = [0x37u8; 32];
    fs::write(&seed_file, hex::encode(seed_bytes)).unwrap();
    let sk = SigningKey::from_bytes(&seed_bytes);
    let pk = sk.verifying_key().to_bytes();

    // 0A. `chinwag env lock` WITHOUT `--signing-seed-file` or `--ephemeral-key` MUST fail closed (`[F-08]`, exit 2)!
    let missing_key_flag = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["env", "lock", "--repo", repo.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(missing_key_flag.status.code(), Some(2));

    // 0B. Without resolved `.chinwag/store-closures.json`, `chinwag env lock` MUST fail closed!
    let missing_closures = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--repo",
            repo.to_str().unwrap(),
            "--signing-seed-file",
            seed_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!missing_closures.status.success());

    fs::create_dir_all(repo.join(".chinwag")).unwrap();
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
        repo.join(".chinwag/store-closures.json"),
        serde_json::to_vec_pretty(&closures).unwrap(),
    )
    .unwrap();

    // 1. `chinwag env lock --repo <repo> --signing-seed-file <seed> --json`
    let out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--repo",
            repo.to_str().unwrap(),
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
            repo.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!unpinned_out.status.success());

    // 3. Populate `.chinwag/allowed_signers` -> `--check` verifies pinned signer automatically!
    fs::write(
        repo.join(".chinwag/allowed_signers"),
        format_openssh_allowed_signer_line("ci@example.invalid", &pk, "test"),
    )
    .unwrap();

    let check_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--check",
            "--repo",
            repo.to_str().unwrap(),
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
        repo.join("Cargo.toml"),
        "[package]\nname = \"sample-cleanroom\"\nversion = \"0.2.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    let drift_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "env",
            "lock",
            "--check",
            "--repo",
            repo.to_str().unwrap(),
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
        .args([
            "env",
            "lock",
            "--ephemeral-key",
            "--repo",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("INV-NIX-ZERO-SYNTAX-01"));
}

#[test]
fn cli_runner_start_ephemeral_enforces_lockfile_gate_guest_seatbelt_env_i_and_0600_scrubbed_bundles()
 {
    let tmp = TempDir::new().unwrap();
    let unverified_repo = tmp.path().join("unverified-repo");
    fs::create_dir_all(&unverified_repo).unwrap();
    let repo = tmp.path().join("verified-repo");
    fs::create_dir_all(&repo).unwrap();
    let mock_nix = tmp.path().join("nix-store");
    let mock_sccache = tmp.path().join("sccache");
    fs::create_dir_all(&mock_nix).unwrap();
    fs::create_dir_all(&mock_sccache).unwrap();
    let slot_dir = tmp.path().join("slots");
    fs::create_dir_all(&slot_dir).unwrap();
    fs::set_permissions(&slot_dir, fs::Permissions::from_mode(0o700)).unwrap();

    // 1. Missing `--ephemeral` fails closed with exit code 2
    let no_ephemeral = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args(["runner", "start", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(no_ephemeral.status.code(), Some(2));

    // 2. Unverified repository WITHOUT `.chinwag/flake.lock` + `.chinwag/allowed_signers` MUST be refused before VM boot (`[F-08]`)!
    let unlocked_refused = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            unverified_repo.to_str().unwrap(),
            "--slot-dir",
            slot_dir.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!unlocked_refused.status.success());
    let unlocked_json: Value = serde_json::from_slice(&unlocked_refused.stdout).unwrap();
    assert_eq!(unlocked_json["ok"], false);
    assert_eq!(unlocked_json["stage"], "env_lock_gate");

    // Lock `repo` with pinned Ed25519 key (`[F-08]`)
    let lock_pk = init_signed_cleanroom_worktree(&repo, [0x62u8; 32]);

    // 3. Valid `--ephemeral --dry-run --json` emits hardened Tart + guest VirtioFS Seatbelt + `/usr/bin/env -i` plan
    let ok_dry = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .env(
            "GITHUB_TOKEN",
            concat!("gh", "p_must_not_enter_guest_1234567890"),
        )
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            repo.to_str().unwrap(),
            "--nix-store",
            mock_nix.to_str().unwrap(),
            "--sccache",
            mock_sccache.to_str().unwrap(),
            "--slot-dir",
            slot_dir.to_str().unwrap(),
            "--profile",
            "public",
            "--base-image",
            "macos-sequoia-cleanroom-v1",
            "--run-name",
            "job-pr-32",
            "--egress-cidr",
            "1.1.1.1/32",
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

    // `[F-04]`: `tart run` includes `--no-clipboard`, `--no-audio`, `--net-softnet`, `--net-softnet-allow=1.1.1.1/32`, and `:ro` worktree mount
    let run_args: Vec<String> = serde_json::from_value(plan["tart_plan"]["run"].clone()).unwrap();
    assert!(run_args.contains(&"--no-clipboard".to_owned()));
    assert!(run_args.contains(&"--no-audio".to_owned()));
    assert!(run_args.contains(&"--net-softnet".to_owned()));
    assert!(run_args.contains(&"--net-softnet-allow=1.1.1.1/32".to_owned()));
    assert!(
        run_args
            .iter()
            .any(|a| a.starts_with("--dir=worktree:") && a.ends_with(":ro"))
    );

    // `[F-03]` & `[F-09]`: `exec_sandboxed` uses guest VirtioFS paths (no host worktree path in SBPL!) and `/usr/bin/env -i`
    let exec_args: Vec<String> =
        serde_json::from_value(plan["tart_plan"]["exec_sandboxed"].clone()).unwrap();
    assert_eq!(exec_args[0], "exec");
    assert_eq!(exec_args[1], "job-pr-32");
    assert_eq!(exec_args[2], "--");
    assert_eq!(exec_args[3], "/usr/bin/sandbox-exec");
    assert_eq!(exec_args[4], "-p");
    let sbpl_arg = &exec_args[5];
    assert!(sbpl_arg.contains(GUEST_NIX_STORE_MOUNT));
    assert!(sbpl_arg.contains(GUEST_SCCACHE_MOUNT));
    assert!(sbpl_arg.contains(GUEST_WORKTREE_MOUNT));
    assert!(
        !sbpl_arg.contains(repo.to_str().unwrap()),
        "host worktree path must NOT leak into guest SBPL argv"
    );
    assert_eq!(exec_args[6], "--");
    assert_eq!(exec_args[7], "/usr/bin/env");
    assert_eq!(exec_args[8], "-i");
    assert!(
        !exec_args.iter().any(|a| a.contains("GITHUB_TOKEN")),
        "host GITHUB_TOKEN must be stripped from guest `/usr/bin/env -i`"
    );
    assert_eq!(
        plan["tart_plan"]["defer_delete"],
        serde_json::json!(["delete", "job-pr-32"])
    );

    // 4. Valid `--profile release` with customer `ReleaseRefPolicy` + `ReleaseSignerAttestation` succeeds
    let rel_sk = SigningKey::from_bytes(&[0x62u8; 32]);
    assert_eq!(rel_sk.verifying_key().to_bytes(), lock_pk);
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
            repo.to_str().unwrap(),
            "--nix-store",
            mock_nix.to_str().unwrap(),
            "--sccache",
            mock_sccache.to_str().unwrap(),
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

    // 5. Failed Tart invocation scrubs secrets BEFORE JSON/stderr emission AND atomically writes `0600` `SealedFailureBundleV1` (`[F-09]`)
    let (recipient_sk, recipient_pk) = generate_recipient_kem_keypair().unwrap();
    let pk_file = tmp.path().join("recipient-xwing.pk");
    fs::write(&pk_file, &recipient_pk).unwrap();
    let runner_seed_file = tmp.path().join("runner.seed");
    fs::write(&runner_seed_file, hex::encode([0x84u8; 32])).unwrap();
    let expected_runner_pk = SigningKey::from_bytes(&[0x84u8; 32])
        .verifying_key()
        .to_bytes();
    let bundle_out = tmp.path().join("failure-bundle.json");

    let leaking_tart = tmp.path().join("leaking-tart.sh");
    fs::write(
        &leaking_tart,
        concat!(
            "#!/bin/sh\necho 'Authorization: Bearer live_leak_tok_999 {\"k\":\"",
            "sk-",
            "proj-1234567890abcdefghij\"}' >&2\nexit 1\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&leaking_tart, fs::Permissions::from_mode(0o755)).unwrap();

    let fail_run = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            repo.to_str().unwrap(),
            "--nix-store",
            mock_nix.to_str().unwrap(),
            "--sccache",
            mock_sccache.to_str().unwrap(),
            "--slot-dir",
            slot_dir.to_str().unwrap(),
            "--tart-bin",
            leaking_tart.to_str().unwrap(),
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
    let fail_stdout_str = String::from_utf8_lossy(&fail_run.stdout);
    assert!(!fail_stdout_str.contains("live_leak_tok_999"));
    assert!(!fail_stdout_str.contains(concat!("sk-", "proj-1234567890")));
    assert!(bundle_out.is_file());
    let bundle_mode = fs::symlink_metadata(&bundle_out)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(bundle_mode, 0o600);
    let sealed: SealedFailureBundleV1 =
        serde_json::from_slice(&fs::read(&bundle_out).unwrap()).unwrap();
    let opened =
        open_failure_diagnostic_bundle(&sealed, &recipient_sk, &expected_runner_pk).unwrap();
    assert_eq!(opened.exit_code, 1);
    assert!(!opened.stderr_tail.contains("live_leak_tok_999"));
    assert!(
        !opened
            .stderr_tail
            .contains(concat!("sk-", "proj-1234567890"))
    );

    // 6. Concurrent background `tart run` (`sleep 30`) + live `tart exec` + teardown-only `delete` failure
    let mock_tart = tmp.path().join("mock-tart.sh");
    let trace_file = tmp.path().join("tart-trace.log");
    fs::write(
        &mock_tart,
        format!(
            "#!/bin/sh\necho \"$1\" >> \"{}\"\ncase \"$1\" in\n  clone|set|exec|stop) exit 0 ;;\n  run) exec /bin/sleep 30 ;;\n  delete) echo 'simulated delete failure {}' >&2; exit 1 ;;\n  *) exit 1 ;;\nesac\n",
            trace_file.display(),
            concat!("chwg_", "live_1234567890abcdef")
        ),
    )
    .unwrap();
    fs::set_permissions(&mock_tart, fs::Permissions::from_mode(0o755)).unwrap();

    let teardown_bundle = tmp.path().join("teardown-failure-bundle.json");
    let teardown_fail = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            repo.to_str().unwrap(),
            "--nix-store",
            mock_nix.to_str().unwrap(),
            "--sccache",
            mock_sccache.to_str().unwrap(),
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
    assert!(
        !td_json["error"]
            .as_str()
            .unwrap()
            .contains(concat!("chwg_", "live_123456"))
    );
    assert!(teardown_bundle.is_file());
    let td_sealed: SealedFailureBundleV1 =
        serde_json::from_slice(&fs::read(&teardown_bundle).unwrap()).unwrap();
    let td_opened =
        open_failure_diagnostic_bundle(&td_sealed, &recipient_sk, &expected_runner_pk).unwrap();
    assert!(td_opened.stderr_tail.contains("teardown failed"));
    assert!(
        !td_opened
            .stderr_tail
            .contains(concat!("chwg_", "live_123456"))
    );

    let trace = fs::read_to_string(&trace_file).unwrap();
    let trace_lines: Vec<&str> = trace.lines().collect();
    assert_eq!(trace_lines.len(), 7);
    assert_eq!(&trace_lines[..2], &["clone", "set"]);
    assert!(trace_lines[2..5].contains(&"run"));
    assert_eq!(
        trace_lines[2..5].iter().filter(|&&s| s == "exec").count(),
        2
    );
    assert_eq!(&trace_lines[5..], &["stop", "delete"]);
}

#[test]
fn cli_runner_policy_toml_offline_and_opportunistic_controls() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("policy-repo");
    fs::create_dir_all(&repo).unwrap();
    let mock_nix = tmp.path().join("nix-store");
    let mock_sccache = tmp.path().join("sccache");
    let slot_dir = tmp.path().join("slots-0700");
    fs::create_dir_all(&mock_nix).unwrap();
    fs::create_dir_all(&mock_sccache).unwrap();
    fs::create_dir_all(&slot_dir).unwrap();
    fs::set_permissions(&slot_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let _pk = init_signed_cleanroom_worktree(&repo, [0x91u8; 32]);
    fs::write(
        repo.join(".chinwag/cleanroom-policy.toml"),
        format!(
            "base_image = \"customer-sequoia-cleanroom-v3\"\nnix_store_path = \"{}\"\nsccache_dir = \"{}\"\nnix_daemon_socket_dir = \"/nix/var/nix/org-daemon\"\nnix_daemon_socket_path = \"/nix/var/nix/org-daemon/socket\"\nguest_scratch_root = \"/private/var/tmp\"\nslot_dir = \"{}\"\nrelease_lease_env_keys = [\"CUSTOMER_SIGN_LEASE\"]\nallowed_egress_cidrs = [\"198.51.100.0/24\"]\n",
            mock_nix.display(),
            mock_sccache.display(),
            slot_dir.display()
        ),
    )
    .unwrap();

    // 1. `--offline` overrides policy CIDRs to `--net-softnet-allow=127.0.0.1/32` and emits custom daemon socket denies
    let offline_out = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            repo.to_str().unwrap(),
            "--run-name",
            "policy-vm-1",
            "--offline",
            "--opportunistic",
            "--ac-power",
            "true",
            "--thermal",
            "nominal",
            "--cpu-idle",
            "85",
            "--user-hid-active",
            "false",
            "--active-vms",
            "0",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        offline_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&offline_out.stderr)
    );
    let plan: Value = serde_json::from_slice(&offline_out.stdout).unwrap();
    assert_eq!(
        plan["tart_plan"]["clone"],
        serde_json::json!(["clone", "customer-sequoia-cleanroom-v3", "policy-vm-1"])
    );
    let run_args: Vec<String> = serde_json::from_value(plan["tart_plan"]["run"].clone()).unwrap();
    assert!(run_args.contains(&"--net-softnet-allow=127.0.0.1/32".to_owned()));
    let exec_args: Vec<String> =
        serde_json::from_value(plan["tart_plan"]["exec_sandboxed"].clone()).unwrap();
    assert!(exec_args[5].contains("/nix/var/nix/org-daemon"));
    assert!(exec_args[5].contains("/private/var/tmp/policy-vm-1-worktree"));
    assert!(!exec_args[5].contains("(allow network-outbound"));

    // 2. `--opportunistic` with `--ac-power false` defers admission immediately
    let battery_refused = Command::new(env!("CARGO_BIN_EXE_chinwag"))
        .args([
            "runner",
            "start",
            "--ephemeral",
            "--repo",
            repo.to_str().unwrap(),
            "--opportunistic",
            "--ac-power",
            "false",
            "--thermal",
            "nominal",
            "--cpu-idle",
            "90",
            "--user-hid-active",
            "false",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!battery_refused.status.success());
    let bat_json: Value = serde_json::from_slice(&battery_refused.stdout).unwrap();
    assert_eq!(bat_json["stage"], "pool_admission");
    assert_eq!(
        bat_json["admission"]["reason"],
        "opportunistic_requires_ac_wall_power"
    );
}
