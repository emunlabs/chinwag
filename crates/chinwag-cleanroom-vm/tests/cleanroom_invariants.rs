// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use chinwag_cleanroom_vm::{
    CleanroomDiagnosticInput, CleanroomSeatbeltSpec, CleanroomVmError, EnvLockError,
    EphemeralTartSession, HostHardwareTelemetry, JobTriggerContext, MAX_DRAIN_BUDGET_MS,
    MAX_VIRTIOFS_MOUNT_LATENCY_MS, MAX_VMS_PER_MAC_HOST, NetworkEgressPolicy, PoolAdmissionPolicy,
    ReleaseRefPolicy, ReleaseSignerAttestation, RunnerPoolController, RunnerTrustProfile,
    SeatbeltError, SeatbeltSignalMode, StoreClosureEntry, TartCleanroomSpec, TartCommandRecord,
    TartExecutor, ThermalPressure, TrustPoolError, VirtioFsAccess, VirtioFsMount,
    acquire_host_vm_slot, compile_seatbelt_profile, compile_workspace_env_lock,
    count_active_slot_leases, evaluate_trust_gate, evaluate_trust_gate_with_policy,
    generate_receipt_signing_key, generate_recipient_kem_keypair, open_failure_diagnostic_bundle,
    parse_openssh_allowed_signers_ed25519, scrub_diagnostic_secrets,
    seal_failure_diagnostic_bundle, sign_env_lock_receipt, signing_key_from_seed_file,
    verify_env_lock_bundle, verify_env_lock_bundle_with_signers, verify_env_lock_receipt,
    write_env_lock_bundle,
};
use ed25519_dalek::SigningKey;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::rc::Rc;
use tempfile::TempDir;

#[derive(Clone, Default)]
struct RecordingTartExecutor {
    log: Rc<RefCell<Vec<TartCommandRecord>>>,
    fail_on_step: Option<&'static str>,
}

impl TartExecutor for RecordingTartExecutor {
    fn exec_tart(&mut self, step: &'static str, argv: &[String]) -> Result<(), CleanroomVmError> {
        self.log.borrow_mut().push(TartCommandRecord {
            step: step.to_owned(),
            argv: argv.to_vec(),
        });
        if self.fail_on_step == Some(step) {
            return Err(CleanroomVmError::TartExecutionFailed {
                step,
                detail: "simulated guest execution failure".to_owned(),
            });
        }
        Ok(())
    }
}

// ============================================================================
// Slice 1A: Tart Ephemeral Driver & VirtioFS :ro + XNU Seatbelt Tests
// ============================================================================

#[test]
fn tart_spec_generates_clone_set_run_ro_and_delete_argv() {
    let spec = TartCleanroomSpec::new(
        "macos-sequoia-base-v1",
        "cleanroom-job-42",
        "/nix/store",
        "/var/tmp/sccache",
    )
    .expect("valid spec")
    .with_resources(6, 12_288)
    .expect("valid resources");

    assert_eq!(
        spec.clone_argv(),
        vec!["clone", "macos-sequoia-base-v1", "cleanroom-job-42"]
    );
    assert_eq!(
        spec.set_resources_argv(),
        vec!["set", "cleanroom-job-42", "--cpu", "6", "--memory", "12288"]
    );
    assert_eq!(
        spec.run_argv(),
        vec![
            "run",
            "--no-graphics",
            "--dir=nix-store:/nix/store:ro",
            "--dir=sccache:/var/tmp/sccache:ro",
            "cleanroom-job-42"
        ]
    );
    assert_eq!(spec.delete_argv(), vec!["delete", "cleanroom-job-42"]);
}

#[test]
fn virtiofs_mount_rejects_writable_access_mode() {
    let err = VirtioFsMount::read_only("nix-store", "/nix/store", VirtioFsAccess::ReadWrite)
        .expect_err("writable mount must fail closed");
    assert!(matches!(err, CleanroomVmError::WritableMountForbidden(_)));
}

#[test]
fn tart_spec_rejects_flag_injection_base_collision_and_graphics() {
    assert!(matches!(
        TartCleanroomSpec::new("-flag-inject", "job-1", "/nix/store", "/var/tmp/sccache"),
        Err(CleanroomVmError::InvalidVmName(_))
    ));
    assert!(matches!(
        TartCleanroomSpec::new("same-vm", "same-vm", "/nix/store", "/var/tmp/sccache"),
        Err(CleanroomVmError::RunNameMatchesBaseImage(_))
    ));
    assert!(matches!(
        TartCleanroomSpec::new("base", "job-1", "/nix/store/../etc", "/var/tmp/sccache"),
        Err(CleanroomVmError::InvalidMountPath(_))
    ));
    assert!(matches!(
        TartCleanroomSpec::new("base", "job-1", "/nix/store:rw", "/var/tmp/sccache"),
        Err(CleanroomVmError::InvalidMountPath(_))
    ));

    let spec = TartCleanroomSpec::new("base", "job-1", "/nix/store", "/var/tmp/sccache").unwrap();
    assert_eq!(
        spec.with_graphics_enabled(true),
        Err(CleanroomVmError::GraphicsForbidden)
    );
}

#[test]
fn virtiofs_mount_latency_budget_enforces_200ms_sla() {
    let spec = TartCleanroomSpec::new("base", "job-1", "/nix/store", "/var/tmp/sccache").unwrap();
    assert_eq!(
        spec.mount_latency_budget_ms(),
        MAX_VIRTIOFS_MOUNT_LATENCY_MS
    );
    assert!(spec.check_mount_latency(42).is_ok());
    assert!(spec.check_mount_latency(200).is_ok());
    assert!(matches!(
        spec.check_mount_latency(201),
        Err(CleanroomVmError::MountLatencyExceeded {
            observed_ms: 201,
            budget_ms: 200
        })
    ));
}

#[test]
fn ephemeral_tart_session_guarantees_defer_delete_on_success_and_run_failure() {
    let spec = TartCleanroomSpec::new(
        "base-v1",
        "ephemeral-run-1",
        "/nix/store",
        "/var/tmp/sccache",
    )
    .unwrap();
    let log = Rc::new(RefCell::new(Vec::new()));
    let exec = RecordingTartExecutor {
        log: Rc::clone(&log),
        fail_on_step: None,
    };

    let mut session = EphemeralTartSession::clone_and_arm(spec.clone(), exec).unwrap();
    session.run_ephemeral().unwrap();
    let (_, del_res) = session.finish();
    del_res.unwrap();

    let steps: Vec<String> = log.borrow().iter().map(|r| r.step.clone()).collect();
    assert_eq!(steps, vec!["clone", "set", "run", "delete"]);

    // Verify RAII Drop still executes `tart delete` once when `tart run` fails
    let fail_log = Rc::new(RefCell::new(Vec::new()));
    {
        let fail_exec = RecordingTartExecutor {
            log: Rc::clone(&fail_log),
            fail_on_step: Some("run"),
        };
        let mut failing_session = EphemeralTartSession::clone_and_arm(spec, fail_exec).unwrap();
        let err = failing_session.run_ephemeral().unwrap_err();
        assert!(matches!(
            err,
            CleanroomVmError::TartExecutionFailed { step: "run", .. }
        ));
    }
    let fail_steps: Vec<String> = fail_log.borrow().iter().map(|r| r.step.clone()).collect();
    assert_eq!(fail_steps, vec!["clone", "set", "run", "delete"]);
}

#[test]
fn seatbelt_compiler_emits_sigkill_ro_nix_store_and_daemon_denies() {
    let spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Public,
        "/nix/store",
        "/var/tmp/sccache",
        "/private/tmp/worktree-1",
        "/private/tmp/scratch-1",
    )
    .unwrap();
    let compiled = compile_seatbelt_profile(&spec).unwrap();
    assert!(
        compiled
            .sbpl
            .contains("(deny file-write* (subpath \"/nix/store\") (with send-signal SIGKILL))")
    );
    assert!(
        compiled.sbpl.contains(
            "(deny file-read* file-write* (subpath \"/nix/var/nix/daemon-socket\") (with send-signal SIGKILL))"
        )
    );
    assert!(
        compiled
            .sbpl
            .contains("(deny file-read* (regex #\"/\\.chinwag/signing(/|$)\"))")
    );
    assert_eq!(compiled.sha256_hex.len(), 64);
}

#[test]
fn seatbelt_rejects_sbpl_injection_overlap_and_public_signing_mount() {
    assert!(matches!(
        CleanroomSeatbeltSpec::new(
            RunnerTrustProfile::Public,
            "/nix/store\"))(allow default);(",
            "/var/tmp/sccache",
            "/private/tmp/work",
            "/private/tmp/scratch",
        ),
        Err(SeatbeltError::InvalidPath(_))
    ));

    assert!(matches!(
        CleanroomSeatbeltSpec::new(
            RunnerTrustProfile::Public,
            "/nix/store",
            "/var/tmp/sccache",
            "/nix/store/subworktree",
            "/private/tmp/scratch",
        ),
        Err(SeatbeltError::ReadOnlyOverlap(_, _))
    ));

    let public_spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Public,
        "/nix/store",
        "/var/tmp/sccache",
        "/private/tmp/work",
        "/private/tmp/scratch",
    )
    .unwrap();
    assert_eq!(
        public_spec.with_release_signing_dir("/private/tmp/release-lease"),
        Err(SeatbeltError::ReleaseMountOnPublicProfile)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_sandbox_exec_kernel_enforces_read_only_store_and_writable_worktree() {
    if !Path::new("/usr/bin/sandbox-exec").exists() {
        return;
    }
    let tmp = TempDir::new().unwrap();
    let canon = fs::canonicalize(tmp.path()).unwrap();
    let mock_nix_store = canon.join("nix-store");
    let mock_sccache = canon.join("sccache");
    let worktree = canon.join("worktree");
    let scratch = canon.join("scratch");
    for d in [&mock_nix_store, &mock_sccache, &worktree, &scratch] {
        fs::create_dir_all(d).unwrap();
    }
    let existing_drv = mock_nix_store.join("0000-rustc-1.97.1.drv");
    fs::write(&existing_drv, b"immutable-derivation").unwrap();

    let spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Public,
        &mock_nix_store,
        &mock_sccache,
        &worktree,
        &scratch,
    )
    .unwrap()
    .with_signal_mode(SeatbeltSignalMode::KernelDeny);
    let profile = compile_seatbelt_profile(&spec).unwrap();

    // 1. Reading `/nix/store` and writing inside isolated `worktree` MUST succeed
    let allowed_target = worktree.join("artifact.txt");
    let ok_out = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile.sbpl, "/bin/cp"])
        .arg(&existing_drv)
        .arg(&allowed_target)
        .output()
        .expect("invoke sandbox-exec allow check");
    if !ok_out.status.success() {
        let stderr = String::from_utf8_lossy(&ok_out.stderr);
        // If already running inside an outer nested Seatbelt sandbox that blocks nested `sandbox_init`, skip gracefully
        if stderr.contains("sandbox_apply") || stderr.contains("Operation not permitted") {
            return;
        }
        panic!("expected allowed worktree write to succeed: {stderr}");
    }
    assert_eq!(fs::read(&allowed_target).unwrap(), b"immutable-derivation");

    // 2. Attempting to mutate the read-only Nix store MUST be kernel-blocked!
    let tampered_store_file = mock_nix_store.join("tampered-payload");
    let deny_out = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", &profile.sbpl, "/usr/bin/touch"])
        .arg(&tampered_store_file)
        .output()
        .expect("invoke sandbox-exec deny check");
    assert!(
        !deny_out.status.success(),
        "XNU Seatbelt must block writes to read-only Nix store"
    );
    assert!(!tampered_store_file.exists());
}

// ============================================================================
// Slice 1B: Zero-Nix `chinwag env lock` Deterministic Compiler & Ed25519 Receipt
// ============================================================================

#[test]
fn env_lock_compiles_deterministic_flake_lock_v7_for_polyglot_workspace() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.1\"\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/demo\"]\n[workspace.package]\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"demo-ui","packageManager":"pnpm@10.6.0","engines":{"node":">=22.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname = \"demo-py\"\nrequires-python = \">=3.12\"\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("go.mod"),
        "module example.invalid/demo\n\ngo 1.24.1\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join(".chinwag")).unwrap();
    fs::write(
        dir.path().join(".chinwag/env.ts"),
        "export default { packages: ['ripgrep', 'sccache'] };\n",
    )
    .unwrap();

    let first = compile_workspace_env_lock(dir.path()).unwrap();
    let second = compile_workspace_env_lock(dir.path()).unwrap();

    assert_eq!(first.canonical_json, second.canonical_json);
    assert_eq!(first.flake_lock_sha256_hex, second.flake_lock_sha256_hex);
    assert_eq!(first.closure_sha256_hex, second.closure_sha256_hex);
    assert_eq!(first.flake_lock.version, 7);
    assert_eq!(first.node_nar_hashes.len(), 5);
    for nar in first.node_nar_hashes.values() {
        assert!(
            nar.starts_with("sha256-"),
            "expected SRI narHash, got {nar}"
        );
    }
    let rust_locked = first.flake_lock.nodes["rust-toolchain"]
        .locked
        .as_ref()
        .unwrap();
    assert_eq!(rust_locked.version_pin.as_deref(), Some("1.97.1"));
}

#[test]
fn env_lock_rejects_nix_expression_files_in_root_and_dot_chinwag() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("flake.nix"),
        "{ description = \"forbidden\"; }",
    )
    .unwrap();

    let err = compile_workspace_env_lock(dir.path()).unwrap_err();
    assert!(matches!(err, EnvLockError::ForbiddenNixSyntaxFile(ref f) if f == "flake.nix"));

    fs::remove_file(dir.path().join("flake.nix")).unwrap();
    fs::create_dir_all(dir.path().join(".chinwag")).unwrap();
    fs::write(dir.path().join(".chinwag/shell.nix"), "{}").unwrap();
    let err2 = compile_workspace_env_lock(dir.path()).unwrap_err();
    assert!(matches!(err2, EnvLockError::ForbiddenNixSyntaxFile(ref f) if f == "shell.nix"));
}

#[test]
fn env_lock_bundle_roundtrip_and_tamper_or_drift_rejection() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"cleanroom-demo\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();

    let compiled = compile_workspace_env_lock(dir.path()).unwrap();
    let sk = generate_receipt_signing_key().unwrap();
    let vk_bytes = sk.verifying_key().to_bytes();
    let receipt = sign_env_lock_receipt(&compiled, &sk).unwrap();
    let (lock_path, _) = write_env_lock_bundle(dir.path(), &compiled, &receipt).unwrap();

    // Valid verification with pinned Ed25519 key
    let verified = verify_env_lock_bundle(dir.path(), Some(&vk_bytes)).unwrap();
    assert_eq!(verified.closure_sha256, compiled.closure_sha256_hex);

    // Wrong pinned signer rejected
    let other_sk = SigningKey::from_bytes(&[7u8; 32]);
    let other_vk = other_sk.verifying_key().to_bytes();
    assert!(matches!(
        verify_env_lock_bundle(dir.path(), Some(&other_vk)),
        Err(EnvLockError::ReceiptVerification(_))
    ));

    // Signature tamper rejected by Ed25519 verify_strict
    let mut bad_receipt = receipt.clone();
    let mut sig_bytes = hex::decode(&bad_receipt.signature_hex).unwrap();
    sig_bytes[0] ^= 0xff;
    bad_receipt.signature_hex = hex::encode(sig_bytes);
    assert!(matches!(
        verify_env_lock_receipt(&bad_receipt, compiled.canonical_json.as_bytes(), None),
        Err(EnvLockError::ReceiptVerification(_))
    ));

    // Manifest drift without re-locking fails closed
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"cleanroom-demo\"\nversion = \"0.2.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    assert!(matches!(
        verify_env_lock_bundle(dir.path(), Some(&vk_bytes)),
        Err(EnvLockError::LockfileDrift(_))
    ));

    // Direct byte tamper of `.chinwag/flake.lock` fails closed
    fs::write(&lock_path, "{}\n").unwrap();
    assert!(verify_env_lock_bundle(dir.path(), None).is_err());
}

#[cfg(unix)]
#[test]
fn env_lock_rejects_symlink_manifests_and_seed_files() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let real_seed = dir.path().join("seed.hex");
    fs::write(&real_seed, hex::encode([0x22u8; 32])).unwrap();
    let loaded = signing_key_from_seed_file(&real_seed).unwrap();
    assert_eq!(
        loaded.verifying_key().to_bytes(),
        SigningKey::from_bytes(&[0x22u8; 32])
            .verifying_key()
            .to_bytes()
    );

    let sym_seed = dir.path().join("symlink-seed.hex");
    symlink(&real_seed, &sym_seed).unwrap();
    assert!(signing_key_from_seed_file(&sym_seed).is_err());

    let outside_cargo = dir.path().join("outside-Cargo.toml");
    fs::write(
        &outside_cargo,
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let ws = dir.path().join("ws");
    fs::create_dir_all(&ws).unwrap();
    symlink(&outside_cargo, ws.join("Cargo.toml")).unwrap();
    assert!(matches!(
        compile_workspace_env_lock(&ws),
        Err(EnvLockError::ManifestParse { .. })
    ));
}

// ============================================================================
// Slice 1C: 2-Tier Runner Trust Gate, Multi-Mac Pool Policy & Sealed Bundles
// ============================================================================

#[test]
fn public_profile_scrubs_secrets_and_disables_release_authority() {
    let mut host_env = BTreeMap::new();
    host_env.insert("PATH".to_owned(), "/usr/bin:/bin".to_owned());
    host_env.insert("RUSTUP_TOOLCHAIN".to_owned(), "1.97.1".to_owned());
    host_env.insert("GITHUB_TOKEN".to_owned(), "ghs_secret_123".to_owned());
    host_env.insert(
        "APPLE_DEVELOPER_ID_LEASE".to_owned(),
        "lease_xyz".to_owned(),
    );
    host_env.insert("AWS_SECRET_ACCESS_KEY".to_owned(), "supersecret".to_owned());

    let ctx = JobTriggerContext {
        requested_profile: RunnerTrustProfile::Public,
        git_ref: "refs/pull/99/merge".to_owned(),
        commit_oid: "a".repeat(40),
        is_fork_pr: true,
        is_untrusted_pr_event: true,
        release_attestation: None,
    };

    let decision = evaluate_trust_gate(&ctx, &host_env, &[]).unwrap();
    assert_eq!(decision.profile, RunnerTrustProfile::Public);
    assert!(!decision.allow_release_keys);
    assert!(!decision.phantom_vault_enabled);
    assert!(!decision.allow_apple_notarization);
    assert_eq!(
        decision.network_policy,
        NetworkEgressPolicy::RegistriesAndBinaryCacheOnly
    );
    assert!(!decision.sanitized_env.contains_key("GITHUB_TOKEN"));
    assert!(
        !decision
            .sanitized_env
            .contains_key("APPLE_DEVELOPER_ID_LEASE")
    );
    assert!(!decision.sanitized_env.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert_eq!(
        decision
            .sanitized_env
            .get("CHINWAG_CLEANROOM_TIER")
            .map(String::as_str),
        Some("public")
    );
}

#[test]
fn release_profile_enforces_protected_ref_non_fork_and_verified_ed25519_signer() {
    let release_sk = SigningKey::from_bytes(&[0x44u8; 32]);
    let release_pk = release_sk.verifying_key().to_bytes();
    let oid = "b".repeat(40);
    let valid_att = ReleaseSignerAttestation::sign("refs/heads/main", &oid, &release_sk);

    let mut host_env = BTreeMap::new();
    host_env.insert(
        "APPLE_DEVELOPER_ID_LEASE".to_owned(),
        "scoped-lease-1".to_owned(),
    );
    host_env.insert(
        "GITHUB_TOKEN".to_owned(),
        "must-still-be-dropped".to_owned(),
    );

    // 1. Valid protected main commit with enrolled Ed25519 release signer succeeds
    let valid_ctx = JobTriggerContext {
        requested_profile: RunnerTrustProfile::Release,
        git_ref: "refs/heads/main".to_owned(),
        commit_oid: oid.clone(),
        is_fork_pr: false,
        is_untrusted_pr_event: false,
        release_attestation: Some(valid_att.clone()),
    };
    let ok = evaluate_trust_gate(&valid_ctx, &host_env, &[release_pk]).unwrap();
    assert!(ok.allow_release_keys);
    assert!(ok.phantom_vault_enabled);
    assert_eq!(
        ok.sanitized_env
            .get("APPLE_DEVELOPER_ID_LEASE")
            .map(String::as_str),
        Some("scoped-lease-1")
    );
    assert!(!ok.sanitized_env.contains_key("GITHUB_TOKEN"));

    // 2. Signed `refs/tags/v0.2.0` release tag also succeeds
    let tag_att = ReleaseSignerAttestation::sign("refs/tags/v0.2.0", &oid, &release_sk);
    let tag_ctx = JobTriggerContext {
        git_ref: "refs/tags/v0.2.0".to_owned(),
        release_attestation: Some(tag_att),
        ..valid_ctx.clone()
    };
    assert!(evaluate_trust_gate(&tag_ctx, &host_env, &[release_pk]).is_ok());

    // 3. Fork PR attempting release profile MUST fail closed even if signed
    let fork_ctx = JobTriggerContext {
        is_fork_pr: true,
        ..valid_ctx.clone()
    };
    assert!(matches!(
        evaluate_trust_gate(&fork_ctx, &host_env, &[release_pk]),
        Err(TrustPoolError::ReleaseRefused(_))
    ));

    // 4. Feature branch attempting release profile MUST fail closed
    let feat_att = ReleaseSignerAttestation::sign("refs/heads/feat/x", &oid, &release_sk);
    let feat_ctx = JobTriggerContext {
        git_ref: "refs/heads/feat/x".to_owned(),
        release_attestation: Some(feat_att),
        ..valid_ctx.clone()
    };
    assert!(matches!(
        evaluate_trust_gate(&feat_ctx, &host_env, &[release_pk]),
        Err(TrustPoolError::ReleaseRefused(_))
    ));

    // 5. Unenrolled signer MUST fail closed
    let rogue_sk = SigningKey::from_bytes(&[0x99u8; 32]);
    let rogue_att = ReleaseSignerAttestation::sign("refs/heads/main", &oid, &rogue_sk);
    let rogue_ctx = JobTriggerContext {
        release_attestation: Some(rogue_att),
        ..valid_ctx
    };
    assert!(matches!(
        evaluate_trust_gate(&rogue_ctx, &host_env, &[release_pk]),
        Err(TrustPoolError::ReleaseRefused(_))
    ));
}

#[test]
fn runner_pool_enforces_2vm_cap_ac_power_thermals_and_500ms_drain() {
    assert_eq!(MAX_VMS_PER_MAC_HOST, 2);
    assert_eq!(MAX_DRAIN_BUDGET_MS, 500);

    // Reject illegal >2 VM policy per Apple Virtualization.framework EULA
    let mut illegal = PoolAdmissionPolicy::dedicated();
    illegal.max_vms_per_host = 3;
    assert!(RunnerPoolController::new(illegal).is_err());

    let opp = RunnerPoolController::new(PoolAdmissionPolicy::opportunistic()).unwrap();

    // Plugged-in, nominal thermal, 85% idle, 1 active VM -> admitted to slot 2
    let healthy = HostHardwareTelemetry {
        ac_power_connected: true,
        thermal_pressure: ThermalPressure::Nominal,
        cpu_idle_percent: 85,
        active_vm_count: 1,
        user_hid_active: false,
    };
    let d1 = opp.evaluate_admission(&healthy);
    assert!(d1.admitted);
    assert_eq!(d1.allocated_slot, Some(2));

    // 2 active VMs -> cap reached
    let full = HostHardwareTelemetry {
        active_vm_count: 2,
        ..healthy
    };
    let d_full = opp.evaluate_admission(&full);
    assert!(!d_full.admitted);
    assert_eq!(d_full.reason, "host_two_vm_hypervisor_cap_reached");

    // Battery power with 1 active VM -> refused AND triggers `<500ms` drain!
    let unplugged = HostHardwareTelemetry {
        ac_power_connected: false,
        ..healthy
    };
    let d_bat = opp.evaluate_admission(&unplugged);
    assert!(!d_bat.admitted);
    assert!(d_bat.drain_required);
    assert_eq!(d_bat.drain_budget_ms, 500);

    // Thermal pressure `Fair` or user HID active -> refused with drain
    let warm = HostHardwareTelemetry {
        thermal_pressure: ThermalPressure::Fair,
        ..healthy
    };
    assert!(!opp.evaluate_admission(&warm).admitted);

    let hid_busy = HostHardwareTelemetry {
        user_hid_active: true,
        ..healthy
    };
    let d_hid = opp.evaluate_admission(&hid_busy);
    assert!(!d_hid.admitted);
    assert!(d_hid.drain_required);
}

#[test]
fn sealed_failure_bundle_scrubs_secrets_roundtrips_x25519_mlkem768_and_verifies_before_decrypt() {
    let (recipient_sk, recipient_pk) = generate_recipient_kem_keypair().unwrap();
    assert_eq!(recipient_pk.len(), 1216);

    let runner_sk = SigningKey::from_bytes(&[0x55u8; 32]);
    let runner_pk = runner_sk.verifying_key().to_bytes();

    let raw_stderr = "\
error: test failed
Authorization: Bearer secret_live_bearer_999999
token=ghp_1234567890abcdefghijklmnopqrstuv
GITHUB_TOKEN=ghs_secret_inline
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==
-----END OPENSSH PRIVATE KEY-----
assertion `left == right` failed at line 42";

    let scrubbed_preview = scrub_diagnostic_secrets(raw_stderr);
    assert!(!scrubbed_preview.contains("secret_live_bearer_999999"));
    assert!(!scrubbed_preview.contains("ghp_1234567890"));
    assert!(!scrubbed_preview.contains("ghs_secret_inline"));
    assert!(!scrubbed_preview.contains("b3BlbnNzaC1rZXktdjE"));
    assert!(scrubbed_preview.contains("assertion `left == right` failed at line 42"));

    let input = CleanroomDiagnosticInput {
        job_id: "job-chwg-0202".to_owned(),
        run_vm_name: "cleanroom-slot-1".to_owned(),
        trust_profile: RunnerTrustProfile::Public,
        exit_code: 101,
        flake_lock_sha256: "c".repeat(64),
        stderr_tail: raw_stderr.to_owned(),
    };

    let bundle = seal_failure_diagnostic_bundle(input, &recipient_pk, &runner_sk).unwrap();
    assert_eq!(
        hex::decode(&bundle.encapsulated_key_hex).unwrap().len(),
        1120
    );

    // Valid open recovers scrubbed diagnostic payload
    let opened = open_failure_diagnostic_bundle(&bundle, &recipient_sk, &runner_pk).unwrap();
    assert_eq!(opened.job_id, "job-chwg-0202");
    assert_eq!(opened.exit_code, 101);
    assert!(!opened.stderr_tail.contains("secret_live_bearer_999999"));
    assert!(opened.stderr_tail.contains("[REDACTED_BEARER]"));
    assert!(opened.stderr_tail.contains("[REDACTED_PRIVATE_KEY_BLOCK]"));

    // Prove Verify-Before-Decrypt: pass a BOGUS recipient KEM secret key `[0x11; 32]` AND
    // a tampered ciphertext. `open_failure_diagnostic_bundle` MUST fail on `Ed25519 verify_strict`
    // BEFORE ever touching `recipient_kem_secret`!
    let mut tampered = bundle.clone();
    let mut ct = hex::decode(&tampered.ciphertext_hex).unwrap();
    ct[0] ^= 0x01;
    tampered.ciphertext_hex = hex::encode(ct);

    let bogus_kem_sk = [0x11u8; 32];
    let err = open_failure_diagnostic_bundle(&tampered, &bogus_kem_sk, &runner_pk).unwrap_err();
    assert_eq!(
        err,
        TrustPoolError::DiagnosticBundle("Ed25519 verify_strict rejected unauthenticated bundle")
    );
}

#[test]
fn tart_spec_resource_bounds_reject_zero_cores_and_undersized_ram() {
    let spec = TartCleanroomSpec::new("base", "job-res", "/nix/store", "/var/tmp/sccache").unwrap();
    assert!(matches!(
        spec.clone().with_resources(0, 8192),
        Err(CleanroomVmError::InvalidResourceBounds { .. })
    ));
    assert!(matches!(
        spec.clone().with_resources(64, 8192),
        Err(CleanroomVmError::InvalidResourceBounds { .. })
    ));
    assert!(matches!(
        spec.with_resources(4, 1024),
        Err(CleanroomVmError::InvalidResourceBounds { .. })
    ));
}

#[test]
fn tart_spec_extra_ro_mounts_preserve_order_and_reject_duplicate_tags() {
    let extra = VirtioFsMount::read_only(
        "cargo-registry",
        "/var/tmp/cargo-reg",
        VirtioFsAccess::ReadOnly,
    )
    .unwrap();
    let spec = TartCleanroomSpec::new("base", "job-extra", "/nix/store", "/var/tmp/sccache")
        .unwrap()
        .with_extra_ro_mount(extra.clone())
        .unwrap();
    assert!(
        spec.run_argv()
            .contains(&"--dir=cargo-registry:/var/tmp/cargo-reg:ro".to_owned())
    );
    assert!(matches!(
        spec.with_extra_ro_mount(extra),
        Err(CleanroomVmError::InvalidShareTag(_))
    ));
}

#[test]
fn dedicated_pool_admits_fair_thermals_and_refuses_serious_or_critical() {
    let ded = RunnerPoolController::new(PoolAdmissionPolicy::dedicated()).unwrap();
    let fair = HostHardwareTelemetry {
        ac_power_connected: true,
        thermal_pressure: ThermalPressure::Fair,
        cpu_idle_percent: 25,
        active_vm_count: 0,
        user_hid_active: true,
    };
    let ok = ded.evaluate_admission(&fair);
    assert!(ok.admitted);
    assert_eq!(ok.allocated_slot, Some(1));

    for bad_thermal in [ThermalPressure::Serious, ThermalPressure::Critical] {
        let hot = HostHardwareTelemetry {
            thermal_pressure: bad_thermal,
            ..fair
        };
        let dec = ded.evaluate_admission(&hot);
        assert!(!dec.admitted);
        assert_eq!(dec.reason, "dedicated_host_thermal_throttling");
    }
}

#[test]
fn runner_trust_profile_label_parser_accepts_canonical_and_short_forms() {
    assert_eq!(
        RunnerTrustProfile::parse_label("public").unwrap(),
        RunnerTrustProfile::Public
    );
    assert_eq!(
        RunnerTrustProfile::parse_label("chinwag-ephemeral-public").unwrap(),
        RunnerTrustProfile::Public
    );
    assert_eq!(
        RunnerTrustProfile::parse_label("release").unwrap(),
        RunnerTrustProfile::Release
    );
    assert_eq!(
        RunnerTrustProfile::parse_label("chinwag-ephemeral-release").unwrap(),
        RunnerTrustProfile::Release
    );
    assert!(matches!(
        RunnerTrustProfile::parse_label("privileged-root"),
        Err(TrustPoolError::UnknownProfile(_))
    ));
}

#[test]
fn env_lock_rejects_empty_repository_without_supported_manifests() {
    let dir = TempDir::new().unwrap();
    assert!(matches!(
        compile_workspace_env_lock(dir.path()),
        Err(EnvLockError::NoSupportedManifests(_))
    ));
}

#[test]
fn env_lock_rejects_malformed_cargo_toml_and_package_json() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "not = [valid toml").unwrap();
    assert!(matches!(
        compile_workspace_env_lock(dir.path()),
        Err(EnvLockError::ManifestParse { ref path, .. }) if path == "Cargo.toml"
    ));

    let dir2 = TempDir::new().unwrap();
    fs::write(dir2.path().join("package.json"), "{broken_json").unwrap();
    assert!(matches!(
        compile_workspace_env_lock(dir2.path()),
        Err(EnvLockError::ManifestParse { ref path, .. }) if path == "package.json"
    ));
}

#[test]
fn env_lock_rejects_weak_small_order_ed25519_public_key_in_receipt() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let compiled = compile_workspace_env_lock(dir.path()).unwrap();
    let sk = generate_receipt_signing_key().unwrap();
    let mut receipt = sign_env_lock_receipt(&compiled, &sk).unwrap();
    // Identity point `[1, 0, ..., 0]` is a canonical small-order Ed25519 torsion point
    let mut identity_pt = [0u8; 32];
    identity_pt[0] = 1;
    receipt.signer_public_key_hex = hex::encode(identity_pt);
    assert!(matches!(
        verify_env_lock_receipt(&receipt, compiled.canonical_json.as_bytes(), None),
        Err(EnvLockError::ReceiptVerification(
            "weak small-order Ed25519 public key rejected"
        ))
    ));
}

#[test]
fn seatbelt_release_profile_allows_explicit_ephemeral_signing_lease_dir() {
    let spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Release,
        "/nix/store",
        "/var/tmp/sccache",
        "/private/tmp/worktree-rel",
        "/private/tmp/scratch-rel",
    )
    .unwrap()
    .with_release_signing_dir("/private/tmp/ephemeral-signing-lease")
    .unwrap();
    let profile = compile_seatbelt_profile(&spec).unwrap();
    assert!(
        profile
            .sbpl
            .contains("(allow file-read* (subpath \"/private/tmp/ephemeral-signing-lease\"))")
    );
}

#[test]
fn sealed_failure_bundle_rejects_wrong_pinned_runner_identity() {
    let (recipient_sk, recipient_pk) = generate_recipient_kem_keypair().unwrap();
    let runner_sk = SigningKey::from_bytes(&[0x31u8; 32]);
    let other_runner_pk = SigningKey::from_bytes(&[0x32u8; 32])
        .verifying_key()
        .to_bytes();

    let input = CleanroomDiagnosticInput {
        job_id: "job-id-1".to_owned(),
        run_vm_name: "vm-1".to_owned(),
        trust_profile: RunnerTrustProfile::Public,
        exit_code: 1,
        flake_lock_sha256: "a".repeat(64),
        stderr_tail: "boom".to_owned(),
    };
    let bundle = seal_failure_diagnostic_bundle(input, &recipient_pk, &runner_sk).unwrap();
    let err = open_failure_diagnostic_bundle(&bundle, &recipient_sk, &other_runner_pk).unwrap_err();
    assert_eq!(
        err,
        TrustPoolError::DiagnosticBundle("runner pubkey mismatch against pinned runner identity")
    );
}

#[test]
fn sealed_failure_bundle_rejects_mismatched_recipient_kem_key_after_sig_verify() {
    let (_recipient_sk, recipient_pk) = generate_recipient_kem_keypair().unwrap();
    let (wrong_recipient_sk, _) = generate_recipient_kem_keypair().unwrap();
    let runner_sk = SigningKey::from_bytes(&[0x61u8; 32]);
    let runner_pk = runner_sk.verifying_key().to_bytes();

    let input = CleanroomDiagnosticInput {
        job_id: "job-id-2".to_owned(),
        run_vm_name: "vm-2".to_owned(),
        trust_profile: RunnerTrustProfile::Public,
        exit_code: 2,
        flake_lock_sha256: "b".repeat(64),
        stderr_tail: "compile error".to_owned(),
    };
    let bundle = seal_failure_diagnostic_bundle(input, &recipient_pk, &runner_sk).unwrap();
    let err = open_failure_diagnostic_bundle(&bundle, &wrong_recipient_sk, &runner_pk).unwrap_err();
    assert_eq!(
        err,
        TrustPoolError::DiagnosticBundle("recipient key fingerprint mismatch")
    );
}

#[test]
fn opportunistic_pool_rejects_low_cpu_idle_headroom_without_draining_existing_slot() {
    let opp = RunnerPoolController::new(PoolAdmissionPolicy::opportunistic()).unwrap();
    let busy = HostHardwareTelemetry {
        ac_power_connected: true,
        thermal_pressure: ThermalPressure::Nominal,
        cpu_idle_percent: 45,
        active_vm_count: 1,
        user_hid_active: false,
    };
    let dec = opp.evaluate_admission(&busy);
    assert!(!dec.admitted);
    assert!(!dec.drain_required);
    assert_eq!(dec.reason, "opportunistic_insufficient_cpu_idle_headroom");
}

#[test]
fn release_trust_gate_rejects_malformed_commit_oid() {
    let ctx = JobTriggerContext {
        requested_profile: RunnerTrustProfile::Public,
        git_ref: "refs/pull/1/merge".to_owned(),
        commit_oid: "not-hex-oid".to_owned(),
        is_fork_pr: true,
        is_untrusted_pr_event: true,
        release_attestation: None,
    };
    assert_eq!(
        evaluate_trust_gate(&ctx, &BTreeMap::new(), &[]),
        Err(TrustPoolError::ReleaseRefused("malformed commit OID"))
    );
}

#[test]
fn ephemeral_tart_session_with_seatbelt_executes_guest_sandbox_exec_and_deletes_on_failure() {
    let spec = TartCleanroomSpec::new(
        "base-v1",
        "sandboxed-run-1",
        "/nix/store",
        "/var/tmp/sccache",
    )
    .unwrap();
    let sb_spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Public,
        "/nix/store",
        "/var/tmp/sccache",
        "/private/tmp/worktree-sb",
        "/private/tmp/scratch-sb",
    )
    .unwrap();
    let seatbelt = compile_seatbelt_profile(&sb_spec).unwrap();
    let cmd = vec![
        "cargo".to_owned(),
        "test".to_owned(),
        "--offline".to_owned(),
    ];

    let log = Rc::new(RefCell::new(Vec::new()));
    let exec = RecordingTartExecutor {
        log: Rc::clone(&log),
        fail_on_step: None,
    };
    let mut session = EphemeralTartSession::clone_and_arm(spec.clone(), exec).unwrap();
    session
        .run_ephemeral_with_seatbelt(&seatbelt, &cmd)
        .unwrap();
    let (_, del_res) = session.finish();
    del_res.unwrap();

    let records = log.borrow();
    let steps: Vec<&str> = records.iter().map(|r| r.step.as_str()).collect();
    assert_eq!(steps, vec!["clone", "set", "run", "exec", "delete"]);
    assert_eq!(records[3].argv[0], "exec");
    assert_eq!(records[3].argv[1], "sandboxed-run-1");
    assert_eq!(records[3].argv[2], "/usr/bin/sandbox-exec");
    assert_eq!(records[3].argv[3], "-p");
    assert!(records[3].argv[4].contains("(deny file-write* (subpath \"/nix/store\")"));
    assert_eq!(&records[3].argv[5..], &["--", "cargo", "test", "--offline"]);
}

#[cfg(unix)]
#[test]
fn env_lock_recursively_rejects_nested_nix_files_and_nix_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"nested-check\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("crates/sub/nix")).unwrap();
    fs::write(dir.path().join("crates/sub/nix/overlay.nix"), "{}").unwrap();
    assert!(matches!(
        compile_workspace_env_lock(dir.path()),
        Err(EnvLockError::ForbiddenNixSyntaxFile(_))
    ));
    fs::remove_file(dir.path().join("crates/sub/nix/overlay.nix")).unwrap();

    let innocent = dir.path().join("Cargo.toml");
    symlink(&innocent, dir.path().join("crates/sub/sneaky.nix")).unwrap();
    assert!(matches!(
        compile_workspace_env_lock(dir.path()),
        Err(EnvLockError::ForbiddenNixSyntaxFile(_))
    ));
}

#[test]
fn env_lock_pins_resolved_store_closures_nar_hash_and_verifies_openssh_allowed_signers() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use sha2::{Digest, Sha256};

    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"store-pin\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join(".chinwag")).unwrap();

    let nar_bytes = b"simulated-nix-nar-archive-bytes-for-rust-1.97.1";
    fs::write(dir.path().join(".chinwag/rust.nar"), nar_bytes).unwrap();
    let expected_nar_sha = hex::encode(Sha256::digest(nar_bytes));
    let expected_sri = format!(
        "sha256-{}",
        BASE64_STANDARD.encode(Sha256::digest(nar_bytes))
    );

    let mut map = BTreeMap::new();
    map.insert(
        "rust-toolchain".to_owned(),
        StoreClosureEntry {
            store_path: "/nix/store/00000000000000000000000000000000-rust-1.97.1".to_owned(),
            nar_sha256_hex: Some(expected_nar_sha),
            artifact_file: Some(".chinwag/rust.nar".to_owned()),
        },
    );
    fs::write(
        dir.path().join(".chinwag/store-closures.json"),
        serde_json::to_vec_pretty(&map).unwrap(),
    )
    .unwrap();

    let compiled = compile_workspace_env_lock(dir.path()).unwrap();
    let locked = compiled.flake_lock.nodes["rust-toolchain"]
        .locked
        .as_ref()
        .unwrap();
    assert_eq!(locked.nar_hash, expected_sri);
    assert_eq!(
        locked.store_path.as_deref(),
        Some("/nix/store/00000000000000000000000000000000-rust-1.97.1")
    );

    // Encode signer key in OpenSSH `allowed_signers` format and verify strict pinned check
    let sk = SigningKey::from_bytes(&[0x73u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let mut ssh_wire = Vec::with_capacity(51);
    ssh_wire.extend_from_slice(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20");
    ssh_wire.extend_from_slice(&pk);
    let allowed_signers_text = format!(
        "maintainer@example.invalid ssh-ed25519 {} cleanroom\n",
        BASE64_STANDARD.encode(&ssh_wire)
    );
    let parsed_signers = parse_openssh_allowed_signers_ed25519(&allowed_signers_text).unwrap();
    assert_eq!(parsed_signers, vec![pk]);

    let receipt = sign_env_lock_receipt(&compiled, &sk).unwrap();
    write_env_lock_bundle(dir.path(), &compiled, &receipt).unwrap();

    // Empty allowlist MUST fail closed when pinned verification is required
    assert!(verify_env_lock_bundle_with_signers(dir.path(), &[]).is_err());
    // Enrolled OpenSSH signer succeeds
    assert!(verify_env_lock_bundle_with_signers(dir.path(), &parsed_signers).is_ok());
}

#[test]
fn atomic_host_vm_slot_reservation_caps_at_two_concurrent_leases_and_releases_on_drop() {
    let dir = TempDir::new().unwrap();
    let slot_dir = dir.path().join("slots");

    let lease1 = acquire_host_vm_slot(&slot_dir, 2).unwrap();
    assert_eq!(lease1.slot_index(), 1);
    let lease2 = acquire_host_vm_slot(&slot_dir, 2).unwrap();
    assert_eq!(lease2.slot_index(), 2);
    assert_eq!(count_active_slot_leases(&slot_dir, 2), 2);

    // Third concurrent reservation MUST fail closed at 2-VM cap
    assert_eq!(
        acquire_host_vm_slot(&slot_dir, 2).unwrap_err(),
        TrustPoolError::PoolAdmissionRefused("host_two_vm_hypervisor_cap_reached")
    );

    // Dropping slot 1 immediately frees slot 1 for the next caller
    drop(lease1);
    assert_eq!(count_active_slot_leases(&slot_dir, 2), 1);
    let lease1_reacquired = acquire_host_vm_slot(&slot_dir, 2).unwrap();
    assert_eq!(lease1_reacquired.slot_index(), 1);
}

#[test]
fn custom_release_ref_policy_supports_customer_release_branches_and_prefixes() {
    let dir = TempDir::new().unwrap();
    let policy_path = dir.path().join("cleanroom-policy.toml");
    fs::write(
        &policy_path,
        "allowed_exact_refs = [\"refs/heads/trunk\"]\nallowed_ref_prefixes = [\"refs/heads/release/\", \"refs/tags/rel-\"]\n",
    )
    .unwrap();
    let policy = ReleaseRefPolicy::from_toml_file(&policy_path).unwrap();
    assert!(policy.allows_ref("refs/heads/trunk"));
    assert!(policy.allows_ref("refs/heads/release/2026.11"));
    assert!(policy.allows_ref("refs/tags/rel-1.0.0"));
    assert!(!policy.allows_ref("refs/heads/main"));

    let sk = SigningKey::from_bytes(&[0x51u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let oid = "d".repeat(40);
    let att = ReleaseSignerAttestation::sign("refs/heads/release/2026.11", &oid, &sk);
    let ctx = JobTriggerContext {
        requested_profile: RunnerTrustProfile::Release,
        git_ref: "refs/heads/release/2026.11".to_owned(),
        commit_oid: oid,
        is_fork_pr: false,
        is_untrusted_pr_event: false,
        release_attestation: Some(att),
    };
    let dec = evaluate_trust_gate_with_policy(&ctx, &BTreeMap::new(), &[pk], &policy).unwrap();
    assert!(dec.allow_release_keys);
}
