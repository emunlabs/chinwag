// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use chinwag_cleanroom_vm::{
    CleanroomDiagnosticInput, CleanroomSeatbeltSpec, CleanroomVmError, EnvLockError,
    EphemeralTartSession, GUEST_NIX_STORE_MOUNT, GUEST_SCCACHE_MOUNT, GUEST_WORKTREE_MOUNT,
    HostHardwareTelemetry, JobTriggerContext, MAX_DRAIN_BUDGET_MS, MAX_VIRTIOFS_MOUNT_LATENCY_MS,
    MAX_VMS_PER_MAC_HOST, NetworkEgressPolicy, PoolAdmissionPolicy, ProcessTartExecutor,
    ReleaseRefPolicy, ReleaseSignerAttestation, RunnerPoolController, RunnerTrustProfile,
    RunningTartVm, SeatbeltError, SeatbeltSignalMode, StoreClosureEntry, TartCleanroomSpec,
    TartCommandRecord, TartExecutor, ThermalPressure, TrustPoolError, VirtioFsAccess,
    VirtioFsMount, acquire_host_vm_slot, atomic_write_regular_file, compile_seatbelt_profile,
    compile_workspace_env_lock, count_active_slot_leases, evaluate_trust_gate,
    evaluate_trust_gate_with_policy, generate_receipt_signing_key, generate_recipient_kem_keypair,
    open_failure_diagnostic_bundle, parse_darwin_ioreg_hid_active, parse_darwin_pmset_therm,
    parse_darwin_top_cpu_idle, parse_openssh_allowed_signers_ed25519, reap_dead_slot_leases,
    scrub_diagnostic_secrets, seal_failure_diagnostic_bundle, serialize_nar_v1,
    sign_env_lock_receipt, signing_key_from_seed_file, verify_env_lock_bundle,
    verify_env_lock_bundle_with_signers, verify_env_lock_receipt, verify_host_mount_directory,
    verify_mounted_store_closures, verify_trusted_executable_path, write_env_lock_bundle,
};
use ed25519_dalek::SigningKey;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::rc::Rc;
use tempfile::TempDir;

#[derive(Default)]
struct SharedTartSimState {
    log: Vec<TartCommandRecord>,
    vm_running: bool,
    ready_calls: u32,
}

struct MockRunningTartVm {
    state: Rc<RefCell<SharedTartSimState>>,
    premature_exit: Option<Result<(), String>>,
}

impl RunningTartVm for MockRunningTartVm {
    fn try_poll_exited(&mut self) -> Result<Option<Result<(), String>>, CleanroomVmError> {
        if let Some(outcome) = self.premature_exit.take() {
            self.state.borrow_mut().vm_running = false;
            return Ok(Some(outcome));
        }
        Ok(None)
    }

    fn reap(&mut self) -> Result<(), CleanroomVmError> {
        let mut st = self.state.borrow_mut();
        st.vm_running = false;
        st.log.push(TartCommandRecord {
            step: "reap-run".to_owned(),
            argv: vec![],
        });
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RecordingTartExecutor {
    state: Rc<RefCell<SharedTartSimState>>,
    fail_on_step: Option<&'static str>,
    ready_succeeds_on_attempt: u32,
    premature_run_exit: Option<Result<(), String>>,
}

impl TartExecutor for RecordingTartExecutor {
    fn exec_tart(&mut self, step: &'static str, argv: &[String]) -> Result<(), CleanroomVmError> {
        {
            let mut st = self.state.borrow_mut();
            st.log.push(TartCommandRecord {
                step: step.to_owned(),
                argv: argv.to_vec(),
            });
            if matches!(step, "wait-ready" | "exec") {
                assert!(
                    st.vm_running,
                    "`{step}` invoked while VM is NOT running (would deadlock or fail against real Tart)"
                );
            }
            if step == "delete" {
                assert!(
                    !st.vm_running,
                    "`tart delete` invoked while background `tart run` handle is still un-reaped"
                );
            }
            if step == "wait-ready" {
                st.ready_calls += 1;
                let threshold = self.ready_succeeds_on_attempt.max(1);
                if st.ready_calls < threshold {
                    return Err(CleanroomVmError::TartExecutionFailed {
                        step,
                        detail: "guest agent not yet ready".to_owned(),
                    });
                }
            }
            if step == "stop" {
                st.vm_running = false;
            }
        }
        if self.fail_on_step == Some(step) {
            return Err(CleanroomVmError::TartExecutionFailed {
                step,
                detail: "simulated guest execution failure".to_owned(),
            });
        }
        Ok(())
    }

    fn spawn_tart_run(
        &mut self,
        argv: &[String],
    ) -> Result<Box<dyn RunningTartVm>, CleanroomVmError> {
        {
            let mut st = self.state.borrow_mut();
            st.log.push(TartCommandRecord {
                step: "spawn-run".to_owned(),
                argv: argv.to_vec(),
            });
            if self.fail_on_step == Some("run") {
                return Err(CleanroomVmError::TartExecutionFailed {
                    step: "run",
                    detail: "simulated tart run spawn failure".to_owned(),
                });
            }
            st.vm_running = true;
        }
        Ok(Box::new(MockRunningTartVm {
            state: Rc::clone(&self.state),
            premature_exit: self.premature_run_exit.clone(),
        }))
    }
}

fn write_resolved_store_closures(repo_root: &Path, nodes_and_names: &[(&str, &str, u8)]) {
    let dot_chinwag = repo_root.join(".chinwag");
    fs::create_dir_all(&dot_chinwag).unwrap();
    let mut map = BTreeMap::new();
    for (node, store_suffix, fill) in nodes_and_names {
        map.insert(
            (*node).to_owned(),
            StoreClosureEntry {
                store_path: format!(
                    "/nix/store/{}-{store_suffix}",
                    "a".repeat(31) + &format!("{}", fill % 10)
                ),
                nar_sha256_hex: Some(hex::encode([*fill; 32])),
                artifact_file: None,
            },
        );
    }
    fs::write(
        dot_chinwag.join("store-closures.json"),
        serde_json::to_vec_pretty(&map).unwrap(),
    )
    .unwrap();
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
            "--no-clipboard",
            "--no-audio",
            "--net-softnet",
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
    .unwrap()
    .with_boot_readiness(3, 0);
    let sb_spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Public,
        "/nix/store",
        "/var/tmp/sccache",
        "/private/tmp/worktree-1",
        "/private/tmp/scratch-1",
    )
    .unwrap();
    let seatbelt = compile_seatbelt_profile(&sb_spec).unwrap();
    let guest_cmd = vec!["/usr/bin/true".to_owned()];

    let state = Rc::new(RefCell::new(SharedTartSimState::default()));
    let exec = RecordingTartExecutor {
        state: Rc::clone(&state),
        fail_on_step: None,
        ready_succeeds_on_attempt: 2,
        premature_run_exit: None,
    };

    let mut session = EphemeralTartSession::clone_and_arm(spec.clone(), exec).unwrap();
    session
        .run_ephemeral_with_seatbelt(&seatbelt, &guest_cmd)
        .unwrap();
    let (_, del_res) = session.finish();
    del_res.unwrap();

    let steps: Vec<String> = state.borrow().log.iter().map(|r| r.step.clone()).collect();
    assert_eq!(
        steps,
        vec![
            "clone",
            "set",
            "spawn-run",
            "wait-ready",
            "wait-ready",
            "exec",
            "stop",
            "reap-run",
            "delete"
        ]
    );

    // Verify RAII Drop still reaps & executes `tart delete` once when background `tart run` exits early
    let fail_state = Rc::new(RefCell::new(SharedTartSimState::default()));
    {
        let fail_exec = RecordingTartExecutor {
            state: Rc::clone(&fail_state),
            fail_on_step: None,
            ready_succeeds_on_attempt: 1,
            premature_run_exit: Some(Err("hypervisor boot crash".to_owned())),
        };
        let mut failing_session = EphemeralTartSession::clone_and_arm(spec, fail_exec).unwrap();
        let err = failing_session
            .run_ephemeral_with_seatbelt(&seatbelt, &guest_cmd)
            .unwrap_err();
        assert!(matches!(
            err,
            CleanroomVmError::TartExecutionFailed { step: "run", .. }
        ));
    }
    let fail_steps: Vec<String> = fail_state
        .borrow()
        .log
        .iter()
        .map(|r| r.step.clone())
        .collect();
    assert_eq!(
        fail_steps,
        vec!["clone", "set", "spawn-run", "reap-run", "delete"]
    );
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
        .current_dir(&worktree)
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
        .current_dir(&worktree)
        .args(["-p", &profile.sbpl, "/usr/bin/touch"])
        .arg(&tampered_store_file)
        .output()
        .expect("invoke sandbox-exec deny check");
    assert!(
        !deny_out.status.success(),
        "XNU Seatbelt must block writes to read-only Nix store"
    );
    assert!(!tampered_store_file.exists());

    // 3. Default-deny file-read* (`[F-01]`): reading an unmounted host secret file MUST be kernel-blocked!
    let unmounted_secret_dir = canon.join("host-private-secrets");
    fs::create_dir_all(&unmounted_secret_dir).unwrap();
    let secret_file = unmounted_secret_dir.join("id_ed25519");
    fs::write(&secret_file, b"TOP_SECRET_HOST_KEY").unwrap();
    let deny_read = Command::new("/usr/bin/sandbox-exec")
        .current_dir(&worktree)
        .args(["-p", &profile.sbpl, "/bin/cat"])
        .arg(&secret_file)
        .output()
        .expect("invoke sandbox-exec read deny check");
    assert!(
        !deny_read.status.success(),
        "XNU Seatbelt default-deny file-read* must block reading unmounted host paths"
    );
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
    write_resolved_store_closures(
        dir.path(),
        &[
            ("rust-toolchain", "rust-1.97.1", 0x11),
            ("nodejs-runtime", "nodejs-22.14.0", 0x22),
            ("python-runtime", "python3-3.12.9", 0x33),
            ("go-toolchain", "go-1.24.1", 0x44),
            ("chinwag-env-ts", "jinx-env-v1", 0x55),
        ],
    );

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
    assert!(
        matches!(err2, EnvLockError::ForbiddenNixSyntaxFile(ref f) if f == ".chinwag/shell.nix")
    );
}

#[test]
fn env_lock_bundle_roundtrip_and_tamper_or_drift_rejection() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"cleanroom-demo\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    write_resolved_store_closures(dir.path(), &[("rust-toolchain", "rust-1.97.1", 0x61)]);

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
    host_env.insert(
        "GITHUB_TOKEN".to_owned(),
        concat!("gh", "s_secret_123").to_owned(),
    );
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

    let raw_stderr = concat!(
        "error: test failed\n",
        "Authorization: Bearer secret_live_bearer_999999\n",
        "token=",
        "gh",
        "p_1234567890abcdefghijklmnopqrstuv\n",
        "GITHUB_TOKEN=",
        "gh",
        "s_secret_inline\n",
        "-----BEGIN ",
        "OPENSSH PRIVATE KEY-----\n",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n",
        "-----END ",
        "OPENSSH PRIVATE KEY-----\n",
        "assertion `left == right` failed at line 42"
    );

    let scrubbed_preview = scrub_diagnostic_secrets(raw_stderr);
    assert!(!scrubbed_preview.contains("secret_live_bearer_999999"));
    assert!(!scrubbed_preview.contains(concat!("gh", "p_1234567890")));
    assert!(!scrubbed_preview.contains(concat!("gh", "s_secret_inline")));
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
    write_resolved_store_closures(dir.path(), &[("rust-toolchain", "rust-1.97.1", 0x71)]);
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
    .unwrap()
    .with_boot_readiness(2, 0);
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

    let state = Rc::new(RefCell::new(SharedTartSimState::default()));
    let exec = RecordingTartExecutor {
        state: Rc::clone(&state),
        fail_on_step: None,
        ready_succeeds_on_attempt: 1,
        premature_run_exit: None,
    };
    let mut session = EphemeralTartSession::clone_and_arm(spec.clone(), exec).unwrap();
    session
        .run_ephemeral_with_seatbelt(&seatbelt, &cmd)
        .unwrap();
    let (_, del_res) = session.finish();
    del_res.unwrap();

    let st = state.borrow();
    let steps: Vec<&str> = st.log.iter().map(|r| r.step.as_str()).collect();
    assert_eq!(
        steps,
        vec![
            "clone",
            "set",
            "spawn-run",
            "wait-ready",
            "exec",
            "stop",
            "reap-run",
            "delete"
        ]
    );
    assert_eq!(st.log[4].argv[0], "exec");
    assert_eq!(st.log[4].argv[1], "sandboxed-run-1");
    assert_eq!(st.log[4].argv[2], "--");
    assert_eq!(st.log[4].argv[3], "/usr/bin/sandbox-exec");
    assert_eq!(st.log[4].argv[4], "-p");
    assert!(st.log[4].argv[5].contains("(deny file-write* (subpath \"/nix/store\")"));
    assert_eq!(
        &st.log[4].argv[6..],
        &["--", "/usr/bin/env", "-i", "cargo", "test", "--offline"]
    );
    drop(st);

    // Also verify workload `exec` failure STILL runs `stop` + `reap-run` + `delete`
    let fail_state = Rc::new(RefCell::new(SharedTartSimState::default()));
    {
        let fail_exec = RecordingTartExecutor {
            state: Rc::clone(&fail_state),
            fail_on_step: Some("exec"),
            ready_succeeds_on_attempt: 1,
            premature_run_exit: None,
        };
        let mut s2 = EphemeralTartSession::clone_and_arm(spec, fail_exec).unwrap();
        assert!(matches!(
            s2.run_ephemeral_with_seatbelt(&seatbelt, &cmd),
            Err(CleanroomVmError::TartExecutionFailed { step: "exec", .. })
        ));
    }
    let fail_steps: Vec<String> = fail_state
        .borrow()
        .log
        .iter()
        .map(|r| r.step.clone())
        .collect();
    assert_eq!(
        fail_steps,
        vec![
            "clone",
            "set",
            "spawn-run",
            "wait-ready",
            "exec",
            "stop",
            "reap-run",
            "delete"
        ]
    );
}

#[cfg(unix)]
#[test]
fn env_lock_recursively_rejects_nested_nix_files_in_target_node_modules_and_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"nested-check\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    for sneaky_dir in ["crates/sub/nix", "target/hidden", "node_modules/pkg"] {
        fs::create_dir_all(dir.path().join(sneaky_dir)).unwrap();
        let nix_file = dir.path().join(sneaky_dir).join("overlay.nix");
        fs::write(&nix_file, "{}").unwrap();
        assert!(matches!(
            compile_workspace_env_lock(dir.path()),
            Err(EnvLockError::ForbiddenNixSyntaxFile(_))
        ));
        fs::remove_file(&nix_file).unwrap();
    }

    let innocent = dir.path().join("Cargo.toml");
    symlink(&innocent, dir.path().join("crates/sub/sneaky.nix")).unwrap();
    assert!(matches!(
        compile_workspace_env_lock(dir.path()),
        Err(EnvLockError::ForbiddenNixSyntaxFile(_))
    ));
}

#[test]
fn env_lock_rejects_missing_store_closure_pins_and_verifies_canonical_nar_v1_archive() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use sha2::{Digest, Sha256};

    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"store-pin\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();

    // Missing `.chinwag/store-closures.json` MUST fail closed (never synthesize manifest narHash!)
    assert!(matches!(
        compile_workspace_env_lock(dir.path()),
        Err(EnvLockError::UnresolvedStoreClosure { ref node, .. }) if node == "rust-toolchain"
    ));

    fs::create_dir_all(dir.path().join(".chinwag/payload")).unwrap();
    fs::write(
        dir.path().join(".chinwag/payload/rustc-meta"),
        b"rustc 1.97.1 cleanroom closure",
    )
    .unwrap();
    let nar_bytes = serialize_nar_v1(&dir.path().join(".chinwag/payload")).unwrap();
    assert!(nar_bytes.starts_with(b"\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00"));
    fs::write(dir.path().join(".chinwag/rust.nar"), &nar_bytes).unwrap();
    let expected_nar_sha = hex::encode(Sha256::digest(&nar_bytes));
    let expected_sri = format!(
        "sha256-{}",
        BASE64_STANDARD.encode(Sha256::digest(&nar_bytes))
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
        locked.store_path,
        "/nix/store/00000000000000000000000000000000-rust-1.97.1"
    );

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

    assert!(verify_env_lock_bundle_with_signers(dir.path(), &[]).is_err());
    assert!(verify_env_lock_bundle_with_signers(dir.path(), &parsed_signers).is_ok());

    // Removing `.chinwag/store-closures.json` after locking MUST cause `--check` verification to fail closed!
    fs::remove_file(dir.path().join(".chinwag/store-closures.json")).unwrap();
    assert!(matches!(
        verify_env_lock_bundle_with_signers(dir.path(), &parsed_signers),
        Err(EnvLockError::UnresolvedStoreClosure { .. })
    ));
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

// ============================================================================
// Security Audit Remediation Regression Suite (`[F-01]`..`[F-09]` & `[F-11]`)
// ============================================================================

#[test]
fn f01_seatbelt_default_deny_forbids_allow_default_and_scopes_network_and_reads() {
    let pub_spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Public,
        "/nix/store",
        "/var/tmp/sccache",
        "/private/tmp/worktree-f01",
        "/private/tmp/scratch-f01",
    )
    .unwrap();
    let pub_profile = compile_seatbelt_profile(&pub_spec).unwrap();
    assert!(!pub_profile.sbpl.contains("(allow default)"));
    assert!(pub_profile.sbpl.contains("(deny default)"));
    assert!(pub_profile.sbpl.contains("(deny file-read*)"));
    assert!(pub_profile.sbpl.contains("(deny file-write*)"));
    assert!(pub_profile.sbpl.contains("(deny network*)"));
    assert!(pub_profile.sbpl.contains("(deny network-inbound)"));
    assert!(pub_profile.sbpl.contains("(deny network-bind)"));
    assert!(
        pub_profile
            .sbpl
            .contains("(deny file-read* (regex #\"/\\.ssh(/|$)\"))")
    );
    assert!(
        pub_profile
            .sbpl
            .contains("(deny file-read* (regex #\"/Library/Keychains(/|$)\"))")
    );
    assert!(
        pub_profile
            .sbpl
            .contains("(deny file-read* (regex #\"/Users/[^/]+/\\.chinwag(/|$)\"))")
    );

    // Offline mode emits zero outbound network allow rules
    let offline_spec = pub_spec
        .clone()
        .with_network_policy(NetworkEgressPolicy::Offline)
        .unwrap();
    let offline_profile = compile_seatbelt_profile(&offline_spec).unwrap();
    assert!(!offline_profile.sbpl.contains("(allow network-outbound"));

    // Public profile cannot enable release upload/notarization network policy
    assert_eq!(
        pub_spec.with_network_policy(NetworkEgressPolicy::ScopedReleaseUploadAndNotarization),
        Err(SeatbeltError::NetworkPolicyProfileMismatch(
            NetworkEgressPolicy::ScopedReleaseUploadAndNotarization
        ))
    );

    // Release profile ALSO retains Keychain, SSH, and ~/.chinwag denies
    let rel_spec = CleanroomSeatbeltSpec::new(
        RunnerTrustProfile::Release,
        "/nix/store",
        "/var/tmp/sccache",
        "/private/tmp/worktree-rel-f01",
        "/private/tmp/scratch-rel-f01",
    )
    .unwrap();
    let rel_profile = compile_seatbelt_profile(&rel_spec).unwrap();
    assert!(!rel_profile.sbpl.contains("(allow default)"));
    assert!(
        rel_profile
            .sbpl
            .contains("(deny file-read* (regex #\"/\\.ssh(/|$)\"))")
    );
    assert!(
        rel_profile
            .sbpl
            .contains("(deny file-read* (regex #\"/Library/Keychains(/|$)\"))")
    );
    assert!(
        rel_profile
            .sbpl
            .contains("(deny file-read* (regex #\"/Users/[^/]+/\\.chinwag(/|$)\"))")
    );
}

#[test]
fn f02_seatbelt_rejects_repeated_slashes_root_mounts_and_canonicalizes_var_tmp_overlap() {
    for invalid in [
        "/nix//store",
        "/var/tmp//sccache",
        "/",
        "/Users",
        "/System",
        "/tmp",
        "/nix/store/",
    ] {
        assert!(
            matches!(
                CleanroomSeatbeltSpec::new(
                    RunnerTrustProfile::Public,
                    invalid,
                    "/var/tmp/sccache",
                    "/private/tmp/worktree",
                    "/private/tmp/scratch",
                ),
                Err(SeatbeltError::InvalidPath(_))
            ),
            "expected `{invalid}` to fail strict SBPL normalization"
        );
    }

    // `/var/tmp/shared-ro` canonicalizes to `/private/var/tmp/shared-ro`, catching overlap!
    assert!(matches!(
        CleanroomSeatbeltSpec::new(
            RunnerTrustProfile::Public,
            "/nix/store",
            "/var/tmp/shared-ro",
            "/private/var/tmp/shared-ro/nested-worktree",
            "/private/tmp/scratch",
        ),
        Err(SeatbeltError::ReadOnlyOverlap(_, _))
    ));
}

#[test]
fn f03_seatbelt_serde_try_from_blocks_bypass_and_guest_virtiofs_hides_host_paths() {
    let overlap_json = r#"{
        "trust_profile": "chinwag-ephemeral-public",
        "nix_store_path": "/nix/store",
        "sccache_path": "/private/var/tmp/sccache",
        "writable_worktree": "/nix/store/sneaky-overlap",
        "writable_scratch": "/private/tmp/scratch"
    }"#;
    assert!(serde_json::from_str::<CleanroomSeatbeltSpec>(overlap_json).is_err());

    let public_rel_json = r#"{
        "trust_profile": "chinwag-ephemeral-public",
        "nix_store_path": "/nix/store",
        "sccache_path": "/private/var/tmp/sccache",
        "writable_worktree": "/private/tmp/worktree",
        "writable_scratch": "/private/tmp/scratch",
        "release_signing_dir": "/private/tmp/signing-lease"
    }"#;
    assert!(serde_json::from_str::<CleanroomSeatbeltSpec>(public_rel_json).is_err());

    let guest_spec = CleanroomSeatbeltSpec::for_guest_virtiofs(
        RunnerTrustProfile::Public,
        "vm-pr-97",
        "/private/tmp",
    )
    .unwrap();
    let guest_sbpl = compile_seatbelt_profile(&guest_spec).unwrap();
    assert!(guest_sbpl.sbpl.contains(GUEST_NIX_STORE_MOUNT));
    assert!(guest_sbpl.sbpl.contains(GUEST_SCCACHE_MOUNT));
    assert!(guest_sbpl.sbpl.contains(GUEST_WORKTREE_MOUNT));
    assert!(guest_sbpl.sbpl.contains("/private/tmp/vm-pr-97-worktree"));
    assert!(guest_sbpl.sbpl.contains("/private/tmp/vm-pr-97-scratch"));
}

#[test]
fn f04_tart_run_argv_enforces_no_clipboard_no_audio_and_softnet_cidr_policy() {
    let base =
        TartCleanroomSpec::new("base-img", "run-vm-4", "/nix/store", "/var/tmp/sccache").unwrap();
    let argv = base.run_argv();
    assert!(argv.contains(&"--no-graphics".to_owned()));
    assert!(argv.contains(&"--no-clipboard".to_owned()));
    assert!(argv.contains(&"--no-audio".to_owned()));
    assert!(argv.contains(&"--net-softnet".to_owned()));

    let offline = base
        .clone()
        .with_network_egress(NetworkEgressPolicy::Offline, vec!["1.1.1.1/32".to_owned()])
        .unwrap();
    assert!(
        offline
            .run_argv()
            .contains(&"--net-softnet-allow=127.0.0.1/32".to_owned())
    );

    let scoped = base
        .clone()
        .with_network_egress(
            NetworkEgressPolicy::RegistriesAndBinaryCacheOnly,
            vec!["1.1.1.1/32".to_owned(), "2606:4700::/32".to_owned()],
        )
        .unwrap();
    assert!(
        scoped
            .run_argv()
            .contains(&"--net-softnet-allow=1.1.1.1/32,2606:4700::/32".to_owned())
    );

    for bad_cidr in [
        "-inject/32",
        "10.0.0.1",
        "10.0.0.1/33",
        "10.0.0.1/24,0.0.0.0/0",
        "not-an-ip/24",
    ] {
        assert!(matches!(
            base.clone().with_network_egress(
                NetworkEgressPolicy::RegistriesAndBinaryCacheOnly,
                vec![bad_cidr.to_owned()]
            ),
            Err(CleanroomVmError::InvalidEgressCidr(_))
        ));
    }
}

#[cfg(unix)]
#[test]
fn f05_virtiofs_and_tart_spec_serde_and_live_host_mount_reject_symlinks_and_broad_roots() {
    use std::os::unix::fs::symlink;

    for blocked in [
        "/",
        "/Users",
        "/Users/alice",
        "/Users/alice/.ssh",
        "/Users/alice/.chinwag",
        "/Users/alice/Library/Keychains",
        "/System/Library",
        "/Volumes/MacintoshHD",
        "/private/etc/ssl",
        "/etc/ssl",
        "/var/root/secret",
    ] {
        assert!(
            VirtioFsMount::read_only("worktree", blocked, VirtioFsAccess::ReadOnly).is_err(),
            "broad or sensitive host path `{blocked}` must be rejected"
        );
    }

    // Deserializing `:rw` or `run_vm_name == base_image` via serde_json MUST fail closed!
    assert!(
        serde_json::from_str::<VirtioFsMount>(
            r#"{"tag":"nix-store","host_path":"/nix/store","access":"read_write"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<TartCleanroomSpec>(
            r#"{
                "base_image": "same-vm",
                "run_vm_name": "same-vm",
                "nix_store_mount": {"tag":"nix-store","host_path":"/nix/store"},
                "sccache_mount": {"tag":"sccache","host_path":"/var/tmp/sccache"}
            }"#
        )
        .is_err()
    );

    let tmp = TempDir::new().unwrap();
    let real_dir = tmp.path().join("real-mount");
    fs::create_dir_all(&real_dir).unwrap();
    assert!(verify_host_mount_directory(&real_dir).is_ok());

    let sym_dir = tmp.path().join("sym-mount");
    symlink(&real_dir, &sym_dir).unwrap();
    assert!(matches!(
        verify_host_mount_directory(&sym_dir),
        Err(CleanroomVmError::InvalidMountPath(_))
    ));
}

#[cfg(unix)]
#[test]
fn f06_process_tart_executor_drains_large_stderr_without_deadlock_and_validates_bin_and_nul() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let tmp = TempDir::new().unwrap();
    let nix_dir = tmp.path().join("nix-store");
    let sccache_dir = tmp.path().join("sccache");
    fs::create_dir_all(&nix_dir).unwrap();
    fs::create_dir_all(&sccache_dir).unwrap();

    // Reject relative PATH, symlinks, and world-writable binaries
    assert!(verify_trusted_executable_path(Path::new("tart")).is_err());
    assert!(verify_trusted_executable_path(Path::new("./tart")).is_err());

    let mock_tart = tmp.path().join("tart-flood.sh");
    // `run` floods >192 KiB to stderr (3x 64 KiB pipe capacity!) then sleeps until stopped;
    // without `spawn_bounded_stderr_drain`, the child blocks on write(2) and deadlocks!
    fs::write(
        &mock_tart,
        "#!/bin/sh\ncase \"$1\" in\n  clone|set|exec|stop|delete) exit 0 ;;\n  run)\n    dd if=/dev/zero bs=1024 count=196 2>/dev/null | tr '\\0' 'E' >&2\n    sleep 2\n    exit 0\n    ;;\n  *) exit 1 ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&mock_tart, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        verify_trusted_executable_path(&mock_tart).is_err(),
        "world-writable tart binary must fail closed"
    );
    fs::set_permissions(&mock_tart, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(verify_trusted_executable_path(&mock_tart).is_ok());

    let sym_bin = tmp.path().join("tart-sym.sh");
    symlink(&mock_tart, &sym_bin).unwrap();
    assert!(verify_trusted_executable_path(&sym_bin).is_err());

    let spec = TartCleanroomSpec::new("base-v1", "flood-vm-1", &nix_dir, &sccache_dir)
        .unwrap()
        .with_boot_readiness(4, 10);
    let sb = compile_seatbelt_profile(
        &CleanroomSeatbeltSpec::for_guest_virtiofs(
            RunnerTrustProfile::Public,
            "flood-vm-1",
            "/private/tmp",
        )
        .unwrap(),
    )
    .unwrap();

    // Reject NUL bytes and leading `-` in guest_command
    assert!(
        spec.guest_sandbox_exec_argv(&sb, &["/usr/bin/echo".into(), "bad\0arg".into()])
            .is_err()
    );
    assert!(
        spec.guest_sandbox_exec_argv(&sb, &["-flag".into()])
            .is_err()
    );

    let exec = ProcessTartExecutor::new(&mock_tart);
    let mut session = EphemeralTartSession::clone_and_arm(spec, exec).unwrap();
    session
        .run_ephemeral_with_seatbelt(&sb, &["/usr/bin/true".to_owned()])
        .expect("stderr flood >64 KiB must drain without deadlocking");
    assert!(session.startup_telemetry().is_some());
    let (_, del_res) = session.finish();
    del_res.unwrap();
}

#[cfg(unix)]
#[test]
fn f07_env_lock_rejects_intermediate_dir_symlinks_arbitrary_symlinks_and_hardlinked_manifests() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "outside-data").unwrap();

    let ws = tmp.path().join("ws");
    fs::create_dir_all(&ws).unwrap();
    fs::write(
        ws.join("Cargo.toml"),
        "[package]\nname = \"f07\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    write_resolved_store_closures(&ws, &[("rust-toolchain", "rust-1.97.1", 0x31)]);
    assert!(compile_workspace_env_lock(&ws).is_ok());

    // 1. Arbitrary non-.nix file symlink inside repo_root MUST fail closed
    symlink(outside.join("secret.txt"), ws.join("notes.txt")).unwrap();
    assert!(matches!(
        compile_workspace_env_lock(&ws),
        Err(EnvLockError::SymlinkForbidden(ref p)) if p == "notes.txt"
    ));
    fs::remove_file(ws.join("notes.txt")).unwrap();

    // 2. Intermediate directory symlink inside repo_root MUST fail closed
    symlink(&outside, ws.join("linked-dir")).unwrap();
    assert!(matches!(
        compile_workspace_env_lock(&ws),
        Err(EnvLockError::SymlinkForbidden(ref p)) if p == "linked-dir"
    ));
    fs::remove_file(ws.join("linked-dir")).unwrap();

    // 3. Hard-linked manifest (`st_nlink > 1`) MUST fail closed
    let hard_copy = tmp.path().join("cargo-hardlink.toml");
    fs::hard_link(ws.join("Cargo.toml"), &hard_copy).unwrap();
    assert!(matches!(
        compile_workspace_env_lock(&ws),
        Err(EnvLockError::ManifestParse { ref path, .. }) if path == "Cargo.toml"
    ));
    fs::remove_file(&hard_copy).unwrap();
    assert!(compile_workspace_env_lock(&ws).is_ok());
}

#[cfg(unix)]
#[test]
fn f08_nar_v1_supports_intra_store_relative_symlinks_rejects_escape_and_checks_manifest_list_parity()
 {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let mock_store = tmp.path().join("nix-store");
    let pkg_root = mock_store.join("00000000000000000000000000000000-rust-1.97.1");
    fs::create_dir_all(pkg_root.join("bin")).unwrap();
    fs::create_dir_all(pkg_root.join("lib")).unwrap();
    fs::write(pkg_root.join("lib/rustc-driver"), b"rustc-binary-v1").unwrap();
    // Valid intra-store relative symlink (`bin/rustc -> ../lib/rustc-driver`)
    symlink("../lib/rustc-driver", pkg_root.join("bin/rustc")).unwrap();

    let nar_ok = serialize_nar_v1(&pkg_root).expect("intra-store relative symlink must serialize");
    assert_eq!(nar_ok, serialize_nar_v1(&pkg_root).unwrap());
    let nar_sha_hex = hex::encode(Sha256::digest(&nar_ok));

    // Escaping relative symlink (`../../outside`) or absolute symlink (`/etc/passwd`) MUST fail closed!
    let bad_store = tmp.path().join("bad-store");
    fs::create_dir_all(bad_store.join("bin")).unwrap();
    symlink("../../outside", bad_store.join("bin/escape")).unwrap();
    assert!(serialize_nar_v1(&bad_store).is_err());

    let abs_store = tmp.path().join("abs-store");
    fs::create_dir_all(&abs_store).unwrap();
    symlink("/etc/hosts", abs_store.join("hosts")).unwrap();
    assert!(serialize_nar_v1(&abs_store).is_err());

    // Verify `receipt.manifests == compiled.manifests` & `verify_mounted_store_closures`
    let ws = tmp.path().join("ws");
    fs::create_dir_all(ws.join(".chinwag")).unwrap();
    fs::write(
        ws.join("Cargo.toml"),
        "[package]\nname = \"f08\"\nversion = \"0.1.0\"\nrust-version = \"1.97.1\"\n",
    )
    .unwrap();
    let mut closures = BTreeMap::new();
    closures.insert(
        "rust-toolchain".to_owned(),
        StoreClosureEntry {
            store_path: "/nix/store/00000000000000000000000000000000-rust-1.97.1".to_owned(),
            nar_sha256_hex: Some(nar_sha_hex),
            artifact_file: None,
        },
    );
    fs::write(
        ws.join(".chinwag/store-closures.json"),
        serde_json::to_vec_pretty(&closures).unwrap(),
    )
    .unwrap();

    let compiled = compile_workspace_env_lock(&ws).unwrap();
    let sk = SigningKey::from_bytes(&[0x48u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let receipt = sign_env_lock_receipt(&compiled, &sk).unwrap();
    write_env_lock_bundle(&ws, &compiled, &receipt).unwrap();

    // Realized store directory matches locked narHash -> passes!
    verify_mounted_store_closures(&ws, &mock_store).unwrap();

    // Tamper realized store file without updating lock -> fails closed with `LockfileDrift`!
    fs::write(pkg_root.join("lib/rustc-driver"), b"tampered-rustc").unwrap();
    assert!(matches!(
        verify_mounted_store_closures(&ws, &mock_store),
        Err(EnvLockError::LockfileDrift(_))
    ));

    // Re-sign a receipt with truncated `manifests` list -> `verify_env_lock_bundle_with_signers` rejects!
    let mut forged_compiled = compiled.clone();
    forged_compiled.manifests.truncate(1);
    let forged_receipt = sign_env_lock_receipt(&forged_compiled, &sk).unwrap();
    write_env_lock_bundle(&ws, &compiled, &forged_receipt).unwrap();
    assert!(matches!(
        verify_env_lock_bundle_with_signers(&ws, &[pk]),
        Err(EnvLockError::LockfileDrift(_))
    ));
}

#[cfg(unix)]
#[test]
fn f09_guest_env_i_populates_sanitized_env_and_scrubber_redacts_json_urls_multi_bearer_and_all_token_families()
 {
    use std::os::unix::fs::PermissionsExt;

    let spec =
        TartCleanroomSpec::new("base-img", "env-vm-9", "/nix/store", "/var/tmp/sccache").unwrap();
    let sb = compile_seatbelt_profile(
        &CleanroomSeatbeltSpec::for_guest_virtiofs(
            RunnerTrustProfile::Public,
            "env-vm-9",
            "/private/tmp",
        )
        .unwrap(),
    )
    .unwrap();
    let mut env_map = BTreeMap::new();
    env_map.insert("CHINWAG_CLEANROOM_TIER".to_owned(), "public".to_owned());
    env_map.insert("LANG".to_owned(), "C.UTF-8".to_owned());
    let argv = spec
        .guest_sandbox_exec_with_env_argv(&sb, &env_map, &["cargo".into(), "test".into()])
        .unwrap();
    assert_eq!(
        &argv[6..],
        &[
            "--",
            "/usr/bin/env",
            "-i",
            "CHINWAG_CLEANROOM_TIER=public",
            "LANG=C.UTF-8",
            "cargo",
            "test"
        ]
    );

    let dirty = concat!(
        "{\"openai\":\"",
        "sk-",
        "proj-1234567890abcdefghijklmnop\",",
        "\"jwt\":\"",
        "ey",
        "JhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2\"}\n",
        "url=https://ci.example.invalid/cb?tok=",
        "gh",
        "p_1234567890abcdefghijklmnopqrstuv&slack=",
        "xox",
        "b-1234567890-abcdefghij\n",
        "hdrs: Authorization: Bearer   first_live_secret_111 , Proxy-Auth: bearer\tsecond_live_secret_222\n",
        "chinwag1=",
        "chwg_",
        "live_abcdef0123456789 chinwag2=",
        "chwg_",
        "agent_9876543210abcdef rk=",
        "rk",
        "-live-1234567890abcdef\n",
        "gitlab=",
        "gl",
        "pat-1234567890abcdefghij aws1=",
        "AK",
        "IA1234567890ABCDEF aws2=",
        "AS",
        "IA1234567890ABCDEF\n",
        "ANTHROPIC_API_KEY=custom_anth_val_999 OPENAI_ORG_KEY=org_val_888 GEMINI_API_KEY=",
        "AI",
        "zaSyA1234567890abcdefghijk VERCEL_TOKEN=",
        "vc",
        "p_1234567890abcdef\n",
        "UNUSUAL_LHS_NAME=",
        "sk-",
        "ant-api03-secretvalue1234567890"
    );
    let clean = scrub_diagnostic_secrets(dirty);
    for forbidden in [
        concat!("sk-", "proj-1234567890"),
        concat!("ey", "JhbGciOiJFZERTQSJ9"),
        concat!("gh", "p_1234567890"),
        concat!("xox", "b-1234567890"),
        "first_live_secret_111",
        "second_live_secret_222",
        concat!("chwg_", "live_abcdef"),
        concat!("chwg_", "agent_987654"),
        concat!("rk", "-live-123456"),
        concat!("gl", "pat-123456"),
        concat!("AK", "IA1234567890ABCDEF"),
        concat!("AS", "IA1234567890ABCDEF"),
        "custom_anth_val_999",
        "org_val_888",
        concat!("AI", "zaSyA1234567890"),
        concat!("vc", "p_1234567890"),
        concat!("sk-", "ant-api03-secretvalue"),
    ] {
        assert!(
            !clean.contains(forbidden),
            "scrubber failed to redact `{forbidden}` in:\n{clean}"
        );
    }

    let tmp = TempDir::new().unwrap();
    let bundle_file = tmp.path().join("sealed-0600.json");
    atomic_write_regular_file(&bundle_file, b"{\"ok\":true}\n", 0o600).unwrap();
    let mode = fs::symlink_metadata(&bundle_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn f11_cleanroom_policy_toml_darwin_parsers_0700_slot_dir_and_dead_pid_lease_reaping() {
    use std::os::unix::fs::PermissionsExt;

    assert_eq!(
        parse_darwin_pmset_therm(
            "Note: No thermal warning level has been recorded\n\tCPU_Speed_Limit = 100\n"
        ),
        ThermalPressure::Nominal
    );
    assert_eq!(
        parse_darwin_pmset_therm("\tCPU_Speed_Limit = 85\n"),
        ThermalPressure::Fair
    );
    assert_eq!(
        parse_darwin_pmset_therm("\tCPU_Speed_Limit = 60\n"),
        ThermalPressure::Serious
    );
    assert!(parse_darwin_ioreg_hid_active("    |   \"HIDIdleTime\" = 5000000000\n").unwrap());
    assert!(!parse_darwin_ioreg_hid_active("    |   \"HIDIdleTime\" = 45000000000\n").unwrap());
    assert_eq!(
        parse_darwin_top_cpu_idle("CPU usage: 8.12% user, 4.38% sys, 87.50% idle\n").unwrap(),
        87
    );

    let tmp = TempDir::new().unwrap();
    let policy_path = tmp.path().join("cleanroom-policy.toml");
    fs::write(
        &policy_path,
        r#"
allowed_exact_refs = ["refs/heads/main"]
allowed_ref_prefixes = ["refs/tags/v"]
base_image = "org-custom-sequoia-v2"
nix_store_path = "/nix/store"
nix_daemon_socket_dir = "/nix/var/nix/custom-daemon"
nix_daemon_socket_path = "/nix/var/nix/custom-daemon/socket"
sccache_dir = "/private/var/tmp/org-sccache"
guest_scratch_root = "/private/var/tmp"
release_lease_env_keys = ["ORG_NOTARY_LEASE"]
allowed_egress_cidrs = ["203.0.113.0/24"]
"#,
    )
    .unwrap();
    let policy = ReleaseRefPolicy::from_toml_file(&policy_path).unwrap();
    assert_eq!(policy.base_image, "org-custom-sequoia-v2");
    assert_eq!(policy.allowed_egress_cidrs, vec!["203.0.113.0/24"]);

    let sk = SigningKey::from_bytes(&[0x77u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let oid = "f".repeat(40);
    let att = ReleaseSignerAttestation::sign("refs/heads/main", &oid, &sk);
    let mut host_env = BTreeMap::new();
    host_env.insert("ORG_NOTARY_LEASE".to_owned(), "lease-ok".to_owned());
    host_env.insert(
        "APPLE_DEVELOPER_ID_LEASE".to_owned(),
        "not-in-custom-policy".to_owned(),
    );
    let rel_dec = evaluate_trust_gate_with_policy(
        &JobTriggerContext {
            requested_profile: RunnerTrustProfile::Release,
            git_ref: "refs/heads/main".to_owned(),
            commit_oid: oid,
            is_fork_pr: false,
            is_untrusted_pr_event: false,
            release_attestation: Some(att),
        },
        &host_env,
        &[pk],
        &policy,
    )
    .unwrap();
    assert_eq!(
        rel_dec
            .sanitized_env
            .get("ORG_NOTARY_LEASE")
            .map(String::as_str),
        Some("lease-ok")
    );
    assert!(
        !rel_dec
            .sanitized_env
            .contains_key("APPLE_DEVELOPER_ID_LEASE")
    );

    // 0755 slot_dir MUST fail closed (`0700` required)
    let insecure_slots = tmp.path().join("slots-0755");
    fs::create_dir_all(&insecure_slots).unwrap();
    fs::set_permissions(&insecure_slots, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(acquire_host_vm_slot(&insecure_slots, 2).is_err());

    // 0700 slot_dir with stale dead-PID lease (`pid=99999999`) reaps dead lease and acquires slot 1!
    let secure_slots = tmp.path().join("slots-0700");
    fs::create_dir_all(&secure_slots).unwrap();
    fs::set_permissions(&secure_slots, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(secure_slots.join("slot-1.lease"), "pid=99999999\nslot=1\n").unwrap();
    assert_eq!(reap_dead_slot_leases(&secure_slots, 2).unwrap(), 1);
    let lease = acquire_host_vm_slot(&secure_slots, 2).unwrap();
    assert_eq!(lease.slot_index(), 1);
}
