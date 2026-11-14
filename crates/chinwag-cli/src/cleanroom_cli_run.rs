// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! CLI entrypoints for `chinwag env lock` (`INV-NIX-ZERO-SYNTAX-01`) and
//! `chinwag runner start --ephemeral` (`INV-NIX-VIRTIOFS-01`, `INV-NIX-RO-STORE-01`,
//! and `INV-CLEANROOM-TRUST-SPLIT-01`).

use chinwag_cleanroom_vm::{
    CleanroomSeatbeltSpec, EphemeralTartSession, HostHardwareTelemetry, JobTriggerContext,
    PoolAdmissionPolicy, ProcessTartExecutor, RunnerPoolController, RunnerTrustProfile,
    SeatbeltSignalMode, TartCleanroomSpec, ThermalPressure, compile_seatbelt_profile,
    compile_workspace_env_lock, evaluate_trust_gate, generate_receipt_signing_key,
    sign_env_lock_receipt, signing_key_from_seed_file, verify_env_lock_bundle,
    write_env_lock_bundle,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

const ENV_USAGE: &str = "\
Usage: chinwag env lock [--repo <path>] [--check] [--signing-seed-file <path>] [--signer-pubkey-hex <64hex>] [--json]

Deterministically compiles `.chinwag/flake.lock` and a signed verification receipt
from repository manifests with zero `.nix` expression syntax (`INV-NIX-ZERO-SYNTAX-01`).
";

const RUNNER_USAGE: &str = "\
Usage: chinwag runner start --ephemeral [options]

Options:
  --ephemeral                    Required: clone, run headless, and destroy VM after job
  --repo <path>                  Repository worktree path (defaults to current directory)
  --profile <public|release>     Trust profile (`chinwag-ephemeral-public` default)
  --base-image <name>            Cleanroom base VM image (default: `chinwag-macos-sequoia-base`)
  --run-name <name>              Unique ephemeral VM instance name
  --nix-store <path>             Read-only host Nix store path (default: `/nix/store`)
  --sccache <path>               Read-only host sccache path (default: `/var/tmp/chinwag-sccache`)
  --cpu <cores>                  Guest vCPU cores (1..=32, default: 4)
  --memory-mib <mib>             Guest RAM in MiB (2048..=131072, default: 8192)
  --opportunistic                Enforce AC wall power, nominal thermals, and CPU idle headroom
  --ac-power <true|false>        Observed AC wall-power state (default: true)
  --thermal <nominal|fair|serious|critical>
                                 Observed macOS thermal pressure state (default: nominal)
  --cpu-idle <0..=100>           Observed CPU idle percentage (default: 85)
  --active-vms <0..=2>           Active Virtualization.framework VM count on host (default: 0)
  --git-ref <ref>                Triggering Git ref (default: `refs/pull/0/merge`)
  --commit-oid <hex>             40- or 64-char commit OID
  --fork-pr                      Mark trigger as untrusted fork pull request
  --tart-bin <path>              Explicit `tart` binary path (default: `tart`)
  --dry-run                      Validate trust split, pool admission, Seatbelt, and Tart argv without booting VM
  --json                         Emit structured JSON output
";

pub fn run_env_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h" | "help") {
        let _ = write!(stdout, "{ENV_USAGE}");
        return 0;
    }
    if args[0] != "lock" {
        let _ = writeln!(
            stderr,
            "chinwag env: unknown subcommand `{}` (expected `lock`)",
            args[0]
        );
        return 2;
    }

    let mut repo_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut json_mode = false;
    let mut signing_seed_file: Option<PathBuf> = None;
    let mut signer_pubkey_hex: Option<String> = None;

    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "--help" | "-h" => {
                let _ = write!(stdout, "{ENV_USAGE}");
                return 0;
            }
            "--check" => {
                check_only = true;
                idx += 1;
            }
            "--json" => {
                json_mode = true;
                idx += 1;
            }
            "--repo" => {
                let Some(val) = args.get(idx + 1) else {
                    let _ = writeln!(stderr, "chinwag env lock: --repo requires a path");
                    return 2;
                };
                repo_path = Some(PathBuf::from(val));
                idx += 2;
            }
            "--signing-seed-file" => {
                let Some(val) = args.get(idx + 1) else {
                    let _ = writeln!(
                        stderr,
                        "chinwag env lock: --signing-seed-file requires a path"
                    );
                    return 2;
                };
                signing_seed_file = Some(PathBuf::from(val));
                idx += 2;
            }
            "--signer-pubkey-hex" => {
                let Some(val) = args.get(idx + 1) else {
                    let _ = writeln!(
                        stderr,
                        "chinwag env lock: --signer-pubkey-hex requires 64 hex chars"
                    );
                    return 2;
                };
                signer_pubkey_hex = Some(val.clone());
                idx += 2;
            }
            other => {
                let _ = writeln!(stderr, "chinwag env lock: unknown argument `{other}`");
                return 2;
            }
        }
    }

    let root = match repo_path {
        Some(p) => p,
        None => match std::env::current_dir() {
            Ok(cwd) => cwd,
            Err(e) => {
                let _ = writeln!(stderr, "chinwag env lock: failed to resolve cwd: {e}");
                return 1;
            }
        },
    };

    if check_only {
        let pinned_key: Option<[u8; 32]> = match signer_pubkey_hex {
            Some(ref hex_str) => {
                let Ok(bytes) = hex::decode(hex_str.trim()) else {
                    let _ = writeln!(stderr, "chinwag env lock: invalid --signer-pubkey-hex");
                    return 2;
                };
                let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                    let _ = writeln!(
                        stderr,
                        "chinwag env lock: --signer-pubkey-hex must decode to 32 bytes"
                    );
                    return 2;
                };
                Some(arr)
            }
            None => None,
        };

        match verify_env_lock_bundle(&root, pinned_key.as_ref()) {
            Ok(receipt) => {
                if json_mode {
                    let out = json!({
                        "ok": true,
                        "mode": "check",
                        "schema": receipt.schema,
                        "zero_nix_syntax": receipt.zero_nix_syntax,
                        "flake_lock_sha256": receipt.flake_lock_sha256,
                        "closure_sha256": receipt.closure_sha256,
                        "node_nar_hashes": receipt.node_nar_hashes,
                        "signer_public_key_hex": receipt.signer_public_key_hex,
                    });
                    let _ = writeln!(stdout, "{out}");
                } else {
                    let _ = writeln!(
                        stdout,
                        "chinwag env lock --check: verified (.chinwag/flake.lock sha256={})",
                        receipt.flake_lock_sha256
                    );
                }
                0
            }
            Err(err) => {
                if json_mode {
                    let out = json!({
                        "ok": false,
                        "mode": "check",
                        "error": err.to_string(),
                    });
                    let _ = writeln!(stdout, "{out}");
                } else {
                    let _ = writeln!(stderr, "chinwag env lock --check failed: {err}");
                }
                1
            }
        }
    } else {
        let compiled = match compile_workspace_env_lock(&root) {
            Ok(c) => c,
            Err(err) => {
                let _ = writeln!(stderr, "chinwag env lock failed: {err}");
                return 1;
            }
        };
        let signing_key = match signing_seed_file {
            Some(ref seed_path) => match signing_key_from_seed_file(seed_path) {
                Ok(k) => k,
                Err(err) => {
                    let _ = writeln!(stderr, "chinwag env lock signing key error: {err}");
                    return 1;
                }
            },
            None => match generate_receipt_signing_key() {
                Ok(k) => k,
                Err(err) => {
                    let _ = writeln!(stderr, "chinwag env lock entropy error: {err}");
                    return 1;
                }
            },
        };
        let receipt = match sign_env_lock_receipt(&compiled, &signing_key) {
            Ok(r) => r,
            Err(err) => {
                let _ = writeln!(stderr, "chinwag env lock receipt error: {err}");
                return 1;
            }
        };
        let (lock_path, receipt_path) = match write_env_lock_bundle(&root, &compiled, &receipt) {
            Ok(paths) => paths,
            Err(err) => {
                let _ = writeln!(stderr, "chinwag env lock write error: {err}");
                return 1;
            }
        };

        if json_mode {
            let out = json!({
                "ok": true,
                "mode": "lock",
                "lock_file": lock_path.file_name().and_then(|s| s.to_str()).unwrap_or("flake.lock"),
                "receipt_file": receipt_path.file_name().and_then(|s| s.to_str()).unwrap_or("env-lock.receipt.json"),
                "zero_nix_syntax": receipt.zero_nix_syntax,
                "flake_lock_sha256": receipt.flake_lock_sha256,
                "closure_sha256": receipt.closure_sha256,
                "node_nar_hashes": receipt.node_nar_hashes,
                "signer_public_key_hex": receipt.signer_public_key_hex,
                "manifests": receipt.manifests,
            });
            let _ = writeln!(stdout, "{out}");
        } else {
            let _ = writeln!(
                stdout,
                "Wrote .chinwag/flake.lock (closure_sha256={}, nodes={})",
                receipt.closure_sha256,
                receipt.node_nar_hashes.len()
            );
        }
        0
    }
}

pub fn run_runner_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h" | "help") {
        let _ = write!(stdout, "{RUNNER_USAGE}");
        return 0;
    }
    if args[0] != "start" {
        let _ = writeln!(
            stderr,
            "chinwag runner: unknown subcommand `{}` (expected `start`)",
            args[0]
        );
        return 2;
    }

    let mut ephemeral = false;
    let mut repo_path: Option<PathBuf> = None;
    let mut profile_raw = "public".to_owned();
    let mut base_image = "chinwag-macos-sequoia-base".to_owned();
    let mut run_name: Option<String> = None;
    let mut nix_store = PathBuf::from("/nix/store");
    let mut sccache = PathBuf::from("/var/tmp/chinwag-sccache");
    let mut cpu_cores: u8 = 4;
    let mut memory_mib: u32 = 8192;
    let mut opportunistic = false;
    let mut ac_power = true;
    let mut thermal = ThermalPressure::Nominal;
    let mut cpu_idle: u8 = 85;
    let mut active_vms: u8 = 0;
    let mut git_ref = "refs/pull/0/merge".to_owned();
    let mut commit_oid = "0123456789abcdef0123456789abcdef01234567".to_owned();
    let mut fork_pr = false;
    let mut tart_bin = PathBuf::from("tart");
    let mut dry_run = false;
    let mut json_mode = false;

    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "--help" | "-h" => {
                let _ = write!(stdout, "{RUNNER_USAGE}");
                return 0;
            }
            "--ephemeral" => {
                ephemeral = true;
                idx += 1;
            }
            "--opportunistic" => {
                opportunistic = true;
                idx += 1;
            }
            "--fork-pr" => {
                fork_pr = true;
                idx += 1;
            }
            "--dry-run" => {
                dry_run = true;
                idx += 1;
            }
            "--json" => {
                json_mode = true;
                idx += 1;
            }
            flag @ ("--repo" | "--profile" | "--base-image" | "--run-name" | "--nix-store"
            | "--sccache" | "--cpu" | "--memory-mib" | "--ac-power" | "--thermal"
            | "--cpu-idle" | "--active-vms" | "--git-ref" | "--commit-oid"
            | "--tart-bin") => {
                let Some(val) = args.get(idx + 1) else {
                    let _ = writeln!(stderr, "chinwag runner start: {flag} requires a value");
                    return 2;
                };
                match flag {
                    "--repo" => repo_path = Some(PathBuf::from(val)),
                    "--profile" => profile_raw = val.clone(),
                    "--base-image" => base_image = val.clone(),
                    "--run-name" => run_name = Some(val.clone()),
                    "--nix-store" => nix_store = PathBuf::from(val),
                    "--sccache" => sccache = PathBuf::from(val),
                    "--cpu" => match val.parse::<u8>() {
                        Ok(v) => cpu_cores = v,
                        Err(_) => {
                            let _ = writeln!(stderr, "chinwag runner start: invalid --cpu `{val}`");
                            return 2;
                        }
                    },
                    "--memory-mib" => match val.parse::<u32>() {
                        Ok(v) => memory_mib = v,
                        Err(_) => {
                            let _ = writeln!(
                                stderr,
                                "chinwag runner start: invalid --memory-mib `{val}`"
                            );
                            return 2;
                        }
                    },
                    "--ac-power" => match val.as_str() {
                        "true" | "1" => ac_power = true,
                        "false" | "0" => ac_power = false,
                        _ => {
                            let _ = writeln!(
                                stderr,
                                "chinwag runner start: --ac-power expects true or false"
                            );
                            return 2;
                        }
                    },
                    "--thermal" => {
                        thermal = match val.as_str() {
                            "nominal" => ThermalPressure::Nominal,
                            "fair" => ThermalPressure::Fair,
                            "serious" => ThermalPressure::Serious,
                            "critical" => ThermalPressure::Critical,
                            _ => {
                                let _ = writeln!(
                                    stderr,
                                    "chinwag runner start: invalid --thermal `{val}`"
                                );
                                return 2;
                            }
                        };
                    }
                    "--cpu-idle" => match val.parse::<u8>() {
                        Ok(v) if v <= 100 => cpu_idle = v,
                        _ => {
                            let _ = writeln!(
                                stderr,
                                "chinwag runner start: --cpu-idle must be 0..=100"
                            );
                            return 2;
                        }
                    },
                    "--active-vms" => match val.parse::<u8>() {
                        Ok(v) => active_vms = v,
                        Err(_) => {
                            let _ = writeln!(stderr, "chinwag runner start: invalid --active-vms");
                            return 2;
                        }
                    },
                    "--git-ref" => git_ref = val.clone(),
                    "--commit-oid" => commit_oid = val.clone(),
                    "--tart-bin" => tart_bin = PathBuf::from(val),
                    _ => unreachable!(),
                }
                idx += 2;
            }
            other => {
                let _ = writeln!(stderr, "chinwag runner start: unknown argument `{other}`");
                return 2;
            }
        }
    }

    if !ephemeral {
        let _ = writeln!(
            stderr,
            "chinwag runner start: `--ephemeral` is required (persistent mutable cleanroom VMs are prohibited)"
        );
        return 2;
    }

    let profile = match RunnerTrustProfile::parse_label(&profile_raw) {
        Ok(p) => p,
        Err(err) => {
            let _ = writeln!(stderr, "chinwag runner start: {err}");
            return 2;
        }
    };

    let host_env: BTreeMap<String, String> = std::env::vars().collect();
    let trigger_ctx = JobTriggerContext {
        requested_profile: profile,
        git_ref: git_ref.clone(),
        commit_oid: commit_oid.clone(),
        is_fork_pr: fork_pr,
        is_untrusted_pr_event: fork_pr || git_ref.starts_with("refs/pull/"),
        release_attestation: None,
    };

    let trust_decision = match evaluate_trust_gate(&trigger_ctx, &host_env, &[]) {
        Ok(d) => d,
        Err(err) => {
            if json_mode {
                let out = json!({
                    "ok": false,
                    "stage": "trust_gate",
                    "error": err.to_string(),
                });
                let _ = writeln!(stdout, "{out}");
            } else {
                let _ = writeln!(stderr, "chinwag runner start refused: {err}");
            }
            return 1;
        }
    };

    let policy = if opportunistic {
        PoolAdmissionPolicy::opportunistic()
    } else {
        PoolAdmissionPolicy::dedicated()
    };
    let controller = match RunnerPoolController::new(policy) {
        Ok(c) => c,
        Err(err) => {
            let _ = writeln!(stderr, "chinwag runner start pool error: {err}");
            return 1;
        }
    };
    let telemetry = HostHardwareTelemetry {
        ac_power_connected: ac_power,
        thermal_pressure: thermal,
        cpu_idle_percent: cpu_idle,
        active_vm_count: active_vms,
        user_hid_active: false,
    };
    let admission = controller.evaluate_admission(&telemetry);
    if !admission.admitted {
        if json_mode {
            let out = json!({
                "ok": false,
                "stage": "pool_admission",
                "admission": admission,
            });
            let _ = writeln!(stdout, "{out}");
        } else {
            let _ = writeln!(
                stderr,
                "chinwag runner start deferred by host pool policy: {}",
                admission.reason
            );
        }
        return 1;
    }

    let raw_worktree = match repo_path {
        Some(p) => p,
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/private/tmp/chinwag-worktree")),
    };
    let worktree = std::fs::canonicalize(&raw_worktree).unwrap_or(raw_worktree);
    let vm_instance_name = run_name.unwrap_or_else(|| {
        format!(
            "chinwag-cleanroom-slot-{}-{}",
            admission.allocated_slot.unwrap_or(1),
            std::process::id()
        )
    });
    let scratch_dir = PathBuf::from(format!("/private/tmp/{vm_instance_name}-scratch"));

    let seatbelt_spec =
        match CleanroomSeatbeltSpec::new(profile, &nix_store, &sccache, &worktree, &scratch_dir) {
            Ok(s) => s.with_signal_mode(SeatbeltSignalMode::SigKill),
            Err(err) => {
                let _ = writeln!(stderr, "chinwag runner start seatbelt error: {err}");
                return 1;
            }
        };
    let seatbelt = match compile_seatbelt_profile(&seatbelt_spec) {
        Ok(p) => p,
        Err(err) => {
            let _ = writeln!(stderr, "chinwag runner start seatbelt compile error: {err}");
            return 1;
        }
    };

    let tart_spec =
        match TartCleanroomSpec::new(&base_image, &vm_instance_name, &nix_store, &sccache)
            .and_then(|s| s.with_resources(cpu_cores, memory_mib))
        {
            Ok(s) => s,
            Err(err) => {
                let _ = writeln!(stderr, "chinwag runner start VM spec error: {err}");
                return 1;
            }
        };

    if dry_run {
        if json_mode {
            let out = json!({
                "ok": true,
                "dry_run": true,
                "profile": trust_decision.profile.as_str(),
                "allow_release_keys": trust_decision.allow_release_keys,
                "network_policy": trust_decision.network_policy,
                "admission": admission,
                "seatbelt_sha256": seatbelt.sha256_hex,
                "tart_plan": {
                    "clone": tart_spec.clone_argv(),
                    "set": tart_spec.set_resources_argv(),
                    "run": tart_spec.run_argv(),
                    "defer_delete": tart_spec.delete_argv(),
                }
            });
            let _ = writeln!(stdout, "{out}");
        } else {
            let _ = writeln!(
                stdout,
                "Cleanroom dry-run verified: profile={} slot={:?} vm={} seatbelt_sha256={}",
                trust_decision.profile.as_str(),
                admission.allocated_slot,
                tart_spec.run_vm_name(),
                seatbelt.sha256_hex
            );
        }
        return 0;
    }

    let executor = ProcessTartExecutor::new(tart_bin);
    let mut session = match EphemeralTartSession::clone_and_arm(tart_spec, executor) {
        Ok(s) => s,
        Err(err) => {
            let _ = writeln!(stderr, "chinwag runner start clone failed: {err}");
            return 1;
        }
    };
    let run_res = session.run_ephemeral();
    let (_, delete_res) = session.finish();

    match (run_res, delete_res) {
        (Ok(()), Ok(())) => {
            if json_mode {
                let out = json!({
                    "ok": true,
                    "dry_run": false,
                    "profile": trust_decision.profile.as_str(),
                    "vm_deleted": true,
                    "seatbelt_sha256": seatbelt.sha256_hex,
                });
                let _ = writeln!(stdout, "{out}");
            } else {
                let _ = writeln!(stdout, "Ephemeral cleanroom VM completed and destroyed.");
            }
            0
        }
        (Err(run_err), del_outcome) => {
            let _ = writeln!(
                stderr,
                "chinwag runner start execution failed: {run_err} (cleanup_ok={})",
                del_outcome.is_ok()
            );
            1
        }
        (Ok(()), Err(del_err)) => {
            let _ = writeln!(stderr, "chinwag runner start teardown failed: {del_err}");
            1
        }
    }
}
