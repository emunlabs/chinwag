// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! CLI entrypoints for `chinwag env lock` (`INV-NIX-ZERO-SYNTAX-01`) and
//! `chinwag runner start --ephemeral` (`INV-NIX-VIRTIOFS-01`, `INV-NIX-RO-STORE-01`,
//! and `INV-CLEANROOM-TRUST-SPLIT-01`).

use chinwag_cleanroom_vm::{
    CleanroomDiagnosticInput, CleanroomSeatbeltSpec, EphemeralTartSession, HostHardwareTelemetry,
    JobTriggerContext, PoolAdmissionPolicy, ProcessTartExecutor, ReleaseRefPolicy,
    ReleaseSignerAttestation, RunnerPoolController, RunnerTrustProfile, SeatbeltSignalMode,
    TartCleanroomSpec, ThermalPressure, acquire_host_vm_slot, compile_seatbelt_profile,
    compile_workspace_env_lock, evaluate_trust_gate_with_policy, generate_receipt_signing_key,
    load_allowed_signers_file, probe_host_hardware_telemetry, seal_failure_diagnostic_bundle,
    sign_env_lock_receipt, signing_key_from_seed_file, verify_env_lock_bundle,
    verify_env_lock_bundle_with_signers, write_env_lock_bundle,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const ENV_USAGE: &str = "\
Usage: chinwag env lock [--repo <path>] [--check] [--signing-seed-file <path>] [--signer-pubkey-hex <64hex>] [--allowed-signers <path>] [--allow-unpinned-receipt] [--json]

Deterministically compiles `.chinwag/flake.lock` and a signed verification receipt
from repository manifests with zero `.nix` expression syntax (`INV-NIX-ZERO-SYNTAX-01`).
";

const RUNNER_USAGE: &str = "\
Usage: chinwag runner start --ephemeral [options] [-- <guest-command...>]

Options:
  --ephemeral                    Required: clone, run headless under Seatbelt, and destroy VM after job
  --repo <path>                  Repository worktree path (defaults to current directory)
  --profile <public|release>     Trust profile (`chinwag-ephemeral-public` default)
  --base-image <name>            Cleanroom base VM image (default: `chinwag-macos-sequoia-base`)
  --run-name <name>              Unique ephemeral VM instance name
  --nix-store <path>             Read-only host Nix store path (default: `/nix/store`)
  --sccache <path>               Read-only host sccache path (default: `/var/tmp/chinwag-sccache`)
  --slot-dir <path>              Shared atomic hypervisor slot lease dir (default: `/var/tmp/chinwag-cleanroom-slots`)
  --cpu <cores>                  Guest vCPU cores (1..=32, default: 4)
  --memory-mib <mib>             Guest RAM in MiB (2048..=131072, default: 8192)
  --opportunistic                Enforce AC wall power, nominal thermals, and CPU idle headroom
  --ac-power <true|false>        Override probed AC wall-power state
  --thermal <nominal|fair|serious|critical>
                                 Override probed macOS thermal pressure state
  --cpu-idle <0..=100>           Override probed CPU idle percentage
  --active-vms <0..=2>           Override probed active VM slot lease count
  --git-ref <ref>                Triggering Git ref (default: `refs/pull/0/merge`)
  --commit-oid <hex>             40- or 64-char commit OID
  --fork-pr                      Mark trigger as untrusted fork pull request
  --release-attestation-file <p> JSON `ReleaseSignerAttestation` for `--profile release`
  --allowed-signers <path>       OpenSSH `allowed_signers` file (defaults to `<repo>/.chinwag/allowed_signers`)
  --allow-release-ref <ref>      Additional exact protected Git ref for `--profile release`
  --allow-release-prefix <pref>  Additional protected Git ref prefix for `--profile release`
  --seal-failure-bundle <path>   Write `SealedFailureBundleV1` (`X25519-MLKEM768`) if execution fails
  --diagnostic-recipient-pubkey-file <path>
                                 1,216-byte `X25519-MLKEM768` recipient public key (raw or hex) for `--seal-failure-bundle`
  --runner-signing-seed-file <p> Optional 32-byte hex `Ed25519` runner seed for `--seal-failure-bundle`
  --tart-bin <path>              Explicit `tart` binary path (default: `tart`)
  --command <arg>                Guest command token executed under `/usr/bin/sandbox-exec` (repeatable)
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
    let mut allowed_signers_path: Option<PathBuf> = None;
    let mut allow_unpinned_receipt = false;

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
            "--allow-unpinned-receipt" => {
                allow_unpinned_receipt = true;
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
            "--allowed-signers" => {
                let Some(val) = args.get(idx + 1) else {
                    let _ = writeln!(
                        stderr,
                        "chinwag env lock: --allowed-signers requires a path"
                    );
                    return 2;
                };
                allowed_signers_path = Some(PathBuf::from(val));
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
        let mut pinned_keys: Vec<[u8; 32]> = Vec::new();
        if let Some(ref hex_str) = signer_pubkey_hex {
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
            pinned_keys.push(arr);
        } else if let Some(ref signers_file) = allowed_signers_path {
            match load_allowed_signers_file(signers_file) {
                Ok(keys) => pinned_keys = keys,
                Err(err) => {
                    emit_check_failure(json_mode, stdout, stderr, &err.to_string());
                    return 1;
                }
            }
        } else {
            let default_signers = root.join(".chinwag").join("allowed_signers");
            if default_signers.exists() {
                match load_allowed_signers_file(&default_signers) {
                    Ok(keys) => pinned_keys = keys,
                    Err(err) => {
                        emit_check_failure(json_mode, stdout, stderr, &err.to_string());
                        return 1;
                    }
                }
            }
        }

        let check_res = if pinned_keys.is_empty() && allow_unpinned_receipt {
            verify_env_lock_bundle(&root, None)
        } else {
            verify_env_lock_bundle_with_signers(&root, &pinned_keys)
        };

        match check_res {
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
                        "pinned_signer_verified": !allow_unpinned_receipt || !pinned_keys.is_empty(),
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
                emit_check_failure(json_mode, stdout, stderr, &err.to_string());
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

fn emit_check_failure(
    json_mode: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    message: &str,
) {
    if json_mode {
        let out = json!({
            "ok": false,
            "mode": "check",
            "error": message,
        });
        let _ = writeln!(stdout, "{out}");
    } else {
        let _ = writeln!(stderr, "chinwag env lock --check failed: {message}");
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
    let mut slot_dir = PathBuf::from("/var/tmp/chinwag-cleanroom-slots");
    let mut cpu_cores: u8 = 4;
    let mut memory_mib: u32 = 8192;
    let mut opportunistic = false;
    let mut ac_power_override: Option<bool> = None;
    let mut thermal_override: Option<ThermalPressure> = None;
    let mut cpu_idle_override: Option<u8> = None;
    let mut active_vms_override: Option<u8> = None;
    let mut git_ref = "refs/pull/0/merge".to_owned();
    let mut commit_oid = "0123456789abcdef0123456789abcdef01234567".to_owned();
    let mut fork_pr = false;
    let mut release_attestation_file: Option<PathBuf> = None;
    let mut allowed_signers_file: Option<PathBuf> = None;
    let mut extra_exact_refs: Vec<String> = Vec::new();
    let mut extra_ref_prefixes: Vec<String> = Vec::new();
    let mut seal_failure_bundle_out: Option<PathBuf> = None;
    let mut diagnostic_recipient_pk_file: Option<PathBuf> = None;
    let mut runner_signing_seed_file: Option<PathBuf> = None;
    let mut tart_bin = PathBuf::from("tart");
    let mut guest_command: Vec<String> = Vec::new();
    let mut dry_run = false;
    let mut json_mode = false;

    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "--help" | "-h" => {
                let _ = write!(stdout, "{RUNNER_USAGE}");
                return 0;
            }
            "--" => {
                guest_command.extend_from_slice(&args[idx + 1..]);
                break;
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
            flag @ ("--repo"
            | "--profile"
            | "--base-image"
            | "--run-name"
            | "--nix-store"
            | "--sccache"
            | "--slot-dir"
            | "--cpu"
            | "--memory-mib"
            | "--ac-power"
            | "--thermal"
            | "--cpu-idle"
            | "--active-vms"
            | "--git-ref"
            | "--commit-oid"
            | "--release-attestation-file"
            | "--allowed-signers"
            | "--allow-release-ref"
            | "--allow-release-prefix"
            | "--seal-failure-bundle"
            | "--diagnostic-recipient-pubkey-file"
            | "--runner-signing-seed-file"
            | "--tart-bin"
            | "--command") => {
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
                    "--slot-dir" => slot_dir = PathBuf::from(val),
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
                        "true" | "1" => ac_power_override = Some(true),
                        "false" | "0" => ac_power_override = Some(false),
                        _ => {
                            let _ = writeln!(
                                stderr,
                                "chinwag runner start: --ac-power expects true or false"
                            );
                            return 2;
                        }
                    },
                    "--thermal" => {
                        let parsed = match val.as_str() {
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
                        thermal_override = Some(parsed);
                    }
                    "--cpu-idle" => match val.parse::<u8>() {
                        Ok(v) if v <= 100 => cpu_idle_override = Some(v),
                        _ => {
                            let _ = writeln!(
                                stderr,
                                "chinwag runner start: --cpu-idle must be 0..=100"
                            );
                            return 2;
                        }
                    },
                    "--active-vms" => match val.parse::<u8>() {
                        Ok(v) => active_vms_override = Some(v),
                        Err(_) => {
                            let _ = writeln!(stderr, "chinwag runner start: invalid --active-vms");
                            return 2;
                        }
                    },
                    "--git-ref" => git_ref = val.clone(),
                    "--commit-oid" => commit_oid = val.clone(),
                    "--release-attestation-file" => {
                        release_attestation_file = Some(PathBuf::from(val));
                    }
                    "--allowed-signers" => allowed_signers_file = Some(PathBuf::from(val)),
                    "--allow-release-ref" => extra_exact_refs.push(val.clone()),
                    "--allow-release-prefix" => extra_ref_prefixes.push(val.clone()),
                    "--seal-failure-bundle" => seal_failure_bundle_out = Some(PathBuf::from(val)),
                    "--diagnostic-recipient-pubkey-file" => {
                        diagnostic_recipient_pk_file = Some(PathBuf::from(val));
                    }
                    "--runner-signing-seed-file" => {
                        runner_signing_seed_file = Some(PathBuf::from(val));
                    }
                    "--tart-bin" => tart_bin = PathBuf::from(val),
                    "--command" => guest_command.push(val.clone()),
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

    if seal_failure_bundle_out.is_some() && diagnostic_recipient_pk_file.is_none() {
        let _ = writeln!(
            stderr,
            "chinwag runner start: `--seal-failure-bundle` requires `--diagnostic-recipient-pubkey-file`"
        );
        return 2;
    }

    if guest_command.is_empty() {
        guest_command.push("/usr/bin/true".to_owned());
    }

    let profile = match RunnerTrustProfile::parse_label(&profile_raw) {
        Ok(p) => p,
        Err(err) => {
            let _ = writeln!(stderr, "chinwag runner start: {err}");
            return 2;
        }
    };

    let raw_worktree = match repo_path {
        Some(p) => p,
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/private/tmp/chinwag-worktree")),
    };
    let worktree = std::fs::canonicalize(&raw_worktree).unwrap_or(raw_worktree);

    let mut ref_policy = {
        let policy_toml = worktree.join(".chinwag").join("cleanroom-policy.toml");
        if policy_toml.exists() {
            match ReleaseRefPolicy::from_toml_file(&policy_toml) {
                Ok(p) => p,
                Err(err) => {
                    let _ = writeln!(stderr, "chinwag runner start policy error: {err}");
                    return 1;
                }
            }
        } else {
            ReleaseRefPolicy::default()
        }
    };
    ref_policy.allowed_exact_refs.extend(extra_exact_refs);
    ref_policy.allowed_ref_prefixes.extend(extra_ref_prefixes);

    let release_attestation = match release_attestation_file {
        Some(ref att_path) => match load_release_attestation_file(att_path) {
            Ok(att) => Some(att),
            Err(err) => {
                let _ = writeln!(stderr, "chinwag runner start attestation error: {err}");
                return 1;
            }
        },
        None => None,
    };

    let pinned_release_signers = if profile == RunnerTrustProfile::Release {
        let signers_path = allowed_signers_file
            .unwrap_or_else(|| worktree.join(".chinwag").join("allowed_signers"));
        if signers_path.exists() {
            match load_allowed_signers_file(&signers_path) {
                Ok(keys) => keys,
                Err(err) => {
                    let _ = writeln!(stderr, "chinwag runner start allowed_signers error: {err}");
                    return 1;
                }
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let host_env: BTreeMap<String, String> = std::env::vars().collect();
    let trigger_ctx = JobTriggerContext {
        requested_profile: profile,
        git_ref: git_ref.clone(),
        commit_oid: commit_oid.clone(),
        is_fork_pr: fork_pr,
        is_untrusted_pr_event: fork_pr || git_ref.starts_with("refs/pull/"),
        release_attestation,
    };

    let trust_decision = match evaluate_trust_gate_with_policy(
        &trigger_ctx,
        &host_env,
        &pinned_release_signers,
        &ref_policy,
    ) {
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

    let probed = probe_host_hardware_telemetry(&slot_dir);
    let telemetry = HostHardwareTelemetry {
        ac_power_connected: ac_power_override.unwrap_or(probed.ac_power_connected),
        thermal_pressure: thermal_override.unwrap_or(probed.thermal_pressure),
        cpu_idle_percent: cpu_idle_override.unwrap_or(probed.cpu_idle_percent),
        active_vm_count: active_vms_override.unwrap_or(probed.active_vm_count),
        user_hid_active: probed.user_hid_active,
    };
    let mut admission = controller.evaluate_admission(&telemetry);
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

    let _slot_lease = if !dry_run {
        match acquire_host_vm_slot(&slot_dir, policy.max_vms_per_host) {
            Ok(lease) => {
                admission.allocated_slot = Some(lease.slot_index());
                Some(lease)
            }
            Err(err) => {
                if json_mode {
                    let out = json!({
                        "ok": false,
                        "stage": "pool_admission",
                        "error": err.to_string(),
                    });
                    let _ = writeln!(stdout, "{out}");
                } else {
                    let _ = writeln!(stderr, "chinwag runner start slot lease refused: {err}");
                }
                return 1;
            }
        }
    } else {
        None
    };

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
    let sandbox_exec_argv = match tart_spec.guest_sandbox_exec_argv(&seatbelt, &guest_command) {
        Ok(argv) => argv,
        Err(err) => {
            let _ = writeln!(stderr, "chinwag runner start guest command error: {err}");
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
                    "wait_ready": tart_spec.guest_readiness_argv(),
                    "exec_sandboxed": sandbox_exec_argv,
                    "stop": tart_spec.stop_argv(),
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
            let detail = format!("clone failed: {err}");
            let sealed_path = maybe_emit_failure_bundle(
                seal_failure_bundle_out.as_deref(),
                diagnostic_recipient_pk_file.as_deref(),
                runner_signing_seed_file.as_deref(),
                &worktree,
                &vm_instance_name,
                profile,
                &detail,
            );
            emit_runner_failure(
                json_mode,
                stdout,
                stderr,
                &detail,
                true,
                sealed_path.as_deref(),
            );
            return 1;
        }
    };
    let run_res = session.run_ephemeral_with_seatbelt(&seatbelt, &guest_command);
    let (_, delete_res) = session.finish();

    match (run_res, delete_res) {
        (Ok(()), Ok(())) => {
            if json_mode {
                let out = json!({
                    "ok": true,
                    "dry_run": false,
                    "profile": trust_decision.profile.as_str(),
                    "allocated_slot": admission.allocated_slot,
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
            let combined_detail = match del_outcome {
                Ok(()) => run_err.to_string(),
                Err(ref del_err) => format!("{run_err}; teardown failed: {del_err}"),
            };
            let sealed_path = maybe_emit_failure_bundle(
                seal_failure_bundle_out.as_deref(),
                diagnostic_recipient_pk_file.as_deref(),
                runner_signing_seed_file.as_deref(),
                &worktree,
                &vm_instance_name,
                profile,
                &combined_detail,
            );
            emit_runner_failure(
                json_mode,
                stdout,
                stderr,
                &combined_detail,
                del_outcome.is_ok(),
                sealed_path.as_deref(),
            );
            1
        }
        (Ok(()), Err(del_err)) => {
            let teardown_detail = format!("teardown failed: {del_err}");
            let sealed_path = maybe_emit_failure_bundle(
                seal_failure_bundle_out.as_deref(),
                diagnostic_recipient_pk_file.as_deref(),
                runner_signing_seed_file.as_deref(),
                &worktree,
                &vm_instance_name,
                profile,
                &teardown_detail,
            );
            emit_runner_failure(
                json_mode,
                stdout,
                stderr,
                &teardown_detail,
                false,
                sealed_path.as_deref(),
            );
            1
        }
    }
}

fn emit_runner_failure(
    json_mode: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    error_detail: &str,
    cleanup_ok: bool,
    sealed_bundle_path: Option<&Path>,
) {
    if json_mode {
        let out = json!({
            "ok": false,
            "stage": "execution",
            "error": error_detail,
            "cleanup_ok": cleanup_ok,
            "sealed_failure_bundle": sealed_bundle_path.map(|p| p.display().to_string()),
        });
        let _ = writeln!(stdout, "{out}");
    } else {
        let _ = writeln!(
            stderr,
            "chinwag runner start execution failed: {error_detail} (cleanup_ok={cleanup_ok})"
        );
    }
}

fn load_release_attestation_file(path: &Path) -> Result<ReleaseSignerAttestation, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("attestation file must be a regular non-symlink file".to_owned());
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn maybe_emit_failure_bundle(
    out_path: Option<&Path>,
    recipient_pk_file: Option<&Path>,
    runner_seed_file: Option<&Path>,
    worktree: &Path,
    vm_instance_name: &str,
    profile: RunnerTrustProfile,
    error_detail: &str,
) -> Option<PathBuf> {
    let out_target = out_path?;
    let pk_path = recipient_pk_file?;
    let pk_meta = fs::symlink_metadata(pk_path).ok()?;
    if pk_meta.file_type().is_symlink() || !pk_meta.is_file() {
        return None;
    }
    let raw_pk = fs::read(pk_path).ok()?;
    let recipient_pk_bytes = if raw_pk.len() == 1216 {
        raw_pk
    } else {
        let trimmed = std::str::from_utf8(&raw_pk).ok()?.trim();
        hex::decode(trimmed).ok()?
    };

    let runner_sk = match runner_seed_file {
        Some(seed_path) => signing_key_from_seed_file(seed_path).ok()?,
        None => generate_receipt_signing_key().ok()?,
    };

    let flake_lock_sha256 = compile_workspace_env_lock(worktree)
        .map(|c| c.flake_lock_sha256_hex)
        .unwrap_or_else(|_| "0".repeat(64));

    let diag = CleanroomDiagnosticInput {
        job_id: format!("runner-{}", std::process::id()),
        run_vm_name: vm_instance_name.to_owned(),
        trust_profile: profile,
        exit_code: 1,
        flake_lock_sha256,
        stderr_tail: error_detail.to_owned(),
    };
    let bundle = seal_failure_diagnostic_bundle(diag, &recipient_pk_bytes, &runner_sk).ok()?;
    if let Ok(meta) = fs::symlink_metadata(out_target)
        && meta.file_type().is_symlink()
    {
        return None;
    }
    let mut serialized = serde_json::to_vec_pretty(&bundle).ok()?;
    serialized.push(b'\n');
    fs::write(out_target, serialized).ok()?;
    Some(out_target.to_path_buf())
}
