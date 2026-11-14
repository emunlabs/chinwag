// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Ephemeral Apple Silicon Tart cleanroom VM orchestration, read-only `VirtioFS`
//! and XNU Seatbelt enforcement (`INV-NIX-VIRTIOFS-01` & `INV-NIX-RO-STORE-01`),
//! zero-Nix-syntax deterministic `.chinwag/flake.lock` synthesis (`INV-NIX-ZERO-SYNTAX-01`),
//! two-tier runner trust isolation (`INV-CLEANROOM-TRUST-SPLIT-01`), AC/thermal/HID/CPU
//! multi-Mac pool admission, and `X25519-MLKEM768` HPKE diagnostic failure sealing.

pub mod env_lock;
pub mod runner_pool;
pub mod seatbelt;
pub mod tart;

pub use env_lock::{
    CompiledEnvLock, EnvLockError, EnvLockReceiptV1, FlakeLockV7, MAX_MANIFEST_BYTES,
    MAX_NAR_TOTAL_BYTES, ManifestDigestRecord, StoreClosureEntry, atomic_write_regular_file,
    compile_workspace_env_lock, format_openssh_allowed_signer_line, generate_receipt_signing_key,
    load_allowed_signers_file, parse_openssh_allowed_signers_ed25519, read_non_symlink,
    serialize_nar_v1, sign_env_lock_receipt, signing_key_from_seed_file, verify_env_lock_bundle,
    verify_env_lock_bundle_with_signers, verify_env_lock_receipt, verify_mounted_store_closures,
    verify_zero_nix_syntax, write_env_lock_bundle,
};
pub use runner_pool::{
    CleanroomDiagnosticInput, CleanroomPolicyConfig, DEFAULT_CLEANROOM_BASE_IMAGE,
    DEFAULT_GUEST_SCRATCH_ROOT, DEFAULT_HOST_SCCACHE_DIR, HardwareProbeReport,
    HostHardwareTelemetry, HostVmSlotLease, JobTriggerContext, MAX_DRAIN_BUDGET_MS,
    MAX_VMS_PER_MAC_HOST, NetworkEgressPolicy, PoolAdmissionDecision, PoolAdmissionPolicy,
    ReleaseRefPolicy, ReleaseSignerAttestation, RunnerPoolController, RunnerPoolMode,
    RunnerTrustDecision, RunnerTrustProfile, SealedFailureBundleV1, ThermalPressure,
    TrustPoolError, acquire_host_vm_slot, count_active_slot_leases, default_runtime_slot_dir,
    evaluate_trust_gate, evaluate_trust_gate_with_policy, generate_recipient_kem_keypair,
    open_failure_diagnostic_bundle, parse_darwin_ioreg_hid_active, parse_darwin_pmset_therm,
    parse_darwin_top_cpu_idle, probe_host_hardware_report, probe_host_hardware_telemetry,
    reap_dead_slot_leases, scrub_diagnostic_secrets, seal_failure_diagnostic_bundle,
    try_probe_host_hardware_telemetry,
};
pub use seatbelt::{
    CleanroomSeatbeltSpec, DEFAULT_NIX_DAEMON_SOCKET_DIR, DEFAULT_NIX_DAEMON_SOCKET_PATH,
    DEFAULT_NIX_STORE_SUBPATH, GUEST_NIX_STORE_MOUNT, GUEST_RELEASE_SIGNING_MOUNT,
    GUEST_SCCACHE_MOUNT, GUEST_VIRTIOFS_ROOT, GUEST_WORKTREE_MOUNT, SeatbeltError, SeatbeltProfile,
    SeatbeltSignalMode, compile_seatbelt_profile, normalize_and_canonicalize_sbpl_path,
};
pub use tart::{
    CleanroomStartupTelemetry, CleanroomVmError, EphemeralTartSession,
    MAX_VIRTIOFS_MOUNT_LATENCY_MS, NIX_STORE_TAG, ProcessTartExecutor, RELEASE_SIGNING_TAG,
    RunningTartVm, SCCACHE_TAG, TartCleanroomSpec, TartCommandRecord, TartExecutor, VirtioFsAccess,
    VirtioFsMount, WORKTREE_TAG, verify_host_mount_directory, verify_trusted_executable_path,
};
