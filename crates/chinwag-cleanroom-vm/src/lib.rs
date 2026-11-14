// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Ephemeral Apple Silicon Tart cleanroom VM orchestration, read-only `VirtioFS`
//! and XNU Seatbelt enforcement (`INV-NIX-VIRTIOFS-01` & `INV-NIX-RO-STORE-01`),
//! zero-Nix-syntax deterministic `.chinwag/flake.lock` synthesis (`INV-NIX-ZERO-SYNTAX-01`),
//! two-tier runner trust isolation (`INV-CLEANROOM-TRUST-SPLIT-01`), AC/thermal
//! multi-Mac pool admission, and `X25519-MLKEM768` HPKE diagnostic failure sealing.

pub mod env_lock;
pub mod runner_pool;
pub mod seatbelt;
pub mod tart;

pub use env_lock::{
    CompiledEnvLock, EnvLockError, EnvLockReceiptV1, FlakeLockV7, ManifestDigestRecord,
    compile_workspace_env_lock, generate_receipt_signing_key, sign_env_lock_receipt,
    signing_key_from_seed_file, verify_env_lock_bundle, verify_env_lock_receipt,
    verify_zero_nix_syntax, write_env_lock_bundle,
};
pub use runner_pool::{
    CleanroomDiagnosticInput, HostHardwareTelemetry, JobTriggerContext, MAX_DRAIN_BUDGET_MS,
    MAX_VMS_PER_MAC_HOST, NetworkEgressPolicy, PoolAdmissionDecision, PoolAdmissionPolicy,
    ReleaseSignerAttestation, RunnerPoolController, RunnerPoolMode, RunnerTrustDecision,
    RunnerTrustProfile, SealedFailureBundleV1, ThermalPressure, TrustPoolError,
    evaluate_trust_gate, generate_recipient_kem_keypair, open_failure_diagnostic_bundle,
    scrub_diagnostic_secrets, seal_failure_diagnostic_bundle,
};
pub use seatbelt::{
    CleanroomSeatbeltSpec, SeatbeltError, SeatbeltProfile, SeatbeltSignalMode,
    compile_seatbelt_profile,
};
pub use tart::{
    CleanroomVmError, EphemeralTartSession, MAX_VIRTIOFS_MOUNT_LATENCY_MS, ProcessTartExecutor,
    TartCleanroomSpec, TartCommandRecord, TartExecutor, VirtioFsAccess, VirtioFsMount,
};
